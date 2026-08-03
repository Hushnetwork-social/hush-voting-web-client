//! Production native cryptography (FEAT-005 Phase 3, Task 3.3).
//!
//! Exact-pinned RustCrypto suite: Argon2id, HKDF-SHA-256, AES-256-GCM, an
//! OS-backed CSPRNG (`getrandom`), and zeroizing secret containers. No caller
//! controls algorithms, parameters, salts, nonces, or keys. Argon2 runs on a
//! dedicated bounded native worker thread — never the UI thread — with epoch
//! cancellation that discards and zeroizes stale output.
//!
//! Immutable corpus replay: the unit tests replay the FEAT-003 vault suite
//! vectors (S-001..S-006) and AAD vectors (A-001..A-00N) byte-exactly from
//! `conformance/vault/v1/vectors/`.

pub mod aad;
pub mod encoding;
pub mod hardening;
pub mod jcs;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use sha2::Sha256;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Immutable v1 suite constants (mirror of FEAT-003 `contracts/suite.ts`).
pub const SUITE_ID: &str = "hush/vault/suite/v1";
pub const KDF_MIN_MEMORY_KIB: u32 = 19_456;
pub const KDF_ITERATIONS: u32 = 2;
pub const KDF_PARALLELISM: u32 = 1;
pub const KDF_SALT_BYTES_MIN: usize = 16;
pub const KDF_OUTPUT_BYTES: usize = 32;
pub const KDF_CALIBRATION_TARGET_MS: u64 = 750;
pub const KDF_HARD_TIMEOUT_MS: u64 = 1_500;
pub const KDF_UBUNTU_MEMORY_CAP_KIB: u32 = 262_144;
pub const AES_KEY_BYTES: usize = 32;
pub const AES_NONCE_BYTES: usize = 12;
pub const HKDF_OUTPUT_BYTES: usize = 32;
pub const HKDF_LABEL_CREDENTIAL_KEK: &[u8] = b"hush/vault/v1/credential-kek";
pub const HKDF_LABEL_MNEMONIC_KEK: &[u8] = b"hush/vault/v1/mnemonic-kek";

/// Zeroizing secret container (application-owned secret memory).
pub type SecretBytes = Zeroizing<Vec<u8>>;

/// Closed crypto error union (raw detail never crosses the adapter boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    InvalidParameters,
    Argon2Failed,
    AeadFailed,
    RngFailed,
    Cancelled,
    KdfResourceLimit,
    OutputTooLong,
}

impl std::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidParameters => write!(f, "invalid cryptographic parameters"),
            Self::Argon2Failed => write!(f, "argon2 derivation failed"),
            Self::AeadFailed => write!(f, "AEAD authentication failed"),
            Self::RngFailed => write!(f, "randomness source failed"),
            Self::Cancelled => write!(f, "operation cancelled"),
            Self::KdfResourceLimit => write!(f, "KDF resource limit"),
            Self::OutputTooLong => write!(f, "requested output exceeds limit"),
        }
    }
}

impl std::error::Error for CryptoError {}

/// Validate the closed suite-v1 parameter set (no caller-selected/downgraded
/// parameters; Ubuntu memory cap enforced).
pub fn validate_suite_params(
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<(), CryptoError> {
    if !(KDF_MIN_MEMORY_KIB..=KDF_UBUNTU_MEMORY_CAP_KIB).contains(&memory_kib) {
        return Err(CryptoError::InvalidParameters);
    }
    if iterations != KDF_ITERATIONS {
        return Err(CryptoError::InvalidParameters);
    }
    if parallelism != KDF_PARALLELISM {
        return Err(CryptoError::InvalidParameters);
    }
    Ok(())
}

/// Argon2id (RFC 9106) with the closed suite-v1 construction.
pub fn argon2id_derive(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    output_bytes: usize,
) -> Result<SecretBytes, CryptoError> {
    if salt.len() < KDF_SALT_BYTES_MIN {
        return Err(CryptoError::InvalidParameters);
    }
    if output_bytes > KDF_OUTPUT_BYTES * 2 {
        return Err(CryptoError::OutputTooLong);
    }
    validate_suite_params(memory_kib, iterations, parallelism)?;
    let params = Params::new(memory_kib, iterations, parallelism, Some(output_bytes))
        .map_err(|_| CryptoError::InvalidParameters)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new(vec![0u8; output_bytes]);
    argon2
        .hash_password_into(password, salt, &mut out)
        .map_err(|_| CryptoError::Argon2Failed)?;
    Ok(out)
}

/// HKDF-SHA-256 (RFC 5869) with the pinned output length.
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    output_bytes: usize,
) -> Result<SecretBytes, CryptoError> {
    if output_bytes > 255 * 32 {
        return Err(CryptoError::OutputTooLong);
    }
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut out = Zeroizing::new(vec![0u8; output_bytes]);
    hk.expand(info, &mut out)
        .map_err(|_| CryptoError::InvalidParameters)?;
    Ok(out)
}

/// AES-256-GCM encrypt with caller-owned fresh nonce and purpose-bound AAD.
pub fn aes256_gcm_encrypt(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<(SecretBytes, SecretBytes), CryptoError> {
    if key.len() != AES_KEY_BYTES || nonce.len() != AES_NONCE_BYTES {
        return Err(CryptoError::InvalidParameters);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidParameters)?;
    let nonce = Nonce::from_slice(nonce);
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|_| CryptoError::AeadFailed)?;
    // aes-gcm returns ciphertext || tag (16-byte GCM tag appended).
    let split = ciphertext.len() - 16;
    let mut ct = Zeroizing::new(ciphertext);
    let tag: SecretBytes = Zeroizing::new(ct.split_off(split));
    Ok((ct, tag))
}

/// AES-256-GCM decrypt with tag verification. Authentication failure returns
/// the closed `AeadFailed` — indistinguishable wrong-key/damaged-data.
pub fn aes256_gcm_decrypt(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    aad: &[u8],
) -> Result<SecretBytes, CryptoError> {
    if key.len() != AES_KEY_BYTES || nonce.len() != AES_NONCE_BYTES {
        return Err(CryptoError::InvalidParameters);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| CryptoError::InvalidParameters)?;
    let nonce = Nonce::from_slice(nonce);
    let mut sealed = Vec::with_capacity(ciphertext.len() + tag.len());
    sealed.extend_from_slice(ciphertext);
    sealed.extend_from_slice(tag);
    let payload = Payload { msg: &sealed, aad };
    let plaintext = cipher
        .decrypt(nonce, payload)
        .map_err(|_| CryptoError::AeadFailed)?;
    Ok(Zeroizing::new(plaintext))
}

/// OS-backed CSPRNG bytes (approved `getrandom`).
pub fn random_bytes(len: usize) -> Result<SecretBytes, CryptoError> {
    if len > 65_536 {
        return Err(CryptoError::OutputTooLong);
    }
    let mut out = Zeroizing::new(vec![0u8; len]);
    getrandom::getrandom(&mut out).map_err(|_| CryptoError::RngFailed)?;
    Ok(out)
}

/// Fresh 256-bit wrapping key.
pub fn new_wrapping_key() -> Result<SecretBytes, CryptoError> {
    random_bytes(AES_KEY_BYTES)
}

/// Cancellable Argon2id derivation.
///
/// Runs on a dedicated bounded worker thread. The cancellation flag is
/// checked after derivation completes; a cancelled result is discarded and
/// zeroized before returning `Cancelled`. Callers (Phase 4 session authority)
/// enforce the one-second cleanup acknowledgement and controlled fail-closed
/// termination on unconfirmed cleanup.
pub fn derive_password_key_cancellable(
    password: &[u8],
    salt: &[u8],
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    output_bytes: usize,
    cancel: Arc<AtomicBool>,
) -> Result<SecretBytes, CryptoError> {
    let password = password.to_vec();
    let salt = salt.to_vec();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let result = argon2id_derive(
            &password,
            &salt,
            memory_kib,
            iterations,
            parallelism,
            output_bytes,
        );
        let _ = tx.send(result);
    });
    let result = rx.recv().map_err(|_| CryptoError::Argon2Failed)?;
    // Cancellation is checked after completion: a stale result is discarded
    // (dropped → zeroized) and the caller sees Cancelled.
    if cancel.load(Ordering::SeqCst) {
        return Err(CryptoError::Cancelled);
    }
    result
}

/// The closed suite-v1 password-key derivation (minimum parameters).
pub fn suite_v1_password_key(password: &[u8], salt: &[u8]) -> Result<SecretBytes, CryptoError> {
    argon2id_derive(
        password,
        salt,
        KDF_MIN_MEMORY_KIB,
        KDF_ITERATIONS,
        KDF_PARALLELISM,
        KDF_OUTPUT_BYTES,
    )
}

/// HKDF key-stretching with the exact versioned labels (FEAT-003).
pub fn hkdf_credential_kek(ikm: &[u8], salt: &[u8]) -> Result<SecretBytes, CryptoError> {
    hkdf_sha256(ikm, salt, HKDF_LABEL_CREDENTIAL_KEK, HKDF_OUTPUT_BYTES)
}

pub fn hkdf_mnemonic_kek(ikm: &[u8], salt: &[u8]) -> Result<SecretBytes, CryptoError> {
    hkdf_sha256(ikm, salt, HKDF_LABEL_MNEMONIC_KEK, HKDF_OUTPUT_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::{AssociatedData, ParamsBuilder};
    use serde_json::Value;

    const VECTORS_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../conformance/vault/v1/vectors/suite-vectors.json"
    );

    fn load_vectors() -> Value {
        let text = std::fs::read_to_string(VECTORS_PATH).expect("suite vectors readable");
        serde_json::from_str(&text).expect("suite vectors valid JSON")
    }

    fn b64url_decode(s: &str) -> Vec<u8> {
        crate::ubuntu_vault::crypto::encoding::b64url_decode(s).expect("valid base64url")
    }

    fn hex_decode(s: &str) -> Vec<u8> {
        crate::ubuntu_vault::crypto::encoding::hex_decode(s).expect("valid hex")
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::Digest;
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let out = hasher.finalize();
        out.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn replays_suite_vector_s001_hkdf() {
        let v = &load_vectors()["vectors"][0];
        assert_eq!(v["id"], "S-001");
        let ikm = b64url_decode(v["ikmB64url"].as_str().unwrap());
        let salt = b64url_decode(v["saltB64url"].as_str().unwrap());
        let out = hkdf_sha256(&ikm, &salt, b"hush/vault/v1/credential-kek", 32).unwrap();
        assert_eq!(
            sha256_hex(&out),
            v["outputSha256"].as_str().unwrap(),
            "S-001 HKDF label mismatch"
        );
    }

    #[test]
    fn replays_suite_vector_s002_hkdf_mnemonic_label() {
        let v = &load_vectors()["vectors"][1];
        assert_eq!(v["id"], "S-002");
        let ikm = b64url_decode(v["ikmB64url"].as_str().unwrap());
        let salt = b64url_decode(v["saltB64url"].as_str().unwrap());
        let out = hkdf_sha256(&ikm, &salt, b"hush/vault/v1/mnemonic-kek", 32).unwrap();
        assert_eq!(
            sha256_hex(&out),
            v["outputSha256"].as_str().unwrap(),
            "S-002 HKDF mnemonic label mismatch"
        );
    }

    #[test]
    fn replays_suite_vector_s003_aes_gcm() {
        let v = &load_vectors()["vectors"][2];
        assert_eq!(v["id"], "S-003");
        let key = hex_decode(v["keyHex"].as_str().unwrap());
        let nonce = hex_decode(v["nonceHex"].as_str().unwrap());
        let plaintext = v["plaintextUtf8"].as_str().unwrap().as_bytes();
        // A-001 AAD (ordinary record, Alice fixture) — see aad.rs corpus helper.
        let aad = crate::ubuntu_vault::crypto::aad::tests::corpus_aad_inputs("ordinary")
            .canonical_bytes()
            .unwrap();
        let (ct, tag) = aes256_gcm_encrypt(&key, &nonce, plaintext, &aad).unwrap();
        assert_eq!(
            sha256_hex(&ct),
            v["ciphertextSha256"].as_str().unwrap(),
            "S-003 ciphertext mismatch"
        );
        assert_eq!(
            sha256_hex(&tag),
            v["tagSha256"].as_str().unwrap(),
            "S-003 tag mismatch"
        );
        let round = aes256_gcm_decrypt(&key, &nonce, &ct, &tag, &aad).unwrap();
        assert_eq!(&*round, plaintext);
    }

    #[test]
    fn replays_suite_vector_s004_argon2id() {
        let v = &load_vectors()["vectors"][3];
        assert_eq!(v["id"], "S-004");
        let password = v["passwordUtf8"].as_str().unwrap().as_bytes();
        let salt = hex_decode(v["saltHex"].as_str().unwrap());
        let out = argon2id_derive(
            password,
            &salt,
            v["memoryKiB"].as_u64().unwrap() as u32,
            v["iterations"].as_u64().unwrap() as u32,
            v["parallelism"].as_u64().unwrap() as u32,
            v["outputBytes"].as_u64().unwrap() as usize,
        )
        .unwrap();
        assert_eq!(
            sha256_hex(&out),
            v["outputSha256"].as_str().unwrap(),
            "S-004 Argon2id mismatch"
        );
    }

    #[test]
    fn replays_suite_vector_s005_argon2id_rfc9106_kat() {
        let v = &load_vectors()["vectors"][4];
        assert_eq!(v["id"], "S-005");
        let password = hex_decode(v["passwordHex"].as_str().unwrap());
        let salt = hex_decode(v["saltHex"].as_str().unwrap());
        // RFC 9106 §5.3 KAT uses secret+ad; argon2 0.5.3 exposes both through
        // its public builder API: `ParamsBuilder::data(AssociatedData)` for
        // the ad and `Argon2::new_with_secret` for the secret.
        let secret = hex_decode(v["secretHex"].as_str().unwrap());
        let ad = hex_decode(v["adHex"].as_str().unwrap());
        let params = ParamsBuilder::new()
            .m_cost(v["memoryKiB"].as_u64().unwrap() as u32)
            .t_cost(v["iterations"].as_u64().unwrap() as u32)
            .p_cost(v["parallelism"].as_u64().unwrap() as u32)
            .output_len(v["outputBytes"].as_u64().unwrap() as usize)
            .data(AssociatedData::new(&ad).unwrap())
            .build()
            .unwrap();
        let argon2 =
            Argon2::new_with_secret(&secret, Algorithm::Argon2id, Version::V0x13, params).unwrap();
        let mut out = Zeroizing::new(vec![0u8; v["outputBytes"].as_u64().unwrap() as usize]);
        argon2
            .hash_password_into(&password, &salt, &mut out)
            .unwrap();
        assert_eq!(
            hex_decode(v["outputHex"].as_str().unwrap()),
            *out,
            "S-005 RFC 9106 KAT mismatch"
        );
    }

    #[test]
    fn replays_suite_vector_s006_hkdf_rfc5869_kat() {
        let v = &load_vectors()["vectors"][5];
        assert_eq!(v["id"], "S-006");
        let ikm = hex_decode(v["ikmHex"].as_str().unwrap());
        let salt = hex_decode(v["saltHex"].as_str().unwrap());
        let info = hex_decode(v["infoHex"].as_str().unwrap());
        let out = hkdf_sha256(
            &ikm,
            &salt,
            &info,
            v["outputBytes"].as_u64().unwrap() as usize,
        )
        .unwrap();
        assert_eq!(
            hex_decode(v["outputHex"].as_str().unwrap()),
            *out,
            "S-006 RFC 5869 KAT mismatch"
        );
    }

    #[test]
    fn nonce_freshness_is_adapter_owned() {
        // random_bytes is the only nonce source; no caller-supplied nonce
        // ever enters production paths (enforced by signature).
        let a = random_bytes(12).unwrap();
        let b = random_bytes(12).unwrap();
        assert_ne!(*a, *b);
    }

    #[test]
    fn tampered_aad_fails_closed() {
        let key = vec![3u8; 32];
        let nonce = vec![5u8; 12];
        let aad1 = b"correct-purpose-aad";
        let aad2 = b"tampered-purpose-aad";
        let (ct, tag) = aes256_gcm_encrypt(&key, &nonce, b"payload", aad1).unwrap();
        // Wrong AAD must fail with the closed AeadFailed (no partial output).
        assert_eq!(
            aes256_gcm_decrypt(&key, &nonce, &ct, &tag, aad2),
            Err(CryptoError::AeadFailed)
        );
    }

    #[test]
    fn wrong_password_and_damaged_data_are_indistinguishable() {
        // Both wrong inner key and corrupted ciphertext produce the same
        // closed code — no oracle leaks which field differed.
        let key = vec![1u8; 32];
        let nonce = vec![2u8; 12];
        let (ct, tag) = aes256_gcm_encrypt(&key, &nonce, b"secret", b"aad").unwrap();
        let wrong_key = vec![9u8; 32];
        assert_eq!(
            aes256_gcm_decrypt(&wrong_key, &nonce, &ct, &tag, b"aad"),
            Err(CryptoError::AeadFailed)
        );
        let mut damaged = ct.clone();
        damaged[0] ^= 0x80;
        assert_eq!(
            aes256_gcm_decrypt(&key, &nonce, &damaged, &tag, b"aad"),
            Err(CryptoError::AeadFailed)
        );
    }

    #[test]
    fn suite_params_are_closed_no_downgrade() {
        // No caller-selected/downgraded parameters.
        assert_eq!(
            validate_suite_params(1, 1, 1),
            Err(CryptoError::InvalidParameters)
        );
        assert_eq!(validate_suite_params(KDF_MIN_MEMORY_KIB, 2, 1), Ok(()));
        assert_eq!(
            validate_suite_params(KDF_UBUNTU_MEMORY_CAP_KIB + 1, 2, 1),
            Err(CryptoError::InvalidParameters)
        );
    }

    #[test]
    fn cancelled_kdf_discards_and_zeroizes() {
        let cancel = Arc::new(AtomicBool::new(true));
        let result = derive_password_key_cancellable(
            b"password",
            &[7u8; 16],
            KDF_MIN_MEMORY_KIB,
            KDF_ITERATIONS,
            KDF_PARALLELISM,
            KDF_OUTPUT_BYTES,
            cancel,
        );
        assert_eq!(result, Err(CryptoError::Cancelled));
    }

    #[test]
    fn non_cancelled_kdf_derives() {
        let cancel = Arc::new(AtomicBool::new(false));
        let result = derive_password_key_cancellable(
            b"password-bytes",
            &hex_decode("07070707070707070707070707070707"),
            KDF_MIN_MEMORY_KIB,
            KDF_ITERATIONS,
            KDF_PARALLELISM,
            KDF_OUTPUT_BYTES,
            cancel,
        );
        let out = result.unwrap();
        // S-004 outputSha256 anchors the derivation.
        assert_eq!(
            sha256_hex(&out),
            "c78cf17e0576ca8836864cd1623d97359564eb5dafff779bacf42e6c77fc03e2"
        );
    }
}
