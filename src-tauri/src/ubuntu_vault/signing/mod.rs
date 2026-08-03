//! Native operation-specific signing (FEAT-005 "Canonical Signing Boundary";
//! FEAT-001 replay).
//!
//! TypeScript remains the canonical transaction serializer. Rust signs ONLY
//! after every operation-specific check succeeds: exact canonical envelope
//! parse, pinned payload kind, signatory/public-key equality with the session
//! identity, bounded sizes, alias/visibility, and the user-confirmation
//! binding. ECDSA uses the SHA-256 prehash with deterministic RFC 6979
//! nonces and returns compact 64-byte r||s (FEAT-001 P-01 semantics).
//! Signature behavior replays the immutable FEAT-001 signature vectors by
//! cross-verification (compact and DER). No generic `sign(bytes)` exists.

pub mod envelope;

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::ubuntu_vault::crypto::encoding::hex_encode;
use crate::ubuntu_vault::session::commands::ConfirmationContext;
use crate::ubuntu_vault::session::SessionIdentity;
use crate::ubuntu_vault::signing::envelope::{
    parse_envelope, CanonicalEnvelope, EnvelopeError, CANONICAL_MAX_BYTES,
};

/// Fixed operation purpose for `CreateFullIdentity` signing.
pub const CREATE_FULL_IDENTITY_PURPOSE: &str = "create-full-identity-sign";
/// Operation contract version.
pub const CREATE_FULL_IDENTITY_VERSION: u32 = 1;

/// Closed signing failure vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningError {
    KeyInvalid,
    BoundsExceeded,
    Envelope(EnvelopeError),
    ConfirmationMismatch,
    IdentityMismatch,
    SignatoryMismatch,
    InvalidSignatureEncoding,
}

impl From<EnvelopeError> for SigningError {
    fn from(e: EnvelopeError) -> Self {
        Self::Envelope(e)
    }
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "native signing failure (closed code)")
    }
}

impl std::error::Error for SigningError {}

/// Native secp256k1 signing key (secret; NO Debug).
pub struct NativeSigner {
    key: SigningKey,
}

impl NativeSigner {
    /// Adopt a 32-byte secret key from native custody.
    pub fn from_bytes(secret: &[u8]) -> Result<Self, SigningError> {
        if secret.len() != 32 {
            return Err(SigningError::KeyInvalid);
        }
        let key = SigningKey::from_slice(secret).map_err(|_| SigningError::KeyInvalid)?;
        Ok(Self { key })
    }

    /// Public signing address (SEC1 compressed hex) — safe public field.
    pub fn signing_address(&self) -> String {
        hex_encode(
            VerifyingKey::from(&self.key)
                .to_encoded_point(true)
                .as_bytes(),
        )
    }

    /// Deterministic ECDSA over the SHA-256 prehash of the exact canonical
    /// bytes; compact 64-byte r||s.
    pub fn sign_canonical(&self, canonical: &[u8]) -> Result<Zeroizing<[u8; 64]>, SigningError> {
        if canonical.len() > CANONICAL_MAX_BYTES {
            return Err(SigningError::BoundsExceeded);
        }
        let digest = Sha256::digest(canonical);
        let signature: Signature = self
            .key
            .sign_prehash(&digest)
            .map_err(|_| SigningError::KeyInvalid)?;
        let bytes = signature.to_bytes();
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        Ok(Zeroizing::new(out))
    }
}

/// Public submission envelope returned after signing (no private material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicSubmissionEnvelope {
    pub signing_address: String,
    pub encrypt_address: String,
    pub identity_alias: String,
    pub is_public: bool,
}

/// Outcome of a closed `CreateFullIdentity` sign.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateFullIdentityOutcome {
    pub signature_compact_hex: String,
    pub envelope: PublicSubmissionEnvelope,
}

/// Request for the closed `CreateFullIdentitySign` operation.
#[derive(Debug, Clone)]
pub struct CreateFullIdentityRequest<'a> {
    /// Exact TypeScript canonical bytes (bounded).
    pub canonical_bytes: &'a [u8],
    /// TypeScript-computed SHA-256 of the canonical bytes (confirmation
    /// binding — must equal the native computation).
    pub confirmation_digest: [u8; 32],
    pub session_identity: &'a SessionIdentity,
    pub confirmation: &'a ConfirmationContext,
}

/// Sign TypeScript canonical bytes ONLY after every operation-specific check
/// succeeds. Returns only the signature and the approved public submission
/// envelope — never a private key, never the decrypted bundle.
pub fn sign_create_full_identity(
    signer: &NativeSigner,
    req: &CreateFullIdentityRequest<'_>,
) -> Result<CreateFullIdentityOutcome, SigningError> {
    // 1. Operation/version confirmation binding.
    if req.confirmation.operation_purpose != CREATE_FULL_IDENTITY_PURPOSE
        || req.confirmation.version != CREATE_FULL_IDENTITY_VERSION
    {
        return Err(SigningError::ConfirmationMismatch);
    }
    // 2. Bounds.
    if req.canonical_bytes.len() > CANONICAL_MAX_BYTES {
        return Err(SigningError::BoundsExceeded);
    }
    // 3. Confirmation digest must match the canonical bytes natively.
    let digest = Sha256::digest(req.canonical_bytes);
    if digest.as_slice() != req.confirmation_digest {
        return Err(SigningError::ConfirmationMismatch);
    }
    // 4. Envelope parse + closed validation.
    let env: CanonicalEnvelope = parse_envelope(req.canonical_bytes)?;
    // 5. Identity binding: envelope keys must equal the session identity.
    if !env
        .public_signing_address
        .eq_ignore_ascii_case(&req.session_identity.signing_address)
        || !env
            .public_encrypt_address
            .eq_ignore_ascii_case(&req.session_identity.encrypt_address)
    {
        return Err(SigningError::IdentityMismatch);
    }
    // 6. Signatory check: the signing key must belong to the claimed
    //    signing address.
    if !signer
        .signing_address()
        .eq_ignore_ascii_case(&env.public_signing_address)
    {
        return Err(SigningError::SignatoryMismatch);
    }
    // 7. Sign the exact canonical bytes.
    let signature = signer.sign_canonical(req.canonical_bytes)?;
    Ok(CreateFullIdentityOutcome {
        signature_compact_hex: hex_encode(&*signature),
        envelope: PublicSubmissionEnvelope {
            signing_address: env.public_signing_address,
            encrypt_address: env.public_encrypt_address,
            identity_alias: env.identity_alias,
            is_public: env.is_public,
        },
    })
}

/// Verify a compact (64-byte) or DER signature over the SHA-256 prehash of a
/// message with a SEC1 public key (FEAT-001 corpus replay).
pub fn verify_signature(message: &[u8], signature_hex: &str, public_key_hex: &str) -> bool {
    let Ok(pubkey_bytes) = crate::ubuntu_vault::crypto::encoding::hex_decode(public_key_hex) else {
        return false;
    };
    let Ok(verifying) = VerifyingKey::from_sec1_bytes(&pubkey_bytes) else {
        return false;
    };
    let Ok(sig_bytes) = crate::ubuntu_vault::crypto::encoding::hex_decode(signature_hex) else {
        return false;
    };
    let signature = match sig_bytes.len() {
        64 => Signature::from_slice(&sig_bytes),
        _ => Signature::from_der(&sig_bytes),
    };
    let Ok(signature) = signature else {
        return false;
    };
    let digest = Sha256::digest(message);
    verifying.verify_prehash(&digest, &signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ubuntu_vault::crypto::encoding::hex_decode;
    use serde_json::Value;

    const SIG_VECTORS_PATH: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../conformance/identity/v1/vectors/signature-vectors.json"
    );

    fn load_sig_vectors() -> Value {
        let text = std::fs::read_to_string(SIG_VECTORS_PATH).expect("signature vectors readable");
        serde_json::from_str(&text).expect("valid JSON")
    }

    const CB_001: &str = r#"{"TransactionId":"d4a2f9c1-3b5e-4f6a-9c7d-2e8f1a0b3c4d","PayloadKind":"351cd60b-3fdf-48d4-b608-e93c0100f7d0","TransactionTimeStamp":"2026-08-01T12:34:56.789Z","Payload":{"IdentityAlias":"public-test-alias-001","PublicSigningAddress":"0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5","PublicEncryptAddress":"032ebaf076203f15ac8119cfdbc9394d1c7b9929b0647e4f607e27da95701f8556","IsPublic":true},"PayloadSize":241}"#;

    fn confirmation() -> ConfirmationContext {
        ConfirmationContext {
            operation_purpose: CREATE_FULL_IDENTITY_PURPOSE,
            version: CREATE_FULL_IDENTITY_VERSION,
        }
    }

    #[test]
    fn replays_signature_vectors_by_cross_verification() {
        let vectors = load_sig_vectors();
        for vec in vectors["vectors"].as_array().unwrap() {
            let expected = vec["expected"].as_str().unwrap();
            if vec["operation"].as_str() != Some("VERIFY") {
                continue;
            }
            let message = match vec.get("messageUtf8") {
                Some(Value::String(s)) => s.clone(),
                _ => vec
                    .get("messageUtf8Hex")
                    .map(|h| String::from_utf8(hex_decode(h.as_str().unwrap()).unwrap()).unwrap())
                    .unwrap(),
            };
            let pubkey = vec["publicKeyHex"].as_str().unwrap();
            let mut verified = false;
            if let Some(compact) = vec.get("signatureCompactHex").and_then(Value::as_str) {
                verified |= verify_signature(message.as_bytes(), compact, pubkey);
            }
            if let Some(der) = vec.get("signatureDerHex").and_then(Value::as_str) {
                verified |= verify_signature(message.as_bytes(), der, pubkey);
            }
            if let Some(b64) = vec.get("signatureCompactBase64").and_then(Value::as_str) {
                // Corpus uses standard base64; convert to the URL-safe
                // alphabet for the shared decoder (fixture-only mapping).
                let url_safe = b64.replace('+', "-").replace('/', "_");
                if let Ok(bytes) = crate::ubuntu_vault::crypto::encoding::b64url_decode(&url_safe) {
                    verified |= verify_signature(message.as_bytes(), &hex_encode(&bytes), pubkey);
                }
            }
            assert_eq!(
                verified,
                expected == "VALID",
                "vector {} expected {expected}, verified {verified}",
                vec["id"]
            );
        }
    }

    #[test]
    fn malformed_signature_encodings_never_verify() {
        // S-006 (63-byte compact) and S-007 (malformed DER) must fail.
        let vectors = load_sig_vectors();
        for vec in vectors["vectors"].as_array().unwrap() {
            if vec["operation"].as_str() != Some("DECODE") {
                continue;
            }
            let signature = vec
                .get("signatureCompactHex")
                .or_else(|| vec.get("signatureDerHex"))
                .and_then(Value::as_str)
                .unwrap();
            // The malformed encodings must not verify against any key.
            assert!(!verify_signature(
                b"any-message",
                signature,
                &"02".repeat(33)
            ));
        }
    }

    #[test]
    fn deterministic_sign_and_verify_round_trip() {
        let secret = [0x42u8; 32];
        let signer = NativeSigner::from_bytes(&secret).unwrap();
        let sig1 = signer.sign_canonical(CB_001.as_bytes()).unwrap();
        let sig2 = signer.sign_canonical(CB_001.as_bytes()).unwrap();
        // RFC 6979 determinism.
        assert_eq!(&*sig1, &*sig2);
        assert!(verify_signature(
            CB_001.as_bytes(),
            &hex_encode(&*sig1),
            &signer.signing_address()
        ));
        // A different message fails.
        assert!(!verify_signature(
            b"different-canonical-bytes",
            &hex_encode(&*sig1),
            &signer.signing_address()
        ));
    }

    #[test]
    fn create_full_identity_signs_only_after_all_checks() {
        let secret = [0x42u8; 32];
        let signer = NativeSigner::from_bytes(&secret).unwrap();
        // Build a canonical envelope whose signing address matches the
        // signer's own public key (fresh synthetic fixture; encrypt address
        // is a fixed synthetic public field).
        let signing = signer.signing_address();
        let template = format!(
            r#"{{"TransactionId":"d4a2f9c1-3b5e-4f6a-9c7d-2e8f1a0b3c4d","PayloadKind":"351cd60b-3fdf-48d4-b608-e93c0100f7d0","TransactionTimeStamp":"2026-08-01T12:34:56.789Z","Payload":{{"IdentityAlias":"public-test-alias-001","PublicSigningAddress":"{signing}","PublicEncryptAddress":"032ebaf076203f15ac8119cfdbc9394d1c7b9929b0647e4f607e27da95701f8556","IsPublic":true}},"PayloadSize":__SIZE__}}"#
        );
        // Compute the real PayloadSize from the raw payload span, then
        // substitute (the payload object precedes PayloadSize and is
        // unaffected).
        let payload_size =
            crate::ubuntu_vault::signing::envelope::raw_payload_size_for_test(&template);
        let canonical = template.replace("__SIZE__", &payload_size.to_string());
        let canonical_bytes = canonical.as_bytes();

        let identity = SessionIdentity {
            signing_address: signing.clone(),
            encrypt_address: "032ebaf076203f15ac8119cfdbc9394d1c7b9929b0647e4f607e27da95701f8556"
                .to_string(),
        };
        let digest = Sha256::digest(canonical_bytes);
        let req = CreateFullIdentityRequest {
            canonical_bytes,
            confirmation_digest: digest.into(),
            session_identity: &identity,
            confirmation: &confirmation(),
        };
        // A fresh key with a different address: signatory mismatch.
        let other_signer = NativeSigner::from_bytes(&[0x11u8; 32]).unwrap();
        assert_eq!(
            sign_create_full_identity(&other_signer, &req),
            Err(SigningError::SignatoryMismatch)
        );
        // Wrong confirmation digest.
        let bad_digest = CreateFullIdentityRequest {
            canonical_bytes,
            confirmation_digest: [0u8; 32],
            session_identity: &identity,
            confirmation: &confirmation(),
        };
        assert_eq!(
            sign_create_full_identity(&signer, &bad_digest),
            Err(SigningError::ConfirmationMismatch)
        );
        // Wrong session identity binding.
        let wrong_identity = SessionIdentity {
            signing_address: "03".repeat(33),
            encrypt_address: "02".repeat(33),
        };
        let wrong_id_req = CreateFullIdentityRequest {
            canonical_bytes,
            confirmation_digest: digest.into(),
            session_identity: &wrong_identity,
            confirmation: &confirmation(),
        };
        assert_eq!(
            sign_create_full_identity(&signer, &wrong_id_req),
            Err(SigningError::IdentityMismatch)
        );
        // Wrong operation purpose.
        let wrong_ctx = ConfirmationContext {
            operation_purpose: "sign-bytes",
            version: 1,
        };
        let wrong_ctx_req = CreateFullIdentityRequest {
            canonical_bytes,
            confirmation_digest: digest.into(),
            session_identity: &identity,
            confirmation: &wrong_ctx,
        };
        assert_eq!(
            sign_create_full_identity(&signer, &wrong_ctx_req),
            Err(SigningError::ConfirmationMismatch)
        );
        // Full valid request signs and returns only safe fields.
        let outcome = sign_create_full_identity(&signer, &req).unwrap();
        assert_eq!(outcome.signature_compact_hex.len(), 128);
        assert_eq!(outcome.envelope.signing_address, signing);
        assert_eq!(outcome.envelope.identity_alias, "public-test-alias-001");
        assert!(outcome.envelope.is_public);
        assert!(verify_signature(
            canonical_bytes,
            &outcome.signature_compact_hex,
            &outcome.envelope.signing_address
        ));
    }

    #[test]
    fn signer_never_exposes_secret_material() {
        let secret = [0x42u8; 32];
        let signer = NativeSigner::from_bytes(&secret).unwrap();
        // The signer exposes only the safe public address; the secret key
        // has no Debug derive and no getter.
        assert_eq!(signer.signing_address().len(), 66);
    }
}
