//! Android wrapper orchestration and platform-result validation (FEAT-006
//! Phase 3, Task 3.3).
//!
//! The Kotlin bridge owns Android Keystore AES-GCM (provider-generated nonce).
//! Rust owns everything around it: canonical metadata construction, the
//! platform-result validation contract (96-bit nonce, 128-bit tag, bounded
//! sizes, canonical metadata reparse), and the unchanged FEAT-003 inner
//! envelope crypto. The inner suite is platform-neutral: S-001..S-006 and
//! A-001..A-002 replay through the shared native crypto primitives exactly as
//! FEAT-005 does — Android adds the outer wrapper, never a changed inner
//! format. Caller-provided production nonce or key material is forbidden.
//!
//! `PlatformGcm` abstracts the platform wrap/unwrap so the orchestration and
//! contract validation are fully testable without a device; production uses
//! the Kotlin Keystore implementation (Phase 6 wiring, Phase 7 device tests).

use serde::{Deserialize, Serialize};

use crate::android_vault::wrapper::{AndroidWrapperMetadataV1, CanonicalJsonError};
use crate::ubuntu_vault::crypto::encoding::{b64url_decode, b64url_encode, EncodingError};

pub const WRAPPER_PACKAGE_SCHEMA_VERSION: u32 = 1;
pub const PLATFORM_NONCE_BYTES: usize = 12; // 96-bit
pub const PLATFORM_TAG_BYTES: usize = 16; // 128-bit

/// Closed errors for the Android wrapper flow (never raw platform detail).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WrapperFlowError {
    NonceLengthMismatch,
    TagLengthMismatch,
    WrapperTooLarge,
    InnerTooLarge,
    Canonicalization(CanonicalJsonError),
    Encoding(EncodingError),
    Aead,
    PlatformUnwrapRejected,
    MetadataMismatch,
    UnknownSchemaVersion,
}

impl From<CanonicalJsonError> for WrapperFlowError {
    fn from(e: CanonicalJsonError) -> Self {
        Self::Canonicalization(e)
    }
}

impl From<EncodingError> for WrapperFlowError {
    fn from(e: EncodingError) -> Self {
        Self::Encoding(e)
    }
}

/// The complete base64-bearing Android wrapper v1 package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WrapperPackageV1 {
    pub schema_version: u32,
    /// Unpadded base64url nonce (must decode to exactly 96 bits).
    pub nonce_b64url: String,
    /// Unpadded base64url authentication tag (must decode to exactly 128 bits).
    pub tag_b64url: String,
    /// Unpadded base64url ciphertext of the password-protected inner package.
    pub ciphertext_b64url: String,
    /// Canonical authenticated metadata (reparsed and validated by Rust).
    pub metadata: AndroidWrapperMetadataV1,
}

/// Platform wrap result (provider nonce, tag, ciphertext) — a named type to
/// keep the trait signature simple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedPayload {
    pub nonce: Vec<u8>,
    pub tag: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Platform GCM abstraction (testable without a device).
pub trait PlatformGcm {
    /// Encrypt with a provider-generated fresh 96-bit nonce.
    fn wrap(&self, plaintext: &[u8], aad: &[u8]) -> Result<WrappedPayload, WrapperFlowError>;
    /// Decrypt and authenticate; authentication failure returns
    /// `PlatformUnwrapRejected` (never a wrong-password result).
    fn unwrap(
        &self,
        nonce: &[u8],
        tag: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, WrapperFlowError>;
}

/// Validation of a platform wrap result (the Rust revalidation step).
pub fn validate_platform_wrap_result(
    nonce: &[u8],
    tag: &[u8],
    ciphertext_len: usize,
    inner_max: usize,
) -> Result<(), WrapperFlowError> {
    if nonce.len() != PLATFORM_NONCE_BYTES {
        return Err(WrapperFlowError::NonceLengthMismatch);
    }
    if tag.len() != PLATFORM_TAG_BYTES {
        return Err(WrapperFlowError::TagLengthMismatch);
    }
    if ciphertext_len > inner_max {
        return Err(WrapperFlowError::InnerTooLarge);
    }
    Ok(())
}

/// Construct the complete wrapper package from a platform wrap result.
pub fn build_wrapper_package(
    platform: &dyn PlatformGcm,
    inner_package: &[u8],
    metadata: &AndroidWrapperMetadataV1,
) -> Result<WrapperPackageV1, WrapperFlowError> {
    if inner_package.len() > crate::android_vault::INNER_ENVELOPE_MAX_BYTES {
        return Err(WrapperFlowError::InnerTooLarge);
    }
    let aad = metadata.canonical_bytes()?;
    let wrapped = platform.wrap(inner_package, &aad)?;
    let (nonce, tag, ciphertext) = (wrapped.nonce, wrapped.tag, wrapped.ciphertext);
    validate_platform_wrap_result(
        &nonce,
        &tag,
        ciphertext.len(),
        crate::android_vault::INNER_ENVELOPE_MAX_BYTES,
    )?;
    let package = WrapperPackageV1 {
        schema_version: WRAPPER_PACKAGE_SCHEMA_VERSION,
        nonce_b64url: b64url_encode(&nonce),
        tag_b64url: b64url_encode(&tag),
        ciphertext_b64url: b64url_encode(&ciphertext),
        metadata: metadata.clone(),
    };
    let serialized_len = serde_json::to_vec(&package)
        .map_err(|e| {
            WrapperFlowError::Canonicalization(CanonicalJsonError::Serialize(e.to_string()))
        })?
        .len();
    if serialized_len > crate::android_vault::WRAPPER_MAX_BYTES {
        return Err(WrapperFlowError::WrapperTooLarge);
    }
    Ok(package)
}

/// Reparse and authenticate a wrapper package from bytes (Rust revalidation
/// before storage). Decodes nonce/tag/ciphertext, re-canonicalizes metadata,
/// and unwraps the inner package.
pub fn parse_and_unwrap_package(
    platform: &dyn PlatformGcm,
    package_json: &[u8],
) -> Result<Vec<u8>, WrapperFlowError> {
    if package_json.len() > crate::android_vault::WRAPPER_MAX_BYTES {
        return Err(WrapperFlowError::WrapperTooLarge);
    }
    let package: WrapperPackageV1 = serde_json::from_slice(package_json).map_err(|e| {
        WrapperFlowError::Canonicalization(CanonicalJsonError::Serialize(e.to_string()))
    })?;
    if package.schema_version != WRAPPER_PACKAGE_SCHEMA_VERSION {
        return Err(WrapperFlowError::UnknownSchemaVersion);
    }
    let nonce = b64url_decode(&package.nonce_b64url)?;
    let tag = b64url_decode(&package.tag_b64url)?;
    let ciphertext = b64url_decode(&package.ciphertext_b64url)?;
    validate_platform_wrap_result(
        &nonce,
        &tag,
        ciphertext.len(),
        crate::android_vault::INNER_ENVELOPE_MAX_BYTES,
    )?;
    let aad = package.metadata.canonical_bytes()?;
    platform
        .unwrap(&nonce, &tag, &ciphertext, &aad)
        .map_err(|_| WrapperFlowError::PlatformUnwrapRejected)
}

/// Reference platform GCM for tests and deterministic vectors: uses the shared
/// FEAT-003 AES-256-GCM primitive with a caller key. Production replaces this
/// with the Android Keystore key (never a caller nonce; nonce is always
/// provider-generated here via the shared primitive).
pub struct TestPlatformGcm {
    key: Vec<u8>,
}

impl TestPlatformGcm {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }
}

impl PlatformGcm for TestPlatformGcm {
    fn wrap(&self, plaintext: &[u8], aad: &[u8]) -> Result<WrappedPayload, WrapperFlowError> {
        let nonce = crate::ubuntu_vault::crypto::random_bytes(PLATFORM_NONCE_BYTES)
            .map_err(|_| WrapperFlowError::Aead)?;
        let (ct, tag) =
            crate::ubuntu_vault::crypto::aes256_gcm_encrypt(&self.key, &nonce, plaintext, aad)
                .map_err(|_| WrapperFlowError::Aead)?;
        Ok(WrappedPayload {
            nonce: nonce.to_vec(),
            tag: tag.to_vec(),
            ciphertext: ct.to_vec(),
        })
    }

    fn unwrap(
        &self,
        nonce: &[u8],
        tag: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, WrapperFlowError> {
        crate::ubuntu_vault::crypto::aes256_gcm_decrypt(&self.key, nonce, ciphertext, tag, aad)
            .map(|p| p.to_vec())
            .map_err(|_| WrapperFlowError::PlatformUnwrapRejected)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::android_vault::contracts::capability::SecurityLevel;
    use crate::android_vault::wrapper::{hex_lower, AndroidWrapperMetadataV1};

    fn sample_metadata() -> AndroidWrapperMetadataV1 {
        AndroidWrapperMetadataV1 {
            wrapper_version: crate::android_vault::WRAPPER_FORMAT_VERSION,
            adapter_id: crate::android_vault::ADAPTER_ID.to_string(),
            application_id: crate::android_vault::APPLICATION_ID.to_string(),
            release_channel: crate::android_vault::wrapper::ReleaseChannel::Production,
            vault_key_reference: "hvk-9f3e1a02b8c4".to_string(),
            envelope_format_version: 1,
            parameter_suite_version: 1,
            record_schema_version: 1,
            slot: crate::android_vault::wrapper::Slot::A,
            vault_generation: 7,
            record_purpose: crate::android_vault::RECORD_PURPOSE.to_string(),
            critical_extensions: vec![],
        }
    }

    fn platform() -> TestPlatformGcm {
        TestPlatformGcm::new(vec![0x42u8; 32])
    }

    #[test]
    fn wrap_parse_unwrap_round_trips() {
        let inner = b"FEAT-003 password-protected package bytes";
        let meta = sample_metadata();
        let package = build_wrapper_package(&platform(), inner, &meta).unwrap();
        assert_eq!(package.schema_version, WRAPPER_PACKAGE_SCHEMA_VERSION);
        // Platform-result contract: 96-bit nonce, 128-bit tag.
        assert_eq!(
            b64url_decode(&package.nonce_b64url).unwrap().len(),
            PLATFORM_NONCE_BYTES
        );
        assert_eq!(
            b64url_decode(&package.tag_b64url).unwrap().len(),
            PLATFORM_TAG_BYTES
        );
        let serialized = serde_json::to_vec(&package).unwrap();
        assert!(serialized.len() <= crate::android_vault::WRAPPER_MAX_BYTES);
        let round = parse_and_unwrap_package(&platform(), &serialized).unwrap();
        assert_eq!(round, inner);
    }

    #[test]
    fn tampered_metadata_changes_aad_and_fails_auth() {
        let inner = b"package";
        let meta = sample_metadata();
        let package = build_wrapper_package(&platform(), inner, &meta).unwrap();
        let mut tampered = package.clone();
        tampered.metadata.vault_generation += 1;
        let serialized = serde_json::to_vec(&tampered).unwrap();
        let result = parse_and_unwrap_package(&platform(), &serialized);
        // AAD mismatch -> platform unwrap rejection, never wrong-password.
        assert_eq!(result, Err(WrapperFlowError::PlatformUnwrapRejected));
    }

    #[test]
    fn tampered_ciphertext_slot_generation_fails() {
        let inner = b"package";
        let meta = sample_metadata();
        let package = build_wrapper_package(&platform(), inner, &meta).unwrap();
        let mut tampered = package.clone();
        let mut ct = b64url_decode(&tampered.ciphertext_b64url).unwrap();
        ct[0] ^= 0x01;
        tampered.ciphertext_b64url = b64url_encode(&ct);
        let serialized = serde_json::to_vec(&tampered).unwrap();
        assert_eq!(
            parse_and_unwrap_package(&platform(), &serialized),
            Err(WrapperFlowError::PlatformUnwrapRejected)
        );
    }

    #[test]
    fn wrong_nonce_or_tag_length_is_rejected_before_unwrap() {
        let bad_nonce = WrapperPackageV1 {
            schema_version: 1,
            nonce_b64url: b64url_encode(&[0u8; 8]),
            tag_b64url: b64url_encode(&[0u8; 16]),
            ciphertext_b64url: b64url_encode(&[0u8; 16]),
            metadata: sample_metadata(),
        };
        let json = serde_json::to_vec(&bad_nonce).unwrap();
        assert_eq!(
            parse_and_unwrap_package(&platform(), &json),
            Err(WrapperFlowError::NonceLengthMismatch)
        );
        let bad_tag = WrapperPackageV1 {
            schema_version: 1,
            nonce_b64url: b64url_encode(&[0u8; 12]),
            tag_b64url: b64url_encode(&[0u8; 8]),
            ciphertext_b64url: b64url_encode(&[0u8; 16]),
            metadata: sample_metadata(),
        };
        let json = serde_json::to_vec(&bad_tag).unwrap();
        assert_eq!(
            parse_and_unwrap_package(&platform(), &json),
            Err(WrapperFlowError::TagLengthMismatch)
        );
    }

    #[test]
    fn oversized_package_is_rejected() {
        let meta = sample_metadata();
        let big = vec![0u8; crate::android_vault::INNER_ENVELOPE_MAX_BYTES + 1];
        assert_eq!(
            build_wrapper_package(&platform(), &big, &meta),
            Err(WrapperFlowError::InnerTooLarge)
        );
    }

    #[test]
    fn unknown_schema_version_preserves_bytes_and_fails_closed() {
        let inner = b"package";
        let meta = sample_metadata();
        let package = build_wrapper_package(&platform(), inner, &meta).unwrap();
        let mut newer = package.clone();
        newer.schema_version = 99;
        let json = serde_json::to_vec(&newer).unwrap();
        assert_eq!(
            parse_and_unwrap_package(&platform(), &json),
            Err(WrapperFlowError::UnknownSchemaVersion)
        );
    }

    #[test]
    fn fresh_nonce_used_per_wrap() {
        let inner = b"package";
        let meta = sample_metadata();
        let p1 = build_wrapper_package(&platform(), inner, &meta).unwrap();
        let p2 = build_wrapper_package(&platform(), inner, &meta).unwrap();
        assert_ne!(p1.nonce_b64url, p2.nonce_b64url);
        assert_ne!(p1.ciphertext_b64url, p2.ciphertext_b64url);
    }

    #[test]
    fn aw001_canonical_aad_replays_unmodified() {
        // The wrapper AAD used in wrap must equal the pinned AW-001 bytes.
        let meta = sample_metadata();
        let aad = meta.canonical_bytes().unwrap();
        let sha = hex_lower(&{
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(&aad);
            h.finalize()
        });
        assert_eq!(
            sha,
            "706f5a9dcf9c8ccc4484e3c5099835bae1894d204886165f65dafe94059edd76"
        );
    }

    #[test]
    fn platform_security_level_is_checked_by_policy_not_wrapper() {
        let meta = sample_metadata();
        assert!(meta.accepts_security_level(SecurityLevel::TrustedEnvironment));
        assert!(meta.accepts_security_level(SecurityLevel::StrongBox));
        assert!(!meta.accepts_security_level(SecurityLevel::SoftwareOrUnknown));
    }
}
