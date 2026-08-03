//! Slot file envelope v1 (FEAT-005 "Wrapper-key construction", "Native
//! Filesystem Storage", "Protection Modes").
//!
//! A slot file is one of two closed formats, discriminated by the `mode`
//! field:
//!
//! - `os-backed`: the FEAT-003 password-encrypted package bytes are wrapped
//!   with the OS Secret Service wrapping key (AES-256-GCM). The authenticated
//!   metadata binds wrapper format version, adapter ID, application ID,
//!   release channel, package generation, and record purpose. It NEVER binds
//!   provider name, Ubuntu username, machine hostname, or endpoint.
//! - `password-only`: the FEAT-003 password-encrypted package bytes stored
//!   directly (confirmed-provider-absence fallback) under the same filesystem
//!   protections. No outer OS wrapper exists.
//!
//! The slot file itself is the authoritative protection-mode signal: the
//! sidecar mirrors it for fast non-secret projection and is reconciled at
//! open. Unknown fields are rejected (fail closed); malformed or unsupported
//! envelopes map to closed native codes.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::ubuntu_vault::contracts::protection::ProtectionMode;
use crate::ubuntu_vault::contracts::results::NativeErrorCode;
use crate::ubuntu_vault::contracts::wrapper::WrapperMetadataV1;
use crate::ubuntu_vault::crypto::aes256_gcm_decrypt;
use crate::ubuntu_vault::crypto::aes256_gcm_encrypt;
use crate::ubuntu_vault::crypto::encoding::{hex_decode, hex_encode};
use crate::ubuntu_vault::crypto::random_bytes;
use crate::ubuntu_vault::crypto::{CryptoError, AES_KEY_BYTES, AES_NONCE_BYTES};

/// Slot envelope format version (integer; unsupported versions fail closed).
pub const SLOT_ENVELOPE_FORMAT_VERSION: u32 = 1;

/// GCM tag length in bytes (aes-gcm appends a 16-byte tag).
pub const GCM_TAG_BYTES: usize = 16;

/// Closed envelope failure vocabulary (raw detail never crosses the
/// boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    /// Fixed vocabulary/identity-free/bounds validation failed.
    InvalidMetadata,
    /// Envelope/wrapper format version is unsupported.
    UnsupportedVersion,
    /// Structural parse/encoding failure (malformed slot file).
    Malformed,
    /// Outer-wrapper authentication failed (wrong key, tamper, or damage).
    AuthenticationFailed,
    /// Underlying crypto operation failed.
    Crypto,
}

impl EnvelopeError {
    /// Safe closed mapping (outer-wrapper failure is the distinct
    /// `PlatformProtectionInvalidated` recovery path).
    pub fn to_native_error(self) -> NativeErrorCode {
        match self {
            Self::InvalidMetadata | Self::Malformed => NativeErrorCode::MalformedEnvelope,
            Self::UnsupportedVersion => NativeErrorCode::WrapperVersionUnsupported,
            Self::AuthenticationFailed => NativeErrorCode::PlatformProtectionInvalidated,
            Self::Crypto => NativeErrorCode::PlatformProtectionUnavailable,
        }
    }
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "slot envelope failure: {self:?}")
    }
}

impl std::error::Error for EnvelopeError {}

impl From<CryptoError> for EnvelopeError {
    fn from(_: CryptoError) -> Self {
        Self::Crypto
    }
}

/// OS-backed slot envelope (outer wrapper over the FEAT-003 package).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OsBackedSlotV1 {
    pub envelope_format_version: u32,
    pub wrapper: WrapperMetadataV1,
    pub nonce_hex: String,
    pub ciphertext_hex: String,
    pub tag_hex: String,
}

/// Password-only slot (FEAT-003 package without an outer OS wrapper).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PasswordOnlySlotV1 {
    pub envelope_format_version: u32,
    pub generation: u64,
    /// Hex-encoded FEAT-003 password-encrypted package bytes.
    pub package_hex: String,
}

/// Closed slot-file union, discriminated by `mode`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "camelCase", deny_unknown_fields)]
pub enum SlotFile {
    #[serde(rename = "osBacked")]
    OsBacked(OsBackedSlotV1),
    #[serde(rename = "passwordOnly")]
    PasswordOnly(PasswordOnlySlotV1),
}

impl SlotFile {
    /// The protection mode of this slot (authoritative signal).
    pub fn mode(&self) -> ProtectionMode {
        match self {
            Self::OsBacked(_) => ProtectionMode::OsBacked,
            Self::PasswordOnly(_) => ProtectionMode::PasswordOnly,
        }
    }

    /// The vault package generation protected by this slot.
    pub fn generation(&self) -> u64 {
        match self {
            Self::OsBacked(slot) => slot.wrapper.generation,
            Self::PasswordOnly(slot) => slot.generation,
        }
    }
}

/// Wrap a FEAT-003 package under the OS wrapping key (OS-backed mode).
///
/// The caller owns the fresh nonce and the wrapping key; no caller-supplied
/// nonce or key ever enters production paths. Metadata is validated before
/// any cryptography runs.
pub fn wrap_os_backed(
    wrapping_key: &[u8],
    package: &[u8],
    wrapper: WrapperMetadataV1,
) -> Result<SlotFile, EnvelopeError> {
    validate_metadata(&wrapper)?;
    if wrapping_key.len() != AES_KEY_BYTES {
        return Err(EnvelopeError::InvalidMetadata);
    }
    let nonce = random_bytes(AES_NONCE_BYTES).map_err(EnvelopeError::from)?;
    let aad = wrapper_aad_bytes(&wrapper)?;
    let (ciphertext, tag) =
        aes256_gcm_encrypt(wrapping_key, &nonce, package, &aad).map_err(EnvelopeError::from)?;
    Ok(SlotFile::OsBacked(OsBackedSlotV1 {
        envelope_format_version: SLOT_ENVELOPE_FORMAT_VERSION,
        wrapper,
        nonce_hex: hex_encode(&nonce),
        ciphertext_hex: hex_encode(&ciphertext),
        tag_hex: hex_encode(&tag),
    }))
}

/// Unwrap an OS-backed slot, authenticating metadata and ciphertext.
///
/// Authentication failure returns `AuthenticationFailed` — indistinguishable
/// wrong-key/tamper/damage, which maps to the distinct
/// `PlatformProtectionInvalidated` recovery path.
pub fn unwrap_os_backed(
    wrapping_key: &[u8],
    slot: &OsBackedSlotV1,
) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    validate_metadata(&slot.wrapper)?;
    if slot.envelope_format_version != SLOT_ENVELOPE_FORMAT_VERSION {
        return Err(EnvelopeError::UnsupportedVersion);
    }
    if wrapping_key.len() != AES_KEY_BYTES {
        return Err(EnvelopeError::InvalidMetadata);
    }
    let nonce = hex_decode(&slot.nonce_hex).map_err(|_| EnvelopeError::Malformed)?;
    let ciphertext = hex_decode(&slot.ciphertext_hex).map_err(|_| EnvelopeError::Malformed)?;
    let tag = hex_decode(&slot.tag_hex).map_err(|_| EnvelopeError::Malformed)?;
    if nonce.len() != AES_NONCE_BYTES || tag.len() != GCM_TAG_BYTES {
        return Err(EnvelopeError::Malformed);
    }
    let aad = wrapper_aad_bytes(&slot.wrapper)?;
    aes256_gcm_decrypt(wrapping_key, &nonce, &ciphertext, &tag, &aad)
        .map_err(|_| EnvelopeError::AuthenticationFailed)
}

/// Build a password-only slot (confirmed-absence fallback).
pub fn password_only_slot(generation: u64, package: &[u8]) -> SlotFile {
    SlotFile::PasswordOnly(PasswordOnlySlotV1 {
        envelope_format_version: SLOT_ENVELOPE_FORMAT_VERSION,
        generation,
        package_hex: hex_encode(package),
    })
}

/// Extract the FEAT-003 package bytes from a password-only slot.
pub fn unwrap_password_only(
    slot: &PasswordOnlySlotV1,
) -> Result<Zeroizing<Vec<u8>>, EnvelopeError> {
    if slot.envelope_format_version != SLOT_ENVELOPE_FORMAT_VERSION {
        return Err(EnvelopeError::UnsupportedVersion);
    }
    let bytes = hex_decode(&slot.package_hex).map_err(|_| EnvelopeError::Malformed)?;
    Ok(Zeroizing::new(bytes))
}

/// Canonical wrapper AAD metadata object (deterministic across runtimes).
fn wrapper_aad_object(wrapper: &WrapperMetadataV1) -> serde_json::Value {
    serde_json::json!({
        "binding": "hush/vault/wrapper-aad/v1",
        "wrapperFormatVersion": wrapper.wrapper_format_version,
        "adapterId": wrapper.adapter_id,
        "applicationId": wrapper.application_id,
        "releaseChannel": wrapper.release_channel.as_str(),
        "generation": wrapper.generation,
        "purpose": wrapper.purpose,
    })
}

/// Canonical JCS bytes for the wrapper metadata (AAD).
fn wrapper_aad_bytes(wrapper: &WrapperMetadataV1) -> Result<Vec<u8>, EnvelopeError> {
    crate::ubuntu_vault::crypto::jcs::canonicalize_json(&wrapper_aad_object(wrapper))
        .map_err(|_| EnvelopeError::Malformed)
}

/// Fixed-vocabulary + identity-free + bounds validation of wrapper metadata.
fn validate_metadata(wrapper: &WrapperMetadataV1) -> Result<(), EnvelopeError> {
    if wrapper.wrapper_format_version != crate::ubuntu_vault::WRAPPER_FORMAT_VERSION {
        return Err(EnvelopeError::UnsupportedVersion);
    }
    if !wrapper.matches_fixed_vocabulary() || !wrapper.is_identity_free() || !wrapper.is_bounded() {
        return Err(EnvelopeError::InvalidMetadata);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ubuntu_vault::contracts::wrapper::{ReleaseChannel, WrapperMetadataV1};
    use crate::ubuntu_vault::crypto::encoding::hex_decode;

    fn sample_wrapper(generation: u64) -> WrapperMetadataV1 {
        WrapperMetadataV1 {
            wrapper_format_version: crate::ubuntu_vault::WRAPPER_FORMAT_VERSION,
            adapter_id: crate::ubuntu_vault::ADAPTER_ID.to_string(),
            application_id: crate::ubuntu_vault::APPLICATION_ID.to_string(),
            release_channel: ReleaseChannel::Production,
            generation,
            purpose: crate::ubuntu_vault::ITEM_PURPOSE.to_string(),
        }
    }

    fn test_key() -> Vec<u8> {
        vec![0x5au8; 32]
    }

    #[test]
    fn os_backed_round_trips_and_authenticates() {
        let key = test_key();
        let package = b"feat-003-password-protected-package-bytes";
        let slot = wrap_os_backed(&key, package, sample_wrapper(7)).unwrap();
        assert_eq!(slot.mode(), ProtectionMode::OsBacked);
        assert_eq!(slot.generation(), 7);
        let inner = unwrap_os_backed(
            &key,
            match &slot {
                SlotFile::OsBacked(s) => s,
                _ => panic!("wrong slot kind"),
            },
        )
        .unwrap();
        assert_eq!(&*inner, package);
    }

    #[test]
    fn os_backed_authenticated_metadata_binds_generation_and_purpose() {
        let key = test_key();
        let package = b"package";
        let slot = wrap_os_backed(&key, package, sample_wrapper(7)).unwrap();
        // A tampered wrapper metadata (generation) must fail authentication.
        let mut tampered = match &slot {
            SlotFile::OsBacked(s) => s.clone(),
            _ => panic!("wrong kind"),
        };
        tampered.wrapper.generation = 8;
        assert_eq!(
            unwrap_os_backed(&key, &tampered),
            Err(EnvelopeError::AuthenticationFailed)
        );
        // Wrong key is indistinguishable from tamper (same closed code).
        let wrong_key = vec![0x99u8; 32];
        let original = match &slot {
            SlotFile::OsBacked(s) => s,
            _ => panic!("wrong kind"),
        };
        assert_eq!(
            unwrap_os_backed(&wrong_key, original),
            Err(EnvelopeError::AuthenticationFailed)
        );
    }

    #[test]
    fn tampered_ciphertext_fails_closed() {
        let key = test_key();
        let slot = wrap_os_backed(&key, b"payload", sample_wrapper(1)).unwrap();
        let mut damaged = match slot {
            SlotFile::OsBacked(s) => s,
            _ => panic!("wrong kind"),
        };
        let bytes = hex_decode(&damaged.ciphertext_hex).unwrap();
        damaged.ciphertext_hex = hex_encode(&{
            let mut b = bytes;
            b[0] ^= 0x01;
            b
        });
        assert_eq!(
            unwrap_os_backed(&key, &damaged),
            Err(EnvelopeError::AuthenticationFailed)
        );
    }

    #[test]
    fn unknown_envelope_fields_are_rejected() {
        let json = r#"{"mode":"osBacked","envelopeFormatVersion":1,"wrapper":{"wrapperFormatVersion":1,"adapterId":"ubuntu-secret-service-v1","applicationId":"com.hushvoting.client","releaseChannel":"production","generation":7,"purpose":"vault-wrapper"},"nonceHex":"00","ciphertextHex":"00","tagHex":"00","sneaky":true}"#;
        assert!(serde_json::from_str::<SlotFile>(json).is_err());
        let po_json = r#"{"mode":"passwordOnly","envelopeFormatVersion":1,"generation":1,"packageHex":"00","extra":1}"#;
        assert!(serde_json::from_str::<SlotFile>(po_json).is_err());
    }

    #[test]
    fn unsupported_format_version_fails_closed() {
        let key = test_key();
        let slot = wrap_os_backed(&key, b"payload", sample_wrapper(1)).unwrap();
        let mut unsupported = match slot {
            SlotFile::OsBacked(s) => s,
            _ => panic!("wrong kind"),
        };
        unsupported.envelope_format_version = 99;
        assert_eq!(
            unwrap_os_backed(&key, &unsupported),
            Err(EnvelopeError::UnsupportedVersion)
        );
        assert_eq!(
            EnvelopeError::UnsupportedVersion.to_native_error(),
            NativeErrorCode::WrapperVersionUnsupported
        );
    }

    #[test]
    fn password_only_slot_has_no_outer_wrapper() {
        let slot = password_only_slot(3, b"package-bytes");
        assert_eq!(slot.mode(), ProtectionMode::PasswordOnly);
        assert_eq!(slot.generation(), 3);
        let inner = match &slot {
            SlotFile::PasswordOnly(s) => unwrap_password_only(s).unwrap(),
            _ => panic!("wrong kind"),
        };
        assert_eq!(&*inner, b"package-bytes");
    }

    #[test]
    fn identity_metadata_is_rejected_before_crypto() {
        let mut wrapper = sample_wrapper(1);
        wrapper.purpose = "vault-wrapper-for-user-bob".to_string();
        assert_eq!(
            wrap_os_backed(&test_key(), b"p", wrapper),
            Err(EnvelopeError::InvalidMetadata)
        );
    }

    #[test]
    fn envelope_aad_is_deterministic_across_construction_order() {
        let key = test_key();
        let a = wrap_os_backed(&key, b"p", sample_wrapper(2)).unwrap();
        let b = wrap_os_backed(&key, b"p", sample_wrapper(2)).unwrap();
        // Nonces differ (fresh) but both unwrap under the same key — the AAD
        // is canonical and order-independent.
        let (a, b) = match (a, b) {
            (SlotFile::OsBacked(a), SlotFile::OsBacked(b)) => (a, b),
            _ => panic!("wrong kinds"),
        };
        assert_ne!(a.nonce_hex, b.nonce_hex);
        assert_eq!(
            &*unwrap_os_backed(&key, &a).unwrap(),
            &*unwrap_os_backed(&key, &b).unwrap()
        );
    }
}
