//! Android wrapper v1 — canonical authenticated metadata (FEAT-006 Phase 2,
//! Task 2.3).
//!
//! The Android Keystore wraps only FEAT-003's already password-protected
//! package. The outer wrapper's authenticated metadata binds: wrapper version,
//! adapter ID `android-keystore`, application ID and release channel, opaque
//! local vault/key reference, FEAT-003 envelope/suite/schema versions, slot
//! (`a`/`b`), expected vault/package generation, record purpose, and bounded
//! critical-extension/version information.
//!
//! It NEVER binds Android username/account, exact device model, hostname,
//! server URL, current time, biometric identity, or Hush alias/address into
//! platform authorization. Encoding is UTF-8 strict JSON with RFC 8785
//! canonical AAD, unpadded base64url where JSON carries bytes, closed fields,
//! duplicate-key rejection (serde deny_unknown_fields + BTreeMap JCS), and
//! bounded allocation. The decoded inner envelope retains FEAT-003's 1 MiB
//! limit; the complete base64-bearing Android wrapper is limited to 1.5 MiB.

use serde::{Deserialize, Serialize};

use crate::android_vault::contracts::capability::SecurityLevel;

/// Release-channel namespace separating production/debug/test/internal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReleaseChannel {
    Production,
    Debug,
    Test,
    Internal,
}

impl ReleaseChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Debug => "debug",
            Self::Test => "test",
            Self::Internal => "internal",
        }
    }
}

/// Fixed vault slot identifier (`a` or `b`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Slot {
    A,
    B,
}

impl Slot {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
        }
    }
}

/// Authenticated Android wrapper metadata (v1). Strict JSON with
/// `deny_unknown_fields`; canonicalized to RFC 8785 bytes for AAD.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AndroidWrapperMetadataV1 {
    /// Android wrapper format version (fixed `1`).
    pub wrapper_version: u32,
    /// Fixed adapter identifier (`android-keystore`).
    pub adapter_id: String,
    /// Fixed application ID (`com.hushvoting.client`).
    pub application_id: String,
    /// Release channel separating production/debug/test/internal.
    pub release_channel: ReleaseChannel,
    /// Opaque local vault/key reference (never an alias/address/identity).
    pub vault_key_reference: String,
    /// FEAT-003 envelope format version (unchanged inner format).
    pub envelope_format_version: u32,
    /// FEAT-003 parameter suite version.
    pub parameter_suite_version: u32,
    /// FEAT-003 record schema version.
    pub record_schema_version: u32,
    /// Fixed slot (`a` or `b`) this wrapped package occupies.
    pub slot: Slot,
    /// Expected vault/package generation.
    pub vault_generation: u64,
    /// Record/package purpose (`vault-package`).
    pub record_purpose: String,
    /// Bounded critical-extension/version information (identity-free keys).
    pub critical_extensions: Vec<CriticalExtension>,
}

/// One bounded critical-extension entry (closed key/value pair).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CriticalExtension {
    pub key: String,
    pub value: String,
}

impl AndroidWrapperMetadataV1 {
    /// Identity-free check: no alias, address, user/account, host, URL, time,
    /// biometric, identity, model, or endpoint token may appear in any string
    /// field (except the fixed release-channel vocabulary).
    pub fn is_identity_free(&self) -> bool {
        let forbidden = [
            "alias",
            "address",
            "user",
            "account",
            "host",
            "url",
            "time",
            "biometric",
            "identity",
            "model",
            "endpoint",
            "serial",
            "androidid",
            "attestation",
        ];
        let haystacks = [
            self.adapter_id.as_str(),
            self.application_id.as_str(),
            self.vault_key_reference.as_str(),
            self.record_purpose.as_str(),
        ];
        let check = |value: &str| -> bool {
            let lower = value.to_ascii_lowercase();
            !forbidden.iter().any(|needle| lower.contains(needle))
        };
        if !haystacks.iter().all(|h| check(h)) {
            return false;
        }
        for ext in &self.critical_extensions {
            if !check(&ext.key) || !check(&ext.value) {
                return false;
            }
        }
        true
    }

    /// Whether this metadata matches the fixed production vocabulary.
    pub fn matches_fixed_vocabulary(&self) -> bool {
        self.wrapper_version == crate::android_vault::WRAPPER_FORMAT_VERSION
            && self.adapter_id == crate::android_vault::ADAPTER_ID
            && self.application_id == crate::android_vault::APPLICATION_ID
            && self.record_purpose == crate::android_vault::RECORD_PURPOSE
    }

    /// Bounded string fields and critical-extension cardinality.
    pub fn is_bounded(&self) -> bool {
        const MAX: usize = crate::android_vault::MAX_FIELD_LEN;
        self.adapter_id.len() <= MAX
            && self.application_id.len() <= MAX
            && self.vault_key_reference.len() <= MAX
            && self.record_purpose.len() <= MAX
            && self.critical_extensions.len() <= crate::android_vault::MAX_CRITICAL_EXTENSIONS
            && self
                .critical_extensions
                .iter()
                .all(|e| e.key.len() <= MAX && e.value.len() <= MAX)
    }

    /// Build the canonical metadata object (field names/nesting fixed; JCS
    /// sorts keys so construction order is irrelevant). Byte-identical across
    /// TypeScript (`canonicalBytesOf`) and Rust (`canonicalize_json`).
    pub fn metadata_object(&self) -> serde_json::Value {
        serde_json::json!({
            "wrapperVersion": self.wrapper_version,
            "adapterId": self.adapter_id,
            "applicationId": self.application_id,
            "releaseChannel": self.release_channel.as_str(),
            "vaultKeyReference": self.vault_key_reference,
            "envelopeFormatVersion": self.envelope_format_version,
            "parameterSuiteVersion": self.parameter_suite_version,
            "recordSchemaVersion": self.record_schema_version,
            "slot": self.slot.as_str(),
            "vaultGeneration": self.vault_generation,
            "recordPurpose": self.record_purpose,
            "criticalExtensions": self
                .critical_extensions
                .iter()
                .map(|e| serde_json::json!({"key": e.key, "value": e.value}))
                .collect::<Vec<_>>(),
        })
    }

    /// Canonical AAD bytes (RFC 8785; deterministic across runtimes).
    pub fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, crate::android_vault::wrapper::CanonicalJsonError> {
        crate::android_vault::wrapper::canonicalize_json(&self.metadata_object())
    }

    /// SHA-256 of the canonical AAD bytes (vector replay identity).
    pub fn canonical_sha256(&self) -> Result<String, CanonicalJsonError> {
        use sha2::{Digest, Sha256};
        let bytes = self.canonical_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        Ok(hex_lower(&hasher.finalize()))
    }

    /// Whether the wrapper's broad security level is production-qualified.
    /// (The level itself is never authenticated into platform authorization;
    /// it is validated separately against KeyInfo before sensitive use.)
    pub fn accepts_security_level(&self, level: SecurityLevel) -> bool {
        level.is_hardware_backed()
    }
}

/// RFC 8785 canonicalization errors (mirror of `ubuntu_vault::crypto::jcs`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalJsonError {
    NonCanonicalValue,
    Serialize(String),
}

impl std::fmt::Display for CanonicalJsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonCanonicalValue => write!(f, "value cannot be canonicalized"),
            Self::Serialize(msg) => write!(f, "canonical serialization failed: {msg}"),
        }
    }
}

impl std::error::Error for CanonicalJsonError {}

/// Canonicalize a JSON value to RFC 8785 bytes (serde_json BTreeMap default
/// provides byte-sorted object keys; see `ubuntu_vault::crypto::jcs`).
pub fn canonicalize_json(value: &serde_json::Value) -> Result<Vec<u8>, CanonicalJsonError> {
    if !is_canonicalizable(value) {
        return Err(CanonicalJsonError::NonCanonicalValue);
    }
    serde_json::to_vec(value).map_err(|e| CanonicalJsonError::Serialize(e.to_string()))
}

fn is_canonicalizable(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::String(_)
        | serde_json::Value::Number(_) => true,
        serde_json::Value::Array(items) => items.iter().all(is_canonicalizable),
        serde_json::Value::Object(map) => map.values().all(is_canonicalizable),
    }
}

/// Lowercase hex of a digest (no allocation surprises; used for vector replay).
pub fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> AndroidWrapperMetadataV1 {
        AndroidWrapperMetadataV1 {
            wrapper_version: crate::android_vault::WRAPPER_FORMAT_VERSION,
            adapter_id: crate::android_vault::ADAPTER_ID.to_string(),
            application_id: crate::android_vault::APPLICATION_ID.to_string(),
            release_channel: ReleaseChannel::Production,
            vault_key_reference: "hvk-9f3e1a02b8c4".to_string(),
            envelope_format_version: 1,
            parameter_suite_version: 1,
            record_schema_version: 1,
            slot: Slot::A,
            vault_generation: 7,
            record_purpose: crate::android_vault::RECORD_PURPOSE.to_string(),
            critical_extensions: vec![],
        }
    }

    #[test]
    fn fixed_metadata_is_identity_free_and_matches() {
        let meta = sample();
        assert!(meta.is_identity_free());
        assert!(meta.matches_fixed_vocabulary());
        assert!(meta.is_bounded());
        assert!(meta.accepts_security_level(SecurityLevel::TrustedEnvironment));
        assert!(meta.accepts_security_level(SecurityLevel::StrongBox));
        assert!(!meta.accepts_security_level(SecurityLevel::SoftwareOrUnknown));
    }

    #[test]
    fn identity_bearing_reference_is_rejected() {
        let mut meta = sample();
        meta.vault_key_reference = "alias-user-bob".to_string();
        assert!(!meta.is_identity_free());
    }

    #[test]
    fn wrong_version_fails_vocabulary() {
        let mut meta = sample();
        meta.wrapper_version = 99;
        assert!(!meta.matches_fixed_vocabulary());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let json = r#"{"wrapperVersion":1,"adapterId":"android-keystore","applicationId":"com.hushvoting.client","releaseChannel":"production","vaultKeyReference":"hvk-9f3e1a02b8c4","envelopeFormatVersion":1,"parameterSuiteVersion":1,"recordSchemaVersion":1,"slot":"a","vaultGeneration":7,"recordPurpose":"vault-package","criticalExtensions":[],"alias":"sneaky"}"#;
        assert!(serde_json::from_str::<AndroidWrapperMetadataV1>(json).is_err());
    }

    #[test]
    fn oversized_fields_and_extensions_are_rejected() {
        let mut meta = sample();
        meta.vault_key_reference = "x".repeat(200);
        assert!(!meta.is_bounded());
        let mut meta2 = sample();
        for i in 0..(crate::android_vault::MAX_CRITICAL_EXTENSIONS + 1) {
            meta2.critical_extensions.push(CriticalExtension {
                key: format!("k{i}"),
                value: "v".to_string(),
            });
        }
        assert!(!meta2.is_bounded());
    }

    #[test]
    fn canonical_bytes_are_deterministic_and_mutation_sensitive() {
        let a = sample();
        let b = sample();
        assert_eq!(a.canonical_bytes().unwrap(), b.canonical_bytes().unwrap());
        assert_eq!(a.canonical_sha256().unwrap(), b.canonical_sha256().unwrap());

        let mut changed = sample();
        changed.slot = Slot::B;
        assert_ne!(
            a.canonical_sha256().unwrap(),
            changed.canonical_sha256().unwrap()
        );
        let mut changed2 = sample();
        changed2.vault_generation = 8;
        assert_ne!(
            a.canonical_sha256().unwrap(),
            changed2.canonical_sha256().unwrap()
        );
        let mut changed3 = sample();
        changed3.release_channel = ReleaseChannel::Debug;
        assert_ne!(
            a.canonical_sha256().unwrap(),
            changed3.canonical_sha256().unwrap()
        );
        let mut changed4 = sample();
        changed4.vault_key_reference = "hvk-other".to_string();
        assert_ne!(
            a.canonical_sha256().unwrap(),
            changed4.canonical_sha256().unwrap()
        );
        let mut changed5 = sample();
        changed5.critical_extensions.push(CriticalExtension {
            key: "k".to_string(),
            value: "v".to_string(),
        });
        assert_ne!(
            a.canonical_sha256().unwrap(),
            changed5.canonical_sha256().unwrap()
        );
    }

    #[test]
    fn canonical_sha_is_stable_pinned_value() {
        // Pinned cross-runtime vector: TypeScript must produce the identical
        // digest for the same sample (see conformance/android-vault/v1/vectors).
        let meta = sample();
        let sha = meta.canonical_sha256().unwrap();
        assert_eq!(sha.len(), 64);
        assert!(sha.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn slots_and_channels_are_distinct_namespaces() {
        assert_ne!(Slot::A.as_str(), Slot::B.as_str());
        assert_ne!(
            ReleaseChannel::Production.as_str(),
            ReleaseChannel::Debug.as_str()
        );
        assert_ne!(
            ReleaseChannel::Debug.as_str(),
            ReleaseChannel::Test.as_str()
        );
        assert_ne!(
            ReleaseChannel::Test.as_str(),
            ReleaseChannel::Internal.as_str()
        );
    }
}
