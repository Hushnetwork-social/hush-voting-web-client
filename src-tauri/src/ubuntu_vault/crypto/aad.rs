//! Purpose-bound AAD assembly (mirror of FEAT-003 `canonical/aad.ts`).
//!
//! AAD binds at least (v1): all four version axes; suite id and exact KDF
//! parameters; adapter/platform binding; allowlisted cleartext preview; vault
//! generation and record generation; record purpose; producer/version and
//! public identity binding; critical extension list. There is NO network
//! identity in v1. Moving ciphertext between record purposes, vault
//! generations, adapters, or identities fails authentication.

use crate::ubuntu_vault::crypto::jcs::canonicalize_json;
use serde::Serialize;

/// Adapter/platform binding ('logical' for corpus fixtures; 'ubuntu' for the
/// native adapter's own envelopes where approved).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum AdapterBinding {
    Logical,
    Ubuntu,
}

impl AdapterBinding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Logical => "logical",
            Self::Ubuntu => "ubuntu",
        }
    }
}

/// AAD binding inputs — every field is authenticated.
#[derive(Debug, Clone, Serialize)]
pub struct AadInputs {
    pub envelope_format_version: u32,
    pub parameter_suite_version: u32,
    pub record_schema_version: u32,
    pub platform_wrapper_version: u32,
    pub suite_id: String,
    pub kdf: KdfParameters,
    pub adapter_binding: AdapterBinding,
    pub preview: VaultPreviewV1,
    pub vault_generation: u64,
    pub record_generation: u64,
    pub record_purpose: RecordPurpose,
    pub producer: Producer,
    /// Public signing-address binding (identity binding; no private material).
    pub signing_address: String,
    pub critical_extensions: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct KdfParameters {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

/// Allowlisted cleartext preview fields (never authorization proof).
#[derive(Debug, Clone, Serialize)]
pub struct VaultPreviewV1 {
    pub alias: String,
    pub signing_address_prefix: String,
    pub signing_address_suffix: String,
    pub lifecycle_status: String,
    pub envelope_format_version: u32,
    pub parameter_suite_version: u32,
    pub record_schema_version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum RecordPurpose {
    Ordinary,
    Mnemonic,
}

impl RecordPurpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ordinary => "ordinary",
            Self::Mnemonic => "mnemonic",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Producer {
    pub id: String,
    pub version: String,
}

impl AadInputs {
    /// Build the canonical AAD metadata object (mirror of TS
    /// `buildAadMetadata`). Field names and nesting match exactly; JCS sorts
    /// object keys so construction order is irrelevant.
    pub fn metadata_object(&self) -> serde_json::Value {
        serde_json::json!({
            "envelopeFormatVersion": self.envelope_format_version,
            "parameterSuiteVersion": self.parameter_suite_version,
            "recordSchemaVersion": self.record_schema_version,
            "platformWrapperVersion": self.platform_wrapper_version,
            "suiteId": self.suite_id,
            "kdf": {
                "algorithm": self.kdf.algorithm,
                "memoryKiB": self.kdf.memory_kib,
                "iterations": self.kdf.iterations,
                "parallelism": self.kdf.parallelism,
            },
            "adapterBinding": self.adapter_binding.as_str(),
            "preview": {
                "alias": self.preview.alias,
                "signingAddressPrefix": self.preview.signing_address_prefix,
                "signingAddressSuffix": self.preview.signing_address_suffix,
                "lifecycleStatus": self.preview.lifecycle_status,
                "envelopeFormatVersion": self.preview.envelope_format_version,
                "parameterSuiteVersion": self.preview.parameter_suite_version,
                "recordSchemaVersion": self.preview.record_schema_version,
            },
            "vaultGeneration": self.vault_generation,
            "recordGeneration": self.record_generation,
            "recordPurpose": self.record_purpose.as_str(),
            "producer": {
                "id": self.producer.id,
                "version": self.producer.version,
            },
            "signingAddress": self.signing_address,
            "criticalExtensions": self.critical_extensions.clone(),
        })
    }

    /// Canonical AAD bytes (deterministic across TypeScript and Rust).
    pub fn canonical_bytes(
        &self,
    ) -> Result<Vec<u8>, crate::ubuntu_vault::crypto::jcs::CanonicalJsonError> {
        canonicalize_json(&self.metadata_object())
    }

    /// SHA-256 of the canonical AAD bytes (corpus replay identity).
    pub fn canonical_sha256(
        &self,
    ) -> Result<String, crate::ubuntu_vault::crypto::jcs::CanonicalJsonError> {
        use sha2::{Digest, Sha256};
        let bytes = self.canonical_bytes()?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        Ok(hex_lower(&hasher.finalize()))
    }
}

/// Lowercase hex of a digest (no allocation surprises; used for corpus replay).
pub fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// Corpus fixture A-001/A-002 AAD inputs (from
    /// `conformance/vault/v1/vectors/aad-vectors.json`).
    pub fn corpus_aad_inputs(record_purpose: &str) -> AadInputs {
        AadInputs {
            envelope_format_version: 1,
            parameter_suite_version: 1,
            record_schema_version: 1,
            platform_wrapper_version: 0,
            suite_id: "hush/vault/suite/v1".to_string(),
            kdf: KdfParameters {
                algorithm: "Argon2id".to_string(),
                memory_kib: 19456,
                iterations: 2,
                parallelism: 1,
            },
            adapter_binding: AdapterBinding::Logical,
            preview: VaultPreviewV1 {
                alias: "Alice".to_string(),
                signing_address_prefix: "01234567".to_string(),
                signing_address_suffix: "89abcd".to_string(),
                lifecycle_status: "Active".to_string(),
                envelope_format_version: 1,
                parameter_suite_version: 1,
                record_schema_version: 1,
            },
            vault_generation: 1,
            record_generation: 1,
            record_purpose: match record_purpose {
                "mnemonic" => RecordPurpose::Mnemonic,
                _ => RecordPurpose::Ordinary,
            },
            producer: Producer {
                id: "hush-voting-ts".to_string(),
                version: "1.0.0".to_string(),
            },
            signing_address: "0123456789abcdef".to_string(),
            critical_extensions: vec![],
        }
    }

    #[test]
    fn corpus_a001_canonical_sha_matches_pinned_manifest() {
        // A-001 pinned inputSha256: 7f9a6ca3317e8e0134b11fae6e9c39bf580aa07df1f16f849e29fb39c6a84a03
        let sha = corpus_aad_inputs("ordinary").canonical_sha256().unwrap();
        assert_eq!(
            sha,
            "7f9a6ca3317e8e0134b11fae6e9c39bf580aa07df1f16f849e29fb39c6a84a03"
        );
    }

    #[test]
    fn corpus_a002_canonical_sha_matches_pinned_manifest() {
        // A-002 pinned inputSha256: 6dc951d1ed188d8c0639774975b8055c607142251dd88ad41f78490e97a71f51
        let sha = corpus_aad_inputs("mnemonic").canonical_sha256().unwrap();
        assert_eq!(
            sha,
            "6dc951d1ed188d8c0639774975b8055c607142251dd88ad41f78490e97a71f51"
        );
    }
}
