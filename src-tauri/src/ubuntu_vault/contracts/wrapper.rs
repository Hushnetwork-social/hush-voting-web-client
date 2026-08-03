//! Wrapper metadata and release-channel contract (FEAT-005
//! "Default/login collection" + "Wrapper-key construction").
//!
//! The wrapping item's authenticated metadata binds wrapper version, adapter
//! ID, application ID/release channel, package generation, and record purpose.
//! It NEVER binds provider name, Ubuntu username, machine hostname, or
//! endpoint into cryptographic authorization, and never contains alias,
//! blockchain address, mnemonic status, network, or vault generation labels
//! in human-readable attributes.

use serde::{Deserialize, Serialize};

/// Fixed release-channel namespace separating production/development/test.
/// Entries never collide across channels.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ReleaseChannel {
    Production,
    Development,
    Test,
}

impl ReleaseChannel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Development => "development",
            Self::Test => "test",
        }
    }
}

/// Authenticated wrapper metadata (v1). Serialized into the outer wrapper
/// envelope and validated on read-back; used for duplicate-item key testing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WrapperMetadataV1 {
    /// Integer wrapper format version (fixed value `1` at this release).
    pub wrapper_format_version: u32,
    /// Fixed adapter identifier (`ubuntu-secret-service-v1`).
    pub adapter_id: String,
    /// Fixed application ID (`com.hushvoting.client`).
    pub application_id: String,
    /// Release channel separating production/development/test.
    pub release_channel: ReleaseChannel,
    /// Vault package generation the wrapper protects.
    pub generation: u64,
    /// Fixed record purpose (`vault-wrapper`).
    pub purpose: String,
}

impl WrapperMetadataV1 {
    /// Identity-free attribute check: no alias, address, username/UID,
    /// mnemonic status, endpoint, network, or hostname may appear.
    pub fn is_identity_free(&self) -> bool {
        let forbidden = [
            "alias", "address", "user", "uid", "mnemonic", "endpoint", "network", "host", "profile",
        ];
        let haystacks = [
            self.adapter_id.as_str(),
            self.application_id.as_str(),
            self.purpose.as_str(),
        ];
        for needle in forbidden {
            for haystack in haystacks {
                if haystack.to_ascii_lowercase().contains(needle) {
                    return false;
                }
            }
        }
        // Release channel and generation must stay out of item attributes too,
        // but the metadata itself is authenticated (not a label).
        true
    }

    /// Whether this metadata matches the fixed production vocabulary.
    pub fn matches_fixed_vocabulary(&self) -> bool {
        self.wrapper_format_version == crate::ubuntu_vault::WRAPPER_FORMAT_VERSION
            && self.adapter_id == crate::ubuntu_vault::ADAPTER_ID
            && self.application_id == crate::ubuntu_vault::APPLICATION_ID
            && self.purpose == crate::ubuntu_vault::ITEM_PURPOSE
    }

    /// Bounded string fields (identity-free and size-bounded).
    pub fn is_bounded(&self) -> bool {
        const MAX_FIELD_LEN: usize = 64;
        self.adapter_id.len() <= MAX_FIELD_LEN
            && self.application_id.len() <= MAX_FIELD_LEN
            && self.purpose.len() <= MAX_FIELD_LEN
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> WrapperMetadataV1 {
        WrapperMetadataV1 {
            wrapper_format_version: 1,
            adapter_id: crate::ubuntu_vault::ADAPTER_ID.to_string(),
            application_id: crate::ubuntu_vault::APPLICATION_ID.to_string(),
            release_channel: ReleaseChannel::Production,
            generation: 7,
            purpose: crate::ubuntu_vault::ITEM_PURPOSE.to_string(),
        }
    }

    #[test]
    fn fixed_metadata_is_identity_free_and_matches() {
        let meta = sample();
        assert!(meta.is_identity_free());
        assert!(meta.matches_fixed_vocabulary());
    }

    #[test]
    fn identity_metadata_is_rejected() {
        let mut meta = sample();
        meta.purpose = "vault-wrapper-for-user-bob".to_string();
        assert!(!meta.is_identity_free());
    }

    #[test]
    fn wrong_version_fails_vocabulary() {
        let mut meta = sample();
        meta.wrapper_format_version = 99;
        assert!(!meta.matches_fixed_vocabulary());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let json = r#"{"wrapperFormatVersion":1,"adapterId":"ubuntu-secret-service-v1","applicationId":"com.hushvoting.client","releaseChannel":"production","generation":7,"purpose":"vault-wrapper","alias":"sneaky"}"#;
        assert!(serde_json::from_str::<WrapperMetadataV1>(json).is_err());
    }

    #[test]
    fn oversized_metadata_fields_are_rejected() {
        let mut meta = sample();
        meta.application_id = "x".repeat(200);
        assert!(!meta.is_bounded());
        let ok = sample();
        assert!(ok.is_bounded());
    }

    #[test]
    fn channels_are_distinct_namespaces() {
        assert_ne!(
            ReleaseChannel::Production.as_str(),
            ReleaseChannel::Development.as_str()
        );
        assert_ne!(
            ReleaseChannel::Development.as_str(),
            ReleaseChannel::Test.as_str()
        );
    }
}
