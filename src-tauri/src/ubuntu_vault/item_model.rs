//! Secret Service item and qualification model (FEAT-005 Phase 2, Task 2.3).
//!
//! Defines the fixed item attribute vocabulary, the one-active/one-staged
//! cardinality model, deterministic duplicate/orphan/invalidation states, and
//! the qualification evidence model. Item attributes contain no identity or
//! OS-user metadata; search order never selects a key.

use serde::{Deserialize, Serialize};

/// Fixed secret-item attribute keys (Secret Service item attributes).
/// Values are identity-free: no alias, Ubuntu username/UID, blockchain
/// address, profile ID, mnemonic status, endpoint, network, or vault
/// generation appears in any attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ItemAttributeKey {
    ApplicationId,
    ReleaseChannel,
    Purpose,
    WrapperFormatVersion,
}

impl ItemAttributeKey {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ApplicationId => "application-id",
            Self::ReleaseChannel => "release-channel",
            Self::Purpose => "purpose",
            Self::WrapperFormatVersion => "wrapper-format-version",
        }
    }
}

/// One item model: fixed attribute set + opaque key probe result.
/// The `validates_generation` flag is only set after authenticated
/// outer-wrapper data (AAD) confirms the key value — search order is never
/// used to select a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretItemModel {
    /// Deterministic item index (not the D-Bus object path).
    pub item_index: u64,
    pub application_id: String,
    pub release_channel: String,
    pub purpose: String,
    pub wrapper_format_version: u32,
    /// Whether this item's secret value validated the authenticated wrapper
    /// (only meaningful after a probe).
    pub validates_wrapper: bool,
    /// Staged (rotation temporary) vs active.
    pub staged: bool,
}

/// Deterministic classification of the inspected item set. Zero or multiple
/// distinct validating keys preserve all artifacts and require recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ItemCardinality {
    /// No items and no vault files → fresh provisioning.
    None,
    /// Exactly one active item matching fixed attributes.
    OneActive,
    /// One staged item plus one active (rotation in progress).
    ActiveWithStaged,
    /// Multiple matching items where exactly one distinct key validates.
    DuplicatesOneValid,
    /// Zero or multiple distinct validating keys → ambiguous; preserve all.
    Ambiguous,
    /// Item present but no vault/tombstone files → orphan.
    Orphan,
    /// Item missing but vault files exist → protection invalidated.
    MissingWithFiles,
    /// Item attributes or wrapper version mismatch the fixed vocabulary.
    StaleOrUnsupported,
}

impl ItemCardinality {
    /// Whether the state requires portable recovery (no guessing/deletion).
    pub fn requires_recovery(self) -> bool {
        matches!(
            self,
            Self::Ambiguous | Self::MissingWithFiles | Self::StaleOrUnsupported
        )
    }

    /// Whether cleanup is allowed at all (always gated by the target's
    /// verified preconditions: successful device-password unlock, exact
    /// online identity verification, explicit repair confirmation).
    pub fn cleanup_permitted_precondition(self) -> bool {
        matches!(self, Self::DuplicatesOneValid | Self::Orphan)
    }
}

/// Qualification evidence model: provider name is NEVER proof. Qualification
/// requires build-pinned evidence plus live capability checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct QualificationEvidenceRef {
    /// Build-pinned qualification bundle version (digest pinned in release).
    pub qualification_bundle_version: u32,
    /// Live capability probe completed (unlock/prompt/replacement/lock/
    /// restart/fault/package/accessibility/lifecycle suite).
    pub live_capability_checks_passed: bool,
}

impl QualificationEvidenceRef {
    pub fn is_qualified(self) -> bool {
        self.qualification_bundle_version > 0 && self.live_capability_checks_passed
    }
}

/// Lookup classification decision (deterministic, order-independent).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ItemLookupDecision {
    pub cardinality: ItemCardinality,
    /// True only when exactly one distinct key value validated.
    pub single_validating_key: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn item(index: u64, channel: &str, validates: bool) -> SecretItemModel {
        SecretItemModel {
            item_index: index,
            application_id: "com.hushvoting.client".to_string(),
            release_channel: channel.to_string(),
            purpose: "vault-wrapper".to_string(),
            wrapper_format_version: 1,
            validates_wrapper: validates,
            staged: false,
        }
    }

    #[test]
    fn duplicate_keys_are_not_guessed() {
        // Several matching items, zero validating → ambiguous, recovery needed.
        let decision = ItemLookupDecision {
            cardinality: ItemCardinality::Ambiguous,
            single_validating_key: false,
        };
        assert!(decision.cardinality.requires_recovery());
        assert!(!decision.cardinality.cleanup_permitted_precondition());
    }

    #[test]
    fn exactly_one_validating_key_among_duplicates_allows_verified_cleanup() {
        let decision = ItemLookupDecision {
            cardinality: ItemCardinality::DuplicatesOneValid,
            single_validating_key: true,
        };
        assert!(decision.cardinality.cleanup_permitted_precondition());
        assert!(!decision.cardinality.requires_recovery());
    }

    #[test]
    fn release_channels_never_collide() {
        let prod = item(1, "production", true);
        let dev = item(2, "development", true);
        // The channel separates the namespaces; the application ID is shared
        // across channels by design (same app, distinct production/dev/test
        // wrapping entries).
        assert_ne!(prod.release_channel, dev.release_channel);
        assert_eq!(prod.application_id, dev.application_id);
    }

    #[test]
    fn qualification_requires_evidence_plus_live_checks() {
        assert!(!QualificationEvidenceRef {
            qualification_bundle_version: 0,
            live_capability_checks_passed: true,
        }
        .is_qualified());
        assert!(!QualificationEvidenceRef {
            qualification_bundle_version: 1,
            live_capability_checks_passed: false,
        }
        .is_qualified());
        assert!(QualificationEvidenceRef {
            qualification_bundle_version: 1,
            live_capability_checks_passed: true,
        }
        .is_qualified());
    }

    #[test]
    fn missing_with_files_is_invalidated_not_orphan() {
        assert!(ItemCardinality::MissingWithFiles.requires_recovery());
        assert!(!ItemCardinality::Orphan.requires_recovery());
        assert!(ItemCardinality::Orphan.cleanup_permitted_precondition());
    }

    #[test]
    fn active_with_staged_rotation_never_requires_recovery() {
        assert!(!ItemCardinality::ActiveWithStaged.requires_recovery());
        assert!(!ItemCardinality::OneActive.requires_recovery());
    }

    #[test]
    fn unknown_item_fields_are_rejected() {
        let json = r#"{"itemIndex":1,"applicationId":"com.hushvoting.client","releaseChannel":"production","purpose":"vault-wrapper","wrapperFormatVersion":1,"validatesWrapper":true,"staged":false,"path":"/home/user/.local/share"}"#;
        assert!(serde_json::from_str::<SecretItemModel>(json).is_err());
    }
}
