//! Removal contract (FEAT-005 "Local-User Removal").
//!
//! Tombstone-backed, resumable, password-independent local-user removal. The
//! tombstone is persisted before any destructive step and cleared only after
//! verified absence of both keyring items and vault files. The stages mirror
//! FEAT-003's operational sidecar removal stages, adapted to the native
//! boundary (session revocation and cache clearing are Phase 4 session
//! authority markers; file/keyring cleanup and absence verification are the
//! Phase 3 storage/keyring responsibilities).

use serde::{Deserialize, Serialize};

/// Removal cleanup stages (idempotent resume order; mirror of FEAT-003
/// `RemovalStage`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemovalStage {
    /// Revoke session handles and invalidate the epoch (Phase 4 authority).
    RevokingSession,
    /// Persist the removal tombstone before any destructive step.
    PersistingTombstone,
    /// Delete active/rollback/staged vault files and identity sidecars.
    DeletingSlots,
    /// Delete active and staged keyring entries and verify search absence.
    DeletingKeys,
    /// Clear caches and non-approved preference state (Phase 4 authority).
    ClearingCaches,
    /// Re-verify all required artifacts are absent; clear the tombstone.
    VerifyingAbsence,
}

/// Ordered idempotent removal stages.
pub const REMOVAL_STAGES: &[RemovalStage] = &[
    RemovalStage::RevokingSession,
    RemovalStage::PersistingTombstone,
    RemovalStage::DeletingSlots,
    RemovalStage::DeletingKeys,
    RemovalStage::ClearingCaches,
    RemovalStage::VerifyingAbsence,
];

impl RemovalStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RevokingSession => "revoking-session",
            Self::PersistingTombstone => "persisting-tombstone",
            Self::DeletingSlots => "deleting-slots",
            Self::DeletingKeys => "deleting-keys",
            Self::ClearingCaches => "clearing-caches",
            Self::VerifyingAbsence => "verifying-absence",
        }
    }
}

/// Durable removal tombstone v1 (only while removal is incomplete).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemovalTombstoneV1 {
    pub in_progress: bool,
    pub started_at_ms: u64,
    pub stage: RemovalStage,
}

impl RemovalTombstoneV1 {
    pub fn new(started_at_ms: u64) -> Self {
        Self {
            in_progress: true,
            started_at_ms,
            stage: RemovalStage::PersistingTombstone,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stages_are_ordered_and_closed() {
        assert_eq!(REMOVAL_STAGES.len(), 6);
        assert_eq!(REMOVAL_STAGES[0], RemovalStage::RevokingSession);
        assert_eq!(REMOVAL_STAGES[5], RemovalStage::VerifyingAbsence);
        for stage in REMOVAL_STAGES {
            assert!(!stage.as_str().is_empty());
        }
    }

    #[test]
    fn tombstone_round_trips_without_secrets() {
        let tombstone = RemovalTombstoneV1::new(1_700_000_000_123);
        let json = serde_json::to_string(&tombstone).unwrap();
        let back: RemovalTombstoneV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(tombstone, back);
        assert!(json.contains("\"inProgress\":true"));
        assert!(!json.contains("password"));
    }

    #[test]
    fn unknown_tombstone_fields_are_rejected() {
        let json = r#"{"inProgress":true,"startedAtMs":123,"stage":"deletingSlots","alias":"x"}"#;
        assert!(serde_json::from_str::<RemovalTombstoneV1>(json).is_err());
    }
}
