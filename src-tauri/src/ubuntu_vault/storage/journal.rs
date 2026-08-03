//! Journal model with generation compare-and-swap (FEAT-003 two-slot atomic
//! journal; FEAT-005 durable atomic commit steps 7–10).
//!
//! The journal is written atomically AFTER the inactive slot is written,
//! opened, parsed, unwrapped, authenticated, and validated, and only after an
//! expected-generation recheck. There is no last-write-wins or arbitrary JSON
//! merge. The rollback slot is the fixed inactive slot (the other of the two
//! slot artifacts); the journal records the active slot explicitly so the
//! writer is deterministic regardless of process restarts.

use serde::{Deserialize, Serialize};

use crate::ubuntu_vault::storage::layout::VaultArtifact;

/// Journal state (FEAT-003 lifecycle semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JournalState {
    Active,
    PendingRotation,
    RemovalInProgress,
    Migration,
}

fn default_active_slot() -> VaultArtifact {
    VaultArtifact::SlotA
}

/// One journal record: expected-generation CAS plus rollback window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JournalRecord {
    /// Schema/format version of this record.
    pub format_version: u32,
    pub state: JournalState,
    /// Active generation this journal points to.
    pub active_generation: u64,
    /// Generation the writer expected when committing (CAS guard).
    pub expected_generation: u64,
    /// Retained rollback generation (bounded; removed after next successful
    /// unlock or 24h, whichever is observed first).
    pub retained_generation: Option<u64>,
    /// The authoritative slot artifact (which of slot-a/slot-b is active).
    #[serde(default = "default_active_slot")]
    pub active_slot: VaultArtifact,
    /// Epoch-ms timestamp when the active slot was last fully verified
    /// (next-success/24h rollback-window anchor; `None` = never verified).
    #[serde(default)]
    pub active_verified_at_ms: Option<u64>,
}

impl JournalRecord {
    pub fn new(active_generation: u64) -> Self {
        Self {
            format_version: 1,
            state: JournalState::Active,
            active_generation,
            expected_generation: active_generation,
            retained_generation: None,
            active_slot: VaultArtifact::SlotA,
            active_verified_at_ms: None,
        }
    }

    /// CAS check: the caller's expected generation must equal the active one.
    pub fn generation_matches(&self, expected: u64) -> bool {
        self.active_generation == expected
    }
}

/// Sidecar record (bounded, non-secret; never authorization proof).
///
/// The protection mode is mirrored from the authoritative active slot
/// envelope and reconciled at open; the throttle counter/deadline are
/// operational state with the FEAT-003/004 bounds. The `state_digest_hex`
/// authenticates this non-secret state so tampering is detected (fail
/// closed) without ever carrying secret material. The removal tombstone
/// lives in its own `removal.tombstone` file (authoritative, resumable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SidecarRecord {
    pub format_version: u32,
    /// Coarse protection mode (non-secret; see contracts::protection).
    pub protection_mode: String,
    /// Persisted acknowledgement state for password-only fallback.
    pub fallback_acknowledged: bool,
    /// Bounded failed device-password counter (0–255; FEAT-003 throttle).
    pub failed_password_count: u8,
    /// Epoch-ms cooldown deadline; 0 = no active cooldown.
    pub cooldown_deadline_ms: u64,
    /// SHA-256 digest of the canonical non-secret state (authenticated
    /// projection; tamper detection only, never secret-bearing).
    pub state_digest_hex: String,
}

impl SidecarRecord {
    pub fn fresh() -> Self {
        Self {
            format_version: 1,
            protection_mode: String::new(),
            fallback_acknowledged: false,
            failed_password_count: 0,
            cooldown_deadline_ms: 0,
            state_digest_hex: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cas_rejects_stale_writer() {
        let record = JournalRecord::new(5);
        assert!(record.generation_matches(5));
        assert!(!record.generation_matches(4));
        assert!(!record.generation_matches(6));
    }

    #[test]
    fn journal_round_trips_without_secrets() {
        let record = JournalRecord::new(3);
        let json = serde_json::to_string(&record).unwrap();
        let back: JournalRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
        assert!(!json.contains("password") && !json.contains("key"));
    }

    #[test]
    fn rotation_state_carries_retained_generation() {
        let mut record = JournalRecord::new(9);
        record.state = JournalState::PendingRotation;
        record.retained_generation = Some(8);
        assert_eq!(record.retained_generation, Some(8));
    }

    #[test]
    fn journal_tracks_active_slot_and_verified_at() {
        let mut record = JournalRecord::new(4);
        record.active_slot = VaultArtifact::SlotB;
        record.active_verified_at_ms = Some(1_700_000_000_123);
        let json = serde_json::to_string(&record).unwrap();
        let back: JournalRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back.active_slot, VaultArtifact::SlotB);
        assert_eq!(back.active_verified_at_ms, Some(1_700_000_000_123));
    }

    #[test]
    fn old_journal_records_without_slot_fields_deserialize_safely() {
        // Pre-FEAT-005-phase-3 records had no active_slot/verified-at fields;
        // they must load with the safe default (SlotA, no verified anchor).
        let json = r#"{"formatVersion":1,"state":"active","activeGeneration":2,"expectedGeneration":2,"retainedGeneration":null}"#;
        let back: JournalRecord = serde_json::from_str(json).unwrap();
        assert_eq!(back.active_slot, VaultArtifact::SlotA);
        assert_eq!(back.active_verified_at_ms, None);
    }

    #[test]
    fn unknown_journal_fields_are_rejected() {
        let json = r#"{"formatVersion":1,"state":"active","activeGeneration":1,"expectedGeneration":1,"retainedGeneration":null,"garbage":true}"#;
        assert!(serde_json::from_str::<JournalRecord>(json).is_err());
    }

    #[test]
    fn sidecar_round_trips_without_secrets() {
        let mut record = SidecarRecord::fresh();
        record.protection_mode = "os-backed".to_string();
        record.failed_password_count = 2;
        record.state_digest_hex = "ab".repeat(32);
        let json = serde_json::to_string(&record).unwrap();
        let back: SidecarRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
        assert!(!json.contains("password") && !json.contains("secret"));
    }

    #[test]
    fn sidecar_unknown_fields_are_rejected() {
        let json = r#"{"formatVersion":1,"protectionMode":"os-backed","fallbackAcknowledged":false,"failedPasswordCount":0,"cooldownDeadlineMs":0,"stateDigestHex":"aa","rawSecret":true}"#;
        assert!(serde_json::from_str::<SidecarRecord>(json).is_err());
    }
}
