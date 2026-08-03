//! Journal model with generation compare-and-swap (FEAT-003 two-slot atomic
//! journal; FEAT-005 durable atomic commit steps 7–10).
//!
//! The journal is written atomically AFTER the inactive slot is written,
//! opened, parsed, unwrapped, authenticated, and validated, and only after an
//! expected-generation recheck. There is no last-write-wins or arbitrary JSON
//! merge.

use serde::{Deserialize, Serialize};

/// Journal state (FEAT-003 lifecycle semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum JournalState {
    Active,
    PendingRotation,
    RemovalInProgress,
    Migration,
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
}

impl JournalRecord {
    pub fn new(active_generation: u64) -> Self {
        Self {
            format_version: 1,
            state: JournalState::Active,
            active_generation,
            expected_generation: active_generation,
            retained_generation: None,
        }
    }

    /// CAS check: the caller's expected generation must equal the active one.
    pub fn generation_matches(&self, expected: u64) -> bool {
        self.active_generation == expected
    }
}

/// Sidecar record (bounded, non-secret; never authorization proof).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SidecarRecord {
    pub format_version: u32,
    /// Coarse protection mode (non-secret; see contracts::protection).
    pub protection_mode: String,
    /// Persisted acknowledgement state for password-only fallback.
    pub fallback_acknowledged: bool,
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
    fn unknown_journal_fields_are_rejected() {
        let json = r#"{"formatVersion":1,"state":"active","activeGeneration":1,"expectedGeneration":1,"retainedGeneration":null,"garbage":true}"#;
        assert!(serde_json::from_str::<JournalRecord>(json).is_err());
    }
}
