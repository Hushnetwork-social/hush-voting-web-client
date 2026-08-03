//! Fixed no-backup storage model (FEAT-006 Phase 2, Task 2.3).
//!
//! Persistent vault state lives ONLY under the fixed application-internal
//! root `<noBackupFilesDir>/vault/v1/`. Caller-controlled paths never exist;
//! file names are fixed and identity-neutral (no alias/address-derived names).
//! Kotlin never stores vault data in SharedPreferences or Room. Startup
//! inspection is bounded and non-decrypting; a crash-created orphan or staged
//! key never becomes a false first-run state. This module defines the schemas
//! and strict bounds; the durable two-slot commit writer lands in Phase 3.

use serde::{Deserialize, Serialize};

use crate::android_vault::contracts::capability::KeyState;
use crate::android_vault::contracts::result::AndroidResultCode;

/// Schema version of the storage model (independent of the wrapper version).
pub const STORAGE_SCHEMA_VERSION: u32 = 1;

/// Fixed file set under the vault root (identity-neutral, no caller paths).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VaultFile {
    SlotA,
    SlotB,
    Journal,
    Sidecars,
    Tombstone,
    Lock,
}

impl VaultFile {
    pub fn file_name(self) -> &'static str {
        match self {
            Self::SlotA => crate::android_vault::SLOT_A_FILE,
            Self::SlotB => crate::android_vault::SLOT_B_FILE,
            Self::Journal => crate::android_vault::JOURNAL_FILE,
            Self::Sidecars => crate::android_vault::SIDECARS_FILE,
            Self::Tombstone => crate::android_vault::TOMBSTONE_FILE,
            Self::Lock => crate::android_vault::LOCK_FILE,
        }
    }

    /// Every fixed file name (exact, closed; used by the fixed-root writer).
    pub const ALL: &'static [VaultFile] = &[
        VaultFile::SlotA,
        VaultFile::SlotB,
        VaultFile::Journal,
        VaultFile::Sidecars,
        VaultFile::Tombstone,
        VaultFile::Lock,
    ];
}

/// Bounded journal record: expected generation CAS + active/staged key
/// references (opaque, identity-neutral). No timestamps, no identity fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct JournalRecord {
    pub schema_version: u32,
    /// Expected active generation for generation-CAS commits.
    pub expected_generation: u64,
    /// Active slot (`a` or `b`).
    pub active_slot: SlotName,
    /// Opaque active key reference.
    pub active_key_reference: String,
    /// Opaque staged key reference, if any (rotation/provisioning).
    pub staged_key_reference: Option<String>,
}

impl JournalRecord {
    /// Only the exact active and at most one staged key reference are
    /// accepted; arbitrary alias enumeration is never an authorization
    /// mechanism.
    pub fn has_valid_key_cardinality(&self) -> bool {
        let active = self.active_key_reference.trim();
        let staged = self.staged_key_reference.as_deref().unwrap_or("").trim();
        !active.is_empty()
            && active.len() <= crate::android_vault::MAX_FIELD_LEN
            && staged.len() <= crate::android_vault::MAX_FIELD_LEN
            && self.staged_key_reference.as_deref() != Some(self.active_key_reference.as_str())
    }

    /// Fixed vocabulary check (schema version and active-slot validity).
    pub fn matches_fixed_vocabulary(&self) -> bool {
        self.schema_version == STORAGE_SCHEMA_VERSION && self.active_slot.is_valid()
    }
}

/// Slot name as a closed string vocabulary (`a`/`b`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SlotName {
    A,
    B,
}

impl SlotName {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "a",
            Self::B => "b",
        }
    }

    pub fn is_valid(self) -> bool {
        matches!(self, Self::A | Self::B)
    }
}

/// Bounded password-throttle sidecar (persisted under protected no-backup
/// state; Phase 3 implements the exact cooldown sequence and counting rules).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SidecarRecord {
    pub schema_version: u32,
    /// Completed inner password-authentication failures (0..=255 bounded).
    pub failed_inner_attempts: u8,
    /// Next allowed attempt as a coarse monotonic marker (not an exact wall
    /// timestamp; never surfaced across the boundary).
    pub retry_after_marker: u64,
}

impl SidecarRecord {
    /// Missing/malformed/implausible untrusted sidecar state is bounded and
    /// can never create permanent denial of service. The `u8` type enforces
    /// the 0..=255 attempt bound at the type level.
    pub fn is_bounded(&self) -> bool {
        self.schema_version <= STORAGE_SCHEMA_VERSION
    }
}

/// Non-secret removal tombstone (present only while removal is incomplete).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TombstoneRecord {
    pub schema_version: u32,
    /// Removal phase; `Pending` means cleanup started but is not verified.
    pub phase: RemovalPhase,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RemovalPhase {
    Pending,
    Resumable,
}

impl TombstoneRecord {
    pub fn matches_fixed_vocabulary(&self) -> bool {
        self.schema_version == STORAGE_SCHEMA_VERSION
    }
}

/// Bounded, non-decrypting startup inspection summary (Phase 3 implements the
/// reconciliation; this model fixes the safe state vocabulary now).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StartupInspection {
    /// True when no slot, journal, staged key, tombstone, or other vault
    /// artifact exists → first-run choices may be presented.
    pub is_true_first_run: bool,
    /// Classified key state from non-mutating metadata inspection.
    pub key_state: KeyState,
    /// Whether startup found a removal tombstone (RemovalInProgress).
    pub removal_in_progress: bool,
    /// Typed locked outcome when ambiguous/orphan state exists (never a
    /// false first run).
    pub locked_outcome: Option<AndroidResultCode>,
    /// Fixed file presence map (bounded; no sizes beyond declared caps).
    pub files_present: Vec<VaultFileName>,
}

/// Fixed file name as a closed string vocabulary (for serialization).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VaultFileName {
    SlotA,
    SlotB,
    Journal,
    Sidecars,
    Tombstone,
    Lock,
}

impl VaultFileName {
    pub fn as_str(self) -> &'static str {
        match self {
            VaultFileName::SlotA => crate::android_vault::SLOT_A_FILE,
            VaultFileName::SlotB => crate::android_vault::SLOT_B_FILE,
            VaultFileName::Journal => crate::android_vault::JOURNAL_FILE,
            VaultFileName::Sidecars => crate::android_vault::SIDECARS_FILE,
            VaultFileName::Tombstone => crate::android_vault::TOMBSTONE_FILE,
            VaultFileName::Lock => crate::android_vault::LOCK_FILE,
        }
    }
}

impl From<VaultFile> for VaultFileName {
    fn from(f: VaultFile) -> Self {
        match f {
            VaultFile::SlotA => VaultFileName::SlotA,
            VaultFile::SlotB => VaultFileName::SlotB,
            VaultFile::Journal => VaultFileName::Journal,
            VaultFile::Sidecars => VaultFileName::Sidecars,
            VaultFile::Tombstone => VaultFileName::Tombstone,
            VaultFile::Lock => VaultFileName::Lock,
        }
    }
}

/// Bounded sensitive-state signal (re-exported for downstream phases).
pub use crate::android_vault::contracts::lifecycle::SensitiveState as LifecycleSensitiveState;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn journal() -> JournalRecord {
        JournalRecord {
            schema_version: STORAGE_SCHEMA_VERSION,
            expected_generation: 7,
            active_slot: SlotName::A,
            active_key_reference: "hvk-9f3e1a02b8c4".to_string(),
            staged_key_reference: None,
        }
    }

    #[test]
    fn fixed_file_names_are_exact_and_identity_neutral() {
        assert_eq!(VaultFile::SlotA.file_name(), "slot-a.hvlt");
        assert_eq!(VaultFile::SlotB.file_name(), "slot-b.hvlt");
        assert_eq!(VaultFile::Journal.file_name(), "journal.json");
        assert_eq!(VaultFile::Sidecars.file_name(), "sidecars.json");
        assert_eq!(VaultFile::Tombstone.file_name(), "removal.tombstone");
        assert_eq!(VaultFile::Lock.file_name(), "vault.lock");
        for f in VaultFile::ALL {
            let name = f.file_name();
            assert!(!name.to_ascii_lowercase().contains("alias"));
            assert!(!name.to_ascii_lowercase().contains("address"));
        }
    }

    #[test]
    fn journal_accepts_active_plus_at_most_one_staged_key() {
        let j = journal();
        assert!(j.has_valid_key_cardinality());
        assert!(j.matches_fixed_vocabulary());

        let mut staged = journal();
        staged.staged_key_reference = Some("hvk-staged-123".to_string());
        assert!(staged.has_valid_key_cardinality());

        let mut dup = journal();
        dup.staged_key_reference = Some("hvk-9f3e1a02b8c4".to_string());
        assert!(!dup.has_valid_key_cardinality());

        let mut empty = journal();
        empty.active_key_reference = "".to_string();
        assert!(!empty.has_valid_key_cardinality());
    }

    #[test]
    fn journal_unknown_field_is_rejected() {
        let json = json!({
            "schemaVersion": 1,
            "expectedGeneration": 7,
            "activeSlot": "a",
            "activeKeyReference": "hvk-9f3e1a02b8c4",
            "stagedKeyReference": null,
            "alias": "sneaky"
        });
        assert!(serde_json::from_value::<JournalRecord>(json).is_err());
    }

    #[test]
    fn sidecar_bounds_are_enforced() {
        let s = SidecarRecord {
            schema_version: STORAGE_SCHEMA_VERSION,
            failed_inner_attempts: 5,
            retry_after_marker: 12345,
        };
        assert!(s.is_bounded());
        let mut bad = s.clone();
        bad.schema_version = 99;
        assert!(!bad.is_bounded());
    }

    #[test]
    fn sidecar_unknown_field_is_rejected() {
        let json = r#"{"schemaVersion":1,"failedInnerAttempts":5,"retryAfterMarker":12345,"serial":"ABC"}"#;
        assert!(serde_json::from_str::<SidecarRecord>(json).is_err());
    }

    #[test]
    fn tombstone_vocabulary_is_fixed() {
        let t = TombstoneRecord {
            schema_version: STORAGE_SCHEMA_VERSION,
            phase: RemovalPhase::Resumable,
        };
        assert!(t.matches_fixed_vocabulary());
        assert!(serde_json::from_str::<TombstoneRecord>(
            r#"{"schemaVersion":1,"phase":"resumable"}"#
        )
        .is_ok());
        assert!(
            serde_json::from_str::<TombstoneRecord>(r#"{"schemaVersion":1,"phase":"done"}"#)
                .is_err()
        );
    }

    #[test]
    fn startup_inspection_is_closed_and_bounded() {
        let s = StartupInspection {
            is_true_first_run: true,
            key_state: KeyState::Absent,
            removal_in_progress: false,
            locked_outcome: None,
            files_present: vec![],
        };
        let json = serde_json::to_string(&s).unwrap();
        let back: StartupInspection = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
        assert!(serde_json::from_str::<StartupInspection>(
            r#"{"isTrueFirstRun":true,"keyState":"absent","removalInProgress":false,"lockedOutcome":null,"filesPresent":[],"generation":1}"#
        )
        .is_err());
    }
}
