//! Fixed vault layout model (FEAT-005 "Native Filesystem Storage").
//!
//! The root is resolved by the platform via Tauri's `app_data_dir()` and the
//! fixed application ID — never from an alias/address and never hardcoded
//! `$HOME`. File names are fixed and identity-neutral.

use serde::{Deserialize, Serialize};

/// Fixed layout root relative to the resolved app-data directory.
pub const VAULT_ROOT_REL: &str = "vault/v1";

/// Fixed artifact names (identity-neutral; cleartext preview and sidecars stay
/// exactly within FEAT-003's allowlist and are never authorization proof).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VaultArtifact {
    SlotA,
    SlotB,
    Journal,
    Sidecars,
    RemovalTombstone,
    VaultLock,
}

impl VaultArtifact {
    pub fn file_name(self) -> &'static str {
        match self {
            Self::SlotA => "slot-a.hvlt",
            Self::SlotB => "slot-b.hvlt",
            Self::Journal => "journal.json",
            Self::Sidecars => "sidecars.json",
            Self::RemovalTombstone => "removal.tombstone",
            Self::VaultLock => "vault.lock",
        }
    }
}

/// The two-slot journal record references active/retained generations and the
/// rollback window (FEAT-003 bounded rollback).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SlotPair {
    /// Active slot holding the current authoritative generation.
    pub active: VaultArtifact,
    /// Retained verified previous slot (bounded rollback).
    pub retained: Option<VaultArtifact>,
}

/// Directory permission model: vault root and subdirectories `0700`, files
/// `0600`, current-UID owner. Enforced after creation/update, not only umask.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PermissionModel {
    pub directory_mode: u32,
    pub file_mode: u32,
    /// Owner must equal the current process UID.
    pub owner_is_current_uid: bool,
}

impl Default for PermissionModel {
    fn default() -> Self {
        Self {
            directory_mode: 0o700,
            file_mode: 0o600,
            owner_is_current_uid: true,
        }
    }
}

/// Whether a given artifact is a lock/aux file (never carries vault secrets).
impl VaultArtifact {
    pub fn is_lock_or_aux(self) -> bool {
        matches!(self, Self::VaultLock)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_names_are_identity_neutral() {
        for artifact in [
            VaultArtifact::SlotA,
            VaultArtifact::SlotB,
            VaultArtifact::Journal,
            VaultArtifact::Sidecars,
            VaultArtifact::RemovalTombstone,
            VaultArtifact::VaultLock,
        ] {
            let name = artifact.file_name();
            assert!(!name.contains("alias") && !name.contains("address"));
            assert!(!name.contains("user") && !name.contains("uid"));
        }
        assert_eq!(VaultArtifact::SlotA.file_name(), "slot-a.hvlt");
        assert_eq!(VaultArtifact::SlotB.file_name(), "slot-b.hvlt");
        assert_eq!(VaultArtifact::VaultLock.file_name(), "vault.lock");
    }

    #[test]
    fn permission_model_defaults_are_0700_0600() {
        let pm = PermissionModel::default();
        assert_eq!(pm.directory_mode, 0o700);
        assert_eq!(pm.file_mode, 0o600);
        assert!(pm.owner_is_current_uid);
    }

    #[test]
    fn active_and_retained_are_distinct() {
        let pair = SlotPair {
            active: VaultArtifact::SlotA,
            retained: Some(VaultArtifact::SlotB),
        };
        assert_ne!(pair.active, pair.retained.unwrap());
    }
}
