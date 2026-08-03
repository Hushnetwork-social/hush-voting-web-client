//! Android lifecycle evidence, sensitive-state, and document vocabulary
//! (FEAT-006 Phase 2, Task 2.1).
//!
//! Lifecycle/device signals flow from the Kotlin bridge to Rust; Rust owns
//! session epochs and timeout evaluation. JavaScript visibility is
//! corroborative only and can never extend a native session. Timing uses
//! boot-aware monotonic elapsed time that includes deep sleep; wall time is a
//! conservative cross-check only.

use serde::{Deserialize, Serialize};

/// Bounded boot-aware lifecycle evidence consumed by the Rust session
/// authority. Never authoritative on its own; backward, implausible, missing,
/// contradictory, or boot-changed evidence results in Locked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LifecycleEvidence {
    /// Monotonic elapsed time since boot in milliseconds (includes deep sleep;
    /// `SystemClock.elapsedRealtime`). Bounded to a sane upper window.
    pub boot_elapsed_millis: u64,
    /// Whether Android currently reports the device locked.
    pub device_locked: bool,
    /// Whether every application window/activity is backgrounded.
    pub all_windows_backgrounded: bool,
    /// Whether the main window/activity currently has focus.
    pub main_window_focused: bool,
}

/// Maximum plausible boot elapsed time (60 days) — larger values are rejected
/// as implausible and lock rather than extend a session.
pub const MAX_PLAUSIBLE_BOOT_ELAPSED_MILLIS: u64 = 60 * 24 * 60 * 60 * 1000;

impl LifecycleEvidence {
    /// Whether the evidence is internally plausible (bounded, not contradictory
    /// in the focus/background pair).
    pub fn is_plausible(&self) -> bool {
        self.boot_elapsed_millis <= MAX_PLAUSIBLE_BOOT_ELAPSED_MILLIS
            && !(self.main_window_focused && self.all_windows_backgrounded)
    }

    /// A new sensitive operation may start only while the device is unlocked.
    pub fn device_ready(&self) -> bool {
        !self.device_locked
    }
}

/// Typed sensitive state driven by Rust (never arbitrary JavaScript). Native
/// shielding applies FLAG_SECURE and approved window protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SensitiveState {
    None,
    DevicePasswordInput,
    NewDevicePasswordInput,
    DatPasswordInput,
    MnemonicCreation,
    MnemonicReveal,
    MnemonicConfirmation,
    CredentialRestore,
    CredentialExport,
    OperationConfirmation,
}

/// Approved document-picker operations (one bounded URI per operation; no
/// persisted grants, no broad storage permission, no URI/path to TypeScript).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DocumentOperation {
    ImportDatV1,
    ExportDatV1,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence() -> LifecycleEvidence {
        LifecycleEvidence {
            boot_elapsed_millis: 3_600_000,
            device_locked: false,
            all_windows_backgrounded: false,
            main_window_focused: true,
        }
    }

    #[test]
    fn plausible_evidence_is_accepted() {
        assert!(evidence().is_plausible());
        assert!(evidence().device_ready());
    }

    #[test]
    fn contradictory_focus_is_implausible() {
        let mut e = evidence();
        e.main_window_focused = true;
        e.all_windows_backgrounded = true;
        assert!(!e.is_plausible());
    }

    #[test]
    fn absurd_boot_time_is_implausible() {
        let mut e = evidence();
        e.boot_elapsed_millis = MAX_PLAUSIBLE_BOOT_ELAPSED_MILLIS + 1;
        assert!(!e.is_plausible());
    }

    #[test]
    fn locked_device_blocks_sensitive_start() {
        let mut e = evidence();
        e.device_locked = true;
        assert!(!e.device_ready());
    }

    #[test]
    fn sensitive_states_are_closed_and_distinct() {
        let states = [
            SensitiveState::None,
            SensitiveState::DevicePasswordInput,
            SensitiveState::NewDevicePasswordInput,
            SensitiveState::DatPasswordInput,
            SensitiveState::MnemonicCreation,
            SensitiveState::MnemonicReveal,
            SensitiveState::MnemonicConfirmation,
            SensitiveState::CredentialRestore,
            SensitiveState::CredentialExport,
            SensitiveState::OperationConfirmation,
        ];
        let mut seen = std::collections::HashSet::new();
        for s in states {
            assert!(seen.insert(s));
        }
    }

    #[test]
    fn unknown_lifecycle_field_is_rejected() {
        let json = r#"{"bootElapsedMillis":3600000,"deviceLocked":false,"allWindowsBackgrounded":false,"mainWindowFocused":true,"serial":"ABC"}"#;
        assert!(serde_json::from_str::<LifecycleEvidence>(json).is_err());
    }

    #[test]
    fn document_operations_are_closed() {
        assert_eq!(
            serde_json::to_string(&DocumentOperation::ImportDatV1).unwrap(),
            "\"importDatV1\""
        );
        assert!(serde_json::from_str::<DocumentOperation>("\"readAnyUri\"").is_err());
    }
}
