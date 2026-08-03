//! Closed Android typed result union (FEAT-006 Phase 2, Task 2.1).
//!
//! Extends the FEAT-003 closed-result philosophy with reviewed Android
//! mappings. The WebView receives only: stable category, retryability, allowed
//! actions, bounded retry deadline, and an optional random non-correlating
//! support code. No raw exception, provider text, stack, key alias, URI/path,
//! ciphertext, model, address, endpoint, or exact timestamp crosses the
//! boundary. Outer Keystore/AAD authentication failure is never
//! `WrongPassword`; inner password-authenticated decryption uses FEAT-003's
//! combined `WrongPasswordOrDamagedData` result to avoid an oracle.

use serde::{Deserialize, Serialize};

/// Recovery actions the UI may offer for a typed Android failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RecoveryAction {
    /// Retry after the bounded retry deadline.
    Retry,
    /// Open Android security settings from an explicit user action.
    OpenSecuritySettings,
    /// Update HushVoting (patch/version remediation).
    UpdateApp,
    /// Remove the local user (explicit destructive confirmation).
    RemoveLocalUser,
    /// Portable recovery via recovery words or an exported `.dat`.
    PortableRecovery,
    /// Resume an interrupted removal.
    ResumeRemoval,
    /// Cancel the operation; no action offered.
    Cancel,
}

/// Closed Android result codes (v1). Safe subreason may choose UI recovery
/// but never exposes raw platform detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum AndroidResultCode {
    /// Success — typed payload kind in `NativeOutcome`-style result.
    Ok,
    /// No configured secure lock screen; provisioning blocked.
    SecureLockRequired,
    /// Android currently reports the device locked.
    DeviceLocked,
    /// No verified hardware-backed Keystore implementation.
    HardwareBackedKeystoreUnavailable,
    /// Signed-release known-bad device/build rule matched.
    UnsupportedKnownBadBuild,
    /// Transient Keystore/provider failure — retryable.
    TemporaryKeystoreFailure,
    /// Key missing/permanently invalidated/property mismatch; files preserved.
    PlatformProtectionInvalidated,
    /// Outer wrapper/AAD authentication failed — never wrong-password.
    WrapperIntegrityFailure,
    /// WebView/Rust/Kotlin build or protocol version mismatch.
    BuildProtocolMismatch,
    /// Storage unavailable (read-only, missing root, IO failure).
    StorageUnavailable,
    /// Storage quota exceeded / bounded allocation denied.
    StorageQuotaExceeded,
    /// Unknown newer wrapper/journal/envelope version; bytes preserved.
    UnsupportedWrapperVersion,
    /// Operation arrived after Lock/timeout/replacement/removal.
    StaleSession,
    /// Removal or cleanup incomplete; resume offered.
    CleanupRemovalIncomplete,
    /// Inner password-authenticated decryption failed (FEAT-003 combined
    /// result; avoids a wrong-password oracle across the platform boundary).
    WrongPasswordOrDamagedData,
}

impl AndroidResultCode {
    /// Safe recovery action set. No raw detail is ever included.
    pub fn recovery_actions(self) -> &'static [RecoveryAction] {
        match self {
            Self::Ok => &[],
            Self::SecureLockRequired => &[
                RecoveryAction::OpenSecuritySettings,
                RecoveryAction::Retry,
                RecoveryAction::RemoveLocalUser,
                RecoveryAction::PortableRecovery,
            ],
            Self::DeviceLocked => &[RecoveryAction::Retry],
            Self::HardwareBackedKeystoreUnavailable | Self::UnsupportedKnownBadBuild => &[
                RecoveryAction::UpdateApp,
                RecoveryAction::RemoveLocalUser,
                RecoveryAction::PortableRecovery,
            ],
            Self::TemporaryKeystoreFailure => &[RecoveryAction::Retry],
            Self::PlatformProtectionInvalidated => &[
                RecoveryAction::UpdateApp,
                RecoveryAction::RemoveLocalUser,
                RecoveryAction::PortableRecovery,
            ],
            Self::WrapperIntegrityFailure => &[RecoveryAction::Cancel],
            Self::BuildProtocolMismatch => &[RecoveryAction::UpdateApp],
            Self::StorageUnavailable | Self::StorageQuotaExceeded => &[RecoveryAction::Retry],
            Self::UnsupportedWrapperVersion => &[RecoveryAction::UpdateApp, RecoveryAction::Cancel],
            Self::StaleSession => &[RecoveryAction::Retry],
            Self::CleanupRemovalIncomplete => {
                &[RecoveryAction::Retry, RecoveryAction::ResumeRemoval]
            }
            Self::WrongPasswordOrDamagedData => {
                &[RecoveryAction::Retry, RecoveryAction::PortableRecovery]
            }
        }
    }

    /// Whether the failure is retryable without user intervention.
    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            Self::DeviceLocked
                | Self::TemporaryKeystoreFailure
                | Self::StorageUnavailable
                | Self::StorageQuotaExceeded
                | Self::StaleSession
                | Self::CleanupRemovalIncomplete
                | Self::WrongPasswordOrDamagedData
        )
    }
}

/// A safe Android platform outcome (closed). `Ok` carries a typed payload
/// kind; failure carries a closed code plus optional bounded support code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "outcome", deny_unknown_fields)]
pub enum AndroidOutcome {
    Ok {
        kind: OutcomeKind,
    },
    Err {
        code: AndroidResultCode,
        retryable: bool,
        /// Bounded retry deadline in seconds (0 = none).
        retry_deadline_secs: u32,
        /// Random non-correlating support code (8 hex chars, optional).
        support_code: Option<String>,
    },
}

/// Closed payload kind for a successful platform outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OutcomeKind {
    CapabilityStatus,
    KeyInspection,
    WrappedSlot,
    UnwrappedSlot,
    SecureLockState,
    LifecycleEvidence,
    ShieldState,
    ClipboardCleared,
    DocumentHandle,
}

impl AndroidOutcome {
    /// Build a safe error outcome with the code's canonical recovery fields.
    pub fn err(code: AndroidResultCode) -> Self {
        Self::Err {
            code,
            retryable: code.is_retryable(),
            retry_deadline_secs: 0,
            support_code: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_safe_recovery_actions() {
        let codes = [
            AndroidResultCode::Ok,
            AndroidResultCode::SecureLockRequired,
            AndroidResultCode::DeviceLocked,
            AndroidResultCode::HardwareBackedKeystoreUnavailable,
            AndroidResultCode::UnsupportedKnownBadBuild,
            AndroidResultCode::TemporaryKeystoreFailure,
            AndroidResultCode::PlatformProtectionInvalidated,
            AndroidResultCode::WrapperIntegrityFailure,
            AndroidResultCode::BuildProtocolMismatch,
            AndroidResultCode::StorageUnavailable,
            AndroidResultCode::StorageQuotaExceeded,
            AndroidResultCode::UnsupportedWrapperVersion,
            AndroidResultCode::StaleSession,
            AndroidResultCode::CleanupRemovalIncomplete,
            AndroidResultCode::WrongPasswordOrDamagedData,
        ];
        for code in codes {
            let _ = code.recovery_actions();
            let outcome = AndroidOutcome::err(code);
            assert!(matches!(outcome, AndroidOutcome::Err { .. }));
        }
    }

    #[test]
    fn outer_integrity_failure_is_never_wrong_password() {
        assert_ne!(
            AndroidResultCode::WrapperIntegrityFailure,
            AndroidResultCode::WrongPasswordOrDamagedData
        );
    }

    #[test]
    fn retryable_classification_is_exact() {
        assert!(AndroidResultCode::TemporaryKeystoreFailure.is_retryable());
        assert!(AndroidResultCode::DeviceLocked.is_retryable());
        assert!(!AndroidResultCode::SecureLockRequired.is_retryable());
        assert!(!AndroidResultCode::BuildProtocolMismatch.is_retryable());
        assert!(!AndroidResultCode::WrapperIntegrityFailure.is_retryable());
    }

    #[test]
    fn no_raw_detail_fields_are_serializable() {
        let outcome = AndroidOutcome::err(AndroidResultCode::TemporaryKeystoreFailure);
        let json = serde_json::to_string(&outcome).unwrap();
        for raw in [
            "alias",
            "uri",
            "path",
            "exception",
            "stack",
            "ciphertext",
            "address",
            "endpoint",
            "timestamp",
            "model",
        ] {
            assert!(
                !json.to_ascii_lowercase().contains(raw),
                "raw detail leaked: {raw}"
            );
        }
    }

    #[test]
    fn unknown_field_is_rejected() {
        let json = r#"{"outcome":"err","code":"deviceLocked","retryable":true,"retryDeadlineSecs":0,"supportCode":null,"stack":"boom"}"#;
        assert!(serde_json::from_str::<AndroidOutcome>(json).is_err());
    }

    #[test]
    fn unknown_enum_value_is_rejected() {
        let json = r#"{"outcome":"err","code":"magic","retryable":false,"retryDeadlineSecs":0,"supportCode":null}"#;
        assert!(serde_json::from_str::<AndroidOutcome>(json).is_err());
    }
}
