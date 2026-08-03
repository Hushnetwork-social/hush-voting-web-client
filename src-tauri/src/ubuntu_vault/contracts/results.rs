//! Closed native result union (FEAT-005 "Error Handling").
//!
//! Every expected Rust, D-Bus, filesystem, TLS/gRPC, crypto, and IPC failure
//! maps to this closed union. Safe platform subreason may choose UI recovery
//! but never exposes raw provider/path details. This mirrors FEAT-003's
//! typed-result philosophy in native code.

use serde::{Deserialize, Serialize};

/// Recovery actions the UI may offer for a typed failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RecoveryAction {
    Retry,
    Reprovision,
    VerifyOnline,
    UnlockPlatformProtection,
    EnableOsProtection,
    PortableRecovery,
    ClearRemovalTombstone,
    ResumeRemoval,
    Cancel,
}

/// Closed native error codes. Mapping to FEAT-003's vault result codes happens
/// in the bridge layer; native codes here are the adapter's own vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NativeErrorCode {
    NoVault,
    UnsupportedVaultVersion,
    MalformedEnvelope,
    WrongPasswordOrDamagedData,
    Throttled,
    KdfResourceLimit,
    PlatformProtectionUnavailable,
    PlatformProtectionInvalidated,
    IdentityBindingMismatch,
    MigrationFailedRollbackAvailable,
    GenerationConflict,
    StorageUnavailable,
    StorageQuotaExceeded,
    PersistenceDenied,
    StaleSession,
    OperationForbidden,
    CleanupFailed,
    ExtensionUnsupported,
    ProviderAbsent,
    ProviderLocked,
    PromptCancelled,
    PromptTimedOut,
    ProviderTemporarilyUnavailable,
    UnqualifiedProvider,
    WrapperAmbiguous,
    WrapperVersionUnsupported,
    BuildVersionMismatch,
    NetworkTimeout,
    ProfileNotFound,
    KeyMismatch,
    RemovalIncomplete,
}

impl NativeErrorCode {
    /// Safe recovery action set. No raw detail is ever included.
    pub fn recovery_actions(self) -> &'static [RecoveryAction] {
        match self {
            Self::NoVault => &[RecoveryAction::Reprovision],
            Self::UnsupportedVaultVersion | Self::MalformedEnvelope => &[RecoveryAction::Cancel],
            Self::WrongPasswordOrDamagedData => {
                &[RecoveryAction::Retry, RecoveryAction::Reprovision]
            }
            Self::Throttled => &[RecoveryAction::Retry],
            Self::KdfResourceLimit => &[RecoveryAction::Retry],
            Self::PlatformProtectionUnavailable => &[
                RecoveryAction::Retry,
                RecoveryAction::UnlockPlatformProtection,
            ],
            Self::PlatformProtectionInvalidated => &[RecoveryAction::PortableRecovery],
            Self::IdentityBindingMismatch | Self::KeyMismatch => &[
                RecoveryAction::Retry,
                RecoveryAction::VerifyOnline,
                RecoveryAction::Reprovision,
            ],
            Self::MigrationFailedRollbackAvailable => &[RecoveryAction::Retry],
            Self::GenerationConflict => &[RecoveryAction::Retry, RecoveryAction::Cancel],
            Self::StorageUnavailable | Self::StorageQuotaExceeded => &[RecoveryAction::Retry],
            Self::PersistenceDenied => &[RecoveryAction::Cancel],
            Self::StaleSession => &[RecoveryAction::Retry],
            Self::OperationForbidden => &[RecoveryAction::Cancel],
            Self::CleanupFailed => &[RecoveryAction::Retry],
            Self::ExtensionUnsupported => &[RecoveryAction::Cancel],
            Self::ProviderAbsent => &[
                RecoveryAction::Retry,
                RecoveryAction::EnableOsProtection,
                RecoveryAction::PortableRecovery,
            ],
            Self::ProviderLocked | Self::PromptCancelled | Self::PromptTimedOut => &[
                RecoveryAction::Retry,
                RecoveryAction::UnlockPlatformProtection,
            ],
            Self::ProviderTemporarilyUnavailable => &[RecoveryAction::Retry],
            Self::UnqualifiedProvider => &[RecoveryAction::EnableOsProtection],
            Self::WrapperAmbiguous => &[RecoveryAction::PortableRecovery],
            Self::WrapperVersionUnsupported | Self::BuildVersionMismatch => {
                &[RecoveryAction::Cancel]
            }
            Self::NetworkTimeout => &[RecoveryAction::Retry],
            Self::ProfileNotFound => &[RecoveryAction::VerifyOnline, RecoveryAction::Cancel],
            Self::RemovalIncomplete => &[RecoveryAction::Retry, RecoveryAction::ResumeRemoval],
        }
    }
}

/// A safe native outcome: success carries a typed payload kind; failure
/// carries a closed code plus optional support code. No raw detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "outcome", deny_unknown_fields)]
pub enum NativeOutcome {
    Ok {
        kind: OutcomeKind,
    },
    Err {
        code: NativeErrorCode,
        support_code: Option<u64>,
    },
}

/// Safe success payload kinds (opaque handles or coarse state only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum OutcomeKind {
    Locked,
    Unlocked,
    Provisioned,
    Verified,
    Removed,
    Preview,
    RevealPrepared,
    Signed,
    DatImported,
    DatExported,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_codes_have_closed_recovery_actions() {
        // Every code maps to a non-empty closed action set.
        let codes = [
            NativeErrorCode::NoVault,
            NativeErrorCode::UnsupportedVaultVersion,
            NativeErrorCode::MalformedEnvelope,
            NativeErrorCode::WrongPasswordOrDamagedData,
            NativeErrorCode::Throttled,
            NativeErrorCode::KdfResourceLimit,
            NativeErrorCode::PlatformProtectionUnavailable,
            NativeErrorCode::PlatformProtectionInvalidated,
            NativeErrorCode::IdentityBindingMismatch,
            NativeErrorCode::MigrationFailedRollbackAvailable,
            NativeErrorCode::GenerationConflict,
            NativeErrorCode::StorageUnavailable,
            NativeErrorCode::StorageQuotaExceeded,
            NativeErrorCode::PersistenceDenied,
            NativeErrorCode::StaleSession,
            NativeErrorCode::OperationForbidden,
            NativeErrorCode::CleanupFailed,
            NativeErrorCode::ExtensionUnsupported,
            NativeErrorCode::ProviderAbsent,
            NativeErrorCode::ProviderLocked,
            NativeErrorCode::PromptCancelled,
            NativeErrorCode::PromptTimedOut,
            NativeErrorCode::ProviderTemporarilyUnavailable,
            NativeErrorCode::UnqualifiedProvider,
            NativeErrorCode::WrapperAmbiguous,
            NativeErrorCode::WrapperVersionUnsupported,
            NativeErrorCode::BuildVersionMismatch,
            NativeErrorCode::NetworkTimeout,
            NativeErrorCode::ProfileNotFound,
            NativeErrorCode::KeyMismatch,
            NativeErrorCode::RemovalIncomplete,
        ];
        for code in codes {
            assert!(!code.recovery_actions().is_empty(), "{code:?}");
        }
    }

    #[test]
    fn invalidated_never_offers_retry_replacement() {
        let actions = NativeErrorCode::PlatformProtectionInvalidated.recovery_actions();
        assert!(actions.contains(&RecoveryAction::PortableRecovery));
        assert!(!actions.contains(&RecoveryAction::Retry));
    }

    #[test]
    fn outcome_round_trips_closed() {
        let err = NativeOutcome::Err {
            code: NativeErrorCode::WrongPasswordOrDamagedData,
            support_code: Some(1234),
        };
        let json = serde_json::to_string(&err).unwrap();
        let back: NativeOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(err, back);
        assert!(!json.contains("password"));
    }

    #[test]
    fn unknown_fields_are_rejected_fail_closed() {
        // A malformed, unsupported, or stale request must fail closed without
        // changing keyring or vault state — unknown fields never deserialize.
        let json = r#"{"outcome":"err","code":"wrongPasswordOrDamagedData","supportCode":1234,"rawDetail":"secret"}"#;
        assert!(serde_json::from_str::<NativeOutcome>(json).is_err());
    }

    #[test]
    fn support_code_is_bounded() {
        // Support codes are random per-occurrence integers only; no raw detail.
        let err = NativeOutcome::Err {
            code: NativeErrorCode::CleanupFailed,
            support_code: Some(u64::MAX),
        };
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("18446744073709551615"));
        assert!(!json.contains("path") && !json.contains("dbus"));
    }
}
