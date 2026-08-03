//! Sanitized diagnostics contract (FEAT-005 "Error Handling" + "Privacy").
//!
//! Diagnostics are closed typed codes plus coarse timing. No raw exception,
//! D-Bus object path, item attribute/value, filesystem path, UID/username,
//! stack, ciphertext, or free-form platform message may cross.

use serde::{Deserialize, Serialize};

/// Coarse operation category for diagnostics/opt-in telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DiagnosticCategory {
    Preflight,
    KeyringAccess,
    PasswordSubmit,
    Kdf,
    OnlineVerify,
    StorageCommit,
    Lock,
    Removal,
    Reveal,
}

/// Coarse duration bucket (never exact timestamps).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CoarseDuration {
    Under100Ms,
    Under500Ms,
    Under1s,
    Under3s,
    Over3s,
}

/// A bounded, sanitized local diagnostic record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SafeDiagnostic {
    pub category: DiagnosticCategory,
    /// Random per-occurrence support code (only for unknown/rare failures).
    pub support_code: Option<u64>,
    pub coarse_duration: CoarseDuration,
}

/// Closed typed diagnostic code vocabulary. Each code maps to a safe UI
/// recovery action; no code carries provider/path/identity detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DiagnosticCode {
    ProviderAbsent,
    ProviderLocked,
    PromptCancelled,
    PromptTimedOut,
    ProviderTemporarilyUnavailable,
    UnqualifiedProvider,
    ProtectionInvalidated,
    WrapperAmbiguous,
    WrapperVersionUnsupported,
    BuildVersionMismatch,
    WrongPasswordOrDamagedData,
    KdfResourceLimit,
    GenerationConflict,
    RollbackAvailable,
    StorageUnavailable,
    StorageQuotaExceeded,
    FilesystemPolicyViolation,
    NetworkTimeout,
    ProfileNotFound,
    KeyMismatch,
    StaleSession,
    OperationForbidden,
    CleanupFailed,
    RemovalIncomplete,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_vocabulary_is_closed_and_bounded() {
        // Exhaustive round-trip over every code to prove serializability.
        let codes = [
            DiagnosticCode::ProviderAbsent,
            DiagnosticCode::ProviderLocked,
            DiagnosticCode::PromptCancelled,
            DiagnosticCode::PromptTimedOut,
            DiagnosticCode::ProviderTemporarilyUnavailable,
            DiagnosticCode::UnqualifiedProvider,
            DiagnosticCode::ProtectionInvalidated,
            DiagnosticCode::WrapperAmbiguous,
            DiagnosticCode::WrapperVersionUnsupported,
            DiagnosticCode::BuildVersionMismatch,
            DiagnosticCode::WrongPasswordOrDamagedData,
            DiagnosticCode::KdfResourceLimit,
            DiagnosticCode::GenerationConflict,
            DiagnosticCode::RollbackAvailable,
            DiagnosticCode::StorageUnavailable,
            DiagnosticCode::StorageQuotaExceeded,
            DiagnosticCode::FilesystemPolicyViolation,
            DiagnosticCode::NetworkTimeout,
            DiagnosticCode::ProfileNotFound,
            DiagnosticCode::KeyMismatch,
            DiagnosticCode::StaleSession,
            DiagnosticCode::OperationForbidden,
            DiagnosticCode::CleanupFailed,
            DiagnosticCode::RemovalIncomplete,
        ];
        for code in codes {
            let json = serde_json::to_string(&code).expect("serialize");
            let back: DiagnosticCode = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(code, back);
        }
    }
}
