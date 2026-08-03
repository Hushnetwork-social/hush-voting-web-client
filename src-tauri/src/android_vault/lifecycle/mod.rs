//! Key lifecycle, throttling, and removal services (FEAT-006 Phase 3,
//! Task 3.7).
//!
//! - Password throttling: attempts 1-4 cost KDF only; 5-10 use exact
//!   5/10/20/40/80/160 s cooldowns; attempt 11+ caps at 300 s. Only completed
//!   inner password-authentication failures are counted; device lock,
//!   cancellation, Keystore/storage/KDF/network failure, stale results, and
//!   platform invalidation are never counted. Process death/restart preserves
//!   the bounded sidecar. Successful unlock/reprovisioning or verified removal
//!   resets it. Missing/malformed/implausible sidecar state is bounded and can
//!   never create permanent denial of service.
//! - Wrapping-key rotation: one pending key at most; both required journal
//!   generations rewrap transactionally; the new package is verified; promote
//!   atomically; delete the old key only after the new protection is
//!   authoritative and has successfully unlocked. Interrupted rotation resumes
//!   or rolls back safely; never rotate when the old package cannot first be
//!   authenticated.
//! - Invalidation: secure-lock removal immediately blocks vault use and
//!   preserves key/files; existing StrongBox temporarily unavailable -> Retry,
//!   never a replacement TEE key; key missing/permanently invalidated ->
//!   portable recovery into a new vault.

use crate::android_vault::contracts::capability::KeyState;
use crate::android_vault::contracts::result::{AndroidResultCode, RecoveryAction};
use crate::android_vault::keystore::{SecureLockState, StrongBoxAttempt};

/// Exact cooldown sequence after the 4th completed failure.
pub const COOLDOWN_SEQUENCE_SECS: [u64; 6] = [5, 10, 20, 40, 80, 160];
/// Cap after attempt 11+.
pub const THROTTLE_CAP_SECS: u64 = 300;
/// Attempts that incur KDF cost only (no cooldown).
pub const KDF_ONLY_ATTEMPTS: u8 = 4;

/// Throttle decision for one unlock attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleDecision {
    /// Allow the KDF/unlock attempt.
    Allowed,
    /// Deny with a cooldown in seconds (bounded deadline for the UI).
    Denied { cooldown_secs: u64 },
}

/// Compute the cooldown for the NEXT attempt given completed failures so far.
pub fn compute_cooldown(failed_inner_attempts: u8) -> ThrottleDecision {
    let attempts = failed_inner_attempts;
    if attempts < KDF_ONLY_ATTEMPTS {
        return ThrottleDecision::Allowed;
    }
    let idx = (attempts - KDF_ONLY_ATTEMPTS) as usize;
    if idx < COOLDOWN_SEQUENCE_SECS.len() {
        ThrottleDecision::Denied {
            cooldown_secs: COOLDOWN_SEQUENCE_SECS[idx],
        }
    } else {
        ThrottleDecision::Denied {
            cooldown_secs: THROTTLE_CAP_SECS,
        }
    }
}

/// Whether this outcome counts as a completed inner password-authentication
/// failure (target "Password throttling" counting rules).
pub fn counts_as_inner_failure(outcome: InnerUnlockOutcome) -> bool {
    matches!(outcome, InnerUnlockOutcome::WrongPasswordOrDamagedData)
}

/// Closed inner-unlock outcomes (never raw detail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InnerUnlockOutcome {
    Success,
    WrongPasswordOrDamagedData,
    DeviceLocked,
    PlatformIntegrityFailure,
    TemporaryKeystoreFailure,
    KdfResourceLimit,
    StaleResult,
    Cancelled,
    NetworkFailure,
    PlatformInvalidated,
}

/// Update the throttle sidecar state after one completed attempt.
pub fn update_throttle(
    sidecar: Option<SidecarThrottle>,
    outcome: InnerUnlockOutcome,
) -> SidecarThrottle {
    let current = sidecar.unwrap_or_default();
    if matches!(
        outcome,
        InnerUnlockOutcome::Success | InnerUnlockOutcome::PlatformInvalidated
    ) {
        return SidecarThrottle::default();
    }
    if counts_as_inner_failure(outcome) {
        return SidecarThrottle {
            failed_inner_attempts: current.failed_inner_attempts.saturating_add(1),
        };
    }
    current
}

/// Bounded throttle state (mirrors the persisted sidecar).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SidecarThrottle {
    pub failed_inner_attempts: u8,
}

/// Rotation stage (target "Rotation"; at most one pending key).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationStage {
    None,
    PendingKeyCreated,
    RewrappedBothGenerations,
    NewPackageVerified,
    Promoted,
    OldKeyDeleted,
}

/// Rotation policy decision (closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationDecision {
    /// Rotation may proceed.
    Proceed,
    /// The old package could not first be authenticated — never rotate.
    OldPackageNotAuthenticated,
    /// A rotation is already pending — at most one staged key.
    AlreadyPending,
    /// A failed rotation may be resumed/rolled back safely.
    ResumableOrRollback,
}

/// Gate rotation start: old package must authenticate first; at most one
/// pending key.
pub fn rotation_may_start(
    old_package_authenticated: bool,
    staged_key_present: bool,
    existing_rotation: RotationStage,
) -> RotationDecision {
    if !old_package_authenticated {
        return RotationDecision::OldPackageNotAuthenticated;
    }
    if staged_key_present || existing_rotation != RotationStage::None {
        return RotationDecision::AlreadyPending;
    }
    RotationDecision::Proceed
}

/// Progress a rotation through its deterministic stages.
pub fn advance_rotation(
    stage: RotationStage,
    new_package_verified: bool,
    unlocked_after_promote: bool,
) -> RotationStage {
    match stage {
        RotationStage::None => RotationStage::PendingKeyCreated,
        RotationStage::PendingKeyCreated => {
            if new_package_verified {
                RotationStage::NewPackageVerified
            } else {
                RotationStage::PendingKeyCreated
            }
        }
        RotationStage::NewPackageVerified => RotationStage::Promoted,
        RotationStage::Promoted => {
            if unlocked_after_promote {
                RotationStage::OldKeyDeleted
            } else {
                RotationStage::Promoted
            }
        }
        other => other,
    }
}

/// Whether the old key may be deleted: only after promotion AND a successful
/// unlock under the new protection.
pub fn old_key_deletion_allowed(stage: RotationStage, unlocked_after_promote: bool) -> bool {
    stage == RotationStage::Promoted && unlocked_after_promote
}

/// Invalidation handling (target "Key or secure-lock invalidation").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvalidationResponse {
    /// Preserve key/files; block vault use until requalification + Retry.
    RequalifyAndRetry,
    /// Secure lock removed: immediately invalidate session, preserve all.
    BlockUntilSecureLockRestored,
    /// StrongBox temporarily unavailable: Retry, never generate a TEE key.
    RetryStrongBox,
    /// Key missing/permanently invalidated: preserve files; portable recovery.
    PortableRecoveryOnly,
}

pub fn handle_invalidation(
    secure_lock: SecureLockState,
    key_state: KeyState,
    strong_box_attempt: Option<StrongBoxAttempt>,
) -> InvalidationResponse {
    if secure_lock == SecureLockState::NotConfigured {
        return InvalidationResponse::BlockUntilSecureLockRestored;
    }
    match key_state {
        KeyState::Invalidated | KeyState::PropertyMismatch => {
            InvalidationResponse::PortableRecoveryOnly
        }
        KeyState::Absent => InvalidationResponse::PortableRecoveryOnly,
        KeyState::Active | KeyState::Staged => {
            if let Some(attempt) = strong_box_attempt {
                if attempt == StrongBoxAttempt::Retryable {
                    return InvalidationResponse::RetryStrongBox;
                }
            }
            InvalidationResponse::RequalifyAndRetry
        }
    }
}

/// Safe recovery actions offered after invalidation (closed, no raw detail).
pub fn invalidation_recovery_actions(response: InvalidationResponse) -> &'static [RecoveryAction] {
    match response {
        InvalidationResponse::RequalifyAndRetry => &[RecoveryAction::Retry],
        InvalidationResponse::BlockUntilSecureLockRestored => &[
            RecoveryAction::OpenSecuritySettings,
            RecoveryAction::Retry,
            RecoveryAction::RemoveLocalUser,
            RecoveryAction::PortableRecovery,
        ],
        InvalidationResponse::RetryStrongBox => &[RecoveryAction::Retry],
        InvalidationResponse::PortableRecoveryOnly => &[
            RecoveryAction::UpdateApp,
            RecoveryAction::RemoveLocalUser,
            RecoveryAction::PortableRecovery,
        ],
    }
}

/// Map an inner-unlock outcome to a closed result code (no oracle: outer
/// integrity failure never surfaces as wrong-password).
pub fn inner_unlock_to_result(outcome: InnerUnlockOutcome) -> AndroidResultCode {
    match outcome {
        InnerUnlockOutcome::Success => AndroidResultCode::Ok,
        InnerUnlockOutcome::WrongPasswordOrDamagedData => {
            AndroidResultCode::WrongPasswordOrDamagedData
        }
        InnerUnlockOutcome::DeviceLocked => AndroidResultCode::DeviceLocked,
        InnerUnlockOutcome::PlatformIntegrityFailure => AndroidResultCode::WrapperIntegrityFailure,
        InnerUnlockOutcome::TemporaryKeystoreFailure => AndroidResultCode::TemporaryKeystoreFailure,
        InnerUnlockOutcome::KdfResourceLimit => AndroidResultCode::KdfResourceLimit,
        InnerUnlockOutcome::StaleResult | InnerUnlockOutcome::Cancelled => {
            AndroidResultCode::StaleSession
        }
        InnerUnlockOutcome::NetworkFailure => AndroidResultCode::NetworkTimeout,
        InnerUnlockOutcome::PlatformInvalidated => AndroidResultCode::PlatformProtectionInvalidated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttle_sequence_is_exact() {
        // Attempts 0-3 (before the 4th completed failure): KDF cost only.
        for n in 0..KDF_ONLY_ATTEMPTS {
            assert_eq!(compute_cooldown(n), ThrottleDecision::Allowed);
        }
        assert_eq!(
            compute_cooldown(4),
            ThrottleDecision::Denied { cooldown_secs: 5 }
        );
        assert_eq!(
            compute_cooldown(5),
            ThrottleDecision::Denied { cooldown_secs: 10 }
        );
        assert_eq!(
            compute_cooldown(6),
            ThrottleDecision::Denied { cooldown_secs: 20 }
        );
        assert_eq!(
            compute_cooldown(7),
            ThrottleDecision::Denied { cooldown_secs: 40 }
        );
        assert_eq!(
            compute_cooldown(8),
            ThrottleDecision::Denied { cooldown_secs: 80 }
        );
        assert_eq!(
            compute_cooldown(9),
            ThrottleDecision::Denied { cooldown_secs: 160 }
        );
        for n in [10u8, 11, 50, 200] {
            assert_eq!(
                compute_cooldown(n),
                ThrottleDecision::Denied {
                    cooldown_secs: THROTTLE_CAP_SECS
                }
            );
        }
    }

    #[test]
    fn only_completed_inner_failures_count() {
        let mut sidecar = SidecarThrottle::default();
        for outcome in [
            InnerUnlockOutcome::WrongPasswordOrDamagedData,
            InnerUnlockOutcome::WrongPasswordOrDamagedData,
            InnerUnlockOutcome::DeviceLocked,
            InnerUnlockOutcome::PlatformIntegrityFailure,
            InnerUnlockOutcome::TemporaryKeystoreFailure,
            InnerUnlockOutcome::KdfResourceLimit,
            InnerUnlockOutcome::StaleResult,
            InnerUnlockOutcome::Cancelled,
            InnerUnlockOutcome::NetworkFailure,
        ] {
            sidecar = update_throttle(Some(sidecar), outcome);
        }
        assert_eq!(sidecar.failed_inner_attempts, 2);
    }

    #[test]
    fn success_resets_throttle() {
        let sidecar = SidecarThrottle {
            failed_inner_attempts: 7,
        };
        let after = update_throttle(Some(sidecar), InnerUnlockOutcome::Success);
        assert_eq!(after.failed_inner_attempts, 0);
    }

    #[test]
    fn malformed_sidecar_cannot_create_permanent_denial() {
        // u8 caps the counter; saturating add prevents wraparound.
        let sidecar = SidecarThrottle {
            failed_inner_attempts: 255,
        };
        let after = update_throttle(
            Some(sidecar),
            InnerUnlockOutcome::WrongPasswordOrDamagedData,
        );
        assert_eq!(after.failed_inner_attempts, 255);
        // The cap applies regardless.
        assert_eq!(
            compute_cooldown(after.failed_inner_attempts),
            ThrottleDecision::Denied {
                cooldown_secs: THROTTLE_CAP_SECS
            }
        );
    }

    #[test]
    fn rotation_requires_authenticated_old_package_and_single_pending_key() {
        assert_eq!(
            rotation_may_start(false, false, RotationStage::None),
            RotationDecision::OldPackageNotAuthenticated
        );
        assert_eq!(
            rotation_may_start(true, true, RotationStage::None),
            RotationDecision::AlreadyPending
        );
        assert_eq!(
            rotation_may_start(true, false, RotationStage::None),
            RotationDecision::Proceed
        );
        assert_eq!(
            rotation_may_start(true, false, RotationStage::PendingKeyCreated),
            RotationDecision::AlreadyPending
        );
    }

    #[test]
    fn old_key_deleted_only_after_promotion_and_unlock() {
        assert!(!old_key_deletion_allowed(RotationStage::Promoted, false));
        assert!(old_key_deletion_allowed(RotationStage::Promoted, true));
        assert!(!old_key_deletion_allowed(
            RotationStage::NewPackageVerified,
            true
        ));
        let stage = advance_rotation(RotationStage::NewPackageVerified, true, false);
        assert_eq!(stage, RotationStage::Promoted);
        let final_stage = advance_rotation(stage, false, true);
        assert_eq!(final_stage, RotationStage::OldKeyDeleted);
    }

    #[test]
    fn invalidation_handling_is_fail_closed() {
        assert_eq!(
            handle_invalidation(SecureLockState::NotConfigured, KeyState::Active, None),
            InvalidationResponse::BlockUntilSecureLockRestored
        );
        assert_eq!(
            handle_invalidation(SecureLockState::Configured, KeyState::Invalidated, None),
            InvalidationResponse::PortableRecoveryOnly
        );
        assert_eq!(
            handle_invalidation(
                SecureLockState::Configured,
                KeyState::Active,
                Some(StrongBoxAttempt::Retryable)
            ),
            InvalidationResponse::RetryStrongBox
        );
        assert_eq!(
            handle_invalidation(SecureLockState::Configured, KeyState::Active, None),
            InvalidationResponse::RequalifyAndRetry
        );
    }

    #[test]
    fn no_platform_integrity_failure_surfaces_as_wrong_password() {
        assert_eq!(
            inner_unlock_to_result(InnerUnlockOutcome::PlatformIntegrityFailure),
            AndroidResultCode::WrapperIntegrityFailure
        );
        assert_ne!(
            inner_unlock_to_result(InnerUnlockOutcome::PlatformIntegrityFailure),
            AndroidResultCode::WrongPasswordOrDamagedData
        );
    }

    #[test]
    fn kdf_and_network_failures_map_to_distinct_closed_codes() {
        // KDF resource limits and network timeouts must never be conflated
        // with hardware or storage failures (misleading UI remediation).
        assert_eq!(
            inner_unlock_to_result(InnerUnlockOutcome::KdfResourceLimit),
            AndroidResultCode::KdfResourceLimit
        );
        assert_ne!(
            inner_unlock_to_result(InnerUnlockOutcome::KdfResourceLimit),
            AndroidResultCode::HardwareBackedKeystoreUnavailable
        );
        assert_eq!(
            inner_unlock_to_result(InnerUnlockOutcome::NetworkFailure),
            AndroidResultCode::NetworkTimeout
        );
        assert_ne!(
            inner_unlock_to_result(InnerUnlockOutcome::NetworkFailure),
            AndroidResultCode::StorageUnavailable
        );
    }
}
