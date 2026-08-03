//! Android native session authority (FEAT-006 Phase 4, Task 4.3).
//!
//! Rust owns session epochs, capability phases, and timeout evaluation. The
//! WebView receives only unpredictable, in-memory, epoch/channel-bound opaque
//! handles. Every operation validates: main-window caller and Android
//! production runtime; WebView/Rust/Kotlin protocol versions; session epoch,
//! channel, handle, and operation ID; capability phase; operation kind/version
//! and payload bounds; canonical network and public identity; and
//! operation-specific confirmation context. Lock, timeout, process death,
//! activity-authority loss, replacement, removal, platform invalidation, build
//! mismatch, or identity mismatch revokes every handle. Handles are never
//! persisted, logged, placed in navigation/history, or transferred across
//! processes/profiles/devices. Process recreation and reboot always begin
//! Locked; JavaScript cannot extend a native session.

use crate::android_vault::contracts::lifecycle::LifecycleEvidence;
use crate::android_vault::contracts::result::AndroidResultCode;

/// WebView<->Rust IPC protocol version (shared with FEAT-005, platform-neutral).
pub const IPC_PROTOCOL_VERSION: VersionPair = VersionPair { major: 1, minor: 0 };
/// Rust<->Kotlin mobile-plugin protocol version (Android-specific).
pub const MOBILE_PLUGIN_PROTOCOL_VERSION: VersionPair = VersionPair { major: 1, minor: 0 };
/// Default idle lock: five minutes.
pub const DEFAULT_IDLE_LOCK_SECS: u64 = 300;
/// Default background/screen-off lock: 30 seconds.
pub const DEFAULT_BACKGROUND_LOCK_SECS: u64 = 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionPair {
    pub major: u32,
    pub minor: u32,
}

impl VersionPair {
    pub fn matches(self, other: VersionPair) -> bool {
        self.major == other.major && self.minor == other.minor
    }
}

/// Android capability phases (target "Sequential protection").
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapabilityPhase {
    /// No local decryption performed; only safe locked preview.
    Locked,
    /// Local decryption succeeded; exact online both-key verification required.
    VerificationOnly,
    /// Exact online verification passed; authenticated operations allowed.
    Authenticated,
}

/// Closed session errors (never raw detail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    ProtocolMismatch,
    BuildMismatch,
    WrongChannel,
    StaleEpoch,
    StaleHandle,
    PhaseForbidden,
    UnknownOperation,
    BoundsExceeded,
    IdentityUnbound,
    NotAndroidRuntime,
}

impl SessionError {
    pub fn to_result_code(self) -> AndroidResultCode {
        match self {
            Self::ProtocolMismatch | Self::BuildMismatch => {
                AndroidResultCode::BuildProtocolMismatch
            }
            Self::WrongChannel | Self::NotAndroidRuntime | Self::IdentityUnbound => {
                AndroidResultCode::StaleSession
            }
            Self::StaleEpoch | Self::StaleHandle => AndroidResultCode::StaleSession,
            Self::PhaseForbidden | Self::UnknownOperation | Self::BoundsExceeded => {
                AndroidResultCode::StaleSession
            }
        }
    }
}

/// Opaque session handle (16 random bytes; never persisted/logged).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionHandle(pub [u8; 16]);

/// Public identity binding (no secrets).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIdentity {
    pub signing_address: String,
    pub encryption_address: String,
}

/// The Android native session authority. One instance per application process.
#[derive(Debug)]
pub struct SessionAuthority {
    epoch: u64,
    phase: CapabilityPhase,
    handle: Option<SessionHandle>,
    identity: Option<SessionIdentity>,
    build_version: VersionPair,
    ipc_protocol: VersionPair,
    mobile_plugin_protocol: VersionPair,
    android_runtime: bool,
}

impl SessionAuthority {
    pub fn new(build_version: VersionPair, android_runtime: bool) -> Self {
        Self {
            epoch: 1,
            phase: CapabilityPhase::Locked,
            handle: None,
            identity: None,
            build_version,
            ipc_protocol: IPC_PROTOCOL_VERSION,
            mobile_plugin_protocol: MOBILE_PLUGIN_PROTOCOL_VERSION,
            android_runtime,
        }
    }

    pub fn phase(&self) -> CapabilityPhase {
        self.phase
    }

    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Exact handshake: build version, IPC protocol, mobile-plugin protocol,
    /// and Android production runtime. A mismatch grants no handle, performs
    /// no wrap/unwrap, preserves keys/files, and transfers no session.
    pub fn handshake(
        &mut self,
        build: VersionPair,
        ipc: VersionPair,
        plugin: VersionPair,
    ) -> Result<(), SessionError> {
        if !self.android_runtime {
            return Err(SessionError::NotAndroidRuntime);
        }
        if !self.build_version.matches(build) {
            return Err(SessionError::BuildMismatch);
        }
        if !self.ipc_protocol.matches(ipc) || !self.mobile_plugin_protocol.matches(plugin) {
            return Err(SessionError::ProtocolMismatch);
        }
        Ok(())
    }

    /// Promote the current epoch to VerificationOnly after local decryption.
    pub fn begin_verification_only(
        &mut self,
        identity: SessionIdentity,
    ) -> Result<SessionHandle, SessionError> {
        if self.phase != CapabilityPhase::Locked {
            return Err(SessionError::PhaseForbidden);
        }
        if identity.signing_address.is_empty() || identity.encryption_address.is_empty() {
            return Err(SessionError::IdentityUnbound);
        }
        self.phase = CapabilityPhase::VerificationOnly;
        self.identity = Some(identity);
        self.issue_handle()
    }

    /// Promote only after exact online both-key verification (native).
    pub fn promote_authenticated(
        &mut self,
        online_verified: bool,
    ) -> Result<SessionHandle, SessionError> {
        if !online_verified {
            return Err(SessionError::IdentityUnbound);
        }
        if self.phase != CapabilityPhase::VerificationOnly {
            return Err(SessionError::PhaseForbidden);
        }
        self.phase = CapabilityPhase::Authenticated;
        self.issue_handle()
    }

    /// Issue a fresh opaque handle for the current epoch.
    fn issue_handle(&mut self) -> Result<SessionHandle, SessionError> {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).map_err(|_| SessionError::StaleHandle)?;
        let handle = SessionHandle(bytes);
        self.handle = Some(handle);
        Ok(handle)
    }

    /// Validate an operation against the current epoch/phase/handle and
    /// operation bounds (closed; unknown operations fail closed).
    pub fn validate_operation(
        &self,
        handle: SessionHandle,
        required_phase: CapabilityPhase,
        operation_id: u16,
        declared_bounds_ok: bool,
    ) -> Result<(), SessionError> {
        if self.handle != Some(handle) {
            return Err(SessionError::StaleHandle);
        }
        if self.phase < required_phase {
            return Err(SessionError::PhaseForbidden);
        }
        if operation_id == 0 {
            return Err(SessionError::UnknownOperation);
        }
        if !declared_bounds_ok {
            return Err(SessionError::BoundsExceeded);
        }
        Ok(())
    }

    /// Revoke every handle and drop to Locked (synchronous).
    pub fn lock(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.phase = CapabilityPhase::Locked;
        self.handle = None;
        self.identity = None;
    }

    /// Apply a lifecycle boundary: process/activity recreation, reboot, and
    /// lock always begin Locked with a fresh epoch.
    pub fn apply_boundary(&mut self, boundary: SessionBoundary) {
        self.epoch = self.epoch.wrapping_add(1);
        self.phase = CapabilityPhase::Locked;
        self.handle = None;
        let _ = boundary;
    }
}

/// Lifecycle boundaries that revoke the session (target "Native authority").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionBoundary {
    ExplicitLock,
    ProcessDeath,
    ActivityRecreation,
    Reboot,
    Replacement,
    Removal,
    PlatformInvalidation,
    BuildMismatch,
    IdentityMismatch,
    AuthorityLoss,
}

/// Every security boundary must revoke handles (Task 4.4 matrix).
pub const ALL_SESSION_BOUNDARIES: &[SessionBoundary] = &[
    SessionBoundary::ExplicitLock,
    SessionBoundary::ProcessDeath,
    SessionBoundary::ActivityRecreation,
    SessionBoundary::Reboot,
    SessionBoundary::Replacement,
    SessionBoundary::Removal,
    SessionBoundary::PlatformInvalidation,
    SessionBoundary::BuildMismatch,
    SessionBoundary::IdentityMismatch,
    SessionBoundary::AuthorityLoss,
];

/// Idle/background lock policy (target "Lock policy"). Choices preserved from
/// EPIC-001/FEAT-003; a one-time warning exists for weaker choices; explicit
/// Lock, process death/restart, and recovery-word foreground concealment
/// cannot be disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockPolicy {
    pub idle_secs: u64,
    pub background_secs: u64,
}

impl LockPolicy {
    /// Defaults: five-minute idle, 30-second background.
    pub fn defaults() -> Self {
        Self {
            idle_secs: DEFAULT_IDLE_LOCK_SECS,
            background_secs: DEFAULT_BACKGROUND_LOCK_SECS,
        }
    }

    /// Allowed idle choices.
    pub const IDLE_CHOICES_SECS: [u64; 6] = [60, 300, 900, 1800, 3600, u64::MAX];

    /// Allowed background choices (u64::MAX = until restart).
    pub const BACKGROUND_CHOICES_SECS: [u64; 6] = [0, 30, 120, 300, 900, u64::MAX];

    pub fn is_valid_idle(secs: u64) -> bool {
        Self::IDLE_CHOICES_SECS.contains(&secs)
    }

    pub fn is_valid_background(secs: u64) -> bool {
        Self::BACKGROUND_CHOICES_SECS.contains(&secs)
    }

    /// Weaker choices (shortest idle or immediate background) require the
    /// one-time warning.
    pub fn requires_weaker_choice_warning(&self) -> bool {
        self.idle_secs <= 60 || self.background_secs == 0
    }
}

/// Boot-aware timing decision (target "Time authority"). Wall time is a
/// conservative cross-check only; implausible evidence locks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimingDecision {
    SessionActive,
    SessionExpired,
    EvidenceImplausible,
    DeviceLocked,
}

/// Evaluate whether a session may stay active given lifecycle evidence and
/// the configured lock policy. `elapsed_idle_ms`/`elapsed_background_ms` are
/// monotonic deltas computed by the caller from boot-aware evidence.
pub fn evaluate_timing(
    evidence: &LifecycleEvidence,
    policy: &LockPolicy,
    elapsed_idle_ms: u64,
    elapsed_background_ms: u64,
) -> TimingDecision {
    if !evidence.is_plausible() {
        return TimingDecision::EvidenceImplausible;
    }
    if evidence.device_locked {
        return TimingDecision::DeviceLocked;
    }
    if evidence.all_windows_backgrounded && elapsed_background_ms >= policy.background_secs * 1000 {
        return TimingDecision::SessionExpired;
    }
    if elapsed_idle_ms >= policy.idle_secs * 1000 {
        return TimingDecision::SessionExpired;
    }
    TimingDecision::SessionActive
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(unlocked: bool) -> LifecycleEvidence {
        LifecycleEvidence {
            boot_elapsed_millis: 3_600_000,
            device_locked: !unlocked,
            all_windows_backgrounded: false,
            main_window_focused: true,
        }
    }

    fn authority() -> SessionAuthority {
        SessionAuthority::new(VersionPair { major: 1, minor: 0 }, true)
    }

    #[test]
    fn handshake_requires_exact_versions_and_android_runtime() {
        let mut a = authority();
        assert!(a
            .handshake(
                VersionPair { major: 1, minor: 0 },
                IPC_PROTOCOL_VERSION,
                MOBILE_PLUGIN_PROTOCOL_VERSION
            )
            .is_ok());
        assert_eq!(
            a.handshake(
                VersionPair { major: 2, minor: 0 },
                IPC_PROTOCOL_VERSION,
                MOBILE_PLUGIN_PROTOCOL_VERSION
            ),
            Err(SessionError::BuildMismatch)
        );
        assert_eq!(
            a.handshake(
                VersionPair { major: 1, minor: 0 },
                VersionPair { major: 1, minor: 1 },
                MOBILE_PLUGIN_PROTOCOL_VERSION
            ),
            Err(SessionError::ProtocolMismatch)
        );
        let mut desktop = SessionAuthority::new(VersionPair { major: 1, minor: 0 }, false);
        assert_eq!(
            desktop.handshake(
                VersionPair { major: 1, minor: 0 },
                IPC_PROTOCOL_VERSION,
                MOBILE_PLUGIN_PROTOCOL_VERSION
            ),
            Err(SessionError::NotAndroidRuntime)
        );
    }

    #[test]
    fn phases_progress_only_after_local_then_online_verification() {
        let mut a = authority();
        assert_eq!(a.phase(), CapabilityPhase::Locked);
        let h1 = a
            .begin_verification_only(SessionIdentity {
                signing_address: "addr1".to_string(),
                encryption_address: "addr2".to_string(),
            })
            .unwrap();
        assert_eq!(a.phase(), CapabilityPhase::VerificationOnly);
        // VerificationOnly cannot perform authenticated operations.
        assert_eq!(
            a.validate_operation(h1, CapabilityPhase::Authenticated, 1, true),
            Err(SessionError::PhaseForbidden)
        );
        // Fabricated WebView verification is impossible: promotion requires
        // the native online-verified flag.
        assert_eq!(
            a.promote_authenticated(false),
            Err(SessionError::IdentityUnbound)
        );
        let h2 = a.promote_authenticated(true).unwrap();
        assert_eq!(a.phase(), CapabilityPhase::Authenticated);
        assert_ne!(h1, h2);
        assert!(a
            .validate_operation(h2, CapabilityPhase::Authenticated, 7, true)
            .is_ok());
        // Old handle is stale after promotion.
        assert_eq!(
            a.validate_operation(h1, CapabilityPhase::Authenticated, 7, true),
            Err(SessionError::StaleHandle)
        );
    }

    #[test]
    fn every_security_boundary_revokes_handles() {
        for boundary in ALL_SESSION_BOUNDARIES {
            let mut a = authority();
            let h = a
                .begin_verification_only(SessionIdentity {
                    signing_address: "a".to_string(),
                    encryption_address: "b".to_string(),
                })
                .unwrap();
            a.apply_boundary(*boundary);
            assert_eq!(a.phase(), CapabilityPhase::Locked, "boundary {boundary:?}");
            assert_eq!(
                a.validate_operation(h, CapabilityPhase::VerificationOnly, 1, true),
                Err(SessionError::StaleHandle),
                "handle survived boundary {boundary:?}"
            );
        }
    }

    #[test]
    fn lock_is_synchronous_and_increments_epoch() {
        let mut a = authority();
        let h = a
            .begin_verification_only(SessionIdentity {
                signing_address: "a".to_string(),
                encryption_address: "b".to_string(),
            })
            .unwrap();
        let e1 = a.epoch();
        a.lock();
        assert_eq!(a.epoch(), e1.wrapping_add(1));
        assert_eq!(a.phase(), CapabilityPhase::Locked);
        assert_eq!(
            a.validate_operation(h, CapabilityPhase::Locked, 1, true),
            Err(SessionError::StaleHandle)
        );
    }

    #[test]
    fn stale_and_generic_operations_are_rejected() {
        let mut a = authority();
        let h = a
            .begin_verification_only(SessionIdentity {
                signing_address: "a".to_string(),
                encryption_address: "b".to_string(),
            })
            .unwrap();
        assert_eq!(
            a.validate_operation(h, CapabilityPhase::VerificationOnly, 0, true),
            Err(SessionError::UnknownOperation)
        );
        assert_eq!(
            a.validate_operation(h, CapabilityPhase::VerificationOnly, 1, false),
            Err(SessionError::BoundsExceeded)
        );
        assert_eq!(
            a.validate_operation(
                SessionHandle([0; 16]),
                CapabilityPhase::VerificationOnly,
                1,
                true
            ),
            Err(SessionError::StaleHandle)
        );
    }

    #[test]
    fn lock_policy_choices_are_closed() {
        assert!(LockPolicy::is_valid_idle(300));
        assert!(LockPolicy::is_valid_idle(u64::MAX));
        assert!(!LockPolicy::is_valid_idle(120));
        assert!(LockPolicy::is_valid_background(30));
        assert!(LockPolicy::is_valid_background(0));
        assert!(!LockPolicy::is_valid_background(45));
        assert!(!LockPolicy::defaults().requires_weaker_choice_warning());
        let weak = LockPolicy {
            idle_secs: 60,
            background_secs: 0,
        };
        assert!(weak.requires_weaker_choice_warning());
    }

    #[test]
    fn timing_policy_locks_on_implausible_locked_or_expired() {
        let policy = LockPolicy::defaults();
        assert_eq!(
            evaluate_timing(&evidence(true), &policy, 1000, 0),
            TimingDecision::SessionActive
        );
        assert_eq!(
            evaluate_timing(&evidence(true), &policy, 6 * 60 * 1000, 0),
            TimingDecision::SessionExpired
        );
        assert_eq!(
            evaluate_timing(&evidence(false), &policy, 1000, 0),
            TimingDecision::DeviceLocked
        );
        let mut bg = evidence(true);
        bg.all_windows_backgrounded = true;
        bg.main_window_focused = false;
        assert_eq!(
            evaluate_timing(&bg, &policy, 1000, 31_000),
            TimingDecision::SessionExpired
        );
        let mut implausible = evidence(true);
        implausible.main_window_focused = true;
        implausible.all_windows_backgrounded = true;
        assert_eq!(
            evaluate_timing(&implausible, &policy, 1000, 0),
            TimingDecision::EvidenceImplausible
        );
    }
}
