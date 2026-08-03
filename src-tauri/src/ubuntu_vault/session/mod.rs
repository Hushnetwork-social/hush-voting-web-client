//! Opaque native session authority (FEAT-005 "Opaque session", "Tauri IPC
//! and Native Session", "WebView/native handshake").
//!
//! Rust retains decrypted credentials inside native secret containers; the
//! WebView receives only unpredictable, in-memory, epoch-bound opaque handles.
//! Every command validates: main-window caller, exact app-build and
//! IPC-protocol versions, session epoch/handle, operation ID/version/purpose,
//! current capability phase, input size, expected public identity, and
//! user-confirmation context.
//!
//! Lock, timeout, removal, replacement, native failure, ownership loss,
//! process exit, or identity invalidation revokes every handle. Handles are
//! never persisted, logged, copied into navigation/history, or transferred.

use std::collections::HashSet;

pub mod commands;
pub mod lifecycle;

use crate::ubuntu_vault::contracts::operations::{CapabilityPhase, OperationKind};
use crate::ubuntu_vault::contracts::results::NativeErrorCode;
use crate::ubuntu_vault::contracts::session::{SessionEpoch, SessionHandle};
use crate::ubuntu_vault::crypto::random_bytes;

/// Application build version (exact handshake, no secret capability before
/// exact match).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionPair {
    pub major: u32,
    pub minor: u32,
}

/// Caller runtime target — only the main window is an allowed target.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeTarget {
    MainWindow,
    Untrusted,
}

/// Public identity bound to the native session (native-owned; NO private
/// material — only safe public review fields).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionIdentity {
    /// SEC1 compressed/uncompressed signing-address hex.
    pub signing_address: String,
    pub encrypt_address: String,
}

/// Closed session failure vocabulary (raw detail never crosses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionError {
    BuildVersionMismatch,
    ProtocolVersionMismatch,
    StaleSession,
    OperationForbidden,
    PhaseForbidden,
    IdentityUnbound,
    RngFailed,
}

impl SessionError {
    pub fn to_native_error(self) -> NativeErrorCode {
        match self {
            Self::BuildVersionMismatch | Self::ProtocolVersionMismatch => {
                NativeErrorCode::BuildVersionMismatch
            }
            Self::StaleSession => NativeErrorCode::StaleSession,
            Self::OperationForbidden | Self::PhaseForbidden | Self::IdentityUnbound => {
                NativeErrorCode::OperationForbidden
            }
            Self::RngFailed => NativeErrorCode::PlatformProtectionUnavailable,
        }
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "session failure (closed code)")
    }
}

impl std::error::Error for SessionError {}

/// The opaque native session authority (single authority per application
/// instance). Wrapped in a mutex by the Tauri composition root.
pub struct SessionAuthority {
    epoch: SessionEpoch,
    phase: CapabilityPhase,
    build_version: VersionPair,
    protocol_version: VersionPair,
    /// Public identity bound after local decryption (VerificationOnly). The
    /// WebView can never set this value.
    identity: Option<SessionIdentity>,
    /// Current-epoch opaque handle values (revoked by epoch advance).
    handles: HashSet<[u8; 16]>,
    /// Bound confirmation context of the active operation, when one exists.
    active_operation: Option<OperationKind>,
}

impl Default for SessionAuthority {
    fn default() -> Self {
        Self {
            epoch: SessionEpoch(1),
            phase: CapabilityPhase::Locked,
            build_version: VersionPair { major: 1, minor: 0 },
            protocol_version: VersionPair { major: 1, minor: 0 },
            identity: None,
            handles: HashSet::new(),
            active_operation: None,
        }
    }
}

impl SessionAuthority {
    pub fn new(build_version: VersionPair, protocol_version: VersionPair) -> Self {
        Self {
            build_version,
            protocol_version,
            ..Self::default()
        }
    }

    pub fn phase(&self) -> CapabilityPhase {
        self.phase
    }

    pub fn epoch(&self) -> SessionEpoch {
        self.epoch
    }

    /// Exact app-build/protocol handshake. A mismatch grants no handle,
    /// accepts no secret, preserves vault/keyring state, and fails closed.
    pub fn handshake(
        &mut self,
        build: VersionPair,
        protocol: VersionPair,
        target: RuntimeTarget,
    ) -> Result<(), SessionError> {
        if target != RuntimeTarget::MainWindow {
            return Err(SessionError::OperationForbidden);
        }
        if build != self.build_version {
            return Err(SessionError::BuildVersionMismatch);
        }
        if protocol != self.protocol_version {
            return Err(SessionError::ProtocolVersionMismatch);
        }
        Ok(())
    }

    /// Advance from Locked to Provisioning (fresh vault or restore path).
    pub fn begin_provisioning(&mut self) -> Result<(), SessionError> {
        if self.phase != CapabilityPhase::Locked {
            return Err(SessionError::PhaseForbidden);
        }
        self.phase = CapabilityPhase::Provisioning;
        Ok(())
    }

    /// Bind the native-decrypted public identity (VerificationOnly). This is
    /// the ONLY way `identity` becomes Some — never from the WebView.
    pub fn bind_identity(&mut self, identity: SessionIdentity) -> Result<(), SessionError> {
        if self.phase != CapabilityPhase::Provisioning
            && self.phase != CapabilityPhase::VerificationOnly
        {
            return Err(SessionError::PhaseForbidden);
        }
        self.identity = Some(identity);
        self.phase = CapabilityPhase::VerificationOnly;
        Ok(())
    }

    /// Promote to Authenticated — only from VerificationOnly after exact
    /// online both-key verification (Phase 4.3 authority).
    pub fn promote_authenticated(&mut self) -> Result<(), SessionError> {
        if self.phase != CapabilityPhase::VerificationOnly || self.identity.is_none() {
            return Err(SessionError::PhaseForbidden);
        }
        self.phase = CapabilityPhase::Authenticated;
        Ok(())
    }

    pub fn bound_identity(&self) -> Option<&SessionIdentity> {
        self.identity.as_ref()
    }

    /// Issue a fresh opaque handle bound to the current epoch. Never
    /// persisted; revoked by every epoch advance. A handle is the WebView's
    /// instance identity — it may be issued in Locked (the UI needs it to
    /// submit the next Unlock), but it grants nothing: every operation still
    /// validates the capability phase.
    pub fn issue_handle(&mut self) -> Result<SessionHandle, SessionError> {
        for _ in 0..8 {
            let opaque = random_bytes(16).map_err(|_| SessionError::RngFailed)?;
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&opaque);
            if self.handles.insert(bytes) {
                return Ok(SessionHandle {
                    epoch: self.epoch,
                    opaque: bytes,
                    main_window_only: true,
                });
            }
        }
        Err(SessionError::RngFailed)
    }

    /// Validate a handle for the given required capability phase.
    pub fn validate(
        &self,
        handle: &SessionHandle,
        required: CapabilityPhase,
    ) -> Result<(), SessionError> {
        if handle.epoch != self.epoch {
            return Err(SessionError::StaleSession);
        }
        if !handle.main_window_only {
            return Err(SessionError::OperationForbidden);
        }
        if !self.handles.contains(&handle.opaque) {
            return Err(SessionError::StaleSession);
        }
        if !capability_satisfies(self.phase, required) {
            return Err(SessionError::PhaseForbidden);
        }
        Ok(())
    }

    /// Bind the active operation (one at a time; re-binding requires an
    /// explicit new dispatch).
    pub fn bind_operation(&mut self, kind: OperationKind) {
        self.active_operation = Some(kind);
    }

    pub fn active_operation(&self) -> Option<OperationKind> {
        self.active_operation
    }

    /// Global Lock: synchronously invalidates every handle, increments the
    /// epoch, drops the identity binding, and returns the new epoch.
    pub fn lock(&mut self) -> SessionEpoch {
        self.handles.clear();
        self.epoch = self.epoch.next();
        self.phase = CapabilityPhase::Locked;
        self.identity = None;
        self.active_operation = None;
        self.epoch
    }
}

/// Capability-phase ordering: Locked is the base state (safe preview only);
/// Provisioning and VerificationOnly/Authenticated satisfy their own and
/// stronger phases monotonically. Removal is exclusive.
pub fn capability_satisfies(current: CapabilityPhase, required: CapabilityPhase) -> bool {
    use CapabilityPhase::*;
    match required {
        Locked => matches!(
            current,
            Locked | Provisioning | VerificationOnly | Authenticated | Removal
        ),
        Provisioning => current == Provisioning,
        VerificationOnly => matches!(current, VerificationOnly | Authenticated),
        Authenticated => current == Authenticated,
        Removal => current == Removal,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ubuntu_vault::contracts::operations::OperationKind;

    fn authority() -> SessionAuthority {
        SessionAuthority::new(
            VersionPair { major: 1, minor: 0 },
            VersionPair { major: 1, minor: 0 },
        )
    }

    fn provisioned() -> SessionAuthority {
        let mut a = authority();
        a.begin_provisioning().unwrap();
        a.bind_identity(SessionIdentity {
            signing_address: "0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5"
                .to_string(),
            encrypt_address: "032ebaf076203f15ac8119cfdbc9394d1c7b9929b0647e4f607e27da95701f8556"
                .to_string(),
        })
        .unwrap();
        a
    }

    #[test]
    fn starts_locked_and_can_issue_a_session_handle() {
        let mut a = authority();
        assert_eq!(a.phase(), CapabilityPhase::Locked);
        // The WebView always holds a session handle (instance identity); it
        // grants no capability by itself.
        assert!(a.issue_handle().is_ok());
        // Secret-capable operations still fail phase gating while locked.
        let handle = a.issue_handle().unwrap();
        assert_eq!(
            a.validate(&handle, CapabilityPhase::VerificationOnly),
            Err(SessionError::PhaseForbidden)
        );
    }

    #[test]
    fn handshake_requires_exact_versions_and_main_window() {
        let mut a = authority();
        assert!(a
            .handshake(
                VersionPair { major: 1, minor: 0 },
                VersionPair { major: 1, minor: 0 },
                RuntimeTarget::MainWindow
            )
            .is_ok());
        assert_eq!(
            a.handshake(
                VersionPair { major: 2, minor: 0 },
                VersionPair { major: 1, minor: 0 },
                RuntimeTarget::MainWindow
            ),
            Err(SessionError::BuildVersionMismatch)
        );
        assert_eq!(
            a.handshake(
                VersionPair { major: 1, minor: 0 },
                VersionPair { major: 1, minor: 1 },
                RuntimeTarget::MainWindow
            ),
            Err(SessionError::ProtocolVersionMismatch)
        );
        assert_eq!(
            a.handshake(
                VersionPair { major: 1, minor: 0 },
                VersionPair { major: 1, minor: 0 },
                RuntimeTarget::Untrusted
            ),
            Err(SessionError::OperationForbidden)
        );
    }

    #[test]
    fn handles_are_opaque_unpredictable_and_epoch_bound() {
        let mut a = provisioned();
        let h1 = a.issue_handle().unwrap();
        let h2 = a.issue_handle().unwrap();
        assert_ne!(h1.opaque, h2.opaque);
        assert_eq!(h1.epoch, a.epoch());
        assert!(a.validate(&h1, CapabilityPhase::VerificationOnly).is_ok());
        assert!(a.validate(&h2, CapabilityPhase::VerificationOnly).is_ok());
        // A forged/unknown handle fails.
        let forged = SessionHandle {
            epoch: a.epoch(),
            opaque: [0xabu8; 16],
            main_window_only: true,
        };
        assert_eq!(
            a.validate(&forged, CapabilityPhase::VerificationOnly),
            Err(SessionError::StaleSession)
        );
    }

    #[test]
    fn stale_epoch_handle_is_rejected_after_lock() {
        let mut a = provisioned();
        let h = a.issue_handle().unwrap();
        a.lock();
        assert_eq!(
            a.validate(&h, CapabilityPhase::VerificationOnly),
            Err(SessionError::StaleSession)
        );
        assert_eq!(a.phase(), CapabilityPhase::Locked);
        // After Lock the WebView may obtain a fresh (new-epoch) handle.
        assert!(a.issue_handle().is_ok());
    }

    #[test]
    fn promotion_requires_verification_only_with_identity() {
        let mut a = authority();
        assert_eq!(a.promote_authenticated(), Err(SessionError::PhaseForbidden));
        a.begin_provisioning().unwrap();
        assert_eq!(a.promote_authenticated(), Err(SessionError::PhaseForbidden));
        a.bind_identity(SessionIdentity {
            signing_address: "0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5"
                .to_string(),
            encrypt_address: "032ebaf076203f15ac8119cfdbc9394d1c7b9929b0647e4f607e27da95701f8556"
                .to_string(),
        })
        .unwrap();
        assert_eq!(a.phase(), CapabilityPhase::VerificationOnly);
        a.promote_authenticated().unwrap();
        assert_eq!(a.phase(), CapabilityPhase::Authenticated);
    }

    #[test]
    fn capability_ordering_is_monotonic_and_closed() {
        use CapabilityPhase::*;
        assert!(capability_satisfies(Locked, Locked));
        assert!(capability_satisfies(Provisioning, Locked));
        assert!(capability_satisfies(Authenticated, Locked));
        assert!(capability_satisfies(VerificationOnly, VerificationOnly));
        assert!(capability_satisfies(Authenticated, VerificationOnly));
        assert!(!capability_satisfies(Locked, VerificationOnly));
        assert!(!capability_satisfies(Provisioning, VerificationOnly));
        assert!(!capability_satisfies(VerificationOnly, Authenticated));
        assert!(!capability_satisfies(Locked, Provisioning));
        assert!(capability_satisfies(Removal, Removal));
        assert!(!capability_satisfies(Authenticated, Removal));
    }

    #[test]
    fn lock_revokes_every_boundary() {
        let mut a = provisioned();
        let _ = a.issue_handle();
        let before = a.epoch();
        let after = a.lock();
        assert_eq!(after, before.next());
        assert!(a.bound_identity().is_none());
        assert!(a.active_operation().is_none());
    }

    #[test]
    fn operation_binding_is_single_and_rebindable() {
        let mut a = provisioned();
        a.bind_operation(OperationKind::Unlock);
        assert_eq!(a.active_operation(), Some(OperationKind::Unlock));
        a.lock();
        assert_eq!(a.active_operation(), None);
    }
}
