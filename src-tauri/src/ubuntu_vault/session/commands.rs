//! Closed command dispatch validation (FEAT-005 "Closed operation registry",
//! "Opaque session").
//!
//! The native boundary exposes ONLY reviewed operations. This module binds the
//! session authority to the exhaustive operation registry and validates every
//! dispatch BEFORE any secret work: main-window handle, epoch, capability
//! phase, operation ID/version, purpose, input bounds, expected public
//! identity, and user-confirmation context. No generic signer, decryptor,
//! private-key return, vault decrypt, or filesystem command exists.

use crate::ubuntu_vault::contracts::operations::{operation_spec, CapabilityPhase, OperationKind};
use crate::ubuntu_vault::contracts::results::NativeErrorCode;
use crate::ubuntu_vault::contracts::session::SessionHandle;
use crate::ubuntu_vault::session::{SessionAuthority, SessionError, SessionIdentity};

/// User-confirmation binding for secret-owning operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfirmationContext {
    /// Fixed operation purpose (never secret; matches the registry).
    pub operation_purpose: &'static str,
    pub version: u32,
}

/// Everything the dispatcher needs to authorize one operation request.
#[derive(Debug, Clone)]
pub struct DispatchRequest<'a> {
    pub handle: &'a SessionHandle,
    pub kind: OperationKind,
    /// Exact input byte length (bounded by the registry spec).
    pub input_len: usize,
    /// Expected public identity binding, when the operation is identity-bound.
    pub expected_identity: Option<&'a SessionIdentity>,
    /// User-confirmation context, when the operation requires it.
    pub confirmation: Option<&'a ConfirmationContext>,
}

/// Validate a dispatch against the authority and the exhaustive registry.
/// Returns the closed code for the first violated check; no secret work runs
/// when this returns an error.
pub fn validate_dispatch(
    authority: &SessionAuthority,
    req: &DispatchRequest<'_>,
) -> Result<(), NativeErrorCode> {
    let spec = operation_spec(req.kind).ok_or(NativeErrorCode::OperationForbidden)?;

    // 1. Session epoch + main-window handle. `InspectPreview` is the ONLY
    // operation that may run without a live session handle (safe public
    // projection of the locked state — the UI has no handle on first
    // launch); every other operation requires one.
    if req.kind != OperationKind::InspectPreview {
        authority
            .validate(req.handle, spec.required_capability_phase)
            .map_err(|e| match e {
                SessionError::StaleSession => NativeErrorCode::StaleSession,
                _ => NativeErrorCode::OperationForbidden,
            })?;
    }

    // 2. Input size bound.
    if req.input_len > spec.max_input_bytes {
        return Err(NativeErrorCode::OperationForbidden);
    }

    // 3. Identity binding (exact both-key equality at the session level).
    if let Some(expected) = req.expected_identity {
        match authority.bound_identity() {
            Some(bound) => {
                if !same_public_identity(bound, expected) {
                    return Err(NativeErrorCode::IdentityBindingMismatch);
                }
            }
            None => return Err(NativeErrorCode::IdentityBindingMismatch),
        }
    }

    // 4. Confirmation context (secret-owning operations only).
    if let Some(ctx) = req.confirmation {
        if ctx.operation_purpose != spec.purpose || ctx.version != spec.version {
            return Err(NativeErrorCode::OperationForbidden);
        }
    }

    Ok(())
}

/// Exact public-identity equality (case-insensitive hex, both keys).
pub fn same_public_identity(a: &SessionIdentity, b: &SessionIdentity) -> bool {
    a.signing_address.eq_ignore_ascii_case(&b.signing_address)
        && a.encrypt_address.eq_ignore_ascii_case(&b.encrypt_address)
}

/// The required capability phase for an operation (mirror of the registry).
pub fn required_phase(kind: OperationKind) -> CapabilityPhase {
    operation_spec(kind)
        .map(|s| s.required_capability_phase)
        .unwrap_or(CapabilityPhase::Locked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ubuntu_vault::session::{RuntimeTarget, SessionAuthority, VersionPair};

    fn session(phase: CapabilityPhase) -> (SessionAuthority, SessionHandle) {
        let mut a = SessionAuthority::new(
            VersionPair { major: 1, minor: 0 },
            VersionPair { major: 1, minor: 0 },
        );
        a.handshake(
            VersionPair { major: 1, minor: 0 },
            VersionPair { major: 1, minor: 0 },
            RuntimeTarget::MainWindow,
        )
        .unwrap();
        match phase {
            CapabilityPhase::Provisioning => {
                a.begin_provisioning().unwrap();
            }
            CapabilityPhase::VerificationOnly | CapabilityPhase::Authenticated => {
                a.begin_provisioning().unwrap();
                a.bind_identity(SessionIdentity {
                    signing_address:
                        "0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5"
                            .to_string(),
                    encrypt_address:
                        "032ebaf076203f15ac8119cfdbc9394d1c7b9929b0647e4f607e27da95701f8556"
                            .to_string(),
                })
                .unwrap();
                if phase == CapabilityPhase::Authenticated {
                    a.promote_authenticated().unwrap();
                }
            }
            _ => {}
        }
        let h = a.issue_handle().unwrap();
        (a, h)
    }

    fn identity() -> SessionIdentity {
        SessionIdentity {
            signing_address: "0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5"
                .to_string(),
            encrypt_address: "032ebaf076203f15ac8119cfdbc9394d1c7b9929b0647e4f607e27da95701f8556"
                .to_string(),
        }
    }

    fn req<'a>(
        handle: &'a SessionHandle,
        kind: OperationKind,
        input_len: usize,
    ) -> DispatchRequest<'a> {
        DispatchRequest {
            handle,
            kind,
            input_len,
            expected_identity: None,
            confirmation: None,
        }
    }

    #[test]
    fn every_invalid_request_fails_before_secret_work() {
        let (a, h) = session(CapabilityPhase::Authenticated);
        // Stale handle.
        let stale = SessionHandle {
            epoch: crate::ubuntu_vault::contracts::session::SessionEpoch(999),
            opaque: h.opaque,
            main_window_only: true,
        };
        assert_eq!(
            validate_dispatch(&a, &req(&stale, OperationKind::Unlock, 0)),
            Err(NativeErrorCode::StaleSession)
        );
        // Unknown operation kind cannot exist (enum is closed), but an
        // oversized input for a bounded operation must be rejected.
        assert_eq!(
            validate_dispatch(&a, &req(&h, OperationKind::RestoreIdentity, 4096 + 1)),
            Err(NativeErrorCode::OperationForbidden)
        );
        // Identity-bound op with mismatched identity.
        let wrong = SessionIdentity {
            signing_address: "03999999999999999999999999999999999999999999999999999999999999999999"
                .to_string(),
            encrypt_address: identity().encrypt_address.clone(),
        };
        assert_eq!(
            validate_dispatch(
                &a,
                &DispatchRequest {
                    handle: &h,
                    kind: OperationKind::VerifyOnline,
                    input_len: 0,
                    expected_identity: Some(&wrong),
                    confirmation: None,
                }
            ),
            Err(NativeErrorCode::IdentityBindingMismatch)
        );
        // Wrong confirmation context.
        assert_eq!(
            validate_dispatch(
                &a,
                &DispatchRequest {
                    handle: &h,
                    kind: OperationKind::CreateFullIdentitySign,
                    input_len: 0,
                    expected_identity: None,
                    confirmation: Some(&ConfirmationContext {
                        operation_purpose: "wrong-purpose",
                        version: 1,
                    }),
                }
            ),
            Err(NativeErrorCode::OperationForbidden)
        );
    }

    #[test]
    fn valid_operation_passes_phase_gating() {
        // VerificationOnly satisfies VerifyOnline (VerificationOnly required).
        let (a, h) = session(CapabilityPhase::VerificationOnly);
        assert_eq!(
            validate_dispatch(&a, &req(&h, OperationKind::VerifyOnline, 0)),
            Ok(())
        );
        // Provisioning does not satisfy VerificationOnly.
        let (a, h) = session(CapabilityPhase::Provisioning);
        assert_eq!(
            validate_dispatch(&a, &req(&h, OperationKind::VerifyOnline, 0)),
            Err(NativeErrorCode::OperationForbidden)
        );
        // Authenticated satisfies RevealMnemonic (Authenticated required).
        let (a, h) = session(CapabilityPhase::Authenticated);
        assert_eq!(
            validate_dispatch(&a, &req(&h, OperationKind::RevealMnemonic, 0)),
            Ok(())
        );
        // Locked permits safe preview and Unlock (both require Locked);
        // secret-capable operations need their capability phase.
        let (locked, lh) = session(CapabilityPhase::Locked);
        assert_eq!(
            validate_dispatch(&locked, &req(&lh, OperationKind::InspectPreview, 0)),
            Ok(())
        );
        assert_eq!(
            validate_dispatch(&locked, &req(&lh, OperationKind::Unlock, 0)),
            Ok(())
        );
        assert_eq!(
            validate_dispatch(&locked, &req(&lh, OperationKind::VerifyOnline, 0)),
            Err(NativeErrorCode::OperationForbidden)
        );
    }

    #[test]
    fn exact_identity_binding_is_case_insensitive_both_keys() {
        let _a = SessionAuthority::default();
        let mut bound = identity();
        bound.encrypt_address =
            "032ebaf076203f15ac8119cfdbc9394d1c7b9929b0647e4f607e27da95701f8556".to_uppercase();
        assert!(same_public_identity(&bound, &identity()));
        assert!(!same_public_identity(
            &SessionIdentity {
                signing_address: "00".repeat(33),
                encrypt_address: identity().encrypt_address,
            },
            &identity()
        ));
    }

    #[test]
    fn required_phase_mirrors_registry() {
        assert_eq!(
            required_phase(OperationKind::CreateFullIdentitySign),
            CapabilityPhase::VerificationOnly
        );
        assert_eq!(
            required_phase(OperationKind::RemoveLocalUser),
            CapabilityPhase::Authenticated
        );
    }
}
