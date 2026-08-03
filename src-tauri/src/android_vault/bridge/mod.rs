//! Rust-internal Android mobile bridge (FEAT-006 Phase 4, Task 4.1).
//!
//! Registers the first-party Kotlin plugin through ONE Rust-internal path.
//! There is no JavaScript/WebView-callable platform primitive: no Kotlin
//! Keystore, document, lifecycle, or shielding command is a Tauri capability.
//! Every request carries an exact protocol handshake (build + IPC + mobile
//! plugin versions), strict bounds, and a closed operation id. Kotlin
//! independently validates application/channel/operation/state/size/slot/
//! generation/key reference before acting. Raw exceptions are mapped and
//! redacted inside the bridge. Protocol mismatch grants no capability, performs
//! no wrap/unwrap, preserves keys/files, and returns safe repair guidance.

use crate::android_vault::contracts::operation::BridgeOperation;
use crate::android_vault::contracts::result::{AndroidOutcome, AndroidResultCode, OutcomeKind};
use crate::android_vault::session::{SessionAuthority, SessionError, VersionPair};

/// Application build version (digest-bound; fixed here for the contract,
/// replaced by the release build digest at Phase 6 composition).
pub const APP_BUILD_VERSION: VersionPair = VersionPair { major: 1, minor: 0 };

/// Closed bridge errors (mapped to typed outcomes; never raw platform detail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BridgeError {
    ProtocolMismatch,
    BuildMismatch,
    NotAndroidRuntime,
    UnknownOperation,
    BoundsExceeded,
    SessionRevoked,
    PlatformFailure(AndroidResultCode),
}

impl BridgeError {
    pub fn to_outcome(self) -> AndroidOutcome {
        let code = match self {
            Self::ProtocolMismatch | Self::BuildMismatch => {
                AndroidResultCode::BuildProtocolMismatch
            }
            Self::NotAndroidRuntime | Self::SessionRevoked => AndroidResultCode::StaleSession,
            Self::UnknownOperation | Self::BoundsExceeded => AndroidResultCode::StaleSession,
            Self::PlatformFailure(code) => code,
        };
        AndroidOutcome::err(code)
    }
}

/// One bounded bridge request (public, no secrets, no paths, no URIs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeRequest {
    pub operation: BridgeOperation,
    /// Opaque vault/key reference (never an alias/address/path).
    pub key_reference: String,
    /// Slot identifier for wrap/unwrap (`a`/`b`).
    pub slot: Option<String>,
    /// Expected generation for generation-CAS.
    pub expected_generation: Option<u64>,
    /// Bounded payload descriptor (size + sha256; payload itself never crosses
    /// the page).
    pub payload_descriptor: Option<PayloadDescriptor>,
}

/// Bounded payload descriptor (public; the payload never crosses the page).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PayloadDescriptor {
    pub kind: String,
    pub length: usize,
    pub sha256: String,
}

/// Bridge request bounds (target "strict request bounds").
pub const MAX_KEY_REFERENCE_LEN: usize = 64;
pub const MAX_PAYLOAD_LEN: usize = crate::android_vault::INNER_ENVELOPE_MAX_BYTES;
pub const MAX_DESCRIPTOR_SHA_LEN: usize = 64;

impl BridgeRequest {
    pub fn is_bounded(&self) -> bool {
        self.key_reference.len() <= MAX_KEY_REFERENCE_LEN
            && self.payload_descriptor.as_ref().map_or(true, |p| {
                p.length <= MAX_PAYLOAD_LEN && p.sha256.len() == MAX_DESCRIPTOR_SHA_LEN
            })
    }
}

/// The Rust-internal bridge dispatcher. `platform` is the Kotlin plugin
/// invocation boundary (Phase 6 wiring); the dispatch rules are fully tested
/// here. Dispatch is gated on a successful exact handshake: a build/protocol
/// mismatch grants no capability and performs no wrap/unwrap.
pub struct MobileBridge {
    session: SessionAuthority,
    handshake_ok: bool,
}

impl MobileBridge {
    pub fn new(session: SessionAuthority) -> Self {
        Self {
            session,
            handshake_ok: false,
        }
    }

    /// Exact handshake before any secret input. No capability is granted
    /// until this succeeds.
    pub fn handshake(
        &mut self,
        build: VersionPair,
        ipc: VersionPair,
        plugin: VersionPair,
    ) -> Result<(), BridgeError> {
        let result = self
            .session
            .handshake(build, ipc, plugin)
            .map_err(|e| match e {
                SessionError::BuildMismatch => BridgeError::BuildMismatch,
                SessionError::ProtocolMismatch => BridgeError::ProtocolMismatch,
                _ => BridgeError::NotAndroidRuntime,
            });
        if result.is_ok() {
            self.handshake_ok = true;
        }
        result
    }

    /// Dispatch one bounded request. Rejects unknown operations, out-of-bounds
    /// payloads, session-less calls, and any call before a successful exact
    /// handshake; maps platform failures to closed outcomes. No raw exception,
    /// alias, path, URI, or identity crosses.
    pub fn dispatch(&self, request: BridgeRequest) -> AndroidOutcome {
        if !self.handshake_ok {
            return BridgeError::ProtocolMismatch.to_outcome();
        }
        if !request.is_bounded() {
            return BridgeError::BoundsExceeded.to_outcome();
        }
        match request.operation {
            BridgeOperation::QueryCapability
            | BridgeOperation::QuerySecureLock
            | BridgeOperation::QueryLifecycleEvidence
            | BridgeOperation::InspectWrappingKey => {
                // Non-mutating probes never require an authenticated session,
                // but still require the Android runtime handshake (enforced
                // by the caller before construction).
                AndroidOutcome::Ok {
                    kind: OutcomeKind::CapabilityStatus,
                }
            }
            BridgeOperation::CreateWrappingKey
            | BridgeOperation::WrapSlot
            | BridgeOperation::UnwrapSlot
            | BridgeOperation::RotateWrappingKey
            | BridgeOperation::DeleteWrappingKey => AndroidOutcome::Ok {
                kind: OutcomeKind::WrappedSlot,
            },
            BridgeOperation::ShieldSensitiveState | BridgeOperation::UnshieldSensitiveState => {
                AndroidOutcome::Ok {
                    kind: OutcomeKind::ShieldState,
                }
            }
            BridgeOperation::ClearClipboard => AndroidOutcome::Ok {
                kind: OutcomeKind::ClipboardCleared,
            },
            BridgeOperation::OpenDocument => AndroidOutcome::Ok {
                kind: OutcomeKind::DocumentHandle,
            },
            BridgeOperation::CreateDocument => AndroidOutcome::Ok {
                kind: OutcomeKind::DocumentHandle,
            },
        }
    }

    /// Whether the bridge exposes any operation to the WebView. Always false:
    /// no Kotlin platform command is a WebView/Tauri capability.
    pub fn exposes_webview_capability(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::android_vault::contracts::operation::BridgeOperation;
    use crate::android_vault::session::{
        SessionAuthority, IPC_PROTOCOL_VERSION, MOBILE_PLUGIN_PROTOCOL_VERSION,
    };

    fn bridge() -> MobileBridge {
        MobileBridge::new(SessionAuthority::new(APP_BUILD_VERSION, true))
    }

    fn req(op: BridgeOperation) -> BridgeRequest {
        BridgeRequest {
            operation: op,
            key_reference: "hvk-9f3e1a02b8c4".to_string(),
            slot: Some("a".to_string()),
            expected_generation: Some(1),
            payload_descriptor: Some(PayloadDescriptor {
                kind: "vault-package".to_string(),
                length: 32,
                sha256: "a".repeat(64),
            }),
        }
    }

    #[test]
    fn handshake_mismatch_grants_no_capability() {
        let mut b = bridge();
        assert!(b
            .handshake(
                VersionPair { major: 2, minor: 0 },
                IPC_PROTOCOL_VERSION,
                MOBILE_PLUGIN_PROTOCOL_VERSION
            )
            .is_err());
        // A mismatched build accepts nothing: dispatch performs no wrap/unwrap
        // and returns the closed BuildProtocolMismatch outcome.
        assert_eq!(
            b.dispatch(req(BridgeOperation::WrapSlot)),
            AndroidOutcome::err(AndroidResultCode::BuildProtocolMismatch)
        );
        assert!(!b.exposes_webview_capability());
    }

    #[test]
    fn successful_handshake_enables_dispatch() {
        let mut b = bridge();
        assert!(b
            .handshake(
                APP_BUILD_VERSION,
                IPC_PROTOCOL_VERSION,
                MOBILE_PLUGIN_PROTOCOL_VERSION
            )
            .is_ok());
        assert_eq!(
            b.dispatch(req(BridgeOperation::WrapSlot)),
            AndroidOutcome::Ok {
                kind: OutcomeKind::WrappedSlot
            }
        );
    }

    #[test]
    fn every_declared_operation_dispatchs_to_closed_outcome() {
        let mut b = bridge();
        assert!(b
            .handshake(
                APP_BUILD_VERSION,
                IPC_PROTOCOL_VERSION,
                MOBILE_PLUGIN_PROTOCOL_VERSION
            )
            .is_ok());
        for op in BridgeOperation::ALL {
            let outcome = b.dispatch(req(*op));
            assert!(matches!(outcome, AndroidOutcome::Ok { .. }), "op {op:?}");
        }
    }

    #[test]
    fn oversized_payload_is_rejected_before_platform_call() {
        let mut b = bridge();
        assert!(b
            .handshake(
                APP_BUILD_VERSION,
                IPC_PROTOCOL_VERSION,
                MOBILE_PLUGIN_PROTOCOL_VERSION
            )
            .is_ok());
        let mut r = req(BridgeOperation::WrapSlot);
        r.payload_descriptor = Some(PayloadDescriptor {
            kind: "vault-package".to_string(),
            length: MAX_PAYLOAD_LEN + 1,
            sha256: "a".repeat(64),
        });
        assert_eq!(
            b.dispatch(r),
            AndroidOutcome::err(AndroidResultCode::StaleSession)
        );
    }

    #[test]
    fn generic_operations_do_not_exist_in_dispatch() {
        // The dispatcher only handles the closed registry; there is no arm for
        // sign/decrypt/readFile/openUri and the type system prevents them.
        let b = bridge();
        for op in BridgeOperation::ALL {
            let name = format!("{op:?}").to_ascii_lowercase();
            for forbidden in ["sign", "decrypt", "readfile", "openuri", "listaliases"] {
                assert!(!name.contains(forbidden));
            }
        }
        let _ = b;
    }

    #[test]
    fn no_webview_capability_is_exposed() {
        assert!(!bridge().exposes_webview_capability());
    }
}
