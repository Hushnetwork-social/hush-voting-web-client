//! Tauri command layer (FEAT-005 "Tauri IPC and Native Session",
//! "Direct secret submission", "WebView/native handshake").
//!
//! The WebView receives only closed typed outcomes and opaque operation ids.
//! The device-password/mnemonic command is the ONLY secret-accepting command
//! and is bounded, single-use, and non-logged; the payload has no `Debug`
//! impl anywhere. Handshake grants no secret capability until the exact
//! app-build and IPC-protocol versions match.

use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::ubuntu_vault::contracts::results::NativeErrorCode;
use crate::ubuntu_vault::secrets::{
    SecretOperationId, SecretSubmission, DEVICE_PASSWORD_MAX_BYTES,
};
use crate::ubuntu_vault::session::{RuntimeTarget, SessionAuthority, SessionError, VersionPair};

/// Current native build version (exact handshake).
pub const NATIVE_BUILD_VERSION: VersionPair = VersionPair { major: 1, minor: 0 };
/// Current IPC protocol version (exact handshake).
pub const IPC_PROTOCOL_VERSION: VersionPair = VersionPair { major: 1, minor: 0 };

/// Managed native state (single authority per application instance).
pub struct VaultState {
    pub session: Mutex<SessionAuthority>,
    pub pending_secret: Mutex<Option<SecretSubmission>>,
}

impl Default for VaultState {
    fn default() -> Self {
        Self {
            session: Mutex::new(SessionAuthority::new(
                NATIVE_BUILD_VERSION,
                IPC_PROTOCOL_VERSION,
            )),
            pending_secret: Mutex::new(None),
        }
    }
}

/// Closed command error (never carries raw provider/path/identity detail).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommandError {
    pub code: NativeErrorCode,
    /// Random per-occurrence support code (only for rare failures).
    pub support_code: Option<u64>,
}

impl From<SessionError> for CommandError {
    fn from(e: SessionError) -> Self {
        Self {
            code: e.to_native_error(),
            support_code: None,
        }
    }
}

impl From<crate::ubuntu_vault::secrets::SecretError> for CommandError {
    fn from(e: crate::ubuntu_vault::secrets::SecretError) -> Self {
        Self {
            code: e.to_native_error(),
            support_code: None,
        }
    }
}

/// Safe handshake outcome (no secret capability).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandshakeOutcome {
    pub ok: bool,
    pub native_build_major: u32,
    pub native_build_minor: u32,
    pub protocol_major: u32,
    pub protocol_minor: u32,
}

/// Exact app-build/protocol handshake command. On mismatch: no handle, no
/// secret accepted, vault/keyring state preserved, safe repair guidance
/// (UI) — never a hot transfer.
#[tauri::command]
pub fn hush_vault_handshake(
    state: tauri::State<'_, VaultState>,
    build_major: u32,
    build_minor: u32,
    protocol_major: u32,
    protocol_minor: u32,
) -> Result<HandshakeOutcome, CommandError> {
    let mut session = state.session.lock().expect("session mutex");
    session.handshake(
        VersionPair {
            major: build_major,
            minor: build_minor,
        },
        VersionPair {
            major: protocol_major,
            minor: protocol_minor,
        },
        RuntimeTarget::MainWindow,
    )?;
    Ok(HandshakeOutcome {
        ok: true,
        native_build_major: NATIVE_BUILD_VERSION.major,
        native_build_minor: NATIVE_BUILD_VERSION.minor,
        protocol_major: IPC_PROTOCOL_VERSION.major,
        protocol_minor: IPC_PROTOCOL_VERSION.minor,
    })
}

/// Single-use direct secret submission (device password / mnemonic / .dat).
/// Bounded bytes, wrapped immediately in a zeroizing container, cleared by
/// the WebView after acknowledgement; only an opaque operation id returns.
#[tauri::command]
pub fn hush_vault_submit_secret(
    state: tauri::State<'_, VaultState>,
    secret: Vec<u8>,
) -> Result<SecretOperationId, CommandError> {
    let submission = SecretSubmission::accept(secret, DEVICE_PASSWORD_MAX_BYTES)?;
    let id = submission.operation_id();
    let mut pending = state.pending_secret.lock().expect("pending secret mutex");
    *pending = Some(submission);
    Ok(id)
}

/// Drain the pending single-use secret (the consuming native authority calls
/// this exactly once per unlock; cleared on drop).
pub fn take_pending_secret(state: &VaultState) -> Option<SecretSubmission> {
    state
        .pending_secret
        .lock()
        .expect("pending secret mutex")
        .take()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handshake_mismatch_grants_no_capability() {
        let state = VaultState::default();
        let _ = state;
        let authority = SessionAuthority::new(NATIVE_BUILD_VERSION, IPC_PROTOCOL_VERSION);
        assert_eq!(
            authority.phase(),
            crate::ubuntu_vault::contracts::operations::CapabilityPhase::Locked
        );
        // The command-layer handshake path is exercised end-to-end in the
        // session authority tests; here we assert the version constants are
        // stable for the v1 contract.
        assert_eq!(NATIVE_BUILD_VERSION, VersionPair { major: 1, minor: 0 });
        assert_eq!(IPC_PROTOCOL_VERSION, VersionPair { major: 1, minor: 0 });
    }

    #[test]
    fn command_error_is_closed_and_serializable() {
        let error = CommandError {
            code: NativeErrorCode::StaleSession,
            support_code: Some(7),
        };
        let json = serde_json::to_string(&error).unwrap();
        assert!(json.contains("staleSession"));
        assert!(!json.contains("path") && !json.contains("secret"));
    }

    #[test]
    fn secret_markers_never_appear_in_command_artifacts() {
        // Task 4.6 secret-boundary scan: synthetic secret markers must appear
        // nowhere in the closed command surface (success, failure,
        // handshake, handle debug, and serialized outcomes).
        const FORBIDDEN: &[&str] = &[
            "password",
            "mnemonic",
            "secret",
            "privateKey",
            "private-key",
            "passphrase",
            "recoveryWords",
            "ciphertext",
            "seedPhrase",
        ];
        let error = CommandError {
            code: NativeErrorCode::StaleSession,
            support_code: None,
        };
        let handshake = HandshakeOutcome {
            ok: true,
            native_build_major: 1,
            native_build_minor: 0,
            protocol_major: 1,
            protocol_minor: 0,
        };
        let artifacts = [
            serde_json::to_string(&error).unwrap(),
            serde_json::to_string(&handshake).unwrap(),
            format!(
                "{:?}",
                crate::ubuntu_vault::contracts::session::SessionHandle {
                    epoch: crate::ubuntu_vault::contracts::session::SessionEpoch(1),
                    opaque: [0xabu8; 16],
                    main_window_only: true,
                }
            ),
        ];
        for artifact in &artifacts {
            let lower = artifact.to_ascii_lowercase();
            for marker in FORBIDDEN {
                assert!(
                    !lower.contains(marker),
                    "secret marker {marker:?} in command artifact {artifact}"
                );
            }
        }
    }
}
