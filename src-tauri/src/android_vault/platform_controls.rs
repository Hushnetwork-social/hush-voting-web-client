//! Typed sensitive-state shielding, clipboard, and SAF policy (FEAT-006
//! Phase 4, Task 4.7).
//!
//! Rust drives a typed sensitive-state signal; arbitrary JavaScript can never
//! enable/disable native protection. Shielding applies FLAG_SECURE for
//! password/mnemonic/credential/export/confirmation states and conceals on
//! focus loss, navigation, Lock, timeout, or removal. Mnemonic clipboard copy
//! is explicit, warned, bounded to 60 seconds, and best-effort cleared
//! (never overwriting newer user content); passwords and private keys never
//! enter the clipboard. SAF operations accept exactly one content URI in
//! native custody, with no persisted grant, no broad storage permission, and
//! no URI/path/bytes to TypeScript.

use crate::android_vault::contracts::lifecycle::SensitiveState;

/// Mnemonic clipboard cleanup bound (seconds).
pub const CLIPBOARD_CLEAR_BOUND_SECS: u64 = 60;

/// Shielding decision for a sensitive state transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShieldDecision {
    /// Apply native FLAG_SECURE + approved window protection.
    Shield,
    /// Remove native shielding (state no longer sensitive).
    Unshield,
}

/// Whether a sensitive state requires active native shielding.
pub fn shielding_required(state: SensitiveState) -> bool {
    !matches!(state, SensitiveState::None)
}

/// All sensitive states (closed).
pub const ALL_SENSITIVE_STATES: &[SensitiveState] = &[
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

/// Lifecycle events that must conceal sensitive content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConcealEvent {
    FocusLoss,
    TaskBackground,
    ScreenOff,
    NavigationAway,
    Lock,
    Timeout,
    Removal,
    ProcessRecreation,
}

/// Every conceal event (fail-closed matrix).
pub const ALL_CONCEAL_EVENTS: &[ConcealEvent] = &[
    ConcealEvent::FocusLoss,
    ConcealEvent::TaskBackground,
    ConcealEvent::ScreenOff,
    ConcealEvent::NavigationAway,
    ConcealEvent::Lock,
    ConcealEvent::Timeout,
    ConcealEvent::Removal,
    ConcealEvent::ProcessRecreation,
];

/// Typed shield state (non-secret; what the native layer must render).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShieldState {
    Shielded(SensitiveState),
    Concealed,
}

/// Evaluate the shield state after a conceal event: any sensitive state
/// becomes Concealed (never left exposed).
pub fn apply_conceal(state: Option<SensitiveState>, event: ConcealEvent) -> ShieldState {
    match state {
        None => ShieldState::Concealed,
        Some(_) => {
            let _ = event;
            ShieldState::Concealed
        }
    }
}

/// Clipboard policy decision for a mnemonic copy request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardDecision {
    /// Allowed: explicit user action + warning; schedule 60 s cleanup.
    AllowWithWarningAndCleanup,
    /// Denied: passwords and private keys never enter the clipboard.
    DenySecrets,
    /// Denied: no explicit user action for this copy.
    DenyNoExplicitAction,
}

pub fn clipboard_policy(
    explicit_user_action: bool,
    content_kind: ClipboardContentKind,
) -> ClipboardDecision {
    match content_kind {
        ClipboardContentKind::DevicePassword | ClipboardContentKind::PrivateKey => {
            ClipboardDecision::DenySecrets
        }
        ClipboardContentKind::Mnemonic => {
            if explicit_user_action {
                ClipboardDecision::AllowWithWarningAndCleanup
            } else {
                ClipboardDecision::DenyNoExplicitAction
            }
        }
    }
}

/// What kind of content a copy request carries (public category only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClipboardContentKind {
    Mnemonic,
    DevicePassword,
    PrivateKey,
}

/// SAF one-URI bounds (target "Storage Access Framework Handoff").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SafDecision {
    AcceptOneUri,
    RejectMultiple,
    RejectOversized,
    RejectStale,
    RejectPersistedGrant,
    RejectDirectoryOrArbitrary,
    RejectUnknownOperation,
}

/// Validate a document-picker result: exactly one URI, bounded read size, no
/// persisted grant, approved operation only.
pub fn validate_saf_result(
    operation: crate::android_vault::contracts::lifecycle::DocumentOperation,
    uri_count: usize,
    declared_size: usize,
    persisted_grant_requested: bool,
    is_directory: bool,
) -> SafDecision {
    if persisted_grant_requested || is_directory {
        return SafDecision::RejectPersistedGrant;
    }
    if uri_count != 1 {
        return SafDecision::RejectMultiple;
    }
    if declared_size > crate::android_vault::WRAPPER_MAX_BYTES {
        return SafDecision::RejectOversized;
    }
    match operation {
        crate::android_vault::contracts::lifecycle::DocumentOperation::ImportDatV1
        | crate::android_vault::contracts::lifecycle::DocumentOperation::ExportDatV1 => {
            SafDecision::AcceptOneUri
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::android_vault::contracts::lifecycle::DocumentOperation;

    #[test]
    fn shielding_covers_all_secret_states() {
        for state in ALL_SENSITIVE_STATES {
            let expect = !matches!(state, SensitiveState::None);
            assert_eq!(shielding_required(*state), expect);
        }
    }

    #[test]
    fn every_conceal_event_conceals() {
        for event in ALL_CONCEAL_EVENTS {
            assert_eq!(
                apply_conceal(Some(SensitiveState::MnemonicReveal), *event),
                ShieldState::Concealed,
                "event {event:?}"
            );
            assert_eq!(apply_conceal(None, *event), ShieldState::Concealed);
        }
    }

    #[test]
    fn clipboard_policy_never_copies_secrets() {
        assert_eq!(
            clipboard_policy(true, ClipboardContentKind::DevicePassword),
            ClipboardDecision::DenySecrets
        );
        assert_eq!(
            clipboard_policy(true, ClipboardContentKind::PrivateKey),
            ClipboardDecision::DenySecrets
        );
        assert_eq!(
            clipboard_policy(true, ClipboardContentKind::Mnemonic),
            ClipboardDecision::AllowWithWarningAndCleanup
        );
        assert_eq!(
            clipboard_policy(false, ClipboardContentKind::Mnemonic),
            ClipboardDecision::DenyNoExplicitAction
        );
    }

    #[test]
    fn saf_accepts_exactly_one_bounded_uri_per_operation() {
        assert_eq!(
            validate_saf_result(DocumentOperation::ImportDatV1, 1, 1024, false, false),
            SafDecision::AcceptOneUri
        );
        assert_eq!(
            validate_saf_result(DocumentOperation::ExportDatV1, 1, 2048, false, false),
            SafDecision::AcceptOneUri
        );
        assert_eq!(
            validate_saf_result(DocumentOperation::ImportDatV1, 2, 1024, false, false),
            SafDecision::RejectMultiple
        );
        assert_eq!(
            validate_saf_result(
                DocumentOperation::ImportDatV1,
                1,
                crate::android_vault::WRAPPER_MAX_BYTES + 1,
                false,
                false
            ),
            SafDecision::RejectOversized
        );
        assert_eq!(
            validate_saf_result(DocumentOperation::ImportDatV1, 1, 1024, true, false),
            SafDecision::RejectPersistedGrant
        );
        assert_eq!(
            validate_saf_result(DocumentOperation::ImportDatV1, 1, 1024, false, true),
            SafDecision::RejectPersistedGrant
        );
    }
}
