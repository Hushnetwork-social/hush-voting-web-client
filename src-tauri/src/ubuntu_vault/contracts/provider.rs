//! Provider availability state model (FEAT-005 target "Availability state model").
//!
//! Classification rules are part of the contract:
//! - A locked, cancelled, timed-out, restarted, or temporarily failing service
//!   is NEVER treated as provider absence.
//! - Password-only fallback eligibility exists only for `Unavailable`
//!   (confirmed genuine service absence or confirmed lack of a usable default
//!   collection after OS setup/Retry guidance).
//! - `UnqualifiedProvider` blocks persistent production provisioning and is
//!   never treated as absence to obtain fallback.

use serde::{Deserialize, Serialize};

/// Closed provider availability states. Serialized to the WebView as the only
/// provider projection (no raw D-Bus error, path, or item detail).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderAvailability {
    /// A qualified provider owns the Secret Service name and its default/login
    /// collection is unlocked. Continue with OS-backed operation.
    AvailableUnlocked,
    /// Provider present but the default collection is locked. Prompt only from
    /// an explicit user action; cancellation is not a password failure.
    AvailableLocked,
    /// The user cancelled (or the OS prompt timed out) — return to Locked with
    /// Retry; no throttle increment, no fallback.
    PromptCancelled,
    /// Provider present but temporarily unavailable (D-Bus restart, timeout).
    /// Bounded Retry; preserve keyring/files; no fallback.
    TemporarilyUnavailable,
    /// Confirmed genuine absence or confirmed lack of a usable default
    /// collection after OS setup/Retry guidance. The ONLY fallback-eligible
    /// state, and only with explicit informed acknowledgement.
    Unavailable,
    /// A provider exists but has not passed qualification. Block persistent
    /// production provisioning; preserve existing state; never fallback.
    UnqualifiedProvider,
    /// The expected wrapping item cannot be found/used/validated. Preserve all
    /// encrypted files; require portable recovery.
    ProtectionInvalidated,
}

impl ProviderAvailability {
    /// Whether this state is eligible for password-only fallback.
    /// Only confirmed absence qualifies — never lock/cancel/timeout/temp/unqualified.
    pub fn is_fallback_eligible(self) -> bool {
        matches!(self, Self::Unavailable)
    }

    /// Whether this state allows continuing with OS-backed operations.
    pub fn is_os_backed_ready(self) -> bool {
        matches!(self, Self::AvailableUnlocked)
    }

    /// Whether this state represents a transient condition that must never
    /// select fallback nor increment device-password throttling.
    pub fn is_transient(self) -> bool {
        matches!(
            self,
            Self::AvailableLocked | Self::PromptCancelled | Self::TemporarilyUnavailable
        )
    }

    /// Whether persistent provisioning is blocked by this state.
    pub fn blocks_persistent_provisioning(self) -> bool {
        matches!(
            self,
            Self::UnqualifiedProvider | Self::ProtectionInvalidated
        )
    }
}

/// Allowed UI actions for a provider state (drives FEAT-002 safe actions).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderAction {
    UnlockKeyring,
    Retry,
    EnableOsProtection,
    PasswordOnlyFallback,
    PortableRecovery,
    Cancel,
}

impl ProviderAvailability {
    /// The closed action set for this state. No action set ever exposes
    /// raw provider detail; each maps to the target's required behavior.
    pub fn allowed_actions(self) -> &'static [ProviderAction] {
        match self {
            Self::AvailableUnlocked => &[ProviderAction::Cancel],
            Self::AvailableLocked => &[ProviderAction::UnlockKeyring, ProviderAction::Cancel],
            Self::PromptCancelled => &[ProviderAction::Retry, ProviderAction::Cancel],
            Self::TemporarilyUnavailable => &[ProviderAction::Retry, ProviderAction::Cancel],
            Self::Unavailable => &[
                ProviderAction::EnableOsProtection,
                ProviderAction::Retry,
                ProviderAction::PasswordOnlyFallback,
            ],
            Self::UnqualifiedProvider => {
                &[ProviderAction::EnableOsProtection, ProviderAction::Cancel]
            }
            Self::ProtectionInvalidated => {
                &[ProviderAction::PortableRecovery, ProviderAction::Cancel]
            }
        }
    }
}

/// Coarse protection class projected to UI and (opt-in) telemetry. Never
/// contains a provider name/version as proof of qualification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProtectionClass {
    SecretService,
    PasswordOnly,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_confirmed_absence_is_fallback_eligible() {
        for (state, eligible) in [
            (ProviderAvailability::AvailableUnlocked, false),
            (ProviderAvailability::AvailableLocked, false),
            (ProviderAvailability::PromptCancelled, false),
            (ProviderAvailability::TemporarilyUnavailable, false),
            (ProviderAvailability::Unavailable, true),
            (ProviderAvailability::UnqualifiedProvider, false),
            (ProviderAvailability::ProtectionInvalidated, false),
        ] {
            assert_eq!(state.is_fallback_eligible(), eligible, "{state:?}");
        }
    }

    #[test]
    fn locked_cancelled_timeout_are_transient_not_absence() {
        assert!(ProviderAvailability::AvailableLocked.is_transient());
        assert!(ProviderAvailability::PromptCancelled.is_transient());
        assert!(ProviderAvailability::TemporarilyUnavailable.is_transient());
        assert!(!ProviderAvailability::Unavailable.is_transient());
        assert!(!ProviderAvailability::UnqualifiedProvider.is_transient());
    }

    #[test]
    fn unqualified_and_invalidated_block_provisioning() {
        assert!(ProviderAvailability::UnqualifiedProvider.blocks_persistent_provisioning());
        assert!(ProviderAvailability::ProtectionInvalidated.blocks_persistent_provisioning());
        assert!(!ProviderAvailability::Unavailable.blocks_persistent_provisioning());
    }

    #[test]
    fn allowed_actions_are_closed_per_state() {
        assert!(ProviderAvailability::Unavailable
            .allowed_actions()
            .contains(&ProviderAction::PasswordOnlyFallback));
        assert!(!ProviderAvailability::TemporarilyUnavailable
            .allowed_actions()
            .contains(&ProviderAction::PasswordOnlyFallback));
        assert!(!ProviderAvailability::UnqualifiedProvider
            .allowed_actions()
            .contains(&ProviderAction::PasswordOnlyFallback));
    }
}
