//! Android Back and root-only navigation authority (FEAT-006 Phase 4,
//! Task 4.5).
//!
//! Android Back, predictive-back completion, in-app Back, and browser history
//! all invoke FEAT-002's same typed internal navigation authority. The visible
//! WebView URL remains `/`; raw WebView `goBack()` is never workflow
//! authority. Restoring a prior step never replays a secret submission.
//! Missing, stale, unauthorized, or uncertain history returns to the safe
//! authentication entry or the authenticated dashboard. At a safe root, Back
//! may background/finish only after sensitive content is shielded and
//! lifecycle policy is applied. Saved-state/task recreation never restores an
//! authenticated handle or mnemonic/password screen.

use crate::android_vault::contracts::lifecycle::SensitiveState;
use crate::android_vault::platform_controls::{apply_conceal, ConcealEvent, ShieldState};

/// Typed internal destinations (FEAT-002 vocabulary; no raw URLs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    SafeAuthEntry,
    AuthenticatedDashboard,
    PreviousSafeStep,
    CurrentStep,
    BackgroundOrFinish,
}

/// Current workflow position (public category; never secret-bearing values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowPosition {
    AtSafeRoot,
    SecretStep(SensitiveState),
    OrdinaryStep,
}

/// History state categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HistoryState {
    ValidSafe,
    Missing,
    Stale,
    Unauthorized,
    Uncertain,
    SecretBearing,
}

/// Navigation decision (closed; the UI renders safe destinations only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackDecision {
    pub destination: Destination,
    pub conceal: ShieldState,
    pub may_finish_or_background: bool,
}

/// Decide the Back destination (shared authority model; FEAT-002 renders).
pub fn decide_back(
    position: WorkflowPosition,
    history: HistoryState,
    at_safe_root: bool,
    sensitive_active: Option<SensitiveState>,
) -> BackDecision {
    // A secret step never replays a secret submission; conceal first.
    let conceal = match position {
        WorkflowPosition::SecretStep(state) => {
            apply_conceal(Some(state), ConcealEvent::NavigationAway)
        }
        _ => apply_conceal(sensitive_active, ConcealEvent::NavigationAway),
    };

    // Secret-bearing or uncertain history -> safe entry/dashboard, never a
    // replayed submission.
    let destination = match (position, history) {
        (WorkflowPosition::AtSafeRoot, HistoryState::ValidSafe) => Destination::BackgroundOrFinish,
        (WorkflowPosition::SecretStep(_), _) | (_, HistoryState::SecretBearing) => {
            Destination::SafeAuthEntry
        }
        (
            _,
            HistoryState::Missing
            | HistoryState::Stale
            | HistoryState::Unauthorized
            | HistoryState::Uncertain,
        ) => Destination::SafeAuthEntry,
        (WorkflowPosition::OrdinaryStep, HistoryState::ValidSafe) => Destination::PreviousSafeStep,
    };

    let may_finish_or_background = at_safe_root
        && position == WorkflowPosition::AtSafeRoot
        && history == HistoryState::ValidSafe
        && conceal == ShieldState::Concealed;

    BackDecision {
        destination,
        conceal,
        may_finish_or_background,
    }
}

/// Saved-state/task recreation must never restore an authenticated handle or
/// a secret screen (target "Activity/task ownership").
pub fn saved_state_restores_secret(state: Option<SensitiveState>, has_handle: bool) -> bool {
    has_handle || state.is_some_and(|s| s != SensitiveState::None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_root_back_backgrounds_only_after_concealment() {
        let d = decide_back(
            WorkflowPosition::AtSafeRoot,
            HistoryState::ValidSafe,
            true,
            None,
        );
        assert_eq!(d.destination, Destination::BackgroundOrFinish);
        assert!(d.may_finish_or_background);
        assert_eq!(d.conceal, ShieldState::Concealed);
    }

    #[test]
    fn secret_step_never_replays_submission() {
        for history in [
            HistoryState::ValidSafe,
            HistoryState::Missing,
            HistoryState::SecretBearing,
        ] {
            let d = decide_back(
                WorkflowPosition::SecretStep(SensitiveState::MnemonicReveal),
                history,
                false,
                None,
            );
            assert_eq!(
                d.destination,
                Destination::SafeAuthEntry,
                "history {history:?} must not replay a secret step"
            );
            assert_eq!(d.conceal, ShieldState::Concealed);
            assert!(!d.may_finish_or_background);
        }
    }

    #[test]
    fn uncertain_history_returns_to_safe_entry() {
        for history in [
            HistoryState::Missing,
            HistoryState::Stale,
            HistoryState::Unauthorized,
            HistoryState::Uncertain,
        ] {
            let d = decide_back(WorkflowPosition::OrdinaryStep, history, false, None);
            assert_eq!(d.destination, Destination::SafeAuthEntry);
        }
    }

    #[test]
    fn ordinary_step_with_valid_history_goes_back_safely() {
        let d = decide_back(
            WorkflowPosition::OrdinaryStep,
            HistoryState::ValidSafe,
            false,
            None,
        );
        assert_eq!(d.destination, Destination::PreviousSafeStep);
    }

    #[test]
    fn saved_state_never_restores_handle_or_secret() {
        assert!(saved_state_restores_secret(None, true));
        assert!(saved_state_restores_secret(
            Some(SensitiveState::MnemonicReveal),
            false
        ));
        assert!(!saved_state_restores_secret(None, false));
    }
}
