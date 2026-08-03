//! Pure provider state classification (FEAT-005 "Availability state model",
//! "Prompt timing", "Missing, duplicate, and orphan entries").
//!
//! Every D-Bus observation is normalized into a closed `ProbeOutcome` (or a
//! closed `ProviderFailure`), and every classification/decision is a pure
//! synchronous function. This module contains NO D-Bus code: the async glue in
//! `backend` feeds these functions, and the rules here are exhaustively
//! unit-tested without a session bus.
//!
//! Non-negotiable rules encoded here:
//! - A locked service, cancelled prompt, timeout, D-Bus restart, or temporary
//!   failure is NEVER treated as provider absence.
//! - Startup performs only a non-prompting probe bounded by
//!   `STARTUP_PROBE_BOUND_SECS`; an explicit user action is required before
//!   any OS prompt.
//! - The OS prompt is bounded by `PROMPT_BOUND_SECS`.
//! - No replacement wrapping key is ever generated from a probe, a failure, or
//!   a missing/ambiguous/invalidated item.
//! - No prompt cancel/timeout/provider/storage/network failure ever increments
//!   device-password throttling.

use std::time::Duration;

use crate::ubuntu_vault::contracts::provider::ProviderAvailability;
use crate::ubuntu_vault::item_model::{ItemCardinality, ItemLookupDecision};
use crate::ubuntu_vault::{PROMPT_BOUND_SECS, STARTUP_PROBE_BOUND_SECS};

/// A normalized non-prompting or prompt observation from the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// A qualified provider owns the Secret Service name and the default/login
    /// collection is unlocked. OS-backed operations may continue.
    ConnectedUnlocked,
    /// Provider present but the default collection is locked. Prompt only from
    /// an explicit user action.
    ConnectedLocked,
    /// The user dismissed the OS prompt (or the UI cancelled it). Return to
    /// Locked with Retry; no throttle/fallback.
    PromptCancelled,
    /// The OS prompt exceeded `PROMPT_BOUND_SECS`. Same safe return.
    PromptTimedOut,
    /// Provider present but temporarily unavailable (D-Bus restart, wire
    /// timeout). Bounded Retry; preserve keyring/files; no fallback.
    TemporarilyUnavailable,
    /// Confirmed genuine absence: no provider owns the Secret Service name.
    AbsentNoService,
    /// Confirmed lack of a usable default/login collection after OS setup.
    AbsentNoDefaultCollection,
    /// A provider exists but has not passed qualification. Block persistent
    /// production provisioning; preserve existing state; never fallback.
    Unqualified,
}

impl ProbeOutcome {
    /// The closed availability state projected to the WebView.
    pub fn availability(self) -> ProviderAvailability {
        match self {
            Self::ConnectedUnlocked => ProviderAvailability::AvailableUnlocked,
            Self::ConnectedLocked => ProviderAvailability::AvailableLocked,
            Self::PromptCancelled => ProviderAvailability::PromptCancelled,
            Self::PromptTimedOut => ProviderAvailability::PromptCancelled,
            Self::TemporarilyUnavailable => ProviderAvailability::TemporarilyUnavailable,
            Self::AbsentNoService | Self::AbsentNoDefaultCollection => {
                ProviderAvailability::Unavailable
            }
            Self::Unqualified => ProviderAvailability::UnqualifiedProvider,
        }
    }
}

/// Automated decisions the native authority may take for a probe outcome.
/// No outcome ever generates a key, increments throttling, or enables
/// fallback without explicit informed acknowledgement at the UI boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeDecisions {
    /// Whether OS-backed operation may proceed.
    pub proceed_os_backed: bool,
    /// Whether an explicit OS prompt may be requested (only from an explicit
    /// user action, never from startup probe).
    pub prompt_eligible: bool,
    /// Whether password-only fallback may be offered (never from a probe
    /// failure; only after confirmed absence + OS setup/Retry guidance at the
    /// UI layer).
    pub fallback_offer_eligible: bool,
    /// Whether throttling may be incremented. Always false for provider
    /// outcomes: prompt cancel/timeout/provider failure never counts.
    pub increment_throttle: bool,
    /// Whether a replacement wrapping key may be generated. Always false here.
    pub generate_key: bool,
}

impl ProbeOutcome {
    pub fn decisions(self) -> ProbeDecisions {
        let availability = self.availability();
        ProbeDecisions {
            proceed_os_backed: availability.is_os_backed_ready(),
            // A prompt is only requested from an explicit Unlock/Create/
            // Restore action — never from the startup probe. The availability
            // state still exposes the action set; `prompt_eligible` reflects
            // that the outcome itself never auto-prompts.
            prompt_eligible: false,
            fallback_offer_eligible: availability.is_fallback_eligible(),
            increment_throttle: false,
            generate_key: false,
        }
    }
}

/// Startup probe bound (non-prompting status/capability probe only).
/// Compared with full `Duration` precision — a 5s + 1ms probe exceeds the
/// bound even though `as_secs()` would truncate it to 5.
pub fn probe_within_bound(elapsed: Duration) -> bool {
    elapsed <= Duration::from_secs(STARTUP_PROBE_BOUND_SECS)
}

/// OS prompt bound (explicit user operation only).
pub fn prompt_within_bound(elapsed: Duration) -> bool {
    elapsed <= Duration::from_secs(PROMPT_BOUND_SECS)
}

/// Classify an item-set observation into a closed availability state.
///
/// `vault_files_exist` distinguishes `MissingWithFiles` (protection
/// invalidated) from a clean `None` (fresh provisioning). Item classification
/// itself is deterministic and order-independent (see `item_model`).
pub fn classify_item_availability(
    decision: ItemLookupDecision,
    vault_files_exist: bool,
) -> ProviderAvailability {
    match decision.cardinality {
        ItemCardinality::None => {
            if vault_files_exist {
                ProviderAvailability::ProtectionInvalidated
            } else {
                // No items and no vault files → fresh provisioning.
                ProviderAvailability::AvailableUnlocked
            }
        }
        ItemCardinality::OneActive
        | ItemCardinality::ActiveWithStaged
        | ItemCardinality::DuplicatesOneValid => ProviderAvailability::AvailableUnlocked,
        ItemCardinality::Orphan => ProviderAvailability::AvailableUnlocked,
        ItemCardinality::Ambiguous => ProviderAvailability::ProtectionInvalidated,
        ItemCardinality::MissingWithFiles => ProviderAvailability::ProtectionInvalidated,
        ItemCardinality::StaleOrUnsupported => ProviderAvailability::ProtectionInvalidated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_probe_outcome_maps_to_a_closed_state() {
        // Exhaustive: each outcome has exactly one availability state.
        assert_eq!(
            ProbeOutcome::ConnectedUnlocked.availability(),
            ProviderAvailability::AvailableUnlocked
        );
        assert_eq!(
            ProbeOutcome::ConnectedLocked.availability(),
            ProviderAvailability::AvailableLocked
        );
        assert_eq!(
            ProbeOutcome::PromptCancelled.availability(),
            ProviderAvailability::PromptCancelled
        );
        assert_eq!(
            ProbeOutcome::PromptTimedOut.availability(),
            ProviderAvailability::PromptCancelled
        );
        assert_eq!(
            ProbeOutcome::TemporarilyUnavailable.availability(),
            ProviderAvailability::TemporarilyUnavailable
        );
        assert_eq!(
            ProbeOutcome::AbsentNoService.availability(),
            ProviderAvailability::Unavailable
        );
        assert_eq!(
            ProbeOutcome::AbsentNoDefaultCollection.availability(),
            ProviderAvailability::Unavailable
        );
        assert_eq!(
            ProbeOutcome::Unqualified.availability(),
            ProviderAvailability::UnqualifiedProvider
        );
    }

    #[test]
    fn locked_cancelled_timeout_temp_are_never_absence() {
        // A locked/cancelled/timed-out/temporarily-unavailable provider is
        // NEVER treated as absence: fallback is not offered and no key is
        // generated.
        for outcome in [
            ProbeOutcome::ConnectedLocked,
            ProbeOutcome::PromptCancelled,
            ProbeOutcome::PromptTimedOut,
            ProbeOutcome::TemporarilyUnavailable,
            ProbeOutcome::Unqualified,
        ] {
            let d = outcome.decisions();
            assert!(!d.fallback_offer_eligible, "{outcome:?}");
            assert!(!d.generate_key, "{outcome:?}");
            assert!(!d.increment_throttle, "{outcome:?}");
        }
    }

    #[test]
    fn only_confirmed_absence_offers_fallback() {
        assert!(
            ProbeOutcome::AbsentNoService
                .decisions()
                .fallback_offer_eligible
        );
        assert!(
            ProbeOutcome::AbsentNoDefaultCollection
                .decisions()
                .fallback_offer_eligible
        );
        // But even absence never generates a key or increments throttle.
        for outcome in [
            ProbeOutcome::AbsentNoService,
            ProbeOutcome::AbsentNoDefaultCollection,
        ] {
            assert!(!outcome.decisions().generate_key);
            assert!(!outcome.decisions().increment_throttle);
        }
    }

    #[test]
    fn probes_never_auto_prompt() {
        // Startup performs only a non-prompting probe; a prompt requires an
        // explicit user action later.
        for outcome in [
            ProbeOutcome::ConnectedUnlocked,
            ProbeOutcome::ConnectedLocked,
            ProbeOutcome::PromptCancelled,
            ProbeOutcome::PromptTimedOut,
            ProbeOutcome::TemporarilyUnavailable,
            ProbeOutcome::AbsentNoService,
            ProbeOutcome::AbsentNoDefaultCollection,
            ProbeOutcome::Unqualified,
        ] {
            assert!(!outcome.decisions().prompt_eligible, "{outcome:?}");
        }
    }

    #[test]
    fn startup_probe_is_bounded() {
        assert!(probe_within_bound(Duration::from_secs(0)));
        assert!(probe_within_bound(Duration::from_secs(5)));
        assert!(!probe_within_bound(
            Duration::from_secs(5) + Duration::from_millis(1)
        ));
        assert!(!probe_within_bound(Duration::from_secs(6)));
    }

    #[test]
    fn os_prompt_is_bounded() {
        assert!(prompt_within_bound(Duration::from_secs(60)));
        assert!(!prompt_within_bound(Duration::from_secs(61)));
    }

    #[test]
    fn missing_item_with_files_is_invalidated() {
        use crate::ubuntu_vault::item_model::{ItemCardinality, ItemLookupDecision};
        let decision = ItemLookupDecision {
            cardinality: ItemCardinality::MissingWithFiles,
            single_validating_key: false,
        };
        assert_eq!(
            classify_item_availability(decision, true),
            ProviderAvailability::ProtectionInvalidated
        );
        // Item missing but no vault files → fresh provisioning state. The
        // fresh case must be classified as `None` cardinality: `MissingWithFiles`
        // already encodes that files exist.
        let fresh = ItemLookupDecision {
            cardinality: ItemCardinality::None,
            single_validating_key: false,
        };
        assert_eq!(
            classify_item_availability(fresh, false),
            ProviderAvailability::AvailableUnlocked
        );
    }

    #[test]
    fn ambiguous_items_preserve_all_artifacts() {
        use crate::ubuntu_vault::item_model::{ItemCardinality, ItemLookupDecision};
        let decision = ItemLookupDecision {
            cardinality: ItemCardinality::Ambiguous,
            single_validating_key: false,
        };
        assert_eq!(
            classify_item_availability(decision, true),
            ProviderAvailability::ProtectionInvalidated
        );
    }

    #[test]
    fn exactly_one_validating_key_among_duplicates_proceeds() {
        use crate::ubuntu_vault::item_model::{ItemCardinality, ItemLookupDecision};
        let decision = ItemLookupDecision {
            cardinality: ItemCardinality::DuplicatesOneValid,
            single_validating_key: true,
        };
        assert_eq!(
            classify_item_availability(decision, true),
            ProviderAvailability::AvailableUnlocked
        );
    }
}
