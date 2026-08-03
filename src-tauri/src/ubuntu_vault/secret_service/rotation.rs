//! Wrapping-key lifecycle: one active plus at most one staged item
//! (FEAT-005 "Wrapper-key rotation", "Missing, duplicate, and orphan
//! entries").
//!
//! Steady state holds exactly one active wrapping item. Rotation stages at
//! most ONE clearly marked temporary item and one staged file package;
//! promotion happens only after complete read-back and one successful unlock.
//! Old wrapping entries are deleted only after the new package is
//! authoritative and recoverable. Removal deletes active and staged items.
//!
//! Search order never selects a key. Duplicate repair is allowed only with
//! the target's verified preconditions: successful device-password unlock,
//! exact online identity verification, and explicit repair confirmation.
//! Zero or multiple distinct validating keys preserve all artifacts and
//! require recovery/support — never a guessed key.

use crate::ubuntu_vault::item_model::{ItemCardinality, ItemLookupDecision};
use crate::ubuntu_vault::secret_service::backend::StoredItem;
use crate::ubuntu_vault::storage::commit::RotationPlan;

/// Outcome of classifying the observed wrapping items.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrappingState {
    /// No items and no vault files → fresh provisioning may create the first
    /// active item.
    Fresh,
    /// Exactly one active item, no staged → steady state.
    OneActive,
    /// One active plus one staged item → rotation in progress.
    RotationInProgress,
    /// Multiple matching items with exactly one distinct validating key →
    /// verified duplicate repair is permitted (with all preconditions).
    DuplicatesOneValid,
    /// Zero or multiple distinct validating keys → preserve all artifacts;
    /// portable recovery required.
    Ambiguous,
    /// Item present but no vault/tombstone files → orphan; verified cleanup.
    Orphan,
    /// Item missing but vault files exist → protection invalidated.
    MissingWithFiles,
    /// Attributes/wrapper version mismatch the fixed vocabulary.
    StaleOrUnsupported,
}

impl WrappingState {
    /// Whether portable recovery is required (never guess a key).
    pub fn requires_recovery(self) -> bool {
        matches!(
            self,
            Self::Ambiguous | Self::MissingWithFiles | Self::StaleOrUnsupported
        )
    }

    /// Whether a new wrapping key may be created (provisioning or verified
    /// rotation staging) — never from an ambiguous/missing/invalidated state.
    pub fn permits_key_creation(self) -> bool {
        matches!(self, Self::Fresh | Self::OneActive)
    }
}

/// Deterministic, order-independent classification of the observed items.
///
/// `staged_present` and `vault_files_exist` are observations, never search
/// order. `distinct_validating_keys` is only meaningful after authenticated
/// outer-wrapper probing of each candidate key.
pub fn classify_wrapping_state(
    active_items: &[StoredItem],
    staged_items: &[StoredItem],
    vault_files_exist: bool,
    distinct_validating_keys: usize,
) -> WrappingState {
    // Spec rule ("Missing, duplicate, and orphan entries"): an item present
    // with no vault/tombstone files is an orphan and is removed only through
    // verified cleanup. A key cannot validate a package that does not exist,
    // so no validating-key count ever overrides orphan classification.
    let any_items = !active_items.is_empty() || !staged_items.is_empty();
    if any_items && !vault_files_exist {
        return WrappingState::Orphan;
    }
    match active_items.len() {
        0 => {
            if !staged_items.is_empty() {
                // Only a staged item: a crashed rotation before promotion.
                // The staged item is a valid candidate only if it is the sole
                // distinct validating key; otherwise recovery is required.
                if distinct_validating_keys == 1 {
                    WrappingState::RotationInProgress
                } else {
                    WrappingState::Ambiguous
                }
            } else if vault_files_exist {
                WrappingState::MissingWithFiles
            } else {
                WrappingState::Fresh
            }
        }
        1 => {
            if !staged_items.is_empty() {
                if distinct_validating_keys == 1 {
                    WrappingState::RotationInProgress
                } else if distinct_validating_keys == 0 && vault_files_exist {
                    // Active item does not validate the package but a staged
                    // one might (only one distinct validating key is
                    // required to continue).
                    WrappingState::DuplicatesOneValid
                } else {
                    WrappingState::Ambiguous
                }
            } else if distinct_validating_keys == 1 {
                WrappingState::OneActive
            } else {
                WrappingState::Ambiguous
            }
        }
        _ => {
            if distinct_validating_keys == 1 {
                WrappingState::DuplicatesOneValid
            } else {
                WrappingState::Ambiguous
            }
        }
    }
}

/// The deterministic cardinality decision for the Phase 2 item model.
pub fn to_item_decision(state: WrappingState) -> ItemLookupDecision {
    let cardinality = match state {
        WrappingState::Fresh => ItemCardinality::None,
        WrappingState::OneActive | WrappingState::RotationInProgress => ItemCardinality::OneActive,
        WrappingState::DuplicatesOneValid => ItemCardinality::DuplicatesOneValid,
        WrappingState::Ambiguous => ItemCardinality::Ambiguous,
        WrappingState::Orphan => ItemCardinality::Orphan,
        WrappingState::MissingWithFiles => ItemCardinality::MissingWithFiles,
        WrappingState::StaleOrUnsupported => ItemCardinality::StaleOrUnsupported,
    };
    ItemLookupDecision {
        cardinality,
        single_validating_key: matches!(
            state,
            WrappingState::OneActive
                | WrappingState::RotationInProgress
                | WrappingState::DuplicatesOneValid
        ),
    }
}

/// Verified preconditions for promotion of a staged rotation item. Promotion
/// requires complete read-back verification AND one successful device-password
/// unlock of the staged-protected package. (Exact online identity verification
/// and explicit repair confirmation are required for duplicate cleanup, and
/// for rollback activation — see `lifecycle`.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PromotionPreconditions {
    /// The staged package was fully written, opened, parsed, unwrapped,
    /// authenticated, and validated (read-back).
    pub staged_package_read_back_verified: bool,
    /// The staged-protected package unlocked successfully once with the device
    /// password.
    pub staged_unlock_succeeded: bool,
}

impl PromotionPreconditions {
    pub fn met(self) -> bool {
        self.staged_package_read_back_verified && self.staged_unlock_succeeded
    }
}

/// Verified preconditions for deleting obsolete wrapping entries or repairing
/// duplicates. Every precondition is required: successful device-password
/// unlock, exact online identity verification, and explicit repair
/// confirmation. `RotationPlan` mirrors these for the file package side.
pub fn cleanup_preconditions_met(
    decision: ItemLookupDecision,
    unlock_succeeded: bool,
    online_verified: bool,
    repair_confirmed: bool,
) -> bool {
    decision.cardinality.cleanup_permitted_precondition()
        && decision.single_validating_key
        && unlock_succeeded
        && online_verified
        && repair_confirmed
}

/// Whether a rotation may stage a new keyring item. At most one staged item
/// exists at any time; a second staged item is a defect (fail closed).
pub fn staging_allowed(current_staged_count: usize) -> bool {
    current_staged_count < 1
}

/// Whether rotation may proceed at all for the current state.
pub fn rotation_allowed(state: WrappingState) -> bool {
    // Rotate only from a valid steady state or an in-progress rotation that
    // already has a staged candidate. Never from ambiguous/invalidated states.
    matches!(
        state,
        WrappingState::OneActive | WrappingState::RotationInProgress
    )
}

/// The rotation plan for the current state (fixed preconditions).
pub fn rotation_plan_for(state: WrappingState) -> RotationPlan {
    let mut plan = RotationPlan::default();
    match state {
        WrappingState::OneActive => {
            plan.staged_item_allowed = true;
            plan.staged_package_allowed = true;
        }
        WrappingState::RotationInProgress => {
            plan.staged_item_allowed = false; // at most one staged item
            plan.staged_package_allowed = false; // at most one staged package
        }
        _ => {
            plan.staged_item_allowed = false;
            plan.staged_package_allowed = false;
        }
    }
    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn active_item(index: u64) -> StoredItem {
        StoredItem {
            item_index: index,
            attributes: crate::ubuntu_vault::secret_service::backend::ItemAttributes::active(
                crate::ubuntu_vault::contracts::wrapper::ReleaseChannel::Production,
            )
            .to_map(),
        }
    }

    fn staged_item() -> StoredItem {
        StoredItem {
            item_index: 99,
            attributes: crate::ubuntu_vault::secret_service::backend::ItemAttributes::staged(
                crate::ubuntu_vault::contracts::wrapper::ReleaseChannel::Production,
            )
            .to_map(),
        }
    }

    #[test]
    fn steady_state_one_active() {
        let items = vec![active_item(0)];
        assert_eq!(
            classify_wrapping_state(&items, &[], true, 1),
            WrappingState::OneActive
        );
        assert!(!WrappingState::OneActive.requires_recovery());
        assert!(WrappingState::OneActive.permits_key_creation());
    }

    #[test]
    fn fresh_provisioning_when_no_items_no_files() {
        assert_eq!(
            classify_wrapping_state(&[], &[], false, 0),
            WrappingState::Fresh
        );
        assert!(WrappingState::Fresh.permits_key_creation());
    }

    #[test]
    fn missing_item_with_files_is_invalidated_not_replaced() {
        assert_eq!(
            classify_wrapping_state(&[], &[], true, 0),
            WrappingState::MissingWithFiles
        );
        assert!(WrappingState::MissingWithFiles.requires_recovery());
        assert!(!WrappingState::MissingWithFiles.permits_key_creation());
    }

    #[test]
    fn orphan_item_without_files_allows_verified_cleanup() {
        assert_eq!(
            classify_wrapping_state(&[active_item(0)], &[], false, 1),
            WrappingState::Orphan
        );
        assert!(!WrappingState::Orphan.requires_recovery());
    }

    #[test]
    fn orphan_wins_over_validating_key_when_no_files_exist() {
        // Spec: an item present with no vault/tombstone files is an orphan —
        // a key cannot validate a package that does not exist, so even a
        // "validating" key never turns a file-less item into OneActive.
        assert_eq!(
            classify_wrapping_state(&[active_item(0)], &[], false, 1),
            WrappingState::Orphan
        );
        // A staged-only leftover with no files is orphaned too (crash before
        // promotion with lost files) → verified cleanup, never promotion.
        assert_eq!(
            classify_wrapping_state(&[], &[staged_item()], false, 1),
            WrappingState::Orphan
        );
    }

    #[test]
    fn rotation_stages_at_most_one() {
        let one_active = vec![active_item(0)];
        let staged_items = vec![staged_item()];
        assert_eq!(
            classify_wrapping_state(&one_active, &staged_items, true, 1),
            WrappingState::RotationInProgress
        );
        assert!(staging_allowed(0));
        assert!(!staging_allowed(1));
        assert!(!staging_allowed(2));
        // Rotation is allowed only from valid states.
        assert!(rotation_allowed(WrappingState::OneActive));
        assert!(rotation_allowed(WrappingState::RotationInProgress));
        assert!(!rotation_allowed(WrappingState::Ambiguous));
        assert!(!rotation_allowed(WrappingState::MissingWithFiles));
    }

    #[test]
    fn ambiguous_preserves_all_artifacts() {
        let dupes = vec![active_item(0), active_item(1)];
        assert_eq!(
            classify_wrapping_state(&dupes, &[], true, 2),
            WrappingState::Ambiguous
        );
        assert!(WrappingState::Ambiguous.requires_recovery());
        // Zero validating keys among several matching items → recovery.
        assert_eq!(
            classify_wrapping_state(&dupes, &[], true, 0),
            WrappingState::Ambiguous
        );
    }

    #[test]
    fn duplicates_one_valid_allows_cleanup_only_with_all_preconditions() {
        let dupes = vec![active_item(0), active_item(1)];
        let state = classify_wrapping_state(&dupes, &[], true, 1);
        assert_eq!(state, WrappingState::DuplicatesOneValid);
        let decision = to_item_decision(state);
        assert!(decision.cardinality.cleanup_permitted_precondition());
        // Every precondition is required — a single missing one blocks.
        assert!(cleanup_preconditions_met(decision, true, true, true));
        assert!(!cleanup_preconditions_met(decision, false, true, true));
        assert!(!cleanup_preconditions_met(decision, true, false, true));
        assert!(!cleanup_preconditions_met(decision, true, true, false));
        assert!(!cleanup_preconditions_met(decision, false, false, false));
    }

    #[test]
    fn promotion_requires_read_back_and_unlock() {
        let pre = PromotionPreconditions {
            staged_package_read_back_verified: true,
            staged_unlock_succeeded: true,
        };
        assert!(pre.met());
        assert!(!PromotionPreconditions {
            staged_package_read_back_verified: false,
            staged_unlock_succeeded: true,
        }
        .met());
        assert!(!PromotionPreconditions {
            staged_package_read_back_verified: true,
            staged_unlock_succeeded: false,
        }
        .met());
    }

    #[test]
    fn rotation_plan_never_stages_twice() {
        let plan = rotation_plan_for(WrappingState::OneActive);
        assert!(plan.staged_item_allowed && plan.staged_package_allowed);
        assert!(plan.promote_requires_read_back_and_unlock);
        assert!(plan.delete_old_requires_new_authoritative);
        let in_progress = rotation_plan_for(WrappingState::RotationInProgress);
        assert!(!in_progress.staged_item_allowed);
        assert!(!in_progress.staged_package_allowed);
        for bad in [
            WrappingState::Fresh,
            WrappingState::Ambiguous,
            WrappingState::MissingWithFiles,
            WrappingState::StaleOrUnsupported,
            WrappingState::DuplicatesOneValid,
            WrappingState::Orphan,
        ] {
            let plan = rotation_plan_for(bad);
            assert!(!plan.staged_item_allowed, "{bad:?}");
            assert!(!plan.staged_package_allowed, "{bad:?}");
        }
    }

    #[test]
    fn item_decision_mapping_is_closed() {
        assert_eq!(
            to_item_decision(WrappingState::Fresh).cardinality,
            ItemCardinality::None
        );
        assert_eq!(
            to_item_decision(WrappingState::OneActive).cardinality,
            ItemCardinality::OneActive
        );
        assert_eq!(
            to_item_decision(WrappingState::MissingWithFiles).cardinality,
            ItemCardinality::MissingWithFiles
        );
        assert_eq!(
            to_item_decision(WrappingState::StaleOrUnsupported).cardinality,
            ItemCardinality::StaleOrUnsupported
        );
        assert!(to_item_decision(WrappingState::DuplicatesOneValid).single_validating_key);
    }
}
