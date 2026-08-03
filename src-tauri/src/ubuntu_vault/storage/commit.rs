//! Durable atomic commit plan model (FEAT-005 "Durable atomic commit").
//!
//! The single native process is the sole writer. A package mutation follows
//! the target's exact 10-step sequence; this module models the plan and its
//! crash boundaries so the Phase 3 writer implements it deterministically.

use serde::{Deserialize, Serialize};

/// Step in the durable commit sequence. Each step is a crash boundary: a
/// process kill/power-loss at any step must preserve at least one verified
/// recoverable slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CommitStep {
    ValidateExpectedGeneration,
    ConstructInactiveSlotInMemory,
    WriteExclusiveTempFile,
    FlushAndFsyncTemp,
    AtomicRenameToInactiveSlot,
    OpenParseUnwrapValidateNewSlot,
    JournalCasAndSwitch,
    FsyncContainingDirectory,
    RetainPreviousAsBoundedRollback,
    RemoveObsoleteSlot,
}

/// One commit plan: which slot becomes active, expected generation, and the
/// retained rollback slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitPlan {
    /// Generation this mutation writes.
    pub target_generation: u64,
    /// Generation the writer expects at start (CAS).
    pub expected_generation: u64,
    /// Slot receiving the new inactive package.
    pub inactive_slot: crate::ubuntu_vault::storage::layout::VaultArtifact,
    /// Slot remaining as bounded rollback.
    pub retained_slot: Option<crate::ubuntu_vault::storage::layout::VaultArtifact>,
}

impl CommitPlan {
    /// Ordered steps executed by the writer. Step order is fixed; steps are
    /// never reordered or skipped.
    pub fn ordered_steps(&self) -> [CommitStep; 10] {
        [
            CommitStep::ValidateExpectedGeneration,
            CommitStep::ConstructInactiveSlotInMemory,
            CommitStep::WriteExclusiveTempFile,
            CommitStep::FlushAndFsyncTemp,
            CommitStep::AtomicRenameToInactiveSlot,
            CommitStep::OpenParseUnwrapValidateNewSlot,
            CommitStep::JournalCasAndSwitch,
            CommitStep::FsyncContainingDirectory,
            CommitStep::RetainPreviousAsBoundedRollback,
            CommitStep::RemoveObsoleteSlot,
        ]
    }

    /// CAS precondition: writer must hold the expected generation.
    pub fn generation_is_current(&self) -> bool {
        self.target_generation > self.expected_generation
            && self.inactive_slot != crate::ubuntu_vault::storage::layout::VaultArtifact::VaultLock
    }
}

/// Rotation plan: at most one staged keyring item and one staged file package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationPlan {
    pub staged_item_allowed: bool,
    pub staged_package_allowed: bool,
    /// Promote only after complete read-back and one successful unlock.
    pub promote_requires_read_back_and_unlock: bool,
    /// Delete old wrapping entries only after the new package is
    /// authoritative and recoverable.
    pub delete_old_requires_new_authoritative: bool,
}

impl Default for RotationPlan {
    fn default() -> Self {
        Self {
            staged_item_allowed: true,
            staged_package_allowed: true,
            promote_requires_read_back_and_unlock: true,
            delete_old_requires_new_authoritative: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ubuntu_vault::storage::layout::VaultArtifact;

    #[test]
    fn commit_plan_step_order_is_fixed() {
        let plan = CommitPlan {
            target_generation: 2,
            expected_generation: 1,
            inactive_slot: VaultArtifact::SlotB,
            retained_slot: Some(VaultArtifact::SlotA),
        };
        let steps = plan.ordered_steps();
        assert_eq!(steps.len(), 10);
        assert_eq!(steps[0], CommitStep::ValidateExpectedGeneration);
        assert_eq!(steps[5], CommitStep::OpenParseUnwrapValidateNewSlot);
        assert_eq!(steps[9], CommitStep::RemoveObsoleteSlot);
        assert!(plan.generation_is_current());
    }

    #[test]
    fn rotation_is_staged_and_verified_only() {
        let plan = RotationPlan::default();
        assert!(plan.staged_item_allowed && plan.staged_package_allowed);
        assert!(plan.promote_requires_read_back_and_unlock);
        assert!(plan.delete_old_requires_new_authoritative);
    }
}
