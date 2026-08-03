//! Resumable local-user removal (FEAT-005 "Local-User Removal").
//!
//! Removal does not require the HushVoting device password (it may require
//! the normal OS keyring unlock prompt). The durable `removal.tombstone` is
//! persisted before any destructive step and survives until verified absence
//! of both keyring items and vault files. Every step is idempotent; a crash
//! or provider/filesystem unavailability leaves `RemovalInProgress` and the
//! next startup resumes from the recorded stage while remaining Locked.
//! Success is reported ONLY after absence is verified — never after partial
//! cleanup.
//!
//! Session revocation (`RevokingSession`) and cache clearing
//! (`ClearingCaches`) are Phase 4 session-authority markers; the file and
//! keyring cleanup steps are the Phase 3 storage/keyring responsibilities.

use crate::ubuntu_vault::contracts::removal::{RemovalStage, RemovalTombstoneV1, REMOVAL_STAGES};
use crate::ubuntu_vault::contracts::results::NativeErrorCode;
use crate::ubuntu_vault::secret_service::ProviderFailure;
use crate::ubuntu_vault::storage::journal::JournalState;
use crate::ubuntu_vault::storage::writer::{StoreError, VaultStore};

/// Keyring cleanup seam: active and staged wrapping items are deleted and
/// search-absence verified. Implemented by the real `Oo7Backend` and by the
/// deterministic in-memory test provider; the orchestrator is generic over
/// this trait so no D-Bus code runs in unit tests.
///
/// `async fn` in a trait is used only with generic (monomorphized) bounds —
/// never through `dyn` — so the missing auto-trait specification is
/// irrelevant here; the concrete futures carry their own bounds.
#[allow(async_fn_in_trait)]
pub trait KeyringVaultOps {
    /// Delete active and staged wrapping items, then verify search absence.
    /// Returns whether absence was verified.
    async fn delete_active_and_staged(&mut self) -> Result<bool, ProviderFailure>;
    /// Verify that no active or staged wrapping item remains.
    async fn verify_absent(&mut self) -> Result<bool, ProviderFailure>;
}

/// Outcome of a removal run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RemovalOutcome {
    /// All artifacts (files and keyring) verified absent; tombstone cleared.
    Complete,
    /// Removal remains in progress at the given stage (resume at startup).
    Incomplete { stage: RemovalStage },
}

/// The next stage in the fixed idempotent order.
pub fn next_stage(stage: RemovalStage) -> Option<RemovalStage> {
    let idx = REMOVAL_STAGES.iter().position(|s| *s == stage)?;
    REMOVAL_STAGES.get(idx + 1).copied()
}

/// Run (or resume) local-user removal. Deterministic, idempotent, and
/// tombstone-backed. Every destructive step is idempotent; a transient
/// failure returns `Incomplete` with the recorded stage so startup can
/// resume without repeating verified work. When final absence verification
/// fails, the idempotent cleanup is re-run once; a persistent delete failure
/// surfaces as `Incomplete` at that stage.
pub async fn run_removal(
    store: &VaultStore,
    keyring: &mut impl KeyringVaultOps,
    now_ms: u64,
) -> Result<RemovalOutcome, StoreError> {
    // Resume from the durable tombstone; otherwise start fresh. Ensure the
    // record is durable before any destructive step.
    let mut tombstone = match store.read_tombstone()? {
        Some(t) => t,
        None => RemovalTombstoneV1::new(now_ms),
    };
    store.write_tombstone(&tombstone)?;
    let mut stage = tombstone.stage;
    let mut cleanup_passes = 0u8;
    loop {
        match stage {
            RemovalStage::RevokingSession | RemovalStage::ClearingCaches => {
                // Phase 4 session-authority markers; recorded for
                // resumability. No file/keyring work.
                stage = advance(store, &mut tombstone, stage, now_ms)?;
            }
            RemovalStage::PersistingTombstone => {
                // The tombstone is already durable at this point (created
                // above or resumed); record the next stage.
                stage = advance(store, &mut tombstone, stage, now_ms)?;
            }
            RemovalStage::DeletingSlots => {
                // Mark the journal as removal-in-progress (best-effort; the
                // journal is deleted in this step).
                if let Ok(journal) = store.read_journal() {
                    let _ = store.write_journal(&{
                        let mut next = journal;
                        next.state = JournalState::RemovalInProgress;
                        next
                    });
                }
                if store.delete_vault_artifacts().is_err()
                    || !store.verify_artifacts_absent().unwrap_or(false)
                {
                    // Fail closed: never report success after partial cleanup.
                    return Ok(RemovalOutcome::Incomplete { stage });
                }
                stage = advance(store, &mut tombstone, stage, now_ms)?;
            }
            RemovalStage::DeletingKeys => {
                match keyring.delete_active_and_staged().await {
                    Ok(true) => {}
                    Ok(false) | Err(_) => {
                        // Provider unavailable/absent or cleanup failed:
                        // remain in progress and resume at startup.
                        return Ok(RemovalOutcome::Incomplete { stage });
                    }
                }
                stage = advance(store, &mut tombstone, stage, now_ms)?;
            }
            RemovalStage::VerifyingAbsence => {
                let files_absent = store.verify_artifacts_absent().unwrap_or(false);
                let keys_absent = keyring.verify_absent().await.unwrap_or(false);
                if files_absent && keys_absent {
                    // Verified complete: clear the tombstone and report
                    // success. An inability to clear keeps removal in
                    // progress so startup re-verifies and re-clears.
                    match store.clear_tombstone() {
                        Ok(()) => return Ok(RemovalOutcome::Complete),
                        Err(_) => return Ok(RemovalOutcome::Incomplete { stage }),
                    }
                }
                if cleanup_passes >= 1 {
                    // A full idempotent cleanup pass already ran and absence
                    // still cannot be verified: remain incomplete (resume).
                    return Ok(RemovalOutcome::Incomplete { stage });
                }
                cleanup_passes += 1;
                // Re-run the idempotent destructive stages (safe: deletion
                // of already-absent artifacts is a no-op).
                tombstone.stage = RemovalStage::DeletingSlots;
                store.write_tombstone(&tombstone)?;
                stage = RemovalStage::DeletingSlots;
            }
        }
    }
}

/// Persist the tombstone pointing at the next stage.
fn advance(
    store: &VaultStore,
    tombstone: &mut RemovalTombstoneV1,
    stage: RemovalStage,
    _now_ms: u64,
) -> Result<RemovalStage, StoreError> {
    let next = next_stage(stage).ok_or(StoreError(NativeErrorCode::RemovalIncomplete))?;
    // `started_at_ms` stays fixed at the removal start (diagnostics anchor);
    // only the stage advances.
    tombstone.stage = next;
    store.write_tombstone(tombstone)?;
    Ok(next)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ubuntu_vault::contracts::protection::ProtectionMode;
    use crate::ubuntu_vault::crypto::encoding::hex_encode;
    use crate::ubuntu_vault::crypto::random_bytes;
    use crate::ubuntu_vault::secret_service::backend::test_provider::InMemoryProvider;
    use crate::ubuntu_vault::secret_service::backend::ItemAttributes;
    use crate::ubuntu_vault::storage::writer::VaultStore;

    fn temp_root(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "feat005-removal-{name}-{}-{}",
            std::process::id(),
            hex_encode(&random_bytes(4).unwrap())
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn provisioned(name: &str) -> (VaultStore, Vec<u8>, InMemoryProvider) {
        let store = VaultStore::open(temp_root(name)).unwrap();
        let k = vec![0x3cu8; 32];
        store
            .provision(b"pkg", ProtectionMode::OsBacked, Some(&k), false, 1_000)
            .unwrap();
        let mut keyring = InMemoryProvider::new();
        let attrs = ItemAttributes::active(
            crate::ubuntu_vault::contracts::wrapper::ReleaseChannel::Production,
        );
        keyring.create_item(&attrs, &k).unwrap();
        (store, k, keyring)
    }

    #[tokio::test]
    async fn removal_verifies_absence_and_clears_tombstone() {
        let (store, _k, mut keyring) = provisioned("complete");
        assert!(!store.verify_artifacts_absent().unwrap());
        let outcome = run_removal(&store, &mut keyring, 2_000).await.unwrap();
        assert_eq!(outcome, RemovalOutcome::Complete);
        assert!(store.verify_artifacts_absent().unwrap());
        assert_eq!(store.read_tombstone().unwrap(), None);
        assert!(keyring.verify_absent().await.unwrap());
        assert_eq!(
            store.read_journal().err().unwrap().0,
            NativeErrorCode::NoVault
        );
    }

    #[tokio::test]
    async fn removal_never_reports_success_after_partial_keyring_cleanup() {
        let (store, _k, mut keyring) = provisioned("partial-keyring");
        // A keyring that fails mid-delete must leave removal incomplete and
        // the tombstone in place for resume.
        keyring.set_delete_failure(true);
        let outcome = run_removal(&store, &mut keyring, 2_000).await.unwrap();
        assert!(matches!(outcome, RemovalOutcome::Incomplete { .. }));
        assert!(store.read_tombstone().unwrap().is_some());
        // Files were deleted but keyring items remain — never success.
        assert!(store.verify_artifacts_absent().unwrap());
        assert!(!keyring.verify_absent().await.unwrap());
        // Resume after the failure completes the removal.
        keyring.set_delete_failure(false);
        let outcome = run_removal(&store, &mut keyring, 3_000).await.unwrap();
        assert_eq!(outcome, RemovalOutcome::Complete);
        assert!(keyring.verify_absent().await.unwrap());
        assert_eq!(store.read_tombstone().unwrap(), None);
    }

    #[tokio::test]
    async fn removal_resumes_from_tombstone_after_crash() {
        let (store, _k, mut keyring) = provisioned("resume");
        // Simulate a crash after files were deleted (tombstone recorded at
        // DeletingKeys) but before keyring deletion.
        store.delete_vault_artifacts().unwrap();
        let tombstone = RemovalTombstoneV1 {
            in_progress: true,
            started_at_ms: 1_000,
            stage: RemovalStage::DeletingKeys,
        };
        store.write_tombstone(&tombstone).unwrap();
        // A fresh run resumes from DeletingKeys and completes.
        let outcome = run_removal(&store, &mut keyring, 2_000).await.unwrap();
        assert_eq!(outcome, RemovalOutcome::Complete);
        assert!(keyring.verify_absent().await.unwrap());
        assert_eq!(store.read_tombstone().unwrap(), None);
    }

    #[tokio::test]
    async fn removal_interrupted_at_every_boundary_resumes() {
        for stage in REMOVAL_STAGES {
            let (store, _k, mut keyring) = provisioned("boundary");
            // Pre-seed the tombstone at each stage (crash at that boundary).
            let tombstone = RemovalTombstoneV1 {
                in_progress: true,
                started_at_ms: 1_000,
                stage: *stage,
            };
            store.write_tombstone(&tombstone).unwrap();
            // Fail keyring deletion to force an incomplete run.
            keyring.set_delete_failure(true);
            let outcome = run_removal(&store, &mut keyring, 2_000).await.unwrap();
            assert!(matches!(outcome, RemovalOutcome::Incomplete { .. }));
            keyring.set_delete_failure(false);
            let outcome = run_removal(&store, &mut keyring, 3_000).await.unwrap();
            assert_eq!(outcome, RemovalOutcome::Complete, "resume from {stage:?}");
            assert_eq!(store.read_tombstone().unwrap(), None);
            assert!(store.verify_artifacts_absent().unwrap());
            assert!(keyring.verify_absent().await.unwrap());
            let _ = std::fs::remove_dir_all(store.root());
        }
    }

    #[test]
    fn stage_order_is_fixed_and_closed() {
        assert_eq!(
            next_stage(RemovalStage::RevokingSession),
            Some(RemovalStage::PersistingTombstone)
        );
        assert_eq!(
            next_stage(RemovalStage::DeletingSlots),
            Some(RemovalStage::DeletingKeys)
        );
        assert_eq!(next_stage(RemovalStage::VerifyingAbsence), None);
        assert_eq!(REMOVAL_STAGES.len(), 6);
    }
}
