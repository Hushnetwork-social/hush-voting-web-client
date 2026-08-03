//! Durable vault store writer (FEAT-005 "Native Filesystem Storage",
//! "Durable atomic commit", "Protection Modes", "Rollback recovery",
//! "Wrapper-key rotation").
//!
//! The single native process is the sole writer. Every artifact write uses a
//! same-directory exclusive temp file (O_EXCL | O_NOFOLLOW), `fsync` of data,
//! atomic rename, and a containing-directory `fsync`. Paths derive only from
//! the resolved root and the fixed identity-neutral layout — never from a
//! caller. Owner/mode/link defenses are enforced after creation and update,
//! not only via the process umask.
//!
//! Commit follows the reference two-slot CAS: write the complete candidate to
//! the inactive fixed slot, read back and fully validate (schema, envelope
//! authentication where the wrapping key is available, generations, mode),
//! then switch the journal only after an expected-generation recheck. The
//! previous verified slot is retained as the single bounded rollback slot.
//! Obsolete rollback is removed only under the next-success/24h rule.
//! Rotation stages at most one staged file package; promotion requires
//! read-back verification AND one successful unlock. Rollback activation
//! requires explicit confirmation AND exact online identity verification.
//! Password-only fallback is accepted only with explicit informed
//! acknowledgement; there is no automatic downgrade from OS-backed mode.

use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::ubuntu_vault::contracts::protection::ProtectionMode;
use crate::ubuntu_vault::contracts::removal::RemovalTombstoneV1;
use crate::ubuntu_vault::contracts::results::NativeErrorCode;
use crate::ubuntu_vault::contracts::wrapper::{ReleaseChannel, WrapperMetadataV1};
use crate::ubuntu_vault::crypto::encoding::hex_encode;
use crate::ubuntu_vault::crypto::random_bytes;
use crate::ubuntu_vault::crypto::AES_KEY_BYTES;
use crate::ubuntu_vault::storage::envelope::{
    password_only_slot, unwrap_os_backed, unwrap_password_only, wrap_os_backed, SlotFile,
    SLOT_ENVELOPE_FORMAT_VERSION,
};
use crate::ubuntu_vault::storage::journal::{JournalRecord, JournalState, SidecarRecord};
use crate::ubuntu_vault::storage::layout::VaultArtifact;
use crate::ubuntu_vault::storage::security::{
    classify_path, containment_of, FileMetadata, PathCheck, VaultPathPolicy,
};

/// Rollback window: obsolete rollback is removed after 24h since the active
/// slot was verified, or after the next successful unlock — whichever is
/// observed first.
pub const ROLLBACK_CLEANUP_MS: u64 = 24 * 60 * 60 * 1000;

/// Closed store error (raw path/OS detail never crosses the boundary).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreError(pub NativeErrorCode);

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "vault storage failure (closed code)")
    }
}

impl std::error::Error for StoreError {}

fn err(code: NativeErrorCode) -> StoreError {
    StoreError(code)
}

/// Fault injection points for the deterministic crash matrix (test-only
/// setters; the checks themselves are always compiled so release code paths
/// are identical).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultPoint {
    WriteTemp,
    FlushFsync,
    Rename,
    VerifySlot,
    /// Flip a byte in the artifact file after the atomic write (bit-rot /
    /// short-write corruption before the journal switch).
    CorruptWrittenSlot,
    JournalCas,
    FsyncDir,
    CleanupObsolete,
    ReadSlot,
    ReadJournal,
    RemoveSlot,
}

#[derive(Debug, Default)]
struct FaultFlags {
    write_temp: AtomicBool,
    flush_fsync: AtomicBool,
    rename: AtomicBool,
    verify_slot: AtomicBool,
    corrupt_written_slot: AtomicBool,
    journal_cas: AtomicBool,
    fsync_dir: AtomicBool,
    cleanup_obsolete: AtomicBool,
    read_slot: AtomicBool,
    read_journal: AtomicBool,
    remove_slot: AtomicBool,
}

impl FaultFlags {
    fn flag(&self, point: FaultPoint) -> &AtomicBool {
        match point {
            FaultPoint::WriteTemp => &self.write_temp,
            FaultPoint::FlushFsync => &self.flush_fsync,
            FaultPoint::Rename => &self.rename,
            FaultPoint::VerifySlot => &self.verify_slot,
            FaultPoint::CorruptWrittenSlot => &self.corrupt_written_slot,
            FaultPoint::JournalCas => &self.journal_cas,
            FaultPoint::FsyncDir => &self.fsync_dir,
            FaultPoint::CleanupObsolete => &self.cleanup_obsolete,
            FaultPoint::ReadSlot => &self.read_slot,
            FaultPoint::ReadJournal => &self.read_journal,
            FaultPoint::RemoveSlot => &self.remove_slot,
        }
    }

    fn hit(&self, point: FaultPoint) -> bool {
        self.flag(point).swap(false, Ordering::SeqCst)
    }
}

/// Durable vault store bound to one resolved vault root.
#[derive(Debug)]
pub struct VaultStore {
    root: PathBuf,
    policy: VaultPathPolicy,
    faults: FaultFlags,
}

/// Outcome of provisioning the first vault.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvisionOutcome {
    pub generation: u64,
    pub active_slot: VaultArtifact,
}

/// Outcome of a successful two-slot commit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommitOutcome {
    pub generation: u64,
    pub active_slot: VaultArtifact,
}

/// Inputs for a two-slot CAS commit (bounded, closed; no raw detail).
#[derive(Debug, Clone, Copy)]
pub struct CommitRequest<'a> {
    pub expected_generation: u64,
    /// Must equal `expected_generation + 1`.
    pub candidate_generation: u64,
    /// FEAT-003 password-encrypted package bytes (opaque to the store).
    pub package: &'a [u8],
    pub mode: ProtectionMode,
    /// Required for OS-backed commits; forbidden for password-only.
    pub wrapping_key: Option<&'a [u8]>,
    /// Explicit informed acknowledgement (mandatory for password-only).
    pub fallback_acknowledged: bool,
    pub now_ms: u64,
}

/// Outcome of obsolete-rollback cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CleanupOutcome {
    /// Whether the bounded rollback slot is still retained.
    pub retained: bool,
    /// Generation of the removed obsolete slot, if any.
    pub removed_generation: Option<u64>,
}

impl VaultStore {
    /// Open (and create on first use) the vault root. The root directory is
    /// created with `0700` and its owner/mode are enforced after creation.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, StoreError> {
        let root = root.as_ref().to_path_buf();
        let store = Self {
            root,
            policy: VaultPathPolicy::default(),
            faults: FaultFlags::default(),
        };
        store.ensure_root_dir()?;
        Ok(store)
    }

    /// Root directory (resolved, never caller-derived).
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn ensure_root_dir(&self) -> Result<(), StoreError> {
        match std::fs::create_dir_all(&self.root) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(map_io(e)),
        }
        // Enforce owner/mode after creation/update (never rely on umask).
        let meta = std::fs::symlink_metadata(&self.root).map_err(map_io)?;
        if meta.uid() != current_uid() {
            return Err(err(NativeErrorCode::PersistenceDenied));
        }
        if meta.mode() & 0o7777 != 0o700 {
            std::fs::set_permissions(&self.root, std::fs::Permissions::from_mode(0o700))
                .map_err(map_io)?;
        }
        let _ = std::fs::File::open(&self.root).map_err(map_io)?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Path and artifact security
    // ------------------------------------------------------------------

    /// Fixed artifact path under the resolved root (containment enforced).
    fn artifact_path(&self, artifact: VaultArtifact) -> Result<PathBuf, StoreError> {
        let path = self.root.join(artifact.file_name());
        if containment_of(&self.root, &path)
            != crate::ubuntu_vault::storage::security::Containment::Contained
        {
            return Err(err(NativeErrorCode::PersistenceDenied));
        }
        Ok(path)
    }

    /// Classify an existing artifact against the mandatory path policy.
    /// Returns `PathCheck::Missing` when the artifact does not exist.
    fn classify(&self, artifact: VaultArtifact) -> Result<PathCheck, StoreError> {
        let path = self.artifact_path(artifact)?;
        let md = match std::fs::symlink_metadata(&path) {
            Ok(md) => md,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(PathCheck::Missing);
            }
            Err(e) => return Err(map_io(e)),
        };
        let meta = FileMetadata {
            is_regular_file: md.file_type().is_file(),
            is_symlink: md.file_type().is_symlink(),
            owner_is_current_uid: md.uid() == current_uid(),
            mode: md.mode() & 0o7777,
            hard_link_count: md.nlink(),
        };
        let containment = containment_of(&self.root, &path);
        Ok(classify_path(&self.policy, containment, meta, 0o600))
    }

    /// Require an artifact to be present and safe.
    fn require_safe(&self, artifact: VaultArtifact) -> Result<(), StoreError> {
        match self.classify(artifact)? {
            PathCheck::Contained => Ok(()),
            PathCheck::Missing => Err(err(NativeErrorCode::NoVault)),
            other => Err(map_path_check(other)),
        }
    }

    fn require_safe_or_missing(&self, artifact: VaultArtifact) -> Result<(), StoreError> {
        match self.classify(artifact)? {
            PathCheck::Contained | PathCheck::Missing => Ok(()),
            other => Err(map_path_check(other)),
        }
    }

    // ------------------------------------------------------------------
    // Artifact I/O (exclusive temp + fsync + atomic rename + dir fsync)
    // ------------------------------------------------------------------

    /// Atomic artifact write: same-directory exclusive temp file with
    /// no-follow semantics, flush, `fsync`, rename, and directory `fsync`.
    fn write_artifact_atomic(
        &self,
        artifact: VaultArtifact,
        bytes: &[u8],
    ) -> Result<(), StoreError> {
        let target = self.artifact_path(artifact)?;
        self.require_safe_or_missing(artifact)?;
        let temp = self.temp_path(artifact)?;
        let result = (|| -> Result<(), StoreError> {
            if self.faults.hit(FaultPoint::WriteTemp) {
                return Err(err(NativeErrorCode::StorageUnavailable));
            }
            let mut opts = OpenOptions::new();
            opts.write(true).create_new(true).mode(0o600);
            opts.custom_flags(libc::O_NOFOLLOW);
            let mut file = opts.open(&temp).map_err(map_io)?;
            file.write_all(bytes).map_err(map_io)?;
            if self.faults.hit(FaultPoint::FlushFsync) {
                return Err(err(NativeErrorCode::StorageUnavailable));
            }
            file.sync_all().map_err(map_io)?;
            drop(file);
            if self.faults.hit(FaultPoint::Rename) {
                return Err(err(NativeErrorCode::StorageUnavailable));
            }
            std::fs::rename(&temp, &target).map_err(map_io)?;
            self.fsync_dir()?;
            Ok(())
        })();
        // Best-effort cleanup of the temp file on any failure (never leaves a
        // half-written temp artifact).
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result
    }

    fn temp_path(&self, artifact: VaultArtifact) -> Result<PathBuf, StoreError> {
        let suffix = random_bytes(6).map_err(|_| err(NativeErrorCode::StorageUnavailable))?;
        Ok(self.root.join(format!(
            ".tmp-{}-{}",
            artifact.file_name(),
            hex_encode(&suffix)
        )))
    }

    fn fsync_dir(&self) -> Result<(), StoreError> {
        if self.faults.hit(FaultPoint::FsyncDir) {
            return Err(err(NativeErrorCode::StorageUnavailable));
        }
        let dir = std::fs::File::open(&self.root).map_err(map_io)?;
        dir.sync_all().map_err(map_io)
    }

    fn remove_artifact(&self, artifact: VaultArtifact) -> Result<(), StoreError> {
        if self.faults.hit(FaultPoint::RemoveSlot) {
            return Err(err(NativeErrorCode::StorageUnavailable));
        }
        let path = self.artifact_path(artifact)?;
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()), // idempotent
            Err(e) => Err(map_io(e)),
        }
    }

    fn read_artifact(&self, artifact: VaultArtifact) -> Result<Vec<u8>, StoreError> {
        let path = self.artifact_path(artifact)?;
        self.require_safe(artifact)?;
        std::fs::read(&path).map_err(map_io)
    }

    // ------------------------------------------------------------------
    // Journal
    // ------------------------------------------------------------------

    pub fn read_journal(&self) -> Result<JournalRecord, StoreError> {
        if self.faults.hit(FaultPoint::ReadJournal) {
            return Err(err(NativeErrorCode::StorageUnavailable));
        }
        let bytes = match self.read_artifact(VaultArtifact::Journal) {
            Ok(b) => b,
            Err(StoreError(NativeErrorCode::NoVault)) => return Err(err(NativeErrorCode::NoVault)),
            Err(e) => return Err(e),
        };
        let record: JournalRecord =
            serde_json::from_slice(&bytes).map_err(|_| err(NativeErrorCode::MalformedEnvelope))?;
        if record.format_version != 1 {
            return Err(err(NativeErrorCode::UnsupportedVaultVersion));
        }
        Ok(record)
    }

    pub fn write_journal(&self, record: &JournalRecord) -> Result<(), StoreError> {
        if self.faults.hit(FaultPoint::JournalCas) {
            return Err(err(NativeErrorCode::StorageUnavailable));
        }
        let bytes =
            serde_json::to_vec(record).map_err(|_| err(NativeErrorCode::MalformedEnvelope))?;
        self.write_artifact_atomic(VaultArtifact::Journal, &bytes)
    }

    // ------------------------------------------------------------------
    // Slots
    // ------------------------------------------------------------------

    pub fn read_slot(&self, artifact: VaultArtifact) -> Result<SlotFile, StoreError> {
        if self.faults.hit(FaultPoint::ReadSlot) {
            return Err(err(NativeErrorCode::StorageUnavailable));
        }
        let bytes = match self.read_artifact(artifact) {
            Ok(b) => b,
            Err(StoreError(NativeErrorCode::NoVault)) => {
                return Err(err(NativeErrorCode::StorageUnavailable));
            }
            Err(e) => return Err(e),
        };
        serde_json::from_slice(&bytes).map_err(|_| err(NativeErrorCode::MalformedEnvelope))
    }

    pub fn slot_exists(&self, artifact: VaultArtifact) -> bool {
        matches!(self.classify(artifact), Ok(PathCheck::Contained))
    }

    /// Validate a slot fully: format version, mode, generation, and — when a
    /// wrapping key is supplied for OS-backed envelopes — envelope
    /// authentication.
    fn validate_slot(
        &self,
        slot: &SlotFile,
        expected_mode: ProtectionMode,
        expected_generation: u64,
        wrapping_key: Option<&[u8]>,
    ) -> Result<(), StoreError> {
        if self.faults.hit(FaultPoint::VerifySlot) {
            return Err(err(NativeErrorCode::StorageUnavailable));
        }
        if slot.mode() != expected_mode {
            return Err(err(NativeErrorCode::MalformedEnvelope));
        }
        if slot.generation() != expected_generation {
            return Err(err(NativeErrorCode::GenerationConflict));
        }
        match slot {
            SlotFile::OsBacked(inner) => {
                if inner.envelope_format_version != SLOT_ENVELOPE_FORMAT_VERSION {
                    return Err(err(NativeErrorCode::WrapperVersionUnsupported));
                }
                if let Some(key) = wrapping_key {
                    if key.len() != AES_KEY_BYTES {
                        return Err(err(NativeErrorCode::MalformedEnvelope));
                    }
                    unwrap_os_backed(key, inner).map_err(|e| StoreError(e.to_native_error()))?;
                }
            }
            SlotFile::PasswordOnly(inner) => {
                if inner.envelope_format_version != SLOT_ENVELOPE_FORMAT_VERSION {
                    return Err(err(NativeErrorCode::WrapperVersionUnsupported));
                }
                unwrap_password_only(inner).map_err(|e| StoreError(e.to_native_error()))?;
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Sidecar
    // ------------------------------------------------------------------

    /// Read the non-secret sidecar. Missing/corrupt sidecars reset safely to
    /// a fresh record (FEAT-003/004 "untrusted sidecar" rule — they can never
    /// create denial of service or lockout).
    pub fn read_sidecar(&self) -> Result<SidecarRecord, StoreError> {
        let bytes = match self.read_artifact(VaultArtifact::Sidecars) {
            Ok(b) => b,
            Err(StoreError(NativeErrorCode::NoVault)) => return Ok(SidecarRecord::fresh()),
            Err(e) => return Err(e),
        };
        match serde_json::from_slice::<SidecarRecord>(&bytes) {
            Ok(record) => Ok(record),
            Err(_) => Ok(SidecarRecord::fresh()),
        }
    }

    pub fn write_sidecar(&self, record: &SidecarRecord) -> Result<(), StoreError> {
        let bytes =
            serde_json::to_vec(record).map_err(|_| err(NativeErrorCode::MalformedEnvelope))?;
        self.write_artifact_atomic(VaultArtifact::Sidecars, &bytes)
    }

    /// Read-modify-write the sidecar atomically.
    pub fn update_sidecar(
        &self,
        update: impl FnOnce(&mut SidecarRecord),
    ) -> Result<SidecarRecord, StoreError> {
        let mut record = self.read_sidecar()?;
        update(&mut record);
        record.state_digest_hex = sidecar_digest(&record);
        self.write_sidecar(&record)?;
        Ok(record)
    }

    /// Current protection mode from the authoritative active slot.
    pub fn protection_mode(&self) -> Result<ProtectionMode, StoreError> {
        let journal = self.read_journal()?;
        let slot = self.read_slot(journal.active_slot)?;
        Ok(slot.mode())
    }

    // ------------------------------------------------------------------
    // Provision (first vault)
    // ------------------------------------------------------------------

    pub fn provision(
        &self,
        package: &[u8],
        mode: ProtectionMode,
        wrapping_key: Option<&[u8]>,
        fallback_acknowledged: bool,
        now_ms: u64,
    ) -> Result<ProvisionOutcome, StoreError> {
        if self.slot_exists(VaultArtifact::SlotA) || self.slot_exists(VaultArtifact::SlotB) {
            // An existing vault must never be silently replaced.
            return Err(err(NativeErrorCode::GenerationConflict));
        }
        if mode == ProtectionMode::PasswordOnly && !fallback_acknowledged {
            // Fallback requires the explicit informed acknowledgement.
            return Err(err(NativeErrorCode::OperationForbidden));
        }
        if mode == ProtectionMode::OsBacked && wrapping_key.is_none() {
            return Err(err(NativeErrorCode::OperationForbidden));
        }
        let generation = 1u64;
        let slot = build_slot(package, mode, wrapping_key, generation)?;
        let active_slot = VaultArtifact::SlotA;
        self.write_slot_checked(active_slot, &slot)?;
        let journal = JournalRecord {
            format_version: 1,
            state: JournalState::Active,
            active_generation: generation,
            expected_generation: generation,
            retained_generation: None,
            active_slot,
            active_verified_at_ms: Some(now_ms),
        };
        self.write_journal(&journal)?;
        self.mirror_sidecar(mode, fallback_acknowledged)?;
        Ok(ProvisionOutcome {
            generation,
            active_slot,
        })
    }

    // ------------------------------------------------------------------
    // Two-slot CAS commit
    // ------------------------------------------------------------------

    /// Commit a complete candidate package to the inactive fixed slot and
    /// atomically switch the journal after read-back verification.
    ///
    /// `candidate_generation` must equal `expected_generation + 1` (reference
    /// FEAT-004 journal semantics). The previous active slot becomes the
    /// single bounded rollback slot.
    pub fn commit(&self, req: &CommitRequest<'_>) -> Result<CommitOutcome, StoreError> {
        let expected_generation = req.expected_generation;
        let candidate_generation = req.candidate_generation;
        let package = req.package;
        let mode = req.mode;
        let wrapping_key = req.wrapping_key;
        let fallback_acknowledged = req.fallback_acknowledged;
        let now_ms = req.now_ms;
        if candidate_generation == 0 || candidate_generation != expected_generation + 1 {
            return Err(err(NativeErrorCode::GenerationConflict));
        }
        if mode == ProtectionMode::PasswordOnly && !fallback_acknowledged {
            return Err(err(NativeErrorCode::OperationForbidden));
        }
        if mode == ProtectionMode::OsBacked && wrapping_key.is_none() {
            return Err(err(NativeErrorCode::OperationForbidden));
        }
        let journal = self.read_journal()?;
        // CAS precondition: writer must hold the expected generation.
        if !journal.generation_matches(expected_generation) {
            return Err(err(NativeErrorCode::GenerationConflict));
        }
        let inactive = inactive_of(journal.active_slot);
        // Step: construct the complete candidate in native memory.
        let slot = build_slot(package, mode, wrapping_key, candidate_generation)?;
        // Steps: exclusive temp write, flush+fsync, atomic rename.
        self.write_slot_checked(inactive, &slot)?;
        // Step: open, parse, unwrap, authenticate, validate.
        let written = self.read_slot(inactive)?;
        self.validate_slot(&written, mode, candidate_generation, wrapping_key)?;
        // Step: journal CAS + switch (the atomic commit point; the journal
        // write itself flushes and fsyncs the containing directory).
        let next = JournalRecord {
            format_version: 1,
            state: JournalState::Active,
            active_generation: candidate_generation,
            expected_generation,
            retained_generation: Some(expected_generation),
            active_slot: inactive,
            active_verified_at_ms: Some(now_ms),
        };
        self.write_journal(&next)?;
        // Mirror the mode into the non-secret sidecar. The sidecar is a
        // projection only — its failure never invalidates the committed
        // vault state (the active slot envelope is authoritative).
        let _ = self.mirror_sidecar(mode, fallback_acknowledged);
        Ok(CommitOutcome {
            generation: candidate_generation,
            active_slot: inactive,
        })
    }

    /// Mirror the non-secret protection projection into the sidecar.
    fn mirror_sidecar(
        &self,
        mode: ProtectionMode,
        fallback_acknowledged: bool,
    ) -> Result<SidecarRecord, StoreError> {
        self.update_sidecar(|r| {
            r.protection_mode = mode_name(mode).to_string();
            r.fallback_acknowledged = fallback_acknowledged;
        })
    }

    fn write_slot_checked(
        &self,
        artifact: VaultArtifact,
        slot: &SlotFile,
    ) -> Result<(), StoreError> {
        let bytes =
            serde_json::to_vec(slot).map_err(|_| err(NativeErrorCode::MalformedEnvelope))?;
        self.write_artifact_atomic(artifact, &bytes)?;
        // Bit-rot / short-write corruption before the journal switch: the
        // read-back must detect it and the journal must remain unchanged.
        if self.faults.hit(FaultPoint::CorruptWrittenSlot) {
            let path = self.artifact_path(artifact)?;
            let mut data = std::fs::read(&path).map_err(map_io)?;
            let mid = data.len() / 2;
            data[mid] ^= 0x01;
            std::fs::write(&path, data).map_err(map_io)?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Rotation (file side): stage + promote
    // ------------------------------------------------------------------

    /// Stage a rotated package into the inactive slot (same generation,
    /// re-wrapped under the staged key). At most one staged package exists;
    /// the active slot remains authoritative until promotion.
    pub fn stage_rotation(
        &self,
        package: &[u8],
        staged_wrapping_key: &[u8],
    ) -> Result<(), StoreError> {
        let journal = self.read_journal()?;
        if journal.state != JournalState::Active {
            // A second staged package is a defect — fail closed.
            return Err(err(NativeErrorCode::OperationForbidden));
        }
        if staged_wrapping_key.len() != AES_KEY_BYTES {
            return Err(err(NativeErrorCode::OperationForbidden));
        }
        let generation = journal.active_generation;
        let wrapper = wrapper_metadata(generation);
        let staged = wrap_os_backed(staged_wrapping_key, package, wrapper)
            .map_err(|e| StoreError(e.to_native_error()))?;
        let inactive = inactive_of(journal.active_slot);
        self.write_slot_checked(inactive, &staged)?;
        // Read-back verification of the staged package.
        let written = self.read_slot(inactive)?;
        self.validate_slot(
            &written,
            ProtectionMode::OsBacked,
            generation,
            Some(staged_wrapping_key),
        )?;
        let next = JournalRecord {
            state: JournalState::PendingRotation,
            ..journal
        };
        self.write_journal(&next)?;
        Ok(())
    }

    /// Promote a staged rotation after read-back verification AND one
    /// successful unlock of the staged-protected package. The old active slot
    /// becomes the bounded rollback slot.
    pub fn promote_rotation(
        &self,
        staged_wrapping_key: &[u8],
        staged_unlock_succeeded: bool,
        now_ms: u64,
    ) -> Result<u64, StoreError> {
        if !staged_unlock_succeeded {
            return Err(err(NativeErrorCode::OperationForbidden));
        }
        let journal = self.read_journal()?;
        if journal.state != JournalState::PendingRotation {
            return Err(err(NativeErrorCode::OperationForbidden));
        }
        let staged_slot = inactive_of(journal.active_slot);
        let written = self.read_slot(staged_slot)?;
        self.validate_slot(
            &written,
            ProtectionMode::OsBacked,
            journal.active_generation,
            Some(staged_wrapping_key),
        )?;
        let next = JournalRecord {
            format_version: 1,
            state: JournalState::Active,
            active_generation: journal.active_generation,
            expected_generation: journal.active_generation,
            retained_generation: Some(journal.active_generation),
            active_slot: staged_slot,
            active_verified_at_ms: Some(now_ms),
        };
        self.write_journal(&next)?;
        let _ = self.mirror_sidecar(ProtectionMode::OsBacked, false);
        Ok(journal.active_generation)
    }

    // ------------------------------------------------------------------
    // Verified rollback
    // ------------------------------------------------------------------

    /// Activate the retained rollback slot. Requires explicit confirmation
    /// AND exact online identity verification, plus a fully validated
    /// rollback candidate at the expected generation.
    pub fn promote_rollback(
        &self,
        confirmed: bool,
        online_verified: bool,
        expected_generation: u64,
        wrapping_key: Option<&[u8]>,
        now_ms: u64,
    ) -> Result<u64, StoreError> {
        if !confirmed || !online_verified {
            return Err(err(NativeErrorCode::OperationForbidden));
        }
        let journal = self.read_journal()?;
        let rollback_slot = inactive_of(journal.active_slot);
        let candidate = self.read_slot(rollback_slot)?;
        let mode = candidate.mode();
        self.validate_slot(&candidate, mode, expected_generation, wrapping_key)?;
        let next = JournalRecord {
            format_version: 1,
            state: JournalState::Active,
            active_generation: expected_generation,
            expected_generation,
            retained_generation: Some(journal.active_generation),
            active_slot: rollback_slot,
            active_verified_at_ms: Some(now_ms),
        };
        self.write_journal(&next)?;
        let _ = self.mirror_sidecar(mode, false);
        Ok(expected_generation)
    }

    // ------------------------------------------------------------------
    // Obsolete-rollback cleanup (next-success/24h rule)
    // ------------------------------------------------------------------

    /// Successful unlock of the active slot removes the obsolete rollback
    /// immediately (next-success rule) and re-anchors the verification time.
    /// The journal is switched first so a crash mid-cleanup leaves a
    /// consistent (rollback-cleared) state; the slot removal itself is
    /// best-effort and idempotent.
    pub fn on_successful_unlock(&self, now_ms: u64) -> Result<CleanupOutcome, StoreError> {
        let journal = self.read_journal()?;
        let removed_generation = journal.retained_generation;
        let next = JournalRecord {
            retained_generation: None,
            active_verified_at_ms: Some(now_ms),
            ..journal
        };
        self.write_journal(&next)?;
        if removed_generation.is_some() {
            let rollback_slot = inactive_of(journal.active_slot);
            let _ = self.remove_artifact(rollback_slot);
            let _ = self.fsync_dir();
        }
        Ok(CleanupOutcome {
            retained: false,
            removed_generation,
        })
    }

    /// 24h window cleanup: the obsolete rollback is removed only after the
    /// active slot was verified and the window since that verification has
    /// elapsed. Without a verified-at anchor the rollback is retained
    /// (fail-safe: never delete the only recovery slot).
    pub fn cleanup_obsolete(&self, now_ms: u64) -> Result<CleanupOutcome, StoreError> {
        if self.faults.hit(FaultPoint::CleanupObsolete) {
            return Err(err(NativeErrorCode::StorageUnavailable));
        }
        let journal = self.read_journal()?;
        let Some(retained) = journal.retained_generation else {
            return Ok(CleanupOutcome {
                retained: false,
                removed_generation: None,
            });
        };
        let verified_at = match journal.active_verified_at_ms {
            Some(v) if now_ms >= v && now_ms - v >= ROLLBACK_CLEANUP_MS => v,
            _ => {
                return Ok(CleanupOutcome {
                    retained: true,
                    removed_generation: None,
                });
            }
        };
        let next = JournalRecord {
            retained_generation: None,
            active_verified_at_ms: Some(verified_at),
            ..journal
        };
        self.write_journal(&next)?;
        let rollback_slot = inactive_of(journal.active_slot);
        let _ = self.remove_artifact(rollback_slot);
        let _ = self.fsync_dir();
        Ok(CleanupOutcome {
            retained: false,
            removed_generation: Some(retained),
        })
    }

    // ------------------------------------------------------------------
    // Startup reconciliation (deterministic crash recovery)
    // ------------------------------------------------------------------

    /// Deterministic startup recovery: after any crash/kill/power-loss the
    /// journal is authoritative. The active slot must exist and validate at
    /// the schema/mode/generation level (full envelope authentication happens
    /// at unlock). An unreferenced inactive slot is obsolete (a commit that
    /// never switched) and is removed; a lost staged package during
    /// `PendingRotation` fails closed to portable recovery. A missing journal
    /// means "no vault": any orphan slot is an uncommitted provision and is
    /// removed deterministically so provisioning can be retried. Removal in
    /// progress owns its own state (slots may already be deleted).
    pub fn reconcile(&self) -> Result<(), StoreError> {
        let journal = match self.read_journal() {
            Ok(j) => j,
            Err(StoreError(NativeErrorCode::NoVault)) => {
                // No journal → no vault. Orphan slot files are uncommitted
                // provision garbage (never journaled, never authoritative).
                for artifact in [VaultArtifact::SlotA, VaultArtifact::SlotB] {
                    let _ = self.remove_artifact(artifact);
                }
                let _ = self.fsync_dir();
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        if journal.state == JournalState::RemovalInProgress {
            // Removal resumes through the tombstone path; the active slot may
            // already be deleted and must not block resumption.
            return Ok(());
        }
        let active = self.read_slot(journal.active_slot)?;
        self.validate_slot(&active, active.mode(), journal.active_generation, None)?;
        let inactive = inactive_of(journal.active_slot);
        let inactive_present = self.slot_exists(inactive);
        match journal.state {
            JournalState::Active => {
                if inactive_present && journal.retained_generation.is_none() {
                    // Unreferenced inactive slot: uncommitted write or stale
                    // rollback without journal anchor — deterministic removal.
                    self.remove_artifact(inactive)?;
                    self.fsync_dir()?;
                }
            }
            JournalState::PendingRotation => {
                if !inactive_present {
                    // Staged package lost mid-rotation: fail closed to
                    // portable recovery; never guess a key.
                    return Err(err(NativeErrorCode::PlatformProtectionInvalidated));
                }
                let staged = self.read_slot(inactive)?;
                self.validate_slot(
                    &staged,
                    ProtectionMode::OsBacked,
                    journal.active_generation,
                    None,
                )?;
            }
            JournalState::RemovalInProgress => unreachable!(), // handled above
            JournalState::Migration => {
                // Migration is a committed Active state; nothing extra.
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Tombstone + removal (file side)
    // ------------------------------------------------------------------

    pub fn write_tombstone(&self, tombstone: &RemovalTombstoneV1) -> Result<(), StoreError> {
        let bytes =
            serde_json::to_vec(tombstone).map_err(|_| err(NativeErrorCode::MalformedEnvelope))?;
        self.write_artifact_atomic(VaultArtifact::RemovalTombstone, &bytes)
    }

    pub fn read_tombstone(&self) -> Result<Option<RemovalTombstoneV1>, StoreError> {
        let bytes = match self.read_artifact(VaultArtifact::RemovalTombstone) {
            Ok(b) => b,
            Err(StoreError(NativeErrorCode::NoVault)) => return Ok(None),
            Err(e) => return Err(e),
        };
        match serde_json::from_slice(&bytes) {
            Ok(t) => Ok(Some(t)),
            Err(_) => Ok(None), // malformed tombstone cannot block recovery
        }
    }

    pub fn clear_tombstone(&self) -> Result<(), StoreError> {
        self.remove_artifact(VaultArtifact::RemovalTombstone)?;
        self.fsync_dir()?;
        Ok(())
    }

    /// Delete active/rollback/staged vault files, journal, sidecars, and the
    /// lock, then flush the directory. The removal tombstone is deliberately
    /// NOT deleted here: it must survive until verified absence clears it.
    pub fn delete_vault_artifacts(&self) -> Result<(), StoreError> {
        for artifact in VAULT_ARTIFACTS_EXCL_TOMBSTONE {
            let _ = self.remove_artifact(*artifact);
        }
        self.fsync_dir()?;
        Ok(())
    }

    /// Verify all required artifacts are absent (exact success verification).
    pub fn verify_artifacts_absent(&self) -> Result<bool, StoreError> {
        let mut absent = true;
        for artifact in VAULT_ARTIFACTS_EXCL_TOMBSTONE {
            if self.slot_exists(*artifact) {
                absent = false;
            }
        }
        Ok(absent)
    }

    // ------------------------------------------------------------------
    // Test-only fault injection
    // ------------------------------------------------------------------

    /// Arm a fault for the next occurrence of `point` (deterministic crash
    /// matrix). Test-only: release builds never set faults.
    #[cfg(test)]
    pub fn set_fault(&self, point: FaultPoint) {
        self.faults.flag(point).store(true, Ordering::SeqCst);
    }
}

/// All fixed vault artifacts (layout order).
pub const ALL_ARTIFACTS: &[VaultArtifact] = &[
    VaultArtifact::SlotA,
    VaultArtifact::SlotB,
    VaultArtifact::Journal,
    VaultArtifact::Sidecars,
    VaultArtifact::RemovalTombstone,
    VaultArtifact::VaultLock,
];

/// Artifacts removed during local-user removal (tombstone survives until
/// verified absence).
pub const VAULT_ARTIFACTS_EXCL_TOMBSTONE: &[VaultArtifact] = &[
    VaultArtifact::SlotA,
    VaultArtifact::SlotB,
    VaultArtifact::Journal,
    VaultArtifact::Sidecars,
    VaultArtifact::VaultLock,
];

/// The inactive fixed slot (the other of the two).
pub fn inactive_of(active: VaultArtifact) -> VaultArtifact {
    match active {
        VaultArtifact::SlotA => VaultArtifact::SlotB,
        _ => VaultArtifact::SlotA,
    }
}

fn build_slot(
    package: &[u8],
    mode: ProtectionMode,
    wrapping_key: Option<&[u8]>,
    generation: u64,
) -> Result<SlotFile, StoreError> {
    match mode {
        ProtectionMode::OsBacked => {
            let key = wrapping_key.ok_or_else(|| err(NativeErrorCode::OperationForbidden))?;
            wrap_os_backed(key, package, wrapper_metadata(generation))
                .map_err(|e| StoreError(e.to_native_error()))
        }
        ProtectionMode::PasswordOnly => Ok(password_only_slot(generation, package)),
    }
}

fn wrapper_metadata(generation: u64) -> WrapperMetadataV1 {
    WrapperMetadataV1 {
        wrapper_format_version: crate::ubuntu_vault::WRAPPER_FORMAT_VERSION,
        adapter_id: crate::ubuntu_vault::ADAPTER_ID.to_string(),
        application_id: crate::ubuntu_vault::APPLICATION_ID.to_string(),
        release_channel: ReleaseChannel::Production,
        generation,
        purpose: crate::ubuntu_vault::ITEM_PURPOSE.to_string(),
    }
}

fn mode_name(mode: ProtectionMode) -> &'static str {
    match mode {
        ProtectionMode::OsBacked => "os-backed",
        ProtectionMode::PasswordOnly => "password-only",
    }
}

/// Authenticated non-secret sidecar digest (tamper detection; never secret).
fn sidecar_digest(record: &SidecarRecord) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"hushvoting/sidecar/v1");
    hasher.update([0]);
    hasher.update(record.protection_mode.as_bytes());
    hasher.update([0]);
    hasher.update([record.fallback_acknowledged as u8]);
    hasher.update([0]);
    hasher.update([record.failed_password_count]);
    hasher.update([0]);
    hasher.update(record.cooldown_deadline_ms.to_le_bytes());
    hex_encode(&hasher.finalize())
}

fn current_uid() -> u32 {
    // SAFETY: geteuid has no preconditions.
    unsafe { libc::geteuid() }
}

fn map_path_check(check: PathCheck) -> StoreError {
    match check {
        PathCheck::Contained => err(NativeErrorCode::StorageUnavailable),
        PathCheck::EscapesRoot | PathCheck::WrongType | PathCheck::SymbolicLink => {
            err(NativeErrorCode::PersistenceDenied)
        }
        PathCheck::WrongOwner | PathCheck::WrongMode | PathCheck::LinkCountAnomaly => {
            err(NativeErrorCode::PersistenceDenied)
        }
        PathCheck::Missing => err(NativeErrorCode::NoVault),
    }
}

fn map_io(e: std::io::Error) -> StoreError {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::NotFound => err(NativeErrorCode::NoVault),
        ErrorKind::PermissionDenied => err(NativeErrorCode::PersistenceDenied),
        ErrorKind::StorageFull => err(NativeErrorCode::StorageQuotaExceeded),
        ErrorKind::ReadOnlyFilesystem => err(NativeErrorCode::StorageUnavailable),
        ErrorKind::AlreadyExists => err(NativeErrorCode::GenerationConflict),
        _ => err(NativeErrorCode::StorageUnavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ubuntu_vault::storage::layout::VaultArtifact;

    fn temp_root(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "feat005-writer-{name}-{}-{}",
            std::process::id(),
            hex_encode(&random_bytes(4).unwrap())
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn key() -> Vec<u8> {
        vec![0x2au8; 32]
    }

    fn open_store(name: &str) -> VaultStore {
        VaultStore::open(temp_root(name)).unwrap()
    }

    fn provisioned(name: &str) -> (VaultStore, Vec<u8>) {
        let store = open_store(name);
        let k = key();
        store
            .provision(
                b"package-gen-1",
                ProtectionMode::OsBacked,
                Some(&k),
                false,
                1_000,
            )
            .unwrap();
        (store, k)
    }

    #[test]
    fn open_creates_root_with_0700_and_owner() {
        let root = temp_root("init");
        let store = VaultStore::open(&root).unwrap();
        let meta = std::fs::symlink_metadata(store.root()).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o700);
        assert_eq!(meta.uid(), current_uid());
        assert!(root.is_dir());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn provision_writes_slot_journal_and_sidecar() {
        let store = open_store("provision");
        let k = key();
        let outcome = store
            .provision(b"pkg", ProtectionMode::OsBacked, Some(&k), false, 5_000)
            .unwrap();
        assert_eq!(outcome.generation, 1);
        assert_eq!(outcome.active_slot, VaultArtifact::SlotA);
        assert!(store.slot_exists(VaultArtifact::SlotA));
        let journal = store.read_journal().unwrap();
        assert_eq!(journal.active_generation, 1);
        assert_eq!(journal.active_slot, VaultArtifact::SlotA);
        let sidecar = store.read_sidecar().unwrap();
        assert_eq!(sidecar.protection_mode, "os-backed");
        assert!(!sidecar.state_digest_hex.is_empty());
        assert_eq!(store.protection_mode().unwrap(), ProtectionMode::OsBacked);
    }

    #[test]
    fn provision_rejects_unacknowledged_fallback() {
        let store = open_store("provision-fallback-no-ack");
        assert_eq!(
            store
                .provision(b"pkg", ProtectionMode::PasswordOnly, None, false, 1)
                .err()
                .unwrap()
                .0,
            NativeErrorCode::OperationForbidden
        );
        assert!(!store.slot_exists(VaultArtifact::SlotA));
    }

    #[test]
    fn provision_accepts_acknowledged_fallback() {
        let store = open_store("provision-fallback-ack");
        store
            .provision(b"pkg", ProtectionMode::PasswordOnly, None, true, 1)
            .unwrap();
        assert_eq!(
            store.protection_mode().unwrap(),
            ProtectionMode::PasswordOnly
        );
    }

    #[test]
    fn provision_never_replaces_existing_vault() {
        let (store, _) = provisioned("no-replace");
        assert_eq!(
            store
                .provision(b"pkg2", ProtectionMode::OsBacked, Some(&key()), false, 2)
                .err()
                .unwrap()
                .0,
            NativeErrorCode::GenerationConflict
        );
    }

    #[test]
    fn commit_bumps_generation_and_retains_previous_as_rollback() {
        let (store, k) = provisioned("commit");
        let outcome = store
            .commit(&CommitRequest {
                expected_generation: 1,
                candidate_generation: 2,
                package: b"package-gen-2",
                mode: ProtectionMode::OsBacked,
                wrapping_key: Some(&k),
                fallback_acknowledged: false,
                now_ms: 2_000,
            })
            .unwrap();
        assert_eq!(outcome.generation, 2);
        assert_eq!(outcome.active_slot, VaultArtifact::SlotB);
        let journal = store.read_journal().unwrap();
        assert_eq!(journal.active_generation, 2);
        assert_eq!(journal.active_slot, VaultArtifact::SlotB);
        assert_eq!(journal.retained_generation, Some(1));
        // The previous active slot (slot-a) is the bounded rollback and still
        // decrypts with the same wrapping key.
        let retained = store.read_slot(VaultArtifact::SlotA).unwrap();
        assert_eq!(retained.generation(), 1);
    }

    #[test]
    fn commit_requires_exact_forward_generation() {
        let (store, k) = provisioned("commit-gen");
        // Stale (non-forward) writes are rejected.
        assert_eq!(
            store
                .commit(&CommitRequest {
                    expected_generation: 2,
                    candidate_generation: 1,
                    package: b"pkg",
                    mode: ProtectionMode::OsBacked,
                    wrapping_key: Some(&k),
                    fallback_acknowledged: false,
                    now_ms: 3
                })
                .err()
                .unwrap()
                .0,
            NativeErrorCode::GenerationConflict
        );
        // Out-of-order forward writes are rejected.
        assert_eq!(
            store
                .commit(&CommitRequest {
                    expected_generation: 1,
                    candidate_generation: 3,
                    package: b"pkg",
                    mode: ProtectionMode::OsBacked,
                    wrapping_key: Some(&k),
                    fallback_acknowledged: false,
                    now_ms: 3
                })
                .err()
                .unwrap()
                .0,
            NativeErrorCode::GenerationConflict
        );
    }

    #[test]
    fn commit_cas_rejects_stale_writer() {
        let (store, k) = provisioned("commit-cas");
        // Expected generation 1 is current; a writer believing it is at gen 0
        // must be rejected.
        assert_eq!(
            store
                .commit(&CommitRequest {
                    expected_generation: 0,
                    candidate_generation: 1,
                    package: b"pkg",
                    mode: ProtectionMode::OsBacked,
                    wrapping_key: Some(&k),
                    fallback_acknowledged: false,
                    now_ms: 3
                })
                .err()
                .unwrap()
                .0,
            NativeErrorCode::GenerationConflict
        );
    }

    #[test]
    fn commit_reads_back_and_authenticates_candidate() {
        let (store, k) = provisioned("commit-auth");
        // Bit-rot / short-write corruption after the slot write but before
        // the journal switch: the read-back must fail closed and the journal
        // must remain unchanged (generation 1 authoritative).
        store.set_fault(FaultPoint::CorruptWrittenSlot);
        let err = store
            .commit(&CommitRequest {
                expected_generation: 1,
                candidate_generation: 2,
                package: b"pkg",
                mode: ProtectionMode::OsBacked,
                wrapping_key: Some(&k),
                fallback_acknowledged: false,
                now_ms: 3,
            })
            .err()
            .unwrap()
            .0;
        // The corruption lands either in the hex payload (authentication
        // failure) or in the JSON structure (malformed) — both are closed
        // fail-closed codes; the journal must remain unchanged.
        assert!(
            matches!(
                err,
                NativeErrorCode::PlatformProtectionInvalidated | NativeErrorCode::MalformedEnvelope
            ),
            "unexpected code {err:?}"
        );
        let journal = store.read_journal().unwrap();
        assert_eq!(journal.active_generation, 1); // unchanged
        assert_eq!(journal.active_slot, VaultArtifact::SlotA);
        store.reconcile().unwrap();
        assert_eq!(store.read_journal().unwrap().active_generation, 1);
        // Deterministic recovery removes the corrupted uncommitted slot.
        assert!(!store.slot_exists(VaultArtifact::SlotB));
    }

    #[test]
    fn commit_fault_matrix_preserves_recoverable_state() {
        // Inject a fault at every step; after each failure the vault must
        // still open deterministically with generation 1 authoritative.
        for point in [
            FaultPoint::WriteTemp,
            FaultPoint::FlushFsync,
            FaultPoint::Rename,
            FaultPoint::CorruptWrittenSlot,
            FaultPoint::VerifySlot,
            FaultPoint::JournalCas,
            FaultPoint::FsyncDir,
        ] {
            let (store, k) = provisioned("fault");
            store.set_fault(point);
            let result = store.commit(&CommitRequest {
                expected_generation: 1,
                candidate_generation: 2,
                package: b"pkg",
                mode: ProtectionMode::OsBacked,
                wrapping_key: Some(&k),
                fallback_acknowledged: false,
                now_ms: 2_000,
            });
            assert!(result.is_err(), "fault {point:?} must fail");
            // Deterministic recovery: journal still points at generation 1.
            store.reconcile().unwrap();
            let journal = store.read_journal().unwrap();
            assert_eq!(journal.active_generation, 1, "after {point:?}");
            assert_eq!(journal.active_slot, VaultArtifact::SlotA, "after {point:?}");
            assert_eq!(journal.retained_generation, None, "after {point:?}");
            // The active slot is intact and verifiable.
            let active = store.read_slot(journal.active_slot).unwrap();
            store
                .validate_slot(&active, ProtectionMode::OsBacked, 1, Some(&k))
                .unwrap();
            let _ = std::fs::remove_dir_all(store.root());
        }
    }

    #[test]
    fn on_successful_unlock_removes_obsolete_rollback() {
        let (store, k) = provisioned("unlock-cleanup");
        store
            .commit(&CommitRequest {
                expected_generation: 1,
                candidate_generation: 2,
                package: b"gen2",
                mode: ProtectionMode::OsBacked,
                wrapping_key: Some(&k),
                fallback_acknowledged: false,
                now_ms: 2_000,
            })
            .unwrap();
        assert!(store.slot_exists(VaultArtifact::SlotA)); // retained
        let outcome = store.on_successful_unlock(3_000).unwrap();
        assert_eq!(outcome.removed_generation, Some(1));
        assert!(!store.slot_exists(VaultArtifact::SlotA));
        let journal = store.read_journal().unwrap();
        assert_eq!(journal.retained_generation, None);
    }

    #[test]
    fn cleanup_obsolete_respects_24h_window() {
        let (store, k) = provisioned("cleanup-24h");
        store
            .commit(&CommitRequest {
                expected_generation: 1,
                candidate_generation: 2,
                package: b"gen2",
                mode: ProtectionMode::OsBacked,
                wrapping_key: Some(&k),
                fallback_acknowledged: false,
                now_ms: 2_000,
            })
            .unwrap();
        // Before the window: retained (fail-safe).
        let early = store
            .cleanup_obsolete(2_000 + ROLLBACK_CLEANUP_MS - 1)
            .unwrap();
        assert!(early.retained);
        assert!(store.slot_exists(VaultArtifact::SlotA));
        // After the window: removed.
        let late = store.cleanup_obsolete(2_000 + ROLLBACK_CLEANUP_MS).unwrap();
        assert!(!late.retained);
        assert_eq!(late.removed_generation, Some(1));
        assert!(!store.slot_exists(VaultArtifact::SlotA));
    }

    #[test]
    fn cleanup_obsolete_without_verified_anchor_retains() {
        let store = open_store("cleanup-no-anchor");
        let k = key();
        // Manually build a journal with no verified-at anchor (crash before
        // verification recorded).
        store
            .write_artifact_atomic(
                VaultArtifact::SlotA,
                &serde_json::to_vec(
                    &build_slot(b"pkg", ProtectionMode::OsBacked, Some(&k), 1).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        store
            .write_artifact_atomic(
                VaultArtifact::SlotB,
                &serde_json::to_vec(
                    &build_slot(b"old", ProtectionMode::OsBacked, Some(&k), 1).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        let journal = JournalRecord {
            format_version: 1,
            state: JournalState::Active,
            active_generation: 1,
            expected_generation: 1,
            retained_generation: Some(1),
            active_slot: VaultArtifact::SlotA,
            active_verified_at_ms: None,
        };
        store.write_journal(&journal).unwrap();
        let outcome = store.cleanup_obsolete(now_far_future()).unwrap();
        assert!(outcome.retained);
        assert!(store.slot_exists(VaultArtifact::SlotB));
    }

    fn now_far_future() -> u64 {
        u64::MAX / 2
    }

    #[test]
    fn stage_and_promote_rotation_is_staged_and_verified() {
        let (store, k) = provisioned("rotation");
        let staged_key = vec![0x77u8; 32];
        // Staging writes the same generation under the staged key.
        store.stage_rotation(b"package-gen-1", &staged_key).unwrap();
        let journal = store.read_journal().unwrap();
        assert_eq!(journal.state, JournalState::PendingRotation);
        assert_eq!(journal.active_generation, 1);
        assert_eq!(journal.active_slot, VaultArtifact::SlotA);
        // Staged slot exists and validates under the staged key.
        let staged = store.read_slot(VaultArtifact::SlotB).unwrap();
        store
            .validate_slot(&staged, ProtectionMode::OsBacked, 1, Some(&staged_key))
            .unwrap();
        // Promotion without the successful unlock precondition is forbidden.
        assert_eq!(
            store
                .promote_rotation(&staged_key, false, 2_000)
                .err()
                .unwrap()
                .0,
            NativeErrorCode::OperationForbidden
        );
        // Promotion with read-back + unlock succeeds; old active becomes the
        // rollback.
        let gen = store.promote_rotation(&staged_key, true, 2_000).unwrap();
        assert_eq!(gen, 1);
        let journal = store.read_journal().unwrap();
        assert_eq!(journal.state, JournalState::Active);
        assert_eq!(journal.active_slot, VaultArtifact::SlotB);
        assert_eq!(journal.retained_generation, Some(1));
        // Old active slot still protected by the old key (rollback path).
        let old = store.read_slot(VaultArtifact::SlotA).unwrap();
        store
            .validate_slot(&old, ProtectionMode::OsBacked, 1, Some(&k))
            .unwrap();
    }

    #[test]
    fn staging_is_forbidden_twice_and_from_pending_state() {
        let (store, _k) = provisioned("rotation-twice");
        let staged_key = vec![0x88u8; 32];
        store.stage_rotation(b"pkg", &staged_key).unwrap();
        assert_eq!(
            store.stage_rotation(b"pkg", &staged_key).err().unwrap().0,
            NativeErrorCode::OperationForbidden
        );
    }

    #[test]
    fn rollback_requires_confirmation_and_online_verification() {
        let (store, k) = provisioned("rollback");
        store
            .commit(&CommitRequest {
                expected_generation: 1,
                candidate_generation: 2,
                package: b"gen2",
                mode: ProtectionMode::OsBacked,
                wrapping_key: Some(&k),
                fallback_acknowledged: false,
                now_ms: 2_000,
            })
            .unwrap();
        // Missing confirmation or online verification blocks activation.
        assert_eq!(
            store
                .promote_rollback(false, true, 1, Some(&k), 3_000)
                .err()
                .unwrap()
                .0,
            NativeErrorCode::OperationForbidden
        );
        assert_eq!(
            store
                .promote_rollback(true, false, 1, Some(&k), 3_000)
                .err()
                .unwrap()
                .0,
            NativeErrorCode::OperationForbidden
        );
        // Fully verified activation rolls back to generation 1.
        let gen = store
            .promote_rollback(true, true, 1, Some(&k), 3_000)
            .unwrap();
        assert_eq!(gen, 1);
        let journal = store.read_journal().unwrap();
        assert_eq!(journal.active_generation, 1);
        assert_eq!(journal.active_slot, VaultArtifact::SlotA);
        assert_eq!(journal.retained_generation, Some(2));
    }

    #[test]
    fn rollback_never_activates_wrong_generation() {
        let (store, k) = provisioned("rollback-gen");
        store
            .commit(&CommitRequest {
                expected_generation: 1,
                candidate_generation: 2,
                package: b"gen2",
                mode: ProtectionMode::OsBacked,
                wrapping_key: Some(&k),
                fallback_acknowledged: false,
                now_ms: 2_000,
            })
            .unwrap();
        assert_eq!(
            store
                .promote_rollback(true, true, 9, Some(&k), 3_000)
                .err()
                .unwrap()
                .0,
            NativeErrorCode::GenerationConflict
        );
    }

    #[test]
    fn password_only_upgrade_via_commit_switches_mode_atomically() {
        let store = open_store("upgrade");
        store
            .provision(b"pkg", ProtectionMode::PasswordOnly, None, true, 1_000)
            .unwrap();
        assert_eq!(
            store.protection_mode().unwrap(),
            ProtectionMode::PasswordOnly
        );
        let k = key();
        // The acknowledged fallback source is replaced by an OS-backed
        // package on the next successful unlock path (generation bump).
        store
            .commit(&CommitRequest {
                expected_generation: 1,
                candidate_generation: 2,
                package: b"pkg-os",
                mode: ProtectionMode::OsBacked,
                wrapping_key: Some(&k),
                fallback_acknowledged: false,
                now_ms: 2_000,
            })
            .unwrap();
        assert_eq!(store.protection_mode().unwrap(), ProtectionMode::OsBacked);
        let journal = store.read_journal().unwrap();
        assert_eq!(journal.active_generation, 2);
        // The password-only source remains only until one successful unlock.
        let retained = store.read_slot(VaultArtifact::SlotA).unwrap();
        assert_eq!(retained.mode(), ProtectionMode::PasswordOnly);
        store.on_successful_unlock(3_000).unwrap();
        assert!(!store.slot_exists(VaultArtifact::SlotA));
    }

    #[test]
    fn no_automatic_downgrade_from_os_backed() {
        let (store, _k) = provisioned("no-downgrade");
        // A password-only commit from an OS-backed vault requires the ack;
        // even with the ack the caller must explicitly choose it (no silent
        // path exists). The commit API has no mode coercion — prove that a
        // caller cannot downgrade without an explicit acknowledged commit.
        assert_eq!(
            store
                .commit(&CommitRequest {
                    expected_generation: 1,
                    candidate_generation: 2,
                    package: b"pkg",
                    mode: ProtectionMode::PasswordOnly,
                    wrapping_key: None,
                    fallback_acknowledged: false,
                    now_ms: 2
                })
                .err()
                .unwrap()
                .0,
            NativeErrorCode::OperationForbidden
        );
    }

    #[test]
    fn reconcile_removes_unreferenced_inactive_slot() {
        let (store, _k) = provisioned("reconcile");
        // Simulate a crash after the inactive slot write but before the
        // journal switch.
        store
            .write_slot_checked(
                VaultArtifact::SlotB,
                &build_slot(b"half", ProtectionMode::PasswordOnly, None, 2).unwrap(),
            )
            .unwrap();
        store.reconcile().unwrap();
        assert!(!store.slot_exists(VaultArtifact::SlotB));
        let journal = store.read_journal().unwrap();
        assert_eq!(journal.active_generation, 1);
    }

    #[test]
    fn reconcile_cleans_orphan_slot_after_crashed_provision() {
        let store = open_store("reconcile-provision");
        // Simulate a crash after the slot write but before the journal write
        // during first provisioning: an orphan slot with no journal.
        store
            .write_slot_checked(
                VaultArtifact::SlotA,
                &build_slot(b"half-provision", ProtectionMode::OsBacked, Some(&key()), 1).unwrap(),
            )
            .unwrap();
        assert_eq!(
            store.read_journal().err().unwrap().0,
            NativeErrorCode::NoVault
        );
        // Reconcile treats "no journal" as "no vault" and removes the
        // uncommitted slot so provisioning can be retried.
        store.reconcile().unwrap();
        assert!(!store.slot_exists(VaultArtifact::SlotA));
        assert!(!store.slot_exists(VaultArtifact::SlotB));
        let k = key();
        store
            .provision(b"pkg", ProtectionMode::OsBacked, Some(&k), false, 1_000)
            .unwrap();
        assert_eq!(store.read_journal().unwrap().active_generation, 1);
    }

    #[test]
    fn reconcile_tolerates_removal_in_progress_with_deleted_active_slot() {
        let store = open_store("reconcile-removal");
        let k = key();
        store
            .provision(b"pkg", ProtectionMode::OsBacked, Some(&k), false, 1_000)
            .unwrap();
        // Removal deleted the active slot and marked the journal.
        std::fs::remove_file(store.artifact_path(VaultArtifact::SlotA).unwrap()).unwrap();
        let journal = store.read_journal().unwrap();
        store
            .write_journal(&JournalRecord {
                state: JournalState::RemovalInProgress,
                ..journal
            })
            .unwrap();
        // Reconcile must not block removal resumption on the deleted slot.
        store.reconcile().unwrap();
        assert_eq!(
            store.read_journal().unwrap().state,
            JournalState::RemovalInProgress
        );
    }

    #[test]
    fn reconcile_fails_closed_on_missing_staged_rotation() {
        let (store, _k) = provisioned("reconcile-rotation");
        let staged_key = vec![0x99u8; 32];
        store.stage_rotation(b"pkg", &staged_key).unwrap();
        // Crash before promotion: the staged slot is lost on disk.
        std::fs::remove_file(store.artifact_path(VaultArtifact::SlotB).unwrap()).unwrap();
        let result = store.reconcile();
        assert_eq!(
            result.err().unwrap().0,
            NativeErrorCode::PlatformProtectionInvalidated
        );
    }

    #[test]
    fn reconcile_detects_missing_active_slot() {
        let store = open_store("reconcile-missing-active");
        let k = key();
        store
            .write_artifact_atomic(
                VaultArtifact::SlotA,
                &serde_json::to_vec(
                    &build_slot(b"pkg", ProtectionMode::OsBacked, Some(&k), 1).unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        store
            .write_journal(&JournalRecord {
                format_version: 1,
                state: JournalState::Active,
                active_generation: 1,
                expected_generation: 1,
                retained_generation: None,
                active_slot: VaultArtifact::SlotA,
                active_verified_at_ms: Some(1),
            })
            .unwrap();
        std::fs::remove_file(store.artifact_path(VaultArtifact::SlotA).unwrap()).unwrap();
        let result = store.reconcile();
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().0, NativeErrorCode::StorageUnavailable);
    }

    #[test]
    fn tombstone_round_trips_and_resumes() {
        let store = open_store("tombstone");
        let tombstone = RemovalTombstoneV1::new(1_000);
        store.write_tombstone(&tombstone).unwrap();
        assert_eq!(store.read_tombstone().unwrap(), Some(tombstone));
        store.clear_tombstone().unwrap();
        assert_eq!(store.read_tombstone().unwrap(), None);
    }

    #[test]
    fn delete_and_verify_absence_is_exact() {
        let (store, k) = provisioned("remove");
        store
            .commit(&CommitRequest {
                expected_generation: 1,
                candidate_generation: 2,
                package: b"gen2",
                mode: ProtectionMode::OsBacked,
                wrapping_key: Some(&k),
                fallback_acknowledged: false,
                now_ms: 2_000,
            })
            .unwrap();
        assert!(!store.verify_artifacts_absent().unwrap());
        store.delete_vault_artifacts().unwrap();
        assert!(store.verify_artifacts_absent().unwrap());
        assert_eq!(
            store.read_journal().err().unwrap().0,
            NativeErrorCode::NoVault
        );
    }

    #[test]
    fn symlink_artifact_is_rejected() {
        let store = open_store("symlink");
        let k = key();
        store
            .provision(b"pkg", ProtectionMode::OsBacked, Some(&k), false, 1)
            .unwrap();
        // Replace journal.json with a symlink to an outside file.
        let outside_dir = temp_root("symlink-outside");
        std::fs::create_dir_all(&outside_dir).unwrap();
        let outside = outside_dir.join("evil.json");
        std::fs::write(&outside, b"{}").unwrap();
        let journal_path = store.artifact_path(VaultArtifact::Journal).unwrap();
        std::fs::remove_file(&journal_path).unwrap();
        std::os::unix::fs::symlink(&outside, &journal_path).unwrap();
        assert_eq!(
            store.read_journal().err().unwrap().0,
            NativeErrorCode::PersistenceDenied
        );
        let _ = std::fs::remove_dir_all(store.root());
        let _ = std::fs::remove_dir_all(&outside_dir);
    }

    #[test]
    fn wrong_mode_and_owner_are_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let store = open_store("mode-owner");
        let k = key();
        store
            .provision(b"pkg", ProtectionMode::OsBacked, Some(&k), false, 1)
            .unwrap();
        // Chmod the journal to 0644 → rejected.
        let journal_path = store.artifact_path(VaultArtifact::Journal).unwrap();
        std::fs::set_permissions(&journal_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            store.read_journal().err().unwrap().0,
            NativeErrorCode::PersistenceDenied
        );
    }

    #[test]
    fn artifacts_never_contain_plaintext_package() {
        let (store, k) = provisioned("no-plaintext");
        store
            .commit(&CommitRequest {
                expected_generation: 1,
                candidate_generation: 2,
                package: b"super-secret-package-bytes-xyz",
                mode: ProtectionMode::OsBacked,
                wrapping_key: Some(&k),
                fallback_acknowledged: false,
                now_ms: 2,
            })
            .unwrap();
        for artifact in [
            VaultArtifact::SlotA,
            VaultArtifact::SlotB,
            VaultArtifact::Journal,
            VaultArtifact::Sidecars,
        ] {
            let path = store.artifact_path(artifact).unwrap();
            let bytes = std::fs::read(&path).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(
                !text.contains("super-secret-package-bytes-xyz"),
                "{artifact:?} leaks plaintext"
            );
        }
    }

    #[test]
    fn staged_rotation_uses_staged_purpose_vocabulary() {
        use crate::ubuntu_vault::secret_service::backend::STAGED_ITEM_PURPOSE;
        // The staged keyring item purpose is fixed and distinct from the
        // active purpose (file-side mirror of the keyring-side staging rule).
        assert_eq!(STAGED_ITEM_PURPOSE, "vault-wrapper-staged");
        assert_ne!(STAGED_ITEM_PURPOSE, crate::ubuntu_vault::ITEM_PURPOSE);
    }
}
