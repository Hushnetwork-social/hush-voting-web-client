//! Vault ownership and single-instance defense (FEAT-005 "Single-Instance
//! and Package Identity", "One instance per Ubuntu user session").
//!
//! Exactly one HushVoting process per Ubuntu user session owns the vault and
//! unlocked credentials. `tauri-plugin-single-instance` handles second-launch
//! focus (composition root); this module holds an exclusive file lock over
//! `vault.lock` as defense in depth so no second writer can mutate vault
//! files. A second process unable to acquire ownership exits with safe
//! feedback. Crash-stale ownership is recoverable (the kernel releases the
//! lock when the owning fd/process dies) without transferring an unlocked
//! session.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use crate::ubuntu_vault::storage::layout::VaultArtifact;

/// Closed ownership failure vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnershipError {
    /// Another process holds the vault ownership lock (safe exit path).
    AlreadyOwned,
    /// The lock file could not be created/opened safely.
    LockUnavailable,
}

impl std::fmt::Display for OwnershipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "vault ownership failure (closed code)")
    }
}

impl std::error::Error for OwnershipError {}

/// Held exclusive vault ownership (dropped → lock released by the kernel).
///
/// The `fd_lock::RwLock` is deliberately leaked (`Box::leak`) so the write
/// guard can borrow it for the process lifetime; one small allocation per
/// process is the documented cost of a self-referential lock guard.
pub struct VaultOwnership {
    _lock: &'static mut fd_lock::RwLock<File>,
    _guard: fd_lock::RwLockWriteGuard<'static, File>,
}

impl VaultOwnership {
    /// Try to acquire the exclusive vault ownership lock. `Ok(None)` is never
    /// produced here: ownership is binary — a `WouldBlock` error means another
    /// process owns the vault and the caller must focus the existing window
    /// (plugin) or exit safely, never touching keyring/vault state.
    pub fn try_acquire(vault_root: &Path) -> Result<Self, OwnershipError> {
        let lock_path = vault_root.join(VaultArtifact::VaultLock.file_name());
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)
            .map_err(|_| OwnershipError::LockUnavailable)?;
        let rwlock: &'static mut fd_lock::RwLock<File> =
            Box::leak(Box::new(fd_lock::RwLock::new(file)));
        // Non-blocking exclusive acquisition (defense in depth). A stale
        // lock from a crashed process is released by the kernel (flock).
        let guard = match rwlock.try_write() {
            Ok(guard) => {
                // SAFETY: `rwlock` is leaked for the process lifetime and is
                // never moved or dropped, so the guard's borrow is valid for
                // the entire process. This is the documented cost of a
                // self-referential lock guard: one small leaked allocation.
                unsafe {
                    std::mem::transmute::<
                        fd_lock::RwLockWriteGuard<'_, File>,
                        fd_lock::RwLockWriteGuard<'static, File>,
                    >(guard)
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                return Err(OwnershipError::AlreadyOwned);
            }
            Err(_) => return Err(OwnershipError::LockUnavailable),
        };
        Ok(Self {
            _lock: rwlock,
            _guard: guard,
        })
    }
}

/// The vault lock is an auxiliary artifact that never carries secrets.
pub fn lock_is_aux() -> bool {
    VaultArtifact::VaultLock.is_lock_or_aux()
}

/// Whether the ownership lock artifact is present (removal keeps it).
pub fn lock_artifact_present(root: &Path) -> bool {
    root.join(VaultArtifact::VaultLock.file_name()).exists()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ubuntu_vault::crypto::encoding::hex_encode;
    use crate::ubuntu_vault::crypto::random_bytes;

    fn temp_root(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "feat005-ownership-{name}-{}-{}",
            std::process::id(),
            hex_encode(&random_bytes(4).unwrap())
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn exclusive_ownership_is_second_process_safe() {
        let root = temp_root("exclusive");
        let first = VaultOwnership::try_acquire(&root).unwrap();
        // A second acquire (second process / second fd) is rejected.
        assert!(matches!(
            VaultOwnership::try_acquire(&root),
            Err(OwnershipError::AlreadyOwned)
        ));
        drop(first);
        // After release (or crash), ownership is recoverable.
        assert!(VaultOwnership::try_acquire(&root).is_ok());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn lock_artifact_is_identity_neutral_aux() {
        assert!(lock_is_aux());
        let root = temp_root("aux");
        let _ = VaultOwnership::try_acquire(&root).unwrap();
        assert!(lock_artifact_present(&root));
        let _ = std::fs::remove_dir_all(&root);
    }
}
