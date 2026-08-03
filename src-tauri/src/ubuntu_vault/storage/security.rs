//! Filesystem security validation model (FEAT-005 "Ownership and permissions").
//!
//! Every vault path must satisfy: contained under the resolved root, regular
//! file or directory, current-UID owner, exact mode, no symbolic link, no
//! hard-link-count anomaly, no unexpected file type. Caller-supplied paths
//! are rejected before any filesystem access.

use serde::{Deserialize, Serialize};

/// Result of one path/artifact security validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PathCheck {
    /// Path is contained in the resolved vault root.
    Contained,
    /// Path escapes the resolved vault root (or is caller/identity-derived).
    EscapesRoot,
    /// Object is not a regular file (or not a directory where expected).
    WrongType,
    /// Object is a symbolic link (rejected).
    SymbolicLink,
    /// Owner is not the current UID (rejected).
    WrongOwner,
    /// Mode is not the exact required mode (rejected; never rely on umask).
    WrongMode,
    /// Hard-link count is anomalous (rejected).
    LinkCountAnomaly,
    /// Object is missing (may be legitimate for first provisioning).
    Missing,
}

/// Policy: which checks are mandatory for vault artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultPathPolicy {
    /// Reject any path that is not directly contained in the vault root.
    pub reject_escapes: bool,
    pub reject_symlinks: bool,
    pub require_regular_file: bool,
    pub require_current_uid_owner: bool,
    pub require_exact_mode: bool,
    pub reject_link_count_anomaly: bool,
    /// Never traverse caller-supplied paths.
    pub reject_caller_supplied_paths: bool,
}

impl Default for VaultPathPolicy {
    fn default() -> Self {
        Self {
            reject_escapes: true,
            reject_symlinks: true,
            require_regular_file: true,
            require_current_uid_owner: true,
            require_exact_mode: true,
            reject_link_count_anomaly: true,
            reject_caller_supplied_paths: true,
        }
    }
}

/// Containment check result for a candidate path relative to a root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Containment {
    Contained,
    Escapes,
    RootItself,
}

/// Deterministic containment decision (pure path logic; no filesystem access).
pub fn containment_of(root: &std::path::Path, candidate: &std::path::Path) -> Containment {
    if candidate == root {
        return Containment::RootItself;
    }
    if candidate.starts_with(root) {
        // Reject traversal segments like ".." inside the candidate.
        for component in candidate.components() {
            if let std::path::Component::ParentDir = component {
                return Containment::Escapes;
            }
        }
        Containment::Contained
    } else {
        Containment::Escapes
    }
}

/// Observed metadata for one filesystem object. Pure model input; the Phase 3
/// writer obtains it from `lstat`/`stat` without traversing caller-supplied
/// paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileMetadata {
    pub is_regular_file: bool,
    pub is_symlink: bool,
    pub owner_is_current_uid: bool,
    /// Raw permission bits (e.g. `0o600`). Compared against the exact mode.
    pub mode: u32,
    /// Hard-link count (`st_nlink`); >1 is an anomaly for vault artifacts.
    pub hard_link_count: u64,
}

/// Deterministic classification of one object against the mandatory policy.
/// Pure model logic (no filesystem access): every unsafe shape maps to a
/// closed `PathCheck` and no active slot is touched.
///
/// `required_mode` is the exact mode for this object kind (`0o600` for
/// artifact files, `0o700` for the root directory from `PermissionModel`).
pub fn classify_path(
    policy: &VaultPathPolicy,
    containment: Containment,
    meta: FileMetadata,
    required_mode: u32,
) -> PathCheck {
    if policy.reject_escapes
        && !matches!(
            containment,
            Containment::Contained | Containment::RootItself
        )
    {
        return PathCheck::EscapesRoot;
    }
    if containment == Containment::RootItself {
        // Directory container: owner and exact directory mode only.
        if policy.require_current_uid_owner && !meta.owner_is_current_uid {
            return PathCheck::WrongOwner;
        }
        if policy.require_exact_mode && meta.mode != required_mode {
            return PathCheck::WrongMode;
        }
        return PathCheck::Contained;
    }
    if policy.reject_symlinks && meta.is_symlink {
        return PathCheck::SymbolicLink;
    }
    if policy.require_regular_file && !meta.is_regular_file {
        return PathCheck::WrongType;
    }
    if policy.require_current_uid_owner && !meta.owner_is_current_uid {
        return PathCheck::WrongOwner;
    }
    if policy.require_exact_mode && meta.mode != required_mode {
        return PathCheck::WrongMode;
    }
    if policy.reject_link_count_anomaly && meta.hard_link_count > 1 {
        return PathCheck::LinkCountAnomaly;
    }
    PathCheck::Contained
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn contained_paths_are_accepted() {
        let root = Path::new("/home/user/.local/share/com.hushvoting.client/vault/v1");
        assert_eq!(
            containment_of(root, &root.join("slot-a.hvlt")),
            Containment::Contained
        );
    }

    #[test]
    fn traversal_paths_are_rejected() {
        let root = Path::new("/home/user/.local/share/com.hushvoting.client/vault/v1");
        let evil = root.join("../../other");
        assert_eq!(containment_of(root, &evil), Containment::Escapes);
    }

    #[test]
    fn outside_paths_are_rejected() {
        let root = Path::new("/home/user/app/vault/v1");
        let outside = Path::new("/tmp/escape");
        assert_eq!(containment_of(root, outside), Containment::Escapes);
    }

    #[test]
    fn root_itself_is_distinguished() {
        let root = Path::new("/home/user/app/vault/v1");
        assert_eq!(containment_of(root, root), Containment::RootItself);
    }

    #[test]
    fn policy_defaults_reject_all_unsafe_shapes() {
        let p = VaultPathPolicy::default();
        assert!(p.reject_escapes && p.reject_symlinks && p.require_regular_file);
        assert!(p.require_current_uid_owner && p.require_exact_mode);
        assert!(p.reject_link_count_anomaly && p.reject_caller_supplied_paths);
    }

    fn ok_meta() -> FileMetadata {
        FileMetadata {
            is_regular_file: true,
            is_symlink: false,
            owner_is_current_uid: true,
            mode: 0o600,
            hard_link_count: 1,
        }
    }

    #[test]
    fn clean_artifact_passes_all_checks() {
        let p = VaultPathPolicy::default();
        assert_eq!(
            classify_path(&p, Containment::Contained, ok_meta(), 0o600),
            PathCheck::Contained
        );
    }

    #[test]
    fn symlink_is_rejected() {
        let p = VaultPathPolicy::default();
        let meta = FileMetadata {
            is_symlink: true,
            ..ok_meta()
        };
        assert_eq!(
            classify_path(&p, Containment::Contained, meta, 0o600),
            PathCheck::SymbolicLink
        );
    }

    #[test]
    fn wrong_owner_is_rejected() {
        let p = VaultPathPolicy::default();
        let meta = FileMetadata {
            owner_is_current_uid: false,
            ..ok_meta()
        };
        assert_eq!(
            classify_path(&p, Containment::Contained, meta, 0o600),
            PathCheck::WrongOwner
        );
    }

    #[test]
    fn wrong_mode_is_rejected() {
        let p = VaultPathPolicy::default();
        let meta = FileMetadata {
            mode: 0o644,
            ..ok_meta()
        };
        assert_eq!(
            classify_path(&p, Containment::Contained, meta, 0o600),
            PathCheck::WrongMode
        );
    }

    #[test]
    fn hard_link_anomaly_is_rejected() {
        let p = VaultPathPolicy::default();
        let meta = FileMetadata {
            hard_link_count: 2,
            ..ok_meta()
        };
        assert_eq!(
            classify_path(&p, Containment::Contained, meta, 0o600),
            PathCheck::LinkCountAnomaly
        );
    }

    #[test]
    fn non_regular_file_is_rejected() {
        let p = VaultPathPolicy::default();
        let meta = FileMetadata {
            is_regular_file: false,
            ..ok_meta()
        };
        assert_eq!(
            classify_path(&p, Containment::Contained, meta, 0o600),
            PathCheck::WrongType
        );
    }

    #[test]
    fn escaped_path_is_rejected_before_access() {
        let p = VaultPathPolicy::default();
        assert_eq!(
            classify_path(&p, Containment::Escapes, ok_meta(), 0o600),
            PathCheck::EscapesRoot
        );
    }

    #[test]
    fn root_directory_checks_owner_and_mode() {
        let p = VaultPathPolicy::default();
        let good_dir = FileMetadata {
            is_regular_file: false,
            mode: 0o700,
            ..ok_meta()
        };
        assert_eq!(
            classify_path(&p, Containment::RootItself, good_dir, 0o700),
            PathCheck::Contained
        );
        let bad_owner = FileMetadata {
            owner_is_current_uid: false,
            mode: 0o700,
            ..ok_meta()
        };
        assert_eq!(
            classify_path(&p, Containment::RootItself, bad_owner, 0o700),
            PathCheck::WrongOwner
        );
        let bad_mode = FileMetadata {
            is_regular_file: false,
            mode: 0o755,
            ..ok_meta()
        };
        assert_eq!(
            classify_path(&p, Containment::RootItself, bad_mode, 0o700),
            PathCheck::WrongMode
        );
    }
}
