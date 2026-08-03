//! Secret Service provider access and wrapping-key lifecycle (FEAT-005
//! Phase 3, Task 3.1).
//!
//! FEAT-005 uses the user's **existing** freedesktop Secret Service provider
//! (normally GNOME Keyring) through an exact-pinned `oo7` 0.3.3 explicit D-Bus
//! client. Rules enforced here:
//!
//! - Only `oo7::dbus::Service::encrypted()` is used in production — an
//!   encrypted session with **no** plain-session fallback, no automatic
//!   backend selection, no file/portal backend, no shell-out, and no C
//!   `libsecret` binding.
//! - The default/login collection is used; HushVoting never creates a
//!   separately passworded collection, never starts a provider, never locks
//!   the shared collection, and never reconfigures it.
//! - Wrapping keys are random 256-bit values held in zeroizing containers,
//!   retrieved only for a bounded wrap/unwrap operation and cleared
//!   immediately afterward. Never cached in app files, never returned to the
//!   WebView, never retained for the whole session.
//! - Item attributes are identity-free (no alias, username/UID, address,
//!   profile ID, mnemonic status, endpoint, network, or vault generation) and
//!   release channels never collide.
//! - No raw D-Bus error, object path, item attribute/value, or provider detail
//!   ever crosses the adapter boundary: every observation maps to the closed
//!   `ProviderFailure` vocabulary and the closed availability states.
//!
//! D-Bus interaction is isolated behind thin async glue (`backend`), while
//! every classification/decision rule is a pure synchronous function
//! (`state`, `rotation`) that unit tests can exhaustively exercise without a
//! session bus. Real-provider integration runs only in Phase 7's isolated
//! synthetic desktop account harness — never against a developer's keyring.

pub mod backend;
pub mod rotation;
pub mod state;

pub use backend::{map_oo7_error, ItemAttributes, Oo7Backend, StoredItem, STAGED_ITEM_PURPOSE};
pub use state::{ProbeDecisions, ProbeOutcome};

use crate::ubuntu_vault::contracts::results::NativeErrorCode;

/// Closed provider failure vocabulary. Every expected oo7/D-Bus condition maps
/// to exactly one variant; raw detail (paths, item values, provider names)
/// never appears here and never crosses the boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFailure {
    /// Confirmed absence: the Secret Service name is not owned by any
    /// provider, or no usable default collection exists. The ONLY
    /// fallback-eligible condition, and only after OS setup/Retry guidance.
    Absent,
    /// The default/login collection exists but is locked.
    Locked,
    /// The OS prompt was dismissed by the user (or the UI cancelled it).
    PromptCancelled,
    /// The OS prompt exceeded the 60-second bound (or the probe exceeded its
    /// 5-second bound without answering).
    PromptTimedOut,
    /// Provider present but temporarily unavailable (D-Bus restart, transient
    /// wire failure). Never fallback; never throttle.
    TemporarilyUnavailable,
    /// A provider exists but has not passed qualification. Blocks persistent
    /// production provisioning; never fallback.
    Unqualified,
    /// The wrapping item set is ambiguous (zero or multiple distinct
    /// validating keys) or unsupported — preserve all artifacts, require
    /// portable recovery.
    AmbiguousItems,
    /// Expected wrapping item is missing while vault files exist, or the
    /// provider/account changed. `PlatformProtectionInvalidated` recovery.
    Invalidated,
    /// The item/collection was deleted mid-operation (concurrent removal).
    Deleted,
    /// Filesystem-level I/O failure surfaced by the D-Bus stack.
    Io,
    /// Defensive fallback for an unrecognized condition. Never carries raw
    /// detail; always maps to a safe closed recovery.
    Internal,
}

impl ProviderFailure {
    /// Safe recovery action set in the closed native vocabulary.
    pub fn to_native_error(self) -> NativeErrorCode {
        match self {
            Self::Absent => NativeErrorCode::ProviderAbsent,
            Self::Locked => NativeErrorCode::ProviderLocked,
            Self::PromptCancelled => NativeErrorCode::PromptCancelled,
            Self::PromptTimedOut => NativeErrorCode::PromptTimedOut,
            Self::TemporarilyUnavailable => NativeErrorCode::ProviderTemporarilyUnavailable,
            Self::Unqualified => NativeErrorCode::UnqualifiedProvider,
            Self::AmbiguousItems => NativeErrorCode::WrapperAmbiguous,
            Self::Invalidated => NativeErrorCode::PlatformProtectionInvalidated,
            Self::Deleted => NativeErrorCode::CleanupFailed,
            Self::Io => NativeErrorCode::StorageUnavailable,
            Self::Internal => NativeErrorCode::PlatformProtectionUnavailable,
        }
    }

    /// Whether this failure ever permits password-only fallback.
    pub fn is_fallback_eligible(self) -> bool {
        matches!(self, Self::Absent)
    }

    /// Whether this failure ever increments device-password throttling.
    pub fn increments_throttle(self) -> bool {
        false
    }

    /// Whether a replacement wrapping key may ever be generated from this
    /// failure. Never: no guessed/regenerated key replaces a missing,
    /// ambiguous, or invalidated one.
    pub fn permits_key_generation(self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_failure_maps_to_a_closed_native_error() {
        for failure in [
            ProviderFailure::Absent,
            ProviderFailure::Locked,
            ProviderFailure::PromptCancelled,
            ProviderFailure::PromptTimedOut,
            ProviderFailure::TemporarilyUnavailable,
            ProviderFailure::Unqualified,
            ProviderFailure::AmbiguousItems,
            ProviderFailure::Invalidated,
            ProviderFailure::Deleted,
            ProviderFailure::Io,
            ProviderFailure::Internal,
        ] {
            let code = failure.to_native_error();
            // Closed vocabulary: mapping exists and is non-raw by construction.
            assert_ne!(code, NativeErrorCode::OperationForbidden);
        }
    }

    #[test]
    fn only_confirmed_absence_is_fallback_eligible() {
        for failure in [
            ProviderFailure::Absent,
            ProviderFailure::Locked,
            ProviderFailure::PromptCancelled,
            ProviderFailure::PromptTimedOut,
            ProviderFailure::TemporarilyUnavailable,
            ProviderFailure::Unqualified,
            ProviderFailure::AmbiguousItems,
            ProviderFailure::Invalidated,
            ProviderFailure::Deleted,
            ProviderFailure::Io,
            ProviderFailure::Internal,
        ] {
            assert_eq!(
                failure.is_fallback_eligible(),
                failure == ProviderFailure::Absent,
                "{failure:?}"
            );
            assert!(!failure.increments_throttle(), "{failure:?}");
            assert!(!failure.permits_key_generation(), "{failure:?}");
        }
    }

    #[test]
    fn invalidated_maps_to_platform_protection_invalidated() {
        assert_eq!(
            ProviderFailure::Invalidated.to_native_error(),
            NativeErrorCode::PlatformProtectionInvalidated
        );
        assert_eq!(
            ProviderFailure::AmbiguousItems.to_native_error(),
            NativeErrorCode::WrapperAmbiguous
        );
    }
}
