//! HushVoting Android vault adapter — native module root.
//!
//! FEAT-006: the normal Tauri Rust backend is the native credential boundary
//! for Android. This module is layered so that Phase 2 (contracts, wrapper,
//! storage model, evidence schemas), Phase 3 (Keystore capability/key policy,
//! Rust/Kotlin wrapper integration, crash-safe lifecycle), Phase 4 (Rust-internal
//! mobile bridge, native session, lifecycle/timing/Back authority, shielding/
//! clipboard/SAF), and Phase 6 (composition, packaging, handoff) land in stable
//! submodules.
//!
//! Security invariants (enforced across the module):
//! - No raw Android exception, key alias, path/URI, identity, ciphertext, or
//!   secret detail crosses any boundary.
//! - No generic signer/decryptor/private-key/export/path/URI/filesystem
//!   operation exists; the bridge is Rust-internal only, never a WebView
//!   capability.
//! - No software-backed Keystore, password-only native storage, IndexedDB,
//!   SharedPreferences, Room, WebView credential storage, or silent
//!   StrongBox-to-TEE fallback is permitted in production.
//! - Fixed no-backup storage only; caller-controlled paths never exist.

pub mod bridge;
pub mod contracts;
pub mod crypto;
pub mod evidence;
pub mod keystore;
pub mod lifecycle;
pub mod navigation;
pub mod platform_controls;
pub mod session;
pub mod storage;
pub mod wrapper;

/// Fixed production application identity (mirrors tauri.conf identifier).
pub const APPLICATION_ID: &str = "com.hushvoting.client";

/// Fixed adapter identifier (authored into Android wrapper metadata).
pub const ADAPTER_ID: &str = "android-keystore";

/// Android wrapper format version start (integer version identifier).
pub const WRAPPER_FORMAT_VERSION: u32 = 1;

/// Independent platform wrapper version (versioned separately from FEAT-003).
pub const PLATFORM_WRAPPER_VERSION: &str = "1";

/// Rust<->Kotlin mobile-plugin protocol version (enforced by both sides).
pub const MOBILE_PLUGIN_PROTOCOL_MAJOR: u32 = 1;
pub const MOBILE_PLUGIN_PROTOCOL_MINOR: u32 = 0;

/// FEAT-003 inner envelope maximum (unchanged across platforms).
pub const INNER_ENVELOPE_MAX_BYTES: usize = 1024 * 1024; // 1 MiB

/// Complete Android wrapper (base64-bearing) maximum.
pub const WRAPPER_MAX_BYTES: usize = 1536 * 1024; // 1.5 MiB

/// Fixed record purpose for the Android-wrapped vault package.
pub const RECORD_PURPOSE: &str = "vault-package";

/// Fixed relative vault root under `<noBackupFilesDir>` (never a caller path).
pub const VAULT_ROOT_RELATIVE: &str = "vault/v1";

/// Fixed slot file names (identity-neutral; no alias/address-derived names).
pub const SLOT_A_FILE: &str = "slot-a.hvlt";
pub const SLOT_B_FILE: &str = "slot-b.hvlt";
pub const JOURNAL_FILE: &str = "journal.json";
pub const SIDECARS_FILE: &str = "sidecars.json";
pub const TOMBSTONE_FILE: &str = "removal.tombstone";
pub const LOCK_FILE: &str = "vault.lock";

/// Maximum authenticated string field length (bounded allocation).
pub const MAX_FIELD_LEN: usize = 64;

/// Maximum number of critical extension entries (bounded allocation).
pub const MAX_CRITICAL_EXTENSIONS: usize = 8;
