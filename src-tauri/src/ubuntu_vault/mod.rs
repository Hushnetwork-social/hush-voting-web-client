//! HushVoting Ubuntu vault adapter — native module root.
//!
//! FEAT-005: the normal Tauri Rust backend is the native credential boundary.
//! This module is layered so that Phases 2 (contracts/storage model), 3
//! (Secret Service/crypto/atomic lifecycle), 4 (session/command/transport),
//! and 6 (composition) land in stable submodules.
//!
//! Security invariants (enforced across the module):
//! - No raw D-Bus error, object path, item attribute/value, filesystem path,
//!   UID/username, identity, or secret detail crosses the adapter boundary.
//! - No generic signer/decryptor/private-key/filesystem operation exists.
//! - No browser-vault persistence, bundled provider, daemon, or helper process.

pub mod contracts;
pub mod crypto;
pub mod item_model;
pub mod lifecycle;
pub mod secret_service;
pub mod storage;

/// Fixed production application identity shared by `.deb` and AppImage.
pub const APPLICATION_ID: &str = "com.hushvoting.client";

/// Fixed adapter identifier (authored into wrapper metadata).
pub const ADAPTER_ID: &str = "ubuntu-secret-service-v1";

/// Fixed secret-item label used in the default/login collection.
pub const ITEM_LABEL: &str = "HushVoting! Device Vault";

/// Fixed record purpose for the wrapping item.
pub const ITEM_PURPOSE: &str = "vault-wrapper";

/// Wrapper format version start (integer version identifier).
pub const WRAPPER_FORMAT_VERSION: u32 = 1;

/// Bounded startup preflight probe (non-prompting), seconds.
pub const STARTUP_PROBE_BOUND_SECS: u64 = 5;

/// Bounded OS provider prompt, seconds.
pub const PROMPT_BOUND_SECS: u64 = 60;

/// Bounded online identity verification, seconds (FEAT-002 contract).
pub const ONLINE_VERIFY_BOUND_SECS: u64 = 10;

/// Bounded KDF cleanup acknowledgement, seconds (FEAT-003 hard limit).
pub const CLEANUP_ACK_BOUND_SECS: u64 = 1;
