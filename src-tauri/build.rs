//! FEAT-005 build script: verifies the digest-pinned HushServerNode protocol
//! artifacts and generates the tonic/prost gRPC client from them.
//!
//! Rules enforced here:
//! - The two `.proto` sources MUST match the pinned SHA-256 digests exactly.
//!   An edited/replaced file fails the build (the "no editable copied proto
//!   set" rule is enforced by this gate).
//! - Codegen emits a `file_descriptor_set` so release builds can verify the
//!   exact protocol digest at runtime.
//! - Only the identity/blockchain protocol artifacts participate; no other
//!   server proto is generated or referenced.

use std::path::Path;

const HUSH_IDENTITY_PROTO: &str = "../conformance/protocol/hushIdentity.proto";
const HUSH_BLOCKCHAIN_PROTO: &str = "../conformance/protocol/hushBlockchain.proto";

/// Pinned SHA-256 digests (HushServerNode rev
/// `fb789bd1c2b353387183300a370de2960bc71795`).
const HUSH_IDENTITY_SHA256: &str =
    "df3a2d9b128335dc3c92f0ef2b246655ed4c95f53f7ce058d438d945724f8ffa";
const HUSH_BLOCKCHAIN_SHA256: &str =
    "e0625d52e4227ed77b6eb0e7d74b2990b7a8d3e8ecd77bd308371797275dc04b";

fn sha256_hex(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    let bytes = std::fs::read(path).expect("protocol artifact readable");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn verify_pinned(relative: &str, expected: &str) {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let path = manifest.join(relative);
    let actual = sha256_hex(&path);
    assert_eq!(
        actual, expected,
        "protocol artifact digest mismatch for {relative} (pinned {expected}, found {actual}); \
         the HushServerNode protocol source is immutable — update only via a reviewed \
         compatibility migration and the conformance/protocol provenance record"
    );
}

fn main() {
    println!("cargo:rerun-if-changed=../conformance/protocol/hushIdentity.proto");
    println!("cargo:rerun-if-changed=../conformance/protocol/hushBlockchain.proto");
    println!("cargo:rerun-if-changed=build.rs");

    verify_pinned(HUSH_IDENTITY_PROTO, HUSH_IDENTITY_SHA256);
    verify_pinned(HUSH_BLOCKCHAIN_PROTO, HUSH_BLOCKCHAIN_SHA256);

    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let include_dir = manifest.join("../conformance/protocol");
    let descriptor_path = Path::new(&std::env::var("OUT_DIR").unwrap()).join("protocol.bin");
    tonic_build::configure()
        .file_descriptor_set_path(&descriptor_path)
        // Relative proto paths keep the descriptor's file names stable across
        // machines (absolute paths would change the digest per checkout).
        .compile_protos(
            &["hushIdentity.proto", "hushBlockchain.proto"],
            &[include_dir],
        )
        .expect("tonic-build codegen failed for the pinned protocol artifacts");

    // Tauri composition (config embedding, capabilities, desktop/mobile cfgs).
    tauri_build::build()
}
