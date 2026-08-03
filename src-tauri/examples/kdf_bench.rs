//! FEAT-005 KDF performance benchmark (Phase 7, Task 7.5).
//!
//! Measures the FEAT-003 suite-v1 Argon2id derivation (19 MiB, 2 iterations,
//! parallelism 1) on THIS machine and prints a sanitized report: machine CPU
//! model, median/p95 of repeated runs, and the hard-gate verdict
//! (KDF_HARD_TIMEOUT_MS = 1500 ms resource limit; the 500–1000 ms target is
//! a calibration target, not a hard gate). Human OS-prompt time is excluded
//! by construction (no provider interaction here).
//!
//! Run: `cargo run --release --example kdf_bench --manifest-path src-tauri/Cargo.toml`
//!
//! Output is a digest-only evidence line consumed by the qualification
//! harness; no secret material is involved (fixed synthetic password/salt).

use std::time::Instant;

use hush_voting_app_lib::ubuntu_vault::crypto::argon2id_derive;
use hush_voting_app_lib::ubuntu_vault::crypto::{
    KDF_HARD_TIMEOUT_MS, KDF_ITERATIONS, KDF_MIN_MEMORY_KIB, KDF_OUTPUT_BYTES, KDF_PARALLELISM,
};

fn main() {
    let password = b"benchmark-password-synthetic";
    let salt = [0x5au8; 16];

    // Warm-up (page faults / allocator warm cache).
    let _ = argon2id_derive(
        password,
        &salt,
        KDF_MIN_MEMORY_KIB,
        KDF_ITERATIONS,
        KDF_PARALLELISM,
        KDF_OUTPUT_BYTES,
    )
    .expect("warmup");

    let mut samples = Vec::with_capacity(11);
    for _ in 0..11 {
        let started = Instant::now();
        let out = argon2id_derive(
            password,
            &salt,
            KDF_MIN_MEMORY_KIB,
            KDF_ITERATIONS,
            KDF_PARALLELISM,
            KDF_OUTPUT_BYTES,
        )
        .expect("derive");
        samples.push(started.elapsed().as_millis() as u64);
        assert_eq!(out.len(), KDF_OUTPUT_BYTES);
    }
    samples.sort_unstable();

    let median = samples[samples.len() / 2];
    let p95 = samples[(samples.len() as f64 * 0.95) as usize];
    let machine = machine_name();
    let pass = median < KDF_HARD_TIMEOUT_MS && p95 < KDF_HARD_TIMEOUT_MS;

    // Digest-only evidence line (no secrets; coarse machine class only).
    println!(
        "KDF_BENCH machine={} samples={} medianMs={} p95Ms={} hardLimitMs={} pass={}",
        machine,
        samples.len(),
        median,
        p95,
        KDF_HARD_TIMEOUT_MS,
        pass
    );
    std::process::exit(if pass { 0 } else { 1 });
}

/// Coarse machine class for the report (never exact hardware serials).
fn machine_name() -> String {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let model = cpuinfo
        .lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split(':').nth(1))
        .unwrap_or("unknown")
        .trim()
        .to_string();
    let cores = cpuinfo
        .lines()
        .filter(|l| l.starts_with("processor"))
        .count();
    format!("{model} ({cores} cores)")
}
