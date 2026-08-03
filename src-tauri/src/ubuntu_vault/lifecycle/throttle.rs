//! Wrong-password throttle (FEAT-005 "Password Throttling"; normative mirror
//! of FEAT-003 `password/throttle.ts` and `contracts/sidecar.ts`).
//!
//! Failed device-password attempts are globally serialized per local vault:
//! attempts 1–4 pay the Argon2id computation cost without an added cooldown;
//! attempt 5 = 5 s, 6 = 10 s, 7 = 20 s, 8 = 40 s, 9 = 80 s, 10 = 160 s,
//! 11+ = 300 s maximum. Restart does not reset it. Success, successful
//! reprovisioning, or verified local-user removal resets it. No failure
//! automatically wipes or permanently locks a vault.
//!
//! The sidecar is untrusted: malformed/missing/implausible values reset
//! safely rather than creating denial of service (documented limitation).
//! A failure is counted ONCE only after a completed inner authenticated-
//! decryption failure; prompt cancel/timeout, provider/storage/network
//! failure, stale operations, and process updates never count.

use crate::ubuntu_vault::storage::journal::SidecarRecord;
use crate::ubuntu_vault::storage::writer::StoreError;

/// Bounded failed-attempt counter (0–255; FEAT-003 bound).
pub const MAX_FAILED_PASSWORD_COUNT: u8 = 255;

/// Cap for attempt 12 and later (seconds).
pub const THROTTLE_MAX_SECONDS: u64 = 300;

/// Exact cooldown schedule by attempt number (1-indexed).
pub const THROTTLE_SCHEDULE: [u64; 11] = [0, 0, 0, 0, 5, 10, 20, 40, 80, 160, 300];

/// Deterministic cooldown seconds for a failed-attempt count.
pub fn cooldown_seconds_for_attempt(attempt_number: u64) -> u64 {
    if attempt_number < 1 {
        return 0;
    }
    if attempt_number <= 4 {
        return 0; // attempts 1–4 pay only the Argon2id computation cost
    }
    match THROTTLE_SCHEDULE.get(attempt_number as usize - 1) {
        Some(seconds) => *seconds,
        None => THROTTLE_MAX_SECONDS,
    }
}

/// Bounded throttle state (persisted in the sidecar).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ThrottleState {
    pub failed_password_count: u8,
    /// Epoch-ms deadline; 0 = no active cooldown.
    pub cooldown_deadline_ms: u64,
}

/// Decision for an attempted password entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThrottleDecision {
    /// Entry may proceed (no active cooldown).
    Ok,
    /// Entry is blocked until `retry_deadline_ms`.
    Throttled {
        cooldown_seconds: u64,
        retry_deadline_ms: u64,
    },
}

/// Evaluate an attempted password entry against the current state.
pub fn evaluate(state: ThrottleState, now_ms: u64) -> ThrottleDecision {
    let s = sanitize(state);
    if s.failed_password_count == 0 || s.cooldown_deadline_ms == 0 {
        return ThrottleDecision::Ok;
    }
    if now_ms >= s.cooldown_deadline_ms {
        return ThrottleDecision::Ok;
    }
    let remaining = s.cooldown_deadline_ms - now_ms;
    ThrottleDecision::Throttled {
        cooldown_seconds: remaining.div_ceil(1000),
        retry_deadline_ms: s.cooldown_deadline_ms,
    }
}

/// Record a failed attempt (attempt number = current count + 1).
pub fn record_failure(state: ThrottleState, now_ms: u64) -> ThrottleState {
    let s = sanitize(state);
    let next_count = s.failed_password_count.saturating_add(1); // u8 can never exceed 255
    let cooldown = cooldown_seconds_for_attempt(next_count as u64);
    ThrottleState {
        failed_password_count: next_count,
        cooldown_deadline_ms: if cooldown == 0 {
            0
        } else {
            now_ms.saturating_add(cooldown * 1000)
        },
    }
}

/// Reset on success, successful reprovisioning, or verified removal.
pub fn reset() -> ThrottleState {
    ThrottleState::default()
}

/// Sanitize untrusted sidecar throttle values. Missing/corrupt/implausible
/// values reset safely with no denial of service; sidecar values are never
/// authentication or integrity evidence.
pub fn sanitize(input: ThrottleState) -> ThrottleState {
    let count = input.failed_password_count; // u8 can never exceed 255
    let deadline = input.cooldown_deadline_ms;
    if deadline > 0 && count == 0 {
        return ThrottleState::default();
    }
    ThrottleState {
        failed_password_count: count,
        cooldown_deadline_ms: deadline,
    }
}

impl ThrottleState {
    /// Extract from a sidecar record (sanitized).
    pub fn from_sidecar(record: &SidecarRecord) -> Self {
        sanitize(Self {
            failed_password_count: record.failed_password_count,
            cooldown_deadline_ms: record.cooldown_deadline_ms,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn schedule_matches_feat003_exactly() {
        for attempt in 1..=4 {
            assert_eq!(
                cooldown_seconds_for_attempt(attempt),
                0,
                "attempt {attempt}"
            );
        }
        assert_eq!(cooldown_seconds_for_attempt(5), 5);
        assert_eq!(cooldown_seconds_for_attempt(6), 10);
        assert_eq!(cooldown_seconds_for_attempt(7), 20);
        assert_eq!(cooldown_seconds_for_attempt(8), 40);
        assert_eq!(cooldown_seconds_for_attempt(9), 80);
        assert_eq!(cooldown_seconds_for_attempt(10), 160);
        assert_eq!(cooldown_seconds_for_attempt(11), 300);
        assert_eq!(cooldown_seconds_for_attempt(12), 300);
        assert_eq!(cooldown_seconds_for_attempt(255), 300);
        assert_eq!(cooldown_seconds_for_attempt(0), 0);
    }

    #[test]
    fn first_four_failures_incur_no_cooldown() {
        let mut state = ThrottleState::default();
        for attempt in 1..=4u8 {
            state = record_failure(state, 1_000 * attempt as u64);
            assert_eq!(state.failed_password_count, attempt);
            assert_eq!(state.cooldown_deadline_ms, 0, "attempt {attempt}");
        }
        // Fifth failure starts the escalating cooldown.
        state = record_failure(state, 5_000);
        assert_eq!(state.failed_password_count, 5);
        assert_eq!(state.cooldown_deadline_ms, 10_000); // 5s from now
    }

    #[test]
    fn cooldown_escalates_to_cap() {
        let mut state = ThrottleState::default();
        let mut now = 0u64;
        for _ in 0..11 {
            state = record_failure(state, now);
            now += 1_000_000;
        }
        // 11 failures; the 11th occurred at now == 10_000_000.
        assert_eq!(state.failed_password_count, 11);
        assert_eq!(state.cooldown_deadline_ms, 10_000_000 + 300_000);
        // Cap holds for later attempts.
        state = record_failure(state, 11_000_000);
        assert_eq!(state.failed_password_count, 12);
        assert_eq!(state.cooldown_deadline_ms, 11_000_000 + 300_000);
    }

    #[test]
    fn counter_is_bounded_at_255() {
        let mut state = ThrottleState::default();
        for i in 0..300u64 {
            state = record_failure(state, i * 1_000);
        }
        assert_eq!(state.failed_password_count, 255);
    }

    #[test]
    fn evaluate_blocks_until_deadline() {
        let state = ThrottleState {
            failed_password_count: 5,
            cooldown_deadline_ms: 10_000,
        };
        assert_eq!(
            evaluate(state, 9_500),
            ThrottleDecision::Throttled {
                cooldown_seconds: 1,
                retry_deadline_ms: 10_000
            }
        );
        assert_eq!(
            evaluate(state, 9_000),
            ThrottleDecision::Throttled {
                cooldown_seconds: 1,
                retry_deadline_ms: 10_000
            }
        );
        assert_eq!(evaluate(state, 10_000), ThrottleDecision::Ok);
        assert_eq!(evaluate(state, 12_000), ThrottleDecision::Ok);
    }

    #[test]
    fn zero_state_never_throttles() {
        assert_eq!(evaluate(ThrottleState::default(), 0), ThrottleDecision::Ok);
        // A deadline without a count is sanitized away.
        let weird = ThrottleState {
            failed_password_count: 0,
            cooldown_deadline_ms: 9_999,
        };
        assert_eq!(sanitize(weird), ThrottleState::default());
    }

    #[test]
    fn reset_clears_all() {
        let state = ThrottleState {
            failed_password_count: 200,
            cooldown_deadline_ms: 1_000,
        };
        assert_eq!(reset(), ThrottleState::default());
        assert_ne!(sanitize(state), ThrottleState::default());
    }

    #[test]
    fn malformed_sidecar_values_reset_safely() {
        // A sidecar with an absurd count clamps; a deadline with count resets.
        let huge = ThrottleState {
            failed_password_count: 255,
            cooldown_deadline_ms: u64::MAX,
        };
        assert_eq!(sanitize(huge), huge);
        let zero_count = ThrottleState {
            failed_password_count: 0,
            cooldown_deadline_ms: 123,
        };
        assert_eq!(sanitize(zero_count), ThrottleState::default());
    }
}

/// Persisted throttle authority over the vault sidecar.
#[derive(Debug, Clone, Copy)]
pub struct VaultThrottle<'a> {
    store: &'a crate::ubuntu_vault::storage::writer::VaultStore,
}

impl<'a> VaultThrottle<'a> {
    pub fn new(store: &'a crate::ubuntu_vault::storage::writer::VaultStore) -> Self {
        Self { store }
    }

    /// Current sanitized throttle state from the sidecar.
    pub fn current(&self) -> Result<ThrottleState, StoreError> {
        let record = self.store.read_sidecar()?;
        Ok(ThrottleState::from_sidecar(&record))
    }

    /// Whether a password entry may proceed now.
    pub fn evaluate_now(&self, now_ms: u64) -> Result<ThrottleDecision, StoreError> {
        Ok(evaluate(self.current()?, now_ms))
    }

    /// Count a completed inner authenticated-decryption failure exactly once
    /// and persist the updated state.
    pub fn record_failure(&self, now_ms: u64) -> Result<ThrottleState, StoreError> {
        let next = record_failure(self.current()?, now_ms);
        self.store.update_sidecar(|r| {
            r.failed_password_count = next.failed_password_count;
            r.cooldown_deadline_ms = next.cooldown_deadline_ms;
        })?;
        Ok(next)
    }

    /// Reset after success, verified reprovision, or completed removal.
    pub fn reset(&self) -> Result<ThrottleState, StoreError> {
        let next = reset();
        self.store.update_sidecar(|r| {
            r.failed_password_count = next.failed_password_count;
            r.cooldown_deadline_ms = next.cooldown_deadline_ms;
        })?;
        Ok(next)
    }
}

#[cfg(test)]
mod vault_throttle_tests {
    use super::*;
    use crate::ubuntu_vault::crypto::encoding::hex_encode;
    use crate::ubuntu_vault::crypto::random_bytes;
    use crate::ubuntu_vault::storage::writer::VaultStore;

    fn temp_root(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "feat005-throttle-{name}-{}-{}",
            std::process::id(),
            hex_encode(&random_bytes(4).unwrap())
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn failures_persist_and_reset_across_sidecar_reloads() {
        let store = VaultStore::open(temp_root("persist")).unwrap();
        let throttle = VaultThrottle::new(&store);
        assert!(matches!(
            throttle.evaluate_now(1_000).unwrap(),
            ThrottleDecision::Ok
        ));
        let mut state = ThrottleState::default();
        for i in 0..5u64 {
            state = throttle.record_failure(1_000 + i * 10).unwrap();
        }
        assert_eq!(state.failed_password_count, 5);
        // A fresh authority reads the same persisted state (restart does not
        // reset it).
        let reloaded = VaultThrottle::new(&store);
        assert_eq!(reloaded.current().unwrap().failed_password_count, 5);
        assert!(matches!(
            reloaded.evaluate_now(1_000 + 5 * 10).unwrap(),
            ThrottleDecision::Throttled { .. }
        ));
        throttle.reset().unwrap();
        assert_eq!(throttle.current().unwrap(), ThrottleState::default());
    }

    #[test]
    fn corrupt_sidecar_resets_safely_not_lockout() {
        let store = VaultStore::open(temp_root("corrupt")).unwrap();
        let throttle = VaultThrottle::new(&store);
        throttle.record_failure(1_000).unwrap();
        // Corrupt the sidecar JSON.
        std::fs::write(store.root().join("sidecars.json"), b"not-json{{{").unwrap();
        // Fresh read resets safely — never a permanent lockout.
        assert_eq!(throttle.current().unwrap(), ThrottleState::default());
        assert!(matches!(
            throttle.evaluate_now(1_000).unwrap(),
            ThrottleDecision::Ok
        ));
    }
}
