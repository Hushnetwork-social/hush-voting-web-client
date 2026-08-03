//! Native lifecycle authority (FEAT-005 "Lifecycle and Lock",
//! "Memory and crash hardening").
//!
//! Aggregates native signals into conservative lock decisions: explicit Lock,
//! window focus/minimize/all-hidden (FEAT-003 background timing), Ubuntu
//! session lock and suspend/resume, process exit/crash/restart, native-
//! boundary/keyring invalidation, and clock anomalies. Monotonic time is used
//! while running; backward/implausible/uncertain wall-clock evidence after
//! resume means Locked. Trusted activity only resets allowed idle timers.

use std::time::Duration;

/// FEAT-003 Lock contract: cleanup acknowledgement budget (seconds).
pub const LOCK_CLEANUP_BUDGET_SECS: u64 = 1;

/// Native signal aggregated into a lock decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LifecycleSignal {
    /// Explicit user Lock.
    ExplicitLock,
    /// Ubuntu session lock (e.g. GNOME lock screen).
    OsLock,
    /// Suspend/hibernate began.
    Suspend,
    /// Resume from suspend — evidence (monotonic vs wall) decides.
    Resume,
    /// Main window lost focus.
    FocusLost,
    /// All windows hidden/minimized.
    AllWindowsHidden,
    /// Process exit / crash / single-instance ownership loss.
    ProcessExit,
    /// Native boundary or keyring provider invalidation.
    ProviderInvalidated,
    /// Wall-clock evidence is backward or implausible.
    ClockAnomaly,
}

/// FEAT-003 background timing policy: how long protected content may stay
/// visible without foreground activity. Conservative defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockPolicy {
    /// Idle timeout for backgrounded windows (focus loss/all-hidden).
    pub background_idle_ms: Option<u64>,
}

impl Default for LockPolicy {
    fn default() -> Self {
        // Conservative: no background-unlocked mode in FEAT-005. Focus loss
        // without trusted activity within 60 s locks.
        Self {
            background_idle_ms: Some(60_000),
        }
    }
}

/// Whether the signal requires an IMMEDIATE global lock (never waits for the
/// background idle policy).
pub fn requires_immediate_lock(signal: LifecycleSignal) -> bool {
    matches!(
        signal,
        LifecycleSignal::ExplicitLock
            | LifecycleSignal::OsLock
            | LifecycleSignal::Suspend
            | LifecycleSignal::Resume
            | LifecycleSignal::ProcessExit
            | LifecycleSignal::ProviderInvalidated
            | LifecycleSignal::ClockAnomaly
    )
}

/// Whether the signal enters the background idle timer (focus/all-hidden).
pub fn enters_background_timing(signal: LifecycleSignal) -> bool {
    matches!(
        signal,
        LifecycleSignal::FocusLost | LifecycleSignal::AllWindowsHidden
    )
}

/// Background idle decision: lock when the elapsed idle time exceeds the
/// policy budget (None budget = lock immediately; no tray-unlocked mode).
pub fn background_idle_should_lock(policy: &LockPolicy, idle_ms: u64) -> bool {
    match policy.background_idle_ms {
        Some(budget) => idle_ms >= budget,
        None => true,
    }
}

/// Clock-anomaly detection after resume: monotonic elapsed and wall-clock
/// elapsed must agree within a conservative bound. Backward or implausible
/// wall-clock evidence means Locked.
///
/// - `monotonic_elapsed`: `Instant` delta while the process ran.
/// - `wall_elapsed`: wall-clock delta across the suspend/resume.
pub fn clock_anomaly(monotonic_elapsed: Duration, wall_elapsed: Duration) -> bool {
    // Wall clock ran backward: definite anomaly.
    if wall_elapsed.is_zero() && !monotonic_elapsed.is_zero() {
        return true;
    }
    // Wall clock substantially shorter than monotonic (clock adjusted
    // backward) or vastly longer (suspend with unknown drift) → conservative
    // lock. A 10% tolerance absorbs scheduling noise.
    let monotonic_ms = monotonic_elapsed.as_millis().max(1);
    let wall_ms = wall_elapsed.as_millis();
    if wall_ms < monotonic_ms.saturating_mul(9) / 10 {
        return true;
    }
    // A resume after a long suspend is itself a lock boundary (handled by
    // `Suspend`/`Resume` immediate lock), so implausibly large gaps are
    // conservative-locked here too.
    wall_ms > monotonic_ms.saturating_mul(10).max(86_400_000)
}

/// Whether cleanup acknowledgement exceeded the one-second Lock budget.
pub fn cleanup_budget_exceeded(elapsed: Duration) -> bool {
    elapsed > Duration::from_secs(LOCK_CLEANUP_BUDGET_SECS)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immediate_signals_lock_globally() {
        for signal in [
            LifecycleSignal::ExplicitLock,
            LifecycleSignal::OsLock,
            LifecycleSignal::Suspend,
            LifecycleSignal::Resume,
            LifecycleSignal::ProcessExit,
            LifecycleSignal::ProviderInvalidated,
            LifecycleSignal::ClockAnomaly,
        ] {
            assert!(requires_immediate_lock(signal), "{signal:?}");
            assert!(!enters_background_timing(signal), "{signal:?}");
        }
        assert!(!requires_immediate_lock(LifecycleSignal::FocusLost));
        assert!(!requires_immediate_lock(LifecycleSignal::AllWindowsHidden));
        assert!(enters_background_timing(LifecycleSignal::FocusLost));
        assert!(enters_background_timing(LifecycleSignal::AllWindowsHidden));
    }

    #[test]
    fn background_idle_follows_policy() {
        let policy = LockPolicy::default();
        assert!(!background_idle_should_lock(&policy, 59_999));
        assert!(background_idle_should_lock(&policy, 60_000));
        // No budget → lock immediately (no background-unlocked mode).
        let strict = LockPolicy {
            background_idle_ms: None,
        };
        assert!(background_idle_should_lock(&strict, 0));
    }

    #[test]
    fn clock_anomaly_detects_backward_and_implausible_time() {
        // Backward wall clock.
        assert!(clock_anomaly(Duration::from_secs(10), Duration::ZERO));
        // Wall clock much shorter than monotonic (adjusted backward).
        assert!(clock_anomaly(
            Duration::from_secs(100),
            Duration::from_secs(50)
        ));
        // Plausible agreement → not an anomaly.
        assert!(!clock_anomaly(
            Duration::from_secs(10),
            Duration::from_secs(11)
        ));
        assert!(!clock_anomaly(
            Duration::from_secs(10),
            Duration::from_secs(10)
        ));
        // No elapsed evidence at all → safe (nothing to judge).
        assert!(!clock_anomaly(Duration::ZERO, Duration::ZERO));
    }

    #[test]
    fn cleanup_budget_is_one_second() {
        assert!(!cleanup_budget_exceeded(Duration::from_millis(999)));
        assert!(cleanup_budget_exceeded(
            Duration::from_secs(1) + Duration::from_millis(1)
        ));
        assert_eq!(LOCK_CLEANUP_BUDGET_SECS, 1);
    }
}
