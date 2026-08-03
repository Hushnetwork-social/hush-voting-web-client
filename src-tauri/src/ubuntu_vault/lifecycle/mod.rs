//! Lifecycle module root (FEAT-005 Phase 3): password throttling and
//! resumable local-user removal. Session/command authority lands in Phase 4;
//! this module owns the persisted operational state and its deterministic
//! transitions.

pub mod removal;
pub mod throttle;
