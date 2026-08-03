//! Closed Android adapter contract vocabulary (FEAT-006 Phase 2, Task 2.1).
//!
//! One versioned semantic vocabulary shared by Rust, Kotlin, and TypeScript:
//! capability status, hardware/security level, key state, bridge operation,
//! typed result, recovery action, lifecycle evidence, sensitive state,
//! document operation, and sanitized diagnostics. Every expected failure is
//! typed data with safe fields; no raw Android exception, alias, path/URI,
//! identity, ciphertext, or free-form platform message ever crosses a
//! boundary. Unknown values fail closed.

pub mod capability;
pub mod diagnostics;
pub mod lifecycle;
pub mod operation;
pub mod result;
