//! Restricted filesystem and journal model (FEAT-005 Phase 2, Task 2.5).
//!
//! Phase 2 defines the model only: fixed identity-neutral layout, owner/mode/
//! link/path validation rules, generation compare-and-swap journal records,
//! temporary-file rules, and the durable two-slot commit plan. The Phase 3
//! writer implements these rules against the real filesystem.

pub mod commit;
pub mod journal;
pub mod layout;
pub mod security;
