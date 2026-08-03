//! Closed Ubuntu adapter contracts (FEAT-005 Phase 2, Task 2.1).
//!
//! Every native outcome that crosses the boundary is one of these closed
//! typed states. No raw provider, path, identity, or secret detail may appear
//! in these values. Projection consumers (FEAT-002 UI bridge) map exactly one
//! safe state per native outcome.

pub mod diagnostics;
pub mod operations;
pub mod protection;
pub mod provider;
pub mod results;
pub mod session;
pub mod wrapper;

pub use diagnostics::*;
pub use operations::*;
pub use protection::*;
pub use provider::*;
pub use results::*;
pub use session::*;
pub use wrapper::*;
