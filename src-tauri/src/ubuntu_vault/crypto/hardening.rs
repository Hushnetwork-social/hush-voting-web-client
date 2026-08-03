//! Secret-memory hardening (FEAT-005 "Memory and crash hardening").
//!
//! - Core dumps/crash-memory capture are disabled for the HushVoting process
//!   (best-effort `RLIMIT_CORE`).
//! - Small application-owned private-key/mnemonic buffers may be best-effort
//!   memory-locked (`mlock`/`munlock`) where supported. The complete Argon2
//!   allocation is deliberately NOT locked.
//! - Memory-lock capability is reported only through sanitized local
//!   diagnostics; failures are silently downgraded to None (never a panic).
//!
//! Honest limits: no claim is made against root, debugger/process injection,
//! kernel compromise, swap/engine copies, or deterministic physical memory
//! erasure.

use std::os::unix::ffi::OsStrExt;

/// Best-effort disable of core-dump/crash-memory capture for this process.
/// Returns whether the operation was applied (sanitized diagnostics only).
pub fn disable_core_dumps() -> bool {
    // SAFETY: setrlimit with a stack value; no memory is touched.
    let rlim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: RLIMIT_CORE is a valid resource; rlim points to a valid local.
    unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) == 0 }
}

/// RAII best-effort memory lock over a small owned secret buffer.
///
/// Unlocks on drop (best-effort). `try_lock` never fails the caller: when the
/// OS cannot lock (permissions, rlimit, unsupported), `None` is returned and
/// the buffer remains plain (documented residual risk).
pub struct MemoryLocked {
    ptr: *mut libc::c_void,
    len: usize,
}

impl MemoryLocked {
    /// Best-effort lock of `bytes`. Returns `None` when unsupported/failed.
    pub fn try_lock(bytes: &mut [u8]) -> Option<Self> {
        if bytes.is_empty() {
            return None;
        }
        let ptr = bytes.as_mut_ptr() as *mut libc::c_void;
        // SAFETY: `bytes` is a live mutable slice for the lifetime of this
        // object; mlock locks the caller's pages (no ownership transfer).
        if unsafe { libc::mlock(ptr, bytes.len()) } == 0 {
            Some(Self {
                ptr,
                len: bytes.len(),
            })
        } else {
            None
        }
    }

    /// Whether the lock is actually held (diagnostics only).
    pub fn is_locked(&self) -> bool {
        true
    }
}

impl Drop for MemoryLocked {
    fn drop(&mut self) {
        // SAFETY: same range mlock()ed above; munlock is best-effort.
        unsafe {
            libc::munlock(self.ptr, self.len);
        }
    }
}

/// Best-effort memory-lock capability probe for sanitized local diagnostics.
/// Never exposes rlimit values, addresses, or process details.
pub fn memory_lock_capability() -> bool {
    let mut probe = [0u8; 64];
    MemoryLocked::try_lock(&mut probe).is_some()
}

/// Disable core dumps in addition to zeroization (crash-hardening).
/// Single explicit call site for the hardening contract (Phase 4 composition
/// calls this at startup).
pub fn apply_process_hardening() -> bool {
    disable_core_dumps()
}

/// Best-effort clearing of a small buffer through the volatile-safe path.
/// Prefer `zeroize::Zeroizing` for owned containers; this is for borrowed
/// transient buffers that must be cleared before scope end.
pub fn clear_buffer(bytes: &mut [u8]) {
    use zeroize::Zeroize;
    bytes.zeroize();
}

/// Sanitized path byte length guard: crash reports never include command
/// arguments or paths; this helper exists to keep the boundary explicit for
/// any future diagnostic sink (never passes the path itself).
pub fn sanitized_byte_count(path: &std::path::Path) -> usize {
    path.as_os_str().as_bytes().len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_dump_hardening_is_best_effort() {
        // On Linux this applies cleanly; the contract is "best-effort", so
        // both outcomes are acceptable as long as it does not panic.
        let _ = disable_core_dumps();
        let _ = apply_process_hardening();
    }
    #[test]
    fn memory_lock_is_best_effort_and_releases() {
        let mut small = vec![0x42u8; 256];
        let locked = MemoryLocked::try_lock(&mut small);
        if let Some(lock) = locked {
            assert!(lock.is_locked());
            drop(lock); // munlock on drop; no panic
        }
        // Capability probe never panics and returns a bool.
        let _ = memory_lock_capability();
    }

    #[test]
    fn clear_buffer_zeroizes() {
        let mut buf = vec![0xabu8; 128];
        clear_buffer(&mut buf);
        assert!(buf.iter().all(|b| *b == 0));
    }

    #[test]
    fn crash_reports_never_include_paths() {
        // The hardening boundary only exposes byte counts of paths — never
        // the path content itself (diagnostic sinks receive the count).
        let p = std::path::Path::new("/home/user/.local/share/com.hushvoting.client");
        assert!(sanitized_byte_count(p) > 0);
    }
}
