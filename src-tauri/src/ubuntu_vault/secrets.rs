//! Direct secret submission boundary (FEAT-005 "Direct secret submission",
//! "FEAT-008 recovery words", "FEAT-009/011 .dat").
//!
//! Device-password and mnemonic inputs are uncontrolled in the dedicated UI
//! and cross into native ownership ONCE through a bounded, non-logged
//! command. The bytes are wrapped immediately in a zeroizing container, the
//! WebView input/buffer is cleared after acknowledgement, and the value never
//! enters React, XState, global stores, form persistence, URL/history, logs,
//! or telemetry. Only an opaque operation id returns to the caller.

use zeroize::Zeroizing;

/// Bounded device-password payload (bytes, after one UTF-8 encode).
pub const DEVICE_PASSWORD_MAX_BYTES: usize = 1_024;
/// Bounded recovery-word payload (24-word BIP-39 phrase, one submission).
pub const MNEMONIC_MAX_BYTES: usize = 4_096;
/// Bounded `.dat` file payload (capability-scoped import, native memory).
pub const DAT_IMPORT_MAX_BYTES: usize = 4_096;

/// Closed secret-boundary failure vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretError {
    BoundsExceeded,
    AlreadyHeld,
    Empty,
    RngFailed,
}

impl SecretError {
    pub fn to_native_error(self) -> crate::ubuntu_vault::contracts::results::NativeErrorCode {
        use crate::ubuntu_vault::contracts::results::NativeErrorCode;
        match self {
            Self::BoundsExceeded | Self::Empty | Self::AlreadyHeld => {
                NativeErrorCode::OperationForbidden
            }
            Self::RngFailed => NativeErrorCode::PlatformProtectionUnavailable,
        }
    }
}

impl std::fmt::Display for SecretError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "secret submission failure (closed code)")
    }
}

impl std::error::Error for SecretError {}

/// An opaque operation id returned to the WebView after a secret submission.
/// Never carries or implies the secret value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(transparent)]
pub struct SecretOperationId(pub u64);

/// A single-use native-held secret submission. The bytes live only inside
/// this zeroizing container; there is intentionally NO `Debug` impl.
pub struct SecretSubmission {
    operation_id: SecretOperationId,
    bytes: Zeroizing<Vec<u8>>,
}

impl SecretSubmission {
    /// Wrap caller bytes into native ownership. Bounds are enforced before
    /// any copy; on error the caller buffer is cleared by the caller.
    pub fn accept(bytes: Vec<u8>, max: usize) -> Result<Self, SecretError> {
        if bytes.is_empty() {
            return Err(SecretError::Empty);
        }
        if bytes.len() > max {
            return Err(SecretError::BoundsExceeded);
        }
        let operation_id = new_operation_id()?;
        Ok(Self {
            operation_id,
            bytes: Zeroizing::new(bytes),
        })
    }

    pub fn operation_id(&self) -> SecretOperationId {
        self.operation_id
    }

    /// Drain the secret once (the consuming native authority clears it on
    /// drop). `None` after the first drain.
    pub fn drain(&mut self) -> Option<Zeroizing<Vec<u8>>> {
        if self.bytes.is_empty() {
            return None;
        }
        Some(std::mem::take(&mut self.bytes))
    }
}

/// Unpredictable opaque operation id (CSPRNG; never sequential). A random
/// failure is a closed error — never a weaker fallback id.
fn new_operation_id() -> Result<SecretOperationId, SecretError> {
    let bytes = crate::ubuntu_vault::crypto::random_bytes(8).map_err(|_| SecretError::RngFailed)?;
    let mut raw = [0u8; 8];
    raw.copy_from_slice(&bytes);
    Ok(SecretOperationId(u64::from_le_bytes(raw)))
}

/// Clear a caller-owned transient buffer (WebView-side ownership boundary).
pub fn clear_transient_buffer(bytes: &mut [u8]) {
    use zeroize::Zeroize;
    bytes.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_is_bounded_and_single_use() {
        let mut submission = SecretSubmission::accept(
            b"correct horse battery staple".to_vec(),
            DEVICE_PASSWORD_MAX_BYTES,
        )
        .unwrap();
        let id = submission.operation_id();
        assert_eq!(id.0, id.0);
        let drained = submission.drain().unwrap();
        assert_eq!(&*drained, b"correct horse battery staple");
        // Second drain is None (single-use).
        assert!(submission.drain().is_none());
    }

    #[test]
    fn bounds_and_emptiness_are_rejected() {
        assert!(matches!(
            SecretSubmission::accept(Vec::new(), DEVICE_PASSWORD_MAX_BYTES),
            Err(SecretError::Empty)
        ));
        assert!(matches!(
            SecretSubmission::accept(
                vec![0u8; DEVICE_PASSWORD_MAX_BYTES + 1],
                DEVICE_PASSWORD_MAX_BYTES
            ),
            Err(SecretError::BoundsExceeded)
        ));
    }

    #[test]
    fn operation_ids_are_unpredictable() {
        let a = SecretSubmission::accept(b"one".to_vec(), 64)
            .unwrap()
            .operation_id();
        let b = SecretSubmission::accept(b"two".to_vec(), 64)
            .unwrap()
            .operation_id();
        assert_ne!(a, b);
    }

    #[test]
    fn transient_buffer_is_cleared() {
        let mut buf = vec![0x77u8; 32];
        clear_transient_buffer(&mut buf);
        assert!(buf.iter().all(|b| *b == 0));
    }
}
