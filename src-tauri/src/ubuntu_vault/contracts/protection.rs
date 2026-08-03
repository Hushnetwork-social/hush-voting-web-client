//! Protection mode contract (FEAT-005 "Protection Modes").
//!
//! Only two modes exist: OS-backed (qualified Secret Service provider wraps
//! one random device key) and password-only (confirmed-absence fallback with
//! informed acknowledgement). No mode is ever labeled OS-backed, hardware-
//! backed, or equivalent to Secret Service unless it is.

use serde::{Deserialize, Serialize};

/// Persistent protection mode. Non-secret; shown in authenticated Security
/// settings without interrupting every unlock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProtectionMode {
    /// FEAT-003 password-encrypted package is additionally wrapped by an
    /// OS Secret Service wrapping key. Both are required.
    OsBacked,
    /// FEAT-003 password-encrypted package only (confirmed provider absence,
    /// acknowledged fallback). Never labeled OS-backed.
    PasswordOnly,
}

impl ProtectionMode {
    /// Whether the OS wrapping key is part of this protection.
    pub fn is_os_backed(self) -> bool {
        matches!(self, Self::OsBacked)
    }

    /// Coarse class for UI and opt-in telemetry (never provider name/version).
    pub fn protection_class(self) -> super::provider::ProtectionClass {
        match self {
            Self::OsBacked => super::provider::ProtectionClass::SecretService,
            Self::PasswordOnly => super::provider::ProtectionClass::PasswordOnly,
        }
    }
}

/// Non-secret summary projected to the Security settings surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProtectionModeSummary {
    pub mode: ProtectionMode,
    /// Authenticated non-secret acknowledgement state for fallback (only
    /// meaningful in PasswordOnly mode).
    pub fallback_acknowledged: bool,
    /// Whether an automatic OS-protection upgrade is available after the next
    /// successful device-password unlock (fallback → OS-backed).
    pub upgrade_eligible_after_unlock: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ubuntu_vault::contracts::provider::ProtectionClass;

    #[test]
    fn os_backed_class_is_secret_service() {
        assert_eq!(
            ProtectionMode::OsBacked.protection_class(),
            ProtectionClass::SecretService
        );
        assert!(ProtectionMode::OsBacked.is_os_backed());
    }

    #[test]
    fn password_only_class_is_password_only() {
        assert_eq!(
            ProtectionMode::PasswordOnly.protection_class(),
            ProtectionClass::PasswordOnly
        );
        assert!(!ProtectionMode::PasswordOnly.is_os_backed());
    }
}
