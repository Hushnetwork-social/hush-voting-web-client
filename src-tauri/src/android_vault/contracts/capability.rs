//! Android capability and hardware-level vocabulary (FEAT-006 Phase 2).
//!
//! Mirrors the capability model consumed by the TypeScript boundary. Runtime
//! invariants are computed by the Kotlin bridge (Phase 3) and projected here
//! as closed safe values. Software/unknown hardware is unsupported in
//! production; API 31+ accepts only `TrustedEnvironment`/`StrongBox`.

use serde::{Deserialize, Serialize};

/// Broad security level of the wrapping key's origin (API-appropriate KeyInfo).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SecurityLevel {
    /// Qualified StrongBox (preferred when present).
    StrongBox,
    /// Qualified TEE (supported hardware-backed baseline).
    TrustedEnvironment,
    /// Software-backed or unknown security level — unsupported for production.
    SoftwareOrUnknown,
}

impl SecurityLevel {
    /// Whether this level satisfies the production hardware-backed requirement.
    pub fn is_hardware_backed(self) -> bool {
        matches!(self, Self::StrongBox | Self::TrustedEnvironment)
    }
}

/// Device capability class (target "Capability-gated support").
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CapabilityClass {
    /// Exact representative combination passed the signed physical protocol.
    Qualified,
    /// Runtime checks pass but the exact model was not individually qualified.
    CapabilityCompatible,
    /// A required invariant fails or a signed-release known-bad rule matches.
    Blocked,
}

/// State of the per-vault Android Keystore wrapping key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyState {
    /// No key exists for this vault.
    Absent,
    /// The active key is present, healthy, and property-verified.
    Active,
    /// A staged (rotation/provisioning) key exists alongside the active key.
    Staged,
    /// The key is missing, permanently invalidated, or property-mismatched.
    Invalidated,
    /// The key exists but property inspection diverges from the policy.
    PropertyMismatch,
}

/// Non-mutating Android capability/status projection (safe for the WebView).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CapabilityStatus {
    /// Whether Android reports a configured secure lock screen.
    pub secure_lock_configured: bool,
    /// Whether Android currently reports the device locked.
    pub device_locked: bool,
    /// Broad security level of the produced key origin.
    pub security_level: SecurityLevel,
    /// Whether StrongBox capability is advertised (probe result; never a claim
    /// of a qualified StrongBox key).
    pub strong_box_advertised: bool,
    /// Device capability class under the signed-release policy.
    pub capability_class: CapabilityClass,
    /// Whether a signed-release known-bad rule matches this device/build.
    pub known_bad_build_match: bool,
}

impl CapabilityStatus {
    /// Production persistent provisioning requires: secure lock configured,
    /// device unlocked, hardware-backed security level, non-blocked class.
    pub fn allows_persistent_provisioning(&self) -> bool {
        self.secure_lock_configured
            && !self.device_locked
            && self.security_level.is_hardware_backed()
            && self.capability_class != CapabilityClass::Blocked
            && !self.known_bad_build_match
    }

    /// A sensitive operation may start only while the device is unlocked.
    pub fn device_ready_for_sensitive_operation(&self) -> bool {
        !self.device_locked && self.capability_class != CapabilityClass::Blocked
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn qualified() -> CapabilityStatus {
        CapabilityStatus {
            secure_lock_configured: true,
            device_locked: false,
            security_level: SecurityLevel::TrustedEnvironment,
            strong_box_advertised: true,
            capability_class: CapabilityClass::CapabilityCompatible,
            known_bad_build_match: false,
        }
    }

    #[test]
    fn qualified_status_allows_provisioning() {
        assert!(qualified().allows_persistent_provisioning());
    }

    #[test]
    fn software_level_never_allows_provisioning() {
        let mut s = qualified();
        s.security_level = SecurityLevel::SoftwareOrUnknown;
        assert!(!s.allows_persistent_provisioning());
        assert!(!s.security_level.is_hardware_backed());
    }

    #[test]
    fn missing_secure_lock_blocks_provisioning() {
        let mut s = qualified();
        s.secure_lock_configured = false;
        assert!(!s.allows_persistent_provisioning());
    }

    #[test]
    fn locked_device_blocks_sensitive_work_and_provisioning() {
        let mut s = qualified();
        s.device_locked = true;
        assert!(!s.device_ready_for_sensitive_operation());
        assert!(!s.allows_persistent_provisioning());
    }

    #[test]
    fn known_bad_or_blocked_class_never_provisions() {
        let mut s = qualified();
        s.known_bad_build_match = true;
        assert!(!s.allows_persistent_provisioning());
        let mut s2 = qualified();
        s2.capability_class = CapabilityClass::Blocked;
        assert!(!s2.allows_persistent_provisioning());
        assert!(!s2.device_ready_for_sensitive_operation());
    }

    #[test]
    fn unknown_field_is_rejected() {
        let json = json!({
            "secureLockConfigured": true,
            "deviceLocked": false,
            "securityLevel": "trustedEnvironment",
            "strongBoxAdvertised": false,
            "capabilityClass": "capabilityCompatible",
            "knownBadBuildMatch": false,
            "alias": "sneaky"
        });
        assert!(serde_json::from_value::<CapabilityStatus>(json).is_err());
    }

    #[test]
    fn unknown_enum_value_is_rejected() {
        let json = json!({
            "secureLockConfigured": true,
            "deviceLocked": false,
            "securityLevel": "magic",
            "strongBoxAdvertised": false,
            "capabilityClass": "capabilityCompatible",
            "knownBadBuildMatch": false
        });
        assert!(serde_json::from_value::<CapabilityStatus>(json).is_err());
    }
}
