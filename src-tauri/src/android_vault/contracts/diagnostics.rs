//! Sanitized local diagnostics vocabulary (FEAT-006 Phase 2, Task 2.1).
//!
//! A local security-status view may report ONLY broad values. No alias, path/
//! URI, ciphertext digest, identity/address, endpoint, exact timestamp,
//! serial/Android ID/attestation ID, stable vault/session identifier, or raw
//! platform exception may appear. Telemetry is disabled by default.

use serde::{Deserialize, Serialize};

/// Broad diagnostic categories available to the local security-status view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SanitizedDiagnostics {
    /// Whether a secure lock screen is configured.
    pub secure_lock_configured: bool,
    /// Broad security level (TEE/StrongBox/software) as a category.
    pub security_level_category: SecurityLevelCategory,
    /// Supported/blocked capability class.
    pub capability_class: CapabilityClass,
    /// Wrapper/protocol version identifiers.
    pub wrapper_version: u32,
    /// Release build digest (sanitized; no signing material).
    pub build_digest_prefix: String,
    /// Optional random non-correlating support code from the last failure.
    pub support_code: Option<String>,
}

/// Broad security-level category (never a hardware fingerprint).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SecurityLevelCategory {
    StrongBox,
    Tee,
    SoftwareOrUnknown,
}

/// Supported/blocked capability class (broad).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CapabilityClass {
    Qualified,
    CapabilityCompatible,
    Blocked,
}

/// Forbidden detail markers that must never appear in any diagnostic string.
pub const FORBIDDEN_DIAGNOSTIC_MARKERS: &[&str] = &[
    "alias",
    "address",
    "endpoint",
    "timestamp",
    "serial",
    "androidId",
    "attestationId",
    "ciphertext",
    "uri",
    "path",
    "exception",
    "stack",
    "mnemonic",
    "password",
    "identity",
];

impl SanitizedDiagnostics {
    /// Whether every string field is free of forbidden detail markers.
    pub fn is_sanitized(&self) -> bool {
        let haystacks = [
            self.build_digest_prefix.as_str(),
            self.support_code.as_deref().unwrap_or(""),
        ];
        for needle in FORBIDDEN_DIAGNOSTIC_MARKERS {
            for haystack in haystacks {
                if haystack.to_ascii_lowercase().contains(needle) {
                    return false;
                }
            }
        }
        true
    }

    /// Bounded string fields.
    pub fn is_bounded(&self) -> bool {
        self.build_digest_prefix.len() <= 16
            && self.support_code.as_ref().map_or(true, |s| s.len() <= 8)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> SanitizedDiagnostics {
        SanitizedDiagnostics {
            secure_lock_configured: true,
            security_level_category: SecurityLevelCategory::Tee,
            capability_class: CapabilityClass::CapabilityCompatible,
            wrapper_version: 1,
            build_digest_prefix: "a1b2c3d4".to_string(),
            support_code: Some("9f3e1a02".to_string()),
        }
    }

    #[test]
    fn sanitized_sample_passes() {
        let d = sample();
        assert!(d.is_sanitized());
        assert!(d.is_bounded());
    }

    #[test]
    fn identity_detail_is_rejected() {
        let mut d = sample();
        d.build_digest_prefix = "alias-1a2b".to_string();
        assert!(!d.is_sanitized());
        let mut d2 = sample();
        d2.support_code = Some("serial-99".to_string());
        assert!(!d2.is_sanitized());
    }

    #[test]
    fn oversized_support_code_is_rejected() {
        let mut d = sample();
        d.support_code = Some("123456789".to_string());
        assert!(!d.is_bounded());
    }

    #[test]
    fn unknown_field_is_rejected() {
        let json = r#"{"secureLockConfigured":true,"securityLevelCategory":"tee","capabilityClass":"capabilityCompatible","wrapperVersion":1,"buildDigestPrefix":"a1b2c3d4","supportCode":null,"model":"Pixel"}"#;
        assert!(serde_json::from_str::<SanitizedDiagnostics>(json).is_err());
    }
}
