//! Keystore capability and wrapping-key policy engine (FEAT-006 Phase 3,
//! Task 3.1).
//!
//! This is the deterministic, device-independent authority for Android
//! Keystore qualification and exact AES key policy. The Kotlin platform shim
//! (Phase 6, tracked under `src-tauri/mobile-plugin/`) executes the same rules
//! at the platform call site; Rust remains the authority that consumes
//! evidence and decides. Every rule is unit-tested without a device; the
//! physical protocol (Phase 7) proves real-hardware behavior.
//!
//! Production policy (target "Exact key policy" + "Property verification"):
//! - algorithm AES, size 256, purposes encrypt+decrypt only, mode GCM only,
//!   padding none, randomized encryption required, provider 96-bit nonce,
//!   128-bit tag, unlocked-device restriction on qualified implementations,
//!   per-use user authentication disabled, no biometric binding.
//! - API 31+ accepts only `TRUSTED_ENVIRONMENT` or `STRONGBOX`; API 28-30
//!   requires secure-hardware evidence plus qualified class. Software/unknown
//!   is unsupported.
//! - StrongBox fallback to verified TEE only for definitive absence or
//!   demonstrated incompatibility; transient/ambiguous failure is Retry, never
//!   a silent downgrade and never replacement of an existing StrongBox key.

use crate::android_vault::contracts::capability::{KeyState, SecurityLevel};

/// Exact key-policy constants (one authority; Kotlin asserts the same values).
pub const KEY_ALGORITHM: &str = "AES";
pub const KEY_SIZE_BITS: u32 = 256;
pub const KEY_BLOCK_MODE: &str = "GCM";
pub const KEY_PADDING: &str = "NONE";
pub const KEY_PURPOSES: &str = "ENCRYPT_OR_DECRYPT";
pub const GCM_NONCE_BITS: u32 = 96;
pub const GCM_TAG_BITS: u32 = 128;
/// Minimum API where `KeyInfo.securityLevel` distinguishes TEE/StrongBox.
pub const SECURITY_LEVEL_API_FLOOR: u32 = 28;
/// API where the platform's `KeyInfo` origin/security-level contract is
/// normative (only TEE/StrongBox accepted).
pub const TRUSTED_ENV_EVIDENCE_API_FLOOR: u32 = 31;

/// Reported security-level evidence from the platform.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportedSecurityLevel {
    StrongBox,
    TrustedEnvironment,
    Software,
    Unknown,
}

/// Result of a StrongBox probe/creation attempt (target "StrongBox policy").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StrongBoxAttempt {
    /// StrongBox created/verified successfully.
    Succeeded,
    /// Definitive absence (not advertised or not supported by this device).
    DefinitivelyAbsent,
    /// Demonstrated incompatibility with the required AES-GCM policy.
    Incompatible,
    /// Timeout, provider crash, temporary failure, capacity/slot ambiguity,
    /// or unknown error — retryable, never a downgrade.
    Retryable,
}

/// One immutable known-bad rule from the signed release policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownBadRule {
    pub build_code: String,
    pub reason: String,
}

/// Secure-lock state evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureLockState {
    Configured,
    NotConfigured,
}

/// Policy decision for a capability/key operation (closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyDecision {
    /// Operation may proceed (provisioning/use allowed).
    Allowed,
    /// Provisioning blocked: secure lock missing.
    SecureLockRequired,
    /// Sensitive operation blocked until the device is unlocked.
    DeviceLocked,
    /// Hardware-backed Keystore requirement not met.
    HardwareBackedKeystoreUnavailable,
    /// Signed-release known-bad rule matched.
    UnsupportedKnownBadBuild,
    /// StrongBox attempt returned a retryable outcome — retry, never downgrade.
    StrongBoxRetryable,
}

/// The exact key-policy predicate evaluated against platform-reported
/// properties. Returns a closed list of violations (empty = policy exact).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPolicyViolations(pub Vec<&'static str>);

impl KeyPolicyViolations {
    pub fn is_exact(&self) -> bool {
        self.0.is_empty()
    }
}

/// Validate platform-reported key properties against the exact policy.
pub fn validate_exact_key_policy(
    algorithm: &str,
    size_bits: u32,
    purposes: &str,
    block_modes: &[String],
    paddings: &[String],
    randomized_encryption_required: bool,
) -> KeyPolicyViolations {
    let mut violations = Vec::new();
    if algorithm != KEY_ALGORITHM {
        violations.push("algorithm must be AES");
    }
    if size_bits != KEY_SIZE_BITS {
        violations.push("key size must be 256 bits");
    }
    if purposes != KEY_PURPOSES {
        violations.push("purposes must be ENCRYPT_OR_DECRYPT only");
    }
    if block_modes != [KEY_BLOCK_MODE.to_string()] {
        violations.push("block mode must be GCM only");
    }
    if paddings != [KEY_PADDING.to_string()] {
        violations.push("padding must be NONE only");
    }
    if !randomized_encryption_required {
        violations.push("randomized encryption must be required");
    }
    KeyPolicyViolations(violations)
}

/// Map API level + reported security level to the accepted production level.
///
/// API 31+ accepts only TEE/StrongBox; API 28-30 requires secure-hardware
/// evidence plus the qualified device class (enforced by the caller). Software
/// or unknown evidence is never accepted.
pub fn map_accepted_security_level(
    api_level: u32,
    reported: ReportedSecurityLevel,
) -> Option<SecurityLevel> {
    match reported {
        ReportedSecurityLevel::StrongBox => Some(SecurityLevel::StrongBox),
        ReportedSecurityLevel::TrustedEnvironment => Some(SecurityLevel::TrustedEnvironment),
        ReportedSecurityLevel::Software | ReportedSecurityLevel::Unknown => None,
    }
    .filter(|_| api_level >= SECURITY_LEVEL_API_FLOOR)
}

/// StrongBox/TEE selection state machine (target "StrongBox policy" rules
/// 1-6). Returns the decision for a probe/create outcome.
pub fn decide_strong_box_selection(
    strong_box_advertised: bool,
    attempt: StrongBoxAttempt,
) -> PolicyDecision {
    if !strong_box_advertised {
        return PolicyDecision::Allowed; // definitive absence -> verified TEE path
    }
    match attempt {
        StrongBoxAttempt::Succeeded => PolicyDecision::Allowed,
        StrongBoxAttempt::DefinitivelyAbsent | StrongBoxAttempt::Incompatible => {
            PolicyDecision::Allowed
        }
        StrongBoxAttempt::Retryable => PolicyDecision::StrongBoxRetryable,
    }
}

/// Evaluate a capability qualification (target "Capability-gated support" and
/// "Security-patch policy"). `secure_hardware_evidence` is the API-28-30 path;
/// `security_level` is the API-31+ path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityInputs {
    pub api_level: u32,
    pub secure_lock: SecureLockState,
    pub device_locked: bool,
    pub reported_security_level: ReportedSecurityLevel,
    /// Secure-hardware evidence for API 28-30 (e.g. KeyInfo `insideSecureHardware`).
    pub secure_hardware_evidence: bool,
    pub strong_box_advertised: bool,
    pub strong_box_attempt: Option<StrongBoxAttempt>,
    pub known_bad_match: bool,
}

pub fn evaluate_capability(inputs: CapabilityInputs) -> PolicyDecision {
    if inputs.known_bad_match {
        return PolicyDecision::UnsupportedKnownBadBuild;
    }
    if inputs.secure_lock == SecureLockState::NotConfigured {
        return PolicyDecision::SecureLockRequired;
    }
    if inputs.device_locked {
        return PolicyDecision::DeviceLocked;
    }
    if let Some(attempt) = inputs.strong_box_attempt {
        if attempt == StrongBoxAttempt::Retryable {
            return PolicyDecision::StrongBoxRetryable;
        }
    }
    let hardware_ok = if inputs.api_level >= TRUSTED_ENV_EVIDENCE_API_FLOOR {
        map_accepted_security_level(inputs.api_level, inputs.reported_security_level).is_some()
    } else {
        inputs.secure_hardware_evidence
    };
    if !hardware_ok {
        return PolicyDecision::HardwareBackedKeystoreUnavailable;
    }
    PolicyDecision::Allowed
}

/// Key-state classification from non-mutating metadata (target "Key or
/// secure-lock invalidation"). A key whose property inspection diverges from
/// policy is `PropertyMismatch`; a missing/invalidated key is `Invalidated`.
pub fn classify_key_state(
    key_present: bool,
    property_inspection: Option<KeyPolicyViolations>,
    permanently_invalidated: bool,
) -> KeyState {
    if !key_present {
        return KeyState::Absent;
    }
    if permanently_invalidated {
        return KeyState::Invalidated;
    }
    match property_inspection {
        Some(v) if !v.is_exact() => KeyState::PropertyMismatch,
        _ => KeyState::Active,
    }
}

/// Whether an existing StrongBox key may be replaced by a TEE key. Per target:
/// never replace an unavailable existing StrongBox key with a new TEE key.
pub fn may_replace_strong_box_with_tee(
    existing_strong_box: bool,
    attempt: StrongBoxAttempt,
) -> bool {
    if existing_strong_box {
        return false;
    }
    matches!(
        attempt,
        StrongBoxAttempt::DefinitivelyAbsent | StrongBoxAttempt::Incompatible
    )
}

/// Evaluate a signed-release known-bad rule against the build code.
pub fn matches_known_bad(rules: &[KnownBadRule], build_code: &str) -> bool {
    rules.iter().any(|r| r.build_code == build_code)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed_inputs() -> CapabilityInputs {
        CapabilityInputs {
            api_level: 36,
            secure_lock: SecureLockState::Configured,
            device_locked: false,
            reported_security_level: ReportedSecurityLevel::TrustedEnvironment,
            secure_hardware_evidence: true,
            strong_box_advertised: true,
            strong_box_attempt: Some(StrongBoxAttempt::Succeeded),
            known_bad_match: false,
        }
    }

    #[test]
    fn exact_policy_accepts_only_exact_properties() {
        let ok = validate_exact_key_policy(
            KEY_ALGORITHM,
            KEY_SIZE_BITS,
            KEY_PURPOSES,
            &[KEY_BLOCK_MODE.to_string()],
            &[KEY_PADDING.to_string()],
            true,
        );
        assert!(ok.is_exact());

        let bad_mode = validate_exact_key_policy(
            KEY_ALGORITHM,
            KEY_SIZE_BITS,
            KEY_PURPOSES,
            &["CTR".to_string()],
            &[KEY_PADDING.to_string()],
            true,
        );
        assert!(!bad_mode.is_exact());

        let bad_size = validate_exact_key_policy(
            KEY_ALGORITHM,
            128,
            KEY_PURPOSES,
            &[KEY_BLOCK_MODE.to_string()],
            &[KEY_PADDING.to_string()],
            true,
        );
        assert!(!bad_size.is_exact());

        let not_randomized = validate_exact_key_policy(
            KEY_ALGORITHM,
            KEY_SIZE_BITS,
            KEY_PURPOSES,
            &[KEY_BLOCK_MODE.to_string()],
            &[KEY_PADDING.to_string()],
            false,
        );
        assert!(!not_randomized.is_exact());
    }

    #[test]
    fn api31_accepts_only_tee_or_strongbox() {
        assert_eq!(
            map_accepted_security_level(31, ReportedSecurityLevel::TrustedEnvironment),
            Some(SecurityLevel::TrustedEnvironment)
        );
        assert_eq!(
            map_accepted_security_level(36, ReportedSecurityLevel::StrongBox),
            Some(SecurityLevel::StrongBox)
        );
        assert_eq!(
            map_accepted_security_level(36, ReportedSecurityLevel::Software),
            None
        );
        assert_eq!(
            map_accepted_security_level(36, ReportedSecurityLevel::Unknown),
            None
        );
        // Below the API floor nothing is accepted by this mapping.
        assert_eq!(
            map_accepted_security_level(27, ReportedSecurityLevel::TrustedEnvironment),
            None
        );
    }

    #[test]
    fn strong_box_selection_never_downgrades_on_retryable() {
        assert_eq!(
            decide_strong_box_selection(true, StrongBoxAttempt::Retryable),
            PolicyDecision::StrongBoxRetryable
        );
        assert_eq!(
            decide_strong_box_selection(true, StrongBoxAttempt::Succeeded),
            PolicyDecision::Allowed
        );
        // Not advertised -> definitive absence path.
        assert_eq!(
            decide_strong_box_selection(false, StrongBoxAttempt::Retryable),
            PolicyDecision::Allowed
        );
    }

    #[test]
    fn existing_strong_box_key_is_never_replaced_by_tee() {
        assert!(!may_replace_strong_box_with_tee(
            true,
            StrongBoxAttempt::Retryable
        ));
        assert!(!may_replace_strong_box_with_tee(
            true,
            StrongBoxAttempt::Incompatible
        ));
        assert!(may_replace_strong_box_with_tee(
            false,
            StrongBoxAttempt::DefinitivelyAbsent
        ));
        assert!(may_replace_strong_box_with_tee(
            false,
            StrongBoxAttempt::Incompatible
        ));
        assert!(!may_replace_strong_box_with_tee(
            false,
            StrongBoxAttempt::Retryable
        ));
    }

    #[test]
    fn capability_evaluation_is_fail_closed() {
        assert_eq!(
            evaluate_capability(allowed_inputs()),
            PolicyDecision::Allowed
        );

        let mut no_lock = allowed_inputs();
        no_lock.secure_lock = SecureLockState::NotConfigured;
        assert_eq!(
            evaluate_capability(no_lock),
            PolicyDecision::SecureLockRequired
        );

        let mut locked = allowed_inputs();
        locked.device_locked = true;
        assert_eq!(evaluate_capability(locked), PolicyDecision::DeviceLocked);

        let mut bad_build = allowed_inputs();
        bad_build.known_bad_match = true;
        assert_eq!(
            evaluate_capability(bad_build),
            PolicyDecision::UnsupportedKnownBadBuild
        );

        let mut retry = allowed_inputs();
        retry.strong_box_attempt = Some(StrongBoxAttempt::Retryable);
        assert_eq!(
            evaluate_capability(retry),
            PolicyDecision::StrongBoxRetryable
        );

        // API 28-30 path uses secure-hardware evidence.
        let mut api28 = allowed_inputs();
        api28.api_level = 28;
        api28.secure_hardware_evidence = false;
        assert_eq!(
            evaluate_capability(api28),
            PolicyDecision::HardwareBackedKeystoreUnavailable
        );
        api28.secure_hardware_evidence = true;
        assert_eq!(evaluate_capability(api28), PolicyDecision::Allowed);

        // API 31+ software evidence fails.
        let mut soft = allowed_inputs();
        soft.reported_security_level = ReportedSecurityLevel::Software;
        assert_eq!(
            evaluate_capability(soft),
            PolicyDecision::HardwareBackedKeystoreUnavailable
        );
    }

    #[test]
    fn key_state_classification_is_exact() {
        assert_eq!(
            classify_key_state(true, Some(KeyPolicyViolations(vec![])), false),
            KeyState::Active
        );
        assert_eq!(
            classify_key_state(true, Some(KeyPolicyViolations(vec!["bad"])), false),
            KeyState::PropertyMismatch
        );
        assert_eq!(classify_key_state(false, None, false), KeyState::Absent);
        assert_eq!(classify_key_state(true, None, true), KeyState::Invalidated);
    }

    #[test]
    fn known_bad_rules_match_exact_build_code() {
        let rules = vec![KnownBadRule {
            build_code: "KP1A.200720.009".to_string(),
            reason: "reviewed guarantee-breaking build".to_string(),
        }];
        assert!(matches_known_bad(&rules, "KP1A.200720.009"));
        assert!(!matches_known_bad(&rules, "TP1A.220624.014"));
    }
}
