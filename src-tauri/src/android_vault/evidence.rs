//! Qualification/evidence schemas (FEAT-006 Phase 2, Task 2.5).
//!
//! Machine-readable sanitized evidence records and the required-profile
//! matrix. Evidence contains ONLY broad API/security level, build digest,
//! scenario outcomes, and contract versions. A record containing a serial,
//! Android ID, attestation ID, identity, exact timestamp, model fingerprint,
//! alias, URI, ciphertext, or secret is REJECTED. Missing required physical
//! profiles is a blocking machine result — never a manual checklist or a
//! human attestation. Emulator evidence can never substitute for physical
//! TEE evidence.

use serde::{Deserialize, Serialize};

/// Declared evidence classes (closed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum EvidenceClass {
    /// Production fail-closed behavior on an emulator without hardware.
    Emulator,
    /// Qualified TEE physical device.
    PhysicalTee,
    /// Physical representative of the oldest supported API class (API 28).
    PhysicalOldestApi,
    /// Physical representative of the current target/API class.
    PhysicalCurrentApi,
    /// Qualified StrongBox physical device (release-disabled until passed).
    PhysicalStrongBox,
    /// APK/AAB + supply-chain + secret inspection.
    Package,
    /// Accessibility and sensitive-content qualification.
    Accessibility,
    /// Independent security review ledger.
    Security,
}

impl EvidenceClass {
    /// Classes that are release-blocking mandatory profiles.
    pub const MANDATORY: &'static [EvidenceClass] = &[
        EvidenceClass::PhysicalTee,
        EvidenceClass::PhysicalOldestApi,
        EvidenceClass::PhysicalCurrentApi,
        EvidenceClass::Package,
        EvidenceClass::Accessibility,
        EvidenceClass::Security,
    ];

    pub fn is_mandatory(self) -> bool {
        Self::MANDATORY.contains(&self)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Emulator => "emulator",
            Self::PhysicalTee => "physical-tee",
            Self::PhysicalOldestApi => "physical-oldest-api",
            Self::PhysicalCurrentApi => "physical-current-api",
            Self::PhysicalStrongBox => "physical-strongbox",
            Self::Package => "package",
            Self::Accessibility => "accessibility",
            Self::Security => "security",
        }
    }
}

/// One sanitized scenario outcome inside a qualification report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ScenarioResult {
    /// Closed scenario identifier (contract vocabulary).
    pub scenario: String,
    pub passed: bool,
}

/// One sanitized qualification report (broad fields only).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct QualificationReport {
    pub schema_version: u32,
    pub evidence_class: EvidenceClass,
    /// Release build digest (full hex; sanitized, no signing material).
    pub build_digest: String,
    /// Broad API class (for physical profiles: e.g. 28, 36).
    pub api_level: u32,
    /// Broad security level for physical classes (never a hardware
    /// fingerprint beyond the category).
    pub security_level: BroadSecurityLevel,
    pub capability_class: BroadCapabilityClass,
    /// Sanitized scenario outcomes.
    pub scenario_results: Vec<ScenarioResult>,
    /// Contract versions replay evidence (wrapper/protocol/corpus pins).
    pub contract_versions: Vec<ContractVersionPin>,
}

/// Broad security level (category only).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BroadSecurityLevel {
    StrongBox,
    Tee,
    SoftwareOrUnknown,
}

/// Broad capability class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum BroadCapabilityClass {
    Qualified,
    CapabilityCompatible,
    Blocked,
}

/// One contract/version pin recorded in evidence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractVersionPin {
    pub name: String,
    pub value: String,
}

/// Specific identifiers/secret markers — matched as substrings (camelCase or
/// snake_case tokens that can never legitimately appear in sanitized evidence).
pub const SUBSTRING_FORBIDDEN_EVIDENCE_MARKERS: &[&str] = &[
    "androidId",
    "android_id",
    "attestationId",
    "attestation_id",
    "imei",
    "macAddress",
    "ciphertext",
    "privateKey",
    "mnemonic",
    "password",
    "serial",
    "fingerprint",
    "timestamp",
    "identity",
];

/// Generic English words — matched only at token boundaries to avoid false
/// positives (e.g. `uri` inside `security`).
pub const WORD_FORBIDDEN_EVIDENCE_MARKERS: &[&str] = &[
    "uri", "path", "secret", "model", "alias", "address", "endpoint",
];

/// Whether `marker` appears in `haystack` at a token boundary (start/end of
/// the string or adjacent to a non-alphanumeric character). Case-insensitive.
pub fn contains_at_boundary(haystack: &str, marker: &str) -> bool {
    let h: Vec<char> = haystack.to_ascii_lowercase().chars().collect();
    let m: Vec<char> = marker.to_ascii_lowercase().chars().collect();
    if m.is_empty() || m.len() > h.len() {
        return false;
    }
    for start in 0..=(h.len() - m.len()) {
        if h[start..start + m.len()] == m[..] {
            let before_ok = start == 0 || !h[start - 1].is_ascii_alphanumeric();
            let after = start + m.len();
            let after_ok = after == h.len() || !h[after].is_ascii_alphanumeric();
            if before_ok && after_ok {
                return true;
            }
        }
    }
    false
}

/// Whether any forbidden marker appears in a single string field.
pub fn field_contains_forbidden_marker(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    SUBSTRING_FORBIDDEN_EVIDENCE_MARKERS
        .iter()
        .any(|m| lower.contains(&m.to_ascii_lowercase()))
        || WORD_FORBIDDEN_EVIDENCE_MARKERS
            .iter()
            .any(|m| contains_at_boundary(&lower, m))
}

impl QualificationReport {
    /// Whether every string field is free of forbidden evidence markers.
    pub fn is_sanitized(&self) -> bool {
        let fields = [self.build_digest.as_str(), self.evidence_class.as_str()];
        if fields.iter().any(|f| field_contains_forbidden_marker(f)) {
            return false;
        }
        for s in &self.scenario_results {
            if field_contains_forbidden_marker(&s.scenario) {
                return false;
            }
        }
        for pin in &self.contract_versions {
            if field_contains_forbidden_marker(&pin.name)
                || field_contains_forbidden_marker(&pin.value)
            {
                return false;
            }
        }
        true
    }

    /// A physical evidence class requires a hardware-backed broad level.
    pub fn hardware_claim_is_consistent(&self) -> bool {
        let is_physical = matches!(
            self.evidence_class,
            EvidenceClass::PhysicalTee
                | EvidenceClass::PhysicalOldestApi
                | EvidenceClass::PhysicalCurrentApi
                | EvidenceClass::PhysicalStrongBox
        );
        if is_physical {
            return self.security_level == BroadSecurityLevel::Tee
                || self.security_level == BroadSecurityLevel::StrongBox;
        }
        // Emulator reports make no hardware claim; a Tee/StrongBox level on an
        // emulator report is inconsistent. Package/Accessibility/Security
        // reports carry no hardware claim either way.
        if self.evidence_class == EvidenceClass::Emulator {
            return self.security_level == BroadSecurityLevel::SoftwareOrUnknown;
        }
        true
    }

    /// Emulator evidence can never claim a physical class.
    pub fn provenance_is_consistent(&self) -> bool {
        self.evidence_class != EvidenceClass::Emulator
            || self.security_level == BroadSecurityLevel::SoftwareOrUnknown
    }
}

/// Required-profile matrix validation result (machine-checkable).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProfileMatrixResult {
    pub schema_version: u32,
    /// True only when every mandatory class has a passing, sanitized,
    /// provenance-consistent report for the current build digest.
    pub all_mandatory_present: bool,
    /// Missing mandatory classes (blocking machine result).
    pub missing_mandatory: Vec<String>,
    /// StrongBox remains release-disabled unless a qualified StrongBox
    /// physical report passes for the current digest.
    pub strong_box_release_enabled: bool,
}

impl ProfileMatrixResult {
    /// Evaluate a report set against the mandatory matrix for one digest.
    pub fn evaluate(reports: &[QualificationReport], build_digest: &str) -> Self {
        let mut present = std::collections::BTreeSet::new();
        for r in reports {
            if r.build_digest == build_digest
                && r.is_sanitized()
                && r.hardware_claim_is_consistent()
                && r.provenance_is_consistent()
                && r.scenario_results.iter().all(|s| s.passed)
            {
                present.insert(r.evidence_class);
            }
        }
        let missing_mandatory = EvidenceClass::MANDATORY
            .iter()
            .filter(|c| !present.contains(c))
            .map(|c| c.as_str().to_string())
            .collect::<Vec<_>>();
        let strong_box_ok = reports.iter().any(|r| {
            r.evidence_class == EvidenceClass::PhysicalStrongBox
                && r.build_digest == build_digest
                && r.security_level == BroadSecurityLevel::StrongBox
                && r.scenario_results.iter().all(|s| s.passed)
        });
        Self {
            schema_version: 1,
            all_mandatory_present: missing_mandatory.is_empty(),
            missing_mandatory,
            strong_box_release_enabled: strong_box_ok,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_physical_report(class: EvidenceClass) -> QualificationReport {
        QualificationReport {
            schema_version: 1,
            evidence_class: class,
            build_digest: "a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f809"
                .to_string(),
            api_level: 36,
            security_level: BroadSecurityLevel::Tee,
            capability_class: BroadCapabilityClass::Qualified,
            scenario_results: vec![
                ScenarioResult {
                    scenario: "provision-unlock-verify".to_string(),
                    passed: true,
                },
                ScenarioResult {
                    scenario: "lifecycle-reboot".to_string(),
                    passed: true,
                },
            ],
            contract_versions: vec![
                ContractVersionPin {
                    name: "wrapperVersion".to_string(),
                    value: "1".to_string(),
                },
                ContractVersionPin {
                    name: "mobilePluginProtocol".to_string(),
                    value: "1.0".to_string(),
                },
            ],
        }
    }

    #[test]
    fn sanitized_physical_report_passes_matrix() {
        let r = valid_physical_report(EvidenceClass::PhysicalCurrentApi);
        assert!(r.is_sanitized());
        assert!(r.hardware_claim_is_consistent());
        assert!(r.provenance_is_consistent());
        let matrix = ProfileMatrixResult::evaluate(
            &[r],
            "a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f809",
        );
        assert!(!matrix.all_mandatory_present); // only one class present
        assert!(matrix
            .missing_mandatory
            .contains(&"physical-tee".to_string()));
        assert!(!matrix.strong_box_release_enabled);
    }

    #[test]
    fn complete_matrix_is_green_and_strongbox_gated() {
        let digest = "digest-0000000000000000000000000000000000000000000000000000000000000000";
        let mut reports = Vec::new();
        for &class in EvidenceClass::MANDATORY {
            reports.push(valid_physical_report(class));
        }
        // All mandatory reports carry the same digest; fix each digest to match.
        for r in reports.iter_mut() {
            r.build_digest = digest.to_string();
        }
        let matrix = ProfileMatrixResult::evaluate(&reports, digest);
        assert!(matrix.all_mandatory_present);
        assert!(matrix.missing_mandatory.is_empty());
        assert!(!matrix.strong_box_release_enabled); // no passing StrongBox report

        let mut sb = valid_physical_report(EvidenceClass::PhysicalStrongBox);
        sb.build_digest = digest.to_string();
        sb.security_level = BroadSecurityLevel::StrongBox;
        reports.push(sb);
        let matrix2 = ProfileMatrixResult::evaluate(&reports, digest);
        assert!(matrix2.strong_box_release_enabled);
    }

    #[test]
    fn identifying_evidence_is_rejected() {
        let mut r = valid_physical_report(EvidenceClass::PhysicalTee);
        r.scenario_results.push(ScenarioResult {
            scenario: "capture-serial-9F3E".to_string(),
            passed: true,
        });
        assert!(!r.is_sanitized());
    }

    #[test]
    fn generic_words_match_only_at_boundaries() {
        // "uri" appears inside "security"; boundary matching must not reject
        // the legitimate evidence-class vocabulary.
        assert!(!contains_at_boundary("security", "uri"));
        assert!(contains_at_boundary("content://uri/path", "uri"));
        assert!(contains_at_boundary("some secret text", "secret"));
        assert!(!contains_at_boundary("secretary", "secret"));
        assert!(contains_at_boundary("file-path", "path"));
        assert!(field_contains_forbidden_marker("content://uri/path"));
        assert!(!field_contains_forbidden_marker("security"));
        assert!(!field_contains_forbidden_marker("physical-oldest-api"));
        assert!(field_contains_forbidden_marker("androidId-ABC"));
    }

    #[test]
    fn emulator_cannot_claim_hardware() {
        let mut r = valid_physical_report(EvidenceClass::Emulator);
        r.security_level = BroadSecurityLevel::Tee;
        assert!(!r.provenance_is_consistent());
        assert!(!r.hardware_claim_is_consistent());
    }

    #[test]
    fn software_level_physical_report_is_inconsistent() {
        let mut r = valid_physical_report(EvidenceClass::PhysicalOldestApi);
        r.security_level = BroadSecurityLevel::SoftwareOrUnknown;
        assert!(!r.hardware_claim_is_consistent());
    }

    #[test]
    fn stale_digest_does_not_satisfy_matrix() {
        let r = valid_physical_report(EvidenceClass::PhysicalTee);
        let matrix = ProfileMatrixResult::evaluate(&[r], "other-digest");
        assert!(!matrix.all_mandatory_present);
    }

    #[test]
    fn unknown_evidence_field_is_rejected() {
        let json = r#"{"schemaVersion":1,"evidenceClass":"physicalTee","buildDigest":"abc","apiLevel":36,"securityLevel":"tee","capabilityClass":"qualified","scenarioResults":[],"contractVersions":[],"serial":"ABC"}"#;
        assert!(serde_json::from_str::<QualificationReport>(json).is_err());
    }
}
