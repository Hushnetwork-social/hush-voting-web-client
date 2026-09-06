//! FEAT-016 Task 2.3/2.4 — purpose-bound pending licence transaction record (Rust).
//!
//! Rust mirror of `src/lib/licensing/pending-transaction.ts`. The canonical
//! JSON serialization order and field names are frozen and shared byte-for-byte
//! with the TypeScript codec; cross-language parity is proven by the fixture
//! test below (exact-string equality against the shared canonical string).
//!
//! SECRET BOUNDARY: `transaction.exact_json` carries exact signed licence
//! transaction bytes and must exist ONLY inside approved encrypted native
//! custody (Ubuntu vault / Android Keystore journals). WebView/bridge code
//! never receives this record's exact bytes.
//!
//! Normative source: FEAT-016 FeatureDescription "Licence Transaction and
//! Pending Journal"; FEAT-011 sealed pending-store discipline.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const LICENCE_PENDING_PURPOSE: &str = "pending_licence_transaction";
pub const LICENCE_PENDING_SCHEMA_VERSION: u32 = 1;
pub const LICENCE_PENDING_MAX_JSON_BYTES: usize = 65_536;
pub const LICENCE_PENDING_MAX_ATTEMPT_EVIDENCE: usize = 64;

const TARGET_BINDINGS: [&str; 3] = ["web-sharedworker", "ubuntu-native", "android-native"];
const RECOVERY_STATES: [&str; 7] = [
    "sealed",
    "waitingAccepted",
    "waitingPending",
    "confirmedIndexed",
    "superseded",
    "retired",
    "unrecoverable",
];
const ATTEMPT_OUTCOMES: [&str; 6] = [
    "accepted",
    "pending",
    "alreadyExists",
    "uncertain",
    "terminalRejected",
    "superseded",
];

/// Exact signed transaction (sealed): canonical JSON + lowercase sha-256 hex digest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicenceExactSignedTransaction {
    pub exact_json: String,
    pub digest: String,
}

/// One bounded admission/reconciliation attempt.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicencePendingAttemptEvidence {
    pub at: String, // ISO-8601 UTC
    pub outcome: String,
}

/// Purpose-bound sealed pending licence record.
///
/// Field declaration order IS the canonical serialization order shared with
/// TypeScript: schemaVersion, purpose, transaction, transactionId,
/// identityBinding, networkBinding, targetBinding, createdUtc,
/// attemptEvidence, recoveryState, then optional submittedUtc /
/// indexObservedUtc (absent when None).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LicencePendingTransactionRecord {
    pub schema_version: u32,
    pub purpose: String,
    pub transaction: LicenceExactSignedTransaction,
    pub transaction_id: String,
    pub identity_binding: String,
    pub network_binding: String,
    pub target_binding: String,
    pub created_utc: String,
    pub attempt_evidence: Vec<LicencePendingAttemptEvidence>,
    pub recovery_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub submitted_utc: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_observed_utc: Option<String>,
}

fn is_bounded_string(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max
}

fn is_iso_utc(value: &str) -> bool {
    let ok_len = !value.is_empty() && value.len() <= 64;
    if !ok_len {
        return false;
    }
    // ISO-8601 UTC with optional .fff milliseconds and trailing Z.
    if !value.ends_with('Z') {
        return false;
    }
    let body = &value[..value.len() - 1];
    let parts: Vec<&str> = body.split('T').collect();
    if parts.len() != 2 {
        return false;
    }
    let date_ok = parts[0].len() == 10
        && parts[0].as_bytes().get(4) == Some(&b'-')
        && parts[0].as_bytes().get(7) == Some(&b'-');
    let time_ok = parts[1].len() >= 8
        && parts[1].as_bytes().get(2) == Some(&b':')
        && parts[1].as_bytes().get(5) == Some(&b':');
    date_ok && time_ok
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn sha256_hex_lower(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

impl LicencePendingTransactionRecord {
    /// Recompute and compare the sha-256 digest of the exact bytes.
    pub fn digest_verifies(&self) -> bool {
        self.transaction.digest == sha256_hex_lower(self.transaction.exact_json.as_bytes())
    }

    /// Strict validation mirroring the TypeScript parser (data, not panics).
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != LICENCE_PENDING_SCHEMA_VERSION {
            return Err("schemaVersion mismatch".into());
        }
        if self.purpose != LICENCE_PENDING_PURPOSE {
            return Err("purpose mismatch".into());
        }
        if !is_bounded_string(&self.transaction.exact_json, LICENCE_PENDING_MAX_JSON_BYTES) {
            return Err("transaction.exactJson out of bounds".into());
        }
        if !is_sha256_hex(&self.transaction.digest) || !self.digest_verifies() {
            return Err("transaction.digest mismatch".into());
        }
        if !is_bounded_string(&self.transaction_id, 128) {
            return Err("transactionId out of bounds".into());
        }
        if !is_bounded_string(&self.identity_binding, 128)
            || !is_bounded_string(&self.network_binding, 128)
        {
            return Err("binding out of bounds".into());
        }
        if !TARGET_BINDINGS.contains(&self.target_binding.as_str()) {
            return Err("unknown targetBinding".into());
        }
        if !is_iso_utc(&self.created_utc) {
            return Err("createdUtc not ISO-8601 UTC".into());
        }
        if let Some(submitted) = &self.submitted_utc {
            if !is_iso_utc(submitted) {
                return Err("submittedUtc not ISO-8601 UTC".into());
            }
        }
        if let Some(indexed) = &self.index_observed_utc {
            if !is_iso_utc(indexed) {
                return Err("indexObservedUtc not ISO-8601 UTC".into());
            }
        }
        if !RECOVERY_STATES.contains(&self.recovery_state.as_str()) {
            return Err("unknown recoveryState".into());
        }
        if self.attempt_evidence.len() > LICENCE_PENDING_MAX_ATTEMPT_EVIDENCE {
            return Err("attemptEvidence out of bounds".into());
        }
        for attempt in &self.attempt_evidence {
            if !is_iso_utc(&attempt.at) || !ATTEMPT_OUTCOMES.contains(&attempt.outcome.as_str()) {
                return Err("malformed attemptEvidence".into());
            }
        }
        Ok(())
    }
}

/// Strict parse: deserialize then validate (mirrors TypeScript parser).
pub fn parse_record_json(json: &str) -> Result<LicencePendingTransactionRecord, String> {
    let record: LicencePendingTransactionRecord =
        serde_json::from_str(json).map_err(|e| format!("deserialize failed: {e}"))?;
    record.validate()?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared canonical fixture (must equal the TypeScript-produced string
    /// asserted in `pending-transaction.test.ts` byte-for-byte).
    const SHARED_FIXTURE_EXPECTED_JSON: &str = r#"{"schemaVersion":1,"purpose":"pending_licence_transaction","transaction":{"exactJson":"{\"TransactionId\":\"5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e\",\"PayloadKind\":\"71370664-5eb4-4ce9-b96a-d7e7ffe53db5\",\"TransactionTimeStamp\":\"2026-09-06T00:00:00.000Z\",\"Payload\":{\"TransitionIntent\":\"baseline_free\",\"RequestedPlanId\":\"hushvoting.direct.free\",\"ObservedCatalogueVersion\":\"hushvoting-licence-catalogue/v1.0.0\"},\"PayloadSize\":144}","digest":"a7e344b590e2eebc8b29d3b09fba0178e66e61a810756ae50a7942f4a76cd993"},"transactionId":"5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e","identityBinding":"0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5","networkBinding":"hush-network-local-devnet-5195086","targetBinding":"web-sharedworker","createdUtc":"2026-09-06T00:00:00.000Z","attemptEvidence":[{"at":"2026-09-06T00:00:01.000Z","outcome":"accepted"}],"recoveryState":"waitingAccepted","submittedUtc":"2026-09-06T00:00:01.000Z"}"#;

    fn fixture() -> LicencePendingTransactionRecord {
        LicencePendingTransactionRecord {
            schema_version: LICENCE_PENDING_SCHEMA_VERSION,
            purpose: LICENCE_PENDING_PURPOSE.to_string(),
            transaction: LicenceExactSignedTransaction {
                exact_json: r#"{"TransactionId":"5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e","PayloadKind":"71370664-5eb4-4ce9-b96a-d7e7ffe53db5","TransactionTimeStamp":"2026-09-06T00:00:00.000Z","Payload":{"TransitionIntent":"baseline_free","RequestedPlanId":"hushvoting.direct.free","ObservedCatalogueVersion":"hushvoting-licence-catalogue/v1.0.0"},"PayloadSize":144}"#.to_string(),
                digest: "a7e344b590e2eebc8b29d3b09fba0178e66e61a810756ae50a7942f4a76cd993".to_string(),
            },
            transaction_id: "5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e".to_string(),
            identity_binding: "0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5".to_string(),
            network_binding: "hush-network-local-devnet-5195086".to_string(),
            target_binding: "web-sharedworker".to_string(),
            created_utc: "2026-09-06T00:00:00.000Z".to_string(),
            attempt_evidence: vec![LicencePendingAttemptEvidence {
                at: "2026-09-06T00:00:01.000Z".to_string(),
                outcome: "accepted".to_string(),
            }],
            recovery_state: "waitingAccepted".to_string(),
            submitted_utc: Some("2026-09-06T00:00:01.000Z".to_string()),
            index_observed_utc: None,
        }
    }

    #[test]
    fn serialization_matches_shared_canonical_fixture_byte_for_byte() {
        let record = fixture();
        let json = serde_json::to_string(&record).expect("serialize");
        assert_eq!(json, SHARED_FIXTURE_EXPECTED_JSON);
    }

    #[test]
    fn parse_round_trip_and_digest_verification_pass() {
        let parsed = parse_record_json(SHARED_FIXTURE_EXPECTED_JSON).expect("parse fixture");
        assert_eq!(parsed, fixture());
        assert!(parsed.digest_verifies());
        assert!(parsed.validate().is_ok());
    }

    #[test]
    fn tampered_digest_and_wrong_purpose_are_rejected() {
        let mut tampered_digest = fixture();
        tampered_digest.transaction.digest =
            "a7e344b590e2eebc8b29d3b09fba0178e66e61a810756ae50a7942f4a76cd994".to_string();
        assert!(tampered_digest.validate().is_err());
        assert!(!tampered_digest.digest_verifies());

        let mut wrong_purpose = fixture();
        wrong_purpose.purpose = "pending_identity_transaction".to_string();
        assert!(wrong_purpose.validate().is_err());

        let mut bad_state = fixture();
        bad_state.recovery_state = "not-a-state".to_string();
        assert!(bad_state.validate().is_err());
    }

    #[test]
    fn identity_and_licence_purposes_cannot_alias() {
        assert_eq!(LICENCE_PENDING_PURPOSE, "pending_licence_transaction");
        // Distinct from the FEAT-011 identity convergence purpose vocabulary.
        assert_ne!(LICENCE_PENDING_PURPOSE, "pending_identity_record");
        assert_ne!(LICENCE_PENDING_PURPOSE, "sealed-pending");
    }

    #[test]
    fn malformed_json_fails_closed() {
        assert!(parse_record_json("not json").is_err());
        assert!(parse_record_json(r#"{"schemaVersion":1}"#).is_err());
    }
}
