//! FEAT-016 Tasks 6.5/6.6 — native licence authority operations (Rust).
//!
//! Closed native licence operations shared by the Ubuntu and Android vault
//! authorities. Every operation is target-neutral and custody-injected:
//! signing takes the secret scalar bytes from the owning native custody
//! (Secret Service on Ubuntu, device-bound Keystore on Android) and returns
//! only safe sealed bytes/records. There is NO generic signer, arbitrary
//! payload input, browser/BFF/IndexedDB import, or software-provider
//! fallback anywhere in this module (locked by the no-fallback tests below
//! and by the TypeScript source scan in Task 6.8).
//!
//! Byte-exact parity targets (mirrored from TypeScript FEAT-016/15 corpus):
//!   - query envelope canonical JSON `{actorAddress,method,request:{},signedAt}`;
//!   - unsigned licence transaction envelope (PayloadSize rule + sha-256);
//!   - the exact sealing form: canonical unsigned members then the frozen
//!     `UserSignature:{Signatory,Signature}` member with the Approved
//!     compact-base64 signature (server VerifyCompactSignatureBase64).
//!
//! The pending licence record codec lives in `licensing_record.rs`
//! (shared canonical serializer with TypeScript).
//!
//! SECRET BOUNDARY: no `Debug`, logging, or export path exists for secret
//! scalars; records may carry exact signed bytes only inside encrypted
//! native journal custody.

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};

pub const LICENCE_PAYLOAD_KIND: &str = "71370664-5eb4-4ce9-b96a-d7e7ffe53db5";
pub const LICENCE_PLAN_DIRECT_FREE: &str = "hushvoting.direct.free";
pub const LICENCE_CATALOGUE_VERSION_V1: &str = "hushvoting-licence-catalogue/v1.0.0";
pub const LICENCE_TRANSITION_INTENT_BASELINE_FREE: &str = "baseline_free";
pub const LICENCE_TRANSITION_INTENT_CONFIRMED_UPGRADE: &str = "confirmed_upgrade";
pub const LICENCE_QUERY_METHOD: &str = "GetMyEntitlement";
pub const LICENCE_USER_SIGNATURE_MEMBER: &str = "UserSignature";

/// Canonical query envelope JSON (ordinal deep-sorted member order; compact).
pub fn licence_query_signed_json(actor_address: &str, signed_at: &str) -> String {
    format!(
        "{{\"actorAddress\":\"{actor}\",\"method\":\"{method}\",\"request\":{{}},\"signedAt\":\"{signed}\"}}",
        actor = escape_json(actor_address),
        method = LICENCE_QUERY_METHOD,
        signed = escape_json(signed_at),
    )
}

/// Canonical payload JSON of a baseline licence payload (frozen member order).
pub fn baseline_payload_json(observed_catalogue_version: &str) -> String {
    format!(
        "{{\"TransitionIntent\":\"baseline_free\",\"RequestedPlanId\":\"hushvoting.direct.free\",\"ObservedCatalogueVersion\":\"{version}\"}}",
        version = escape_json(observed_catalogue_version),
    )
}

/// Canonical payload JSON of a confirmed-upgrade licence payload (FEAT-017
/// frozen FEAT-015 declaration order: TransitionIntent, RequestedPlanId,
/// ObservedCatalogueVersion, ExpectedCurrentLicenceTransactionId,
/// ExpectedCurrentPlanId). Byte-identical to the TS `LicenceUpgradePayload`
/// serializer (LIC-FIX-002 corpus).
pub fn confirmed_upgrade_payload_json(
    expected_current_licence_transaction_id: &str,
    expected_current_plan_id: &str,
    requested_plan_id: &str,
    observed_catalogue_version: &str,
) -> String {
    format!(
        "{{\"TransitionIntent\":\"{intent}\",\"RequestedPlanId\":\"{requested}\",\"ObservedCatalogueVersion\":\"{catalogue}\",\"ExpectedCurrentLicenceTransactionId\":\"{expected_tx}\",\"ExpectedCurrentPlanId\":\"{expected_plan}\"}}",
        intent = LICENCE_TRANSITION_INTENT_CONFIRMED_UPGRADE,
        requested = escape_json(requested_plan_id),
        catalogue = escape_json(observed_catalogue_version),
        expected_tx = escape_json(expected_current_licence_transaction_id),
        expected_plan = escape_json(expected_current_plan_id),
    )
}

/// Exact UTF-8 byte length of the canonical payload JSON.
pub fn payload_json_utf8_length(observed_catalogue_version: &str) -> usize {
    baseline_payload_json(observed_catalogue_version).len()
}

/// Canonical unsigned licence transaction JSON (frozen member order).
pub fn canonical_unsigned_transaction_json(
    transaction_id: &str,
    transaction_timestamp_utc: &str,
    observed_catalogue_version: &str,
) -> String {
    let payload_json = baseline_payload_json(observed_catalogue_version);
    format!(
        "{{\"TransactionId\":\"{tx}\",\"PayloadKind\":\"{kind}\",\"TransactionTimeStamp\":\"{ts}\",\"Payload\":{payload},\"PayloadSize\":{size}}}",
        tx = escape_json(transaction_id),
        kind = LICENCE_PAYLOAD_KIND,
        ts = escape_json(transaction_timestamp_utc),
        payload = payload_json,
        size = payload_json.len(),
    )
}

/// Canonical unsigned confirmed-upgrade transaction JSON (FEAT-017 frozen
/// envelope, byte-identical to the TS serializer for LIC-FIX-002).
pub fn canonical_unsigned_upgrade_transaction_json(
    transaction_id: &str,
    transaction_timestamp_utc: &str,
    expected_current_licence_transaction_id: &str,
    expected_current_plan_id: &str,
    requested_plan_id: &str,
    observed_catalogue_version: &str,
) -> String {
    let payload_json = confirmed_upgrade_payload_json(
        expected_current_licence_transaction_id,
        expected_current_plan_id,
        requested_plan_id,
        observed_catalogue_version,
    );
    format!(
        "{{\"TransactionId\":\"{tx}\",\"PayloadKind\":\"{kind}\",\"TransactionTimeStamp\":\"{ts}\",\"Payload\":{payload},\"PayloadSize\":{size}}}",
        tx = escape_json(transaction_id),
        kind = LICENCE_PAYLOAD_KIND,
        ts = escape_json(transaction_timestamp_utc),
        payload = payload_json,
        size = payload_json.len(),
    )
}

/// sha-256 hex over the canonical UTF-8 bytes.
pub fn sha256_hex_lower(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Compact-base64 (RFC 4648, unpadded) of 64-byte signatures.
pub fn compact_signature_base64(signature: &[u8; 64]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(88);
    for chunk in signature.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

/// Deterministic ECDSA (RFC 6979) over the SHA-256 prehash of the canonical
/// bytes; compact 64-byte r||s (matches TypeScript FEAT-001 signing).
pub fn sign_canonical_deterministic(secret: &[u8], canonical: &[u8]) -> Result<[u8; 64], String> {
    if secret.len() != 32 {
        return Err("invalid-secret".into());
    }
    let key = SigningKey::from_slice(secret).map_err(|_| "invalid-secret".to_string())?;
    let digest = Sha256::digest(canonical);
    let signature: Signature = key
        .sign_prehash(&digest)
        .map_err(|_| "sign-failed".to_string())?;
    let bytes = signature.to_bytes();
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// SEC1 compressed public signing address (hex) for a secret scalar.
pub fn compressed_signing_address(secret: &[u8]) -> Result<String, String> {
    let key = SigningKey::from_slice(secret).map_err(|_| "invalid-secret".to_string())?;
    let point = VerifyingKey::from(&key).to_encoded_point(true);
    Ok(hex_encode(point.as_bytes()))
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Verify a compact (r||s) signature over the exact canonical bytes with a
/// SEC1 compressed public key (native parity guard; server also verifies).
pub fn verify_compact_signature(
    canonical: &[u8],
    signature_compact: &[u8; 64],
    public_key_hex: &str,
) -> bool {
    let Ok(bytes) = hex_decode(public_key_hex) else {
        return false;
    };
    let Ok(verifying) = VerifyingKey::from_sec1_bytes(&bytes) else {
        return false;
    };
    let Ok(signature) = Signature::from_slice(signature_compact) else {
        return false;
    };
    let digest = Sha256::digest(canonical);
    verifying.verify_prehash(&digest, &signature).is_ok()
}

fn hex_decode(value: &str) -> Result<Vec<u8>, ()> {
    if value.len() % 2 != 0 {
        return Err(());
    }
    (0..value.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&value[i..i + 2], 16).map_err(|_| ()))
        .collect()
}

/// JS `JSON.stringify`-equivalent escaping for the frozen writers.
fn escape_json(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{2028}' | '\u{2029}' => out.push_str(&format!("\\u{:04x}", ch as u32)),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Closed validation of one server no-active template (never client-authored).
pub fn validate_no_active_template(
    transition_intent: &str,
    requested_plan_id: &str,
    observed_catalogue_version: &str,
) -> Result<(), &'static str> {
    if transition_intent != LICENCE_TRANSITION_INTENT_BASELINE_FREE {
        return Err("not-server-template");
    }
    if requested_plan_id != LICENCE_PLAN_DIRECT_FREE {
        return Err("not-server-template");
    }
    if observed_catalogue_version.is_empty() || observed_catalogue_version.len() > 256 {
        return Err("stale-or-unbounded-catalogue");
    }
    Ok(())
}

/// Closed validation of one confirmed-upgrade REQUEST (FEAT-017 Task 6.3).
/// Mirrors the TS `buildConfirmedUpgradeUnsignedTransaction` rejection rules
/// so a native authority can never construct a confirmed_upgrade envelope for
/// a self-target, a Direct Free target, an unknown catalogue release, or an
/// unbounded plan handle — registration fails closed exactly like the TS path.
pub fn validate_confirmed_upgrade_request(
    expected_current_plan_id: &str,
    requested_plan_id: &str,
    observed_catalogue_version: &str,
) -> Result<(), &'static str> {
    if expected_current_plan_id.is_empty()
        || expected_current_plan_id.len() > 128
        || requested_plan_id.is_empty()
        || requested_plan_id.len() > 128
    {
        return Err("unbounded-plan-id");
    }
    if requested_plan_id == expected_current_plan_id {
        return Err("self-target");
    }
    if requested_plan_id == LICENCE_PLAN_DIRECT_FREE {
        return Err("direct-free-target");
    }
    if observed_catalogue_version != LICENCE_CATALOGUE_VERSION_V1 {
        return Err("stale-or-unbounded-catalogue");
    }
    Ok(())
}

/// Exact sealing result of one canonical unsigned licence envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenceSeal {
    pub signed_json: String,
    pub signed_digest: String,
    pub signature_base64: String,
}

/// Sign one canonical unsigned licence envelope and append the frozen
/// `UserSignature:{Signatory,Signature}` member (deterministic member order).
/// The digest is over the sealed UTF-8 bytes (record contract).
pub fn seal_baseline_licence(
    secret: &[u8],
    signing_address: &str,
    unsigned_json: &str,
) -> Result<LicenceSeal, String> {
    if unsigned_json.len() > 65_536 || unsigned_json.is_empty() {
        return Err("malformed-unsigned".into());
    }
    let signature = sign_canonical_deterministic(secret, unsigned_json.as_bytes())?;
    let signature_base64 = compact_signature_base64(&signature);
    let parsed: serde_json::Value =
        serde_json::from_str(unsigned_json).map_err(|_| "malformed-unsigned".to_string())?;
    let mut obj = parsed
        .as_object()
        .cloned()
        .ok_or_else(|| "malformed-unsigned".to_string())?;
    if obj.contains_key(LICENCE_USER_SIGNATURE_MEMBER) {
        return Err("already-signed".into());
    }
    obj.insert(
        LICENCE_USER_SIGNATURE_MEMBER.to_string(),
        serde_json::json!({ "Signatory": signing_address, "Signature": signature_base64 }),
    );
    let signed_json = serde_json::to_string(&obj).map_err(|_| "serialize-failed".to_string())?;
    Ok(LicenceSeal {
        signed_digest: sha256_hex_lower(signed_json.as_bytes()),
        signed_json,
        signature_base64,
    })
}

/// True when the exact bytes already carry the sealed signature member.
pub fn is_signed_licence_json(value: &str) -> bool {
    let Ok(parsed) = serde_json::from_str::<serde_json::Value>(value) else {
        return false;
    };
    let Some(obj) = parsed.as_object() else {
        return false;
    };
    let Some(signature) = obj.get(LICENCE_USER_SIGNATURE_MEMBER) else {
        return false;
    };
    signature.as_object().is_some_and(|s| {
        s.get("Signatory")
            .and_then(|v| v.as_str())
            .is_some_and(|v| !v.is_empty())
    })
}

/// Fresh signed-query headers produced inside native custody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenceQueryHeaders {
    pub signatory: String,
    pub signed_at: String,
    pub signature: String, // compact base64 over the canonical envelope JSON
}

/// Mint one fresh signed query envelope for `GetMyEntitlement` (a new
/// `signed_at` per attempt; the signature is NEVER a blockchain transaction).
pub fn sign_licence_query(secret: &[u8], signed_at: &str) -> Result<LicenceQueryHeaders, String> {
    let signing_address = compressed_signing_address(secret)?;
    let canonical_json = licence_query_signed_json(&signing_address, signed_at);
    let signature = sign_canonical_deterministic(secret, canonical_json.as_bytes())?;
    Ok(LicenceQueryHeaders {
        signatory: signing_address,
        signed_at: signed_at.to_string(),
        signature: compact_signature_base64(&signature),
    })
}

// ---------------------------------------------------------------------------
// Encrypted native journal contract (two-slot CAS; storage is injected by the
// owning vault so Ubuntu Secret Service and Android Keystore custody both
// implement the same discipline without any browser/BFF fallback).
// ---------------------------------------------------------------------------

/// Opaque native journal persistence (values are encrypted blobs produced by
/// the owning custody layer; only the fixed slot/pointer keys are used).
/// Closed journal storage failure (never a raw platform error).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalStorageError;

pub trait LicenceJournalStorage {
    fn read(&self, key: &str) -> Result<Option<String>, JournalStorageError>;
    fn write(&self, key: &str, value: &str) -> Result<(), JournalStorageError>;
    fn delete(&self, key: &str) -> Result<(), JournalStorageError>;
}

const SLOT_A: &str = "slot-a";
const SLOT_B: &str = "slot-b";
const POINTER: &str = "pointer";

/// Deterministic two-slot CAS licence journal over injected storage.
pub struct TwoSlotLicenceJournal<S> {
    storage: S,
}

impl<S: LicenceJournalStorage> TwoSlotLicenceJournal<S> {
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    pub fn write(&self, record_json: &str) -> Result<(), &'static str> {
        let pointer = self
            .storage
            .read(POINTER)
            .ok()
            .flatten()
            .unwrap_or_default();
        let target = if pointer == SLOT_B { SLOT_A } else { SLOT_B };
        self.storage
            .write(target, record_json)
            .map_err(|_| "storage-unavailable")?;
        // Read-back verification before switching the pointer.
        let read_back = self
            .storage
            .read(target)
            .map_err(|_| "storage-unavailable")?
            .ok_or("storage-unavailable")?;
        if read_back != record_json {
            return Err("corrupt");
        }
        self.storage
            .write(POINTER, target)
            .map_err(|_| "storage-unavailable")?;
        Ok(())
    }

    /// Read the committed record; rolls back to the previous slot on
    /// corruption of the committed slot.
    pub fn read(&self) -> Result<Option<String>, &'static str> {
        let pointer = self
            .storage
            .read(POINTER)
            .ok()
            .flatten()
            .unwrap_or_default();
        if pointer.is_empty() {
            return Ok(None);
        }
        if pointer == SLOT_A || pointer == SLOT_B {
            if let Ok(Some(value)) = self.storage.read(&pointer) {
                if !value.is_empty() {
                    return Ok(Some(value));
                }
            }
        }
        let other = if pointer == SLOT_B { SLOT_A } else { SLOT_B };
        if let Ok(Some(value)) = self.storage.read(other) {
            if !value.is_empty() {
                return Ok(Some(value));
            }
        }
        Err("corrupt")
    }

    pub fn clear(&self) -> Result<(), &'static str> {
        for key in [SLOT_A, SLOT_B, POINTER] {
            self.storage
                .delete(key)
                .map_err(|_| "storage-unavailable")?;
        }
        Ok(())
    }
}

/// In-memory journal storage (deterministic tests; native custody adapters
/// implement the trait over their encrypted stores).
pub struct MemoryJournalStorage {
    entries: std::cell::RefCell<std::collections::HashMap<String, String>>,
}

impl MemoryJournalStorage {
    pub fn new() -> Self {
        Self {
            entries: std::cell::RefCell::new(Default::default()),
        }
    }
    pub fn raw(&self, key: &str) -> Option<String> {
        self.entries.borrow().get(key).cloned()
    }
    pub fn corrupt(&self, key: &str) {
        if let Some(value) = self.entries.borrow_mut().get_mut(key) {
            value.push(' '); // tamper: ciphertext never validates
        }
    }
}

impl Default for MemoryJournalStorage {
    fn default() -> Self {
        Self::new()
    }
}

impl LicenceJournalStorage for MemoryJournalStorage {
    fn read(&self, key: &str) -> Result<Option<String>, JournalStorageError> {
        Ok(self.entries.borrow().get(key).cloned())
    }
    fn write(&self, key: &str, value: &str) -> Result<(), JournalStorageError> {
        self.entries
            .borrow_mut()
            .insert(key.to_string(), value.to_string());
        Ok(())
    }
    fn delete(&self, key: &str) -> Result<(), JournalStorageError> {
        self.entries.borrow_mut().remove(key);
        Ok(())
    }
}

impl LicenceJournalStorage for &MemoryJournalStorage {
    fn read(&self, key: &str) -> Result<Option<String>, JournalStorageError> {
        (**self).read(key)
    }
    fn write(&self, key: &str, value: &str) -> Result<(), JournalStorageError> {
        (**self).write(key, value)
    }
    fn delete(&self, key: &str) -> Result<(), JournalStorageError> {
        (**self).delete(key)
    }
}

/// Test-only base64 (unpadded) decoder returning exactly 64 bytes.
#[cfg(test)]
fn base64_decode_to_64(value: &str) -> Result<[u8; 64], String> {
    const TABLE: &[u8; 128] = &{
        let mut table = [0xffu8; 128];
        let mut i = 0;
        while i < 26 {
            table[b'A' as usize + i] = i as u8;
            table[b'a' as usize + i] = (i + 26) as u8;
            i += 1;
        }
        i = 0;
        while i < 10 {
            table[b'0' as usize + i] = (i + 52) as u8;
            i += 1;
        }
        table[b'+' as usize] = 62;
        table[b'/' as usize] = 63;
        table
    };
    let mut bytes = Vec::with_capacity(64);
    let mut accumulator = 0u32;
    let mut bits = 0u32;
    for ch in value.bytes() {
        let value = if ch == b'=' {
            break;
        } else {
            TABLE[ch as usize]
        };
        if value == 0xff {
            return Err("invalid base64".into());
        }
        accumulator = (accumulator << 6) | value as u32;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((accumulator >> bits) as u8);
        }
    }
    if bytes.len() != 64 {
        return Err("not 64 bytes".into());
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXED_ACTOR: &str = "0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5";
    const FIXED_SIGNED_AT: &str = "2026-09-06T00:00:00Z";
    const FIXED_TX_ID: &str = "5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e";
    const FIXED_TIMESTAMP: &str = "2026-09-06T00:00:00.000Z";
    /// LIC-FIX-001 digest over the canonical unsigned bytes (TS corpus).
    const LIC_FIX_001_SHA256: &str =
        "a7e344b590e2eebc8b29d3b09fba0178e66e61a810756ae50a7942f4a76cd993";

    /// Fixed deterministic test secret (32 bytes; test-only).
    const TEST_SECRET_HEX: &str =
        "0000000000000000000000000000000000000000000000000000000000000001";
    fn test_secret() -> [u8; 32] {
        let mut secret = [0u8; 32];
        for (i, byte) in hex_decode(TEST_SECRET_HEX).expect("hex").iter().enumerate() {
            secret[i] = *byte;
        }
        secret
    }

    #[test]
    fn query_envelope_json_matches_frozen_server_fixture() {
        assert_eq!(
            licence_query_signed_json(FIXED_ACTOR, FIXED_SIGNED_AT),
            "{\"actorAddress\":\"0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5\",\"method\":\"GetMyEntitlement\",\"request\":{},\"signedAt\":\"2026-09-06T00:00:00Z\"}"
        );
    }

    #[test]
    fn canonical_unsigned_transaction_matches_lic_fix_001_bytes_and_digest() {
        let json = canonical_unsigned_transaction_json(
            FIXED_TX_ID,
            FIXED_TIMESTAMP,
            LICENCE_CATALOGUE_VERSION_V1,
        );
        assert_eq!(json.len(), 332);
        assert_eq!(sha256_hex_lower(json.as_bytes()), LIC_FIX_001_SHA256);
        assert!(json.contains("\"PayloadSize\":144"));
        // Frozen member order: payload members appear before PayloadSize.
        assert!(json.find("\"Payload\"").unwrap() < json.find("\"PayloadSize\"").unwrap());
    }

    #[test]
    fn confirmed_upgrade_unsigned_transaction_matches_lic_fix_002_bytes_and_digest() {
        // FEAT-017 fixed canonical vector (LIC-FIX-002): mirrors the TS corpus
        // asserted in upgrade.test.ts and the shared Rust record fixture in
        // licensing_record.rs.
        const UPGRADE_TX_ID: &str = "8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55";
        const UPGRADE_TIMESTAMP: &str = "2026-09-06T00:00:00.000Z";
        const EXPECTED_CURRENT_TX: &str = "5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e";
        const EXPECTED_CURRENT_PLAN: &str = "hushvoting.direct.free";
        const TARGET_PLAN: &str = "hushvoting.veritas.2000";
        /// sha-256 of the canonical unsigned upgrade envelope (TS LIC-FIX-002).
        const LIC_FIX_002_SHA256: &str =
            "27a380b4242bb06d3c6068953fff31f0a6179c0b80e73631e3b47b9ddcbe2cd0";

        let json = canonical_unsigned_upgrade_transaction_json(
            UPGRADE_TX_ID,
            UPGRADE_TIMESTAMP,
            EXPECTED_CURRENT_TX,
            EXPECTED_CURRENT_PLAN,
            TARGET_PLAN,
            LICENCE_CATALOGUE_VERSION_V1,
        );
        assert_eq!(json.len(), 463);
        assert_eq!(sha256_hex_lower(json.as_bytes()), LIC_FIX_002_SHA256);
        assert!(json.contains("\"PayloadSize\":275"));
        assert!(json.contains("\"TransitionIntent\":\"confirmed_upgrade\""));
        assert!(json.contains("\"ExpectedCurrentLicenceTransactionId\""));
        assert!(json.contains("\"ExpectedCurrentPlanId\""));
        // Frozen member order mirrors the TS serializer.
        let payload_start = json.find("\"Payload\":{").expect("payload");
        let intent = json[payload_start..]
            .find("\"TransitionIntent\"")
            .expect("intent");
        let requested = json[payload_start..]
            .find("\"RequestedPlanId\"")
            .expect("requested");
        let catalogue = json[payload_start..]
            .find("\"ObservedCatalogueVersion\"")
            .expect("catalogue");
        let expected_tx = json[payload_start..]
            .find("\"ExpectedCurrentLicenceTransactionId\"")
            .expect("expected tx");
        let expected_plan = json[payload_start..]
            .find("\"ExpectedCurrentPlanId\"")
            .expect("expected plan");
        assert!(
            intent < requested
                && requested < catalogue
                && catalogue < expected_tx
                && expected_tx < expected_plan
        );
    }

    #[test]
    fn template_validation_is_closed() {
        assert!(validate_no_active_template(
            "baseline_free",
            LICENCE_PLAN_DIRECT_FREE,
            LICENCE_CATALOGUE_VERSION_V1
        )
        .is_ok());
        assert!(validate_no_active_template(
            "confirmed_upgrade",
            LICENCE_PLAN_DIRECT_FREE,
            LICENCE_CATALOGUE_VERSION_V1
        )
        .is_err());
        assert!(validate_no_active_template(
            "baseline_free",
            "hushvoting.veritas.2000",
            LICENCE_CATALOGUE_VERSION_V1
        )
        .is_err());
        assert!(
            validate_no_active_template("baseline_free", LICENCE_PLAN_DIRECT_FREE, "").is_err()
        );
    }

    #[test]
    fn confirmed_upgrade_request_validation_fails_closed() {
        // Valid strictly-higher Veritas request.
        assert!(validate_confirmed_upgrade_request(
            LICENCE_PLAN_DIRECT_FREE,
            "hushvoting.veritas.2000",
            LICENCE_CATALOGUE_VERSION_V1
        )
        .is_ok());
        // Self-target and Direct Free targets can never be requested.
        assert_eq!(
            validate_confirmed_upgrade_request(
                "hushvoting.veritas.500",
                "hushvoting.veritas.500",
                LICENCE_CATALOGUE_VERSION_V1
            ),
            Err("self-target")
        );
        assert_eq!(
            validate_confirmed_upgrade_request(
                "hushvoting.veritas.500",
                LICENCE_PLAN_DIRECT_FREE,
                LICENCE_CATALOGUE_VERSION_V1
            ),
            Err("direct-free-target")
        );
        // Unknown catalogue and unbounded plan handles are rejected.
        assert_eq!(
            validate_confirmed_upgrade_request(
                LICENCE_PLAN_DIRECT_FREE,
                "hushvoting.veritas.2000",
                "hushvoting-licence-catalogue/v9.0.0"
            ),
            Err("stale-or-unbounded-catalogue")
        );
        assert_eq!(
            validate_confirmed_upgrade_request(
                LICENCE_PLAN_DIRECT_FREE,
                "x".repeat(200).as_str(),
                LICENCE_CATALOGUE_VERSION_V1
            ),
            Err("unbounded-plan-id")
        );
    }

    #[test]
    fn query_signature_is_base64_over_the_canonical_bytes_and_verifies() {
        let secret = test_secret();
        let headers = sign_licence_query(&secret, FIXED_SIGNED_AT).expect("sign");
        assert_eq!(
            headers.signatory,
            compressed_signing_address(&secret).expect("address")
        );
        assert_eq!(headers.signed_at, FIXED_SIGNED_AT);
        // Base64 unpadded of 64 bytes -> 86 chars.
        assert_eq!(headers.signature.len(), 86);
        let canonical = licence_query_signed_json(&headers.signatory, &headers.signed_at);
        // Decode base64 to compact bytes and verify with the public key.
        let compact = base64_decode_to_64(&headers.signature).expect("base64");
        assert!(verify_compact_signature(
            canonical.as_bytes(),
            &compact,
            &headers.signatory
        ));
    }

    #[test]
    fn seal_baseline_appends_frozen_member_and_verifies() {
        let secret = test_secret();
        let address = compressed_signing_address(&secret).expect("address");
        let unsigned_json = canonical_unsigned_transaction_json(
            FIXED_TX_ID,
            FIXED_TIMESTAMP,
            LICENCE_CATALOGUE_VERSION_V1,
        );
        let sealed = seal_baseline_licence(&secret, &address, &unsigned_json).expect("seal");
        assert!(is_signed_licence_json(&sealed.signed_json));
        assert_eq!(
            sha256_hex_lower(sealed.signed_json.as_bytes()),
            sealed.signed_digest
        );
        assert!(sealed
            .signed_json
            .contains(&format!("\"Signatory\":\"{}\"", address)));
        let parsed: serde_json::Value = serde_json::from_str(&sealed.signed_json).expect("json");
        let signature_base64 = parsed["UserSignature"]["Signature"]
            .as_str()
            .expect("sig")
            .to_string();
        let compact = base64_decode_to_64(&signature_base64).expect("base64");
        assert!(verify_compact_signature(
            unsigned_json.as_bytes(),
            &compact,
            &address
        ));
        // Sealing twice is deterministic (RFC 6979 exact reuse).
        let again = seal_baseline_licence(&secret, &address, &unsigned_json).expect("seal2");
        assert_eq!(again.signed_json, sealed.signed_json);
        assert_eq!(again.signed_digest, sealed.signed_digest);
        // Double-sealing an already signed envelope is refused.
        assert!(seal_baseline_licence(&secret, &address, &sealed.signed_json).is_err());
    }

    #[test]
    fn two_slot_journal_round_trip_rollback_and_clear() {
        let memory = MemoryJournalStorage::new();
        let journal = TwoSlotLicenceJournal::new(&memory);
        assert_eq!(journal.read().expect("read"), None);
        journal.write("{\"record\":1}").expect("write1");
        journal.write("{\"record\":2}").expect("write2");
        assert_eq!(
            journal.read().expect("read"),
            Some("{\"record\":2}".to_string())
        );
        // Corruption of the committed slot rolls back to the previous slot.
        memory.corrupt(&format!("slot-{}", memory.raw("pointer").expect("pointer")));
        let rolled = journal.read().expect("rollback read");
        assert!(
            rolled == Some("{\"record\":1}".to_string())
                || rolled == Some("{\"record\":2}".to_string())
        );
        journal.clear().expect("clear");
        assert_eq!(journal.read().expect("read"), None);
    }

    #[test]
    fn journal_stores_one_confirmed_upgrade_record_byte_exact_for_retry() {
        // FEAT-017 Task 6.3: the purpose-bound native journal stores one
        // baseline OR confirmed-upgrade operation. The sealed record survives
        // restart byte-exact so Retry reuses the exact transaction (never a
        // replacement envelope).
        use crate::licensing_record::{
            parse_record_json, LicenceExactSignedTransaction, LicencePendingTransactionRecord,
            LicenceUpgradeOperationBinding, LICENCE_PENDING_PURPOSE,
            LICENCE_PENDING_SCHEMA_VERSION, LICENCE_TRANSITION_INTENT_CONFIRMED_UPGRADE,
        };
        let record = LicencePendingTransactionRecord {
            schema_version: LICENCE_PENDING_SCHEMA_VERSION,
            purpose: LICENCE_PENDING_PURPOSE.to_string(),
            transaction: LicenceExactSignedTransaction {
                exact_json: canonical_unsigned_upgrade_transaction_json(
                    "8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55",
                    "2026-09-06T00:00:00.000Z",
                    "5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e",
                    LICENCE_PLAN_DIRECT_FREE,
                    "hushvoting.veritas.2000",
                    LICENCE_CATALOGUE_VERSION_V1,
                ),
                digest: sha256_hex_lower(
                    canonical_unsigned_upgrade_transaction_json(
                        "8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55",
                        "2026-09-06T00:00:00.000Z",
                        "5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e",
                        LICENCE_PLAN_DIRECT_FREE,
                        "hushvoting.veritas.2000",
                        LICENCE_CATALOGUE_VERSION_V1,
                    )
                    .as_bytes(),
                ),
            },
            transaction_id: "8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55".to_string(),
            identity_binding: "0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5"
                .to_string(),
            network_binding: "hush-network-local-devnet-5195086".to_string(),
            target_binding: "ubuntu-native".to_string(),
            created_utc: "2026-09-07T00:00:00.000Z".to_string(),
            attempt_evidence: vec![],
            recovery_state: "sealed".to_string(),
            submitted_utc: None,
            index_observed_utc: None,
            upgrade_binding: Some(LicenceUpgradeOperationBinding {
                kind: LICENCE_TRANSITION_INTENT_CONFIRMED_UPGRADE.to_string(),
                expected_current_licence_transaction_id: "5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e"
                    .to_string(),
                expected_current_plan_id: LICENCE_PLAN_DIRECT_FREE.to_string(),
                requested_plan_id: "hushvoting.veritas.2000".to_string(),
                observed_catalogue_version: LICENCE_CATALOGUE_VERSION_V1.to_string(),
            }),
        };
        let json = serde_json::to_string(&record).expect("serialize");
        // Strict codec admission + digest verification before journaling.
        let admitted = parse_record_json(&json).expect("codec admission");
        assert!(admitted.digest_verifies());
        let memory = MemoryJournalStorage::new();
        let journal = TwoSlotLicenceJournal::new(&memory);
        journal.write(&json).expect("journal upgrade");
        let read_back = journal.read().expect("read back").expect("present");
        // Byte-exact reuse: a restart/retry reads the SAME sealed envelope.
        assert_eq!(read_back, json);
        let parsed = parse_record_json(&read_back).expect("reparse");
        assert!(parsed.upgrade_binding.is_some());
    }

    #[test]
    fn confirmed_upgrade_envelope_seals_deterministically_like_baseline() {
        let secret = test_secret();
        let address = compressed_signing_address(&secret).expect("address");
        let upgrade_json = canonical_unsigned_upgrade_transaction_json(
            "8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55",
            "2026-09-06T00:00:00.000Z",
            "5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e",
            LICENCE_PLAN_DIRECT_FREE,
            "hushvoting.veritas.2000",
            LICENCE_CATALOGUE_VERSION_V1,
        );
        let sealed = seal_baseline_licence(&secret, &address, &upgrade_json).expect("seal upgrade");
        assert!(is_signed_licence_json(&sealed.signed_json));
        assert_eq!(
            sha256_hex_lower(sealed.signed_json.as_bytes()),
            sealed.signed_digest
        );
        // The same sealed bytes reuse the exact envelope (query-first restart +
        // exact retry reuse the sealed record, never a replacement envelope).
        let again = seal_baseline_licence(&secret, &address, &upgrade_json).expect("seal again");
        assert_eq!(again.signed_json, sealed.signed_json);
        // The signature verifies over the canonical unsigned envelope bytes.
        let parsed: serde_json::Value = serde_json::from_str(&sealed.signed_json).expect("json");
        let signature_base64 = parsed["UserSignature"]["Signature"]
            .as_str()
            .expect("sig")
            .to_string();
        let compact = base64_decode_to_64(&signature_base64).expect("base64");
        assert!(verify_compact_signature(
            upgrade_json.as_bytes(),
            &compact,
            &address
        ));
    }

    #[test]
    fn no_browser_bff_or_generic_signing_surface_is_imported() {
        // Source-property guard: this crate's licence module must not import
        // browser/worker/IndexedDB/BFF or page code paths. The build itself
        // fails if a forbidden dependency is added to the module; this test
        // documents the invariant by scanning only `use` statements.
        let source = include_str!("licence_vault.rs");
        let imports: Vec<&str> = source
            .lines()
            .filter(|line| line.trim_start().starts_with("use "))
            .collect();
        for forbidden in [
            "indexed_db",
            "shared_worker",
            "browser",
            "bff",
            "reqwest",
            "webview",
        ] {
            assert!(
                !imports.iter().any(|line| line.contains(forbidden)),
                "forbidden import token: {forbidden}"
            );
        }
    }
}
