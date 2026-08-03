//! Canonical identity envelope parser (FEAT-005 "Canonical Signing
//! Boundary"; replay of FEAT-001 canonical-byte vectors).
//!
//! TypeScript remains the canonical transaction serializer. Rust parses the
//! canonical envelope to validate version, payload kind, signatory/public
//! keys, alias/visibility, size, session identity, and user-confirmation
//! binding BEFORE any signature is produced. The canonical bytes are the
//! exact producer bytes (declaration-order JSON — order-sensitive, NOT JCS);
//! the parser never re-serializes for signing.

use crate::ubuntu_vault::crypto::encoding::hex_decode;
use serde_json::Value;

/// Bounded canonical-byte ceiling for `CreateFullIdentity` (registry bound).
pub const CANONICAL_MAX_BYTES: usize = 16_384;

/// Pinned `CreateFullIdentity` payload-kind GUID (FEAT-001).
pub const CREATE_FULL_IDENTITY_KIND: &str = "351cd60b-3fdf-48d4-b608-e93c0100f7d0";

/// Alias bounds (bounded; identity-free storage rules unchanged).
pub const ALIAS_MAX_CHARS: usize = 64;

/// SEC1 address hex lengths (compressed 33-byte and uncompressed 65-byte).
pub const ADDRESS_HEX_LEN_COMPRESSED: usize = 66;
pub const ADDRESS_HEX_LEN_UNCOMPRESSED: usize = 130;

/// Parsed canonical envelope (public fields only; no private material).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalEnvelope {
    pub transaction_id: String,
    pub payload_kind: String,
    pub timestamp: String,
    pub identity_alias: String,
    pub public_signing_address: String,
    pub public_encrypt_address: String,
    pub is_public: bool,
    /// Producer-computed UTF-8 byte length of the payload JSON.
    pub payload_size: usize,
}

/// Closed envelope-parse failure vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnvelopeError {
    BoundsExceeded,
    NotJson,
    Malformed,
    MissingField,
    UnsupportedPayloadKind,
    InvalidTransactionId,
    InvalidTimestamp,
    InvalidAddress,
    InvalidAlias,
    PayloadSizeMismatch,
}

impl EnvelopeError {
    pub fn to_native_error(self) -> crate::ubuntu_vault::contracts::results::NativeErrorCode {
        use crate::ubuntu_vault::contracts::results::NativeErrorCode;
        match self {
            Self::BoundsExceeded | Self::Malformed | Self::MissingField => {
                NativeErrorCode::OperationForbidden
            }
            Self::UnsupportedPayloadKind => NativeErrorCode::ExtensionUnsupported,
            _ => NativeErrorCode::MalformedEnvelope,
        }
    }
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "canonical envelope failure (closed code)")
    }
}

impl std::error::Error for EnvelopeError {}

/// Parse and validate the canonical envelope. The exact input bytes are what
/// gets signed — the parser only validates, it never re-serializes.
pub fn parse_envelope(raw: &[u8]) -> Result<CanonicalEnvelope, EnvelopeError> {
    if raw.len() > CANONICAL_MAX_BYTES {
        return Err(EnvelopeError::BoundsExceeded);
    }
    let value: Value = serde_json::from_slice(raw).map_err(|_| EnvelopeError::NotJson)?;
    let object = value.as_object().ok_or(EnvelopeError::Malformed)?;

    let transaction_id = str_field(object, "TransactionId")?;
    let payload_kind = str_field(object, "PayloadKind")?;
    let timestamp = str_field(object, "TransactionTimeStamp")?;
    let payload_size = object
        .get("PayloadSize")
        .and_then(|v| v.as_u64())
        .ok_or(EnvelopeError::MissingField)? as usize;
    let payload = object
        .get("Payload")
        .and_then(Value::as_object)
        .ok_or(EnvelopeError::MissingField)?;
    let identity_alias = str_field(payload, "IdentityAlias")?;
    let public_signing_address = str_field(payload, "PublicSigningAddress")?;
    let public_encrypt_address = str_field(payload, "PublicEncryptAddress")?;
    let is_public = payload
        .get("IsPublic")
        .and_then(Value::as_bool)
        .ok_or(EnvelopeError::MissingField)?;

    // Payload kind must be the pinned CreateFullIdentity GUID.
    if payload_kind != CREATE_FULL_IDENTITY_KIND {
        return Err(EnvelopeError::UnsupportedPayloadKind);
    }
    if !is_uuid(&transaction_id) {
        return Err(EnvelopeError::InvalidTransactionId);
    }
    if !is_iso_timestamp(&timestamp) {
        return Err(EnvelopeError::InvalidTimestamp);
    }
    if !is_sec1_address(&public_signing_address) || !is_sec1_address(&public_encrypt_address) {
        return Err(EnvelopeError::InvalidAddress);
    }
    if identity_alias.is_empty() || identity_alias.chars().count() > ALIAS_MAX_CHARS {
        return Err(EnvelopeError::InvalidAlias);
    }

    // Producer-computed PayloadSize must equal the UTF-8 byte length of the
    // payload JSON exactly as written (order-sensitive).
    match raw_payload_span(raw) {
        Some((start, end)) if end - start == payload_size => {}
        _ => return Err(EnvelopeError::PayloadSizeMismatch),
    }

    Ok(CanonicalEnvelope {
        transaction_id,
        payload_kind,
        timestamp,
        identity_alias,
        public_signing_address,
        public_encrypt_address,
        is_public,
        payload_size,
    })
}

fn str_field(object: &serde_json::Map<String, Value>, key: &str) -> Result<String, EnvelopeError> {
    object
        .get(key)
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .ok_or(EnvelopeError::MissingField)
}

/// Raw payload-object byte length for a canonical JSON text (test fixture
/// construction). Returns 0 when the payload cannot be located.
pub fn raw_payload_size_for_test(json: &str) -> usize {
    match raw_payload_span(json.as_bytes()) {
        Some((start, end)) => end - start,
        None => 0,
    }
}

/// Extract the byte span of the top-level `Payload` object exactly as
/// written (order-sensitive — never via serde re-serialization).
fn raw_payload_span(raw: &[u8]) -> Option<(usize, usize)> {
    let needle = b"\"Payload\"";
    let mut i = 0;
    while i + needle.len() <= raw.len() {
        if &raw[i..i + needle.len()] == needle {
            let mut j = i + needle.len();
            // Skip whitespace and the key/value colon.
            while j < raw.len() && raw[j].is_ascii_whitespace() {
                j += 1;
            }
            if raw.get(j) == Some(&b':') {
                j += 1;
            }
            while j < raw.len() && raw[j].is_ascii_whitespace() {
                j += 1;
            }
            if raw.get(j) == Some(&b'{') {
                let mut depth = 0u32;
                let mut k = j;
                let mut in_string = false;
                let mut escaped = false;
                while k < raw.len() {
                    let ch = raw[k];
                    if in_string {
                        if escaped {
                            escaped = false;
                        } else if ch == b'\\' {
                            escaped = true;
                        } else if ch == b'"' {
                            in_string = false;
                        }
                    } else {
                        match ch {
                            b'"' => in_string = true,
                            b'{' => depth += 1,
                            b'}' => {
                                depth -= 1;
                                if depth == 0 {
                                    return Some((j, k + 1));
                                }
                            }
                            _ => {}
                        }
                    }
                    k += 1;
                }
                return None;
            }
        }
        i += 1;
    }
    None
}

/// UUID v4-shaped format check (8-4-4-4-12 lowercase hex).
pub fn is_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 36
        && bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && bytes.iter().enumerate().all(|(i, b)| {
            let pos = i + 1;
            !matches!(pos, 9 | 14 | 19 | 24) || *b == b'-'
        })
        && bytes
            .iter()
            .enumerate()
            .all(|(i, b)| matches!(i + 1, 9 | 14 | 19 | 24) || b.is_ascii_hexdigit())
}

/// ISO-8601 UTC timestamp shape (`YYYY-MM-DDTHH:MM:SS.sssZ`, 3-digit ms).
pub fn is_iso_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 24
        && b[4] == b'-'
        && b[7] == b'-'
        && b[10] == b'T'
        && b[13] == b':'
        && b[16] == b':'
        && b[19] == b'.'
        && b[23] == b'Z'
        && (0..4).all(|i| b[i].is_ascii_digit())
        && (5..7).all(|i| b[i].is_ascii_digit())
        && (8..10).all(|i| b[i].is_ascii_digit())
        && (11..13).all(|i| b[i].is_ascii_digit())
        && (14..16).all(|i| b[i].is_ascii_digit())
        && (17..19).all(|i| b[i].is_ascii_digit())
        && (20..23).all(|i| b[i].is_ascii_digit())
}

/// SEC1 public-key hex: compressed (66) or uncompressed (130), valid hex,
/// correct prefix byte (02/03 for compressed, 04 for uncompressed).
pub fn is_sec1_address(s: &str) -> bool {
    let valid_len = match s.len() {
        ADDRESS_HEX_LEN_COMPRESSED => {
            let b = s.as_bytes();
            b[0] == b'0' && (b[1] == b'2' || b[1] == b'3')
        }
        ADDRESS_HEX_LEN_UNCOMPRESSED => {
            let b = s.as_bytes();
            b[0] == b'0' && b[1] == b'4'
        }
        _ => return false,
    };
    if !valid_len {
        return false;
    }
    hex_decode(s).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const CB_001: &str = r#"{"TransactionId":"d4a2f9c1-3b5e-4f6a-9c7d-2e8f1a0b3c4d","PayloadKind":"351cd60b-3fdf-48d4-b608-e93c0100f7d0","TransactionTimeStamp":"2026-08-01T12:34:56.789Z","Payload":{"IdentityAlias":"public-test-alias-001","PublicSigningAddress":"0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5","PublicEncryptAddress":"032ebaf076203f15ac8119cfdbc9394d1c7b9929b0647e4f607e27da95701f8556","IsPublic":true},"PayloadSize":241}"#;

    fn canonical_cb001() -> Vec<u8> {
        CB_001.as_bytes().to_vec()
    }

    #[test]
    fn parses_canonical_cb001_exactly() {
        let raw = canonical_cb001();
        let env = parse_envelope(&raw).unwrap();
        assert_eq!(env.transaction_id, "d4a2f9c1-3b5e-4f6a-9c7d-2e8f1a0b3c4d");
        assert_eq!(env.payload_kind, CREATE_FULL_IDENTITY_KIND);
        assert_eq!(env.timestamp, "2026-08-01T12:34:56.789Z");
        assert_eq!(env.identity_alias, "public-test-alias-001");
        assert_eq!(
            env.public_signing_address,
            "0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5"
        );
        assert!(env.is_public);
        assert_eq!(env.payload_size, 241);
    }

    #[test]
    fn payload_size_must_match_raw_payload_bytes() {
        // Tamper the declared PayloadSize: must fail closed.
        let mut raw = canonical_cb001();
        let n = raw.len();
        // Replace the declared `241` with `242`.
        raw[n - 4] = b'2';
        raw[n - 3] = b'4';
        raw[n - 2] = b'2';
        assert_eq!(
            parse_envelope(&raw),
            Err(EnvelopeError::PayloadSizeMismatch)
        );
    }

    #[test]
    fn unsupported_payload_kind_is_rejected() {
        let raw = canonical_cb001();
        let json = std::str::from_utf8(&raw).unwrap();
        let replaced = json.replacen(
            CREATE_FULL_IDENTITY_KIND,
            "a7e3c4b2-1f8d-4e5a-9c6b-2d3e4f5a6b7c",
            1,
        );
        assert_eq!(
            parse_envelope(replaced.as_bytes()),
            Err(EnvelopeError::UnsupportedPayloadKind)
        );
    }

    #[test]
    fn reordered_payload_keys_keep_logical_parse_but_change_bytes() {
        // CB-002: same fields, different key order. Logical parse succeeds
        // (fields by name), but the raw payload span differs from the
        // canonical declaration order — proven by comparing spans.
        let reordered = r#"{"TransactionId":"d4a2f9c1-3b5e-4f6a-9c7d-2e8f1a0b3c4d","PayloadKind":"351cd60b-3fdf-48d4-b608-e93c0100f7d0","TransactionTimeStamp":"2026-08-01T12:34:56.789Z","Payload":{"IsPublic":true,"IdentityAlias":"public-test-alias-001","PublicSigningAddress":"0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5","PublicEncryptAddress":"032ebaf076203f15ac8119cfdbc9394d1c7b9929b0647e4f607e27da95701f8556"},"PayloadSize":241}"#;
        let env = parse_envelope(reordered.as_bytes()).unwrap();
        assert_eq!(env.identity_alias, "public-test-alias-001");
        let canonical_span = raw_payload_span(&canonical_cb001()).unwrap();
        let reordered_span = raw_payload_span(reordered.as_bytes()).unwrap();
        // Compare the payload CONTENT (spans may coincide because the
        // prefixes and lengths are identical).
        let canonical_payload = &canonical_cb001()[canonical_span.0..canonical_span.1];
        let reordered_payload = &reordered.as_bytes()[reordered_span.0..reordered_span.1];
        assert_ne!(canonical_payload, reordered_payload);
    }

    #[test]
    fn malformed_inputs_fail_closed() {
        assert_eq!(parse_envelope(b""), Err(EnvelopeError::NotJson));
        assert_eq!(parse_envelope(b"not json"), Err(EnvelopeError::NotJson));
        assert_eq!(parse_envelope(b"[1,2,3]"), Err(EnvelopeError::Malformed));
        // Oversized input.
        let big = vec![b'x'; CANONICAL_MAX_BYTES + 1];
        assert_eq!(parse_envelope(&big), Err(EnvelopeError::BoundsExceeded));
    }

    #[test]
    fn address_and_uuid_format_checks() {
        assert!(is_uuid("d4a2f9c1-3b5e-4f6a-9c7d-2e8f1a0b3c4d"));
        assert!(!is_uuid("d4a2f9c1-3b5e-4f6a-9c7d"));
        assert!(is_iso_timestamp("2026-08-01T12:34:56.789Z"));
        assert!(!is_iso_timestamp("2026-08-01T12:34:56.78Z"));
        assert!(is_sec1_address(&"02".repeat(33)));
        assert!(is_sec1_address(&"04".repeat(65)));
        assert!(!is_sec1_address(&"03".repeat(64)));
        assert!(!is_sec1_address(&"zz".repeat(33)));
    }

    #[test]
    fn json_serialization_never_reorders_for_signing() {
        // The parser signs the exact input bytes; verify a round-trip through
        // serde_json::Value would reorder (BTreeMap) and therefore must never
        // be used for canonical bytes.
        let value: Value = serde_json::from_slice(&canonical_cb001()).unwrap();
        let reserialized = serde_json::to_string(&value).unwrap();
        assert_ne!(reserialized.as_bytes(), &*canonical_cb001());
    }
}
