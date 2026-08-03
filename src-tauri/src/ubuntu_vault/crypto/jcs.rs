//! RFC 8785 (JCS) canonical JSON — deterministic AAD bytes.
//!
//! FEAT-005 must produce byte-identical canonical AAD to the TypeScript
//! FEAT-003 implementation (`src/lib/vault-core/canonical/jcs.ts`) so the
//! immutable corpus vectors replay exactly. serde_json's default `Map` is a
//! `BTreeMap` (byte-sorted keys) and its string escaping matches RFC 8785
//! (`\b \t \n \f \r`, `\"`, `\\`, `\uXXXX` for other controls, non-ASCII
//! unescaped); `ryu` floats serialize as shortest round-trip like ECMAScript.
//! This module asserts those properties and rejects any value that cannot be
//! canonicalized.

/// Canonicalize a JSON value to RFC 8785 bytes.
///
/// Fails on values that cannot be canonical (e.g. non-finite numbers, which
/// serde_json never produces). Object key order is byte-sorted by construction
/// (BTreeMap without the `preserve_order` feature).
pub fn canonicalize_json(value: &serde_json::Value) -> Result<Vec<u8>, CanonicalJsonError> {
    if !is_canonicalizable(value) {
        return Err(CanonicalJsonError::NonCanonicalValue);
    }
    serde_json::to_vec(value).map_err(|e| CanonicalJsonError::Serialize(e.to_string()))
}

/// Recursively validate canonicalizability (no floats out of canonical range,
/// no missing values). serde_json already rejects NaN/Infinity and non-string
/// keys; this is a defensive closed gate.
fn is_canonicalizable(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::String(_)
        | serde_json::Value::Number(_) => true,
        serde_json::Value::Array(items) => items.iter().all(is_canonicalizable),
        serde_json::Value::Object(map) => map.values().all(is_canonicalizable),
    }
}

/// Closed error type for canonicalization failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanonicalJsonError {
    NonCanonicalValue,
    Serialize(String),
}

impl std::fmt::Display for CanonicalJsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NonCanonicalValue => write!(f, "value cannot be canonicalized"),
            Self::Serialize(msg) => write!(f, "canonical serialization failed: {msg}"),
        }
    }
}

impl std::error::Error for CanonicalJsonError {}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn objects_are_key_sorted_without_whitespace() {
        let value = json!({"z": 1, "a": {"y": 2, "b": 3}, "m": [4, 5]});
        let bytes = canonicalize_json(&value).unwrap();
        assert_eq!(bytes, br#"{"a":{"b":3,"y":2},"m":[4,5],"z":1}"#.to_vec());
    }

    #[test]
    fn strings_escape_per_rfc_8785() {
        let value = json!({"s": "tab\t newline\n quote\" slash\\ ctrl\u{0001} ü"});
        let bytes = canonicalize_json(&value).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        assert!(s.contains("tab\\t"));
        assert!(s.contains("newline\\n"));
        assert!(s.contains("quote\\\""));
        assert!(s.contains("slash\\\\"));
        assert!(s.contains("ctrl\\u0001"));
        // Non-ASCII is unescaped.
        assert!(s.contains("ü"));
    }

    #[test]
    fn integers_serialize_as_decimal_no_exponent() {
        let value = json!({"n": 12345678901234567890u64, "m": -7});
        let bytes = canonicalize_json(&value).unwrap();
        // BTreeMap sorts keys; the exact bytes prove decimal (no exponent)
        // serialization for both u64 and negative integers.
        assert_eq!(bytes, br#"{"m":-7,"n":12345678901234567890}"#.to_vec());
    }

    #[test]
    fn deterministic_byte_identity() {
        let a = json!({"kdf": {"memoryKiB": 19456, "iterations": 2, "parallelism": 1}, "suiteId": "hush/vault/suite/v1"});
        let b = json!({"suiteId": "hush/vault/suite/v1", "kdf": {"parallelism": 1, "memoryKiB": 19456, "iterations": 2}});
        assert_eq!(
            canonicalize_json(&a).unwrap(),
            canonicalize_json(&b).unwrap()
        );
    }
}
