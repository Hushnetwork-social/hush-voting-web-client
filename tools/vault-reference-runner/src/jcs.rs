//! RFC 8785 JSON Canonicalization Scheme — independent Rust implementation.
//!
//! Rules used by the vault corpus: UTF-16 code-unit object-key ordering, minimal JSON
//! escaping, ECMAScript-compatible finite number formatting, and no NaN/Infinity.

use serde_json::Value;
use std::cmp::Ordering;

/// Escape a string per RFC 8785 §3.2.2.2.
pub fn escape_string(value: &str) -> String {
    let mut output = String::with_capacity(value.len() + 2);
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{09}' => output.push_str("\\t"),
            '\u{0a}' => output.push_str("\\n"),
            '\u{0c}' => output.push_str("\\f"),
            '\u{0d}' => output.push_str("\\r"),
            value if (value as u32) < 0x20 => {
                output.push_str(&format!("\\u{:04x}", value as u32));
            }
            value => output.push(value),
        }
    }
    output.push('"');
    output
}

fn compare_utf16(left: &str, right: &str) -> Ordering {
    left.encode_utf16().cmp(right.encode_utf16())
}

/// Canonical finite-number serialization for the ranges accepted by the corpus.
///
/// `serde_json` already uses shortest-round-trip Ryu formatting. RFC 8785 additionally
/// follows ECMAScript's fixed notation for integral values below 1e21 and normalizes
/// negative zero to zero.
fn canonical_number(number: f64) -> Result<String, ()> {
    if !number.is_finite() {
        return Err(());
    }
    if number == 0.0 {
        return Ok("0".to_owned());
    }
    if number.fract() == 0.0 && number.abs() < 1e21 {
        return Ok(format!("{number:.0}"));
    }
    let value = serde_json::Number::from_f64(number).ok_or(())?.to_string();
    Ok(value.replace("e-0", "e-").replace("e+0", "e+"))
}

/// Canonicalize a JSON value to RFC 8785 bytes represented as a UTF-8 string.
pub fn canonicalize(value: &Value) -> Result<String, ()> {
    match value {
        Value::Null => Ok("null".to_owned()),
        Value::Bool(value) => Ok(if *value { "true" } else { "false" }.to_owned()),
        Value::Number(number) => {
            if let Some(value) = number.as_i64() {
                return Ok(value.to_string());
            }
            if let Some(value) = number.as_u64() {
                return Ok(value.to_string());
            }
            canonical_number(number.as_f64().ok_or(())?)
        }
        Value::String(value) => Ok(escape_string(value)),
        Value::Array(values) => {
            let items: Result<Vec<String>, ()> = values.iter().map(canonicalize).collect();
            Ok(format!("[{}]", items?.join(",")))
        }
        Value::Object(object) => {
            let mut entries: Vec<(&String, &Value)> = object.iter().collect();
            entries.sort_by(|(left, _), (right, _)| compare_utf16(left, right));
            let fields: Result<Vec<String>, ()> = entries
                .into_iter()
                .map(|(key, value)| Ok(format!("{}:{}", escape_string(key), canonicalize(value)?)))
                .collect();
            Ok(format!("{{{}}}", fields?.join(",")))
        }
    }
}

/// Format a digest as lowercase hexadecimal.
pub fn hex_digest(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_object_keys_by_utf16_code_units() {
        let value = json!({ "😀": 1, "\u{e000}": 2 });
        assert_eq!(
            canonicalize(&value).expect("canonical"),
            "{\"😀\":1,\"\":2}"
        );
    }

    #[test]
    fn escapes_minimally() {
        let value = json!({ "s": "a\"b\\c\nd" });
        assert_eq!(
            canonicalize(&value).expect("canonical"),
            r#"{"s":"a\"b\\c\nd"}"#
        );
    }

    #[test]
    fn follows_ecmascript_number_boundaries() {
        assert_eq!(
            canonicalize(&json!(1e20)).expect("canonical"),
            "100000000000000000000"
        );
        assert_eq!(canonicalize(&json!(-0.0)).expect("canonical"), "0");
        assert_eq!(canonicalize(&json!(1e-7)).expect("canonical"), "1e-7");
    }

    #[test]
    fn rejects_non_finite_numbers() {
        assert!(canonical_number(f64::NAN).is_err());
        assert!(canonical_number(f64::INFINITY).is_err());
    }
}
