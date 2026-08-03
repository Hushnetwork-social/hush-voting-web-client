//! Deterministic byte encodings (hex + RFC 4648 base64url, unpadded).
//!
//! Used by the slot envelope and corpus-replay fixtures. Both encodings are
//! pure, total, and failure-closed: a malformed input returns the closed
//! `EncodingError` and never produces partial output.

/// Closed encoding failure (never carries decoded material).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingError {
    InvalidHex,
    InvalidBase64Url,
    OddHexLength,
}

impl std::fmt::Display for EncodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidHex => write!(f, "invalid hexadecimal input"),
            Self::InvalidBase64Url => write!(f, "invalid base64url input"),
            Self::OddHexLength => write!(f, "odd-length hexadecimal input"),
        }
    }
}

impl std::error::Error for EncodingError {}

/// Lowercase hexadecimal encoding.
pub fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Strict lowercase/uppercase hexadecimal decoding (even length required).
pub fn hex_decode(s: &str) -> Result<Vec<u8>, EncodingError> {
    if s.len() % 2 != 0 {
        return Err(EncodingError::OddHexLength);
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = nibble(bytes[i]).ok_or(EncodingError::InvalidHex)?;
        let lo = nibble(bytes[i + 1]).ok_or(EncodingError::InvalidHex)?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// RFC 4648 base64url encoding without padding.
pub fn b64url_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(n >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(n >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 0x3f] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 0x3f] as char);
        }
    }
    out
}

/// RFC 4648 base64url decoding (unpadded or padded input accepted; padding
/// must be valid `=` count when present).
pub fn b64url_decode(s: &str) -> Result<Vec<u8>, EncodingError> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let bytes = s.as_bytes();
    let mut padded = bytes.to_vec();
    if padded.contains(&b'=') {
        // Only trailing padding is valid.
        let eq_start = padded
            .iter()
            .position(|b| *b == b'=')
            .ok_or(EncodingError::InvalidBase64Url)?;
        if !padded[eq_start..].iter().all(|b| *b == b'=') {
            return Err(EncodingError::InvalidBase64Url);
        }
        while padded.last() == Some(&b'=') {
            padded.pop();
        }
    }
    if padded.len() % 4 == 1 {
        return Err(EncodingError::InvalidBase64Url);
    }
    let mut out = Vec::with_capacity(padded.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0u32;
    for ch in padded {
        let v = ALPHABET
            .iter()
            .position(|&a| a == ch)
            .ok_or(EncodingError::InvalidBase64Url)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips() {
        let bytes = [0x00u8, 0x01, 0xab, 0xff, 0x80];
        let enc = hex_encode(&bytes);
        assert_eq!(enc, "0001abff80");
        assert_eq!(hex_decode(&enc).unwrap(), bytes);
        assert_eq!(hex_decode("0001ABFF80").unwrap(), bytes);
    }

    #[test]
    fn hex_rejects_malformed_input() {
        assert_eq!(hex_decode("abc"), Err(EncodingError::OddHexLength));
        assert_eq!(hex_decode("0g"), Err(EncodingError::InvalidHex));
        assert_eq!(hex_decode(""), Ok(vec![]));
    }

    #[test]
    fn base64url_round_trips_and_matches_rfc4648_vectors() {
        // RFC 4648 §10 test vectors (unpadded base64url).
        assert_eq!(b64url_encode(b""), "");
        assert_eq!(b64url_encode(b"f"), "Zg");
        assert_eq!(b64url_encode(b"fo"), "Zm8");
        assert_eq!(b64url_encode(b"foo"), "Zm9v");
        assert_eq!(b64url_encode(b"foob"), "Zm9vYg");
        assert_eq!(b64url_encode(b"fooba"), "Zm9vYmE");
        assert_eq!(b64url_encode(b"foobar"), "Zm9vYmFy");
        for input in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            assert_eq!(b64url_decode(&b64url_encode(input)).unwrap(), input);
        }
    }

    #[test]
    fn base64url_rejects_malformed_input() {
        // Padded input is tolerated (RFC 4648); mid-string padding, length
        // congruent to 1 mod 4, and out-of-alphabet characters are invalid.
        assert!(b64url_decode("abc=").is_ok());
        assert_eq!(b64url_decode("a=b"), Err(EncodingError::InvalidBase64Url));
        assert_eq!(b64url_decode("abcde"), Err(EncodingError::InvalidBase64Url)); // len%4==1
        assert_eq!(b64url_decode("!!!!"), Err(EncodingError::InvalidBase64Url));
    }
}
