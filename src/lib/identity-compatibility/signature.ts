/**
 * FEAT-001 identity compatibility API — signature compatibility.
 *
 * ECDSA over the SHA-256 prehash of the exact UTF-8 canonical transaction
 * bytes (the historical producer behavior). Supports compact 64-byte r||s and
 * DER encodings and cross-verifies both, mirroring the .NET producer's
 * Olimpo.DigitalSignature contract. Producer contracts proven deterministic
 * (P-01) use RFC 6979; non-deterministic producers are verified by
 * cross-verification, never by exact-byte comparison.
 */
import * as secp from '@noble/secp256k1';
import { bytesToHexLower, compactToDer, derToCompact, hexToBytesStrict, utf8Bytes } from './crypto.js';
import type { CompatibilityResult, CompatibilityFailure } from './types.js';

export interface SignatureMaterial {
  readonly compactHex: string;
  readonly compactBase64: string;
  readonly derHex: string;
}

const failure = (code: CompatibilityFailure['code'], message: string): CompatibilityFailure => ({ ok: false, code, message });

/**
 * Sign a UTF-8 message with the historical P-01 semantics: SHA-256 prehash
 * (noble default), deterministic RFC 6979 nonce, compact 64-byte r||s.
 */
export function signMessage(messageUtf8: string, privateKeyHex: string): CompatibilityResult<SignatureMaterial> {
  try {
    const signature = secp.sign(utf8Bytes(messageUtf8), hexToBytesStrict(privateKeyHex));
    const compactHex = bytesToHexLower(signature);
    const der = compactToDer(signature.slice(0, 32), signature.slice(32, 64));
    return {
      ok: true,
      value: {
        compactHex,
        compactBase64: base64Encode(signature),
        derHex: bytesToHexLower(der),
      },
    };
  } catch {
    return failure('DERIVATION_FAILURE', 'signature generation failed');
  }
}

/** Verify a compact or DER signature over a UTF-8 message with a hex public key. */
export function verifyMessage(messageUtf8: string, signatureHex: string, publicKeyHex: string, format: 'compact' | 'der'): boolean {
  try {
    const signatureBytes = format === 'der' ? derToCompact(hexToBytesStrict(signatureHex)) : hexToBytesStrict(signatureHex);
    if (signatureBytes.length !== 64) return false;
    return secp.verify(signatureBytes, utf8Bytes(messageUtf8), hexToBytesStrict(publicKeyHex));
  } catch {
    return false;
  }
}

/** Decode a signature to compact form; typed failure for malformed encodings. */
export function decodeSignature(signatureHex: string, format: 'compact' | 'der'): CompatibilityResult<{ readonly compactHex: string }> {
  try {
    if (format === 'compact') {
      const bytes = hexToBytesStrict(signatureHex);
      if (bytes.length !== 64) return failure('SIGNATURE_MALFORMED', 'compact signature must be 64 bytes');
      return { ok: true, value: { compactHex: bytesToHexLower(bytes) } };
    }
    const compact = derToCompact(hexToBytesStrict(signatureHex));
    return { ok: true, value: { compactHex: bytesToHexLower(compact) } };
  } catch {
    return failure('SIGNATURE_MALFORMED', 'malformed signature encoding');
  }
}

function base64Encode(bytes: Uint8Array): string {
  // globalThis.btoa is available in browsers and Node >= 16 (engines: >=22)
  const binary = Array.from(bytes, (b) => String.fromCharCode(b)).join('');
  return btoa(binary);
}
