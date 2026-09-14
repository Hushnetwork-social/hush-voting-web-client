import { describe, expect, it } from 'vitest';
import { derToCompact, hexToBytesStrict } from './crypto';
import { decodeSignature, verifyMessage } from './signature';

// Public RFC6979/scalar-one fixture shared with ShortDerSignatureTests in .NET.
const message = 'short-der-regression-919';
const signature = '3043021f1a0d32d52c40366c23773acf834218c61d8581bebf7f55f3d99140928b129e0220136fad1ccd454a99bf8fac37eacfcf06f8360a912ed3752af8090ae72685585d';
const address = '0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8';

describe('approved DER signature widths', () => {
  it('cross-verifies the deterministic 69-byte historical signature', () => {
    expect(decodeSignature(signature, 'der').ok).toBe(true);
    expect(verifyMessage(message, signature, address, 'der')).toBe(true);
    expect(verifyMessage(message + ' altered', signature, address, 'der')).toBe(false);
  });

  it.each([[1, 1], [30, 32], [31, 32], [32, 32], [33, 32], [33, 33]])(
    'decodes minimally encoded integer widths %i/%i', (rLength, sLength) => {
      const der = new Uint8Array(6 + rLength + sLength);
      der.set([0x30, der.length - 2, 2, rLength, 1]);
      der.set([2, sLength, 1], 4 + rLength);
      if (rLength === 33) { der[4] = 0; der[5] = 0x80; }
      if (sLength === 33) { der[6 + rLength] = 0; der[7 + rLength] = 0x80; }
      const compact = derToCompact(der);
      expect(compact.length).toBe(64);
      expect(compact[32 - Math.min(rLength, 32)]).toBe(rLength === 33 ? 0x80 : 1);
      expect(compact[64 - Math.min(sLength, 32)]).toBe(sLength === 33 ? 0x80 : 1);
    },
  );

  it.each([
    '300602010102010100', // trailing data
    '3007020101020101', // sequence length mismatch
    '3006020180020101', // negative integer
    '300702020001020101', // redundant leading zero
    '30050200020101', // empty integer
  ])('rejects malformed DER case %#', (encoded) => {
    expect(() => derToCompact(hexToBytesStrict(encoded))).toThrow();
  });
});
