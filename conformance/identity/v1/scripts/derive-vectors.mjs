#!/usr/bin/env node
/**
 * FEAT-001 vector derivation (provenance tooling)
 * ===============================================
 * Produces the deterministic vector and lookup corpus documents for
 * conformance/identity/v1. It implements the evidence contracts exactly:
 *
 *   C-A (P-01 Hush Feeds Web Client / TypeScript): BIP-39 seed (PBKDF2-HMAC-SHA512,
 *       2048, salt "mnemonic"), HKDF-SHA256 info "signing"/"encryption",
 *       compressed secp256k1 public keys, ECDSA-SHA256 compact r||s signatures.
 *   C-B (P-02 Olimpo.KeyDerivation / .NET): same seed; HKDF-SHA256 info
 *       "hush/signing/secp256k1/v1"/"hush/encrypt/secp256k1/v1"; invalid-scalar
 *       retry {info}/{attempt}; uncompressed secp256k1 public keys.
 *   C-C (.dat v1, P-04/P-05): "HUSH" + int32LE(1) + salt(16) + nonce(12) +
 *       AES-256-GCM(128-bit tag); PBKDF2-SHA256 100000, password UTF-8 bytes.
 *
 * Determinism: fixed BIP-39 TREZOR entropies, fixed .dat salt/nonce, RFC 6979
 * deterministic ECDSA (P-01). Output files follow the corpus formatting rules:
 * UTF-8 no BOM, LF endings, lexicographically stable object keys, two-space
 * indentation, one final newline.
 *
 * Dependencies (reviewed lockfile-pinned versions, matching the historical
 * producer's ranges): bip39 ^3.1.0, @noble/hashes ^2.0.1, @noble/secp256k1 ^3.0.0.
 * Run: OUTPUT_DIR=conformance/identity/v1 node scripts/derive-vectors.mjs
 *
 * NOTE: .dat "OVERSIZED" and duplicate-field vectors are constructed by the
 * conformance runners from the documented rules (base envelope + padding /
 * raw payload text); they are defined here as metadata, not stored hex.
 */
import { entropyToMnemonic, mnemonicToSeedSync } from 'bip39';
import { hkdf } from '@noble/hashes/hkdf.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { hmac } from '@noble/hashes/hmac.js';
import * as secp from '@noble/secp256k1';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { webcrypto } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// noble v3 requires explicit hash registration (as the historical runtime does)
secp.hashes.sha256 = sha256;
secp.hashes.hmacSha256 = (key, msg) => hmac(sha256, key, msg);

const N_HEX = 'fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141';
const CURVE_N = BigInt('0x' + N_HEX);

const OUT_DIR = process.env.OUTPUT_DIR ?? dirname(fileURLToPath(import.meta.url)) + '/..';
const enc = new TextEncoder();

function hkdfSha256(ikm, info) {
  return hkdf(sha256, ikm, undefined, enc.encode(info), 32);
}
function scalarOk(hex) {
  const v = BigInt('0x' + hex);
  return v > 0n && v < CURVE_N;
}
// deterministic stable JSON: sorted keys, 2-space indent, final newline
function stableStringify(obj) {
  const sort = (o) => {
    if (Array.isArray(o)) return o.map(sort);
    if (o && typeof o === 'object') {
      return Object.fromEntries(Object.keys(o).sort().map((k) => [k, sort(o[k])]));
    }
    return o;
  };
  return JSON.stringify(sort(obj), null, 2) + '\n';
}
function writeJson(name, obj) {
  const p = join(OUT_DIR, name);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, stableStringify(obj), { encoding: 'utf8', flag: 'w' });
  console.log('wrote', p);
}

// ---- C-A (P-01) ------------------------------------------------------------
function deriveP01(mnemonic) {
  const seed = mnemonicToSeedSync(mnemonic);
  const sSign = hkdfSha256(seed, 'signing');
  const sEnc = hkdfSha256(seed, 'encryption');
  return {
    seedHex: bytesToHex(seed),
    signingPriv: bytesToHex(sSign),
    encryptionPriv: bytesToHex(sEnc),
    signingPubComp: bytesToHex(secp.getPublicKey(sSign, true)),
    signingPubUncomp: bytesToHex(secp.getPublicKey(sSign, false)),
    encryptionPubComp: bytesToHex(secp.getPublicKey(sEnc, true)),
    encryptionPubUncomp: bytesToHex(secp.getPublicKey(sEnc, false)),
  };
}

// ---- C-B (P-02) ------------------------------------------------------------
function deriveP02(mnemonic) {
  const seed = mnemonicToSeedSync(mnemonic); // PBKDF2-HMAC-SHA512 2048, salt "mnemonic" (ASCII => identical)
  const infoSign = 'hush/signing/secp256k1/v1';
  const infoEnc = 'hush/encrypt/secp256k1/v1';
  const derive = (info) => {
    let attempt = 0;
    let keyMaterial = hkdfSha256(seed, info);
    while (!scalarOk(bytesToHex(keyMaterial))) {
      attempt += 1;
      keyMaterial = hkdfSha256(seed, `${info}/${attempt}`);
    }
    return keyMaterial;
  };
  const sSign = derive(infoSign);
  const sEnc = derive(infoEnc);
  return {
    seedHex: bytesToHex(seed),
    signingPriv: bytesToHex(sSign),
    encryptionPriv: bytesToHex(sEnc),
    signingPubUncomp: bytesToHex(secp.getPublicKey(sSign, false)),
    signingPubComp: bytesToHex(secp.getPublicKey(sSign, true)),
    encryptionPubUncomp: bytesToHex(secp.getPublicKey(sEnc, false)),
    encryptionPubComp: bytesToHex(secp.getPublicKey(sEnc, true)),
  };
}

// ---- C-C (.dat v1) ---------------------------------------------------------
function int32LE(n) {
  const b = new DataView(new ArrayBuffer(4));
  b.setInt32(0, n, true);
  return new Uint8Array(b.buffer);
}
async function datKey(password, salt) {
  const km = await webcrypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return webcrypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt.buffer.slice(salt.byteOffset, salt.byteOffset + salt.byteLength),
      iterations: 100000,
      hash: 'SHA-256',
    },
    km,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt'],
  );
}
async function datEncrypt(payloadJson, password, salt, nonce) {
  const key = await datKey(password, salt);
  const ct = await webcrypto.subtle.encrypt(
    { name: 'AES-GCM', iv: nonce, tagLength: 128 },
    key,
    enc.encode(payloadJson),
  );
  const magic = enc.encode('HUSH');
  const out = new Uint8Array(4 + 4 + 16 + 12 + ct.byteLength);
  out.set(magic, 0);
  out.set(int32LE(1), 4);
  out.set(salt, 8);
  out.set(nonce, 24);
  out.set(new Uint8Array(ct), 36);
  return bytesToHex(out);
}

// ---- fixed test material ---------------------------------------------------
const entropy24 = hexToBytes('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f');
const entropy12 = hexToBytes('000102030405060708090a0b0c0d0e0f');
const entropy24b = hexToBytes('101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f');
const m24 = entropyToMnemonic(entropy24);
const m12 = entropyToMnemonic(entropy12);
const m24b = entropyToMnemonic(entropy24b);

const p01 = { m24: deriveP01(m24), m12: deriveP01(m12), m24b: deriveP01(m24b) };
const p02 = { m24: deriveP02(m24), m24b: deriveP02(m24b) };

// canonical signed-transaction bytes (signByUser: JSON.stringify(unsignedTx))
const payload = {
  IdentityAlias: 'public-test-alias-001',
  PublicSigningAddress: p01.m24.signingPubComp,
  PublicEncryptAddress: p01.m24.encryptionPubComp,
  IsPublic: true,
};
const unsignedTx = {
  TransactionId: 'd4a2f9c1-3b5e-4f6a-9c7d-2e8f1a0b3c4d',
  PayloadKind: '351cd60b-3fdf-48d4-b608-e93c0100f7d0',
  TransactionTimeStamp: '2026-08-01T12:34:56.789Z',
  Payload: payload,
  PayloadSize: enc.encode(JSON.stringify(payload)).length,
};
const canonicalJson = JSON.stringify(unsignedTx);
const canonicalBytes = enc.encode(canonicalJson);

// signatures
const sigP01 = secp.sign(canonicalBytes, hexToBytes(p01.m24.signingPriv));
const sigP02 = secp.sign(canonicalBytes, hexToBytes(p02.m24.signingPriv));
function compactToDer(rBytes, sBytes) {
  const encInt = (n) => {
    let h = n.toString(16);
    if (h.length % 2) h = '0' + h;
    const b = hexToBytes(h);
    return b[0] & 0x80 ? new Uint8Array([0x00, ...b]) : b;
  };
  const r = encInt(BigInt('0x' + bytesToHex(rBytes)));
  const s = encInt(BigInt('0x' + bytesToHex(sBytes)));
  const body = new Uint8Array([0x02, r.length, ...r, 0x02, s.length, ...s]);
  return new Uint8Array([0x30, body.length, ...body]);
}
const derP01 = compactToDer(sigP01.slice(0, 32), sigP01.slice(32, 64));
const derP02 = compactToDer(sigP02.slice(0, 32), sigP02.slice(32, 64));

// .dat positive fixture (fixed salt/nonce)
const salt = hexToBytes('000102030405060708090a0b0c0d0e0f');
const nonce = hexToBytes('101112131415161718191a1b');
const datPassword = 'hush-public-test-password-2026-01';
const pc = {
  ProfileName: 'public-test-profile-001',
  PublicSigningAddress: p01.m24.signingPubComp,
  PrivateSigningKey: p01.m24.signingPriv,
  PublicEncryptAddress: p01.m24.encryptionPubComp,
  PrivateEncryptKey: p01.m24.encryptionPriv,
  IsPublic: true,
  Mnemonic: m24,
};
const pcJson = JSON.stringify(pc);
const datHex = await datEncrypt(pcJson, datPassword, salt, nonce);

// point decode helpers
function pointXY(hex) {
  const pt = secp.Point.fromHex(hex);
  return {
    x: pt.x.toString(16).padStart(64, '0'),
    y: pt.y.toString(16).padStart(64, '0'),
  };
}
const kp01 = pointXY(p01.m24.signingPubComp);
const kp02 = pointXY(p02.m24.signingPubUncomp);

// ---- mnemonic vectors ------------------------------------------------------
const mnemonicVectors = {
  schemaVersion: '1.0.0',
  contractVersion: '1.0.0',
  kind: 'mnemonic-vectors',
  vectors: [
    {
      id: 'M-001',
      producerId: 'P-01',
      mnemonic: m24,
      wordCount: 24,
      entropyHex: bytesToHex(entropy24),
      seedHex: p01.m24.seedHex,
      signingPrivateKeyHex: p01.m24.signingPriv,
      encryptionPrivateKeyHex: p01.m24.encryptionPriv,
      signingPublicKeyHex: p01.m24.signingPubComp,
      encryptionPublicKeyHex: p01.m24.encryptionPubComp,
      publicKeyEncoding: 'COMPRESSED',
      expected: 'MATCH',
    },
    {
      id: 'M-002',
      producerId: 'P-01',
      mnemonic: m12,
      wordCount: 12,
      entropyHex: bytesToHex(entropy12),
      seedHex: p01.m12.seedHex,
      signingPrivateKeyHex: p01.m12.signingPriv,
      encryptionPrivateKeyHex: p01.m12.encryptionPriv,
      signingPublicKeyHex: p01.m12.signingPubComp,
      encryptionPublicKeyHex: p01.m12.encryptionPubComp,
      publicKeyEncoding: 'COMPRESSED',
      expected: 'MATCH',
    },
    {
      id: 'M-003',
      producerId: 'P-01',
      mnemonic: m24b,
      wordCount: 24,
      entropyHex: bytesToHex(entropy24b),
      seedHex: p01.m24b.seedHex,
      signingPrivateKeyHex: p01.m24b.signingPriv,
      encryptionPrivateKeyHex: p01.m24b.encryptionPriv,
      signingPublicKeyHex: p01.m24b.signingPubComp,
      encryptionPublicKeyHex: p01.m24b.encryptionPubComp,
      publicKeyEncoding: 'COMPRESSED',
      expected: 'MATCH',
    },
    {
      id: 'M-004',
      producerId: 'P-02',
      mnemonic: m24,
      wordCount: 24,
      entropyHex: bytesToHex(entropy24),
      seedHex: p02.m24.seedHex,
      signingPrivateKeyHex: p02.m24.signingPriv,
      encryptionPrivateKeyHex: p02.m24.encryptionPriv,
      signingPublicKeyHex: p02.m24.signingPubUncomp,
      encryptionPublicKeyHex: p02.m24.encryptionPubUncomp,
      publicKeyEncoding: 'UNCOMPRESSED',
      expected: 'MATCH',
    },
    {
      id: 'M-005',
      producerId: 'P-02',
      mnemonic: m24b,
      wordCount: 24,
      entropyHex: bytesToHex(entropy24b),
      seedHex: p02.m24b.seedHex,
      signingPrivateKeyHex: p02.m24b.signingPriv,
      encryptionPrivateKeyHex: p02.m24b.encryptionPriv,
      signingPublicKeyHex: p02.m24b.signingPubUncomp,
      encryptionPublicKeyHex: p02.m24b.encryptionPubUncomp,
      publicKeyEncoding: 'UNCOMPRESSED',
      expected: 'MATCH',
    },
  ],
};

// ---- key vectors -----------------------------------------------------------
const keyVectors = {
  schemaVersion: '1.0.0',
  contractVersion: '1.0.0',
  kind: 'key-vectors',
  vectors: [
    {
      id: 'K-001',
      producerId: 'P-01',
      operation: 'PUBLIC_KEY_DERIVE',
      privateScalarHex: p01.m24.signingPriv,
      encoding: 'COMPRESSED',
      expectedPublicKeyHex: p01.m24.signingPubComp,
      expected: 'OK',
    },
    {
      id: 'K-002',
      producerId: 'P-01',
      operation: 'POINT_EQUIVALENCE',
      privateScalarHex: p01.m24.signingPriv,
      encoding: 'UNCOMPRESSED',
      expectedPublicKeyHex: p01.m24.signingPubUncomp,
      expected: 'OK',
      notes: 'Compressed and uncompressed encodings of the same curve point are distinct lookup candidates, but decode to the same point.',
    },
    {
      id: 'K-003',
      producerId: 'P-02',
      operation: 'PUBLIC_KEY_DERIVE',
      privateScalarHex: p02.m24.signingPriv,
      encoding: 'UNCOMPRESSED',
      expectedPublicKeyHex: p02.m24.signingPubUncomp,
      expected: 'OK',
    },
    {
      id: 'K-004',
      producerId: 'P-02',
      operation: 'POINT_EQUIVALENCE',
      privateScalarHex: p02.m24.signingPriv,
      encoding: 'COMPRESSED',
      expectedPublicKeyHex: p02.m24.signingPubComp,
      expected: 'OK',
    },
    {
      id: 'K-005',
      operation: 'DECODE',
      inputHex: p01.m24.signingPubComp,
      expectedPointXHex: kp01.x,
      expectedPointYHex: kp01.y,
      expected: 'OK',
      notes: 'Compressed key 02||X decodes to the same point as the P-01 derived key.',
    },
    {
      id: 'K-006',
      operation: 'DECODE',
      inputHex: p02.m24.signingPubUncomp,
      expectedPointXHex: kp02.x,
      expectedPointYHex: kp02.y,
      expected: 'OK',
      notes: 'Uncompressed key 04||X||Y decodes to the same point as the P-02 derived key.',
    },
    {
      id: 'K-007',
      operation: 'DECODE',
      inputHex: '05' + p01.m24.signingPubComp.slice(2),
      expected: 'ERROR',
      errorCode: 'INVALID_KEY_ENCODING',
      notes: 'Unknown 0x05 prefix.',
    },
    {
      id: 'K-008',
      operation: 'DECODE',
      inputHex: '02' + p01.m24.signingPubComp.slice(2, 64),
      expected: 'ERROR',
      errorCode: 'INVALID_KEY_ENCODING',
      notes: 'Truncated compressed key (32 bytes after prefix instead of 32 X bytes).',
    },
    {
      id: 'K-009',
      operation: 'DECODE',
      inputHex: '04' + '00'.repeat(64),
      expected: 'ERROR',
      errorCode: 'INVALID_KEY_ENCODING',
      notes: 'All-zero uncompressed key (not on curve).',
    },
    {
      id: 'K-010',
      operation: 'SCALAR_VALIDATE',
      privateScalarHex: '00'.repeat(32),
      expected: 'ERROR',
      errorCode: 'INVALID_PRIVATE_SCALAR',
      notes: 'Zero scalar.',
    },
    {
      id: 'K-011',
      operation: 'SCALAR_VALIDATE',
      privateScalarHex: N_HEX,
      expected: 'ERROR',
      errorCode: 'INVALID_PRIVATE_SCALAR',
      notes: 'Scalar equal to curve order N.',
    },
    {
      id: 'K-012',
      operation: 'SCALAR_VALIDATE',
      privateScalarHex: (CURVE_N + 1n).toString(16).padStart(64, '0'),
      expected: 'ERROR',
      errorCode: 'INVALID_PRIVATE_SCALAR',
      notes: 'Scalar above curve order N.',
    },
    {
      id: 'K-013',
      operation: 'SCALAR_VALIDATE',
      privateScalarHex: (CURVE_N - 1n).toString(16).padStart(64, '0'),
      expectedPublicKeyHex: bytesToHex(secp.getPublicKey(hexToBytes((CURVE_N - 1n).toString(16).padStart(64, '0')), true)),
      expected: 'OK',
      notes: 'N-1 is a valid scalar boundary.',
    },
  ],
};

// ---- .dat vectors ----------------------------------------------------------
const datVectors = {
  schemaVersion: '1.0.0',
  contractVersion: '1.0.0',
  kind: 'dat-vectors',
  maxEnvelopeBytes: 1048576,
  vectors: [
    {
      id: 'D-001',
      producerId: 'P-04',
      operation: 'DECRYPT',
      envelopeHex: datHex,
      password: datPassword,
      expectedPayloadJson: pcJson,
      expected: 'OK',
    },
    {
      id: 'D-002',
      operation: 'DECRYPT',
      envelopeHex: datHex,
      password: 'wrong-public-test-password',
      expected: 'ERROR',
      errorCode: 'DAT_WRONG_PASSWORD',
      notes: 'AES-GCM authentication failure.',
    },
    {
      id: 'D-003',
      operation: 'DECRYPT',
      envelopeHex: '4855534a' + datHex.slice(8),
      password: datPassword,
      expected: 'ERROR',
      errorCode: 'DAT_INVALID_MAGIC',
      notes: 'Magic "HUSH" mutated to "HUSJ".',
    },
    {
      id: 'D-004',
      operation: 'DECRYPT',
      envelopeHex: '48555348' + '02000000' + datHex.slice(16),
      password: datPassword,
      expected: 'ERROR',
      errorCode: 'DAT_UNSUPPORTED_VERSION',
      notes: 'Version int32 LE set to 2.',
    },
    {
      id: 'D-005',
      operation: 'DECRYPT',
      envelopeHex: datHex.slice(0, datHex.length - 80),
      password: datPassword,
      expected: 'ERROR',
      errorCode: 'DAT_WRONG_PASSWORD',
      notes: 'Truncated ciphertext (last 40 bytes removed) -> GCM auth failure.',
    },
    {
      id: 'D-006',
      operation: 'OVERSIZED',
      baseEnvelopeRef: 'D-001',
      expected: 'ERROR',
      errorCode: 'DAT_MALFORMED',
      notes: 'Runner constructs base envelope + 1 MiB padding beyond maxEnvelopeBytes; rejected before PBKDF2.',
    },
    {
      id: 'D-007',
      operation: 'DECRYPT',
      envelopeHex: datHex.slice(0, 16),
      password: datPassword,
      expected: 'ERROR',
      errorCode: 'DAT_MALFORMED',
      notes: 'Envelope shorter than structural minimum (36 bytes).',
    },
    {
      id: 'D-008',
      operation: 'DECRYPT',
      envelopeHex: datHex.slice(0, datHex.length - 2) + '00',
      password: datPassword,
      expected: 'ERROR',
      errorCode: 'DAT_WRONG_PASSWORD',
      notes: 'Last ciphertext byte flipped -> GCM auth failure.',
    },
    {
      id: 'D-009',
      operation: 'PARSE',
      payloadJson: pcJson.replace(',"IsPublic":true', ''),
      expected: 'ERROR',
      errorCode: 'DAT_MISSING_FIELD',
      notes: 'IsPublic removed.',
    },
    {
      id: 'D-010',
      operation: 'PARSE',
      payloadJson: pcJson.replace('}', ',"ExtraField":1}'),
      expected: 'ERROR',
      errorCode: 'DAT_UNKNOWN_FIELD',
      notes: 'Unknown property appended.',
    },
    {
      id: 'D-011',
      operation: 'PARSE',
      payloadJson: '{"ProfileName":"dup-a","ProfileName":"dup-b","PublicSigningAddress":"' + p01.m24.signingPubComp + '","PrivateSigningKey":"' + p01.m24.signingPriv + '","PublicEncryptAddress":"' + p01.m24.encryptionPubComp + '","PrivateEncryptKey":"' + p01.m24.encryptionPriv + '","IsPublic":true,"Mnemonic":"' + m24 + '"}',
      expected: 'ERROR',
      errorCode: 'DAT_DUPLICATE_FIELD',
      notes: 'Duplicate ProfileName property must fail deterministically, not silently keep the last.',
    },
    {
      id: 'D-012',
      operation: 'PARSE',
      payloadJson: pcJson.replace('"IsPublic":true', '"IsPublic":null'),
      expected: 'ERROR',
      errorCode: 'DAT_INVALID_FIELD',
      notes: 'Null IsPublic.',
    },
    {
      id: 'D-013',
      operation: 'PARSE',
      payloadJson: pcJson.replace('"IsPublic":true', '"IsPublic":"true"'),
      expected: 'ERROR',
      errorCode: 'DAT_INVALID_FIELD',
      notes: 'Wrong-type IsPublic (string instead of boolean).',
    },
    {
      id: 'D-014',
      operation: 'KEY_CONSISTENCY',
      payloadJson: pcJson.replace('"Mnemonic":"' + m24 + '"', '"Mnemonic":"' + m24b + '"'),
      expected: 'ERROR',
      errorCode: 'DAT_MNEMONIC_KEY_MISMATCH',
      notes: 'Mnemonic does not derive the stored private keys.',
    },
    {
      id: 'D-015',
      operation: 'KEY_CONSISTENCY',
      payloadJson: pcJson.replace(p01.m24.signingPriv, p02.m24.signingPriv),
      expected: 'ERROR',
      errorCode: 'DAT_KEY_MISMATCH',
      notes: 'PrivateSigningKey does not match PublicSigningAddress.',
    },
  ],
};

// ---- canonical byte vectors ------------------------------------------------
function cvec(id, operation, json, extra = {}) {
  const bytes = enc.encode(json);
  return { id, operation, json, utf8Hex: bytesToHex(bytes), utf8Length: bytes.length, expected: operation === 'SERIALIZE' ? 'MATCH' : 'DIFFERENT', ...extra };
}
const canonicalVectors = {
  schemaVersion: '1.0.0',
  contractVersion: '1.0.0',
  kind: 'canonical-byte-vectors',
  vectors: [
    cvec('CB-001', 'SERIALIZE', canonicalJson, { payloadSize: unsignedTx.PayloadSize }),
    cvec('CB-002', 'TAMPER', JSON.stringify({ ...unsignedTx, Payload: { IsPublic: true, IdentityAlias: payload.IdentityAlias, PublicSigningAddress: payload.PublicSigningAddress, PublicEncryptAddress: payload.PublicEncryptAddress } }), { mutation: 'REORDER_PAYLOAD_FIELDS' }),
    cvec('CB-003', 'TAMPER', canonicalJson.replace('12:34:56.789Z', '12:34:56.790Z'), { mutation: 'CHANGE_TIMESTAMP_MS' }),
    cvec('CB-004', 'TAMPER', canonicalJson.replace('"PayloadSize":' + unsignedTx.PayloadSize, '"PayloadSize":' + (unsignedTx.PayloadSize + 1)), { mutation: 'CHANGE_PAYLOAD_SIZE' }),
    cvec('CB-005', 'TAMPER', canonicalJson.replace('d4a2f9c1-3b5e-4f6a-9c7d-2e8f1a0b3c4d', 'd4a2f9c1-3b5e-4f6a-9c7d-2e8f1a0b3c4e'), { mutation: 'CHANGE_TRANSACTION_ID' }),
    cvec('CB-006', 'TAMPER', canonicalJson.replace('351cd60b-3fdf-48d4-b608-e93c0100f7d0', 'a7e3c4b2-1f8d-4e5a-9c6b-2d3e4f5a6b7c'), { mutation: 'CHANGE_PAYLOAD_KIND' }),
    cvec('CB-007', 'TAMPER', canonicalJson.replace('public-test-alias-001', 'public-test-alias-002'), { mutation: 'CHANGE_ALIAS_VALUE' }),
    cvec('CB-008', 'TAMPER', canonicalJson.replace('public-test-alias-001', 'public-test-álīas-002'), { mutation: 'NON_ASCII_UTF8_ALIAS', notes: 'Multibyte UTF-8 proves exact byte encoding.' }),
  ],
};

// ---- signature vectors -----------------------------------------------------
function flipLastByte(hex) {
  const last = hex.slice(-2);
  const flipped = (parseInt(last, 16) ^ 0x01).toString(16).padStart(2, '0');
  return hex.slice(0, -2) + flipped;
}
const signatureVectors = {
  schemaVersion: '1.0.0',
  contractVersion: '1.0.0',
  kind: 'signature-vectors',
  vectors: [
    {
      id: 'S-001',
      producerId: 'P-01',
      operation: 'VERIFY',
      messageUtf8: canonicalJson,
      messageUtf8Hex: bytesToHex(canonicalBytes),
      publicKeyHex: p01.m24.signingPubComp,
      signatureCompactBase64: Buffer.from(sigP01).toString('base64'),
      signatureCompactHex: bytesToHex(sigP01),
      signatureDerHex: bytesToHex(derP01),
      expected: 'VALID',
      notes: 'Fixed deterministic (RFC 6979) P-01 compact r||s signature; DER form also verifies.',
    },
    {
      id: 'S-002',
      producerId: 'P-02',
      operation: 'VERIFY',
      messageUtf8: canonicalJson,
      messageUtf8Hex: bytesToHex(canonicalBytes),
      publicKeyHex: p02.m24.signingPubUncomp,
      signatureCompactBase64: Buffer.from(sigP02).toString('base64'),
      signatureCompactHex: bytesToHex(sigP02),
      signatureDerHex: bytesToHex(derP02),
      expected: 'VALID',
      notes: 'P-02 producer signing the same canonical message; verified with uncompressed key. .NET generates a random nonce, so exact bytes need not match across runtimes; cross-verification is the contract.',
    },
    {
      id: 'S-003',
      operation: 'VERIFY',
      messageUtf8: canonicalJson.replace('12:34:56.789Z', '12:34:56.790Z'),
      messageUtf8Hex: bytesToHex(enc.encode(canonicalJson.replace('12:34:56.789Z', '12:34:56.790Z'))),
      publicKeyHex: p01.m24.signingPubComp,
      signatureCompactBase64: Buffer.from(sigP01).toString('base64'),
      expected: 'INVALID',
      notes: 'Wrong message (timestamp tampered).',
    },
    {
      id: 'S-004',
      operation: 'VERIFY',
      messageUtf8: canonicalJson,
      messageUtf8Hex: bytesToHex(canonicalBytes),
      publicKeyHex: p01.m24.signingPubComp,
      signatureCompactBase64: Buffer.from(hexToBytes(flipLastByte(bytesToHex(sigP01)))).toString('base64'),
      signatureCompactHex: flipLastByte(bytesToHex(sigP01)),
      expected: 'INVALID',
      notes: 'Mutated signature (last byte flipped).',
    },
    {
      id: 'S-005',
      operation: 'VERIFY',
      messageUtf8: canonicalJson,
      messageUtf8Hex: bytesToHex(canonicalBytes),
      publicKeyHex: p01.m24.encryptionPubComp,
      signatureCompactBase64: Buffer.from(sigP01).toString('base64'),
      expected: 'INVALID',
      notes: 'Wrong public key (encryption key instead of signing key).',
    },
    {
      id: 'S-006',
      operation: 'DECODE',
      signatureCompactHex: bytesToHex(sigP01).slice(0, 126),
      expected: 'ERROR',
      errorCode: 'SIGNATURE_MALFORMED',
      notes: 'Truncated compact signature (63 bytes).',
    },
    {
      id: 'S-007',
      operation: 'DECODE',
      signatureDerHex: '302a0201' + '00',
      expected: 'ERROR',
      errorCode: 'SIGNATURE_MALFORMED',
      notes: 'Malformed DER sequence.',
    },
    {
      id: 'S-008',
      operation: 'VERIFY',
      messageUtf8: canonicalJson,
      messageUtf8Hex: bytesToHex(canonicalBytes),
      publicKeyHex: p02.m24b.signingPubUncomp,
      signatureCompactBase64: Buffer.from(secp.sign(canonicalBytes, hexToBytes(p02.m24b.signingPriv))).toString('base64'),
      expected: 'VALID',
      notes: 'Second P-02 identity (m24b) signing the same canonical message.',
    },
    {
      id: 'S-009',
      producerId: 'P-07',
      operation: 'VERIFY',
      messageUtf8: canonicalJson,
      messageUtf8Hex: bytesToHex(canonicalBytes),
      publicKeyHex: p01.m24.signingPubComp,
      signatureDerHex: bytesToHex(derP01),
      expected: 'VALID',
      notes: 'P-07 Olimpo.DigitalSignature default DER verification path over the canonical message with the P-01 public key (compressed accepted by BouncyCastle DecodePoint).',
    },
  ],
};

// ---- negative vectors ------------------------------------------------------
const negativeVectors = {
  schemaVersion: '1.0.0',
  contractVersion: '1.0.0',
  kind: 'negative-vectors',
  vectors: [
    {
      id: 'N-001',
      operation: 'MNEMONIC_VALIDATE',
      producerId: 'P-02',
      input: m12,
      expected: 'ERROR',
      errorCode: 'INVALID_WORD_COUNT',
      notes: 'P-02 supports 24-word only; 12-word rejected.',
    },
    {
      id: 'N-002',
      operation: 'MNEMONIC_VALIDATE',
      producerId: 'P-01',
      input: m24.replace('unaware', 'zzzzzz'),
      expected: 'ERROR',
      errorCode: 'UNKNOWN_WORD',
      notes: 'Unknown word not in BIP-39 English wordlist.',
    },
    {
      id: 'N-003',
      operation: 'MNEMONIC_VALIDATE',
      producerId: 'P-01',
      input: m24.replace('unaware', 'abandon'),
      expected: 'ERROR',
      errorCode: 'INVALID_CHECKSUM',
      notes: 'Valid words, wrong final checksum word.',
    },
    {
      id: 'N-004',
      operation: 'MNEMONIC_VALIDATE',
      producerId: 'P-01',
      input: '',
      expected: 'ERROR',
      errorCode: 'INVALID_MNEMONIC',
      notes: 'Empty input.',
    },
    {
      id: 'N-005',
      operation: 'MNEMONIC_VALIDATE',
      producerId: 'P-01',
      input: m24.split(' ').slice(0, 23).join(' '),
      expected: 'ERROR',
      errorCode: 'INVALID_WORD_COUNT',
      notes: '23 words.',
    },
    {
      id: 'N-006',
      operation: 'MNEMONIC_VALIDATE',
      producerId: 'P-01',
      input: m24.toUpperCase(),
      expected: 'ERROR',
      errorCode: 'INVALID_MNEMONIC',
      notes: 'Uppercase rejected by strict BIP-39 validation. P-02 normalizes to lowercase and accepts.',
    },
    {
      id: 'N-100',
      operation: 'PRODUCER_SELECT',
      input: 'P-99',
      expected: 'ERROR',
      errorCode: 'UNSUPPORTED_PRODUCER',
      notes: 'Unknown producer ID.',
    },
    {
      id: 'N-101',
      operation: 'PRODUCER_SELECT',
      input: 'P-06',
      expected: 'ERROR',
      errorCode: 'UNSUPPORTED_PRODUCER',
      notes: 'P-06 RSA-2048 era is classified UNSUPPORTED and is not an Approved derivation contract.',
    },
    {
      id: 'N-102',
      operation: 'VERSION_SELECT',
      input: '9.9.9',
      expected: 'ERROR',
      errorCode: 'UNSUPPORTED_VERSION',
      notes: 'Contract version outside supported range.',
    },
    {
      id: 'N-103',
      operation: 'MNEMONIC_DERIVE',
      producerId: 'P-01',
      input: m24,
      passphrase: 'unsupported-passphrase',
      expected: 'ERROR',
      errorCode: 'UNSUPPORTED_PASSPHRASE',
      notes: 'Approved contracts require an empty BIP-39 passphrase.',
    },
  ],
};

// ---- lookup outcomes -------------------------------------------------------
const lookup = {
  schemaVersion: '1.0.0',
  contractVersion: '1.0.0',
  kind: 'lookup-outcomes',
  registry: [
    {
      id: 'R-001',
      signingAddress: p01.m24.signingPubComp,
      encryptionAddress: p01.m24.encryptionPubComp,
      profileAlias: 'public-test-alias-001',
    },
    {
      id: 'R-002',
      signingAddress: p02.m24.signingPubUncomp,
      encryptionAddress: p02.m24.encryptionPubUncomp,
      profileAlias: 'public-test-alias-002',
    },
    {
      id: 'R-003',
      signingAddress: p01.m24b.signingPubComp,
      encryptionAddress: p01.m24b.encryptionPubComp,
      profileAlias: 'public-test-alias-003',
    },
  ],
  scenarios: [
    {
      id: 'L-001',
      label: 'zero matches',
      candidates: [
        { producerId: 'P-02', signingAddress: p02.m24b.signingPubUncomp, encryptionAddress: p02.m24b.encryptionPubUncomp },
      ],
      expected: { matchCount: 0, ambiguous: false },
      notes: 'No controlled identity registered for this candidate pair.',
    },
    {
      id: 'L-002',
      label: 'one match',
      candidates: [
        { producerId: 'P-01', signingAddress: p01.m24.signingPubComp, encryptionAddress: p01.m24.encryptionPubComp },
      ],
      expected: { matchCount: 1, ambiguous: false, registryIds: ['R-001'] },
      notes: 'Single exact address-pair match resolves to one controlled identity.',
    },
    {
      id: 'L-003',
      label: 'multiple matches (same mnemonic, both approved producers)',
      candidates: [
        { producerId: 'P-01', signingAddress: p01.m24.signingPubComp, encryptionAddress: p01.m24.encryptionPubComp },
        { producerId: 'P-02', signingAddress: p02.m24.signingPubUncomp, encryptionAddress: p02.m24.encryptionPubUncomp },
      ],
      expected: { matchCount: 2, ambiguous: true, registryIds: ['R-001', 'R-002'] },
      notes: 'The same mnemonic derives two registered identities under P-01 and P-02 contracts; the API must return an explicit ambiguous result and never silently choose.',
    },
    {
      id: 'L-004',
      label: 'exact-pair deduplication',
      candidates: [
        { producerId: 'P-02', signingAddress: p02.m24.signingPubUncomp, encryptionAddress: p02.m24.encryptionPubUncomp },
        { producerId: 'P-03', signingAddress: p02.m24.signingPubUncomp, encryptionAddress: p02.m24.encryptionPubUncomp },
      ],
      expected: { matchCount: 1, ambiguous: false, registryIds: ['R-002'], deduplicated: true, producers: ['P-02', 'P-03'] },
      notes: 'Candidates with identical exact encoded address pairs deduplicate while retaining all contributing producer IDs.',
    },
    {
      id: 'L-005',
      label: 'compressed vs uncompressed are distinct candidates',
      candidates: [
        { producerId: 'P-01', signingAddress: p01.m24.signingPubComp, encryptionAddress: p01.m24.encryptionPubComp },
        { producerId: 'P-01', signingAddress: p01.m24.signingPubUncomp, encryptionAddress: p01.m24.encryptionPubUncomp },
      ],
      expected: { matchCount: 1, ambiguous: false, registryIds: ['R-001'] },
      notes: 'Profiles are keyed by exact address strings; only the compressed pair is registered, so the uncompressed encoding is a distinct non-matching candidate.',
    },
  ],
};

writeJson('vectors/mnemonic-vectors.json', mnemonicVectors);
writeJson('vectors/key-vectors.json', keyVectors);
writeJson('vectors/dat-vectors.json', datVectors);
writeJson('vectors/canonical-byte-vectors.json', canonicalVectors);
writeJson('vectors/signature-vectors.json', signatureVectors);
writeJson('vectors/negative-vectors.json', negativeVectors);
writeJson('lookup/outcomes.json', lookup);
console.log('derivation complete');
