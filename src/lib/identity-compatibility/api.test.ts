/**
 * FEAT-001 identity compatibility API — unit tests (Tasks 3.2/3.4/3.6/3.8).
 * Behavior verified against the frozen corpus values where available.
 */
import { describe, it, expect } from 'vitest';
import {
  deriveCandidates,
  deriveSelectedCredentials,
  decodeDatV1,
  parsePortableCredentialsStrict,
  validateKeyConsistency,
  serializeUnsignedTransaction,
  signMessage,
  verifyMessage,
  decodeSignature,
  resolveLookup,
  validateMnemonicForProducer,
  compactToDer,
  derToCompact,
  bytesToHexLower,
  hexToBytesStrict,
} from './index.js';
import mnemonicVectors from '../../../conformance/identity/v1/vectors/mnemonic-vectors.json';
import datVectors from '../../../conformance/identity/v1/vectors/dat-vectors.json';
import canonicalVectors from '../../../conformance/identity/v1/vectors/canonical-byte-vectors.json';
import signatureVectors from '../../../conformance/identity/v1/vectors/signature-vectors.json';
import lookupOutcomes from '../../../conformance/identity/v1/lookup/outcomes.json';

interface MnemonicVector {
  id: string;
  producerId: string;
  mnemonic: string;
  seedHex: string;
  signingPrivateKeyHex: string;
  encryptionPrivateKeyHex: string;
  signingPublicKeyHex: string;
  encryptionPublicKeyHex: string;
  publicKeyEncoding: 'COMPRESSED' | 'UNCOMPRESSED';
}
interface DatVector {
  id: string;
  operation: string;
  password?: string;
  envelopeHex?: string;
  payloadJson?: string;
  expectedPayloadJson?: string;
  expected?: string;
  errorCode?: string;
}
interface CanonicalVector {
  id: string;
  json: string;
  utf8Hex: string;
  utf8Length: number;
}
interface SignatureVector {
  id: string;
  messageUtf8: string;
  signatureCompactHex?: string;
  signatureDerHex?: string;
  publicKeyHex: string;
  expected: string;
}
interface LookupScenario {
  id: string;
  label: string;
  candidates: Array<{ producerId: string; signingAddress: string; encryptionAddress: string }>;
  expected: { matchCount: number; ambiguous: boolean; producers?: string[] };
}

const mnVectors = (mnemonicVectors as { vectors: MnemonicVector[] }).vectors;
const dtVectors = (datVectors as { vectors: DatVector[] }).vectors;
const cbVectors = (canonicalVectors as { vectors: CanonicalVector[] }).vectors;
const sgVectors = (signatureVectors as { vectors: SignatureVector[] }).vectors;
const lkScenarios = (lookupOutcomes as { scenarios: LookupScenario[] }).scenarios;
const lkRegistry = (lookupOutcomes as { registry: Array<{ signingAddress: string; encryptionAddress: string; profileAlias: string }> }).registry;

/** Corpus vectors are schema-validated and always present; fail loudly if not. */
function requireVector<T extends { id: string }>(id: string, list: T[]): T {
  const found = list.find((v) => v.id === id);
  if (!found) throw new Error(`missing corpus vector ${id}`);
  return found;
}

const M001 = requireVector('M-001', mnVectors);
const M002 = requireVector('M-002', mnVectors);
const M004 = requireVector('M-004', mnVectors);
const D001 = requireVector('D-001', dtVectors);
const CB001 = requireVector('CB-001', cbVectors);
const S001 = requireVector('S-001', sgVectors);

describe('mnemonic validation and producer adapters (3.1/3.2)', () => {
  it('P-01 derives the corpus 24-word seed, scalars, and compressed addresses', () => {
    const derived = deriveCandidates(M001.mnemonic);
    expect(derived.ok).toBe(true);
    if (!derived.ok) return;
    const p01 = derived.value.candidates.find((c) => c.producerId === 'P-01');
    expect(p01?.signingAddress).toBe(M001.signingPublicKeyHex);
    expect(p01?.encryptionAddress).toBe(M001.encryptionPublicKeyHex);
    expect(p01?.publicKeyEncoding).toBe('COMPRESSED');
    const secrets = deriveSelectedCredentials(M001.mnemonic, 'P-01');
    expect(secrets.ok).toBe(true);
    if (secrets.ok) {
      expect(secrets.value.signingPrivateKey).toBe(M001.signingPrivateKeyHex);
      expect(secrets.value.encryptionPrivateKey).toBe(M001.encryptionPrivateKeyHex);
    }
  });

  it('P-01 accepts 12-word standard-path input', () => {
    const derived = deriveCandidates(M002.mnemonic);
    expect(derived.ok).toBe(true);
    if (!derived.ok) return;
    expect(derived.value.candidates.find((c) => c.producerId === 'P-01')?.signingAddress).toBe(M002.signingPublicKeyHex);
    expect(derived.value.candidates.find((c) => c.producerId === 'P-02')).toBeUndefined();
  });

  it('P-02 derives uncompressed addresses and is rejected for 12-word input', () => {
    const derived = deriveCandidates(M004.mnemonic);
    expect(derived.ok).toBe(true);
    if (!derived.ok) return;
    const p02 = derived.value.candidates.find((c) => c.producerId === 'P-02');
    expect(p02?.signingAddress).toBe(M004.signingPublicKeyHex);
    expect(p02?.publicKeyEncoding).toBe('UNCOMPRESSED');
    expect(validateMnemonicForProducer(M002.mnemonic, 'P-02').valid).toBe(false);
    const invalid = validateMnemonicForProducer(M002.mnemonic, 'P-02');
    expect(invalid.valid ? '' : invalid.code).toBe('INVALID_WORD_COUNT');
  });

  it('classifies unknown word, checksum, uppercase, and empty inputs', () => {
    expect(validateMnemonicForProducer(M001.mnemonic.replace('unaware', 'zzzzzz'), 'P-01').valid).toBe(false);
    const unknown = validateMnemonicForProducer(M001.mnemonic.replace('unaware', 'zzzzzz'), 'P-01');
    expect(unknown.valid ? '' : unknown.code).toBe('UNKNOWN_WORD');
    const checksum = validateMnemonicForProducer(M001.mnemonic.replace('unaware', 'abandon'), 'P-01');
    expect(checksum.valid ? '' : checksum.code).toBe('INVALID_CHECKSUM');
    const upper = validateMnemonicForProducer(M001.mnemonic.toUpperCase(), 'P-01');
    expect(upper.valid ? '' : upper.code).toBe('INVALID_MNEMONIC');
    expect(validateMnemonicForProducer('', 'P-01').valid).toBe(false);
  });

  it('rejects non-empty passphrase with a typed failure (N-103)', () => {
    const derived = deriveCandidates(M001.mnemonic, 'unsupported-passphrase');
    expect(derived.ok).toBe(false);
    if (!derived.ok) expect(derived.code).toBe('UNSUPPORTED_PASSPHRASE');
  });
});

describe('candidate ordering and two-step secret access (3.3/3.4)', () => {
  it('returns P-01 before P-02 in frozen precedence order', () => {
    const derived = deriveCandidates(M001.mnemonic);
    expect(derived.ok).toBe(true);
    if (!derived.ok) return;
    const order = derived.value.candidates.map((c) => c.producerId);
    expect(order.indexOf('P-01')).toBeLessThan(order.indexOf('P-02'));
  });

  it('deduplicates identical exact address pairs while retaining producer IDs (L-004)', () => {
    const derived = deriveCandidates(M001.mnemonic);
    expect(derived.ok).toBe(true);
    if (!derived.ok) return;
    const p02 = derived.value.candidates.find((c) => c.producerId === 'P-02');
    expect(p02?.producerIds.sort()).toEqual(['P-02', 'P-03']);
  });

  it('keeps compressed and uncompressed encodings as distinct candidates', () => {
    const derived = deriveCandidates(M001.mnemonic);
    expect(derived.ok).toBe(true);
    if (!derived.ok) return;
    const addresses = derived.value.candidates.map((c) => c.signingAddress);
    expect(new Set(addresses).size).toBe(addresses.length);
  });

  it('resolves lookup scenarios from the corpus (zero/one/multiple)', () => {
    const registry = lkRegistry;
    for (const scenario of lkScenarios) {
      const candidates = scenario.candidates.map((c) => ({
        producerId: c.producerId,
        producerName: c.producerId,
        precedence: 0,
        producerIds: [c.producerId],
        signingAddress: c.signingAddress,
        encryptionAddress: c.encryptionAddress,
        publicKeyEncoding: c.signingAddress.startsWith('04') ? ('UNCOMPRESSED' as const) : ('COMPRESSED' as const),
      }));
      const result = resolveLookup(candidates, registry);
      expect(result.matchCount, scenario.label).toBe(scenario.expected.matchCount);
      expect(result.ambiguous, scenario.label).toBe(scenario.expected.ambiguous);
    }
  });

  it('derives private credentials only for the selected producer', () => {
    const p01 = deriveSelectedCredentials(M001.mnemonic, 'P-01');
    const p02 = deriveSelectedCredentials(M001.mnemonic, 'P-02');
    expect(p01.ok).toBe(true);
    expect(p02.ok).toBe(true);
    if (p01.ok && p02.ok) {
      expect(p01.value.signingPrivateKey).not.toBe(p02.value.signingPrivateKey);
      expect(p01.value.producerId).toBe('P-01');
      expect(p02.value.producerId).toBe('P-02');
    }
    const unsupported = deriveSelectedCredentials(M001.mnemonic, 'P-99');
    expect(unsupported.ok).toBe(false);
    if (!unsupported.ok) expect(unsupported.code).toBe('UNSUPPORTED_PRODUCER');
  });
});

describe('pure .dat v1 operations (3.5/3.6)', () => {
  it('decodes the positive corpus fixture (D-001) with full consistency', async () => {
    const result = await decodeDatV1(hexToBytesStrict(D001.envelopeHex!), D001.password!);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(JSON.stringify(result.value.record)).toBe(D001.expectedPayloadJson);
      expect(result.value.privatePublicConsistent).toBe(true);
      expect(result.value.mnemonicKeyConsistent).toBe(true);
    }
  });

  it('rejects wrong password, wrong magic, wrong version, truncation, tamper', async () => {
    const cases = [
      { id: 'D-002', expect: 'DAT_WRONG_PASSWORD' },
      { id: 'D-003', expect: 'DAT_INVALID_MAGIC' },
      { id: 'D-004', expect: 'DAT_UNSUPPORTED_VERSION' },
      { id: 'D-005', expect: 'DAT_WRONG_PASSWORD' },
      { id: 'D-007', expect: 'DAT_MALFORMED' },
      { id: 'D-008', expect: 'DAT_WRONG_PASSWORD' },
    ];
    for (const c of cases) {
      const v = dtVectors.find((x) => x.id === c.id)!;
      const result = await decodeDatV1(hexToBytesStrict(v.envelopeHex!), v.password!);
      expect(result.ok, c.id).toBe(false);
      if (!result.ok) expect(result.code, c.id).toBe(c.expect);
    }
  });

  it('rejects oversized envelopes before PBKDF2 (D-006)', async () => {
    const oversized = Buffer.concat([Buffer.from(D001.envelopeHex!, 'hex'), Buffer.alloc(1024 * 1024 + 1)]);
    const result = await decodeDatV1(new Uint8Array(oversized), D001.password!);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('DAT_MALFORMED');
  });

  it('strictly rejects unknown, missing, duplicate, null, and wrong-type fields', () => {
    const cases = [
      { id: 'D-009', expect: 'DAT_MISSING_FIELD' },
      { id: 'D-010', expect: 'DAT_UNKNOWN_FIELD' },
      { id: 'D-011', expect: 'DAT_DUPLICATE_FIELD' },
      { id: 'D-012', expect: 'DAT_INVALID_FIELD' },
      { id: 'D-013', expect: 'DAT_INVALID_FIELD' },
    ];
    for (const c of cases) {
      const v = dtVectors.find((x) => x.id === c.id)!;
      const result = parsePortableCredentialsStrict(v.payloadJson!);
      expect(result.ok, c.id).toBe(false);
      if (!result.ok) expect(result.code, c.id).toBe(c.expect);
    }
  });

  it('does not false-positive on escaped-quote values (duplicate-key heuristic)', () => {
    // A value containing an escaped quote followed by a colon must not be
    // mistaken for a duplicate property.
    const payload =
      '{"ProfileName":"say \\"hi\\": now","PublicSigningAddress":"0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5",' +
      '"PrivateSigningKey":"6e3f74236c3d4a20553be05963f624696990c22245599b3d1b30262af793d885",' +
      '"PublicEncryptAddress":"032ebaf076203f15ac8119cfdbc9394d1c7b9929b0647e4f607e27da95701f8556",' +
      '"PrivateEncryptKey":"1a68f2d543282dd612502a1b3688e85eeca280057129d512011645a51cf6d552",' +
      '"IsPublic":true,"Mnemonic":null}';
    const result = parsePortableCredentialsStrict(payload);
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.ProfileName).toBe('say "hi": now');
  });

  it('detects mnemonic/key and private/public mismatches (D-014/D-015)', () => {
    const d014 = dtVectors.find((x) => x.id === 'D-014')!;
    const d015 = dtVectors.find((x) => x.id === 'D-015')!;
    const parsed014 = parsePortableCredentialsStrict(d014.payloadJson!);
    const parsed015 = parsePortableCredentialsStrict(d015.payloadJson!);
    // Structurally valid: both fail only on key/mnemonic consistency.
    expect(parsed014.ok).toBe(true);
    expect(parsed015.ok).toBe(true);
    if (parsed014.ok && parsed015.ok) {
      const c014 = validateKeyConsistency(parsed014.value);
      expect(c014.privatePublicConsistent).toBe(true);
      expect(c014.mnemonicKeyConsistent).toBe(false);
      const c015 = validateKeyConsistency(parsed015.value);
      expect(c015.privatePublicConsistent).toBe(false);
    }
  });

  it('decodeDatV1 returns typed failures for key and mnemonic mismatches', async () => {
    // Build real envelopes for the D-014/D-015 payloads using the exact v1
    // envelope layout (HUSH magic, version=1, 16-byte salt, 12-byte nonce).
    const buildEnvelope = async (payloadJson: string): Promise<string> => {
      const subtle = globalThis.crypto.subtle;
      const salt = new Uint8Array(16);
      const nonce = new Uint8Array(12);
      for (let i = 0; i < 16; i++) salt[i] = 0x30 + i;
      for (let i = 0; i < 12; i++) nonce[i] = 0xa0 + i;
      const keyMaterial = await subtle.importKey('raw', new TextEncoder().encode(D001.password), 'PBKDF2', false, ['deriveKey']);
      const key = await subtle.deriveKey(
        { name: 'PBKDF2', salt: salt.buffer, iterations: 100_000, hash: 'SHA-256' },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt'],
      );
      const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv: nonce.buffer, tagLength: 128 }, key, new TextEncoder().encode(payloadJson));
      const head = new Uint8Array([0x48, 0x55, 0x53, 0x48, 1, 0, 0, 0, ...salt, ...nonce]);
      return bytesToHexLower(new Uint8Array([...head, ...new Uint8Array(ciphertext)]));
    };
    const d014 = dtVectors.find((x) => x.id === 'D-014')!;
    const d015 = dtVectors.find((x) => x.id === 'D-015')!;
    const r014 = await decodeDatV1(hexToBytesStrict(await buildEnvelope(d014.payloadJson!)), D001.password!);
    expect(r014.ok).toBe(false);
    if (!r014.ok) expect(r014.code).toBe('DAT_MNEMONIC_KEY_MISMATCH');
    const r015 = await decodeDatV1(hexToBytesStrict(await buildEnvelope(d015.payloadJson!)), D001.password!);
    expect(r015.ok).toBe(false);
    if (!r015.ok) expect(r015.code).toBe('DAT_KEY_MISMATCH');
  });
});

describe('canonical bytes and signatures (3.7/3.8)', () => {
  it('serializes the canonical transaction exactly (CB-001)', () => {
    const tx = JSON.parse(CB001.json);
    expect(serializeUnsignedTransaction(tx)).toBe(CB001.json);
    expect(Buffer.byteLength(serializeUnsignedTransaction(tx), 'utf8')).toBe(CB001.utf8Length);
  });

  it('tamper variants differ from the canonical serialization', () => {
    const base = JSON.parse(CB001.json);
    const canonical = serializeUnsignedTransaction(base);
    for (const v of canonicalVectors.vectors) {
      if (v.id === 'CB-001') continue;
      expect(v.json).not.toBe(canonical);
      expect(Buffer.byteLength(v.json, 'utf8')).toBe(v.utf8Length);
    }
  });

  it('signs and verifies round-trip (compact and DER)', () => {
    const secrets = deriveSelectedCredentials(M001.mnemonic, 'P-01');
    expect(secrets.ok).toBe(true);
    if (!secrets.ok) return;
    const material = signMessage(CB001.json, secrets.value.signingPrivateKey);
    expect(material.ok).toBe(true);
    if (!material.ok) return;
    expect(verifyMessage(CB001.json, material.value.compactHex, secrets.value.signingAddress, 'compact')).toBe(true);
    expect(verifyMessage(CB001.json, material.value.derHex, secrets.value.signingAddress, 'der')).toBe(true);
    expect(verifyMessage(CB001.json.replace('12:34:56.789Z', '12:34:56.790Z'), material.value.compactHex, secrets.value.signingAddress, 'compact')).toBe(false);
  });

  it('verifies the fixed corpus signature fixtures (S-001) with both encodings', () => {
    expect(verifyMessage(S001.messageUtf8, S001.signatureCompactHex!, S001.publicKeyHex, 'compact')).toBe(true);
    expect(verifyMessage(S001.messageUtf8, S001.signatureDerHex!, S001.publicKeyHex, 'der')).toBe(true);
  });

  it('rejects malformed signature encodings deterministically', () => {
    const malformed = decodeSignature(S001.signatureCompactHex!.slice(0, 126), 'compact');
    expect(malformed.ok).toBe(false);
    if (!malformed.ok) expect(malformed.code).toBe('SIGNATURE_MALFORMED');
    const malformedDer = decodeSignature('302a020100', 'der');
    expect(malformedDer.ok).toBe(false);
  });

  it('DER <-> compact conversion is lossless', () => {
    const der = compactToDer(hexToBytesStrict(S001.signatureCompactHex!.slice(0, 64)), hexToBytesStrict(S001.signatureCompactHex!.slice(64)));
    expect(bytesToHexLower(derToCompact(der))).toBe(S001.signatureCompactHex!);
  });
});
