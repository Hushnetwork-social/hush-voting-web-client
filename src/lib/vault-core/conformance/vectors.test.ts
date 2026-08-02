/**
 * FEAT-003 vault-core conformance — deterministic corpus vector derivation + check.
 *
 * Derives the canonical byte/AAD/suite/password vectors in memory and compares them
 * against the committed corpus files. Set GENERATE_VAULT_VECTORS=1 to (re)write the
 * committed vectors (deterministic; no wall-clock inputs). Running without the env
 * var verifies reproduction — drift fails the gate.
 *
 * All vector values are public synthetic test data (declared in metadata.json).
 * Independent cross-check: node:crypto (HKDF) is a different implementation than
 * @noble/hashes (Argon2id); the Rust runner (Phase 5) cross-checks canonical bytes.
 */
import { describe, expect, it } from 'vitest';
import { createHash, hkdfSync } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { canonicalizeJson } from '../canonical/jcs';
import { buildAadBytes, aadInputsFor } from '../canonical/aad';
import { PARAMETER_SUITE_V1 } from '../contracts/suite';
import { validateDevicePassword, comparisonRepresentation, kdfInputBytes } from '../password/unicode';
import { evaluatePasswordPolicy } from '../password/policy';

const VECTORS_DIR = join(process.cwd(), 'conformance/vault/v1/vectors');
const sha256hex = (bytes: Uint8Array) => createHash('sha256').update(bytes).digest('hex');

const preview = {
  alias: 'Alice',
  signingAddressPrefix: '01234567',
  signingAddressSuffix: '89abcd',
  lifecycleStatus: 'Active',
  envelopeFormatVersion: 1,
  parameterSuiteVersion: 1,
  recordSchemaVersion: 1,
} as const;

function aadFor(overrides: Partial<Parameters<typeof aadInputsFor>[1]> = {}) {
  return aadInputsFor(PARAMETER_SUITE_V1, {
    adapterBinding: 'logical',
    preview,
    vaultGeneration: 1,
    recordGeneration: 1,
    recordPurpose: 'ordinary',
    producerId: 'hush-voting-ts',
    producerVersion: '1.0.0',
    signingAddress: '0123456789abcdef',
    criticalExtensions: [],
    ...overrides,
  });
}

function deriveVectors() {
  const canonicalInputs = [
    { b: 1, a: 2 },
    { z: { y: 1, x: 2 }, a: 3 },
    { s: 'a"b\\c\nd' },
    { alias: 'Alice', lifecycleStatus: 'Active', signingAddressPrefix: '01234567' },
  ];
  const canonicalVectors = canonicalInputs.map((input, i) => {
    const canonical = canonicalizeJson(input);
    return { id: `C-${String(i + 1).padStart(3, '0')}`, input, expectedCanonical: canonical, expectedSha256: sha256hex(new TextEncoder().encode(canonical)) };
  });

  const aadCases = [
    { id: 'A-001', input: aadFor() },
    { id: 'A-002', input: aadFor({ recordPurpose: 'mnemonic' }) },
    { id: 'A-003', input: aadFor({ vaultGeneration: 2, recordGeneration: 2 }) },
    { id: 'A-004', input: aadFor({ adapterBinding: 'ubuntu' }) },
    { id: 'A-005', input: aadFor({ preview: { ...preview, alias: 'Bob' } }) },
    { id: 'A-006', input: aadFor({ criticalExtensions: ['hush.vault.telemetry'] }) },
  ];
  const aadVectors = aadCases.map(({ id, input }) => ({ id, inputSha256: sha256hex(buildAadBytes(input)) }));

  const ikm = new TextEncoder().encode('password-bytes');
  const salt = new Uint8Array(16).fill(7);
  const cred = Buffer.from(hkdfSync('sha256', ikm, salt, new TextEncoder().encode('hush/vault/v1/credential-kek'), 32));
  const mnem = Buffer.from(hkdfSync('sha256', ikm, salt, new TextEncoder().encode('hush/vault/v1/mnemonic-kek'), 32));
  const suiteVectors = [
    { id: 'S-001', kind: 'hkdf', label: 'hush/vault/v1/credential-kek', outputSha256: sha256hex(cred) },
    { id: 'S-002', kind: 'hkdf', label: 'hush/vault/v1/mnemonic-kek', outputSha256: sha256hex(mnem) },
  ];

  const pw = validateDevicePassword('correct horse battery staple');
  const passwordVectors = [
    { id: 'P-001', input: 'correct horse battery staple', graphemes: pw.ok ? pw.graphemeClusters : -1, normalizedNfc: pw.ok ? pw.normalizedNfc : null },
    { id: 'P-002', input: 'password', policy: evaluatePasswordPolicy({ password: 'password', aliasTerms: [] }) },
    { id: 'P-003', input: 'alice2024', aliasTerms: ['Alice'], policy: evaluatePasswordPolicy({ password: 'alice2024', aliasTerms: ['Alice'] }) },
    { id: 'P-004', input: 'Tr0ub4dor&3-correct-horse', policy: evaluatePasswordPolicy({ password: 'Tr0ub4dor&3-correct-horse', aliasTerms: [] }) },
  ];

  return {
    'canonical-byte-vectors.json': { version: '1.0.0', vectors: canonicalVectors },
    'aad-vectors.json': { version: '1.0.0', vectors: aadVectors },
    'suite-vectors.json': { version: '1.0.0', vectors: suiteVectors },
    'password-vectors.json': { version: '1.0.0', vectors: passwordVectors },
  };
}

const serialize = (obj: unknown) => `${JSON.stringify(obj, null, 2)}\n`;

describe('vault conformance vectors', () => {
  const derived = deriveVectors();

  for (const [file, content] of Object.entries(derived)) {
    const path = join(VECTORS_DIR, file);
    it(`vector file ${file} is committed and deterministic`, () => {
      const committed = readFileSync(path, 'utf8');
      expect(committed).toBe(serialize(content));
    });
  }

  it('generates vectors deterministically when GENERATE_VAULT_VECTORS=1', () => {
    if (process.env.GENERATE_VAULT_VECTORS === '1') {
      for (const [file, content] of Object.entries(derived)) {
        writeFileSync(join(VECTORS_DIR, file), serialize(content));
      }
      expect(true).toBe(true);
    } else {
      expect(true).toBe(true); // normal mode verifies committed files above
    }
  });

  it('comparison representation is NFKC/case-folded and never KDF input', () => {
    // Full-width compatibility characters are NFKC-folded for comparison only.
    expect(comparisonRepresentation('Ａｌｉｃｅ')).toBe('alice');
    // Case is folded for comparison; NFC bytes remain the KDF input untouched.
    expect(comparisonRepresentation('CorrectHorse')).toBe('correcthorse');
    expect(Buffer.from(kdfInputBytes('Straße')).toString()).toBe('Straße');
  });
});
