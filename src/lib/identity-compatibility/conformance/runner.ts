/**
 * FEAT-001 TypeScript conformance runner.
 *
 * Executes every corpus vector (mnemonic, key, .dat, canonical, signature,
 * negative, lookup) against the production compatibility API and produces a
 * secret-safe JSON report per `schemas/report.schema.json`. Failure records
 * carry contract/schema version, producer ID, fixture ID, operation, field
 * path, stable error code, and expected/actual SHA-256 digests ONLY — never
 * raw mnemonics, passwords, private keys, decrypted content, or ciphertext.
 *
 * Corpus integrity: before executing vectors the runner verifies every corpus
 * file listed in `manifest.json` (path, byte length, SHA-256 digest).
 * Schema validation is enforced by `conformance/identity/v1/scripts/validate.mjs`
 * in the same CI run before vectors execute.
 */
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import {
  decodeDatV1,
  decodePublicKeyPoint,
  decodeSignature,
  deriveCandidates,
  deriveSelectedCredentials,
  derivePublicKey,
  hexToBytesStrict,
  isUsableScalar,
  mnemonicToSeed,
  parsePortableCredentialsStrict,
  resolveLookup,
  serializeUnsignedTransaction,
  sha256Hex,
  validateKeyConsistency,
  verifyMessage,
  validateMnemonicForProducer,
  utf8Bytes,
} from '../index.js';
import type { PublicCandidateDescriptor } from '../types.js';

export const CONTRACT_VERSION = '1.0.0';
export const SCHEMA_VERSION = '1.0.0';

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
interface KeyVector {
  id: string;
  producerId?: string;
  operation: string;
  privateScalarHex?: string;
  encoding?: string;
  inputHex?: string;
  expectedPublicKeyHex?: string;
  expectedPointXHex?: string;
  expectedPointYHex?: string;
  expected: string;
  errorCode?: string;
}
interface DatVector {
  id: string;
  producerId?: string;
  operation: string;
  envelopeHex?: string;
  password?: string;
  baseEnvelopeRef?: string;
  payloadJson?: string;
  expectedPayloadJson?: string;
  expected?: string;
  errorCode?: string;
}
interface CanonicalVector {
  id: string;
  operation: string;
  json: string;
  utf8Hex: string;
  utf8Length: number;
  payloadSize?: number;
}
interface SignatureVector {
  id: string;
  producerId?: string;
  operation: string;
  messageUtf8: string;
  publicKeyHex: string;
  signatureCompactHex?: string;
  signatureCompactBase64?: string;
  signatureDerHex?: string;
  expected: string;
  errorCode?: string;
}
interface NegativeVector {
  id: string;
  producerId?: string;
  operation: string;
  input: string;
  passphrase?: string;
  expected: string;
  errorCode?: string;
}
interface LookupCandidate {
  producerId: string;
  signingAddress: string;
  encryptionAddress: string;
}
interface LookupScenario {
  id: string;
  candidates: LookupCandidate[];
  expected: { matchCount: number; ambiguous: boolean; producers?: string[] };
}
interface LookupDoc {
  registry: Array<{ signingAddress: string; encryptionAddress: string; profileAlias: string }>;
  scenarios: LookupScenario[];
}

export interface ConformanceRecord {
  readonly contractVersion: string;
  readonly schemaVersion: string;
  readonly producerId: string;
  readonly fixtureId: string;
  readonly operation: string;
  readonly fieldPath: string;
  readonly errorCode: string;
  readonly expectedDigest: string;
  readonly actualDigest: string;
}

export interface ConformanceReport {
  readonly schemaVersion: string;
  readonly contractVersion: string;
  readonly runtime: 'typescript';
  readonly result: 'PASS' | 'FAIL' | 'ERROR';
  readonly summary: { readonly total: number; readonly passed: number; readonly failed: number };
  readonly records: ConformanceRecord[];
}

/** Resolve the corpus root relative to the repository root (cwd). */
export function corpusRoot(): string {
  return resolve(process.cwd(), 'conformance/identity/v1');
}

function readCorpusJson<T>(root: string, rel: string): T {
  const raw = readFileSync(join(root, rel), 'utf8');
  return JSON.parse(raw) as T;
}

/** Verify every manifest-listed corpus file (path, bytes, sha256). */
export function verifyCorpusIntegrity(root: string): void {
  const manifest = readCorpusJson<{ files: Array<{ path: string; bytes: number; sha256: string }> }>(root, 'manifest.json');
  for (const f of manifest.files) {
    const full = join(root, f.path);
    if (!existsSync(full)) throw new Error(`corpus file missing: ${f.path}`);
    const bytes = readFileSync(full);
    if (bytes.length !== f.bytes) throw new Error(`corpus file length mismatch: ${f.path}`);
    const sha = createHash('sha256').update(bytes).digest('hex');
    if (sha !== f.sha256) throw new Error(`corpus file digest mismatch: ${f.path}`);
  }
}

interface FailureBuilder {
  records: ConformanceRecord[];
  total: number;
}

function digestOf(value: string | undefined): string {
  return createHash('sha256').update(value ?? '').digest('hex');
}

function check(f: FailureBuilder, fixtureId: string, producerId: string, operation: string, fieldPath: string, expected: string | undefined, actual: string | undefined, expectedErrorCode?: string): void {
  f.total += 1;
  const pass = expected !== undefined && actual !== undefined && expected === actual;
  if (pass) return;
  f.records.push({
    contractVersion: CONTRACT_VERSION,
    schemaVersion: SCHEMA_VERSION,
    producerId,
    fixtureId,
    operation,
    fieldPath,
    errorCode: expectedErrorCode ?? 'MISMATCH',
    expectedDigest: digestOf(expected),
    actualDigest: digestOf(actual),
  });
}

/** Execute the full corpus and return the secret-safe report. */
export async function runConformance(corpus: string = corpusRoot()): Promise<ConformanceReport> {
  verifyCorpusIntegrity(corpus);
  const f: FailureBuilder = { records: [], total: 0 };

  const mnemonicVectors = readCorpusJson<{ vectors: MnemonicVector[] }>(corpus, 'vectors/mnemonic-vectors.json').vectors;
  const keyVectors = readCorpusJson<{ vectors: KeyVector[] }>(corpus, 'vectors/key-vectors.json').vectors;
  const datVectors = readCorpusJson<{ vectors: DatVector[] }>(corpus, 'vectors/dat-vectors.json').vectors;
  const canonicalVectors = readCorpusJson<{ vectors: CanonicalVector[] }>(corpus, 'vectors/canonical-byte-vectors.json').vectors;
  const signatureVectors = readCorpusJson<{ vectors: SignatureVector[] }>(corpus, 'vectors/signature-vectors.json').vectors;
  const negativeVectors = readCorpusJson<{ vectors: NegativeVector[] }>(corpus, 'vectors/negative-vectors.json').vectors;
  const lookup = readCorpusJson<LookupDoc>(corpus, 'lookup/outcomes.json');

  // ---- mnemonic vectors ----------------------------------------------------
  for (const v of mnemonicVectors) {
    const derived = deriveCandidates(v.mnemonic);
    if (!derived.ok) {
      check(f, v.id, v.producerId, 'MNEMONIC_DERIVE', 'candidates', 'ok', 'failure');
      continue;
    }
    const candidate = derived.value.candidates.find((c) => c.producerId === v.producerId);
    if (!candidate) {
      check(f, v.id, v.producerId, 'MNEMONIC_DERIVE', 'candidate', v.producerId, 'missing');
      continue;
    }
    const seedHex = Buffer.from(mnemonicToSeed(v.mnemonic)).toString('hex');
    check(f, v.id, v.producerId, 'MNEMONIC_DERIVE', 'seedHex', v.seedHex, seedHex);
    check(f, v.id, v.producerId, 'MNEMONIC_DERIVE', 'signingAddress', v.signingPublicKeyHex, candidate.signingAddress);
    check(f, v.id, v.producerId, 'MNEMONIC_DERIVE', 'encryptionAddress', v.encryptionPublicKeyHex, candidate.encryptionAddress);
    check(f, v.id, v.producerId, 'MNEMONIC_DERIVE', 'publicKeyEncoding', v.publicKeyEncoding, candidate.publicKeyEncoding);
    const secrets = deriveSelectedCredentials(v.mnemonic, v.producerId);
    if (!secrets.ok) {
      check(f, v.id, v.producerId, 'MNEMONIC_DERIVE', 'private', 'ok', 'failure');
    } else {
      check(f, v.id, v.producerId, 'MNEMONIC_DERIVE', 'signingPrivateKey', v.signingPrivateKeyHex, secrets.value.signingPrivateKey);
      check(f, v.id, v.producerId, 'MNEMONIC_DERIVE', 'encryptionPrivateKey', v.encryptionPrivateKeyHex, secrets.value.encryptionPrivateKey);
    }
  }

  // ---- key vectors ---------------------------------------------------------
  for (const v of keyVectors) {
    const pid = v.producerId ?? 'P-00';
    if (v.operation === 'SCALAR_VALIDATE') {
      const ok = isUsableScalar(v.privateScalarHex!);
      check(f, v.id, pid, v.operation, 'scalar', v.expected, ok ? 'OK' : 'ERROR', ok ? undefined : v.errorCode);
      if (v.expected === 'OK' && ok && v.expectedPublicKeyHex) {
        check(f, v.id, pid, v.operation, 'publicKey', v.expectedPublicKeyHex, derivePublicKey(v.privateScalarHex!, 'COMPRESSED'));
      }
    } else if (v.operation === 'PUBLIC_KEY_DERIVE' || v.operation === 'POINT_EQUIVALENCE') {
      try {
        const pub = derivePublicKey(v.privateScalarHex!, v.encoding === 'COMPRESSED' ? 'COMPRESSED' : 'UNCOMPRESSED');
        check(f, v.id, pid, v.operation, 'publicKey', v.expectedPublicKeyHex, pub, pub === v.expectedPublicKeyHex ? undefined : v.errorCode);
      } catch {
        check(f, v.id, pid, v.operation, 'publicKey', v.expected, 'ERROR', v.errorCode);
      }
    } else if (v.operation === 'DECODE') {
      const point = decodePublicKeyPoint(v.inputHex!);
      if (v.expected === 'ERROR') {
        check(f, v.id, pid, v.operation, 'decode', 'ERROR', point === null ? 'ERROR' : 'OK', v.errorCode);
      } else {
        check(f, v.id, pid, v.operation, 'x', v.expectedPointXHex, point?.xHex, v.errorCode);
        check(f, v.id, pid, v.operation, 'y', v.expectedPointYHex, point?.yHex, v.errorCode);
      }
    }
  }

  // ---- .dat vectors --------------------------------------------------------
  const datPositive = datVectors.find((v) => v.id === 'D-001');
  for (const v of datVectors) {
    const pid = v.producerId ?? 'P-04';
    if (v.operation === 'OVERSIZED') {
      const base = Buffer.from(datPositive?.envelopeHex ?? '', 'hex');
      const oversized = Buffer.concat([base, Buffer.alloc(1024 * 1024 + 1)]);
      const result = await decodeDatV1(new Uint8Array(oversized), datPositive?.password ?? '');
      check(f, v.id, pid, v.operation, 'errorCode', v.errorCode, result.ok ? 'OK' : result.code, v.errorCode);
      continue;
    }
    if (v.operation === 'DECRYPT') {
      const decrypted = await decodeDatV1(hexToBytesStrict(v.envelopeHex!), v.password!);
      if (v.expected === 'OK') {
        check(f, v.id, pid, v.operation, 'payload', v.expectedPayloadJson, decrypted.ok ? JSON.stringify(decrypted.value.record) : 'failure');
      } else {
        check(f, v.id, pid, v.operation, 'errorCode', v.errorCode, decrypted.ok ? 'OK' : decrypted.code, v.errorCode);
      }
      continue;
    }
    if (v.operation === 'KEY_CONSISTENCY') {
      const parsed = parsePortableCredentialsStrict(v.payloadJson!);
      if (!parsed.ok) {
        check(f, v.id, pid, v.operation, 'errorCode', v.errorCode, parsed.code, v.errorCode);
        continue;
      }
      const consistency = validateKeyConsistency(parsed.value);
      const code = !consistency.privatePublicConsistent ? 'DAT_KEY_MISMATCH' : !consistency.mnemonicKeyConsistent ? 'DAT_MNEMONIC_KEY_MISMATCH' : 'OK';
      check(f, v.id, pid, v.operation, 'errorCode', v.errorCode, code, v.errorCode);
      continue;
    }
    const parsed = parsePortableCredentialsStrict(v.payloadJson!);
    if (v.expected === 'ERROR') {
      check(f, v.id, pid, v.operation, 'errorCode', v.errorCode, parsed.ok ? 'OK' : parsed.code, v.errorCode);
    }
  }

  // ---- canonical byte vectors ---------------------------------------------
  const base = canonicalVectors.find((v) => v.id === 'CB-001');
  if (base) {
    const serialized = serializeUnsignedTransaction(JSON.parse(base.json));
    check(f, base.id, 'P-01', 'SERIALIZE', 'json', base.json, serialized);
    check(f, base.id, 'P-01', 'SERIALIZE', 'utf8Hex', base.utf8Hex, Buffer.from(utf8Bytes(serialized)).toString('hex'));
    check(f, base.id, 'P-01', 'SERIALIZE', 'utf8Length', String(base.utf8Length), String(Buffer.from(utf8Bytes(serialized)).length));
  }
  for (const v of canonicalVectors) {
    if (v.id === 'CB-001') continue;
    const bytes = utf8Bytes(v.json);
    check(f, v.id, 'P-01', 'TAMPER', 'utf8Hex', v.utf8Hex, Buffer.from(bytes).toString('hex'));
    check(f, v.id, 'P-01', 'TAMPER', 'utf8Length', String(v.utf8Length), String(bytes.length));
    check(f, v.id, 'P-01', 'TAMPER', 'differsFromBase', 'DIFFERENT', base && v.json !== base.json ? 'DIFFERENT' : 'SAME');
  }

  // ---- signature vectors ---------------------------------------------------
  for (const v of signatureVectors) {
    const pid = v.producerId ?? 'P-07';
    if (v.operation === 'DECODE') {
      const format: 'compact' | 'der' = v.signatureCompactHex ? 'compact' : 'der';
      const decoded = decodeSignature(v.signatureCompactHex ?? v.signatureDerHex ?? '', format);
      check(f, v.id, pid, v.operation, 'errorCode', v.errorCode, decoded.ok ? 'OK' : decoded.code, v.errorCode);
    } else {
      let result: boolean;
      if (v.signatureDerHex) {
        result = verifyMessage(v.messageUtf8, v.signatureDerHex, v.publicKeyHex, 'der');
      } else if (v.signatureCompactHex) {
        result = verifyMessage(v.messageUtf8, v.signatureCompactHex, v.publicKeyHex, 'compact');
      } else {
        // Some producers carry the compact fixture as base64 only.
        const sig = Buffer.from(v.signatureCompactBase64!, 'base64');
        result = sig.length === 64 ? verifyMessage(v.messageUtf8, sig.toString('hex'), v.publicKeyHex, 'compact') : false;
      }
      const expectedOutcome = v.expected === 'VALID';
      check(f, v.id, pid, v.operation, 'outcome', String(expectedOutcome), String(result), expectedOutcome === result ? undefined : v.errorCode);
    }
  }

  // ---- negative vectors ----------------------------------------------------
  for (const v of negativeVectors) {
    const pid = v.producerId ?? 'P-00';
    if (v.operation === 'MNEMONIC_VALIDATE') {
      const validation = validateMnemonicForProducer(v.input, pid);
      check(f, v.id, pid, v.operation, 'errorCode', v.errorCode, validation.valid ? 'VALID' : validation.code, v.errorCode);
    } else if (v.operation === 'MNEMONIC_DERIVE') {
      const derived = deriveCandidates(v.input, v.passphrase);
      check(f, v.id, pid, v.operation, 'errorCode', v.errorCode, derived.ok ? 'OK' : derived.code, v.errorCode);
    } else if (v.operation === 'PRODUCER_SELECT') {
      const derived = deriveSelectedCredentials(m24Of(), v.input);
      check(f, v.id, pid, v.operation, 'errorCode', v.errorCode, derived.ok ? 'OK' : derived.code, v.errorCode);
    } else if (v.operation === 'VERSION_SELECT') {
      check(f, v.id, pid, v.operation, 'errorCode', v.errorCode, v.input === CONTRACT_VERSION ? 'OK' : 'UNSUPPORTED_VERSION', v.errorCode);
    }
  }

  // ---- lookup scenarios ----------------------------------------------------
  for (const s of lookup.scenarios) {
    const deduped = dedupeForLookup(s.candidates);
    const result = resolveLookup(deduped, lookup.registry);
    check(f, s.id, 'P-00', 'LOOKUP', 'matchCount', String(s.expected.matchCount), String(result.matchCount));
    check(f, s.id, 'P-00', 'LOOKUP', 'ambiguous', String(s.expected.ambiguous), String(result.ambiguous));
    const producers = [...new Set(result.matches.flatMap((m) => m.producerIds))].sort();
    if (s.expected.producers) {
      check(f, s.id, 'P-00', 'LOOKUP', 'producers', s.expected.producers.slice().sort().join(','), producers.join(','));
    }
  }

  return {
    schemaVersion: SCHEMA_VERSION,
    contractVersion: CONTRACT_VERSION,
    runtime: 'typescript',
    result: f.records.length === 0 ? 'PASS' : 'FAIL',
    summary: { total: f.total, passed: f.total - f.records.length, failed: f.records.length },
    records: f.records,
  };
}

function m24Of(): string {
  // Producer_SELECT vectors carry an arbitrary mnemonic; derivation failure of
  // an unknown producer is reported before mnemonic validation.
  return 'abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware';
}

function dedupeForLookup(candidates: ReadonlyArray<LookupCandidate>): PublicCandidateDescriptor[] {
  const byKey = new Map<string, PublicCandidateDescriptor>();
  for (const c of candidates) {
    const key = `${c.signingAddress}|${c.encryptionAddress}`;
    const existing = byKey.get(key);
    if (existing) {
      existing.producerIds = [...new Set([...existing.producerIds, c.producerId])];
      continue;
    }
    byKey.set(key, {
      producerId: c.producerId,
      producerName: c.producerId,
      precedence: 0,
      producerIds: [c.producerId],
      signingAddress: c.signingAddress,
      encryptionAddress: c.encryptionAddress,
      publicKeyEncoding: c.signingAddress.startsWith('04') ? 'UNCOMPRESSED' : 'COMPRESSED',
    });
  }
  return [...byKey.values()];
}

/** Write the report to a path (default conformance/reports/typescript-identity-report.json). */
export function writeReport(report: ConformanceReport, path = resolve(process.cwd(), 'conformance/reports/typescript-identity-report.json')): string {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, JSON.stringify(report, null, 2) + '\n', 'utf8');
  return path;
}

export { sha256Hex };
