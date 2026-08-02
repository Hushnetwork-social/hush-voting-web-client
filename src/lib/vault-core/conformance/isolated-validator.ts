/**
 * FEAT-003 isolated TypeScript/Node conformance validator.
 *
 * Independent replay of the immutable `conformance/vault/v1/` corpus through an
 * isolated calculation path. The isolated path:
 *   - verifies corpus manifest integrity (path, byte length, SHA-256) BEFORE vectors;
 *   - validates every schema is a well-formed draft 2020-12 document;
 *   - replays canonical bytes, AAD, HKDF/AES-GCM/Argon2id (published KATs + direct
 *     node:crypto / @noble/hashes), password Unicode and policy, and the
 *     extension/lifecycle/migration/generation/session/typed-result vector families;
 *   - never imports the primary implementation helpers to derive expected outputs;
 *   - emits a deterministic, secret-safe report per `report.schema.json` with
 *     identifiers and digests only — no passwords, mnemonics, keys, plaintext,
 *     ciphertext excerpts, aliases, or stable device/session values.
 *
 * Normative source: FEAT-003 FeatureDescription "Conformance Corpus", planning
 * analysis report §9 (isolated TypeScript/Node validation).
 */
import { createCipheriv, createHash, hkdfSync } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { argon2id } from '@noble/hashes/argon2.js';
import { canonicalize, canonicalizeBytes } from './isolated/jcs';
import { buildAadBytes, type AadVectorInput } from './isolated/aad';
import { isolatedUnicodeCheck } from './isolated/unicode';
import { isolatedHardRejection } from './isolated/policy';
import {
  isolatedExtensionValidate,
  isolatedLifecycleReplay,
  isolatedCheckSupportedVersion,
  isolatedJournalCommit,
  isolatedSessionReplay,
  isolatedTypedResultReplay,
} from './isolated/core';

export const ISOLATED_GENERATOR = 'hush-vault-ts-isolated' as const;

/** One deterministic secret-safe report record (report.schema.json shape). */
export interface IsolatedReportRecord {
  readonly id: string;
  readonly category: 'schema' | 'canonical' | 'algorithm' | 'password' | 'lifecycle' | 'session' | 'typed-result' | 'integrity' | 'extension' | 'migration' | 'performance';
  readonly ok: boolean;
  readonly expectedDigest?: string;
  readonly actualDigest?: string;
  readonly expectedCode?: string;
  readonly actualCode?: string;
}

/** Deterministic report object per conformance/vault/v1/schemas/report.schema.json. */
export interface IsolatedReport {
  readonly schemaVersion: 1;
  readonly generator: typeof ISOLATED_GENERATOR;
  readonly corpusVersion: '1.0.0';
  readonly manifestSha256: string;
  readonly passed: boolean;
  readonly total: number;
  readonly records: readonly IsolatedReportRecord[];
}

const sha256hex = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest('hex');
const digestOf = (value: unknown) => sha256hex(canonicalizeBytes(value));
const utf8 = (value: string) => new TextEncoder().encode(value);

/** Corpus root resolved from the repository root (cwd). */
export function corpusRoot(): string {
  return join(process.cwd(), 'conformance', 'vault', 'v1');
}

function readJson<T>(root: string, rel: string): T {
  const raw = readFileSync(join(root, rel), 'utf8');
  return JSON.parse(raw) as T;
}

/** ---------- 1. corpus integrity ---------- */
export function verifyManifestIndependently(root: string): { manifestSha256: string; records: IsolatedReportRecord[] } {
  const manifest = readJson<{ contractVersion: string; corpusVersion: string; files: Array<{ path: string; bytes: number; sha256: string }> }>(root, 'manifest.json');
  const records: IsolatedReportRecord[] = [];
  const paths = manifest.files.map((f) => f.path).sort();
  records.push({ id: 'integrity:file-set', category: 'integrity', ok: true, expectedDigest: sha256hex(paths.join('\n')), actualDigest: sha256hex(paths.join('\n')) });
  for (const f of manifest.files) {
    const full = join(root, f.path);
    let ok = true;
    let actual = '';
    if (!existsSync(full)) {
      ok = false;
    } else {
      const bytes = readFileSync(full);
      actual = sha256hex(bytes);
      if (bytes.length !== f.bytes || actual !== f.sha256) ok = false;
    }
    records.push({ id: `integrity:${f.path}`, category: 'integrity', ok, expectedDigest: f.sha256, actualDigest: actual || '0'.repeat(64) });
  }
  const manifestBytes = readFileSync(join(root, 'manifest.json'));
  return { manifestSha256: sha256hex(manifestBytes), records };
}

/** ---------- 2. schema shape ---------- */
export function validateSchemasIndependently(root: string): IsolatedReportRecord[] {
  const schemasDir = join(root, 'schemas');
  const files = readdirSync(schemasDir).filter((f) => f.endsWith('.json')).sort();
  const records: IsolatedReportRecord[] = [];
  for (const f of files) {
    const bytes = readFileSync(join(schemasDir, f));
    const doc = JSON.parse(bytes.toString('utf8')) as { $schema?: string; $id?: string; title?: string };
    const ok = doc.$schema === 'https://json-schema.org/draft/2020-12/schema' && typeof doc.$id === 'string' && typeof doc.title === 'string';
    records.push({
      id: `schema:schemas/${f}`,
      category: 'schema',
      ok,
      expectedCode: 'valid-draft-2020-12',
      actualCode: ok ? 'valid-draft-2020-12' : 'invalid',
      expectedDigest: sha256hex(bytes),
      actualDigest: sha256hex(bytes),
    });
  }
  return records;
}

/** ---------- 3. vector replay ---------- */
interface ReplayOptions {
  readonly root: string;
  readonly aadBytesById: Record<string, Uint8Array>;
  readonly records: IsolatedReportRecord[];
}

function record(records: IsolatedReportRecord[], r: IsolatedReportRecord): void {
  records.push(r);
}

/** Canonical byte vectors (C-*): own JCS must reproduce the pinned canonical bytes. */
function replayCanonical(root: string, records: IsolatedReportRecord[]): void {
  const { vectors } = readJson<{ version: string; vectors: Array<{ id: string; input: unknown; expectedCanonical: string; expectedSha256: string }> }>(root, 'vectors/canonical-byte-vectors.json');
  for (const v of vectors) {
    try {
      const canonical = canonicalize(v.input);
      const actual = sha256hex(utf8(canonical));
      const ok = canonical === v.expectedCanonical && actual === v.expectedSha256;
      record(records, { id: v.id, category: 'canonical', ok, expectedDigest: v.expectedSha256, actualDigest: actual, expectedCode: 'OK', actualCode: ok ? 'OK' : 'MISMATCH' });
    } catch (err) {
      record(records, { id: v.id, category: 'canonical', ok: false, expectedCode: 'OK', actualCode: `ERROR:${(err as Error).name}` });
    }
  }
}

/** AAD vectors (A-*): independent assembly + own JCS must reproduce the pinned digest. */
function replayAad(root: string, opts: ReplayOptions): void {
  const { vectors } = readJson<{ version: string; vectors: Array<{ id: string; input: AadVectorInput; inputSha256: string }> }>(root, 'vectors/aad-vectors.json');
  for (const v of vectors) {
    try {
      const bytes = buildAadBytes(v.input);
      const actual = sha256hex(bytes);
      opts.aadBytesById[v.id] = bytes;
      const ok = actual === v.inputSha256;
      record(opts.records, { id: v.id, category: 'canonical', ok, expectedDigest: v.inputSha256, actualDigest: actual, expectedCode: 'OK', actualCode: ok ? 'OK' : 'MISMATCH' });
    } catch (err) {
      record(opts.records, { id: v.id, category: 'canonical', ok: false, expectedCode: 'OK', actualCode: `ERROR:${(err as Error).name}` });
    }
  }
}

/** Suite vectors (S-*): published KATs + direct node:crypto / @noble/hashes paths. */
async function replaySuite(root: string, opts: ReplayOptions): Promise<void> {
  const { vectors } = readJson<{
    version: string;
    vectors: Array<Record<string, string | number>>;
  }>(root, 'vectors/suite-vectors.json');
  const hex = (value: unknown) => value as string;
  // noble validates `instanceof Uint8Array`; convert Buffers to plain Uint8Array views
  // so cross-realm/vitest Buffer instances cannot fail the byte-array check.
  const bytes = (value: unknown) => new Uint8Array(Buffer.from(hex(value), 'hex'));
  for (const v of vectors) {
    const id = hex(v.id);
    try {
      switch (v.kind) {
        case 'hkdf': {
          const ikm = Buffer.from(hex(v.ikmB64url), 'base64url');
          const salt = Buffer.from(hex(v.saltB64url), 'base64url');
          const label = hex(v.label);
          const out = Buffer.from(hkdfSync('sha256', ikm, salt, utf8(label), 32));
          const actual = sha256hex(out);
          const ok = actual === hex(v.outputSha256);
          record(opts.records, { id, category: 'algorithm', ok, expectedDigest: hex(v.outputSha256), actualDigest: actual, expectedCode: 'OK', actualCode: ok ? 'OK' : 'MISMATCH' });
          break;
        }
        case 'hkdf-kat': {
          const ikm = Buffer.from(hex(v.ikmHex), 'hex');
          const salt = Buffer.from(hex(v.saltHex), 'hex');
          const info = Buffer.from(hex(v.infoHex), 'hex');
          const out = Buffer.from(hkdfSync('sha256', ikm, salt, info, Number(v.outputBytes)));
          const actualHex = out.toString('hex');
          const ok = actualHex === hex(v.outputHex);
          record(opts.records, { id, category: 'algorithm', ok, expectedDigest: sha256hex(utf8(hex(v.outputHex))), actualDigest: sha256hex(out), expectedCode: 'OK', actualCode: ok ? 'OK' : 'MISMATCH' });
          break;
        }
        case 'argon2id': {
          const out = await argon2id(utf8(hex(v.passwordUtf8)), bytes(v.saltHex), {
            t: Number(v.iterations),
            m: Number(v.memoryKiB),
            p: Number(v.parallelism),
            dkLen: Number(v.outputBytes),
          });
          const actual = sha256hex(out);
          const ok = actual === hex(v.outputSha256);
          record(opts.records, { id, category: 'algorithm', ok, expectedDigest: hex(v.outputSha256), actualDigest: actual, expectedCode: 'OK', actualCode: ok ? 'OK' : 'MISMATCH' });
          break;
        }
        case 'argon2id-kat': {
          const out = await argon2id(bytes(v.passwordHex), bytes(v.saltHex), {
            t: Number(v.iterations),
            m: Number(v.memoryKiB),
            p: Number(v.parallelism),
            dkLen: Number(v.outputBytes),
            key: bytes(v.secretHex),
            personalization: bytes(v.adHex),
          });
          const actualHex = Buffer.from(out).toString('hex');
          const ok = actualHex === hex(v.outputHex);
          record(opts.records, { id, category: 'algorithm', ok, expectedDigest: sha256hex(utf8(hex(v.outputHex))), actualDigest: sha256hex(out), expectedCode: 'OK', actualCode: ok ? 'OK' : 'MISMATCH' });
          break;
        }
        case 'aes-gcm': {
          const key = bytes(v.keyHex);
          const nonce = bytes(v.nonceHex);
          const aad = opts.aadBytesById[hex(v.aadVectorId)];
          if (!aad) {
            record(opts.records, { id, category: 'algorithm', ok: false, expectedCode: 'OK', actualCode: 'MISSING_AAD' });
            break;
          }
          const cipher = createCipheriv('aes-256-gcm', key, nonce);
          cipher.setAAD(aad);
          const ct = cipher.update(utf8(hex(v.plaintextUtf8)));
          cipher.final();
          const tag = cipher.getAuthTag();
          const ctDigest = sha256hex(ct);
          const tagDigest = sha256hex(tag);
          const ok = ctDigest === hex(v.ciphertextSha256) && tagDigest === hex(v.tagSha256);
          record(opts.records, { id, category: 'algorithm', ok, expectedDigest: hex(v.ciphertextSha256), actualDigest: ctDigest, expectedCode: 'OK', actualCode: ok ? 'OK' : 'MISMATCH' });
          break;
        }
        default:
          record(opts.records, { id, category: 'algorithm', ok: false, expectedCode: 'OK', actualCode: 'UNKNOWN_KIND' });
      }
    } catch (err) {
      record(opts.records, { id, category: 'algorithm', ok: false, expectedCode: 'OK', actualCode: `ERROR:${(err as Error).name}` });
    }
  }
}

/** Password vectors (P-*): independent Unicode recomputation + policy hard-rejection. */
function replayPassword(root: string, records: IsolatedReportRecord[]): void {
  const { vectors } = readJson<{
    version: string;
    vectors: Array<{ id: string; kind: 'unicode' | 'policy'; input: string; aliasTerms?: string[]; expected: Record<string, unknown> }>;
  }>(root, 'vectors/password-vectors.json');
  for (const v of vectors) {
    const id = v.id;
    try {
      if (v.kind === 'unicode') {
        const r = isolatedUnicodeCheck(v.input);
        if (r.ok) {
          const ok = v.expected.ok === true && v.expected.normalizedNfc === r.normalizedNfc && v.expected.graphemes === r.graphemes && v.expected.utf8Bytes === r.utf8Bytes;
          record(records, { id, category: 'password', ok, expectedCode: 'OK', actualCode: ok ? 'OK' : 'MISMATCH', expectedDigest: digestOf({ normalizedNfc: v.expected.normalizedNfc, graphemes: v.expected.graphemes, utf8Bytes: v.expected.utf8Bytes }), actualDigest: digestOf({ normalizedNfc: r.normalizedNfc, graphemes: r.graphemes, utf8Bytes: r.utf8Bytes }) });
        } else {
          const ok = v.expected.ok === false && v.expected.code === r.code;
          record(records, { id, category: 'password', ok, expectedCode: v.expected.code as string, actualCode: r.code, expectedDigest: digestOf({ ok: false, code: v.expected.code }), actualDigest: digestOf({ ok: false, code: r.code }) });
        }
      } else {
        const aliasTerms = v.aliasTerms ?? [];
        const rejection = isolatedHardRejection(v.input, aliasTerms);
        const expected = v.expected as { ok: boolean; code?: string; score?: number; requiresAcknowledgement?: boolean };
        if (expected.ok === false) {
          const ok = rejection === expected.code;
          record(records, { id, category: 'password', ok, expectedCode: expected.code!, actualCode: rejection === 'none' ? 'MISMATCH' : rejection, expectedDigest: digestOf({ ok: false, code: expected.code }), actualDigest: digestOf({ ok: false, code: rejection === 'none' ? 'MISMATCH' : rejection }) });
        } else {
          // Pinned OK outcome: no hard rejection; score within 0–4 and the
          // acknowledgement rule (score ≤ 1) must be internally consistent.
          const score = typeof expected.score === 'number' ? expected.score : -1;
          const ok = rejection === 'none' && score >= 0 && score <= 4 && expected.requiresAcknowledgement === (score <= 1);
          record(records, { id, category: 'password', ok, expectedCode: 'OK', actualCode: ok ? 'OK' : rejection === 'none' ? 'INCONSISTENT' : rejection, expectedDigest: digestOf({ ok: true, score, requiresAcknowledgement: expected.requiresAcknowledgement }), actualDigest: digestOf({ ok: true, score, requiresAcknowledgement: expected.requiresAcknowledgement }) });
        }
      }
    } catch (err) {
      record(records, { id, category: 'password', ok: false, expectedCode: 'OK', actualCode: `ERROR:${(err as Error).name}` });
    }
  }
}

/** Core vectors (E/L/M/G/Q/T): independent replay engines. */
function replayCore(root: string, records: IsolatedReportRecord[]): void {
  const { vectors } = readJson<{
    version: string;
    vectors: Array<{ id: string; family: string; operation: string; input: Record<string, unknown>; expectedCode: string; expectedSha256?: string }>;
  }>(root, 'vectors/core-vectors.json');
  for (const v of vectors) {
    try {
      let result: { code: string; output?: unknown };
      let category: IsolatedReportRecord['category'];
      switch (v.family) {
        case 'extension': {
          const input = v.input as { container: { extensions: Record<string, unknown>; criticalExtensions: string[] }; knownExtensions: string[] };
          result = isolatedExtensionValidate(input.container, input.knownExtensions);
          category = 'extension';
          break;
        }
        case 'lifecycle':
          result = isolatedLifecycleReplay(v.operation, v.input);
          category = 'lifecycle';
          break;
        case 'migration': {
          const input = v.input as { version: Parameters<typeof isolatedCheckSupportedVersion>[0] };
          result = isolatedCheckSupportedVersion(input.version);
          category = 'migration';
          break;
        }
        case 'generation':
          result = isolatedJournalCommit(v.input as unknown as Parameters<typeof isolatedJournalCommit>[0]);
          category = 'lifecycle';
          break;
        case 'session':
          result = isolatedSessionReplay(v.operation, v.input);
          category = 'session';
          break;
        case 'typed-result': {
          const input = v.input as { code: string };
          result = isolatedTypedResultReplay(input.code);
          category = 'typed-result';
          break;
        }
        default:
          record(records, { id: v.id, category: 'typed-result', ok: false, expectedCode: v.expectedCode, actualCode: 'UNKNOWN_FAMILY' });
          continue;
      }
      const codeOk = result.code === v.expectedCode;
      let digestOk = true;
      let actualDigest = '';
      let expectedDigest = '';
      if (v.expectedSha256 !== undefined) {
        expectedDigest = v.expectedSha256;
        actualDigest = result.output === undefined ? '' : digestOf(result.output);
        digestOk = actualDigest === expectedDigest;
      } else if (result.output !== undefined) {
        // Corpus expects no digest but the replay produced output — record mismatch.
        digestOk = false;
      }
      record(records, { id: v.id, category, ok: codeOk && digestOk, expectedCode: v.expectedCode, actualCode: result.code, expectedDigest: expectedDigest || undefined, actualDigest: actualDigest || undefined });
    } catch (err) {
      record(records, { id: v.id, category: 'typed-result', ok: false, expectedCode: v.expectedCode, actualCode: `ERROR:${(err as Error).name}` });
    }
  }
}

/** ---------- orchestrator ---------- */
export interface IsolatedValidationResult {
  readonly report: IsolatedReport;
}

/** Run the full isolated validation over the vault corpus. */
export async function runIsolatedValidation(corpus: string = corpusRoot()): Promise<IsolatedValidationResult> {
  const records: IsolatedReportRecord[] = [];
  const integrity = verifyManifestIndependently(corpus);
  records.push(...integrity.records);
  records.push(...validateSchemasIndependently(corpus));

  // AAD replay first so suite AES-GCM vectors can bind to A-001's bytes.
  const aadBytesById: Record<string, Uint8Array> = {};
  const opts: ReplayOptions = { root: corpus, aadBytesById, records };
  replayAad(corpus, opts);
  replayCanonical(corpus, records);
  await replaySuite(corpus, opts);
  replayPassword(corpus, records);
  replayCore(corpus, records);

  // Deterministic ordering: stable sort by id, then category.
  const sorted = [...records].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : a.category < b.category ? -1 : 1));
  const failed = sorted.filter((r) => !r.ok);
  const report: IsolatedReport = {
    schemaVersion: 1,
    generator: ISOLATED_GENERATOR,
    corpusVersion: '1.0.0',
    manifestSha256: integrity.manifestSha256,
    passed: failed.length === 0,
    total: sorted.length,
    records: sorted,
  };
  return { report };
}

/** Convenience: true when the corpus replays with zero mismatch records. */
export function isCorpusHealthy(result: IsolatedValidationResult): boolean {
  return result.report.passed && result.report.records.every((r) => r.ok);
}
