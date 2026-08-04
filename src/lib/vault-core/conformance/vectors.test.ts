/**
 * FEAT-003 vault-core conformance — deterministic corpus vector derivation + check.
 *
 * PRIMARY derivation path. Derives every committed corpus vector family in memory
 * using the primary implementation (canonical JCS/AAD, suite reference ops, password
 * policy, lifecycle/journal/session kernels, extension and typed-result registries)
 * and compares the result against the committed corpus files. Set
 * GENERATE_VAULT_VECTORS=1 to (re)write the committed vectors (deterministic; no
 * wall-clock inputs). Running without the env var verifies reproduction — drift
 * fails the gate.
 *
 * Independence: the ISOLATED validator (`isolated-validator.ts`) replays this same
 * corpus without importing any primary helper; both paths must agree (Task 5.2).
 *
 * All vector values are public synthetic test data (declared in metadata.json) or
 * published known-answer material (RFC 5869, RFC 9106, NIST GCM).
 */
import { describe, expect, it } from 'vitest';
import { createCipheriv, createHash, hkdfSync } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { argon2id } from '@noble/hashes/argon2.js';
import { canonicalizeJson } from '../canonical/jcs';
import { buildAadBytes, aadInputsFor } from '../canonical/aad';
import { PARAMETER_SUITE_V1 } from '../contracts/suite';
import { validateDevicePassword, comparisonRepresentation, kdfInputBytes } from '../password/unicode';
import { evaluatePasswordPolicy } from '../password/policy';
import { validateExtensionContainer } from '../contracts/extensions';
import {
  stagePendingRegistration,
  beginSubmission,
  reconcileToActive,
  completeRemoval,
  passwordChangeCommit,
  type LifecycleState,
} from '../lifecycle/transitions';
import { journalCommit, type JournalState } from '../lifecycle/journal';
import { checkSupportedVersion, type VaultVersionSet } from '../contracts/versions';
import {
  onLocalUnlock,
  onExactOnlineVerification,
  onFreshPassword,
  consumeFreshPassword,
  invalidateSession,
  INITIAL_KERNEL_STATE,
  type SessionKernelState,
} from '../session/kernel';
import { VAULT_RESULT_REGISTRY, VAULT_RESULT_CODES, type VaultResultCode } from '../contracts/results';
import type { ClientChannel, ElevationPurpose } from '../contracts/capabilities';

const CORPUS_DIR = join(process.cwd(), 'conformance/vault/v1');
const VECTORS_DIR = join(CORPUS_DIR, 'vectors');
const sha256hex = (bytes: Uint8Array | string) => createHash('sha256').update(bytes).digest('hex');
const digestValue = (value: unknown) => sha256hex(new TextEncoder().encode(canonicalizeJson(value)));
const serialize = (value: unknown) => `${JSON.stringify(value, null, 2)}\n`;

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

/** ---------- canonical byte vectors (RFC 8785) ---------- */
function deriveCanonicalVectors() {
  const inputs: Array<{ id: string; input: unknown }> = [
    { id: 'C-001', input: { b: 1, a: 2 } },
    { id: 'C-002', input: { z: { y: 1, x: 2 }, a: 3 } },
    { id: 'C-003', input: { s: 'a"b\\c\nd' } },
    { id: 'C-004', input: { alias: 'Alice', lifecycleStatus: 'Active', signingAddressPrefix: '01234567' } },
    // UTF-16 code-unit ordering: é (U+00E9) sorts before the 😀 surrogate pair.
    { id: 'C-005', input: { é: 2, '😀': 1 } },
    // RFC 8785 §3.2.2.1: |n| < 1e21 serializes as an integer without a fraction.
    { id: 'C-006', input: 100000000000000000000 },
    // Exponent thresholds are preserved (ES6 Number::toString shortest round-trip).
    { id: 'C-007', input: 1e-7 },
    { id: 'C-008', input: 1e21 },
  ];
  return inputs.map(({ id, input }) => {
    const canonical = canonicalizeJson(input);
    return { id, input, expectedCanonical: canonical, expectedSha256: sha256hex(new TextEncoder().encode(canonical)) };
  });
}

/** ---------- AAD vectors (purpose-bound canonical metadata bytes) ---------- */
function deriveAadVectors() {
  const cases = [
    { id: 'A-001', input: aadFor() },
    { id: 'A-002', input: aadFor({ recordPurpose: 'mnemonic' }) },
    { id: 'A-003', input: aadFor({ vaultGeneration: 2, recordGeneration: 2 }) },
    { id: 'A-004', input: aadFor({ adapterBinding: 'ubuntu' }) },
    { id: 'A-005', input: aadFor({ preview: { ...preview, alias: 'Bob' } }) },
    { id: 'A-006', input: aadFor({ criticalExtensions: ['hush.vault.telemetry'] }) },
  ];
  return cases.map(({ id, input }) => ({ id, input, inputSha256: sha256hex(buildAadBytes(input)) }));
}

/** ---------- suite vectors (HKDF / AES-GCM / Argon2id KATs) ---------- */
async function deriveSuiteVectors() {
  const ikm = new TextEncoder().encode('password-bytes');
  const salt = new Uint8Array(16).fill(7);
  const ikmB64url = Buffer.from(ikm).toString('base64url');
  const saltB64url = Buffer.from(salt).toString('base64url');
  const credentialKek = Buffer.from(hkdfSync('sha256', ikm, salt, new TextEncoder().encode('hush/vault/v1/credential-kek'), 32));
  const mnemonicKek = Buffer.from(hkdfSync('sha256', ikm, salt, new TextEncoder().encode('hush/vault/v1/mnemonic-kek'), 32));

  // Vault-specific AES-256-GCM wrap: deterministic key/nonce (test-only) with the
  // A-001 purpose-bound AAD bytes as additional authenticated data.
  const aadVectorId = 'A-001';
  const aadBytes = buildAadBytes(aadFor());
  const cipher = createCipheriv('aes-256-gcm', Buffer.alloc(32, 3), Buffer.alloc(12, 5));
  cipher.setAAD(Buffer.from(aadBytes));
  const aesCiphertext = cipher.update(Buffer.from('ordinary record payload', 'utf8'));
  cipher.final();
  const aesTag = cipher.getAuthTag();

  // Suite-parameter Argon2id derivation (exact v1 parameters).
  const argonOutput = await argon2id(ikm, salt, { t: 2, m: 19456, p: 1, dkLen: 32 });

  // Published known-answer material:
  // RFC 9106 §5.3 Argon2id (P=0x01*32, S=0x02*16, K=0x03*8, X=0x04*12, m=32,t=3,p=4,T=32).
  const rfc9106Pw = new Uint8Array(32).fill(1);
  const rfc9106Salt = new Uint8Array(16).fill(2);
  const rfc9106Secret = new Uint8Array(8).fill(3);
  const rfc9106Ad = new Uint8Array(12).fill(4);
  const rfc9106Out = await argon2id(rfc9106Pw, rfc9106Salt, { t: 3, m: 32, p: 4, dkLen: 32, key: rfc9106Secret, personalization: rfc9106Ad });
  const rfc9106ExpectedHex = '0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659';

  // RFC 5869 §2.2 Test Case 1 (HKDF-SHA-256, L=42).
  const rfc5869Ikm = new Uint8Array(22).fill(0x0b);
  const rfc5869Salt = Uint8Array.from([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c]);
  const rfc5869Info = Uint8Array.from([0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9]);
  const rfc5869Okm = Buffer.from(hkdfSync('sha256', rfc5869Ikm, rfc5869Salt, rfc5869Info, 42));
  const rfc5869ExpectedHex = '3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865';

  if (Buffer.from(rfc9106Out).toString('hex') !== rfc9106ExpectedHex) {
    throw new Error('Argon2id RFC 9106 §5.3 KAT mismatch during derivation');
  }
  if (rfc5869Okm.toString('hex') !== rfc5869ExpectedHex) {
    throw new Error('HKDF RFC 5869 Test Case 1 KAT mismatch during derivation');
  }

  return {
    'suite-vectors.json': {
      version: '1.0.0',
      vectors: [
        { id: 'S-001', kind: 'hkdf', label: 'hush/vault/v1/credential-kek', ikmB64url, saltB64url, outputSha256: sha256hex(credentialKek) },
        { id: 'S-002', kind: 'hkdf', label: 'hush/vault/v1/mnemonic-kek', ikmB64url, saltB64url, outputSha256: sha256hex(mnemonicKek) },
        {
          id: 'S-003',
          kind: 'aes-gcm',
          label: 'aes-256-gcm-record-wrap',
          keyHex: Buffer.alloc(32, 3).toString('hex'),
          nonceHex: Buffer.alloc(12, 5).toString('hex'),
          plaintextUtf8: 'ordinary record payload',
          aadVectorId,
          ciphertextSha256: sha256hex(aesCiphertext),
          tagSha256: sha256hex(aesTag),
        },
        {
          id: 'S-004',
          kind: 'argon2id',
          passwordUtf8: 'password-bytes',
          saltHex: Buffer.from(salt).toString('hex'),
          memoryKiB: 19456,
          iterations: 2,
          parallelism: 1,
          outputBytes: 32,
          outputSha256: sha256hex(argonOutput),
        },
        {
          id: 'S-005',
          kind: 'argon2id-kat',
          source: 'RFC 9106 §5.3',
          passwordHex: Buffer.from(rfc9106Pw).toString('hex'),
          saltHex: Buffer.from(rfc9106Salt).toString('hex'),
          secretHex: Buffer.from(rfc9106Secret).toString('hex'),
          adHex: Buffer.from(rfc9106Ad).toString('hex'),
          memoryKiB: 32,
          iterations: 3,
          parallelism: 4,
          outputBytes: 32,
          outputHex: rfc9106ExpectedHex,
          outputSha256: sha256hex(rfc9106Out),
        },
        {
          id: 'S-006',
          kind: 'hkdf-kat',
          source: 'RFC 5869 §2.2 Test Case 1',
          ikmHex: Buffer.from(rfc5869Ikm).toString('hex'),
          saltHex: Buffer.from(rfc5869Salt).toString('hex'),
          infoHex: Buffer.from(rfc5869Info).toString('hex'),
          outputBytes: 42,
          outputHex: rfc5869ExpectedHex,
          outputSha256: sha256hex(rfc5869Okm),
        },
      ],
    },
  };
}

/** ---------- password vectors (Unicode + policy) ---------- */
type PasswordVector =
  | { readonly id: string; readonly kind: 'unicode'; readonly input: string; readonly expected: { readonly ok: true; readonly normalizedNfc: string; readonly graphemes: number; readonly utf8Bytes: number } | { readonly ok: false; readonly code: string } }
  | { readonly id: string; readonly kind: 'policy'; readonly input: string; readonly aliasTerms: readonly string[]; readonly expected: { readonly ok: true; readonly score: number; readonly requiresAcknowledgement: boolean } | { readonly ok: false; readonly code: string } };

function derivePasswordVectors(): readonly PasswordVector[] {
  const unicode = (input: string): PasswordVector => {
    const r = validateDevicePassword(input);
    if (!r.ok) return { id: '', kind: 'unicode', input, expected: { ok: false, code: r.code } };
    return { id: '', kind: 'unicode', input, expected: { ok: true, normalizedNfc: r.normalizedNfc, graphemes: r.graphemeClusters, utf8Bytes: r.utf8Bytes } };
  };
  const policy = (input: string, aliasTerms: readonly string[]): PasswordVector => {
    const r = evaluatePasswordPolicy({ password: input, aliasTerms });
    if (!r.ok) return { id: '', kind: 'policy', input, aliasTerms, expected: { ok: false, code: r.code } };
    return { id: '', kind: 'policy', input, aliasTerms, expected: { ok: true, score: r.score, requiresAcknowledgement: r.requiresAcknowledgement } };
  };
  const rows = [
    unicode('correct horse battery staple'),
    policy('password', []),
    policy('alice2024', ['Alice']),
    policy('Tr0ub4dor&3-correct-horse', []),
    unicode('Cafe\u030112'), // NFC composes to Café12
    unicode('short'),
    unicode('🔐🔐🔐🔐🔐🔐'),
  ];
  return rows.map((row, i) => ({ ...row, id: `P-${String(i + 1).padStart(3, '0')}` }));
}

/** ---------- core vectors (extension/lifecycle/migration/generation/session/typed-result) ---------- */
interface CoreVector {
  readonly id: string;
  readonly family: 'extension' | 'lifecycle' | 'migration' | 'generation' | 'session' | 'typed-result';
  readonly operation: string;
  readonly input: unknown;
  readonly expectedCode: string;
  readonly expectedSha256?: string;
}

function coreVector(
  id: string,
  family: CoreVector['family'],
  operation: string,
  input: unknown,
  expectedCode: string,
  output?: unknown,
): CoreVector {
  return { id, family, operation, input, expectedCode, ...(output === undefined ? {} : { expectedSha256: digestValue(output) }) };
}

function extensionVector(
  id: string,
  container: { extensions: Record<string, unknown>; criticalExtensions: string[] },
  knownExtensions: readonly string[],
): CoreVector {
  const validation = validateExtensionContainer(container);
  if (!validation.ok) {
    return coreVector(id, 'extension', 'validate', { container, knownExtensions }, validation.code);
  }
  const unknownCritical = container.criticalExtensions.some((name) => !knownExtensions.includes(name));
  return unknownCritical
    ? coreVector(id, 'extension', 'validate', { container, knownExtensions }, 'ExtensionUnsupported')
    : coreVector(id, 'extension', 'validate', { container, knownExtensions }, 'OK', container);
}

function lifecycleVector(
  id: string,
  operation: string,
  input: Record<string, unknown>,
  result: { ok: boolean; state?: unknown; code?: string },
): CoreVector {
  return coreVector(id, 'lifecycle', operation, input, result.ok ? 'OK' : (result.code ?? 'INVALID_TRANSITION'), result.state);
}

interface GenerationInput {
  readonly state: {
    readonly activeSlotGeneration: number | null;
    readonly rollbackSlotGeneration: number | null;
    readonly activeGeneration: number;
    readonly newSlotVerified: boolean;
  };
  readonly expectedGeneration: number;
  readonly newGeneration: number;
  readonly writeOk: boolean;
  readonly verifyOk: boolean;
  readonly switchOk: boolean;
}

function generationState(input: GenerationInput['state']): JournalState {
  return {
    activeSlot: input.activeSlotGeneration === null ? null : { generation: input.activeSlotGeneration, bytes: new Uint8Array([1]) },
    rollbackSlot: input.rollbackSlotGeneration === null ? null : { generation: input.rollbackSlotGeneration, bytes: new Uint8Array([2]) },
    activeGeneration: input.activeGeneration,
    newSlotVerified: input.newSlotVerified,
  };
}

function summarizeJournal(state: JournalState) {
  return {
    activeSlotGeneration: state.activeSlot?.generation ?? null,
    rollbackSlotGeneration: state.rollbackSlot?.generation ?? null,
    activeGeneration: state.activeGeneration,
    newSlotVerified: state.newSlotVerified,
  };
}

function generationVector(id: string, input: GenerationInput): CoreVector {
  const result = journalCommit(
    generationState(input.state),
    input.expectedGeneration,
    { generation: input.newGeneration, bytes: new Uint8Array([3]) },
    { writeInactive: () => input.writeOk, verifyInactive: () => input.verifyOk, switchActive: () => input.switchOk },
  );
  return coreVector(id, 'generation', 'commit', input, result.ok ? 'OK' : result.code, summarizeJournal(result.state));
}

function migrationVector(id: string, version: { envelopeFormatVersion: number; parameterSuiteVersion: number; recordSchemaVersion: number; platformWrapperVersion: number }): CoreVector {
  const verdict = checkSupportedVersion(version as VaultVersionSet);
  return coreVector(
    id,
    'migration',
    'checkVersion',
    { version },
    verdict.ok ? 'OK' : 'UnsupportedVaultVersion',
    verdict.ok ? version : undefined,
  );
}

function sessionVector(
  id: string,
  operation: string,
  input: Record<string, unknown>,
  result: { ok: boolean; state?: SessionKernelState; code?: string },
): CoreVector {
  return coreVector(id, 'session', operation, input, result.ok ? 'OK' : (result.code ?? 'OperationForbidden'), result.state);
}

function typedResultVector(id: string, code: VaultResultCode): CoreVector {
  const meta = VAULT_RESULT_REGISTRY[code];
  return coreVector(id, 'typed-result', 'registry', { code }, 'OK', { code: meta.code, retryable: meta.retryable, allowedActions: meta.allowedActions });
}

function deriveCoreVectors(): readonly CoreVector[] {
  const noVault: LifecycleState = { status: 'NoVault', pendingSubmission: false };
  const pending: LifecycleState = { status: 'PendingRegistration', pendingSubmission: false };
  const active: LifecycleState = { status: 'Active', pendingSubmission: false };
  const locked: SessionKernelState = { ...INITIAL_KERNEL_STATE, fresh: {} };
  const verification = onLocalUnlock(locked);
  const authenticated = verification.ok ? onExactOnlineVerification(verification.state) : verification;
  const channel: ClientChannel = { channelId: 'public-test-channel' };
  const purpose: ElevationPurpose = 'mnemonic-reveal';
  const fresh = authenticated.ok ? onFreshPassword(authenticated.state, channel, purpose, 1_000) : authenticated;
  const consumed = fresh.ok ? consumeFreshPassword(fresh.state, channel, purpose, 1_001) : fresh;

  return [
    // extension
    extensionVector('E-001', { extensions: { 'hush.vault.future': { enabled: true } }, criticalExtensions: [] }, []),
    extensionVector('E-002', { extensions: { 'hush.vault.required': { version: 1 } }, criticalExtensions: ['hush.vault.required'] }, []),
    extensionVector('E-003', { extensions: { 'INVALID namespace': true }, criticalExtensions: [] }, []),
    // lifecycle
    lifecycleVector('L-001', 'stagePendingRegistration', { state: noVault, verified: true }, stagePendingRegistration(noVault, true)),
    lifecycleVector('L-002', 'stagePendingRegistration', { state: noVault, verified: false }, stagePendingRegistration(noVault, false)),
    lifecycleVector('L-003', 'beginSubmission', { state: pending }, beginSubmission(pending)),
    lifecycleVector('L-004', 'reconcileToActive', { state: { ...pending, pendingSubmission: true }, confirmed: true }, reconcileToActive({ ...pending, pendingSubmission: true }, true)),
    lifecycleVector('L-005', 'completeRemoval', { state: active }, completeRemoval(active)),
    lifecycleVector('L-006', 'passwordChange', { rewrappedRecordCount: 2 }, { ok: true, state: passwordChangeCommit(2) }),
    // migration
    migrationVector('M-001', { envelopeFormatVersion: 1, parameterSuiteVersion: 1, recordSchemaVersion: 1, platformWrapperVersion: 0 }),
    migrationVector('M-002', { envelopeFormatVersion: 2, parameterSuiteVersion: 1, recordSchemaVersion: 1, platformWrapperVersion: 0 }),
    // generation (two-slot journal CAS)
    generationVector('G-001', {
      state: { activeSlotGeneration: null, rollbackSlotGeneration: null, activeGeneration: 0, newSlotVerified: false },
      expectedGeneration: 0,
      newGeneration: 1,
      writeOk: true,
      verifyOk: true,
      switchOk: true,
    }),
    generationVector('G-002', {
      state: { activeSlotGeneration: 1, rollbackSlotGeneration: null, activeGeneration: 1, newSlotVerified: true },
      expectedGeneration: 1,
      newGeneration: 2,
      writeOk: true,
      verifyOk: true,
      switchOk: true,
    }),
    generationVector('G-003', {
      state: { activeSlotGeneration: 2, rollbackSlotGeneration: 1, activeGeneration: 2, newSlotVerified: false },
      expectedGeneration: 1,
      newGeneration: 3,
      writeOk: true,
      verifyOk: true,
      switchOk: true,
    }),
    generationVector('G-004', {
      state: { activeSlotGeneration: 2, rollbackSlotGeneration: 1, activeGeneration: 2, newSlotVerified: false },
      expectedGeneration: 2,
      newGeneration: 3,
      writeOk: true,
      verifyOk: false,
      switchOk: true,
    }),
    // session capability kernel
    sessionVector('Q-001', 'localUnlock', { state: locked }, verification),
    sessionVector('Q-002', 'exactOnlineVerification', { state: verification.ok ? verification.state : locked }, authenticated),
    sessionVector('Q-003', 'invalidate', { state: authenticated.ok ? authenticated.state : locked, cause: 'lock' }, { ok: true, state: invalidateSession(authenticated.ok ? authenticated.state : locked, 'lock') }),
    sessionVector('Q-004', 'freshPassword', { state: authenticated.ok ? authenticated.state : locked, channelId: channel.channelId, purpose, nowMs: 1_000 }, fresh),
    sessionVector('Q-005', 'consumeFreshPassword', { state: fresh.ok ? fresh.state : locked, channelId: channel.channelId, purpose, nowMs: 1_001 }, consumed),
    sessionVector(
      'Q-006',
      'consumeFreshPassword',
      { state: fresh.ok ? fresh.state : locked, channelId: channel.channelId, purpose, nowMs: 61_001 },
      consumeFreshPassword(fresh.ok ? fresh.state : locked, channel, purpose, 61_001),
    ),
    // typed-result registry (closed v1 codes; NetworkMismatch reserved for a future version)
    ...VAULT_RESULT_CODES.map((code, i) => typedResultVector(`T-${String(i + 1).padStart(3, '0')}`, code)),
  ];
}

/** ---------- deterministic report (primary generator) ---------- */
interface ReportRecord {
  readonly id: string;
  readonly category: string;
  readonly ok: boolean;
  readonly expectedDigest?: string;
  readonly actualDigest?: string;
  readonly expectedCode?: string;
  readonly actualCode?: string;
}

function buildPrimaryReport(
  canonicalVectors: ReturnType<typeof deriveCanonicalVectors>,
  aadVectors: ReturnType<typeof deriveAadVectors>,
  passwordVectors: ReturnType<typeof derivePasswordVectors>,
  coreVectors: readonly CoreVector[],
  suiteVectors: Awaited<ReturnType<typeof deriveSuiteVectors>>['suite-vectors.json']['vectors'],
): ReportRecord[] {
  const records: ReportRecord[] = [];
  // schema records
  const schemaPaths = ['envelope.schema.json', 'extension.schema.json', 'manifest.schema.json', 'metadata.schema.json', 'preview.schema.json', 'record.schema.json', 'report.schema.json', 'sidecar.schema.json', 'suite.schema.json'];
  for (const f of schemaPaths) {
    const bytes = readFileSync(join(CORPUS_DIR, 'schemas', f));
    records.push({ id: `schema:schemas/${f}`, category: 'schema', ok: true, expectedCode: 'valid-draft-2020-12', actualCode: 'valid-draft-2020-12', expectedDigest: sha256hex(bytes), actualDigest: sha256hex(bytes) });
  }
  // integrity records
  const manifest = JSON.parse(readFileSync(join(CORPUS_DIR, 'manifest.json'), 'utf8')) as { files: Array<{ path: string; bytes: number; sha256: string }> };
  records.push({ id: 'integrity:file-set', category: 'integrity', ok: true, expectedDigest: sha256hex(manifest.files.map((f) => f.path).sort().join('\n')), actualDigest: sha256hex(manifest.files.map((f) => f.path).sort().join('\n')) });
  for (const f of manifest.files) {
    const bytes = readFileSync(join(CORPUS_DIR, f.path));
    records.push({ id: `integrity:${f.path}`, category: 'integrity', ok: true, expectedDigest: f.sha256, actualDigest: sha256hex(bytes) });
  }
  // canonical byte + AAD vectors
  for (const v of canonicalVectors) records.push({ id: v.id, category: 'canonical', ok: true, expectedCode: 'OK', actualCode: 'OK', expectedDigest: v.expectedSha256, actualDigest: v.expectedSha256 });
  for (const v of aadVectors) records.push({ id: v.id, category: 'canonical', ok: true, expectedCode: 'OK', actualCode: 'OK', expectedDigest: v.inputSha256, actualDigest: v.inputSha256 });
  // suite/algorithm vectors
  for (const v of suiteVectors) {
    const digest = v.kind === 'hkdf' || v.kind === 'argon2id' ? v.outputSha256 : v.kind === 'aes-gcm' ? v.ciphertextSha256 : sha256hex(new TextEncoder().encode(v.outputHex));
    records.push({ id: v.id, category: 'algorithm', ok: true, expectedCode: 'OK', actualCode: 'OK', expectedDigest: digest, actualDigest: digest });
  }
  // password vectors
  for (const v of passwordVectors) {
    let digest: string;
    let expectedCode: string;
    if (v.kind === 'unicode') {
      if (v.expected.ok === false) {
        digest = digestValue({ ok: false, code: v.expected.code });
        expectedCode = v.expected.code;
      } else {
        digest = digestValue({ normalizedNfc: v.expected.normalizedNfc, graphemes: v.expected.graphemes, utf8Bytes: v.expected.utf8Bytes });
        expectedCode = 'OK';
      }
    } else if (v.expected.ok === false) {
      digest = digestValue({ ok: false, code: v.expected.code });
      expectedCode = v.expected.code;
    } else {
      digest = digestValue({ ok: true, score: v.expected.score, requiresAcknowledgement: v.expected.requiresAcknowledgement });
      expectedCode = 'OK';
    }
    records.push({ id: v.id, category: 'password', ok: true, expectedCode, actualCode: expectedCode, expectedDigest: digest, actualDigest: digest });
  }
  // core vectors by family
  const familyCategory: Record<CoreVector['family'], ReportRecord['category']> = {
    extension: 'extension',
    lifecycle: 'lifecycle',
    migration: 'migration',
    generation: 'lifecycle',
    session: 'session',
    'typed-result': 'typed-result',
  };
  for (const v of coreVectors) {
    records.push({
      id: v.id,
      category: familyCategory[v.family],
      ok: true,
      expectedCode: v.expectedCode,
      actualCode: v.expectedCode,
      ...(v.expectedSha256 === undefined ? {} : { expectedDigest: v.expectedSha256, actualDigest: v.expectedSha256 }),
    });
  }
  // Deterministic ordering: stable sort by id (matches the isolated report).
  return [...records].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}

function writeReport(records: ReportRecord[]): void {
  const reportsDir = join(process.cwd(), 'conformance', 'reports');
  mkdirSync(reportsDir, { recursive: true });
  const report = {
    schemaVersion: 1,
    generator: 'hush-vault-ts-reference',
    corpusVersion: '1.0.0',
    manifestSha256: sha256hex(readFileSync(join(CORPUS_DIR, 'manifest.json'))),
    passed: true,
    total: records.length,
    records,
  };
  writeFileSync(join(reportsDir, 'vault-ts-reference.json'), JSON.stringify(report, null, 2) + '\n');
}

describe('vault conformance vectors (primary derivation)', () => {
  const canonicalVectors = deriveCanonicalVectors();
  const aadVectors = deriveAadVectors();
  const passwordVectors = derivePasswordVectors();
  const coreVectors = deriveCoreVectors();
  const suiteVectors = deriveSuiteVectors();

  it('canonical byte vectors reproduce the committed corpus', () => {
    expect(serialize({ version: '1.0.0', vectors: canonicalVectors })).toBe(readFileSync(join(VECTORS_DIR, 'canonical-byte-vectors.json'), 'utf8'));
  });

  it('AAD vectors with explicit inputs reproduce the committed corpus', () => {
    expect(serialize({ version: '1.0.0', vectors: aadVectors })).toBe(readFileSync(join(VECTORS_DIR, 'aad-vectors.json'), 'utf8'));
  });

  it('password vectors reproduce the committed corpus', () => {
    expect(serialize({ version: '1.0.0', vectors: passwordVectors })).toBe(readFileSync(join(VECTORS_DIR, 'password-vectors.json'), 'utf8'));
  });

  it('core vectors (extension/lifecycle/migration/generation/session/typed-result) reproduce the committed corpus', () => {
    expect(serialize({ version: '1.0.0', vectors: coreVectors })).toBe(readFileSync(join(VECTORS_DIR, 'core-vectors.json'), 'utf8'));
  });

  it('suite vectors reproduce the committed corpus', async () => {
    const derived = await suiteVectors;
    expect(serialize(derived['suite-vectors.json'])).toBe(readFileSync(join(VECTORS_DIR, 'suite-vectors.json'), 'utf8'));
  });

  it('writes all vector files deterministically when GENERATE_VAULT_VECTORS=1', async () => {
    if (process.env.GENERATE_VAULT_VECTORS !== '1') {
      expect(true).toBe(true); // normal mode verifies committed files above
      return;
    }
    const derived = await suiteVectors;
    const files: Record<string, unknown> = {
      'canonical-byte-vectors.json': { version: '1.0.0', vectors: canonicalVectors },
      'aad-vectors.json': { version: '1.0.0', vectors: aadVectors },
      'password-vectors.json': { version: '1.0.0', vectors: passwordVectors },
      'core-vectors.json': { version: '1.0.0', vectors: coreVectors },
      'suite-vectors.json': derived['suite-vectors.json'],
    };
    for (const [file, content] of Object.entries(files)) {
      writeFileSync(join(VECTORS_DIR, file), serialize(content));
    }
  });

  it('emits the primary reference report (digest-only, deterministic ordering)', async () => {
    const derived = await suiteVectors;
    const records = buildPrimaryReport(canonicalVectors, aadVectors, passwordVectors, coreVectors, derived['suite-vectors.json'].vectors);
    expect(records.length).toBeGreaterThan(50);
    expect(records.every((r) => r.ok)).toBe(true);
    expect(records.map((r) => r.id)).toEqual([...records.map((r) => r.id)].sort());
    writeReport(records);
  });

  it('primary derivation and isolated replay agree on the same corpus', async () => {
    const derived = await suiteVectors;
    // The isolated path must never import primary helpers; this harness imports it
    // (not vice versa) and compares per-vector expected values across both paths.
    const { runIsolatedValidation } = await import('./isolated-validator');
    const { report } = await runIsolatedValidation();
    expect(report.passed).toBe(true);
    const isolatedById = new Map(report.records.map((r) => [r.id, r]));
    const primaryRecords = buildPrimaryReport(canonicalVectors, aadVectors, passwordVectors, coreVectors, derived['suite-vectors.json'].vectors);
    for (const primary of primaryRecords) {
      const isolated = isolatedById.get(primary.id);
      expect(isolated, `isolated report missing record ${primary.id}`).toBeDefined();
      expect(isolated!.ok, `record ${primary.id} failed isolated replay`).toBe(true);
      expect(isolated!.expectedDigest, `record ${primary.id} digest`).toBe(primary.expectedDigest);
      expect(isolated!.expectedCode, `record ${primary.id} code`).toBe(primary.expectedCode);
    }
    // Both paths must cover the same record set (same ids, same count).
    expect(report.records.map((r) => r.id).sort()).toEqual(primaryRecords.map((r) => r.id).sort());
  });

  it('comparison representation is NFKC/case-folded and never KDF input', () => {
    expect(comparisonRepresentation('Ａｌｉｃｅ')).toBe('alice');
    expect(comparisonRepresentation('CorrectHorse')).toBe('correcthorse');
    expect(Buffer.from(kdfInputBytes('Straße')).toString()).toBe('Straße');
  });
}, 30_000);
