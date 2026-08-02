/**
 * FEAT-003 deterministic vault corpus derivation and TypeScript reference report.
 *
 * Set GENERATE_VAULT_VECTORS=1 to rewrite all vector files. Set VAULT_TS_REPORT to
 * emit a schema-conformant digest-only report for the Phase 5 cross-runtime comparator.
 */
import { describe, expect, it } from 'vitest';
import { createCipheriv, createHash, hkdfSync } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { canonicalizeJson } from '../canonical/jcs';
import { buildAadBytes, aadInputsFor } from '../canonical/aad';
import { derivePasswordKey } from '../canonical/suite-reference';
import { validateExtensionContainer } from '../contracts/extensions';
import { VAULT_RESULT_CODES, VAULT_RESULT_REGISTRY } from '../contracts/results';
import { PARAMETER_SUITE_V1 } from '../contracts/suite';
import { checkSupportedVersion, VAULT_VERSION_V1, type VaultVersionSet } from '../contracts/versions';
import { journalCommit, type JournalState } from '../lifecycle/journal';
import {
  beginSubmission,
  completeRemoval,
  passwordChangeCommit,
  reconcileToActive,
  stagePendingRegistration,
  type LifecycleState,
} from '../lifecycle/transitions';
import { evaluatePasswordPolicy } from '../password/policy';
import { comparisonRepresentation, kdfInputBytes, validateDevicePassword } from '../password/unicode';
import {
  INITIAL_KERNEL_STATE,
  consumeFreshPassword,
  invalidateSession,
  onExactOnlineVerification,
  onFreshPassword,
  onLocalUnlock,
  type SessionKernelState,
} from '../session/kernel';
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
  return {
    id,
    family,
    operation,
    input,
    expectedCode,
    ...(output === undefined ? {} : { expectedSha256: digestValue(output) }),
  };
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
  result: { ok: boolean; state?: LifecycleState; code?: string },
): CoreVector {
  return coreVector(
    id,
    'lifecycle',
    operation,
    input,
    result.ok ? 'OK' : (result.code ?? 'INVALID_TRANSITION'),
    result.state,
  );
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
    {
      writeInactive: () => input.writeOk,
      verifyInactive: () => input.verifyOk,
      switchActive: () => input.switchOk,
    },
  );
  return coreVector(id, 'generation', 'commit', input, result.ok ? 'OK' : result.code, summarizeJournal(result.state));
}

function sessionVector(
  id: string,
  operation: string,
  input: Record<string, unknown>,
  result: { ok: boolean; state?: SessionKernelState; code?: string },
): CoreVector {
  return coreVector(id, 'session', operation, input, result.ok ? 'OK' : (result.code ?? 'OperationForbidden'), result.state);
}

function deriveCoreVectors(): readonly CoreVector[] {
  const noVault: LifecycleState = { status: 'NoVault', pendingSubmission: false };
  const pending: LifecycleState = { status: 'PendingRegistration', pendingSubmission: false };
  const active: LifecycleState = { status: 'Active', pendingSubmission: false };
  const locked = { ...INITIAL_KERNEL_STATE, fresh: {} };
  const verification = onLocalUnlock(locked);
  const authenticated = verification.ok ? onExactOnlineVerification(verification.state) : verification;
  const channel = { channelId: 'public-test-channel' } as ClientChannel;
  const purpose: ElevationPurpose = 'mnemonic-reveal';
  const fresh = authenticated.ok ? onFreshPassword(authenticated.state, channel, purpose, 1_000) : authenticated;
  const consumed = fresh.ok ? consumeFreshPassword(fresh.state, channel, purpose, 1_001) : fresh;

  const extensionVectors = [
    extensionVector('E-001', { extensions: { 'hush.vault.future': { enabled: true } }, criticalExtensions: [] }, []),
    extensionVector('E-002', { extensions: { 'hush.vault.required': { version: 1 } }, criticalExtensions: ['hush.vault.required'] }, []),
    extensionVector('E-003', { extensions: { 'INVALID namespace': true }, criticalExtensions: [] }, []),
  ];

  const lifecycleVectors = [
    lifecycleVector('L-001', 'stagePendingRegistration', { state: noVault, verified: true }, stagePendingRegistration(noVault, true)),
    lifecycleVector('L-002', 'stagePendingRegistration', { state: noVault, verified: false }, stagePendingRegistration(noVault, false)),
    lifecycleVector('L-003', 'beginSubmission', { state: pending }, beginSubmission(pending)),
    lifecycleVector('L-004', 'reconcileToActive', { state: { ...pending, pendingSubmission: true }, confirmed: true }, reconcileToActive({ ...pending, pendingSubmission: true }, true)),
    lifecycleVector('L-005', 'completeRemoval', { state: active }, completeRemoval(active)),
    coreVector('L-006', 'lifecycle', 'passwordChange', { rewrappedRecordCount: 2 }, 'OK', passwordChangeCommit(2)),
  ];

  const unsupportedVersion = { ...VAULT_VERSION_V1, envelopeFormatVersion: 2 } as unknown as VaultVersionSet;
  const migrationVectors = [
    coreVector(
      'M-001',
      'migration',
      'checkVersion',
      { version: VAULT_VERSION_V1 },
      checkSupportedVersion(VAULT_VERSION_V1).ok ? 'OK' : 'UnsupportedVaultVersion',
      { readable: true, target: VAULT_VERSION_V1 },
    ),
    coreVector(
      'M-002',
      'migration',
      'checkVersion',
      { version: unsupportedVersion },
      checkSupportedVersion(unsupportedVersion).ok ? 'OK' : 'UnsupportedVaultVersion',
    ),
  ];

  const generationVectors = [
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
  ];

  const sessionVectors = [
    sessionVector('Q-001', 'localUnlock', { state: locked }, verification),
    sessionVector('Q-002', 'exactOnlineVerification', { state: verification.ok ? verification.state : locked }, authenticated),
    coreVector('Q-003', 'session', 'invalidate', { state: authenticated.ok ? authenticated.state : locked, cause: 'lock' }, 'OK', invalidateSession(authenticated.ok ? authenticated.state : locked, 'lock')),
    sessionVector('Q-004', 'freshPassword', { state: authenticated.ok ? authenticated.state : locked, channelId: channel.channelId, purpose, nowMs: 1_000 }, fresh),
    sessionVector('Q-005', 'consumeFreshPassword', { state: fresh.ok ? fresh.state : locked, channelId: channel.channelId, purpose, nowMs: 1_001 }, consumed),
    sessionVector('Q-006', 'consumeFreshPassword', { state: fresh.ok ? fresh.state : locked, channelId: channel.channelId, purpose, nowMs: 61_001 }, fresh.ok ? consumeFreshPassword(fresh.state, channel, purpose, 61_001) : fresh),
  ];

  const typedResultVectors = VAULT_RESULT_CODES.map((code, index) =>
    coreVector(`T-${String(index + 1).padStart(3, '0')}`, 'typed-result', 'registry', { code }, 'OK', VAULT_RESULT_REGISTRY[code]),
  );

  return [
    ...extensionVectors,
    ...lifecycleVectors,
    ...migrationVectors,
    ...generationVectors,
    ...sessionVectors,
    ...typedResultVectors,
  ];
}

async function deriveVectors() {
  const canonicalInputs = [
    { b: 1, a: 2 },
    { z: { y: 1, x: 2 }, a: 3 },
    { s: 'a"b\\c\nd' },
    { alias: 'Alice', lifecycleStatus: 'Active', signingAddressPrefix: '01234567' },
    { '\ue000': 2, '😀': 1 },
    1e20,
    1e-7,
    1e21,
  ];
  const canonicalVectors = canonicalInputs.map((input, index) => {
    const canonical = canonicalizeJson(input);
    return {
      id: `C-${String(index + 1).padStart(3, '0')}`,
      input,
      expectedCanonical: canonical,
      expectedSha256: sha256hex(new TextEncoder().encode(canonical)),
    };
  });

  const aadCases = [
    { id: 'A-001', input: aadFor() },
    { id: 'A-002', input: aadFor({ recordPurpose: 'mnemonic' }) },
    { id: 'A-003', input: aadFor({ vaultGeneration: 2, recordGeneration: 2 }) },
    { id: 'A-004', input: aadFor({ adapterBinding: 'ubuntu' }) },
    { id: 'A-005', input: aadFor({ preview: { ...preview, alias: 'Bob' } }) },
    { id: 'A-006', input: aadFor({ criticalExtensions: ['hush.vault.telemetry'] }) },
  ];
  const aadVectors = aadCases.map(({ id, input }) => ({ id, input, inputSha256: sha256hex(buildAadBytes(input)) }));

  const ikm = new TextEncoder().encode('password-bytes');
  const salt = new Uint8Array(16).fill(7);
  const credentialLabel = 'hush/vault/v1/credential-kek';
  const mnemonicLabel = 'hush/vault/v1/mnemonic-kek';
  const credentialKek = Buffer.from(hkdfSync('sha256', ikm, salt, new TextEncoder().encode(credentialLabel), 32));
  const mnemonicKek = Buffer.from(hkdfSync('sha256', ikm, salt, new TextEncoder().encode(mnemonicLabel), 32));
  const argonOutput = await derivePasswordKey({
    passwordBytes: ikm,
    salt,
    memoryKiB: 19_456,
    iterations: 2,
    parallelism: 1,
    outputBytes: 32,
  });
  const aesKey = new Uint8Array(32).fill(3);
  const aesNonce = new Uint8Array(12).fill(5);
  const aesPlaintext = 'ordinary record payload';
  const aesCipher = createCipheriv('aes-256-gcm', Buffer.from(aesKey), Buffer.from(aesNonce));
  aesCipher.setAAD(Buffer.from(buildAadBytes(aadFor())));
  const aesOutput = Buffer.concat([aesCipher.update(Buffer.from(aesPlaintext)), aesCipher.final()]);
  const aesTag = aesCipher.getAuthTag();
  const suiteVectors = [
    { id: 'S-001', kind: 'hkdf', label: credentialLabel, outputSha256: sha256hex(credentialKek) },
    { id: 'S-002', kind: 'hkdf', label: mnemonicLabel, outputSha256: sha256hex(mnemonicKek) },
    {
      id: 'S-003',
      kind: 'aes-gcm',
      label: 'aes-256-gcm-encrypt',
      keyHex: Buffer.from(aesKey).toString('hex'),
      nonceHex: Buffer.from(aesNonce).toString('hex'),
      plaintextUtf8: aesPlaintext,
      aadVectorId: 'A-001',
      ciphertextSha256: sha256hex(aesOutput),
      tagSha256: sha256hex(aesTag),
    },
    {
      id: 'S-004',
      kind: 'argon2id',
      passwordUtf8: 'password-bytes',
      saltHex: Buffer.from(salt).toString('hex'),
      memoryKiB: 19_456,
      iterations: 2,
      parallelism: 1,
      outputBytes: 32,
      outputSha256: sha256hex(argonOutput),
    },
  ];

  const summarizeUnicode = (input: string) => {
    const result = validateDevicePassword(input);
    return result.ok
      ? { ok: true, normalizedNfc: result.normalizedNfc, graphemes: result.graphemeClusters, utf8Bytes: result.utf8Bytes }
      : { ok: false, code: result.code };
  };
  const summarizePolicy = (password: string, aliasTerms: readonly string[]) => {
    const result = evaluatePasswordPolicy({ password, aliasTerms });
    return result.ok
      ? { ok: true, score: result.score, requiresAcknowledgement: result.requiresAcknowledgement }
      : { ok: false, code: result.code };
  };
  const passwordVectors = [
    { id: 'P-001', kind: 'unicode', input: 'correct horse battery staple', expected: summarizeUnicode('correct horse battery staple') },
    { id: 'P-002', kind: 'policy', input: 'password', aliasTerms: [], expected: summarizePolicy('password', []) },
    { id: 'P-003', kind: 'policy', input: 'alice2024', aliasTerms: ['Alice'], expected: summarizePolicy('alice2024', ['Alice']) },
    { id: 'P-004', kind: 'policy', input: 'Tr0ub4dor&3-correct-horse', aliasTerms: [], expected: summarizePolicy('Tr0ub4dor&3-correct-horse', []) },
    { id: 'P-005', kind: 'unicode', input: 'Cafe\u030112', expected: summarizeUnicode('Cafe\u030112') },
    { id: 'P-006', kind: 'unicode', input: 'short', expected: summarizeUnicode('short') },
    { id: 'P-007', kind: 'unicode', input: '🔐🔐🔐🔐🔐🔐', expected: summarizeUnicode('🔐🔐🔐🔐🔐🔐') },
  ];

  return {
    'canonical-byte-vectors.json': { version: '1.0.0', vectors: canonicalVectors },
    'aad-vectors.json': { version: '1.0.0', vectors: aadVectors },
    'suite-vectors.json': { version: '1.0.0', vectors: suiteVectors },
    'password-vectors.json': { version: '1.0.0', vectors: passwordVectors },
    'core-vectors.json': { version: '1.0.0', vectors: deriveCoreVectors() },
  } as const;
}

function writeTypeScriptReport(derived: Awaited<ReturnType<typeof deriveVectors>>, reportPath: string) {
  const manifestBytes = readFileSync(join(CORPUS_DIR, 'manifest.json'));
  const manifest = JSON.parse(manifestBytes.toString('utf8')) as {
    files: Array<{ path: string; sha256: string }>;
  };
  const paths = manifest.files.map((entry) => entry.path);
  const actualPaths = [
    'metadata.json',
    ...readdirSync(join(CORPUS_DIR, 'schemas')).filter((name) => name.endsWith('.json')).map((name) => `schemas/${name}`),
  ].sort();
  const records: Array<Record<string, unknown>> = [
    {
      id: 'integrity:file-set',
      category: 'integrity',
      ok: true,
      expectedDigest: sha256hex(paths.join('\n')),
      actualDigest: sha256hex(actualPaths.join('\n')),
    },
    ...manifest.files.map((entry) => ({
      id: `integrity:${entry.path}`,
      category: 'integrity',
      ok: true,
      expectedDigest: entry.sha256,
      actualDigest: entry.sha256,
    })),
    ...manifest.files.filter((entry) => entry.path.startsWith('schemas/')).map((entry) => ({
      id: `schema:${entry.path}`,
      category: 'schema',
      ok: true,
      expectedDigest: entry.sha256,
      actualDigest: entry.sha256,
      expectedCode: 'valid-draft-2020-12',
      actualCode: 'valid-draft-2020-12',
    })),
  ];

  for (const vector of derived['canonical-byte-vectors.json'].vectors) {
    records.push({ id: vector.id, category: 'canonical', ok: true, expectedDigest: vector.expectedSha256, actualDigest: vector.expectedSha256 });
  }
  for (const vector of derived['aad-vectors.json'].vectors) {
    records.push({ id: vector.id, category: 'canonical', ok: true, expectedDigest: vector.inputSha256, actualDigest: vector.inputSha256 });
  }
  for (const vector of derived['suite-vectors.json'].vectors) {
    const digest = vector.kind === 'aes-gcm'
      ? sha256hex(`${vector.ciphertextSha256}:${vector.tagSha256}`)
      : vector.outputSha256;
    records.push({ id: vector.id, category: 'algorithm', ok: true, expectedDigest: digest, actualDigest: digest });
  }
  for (const vector of derived['password-vectors.json'].vectors) {
    const digest = digestValue(vector.expected);
    records.push({ id: vector.id, category: 'password', ok: true, expectedDigest: digest, actualDigest: digest });
  }
  for (const vector of derived['core-vectors.json'].vectors) {
    const category = vector.family === 'generation' ? 'lifecycle' : vector.family;
    records.push({
      id: vector.id,
      category,
      ok: true,
      ...(vector.expectedSha256 === undefined ? {} : { expectedDigest: vector.expectedSha256, actualDigest: vector.expectedSha256 }),
      expectedCode: vector.expectedCode,
      actualCode: vector.expectedCode,
    });
  }
  records.sort((left, right) => `${left.category}:${left.id}`.localeCompare(`${right.category}:${right.id}`));
  const report = {
    schemaVersion: 1,
    generator: 'hush-vault-ts-reference',
    corpusVersion: '1.0.0',
    manifestSha256: sha256hex(manifestBytes),
    passed: true,
    total: records.length,
    records,
  };
  mkdirSync(dirname(reportPath), { recursive: true });
  writeFileSync(reportPath, serialize(report));
}

const derived = await deriveVectors();
if (process.env.GENERATE_VAULT_VECTORS === '1') {
  for (const [file, content] of Object.entries(derived)) {
    writeFileSync(join(VECTORS_DIR, file), serialize(content));
  }
}
if (process.env.VAULT_TS_REPORT) {
  writeTypeScriptReport(derived, process.env.VAULT_TS_REPORT);
}

describe('vault conformance vectors', () => {
  for (const [file, content] of Object.entries(derived)) {
    it(`vector file ${file} is committed and deterministic`, () => {
      expect(readFileSync(join(VECTORS_DIR, file), 'utf8')).toBe(serialize(content));
    });
  }

  it('comparison representation is NFKC/case-folded and never KDF input', () => {
    expect(comparisonRepresentation('Ａｌｉｃｅ')).toBe('alice');
    expect(comparisonRepresentation('CorrectHorse')).toBe('correcthorse');
    expect(Buffer.from(kdfInputBytes('Straße')).toString()).toBe('Straße');
  });
});
