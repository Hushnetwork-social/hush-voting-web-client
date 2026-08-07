/**
 * FEAT-010 production browser vault — sealed secret-owning engine (Task 7.3).
 *
 * Runs ONLY inside the SharedWorker (never imported by page/React code). This
 * engine implements the real worker authority `executeOperation` surface over
 * production primitives:
 *
 * - IndexedDB vault storage (two-slot journal + CAS, allowlisted keys);
 * - the closed FEAT-003 suite v1 crypto (Argon2id via @noble/hashes, HKDF +
 *   AES-256-GCM via WebCrypto) with suite-bound inputs only;
 * - the FEAT-003 sidecar throttle schedule (combined wrong-password-or-damage
 *   error, bounded cooldown, no permanent lockout);
 * - the FEAT-010 current-record contract: concrete-key-only, explicit
 *   canonical network binding authenticated inside the encrypted record
 *   (mismatch fails before unlock promotion, AC-010-021/043);
 * - the FEAT-010 no-mnemonic rule: v1 envelopes carry NO mnemonic slot;
 * - real same-origin BFF identity verification (exact signing AND encryption
 *   address equality; no page Boolean can promote authentication);
 * - candidate custody: P-01/words/file candidates are generated and held HERE
 *   (mnemonic, private keys, and .dat bytes never cross to the page).
 *
 * SECRET BOUNDARY: every secret (device password, mnemonic, .dat bytes,
 * private keys, derived keys) stays inside this module's memory and is wiped
 * on Lock/removal/authority loss. Only bounded recovery words leave through
 * the explicit user-facing reveal operation (60 s window, concealable).
 *
 * Normative source: FEAT-003 FeatureDescription "Logical Vault Model",
 * "Cryptographic Suite", "Wrong-password throttling"; FEAT-004 FeatureDescription
 * "Provisioning handoff", "Online Identity Verification"; FEAT-010 FeatureDescription
 * "Current Record", "Returning Unlock", "Removal"; FEAT-001 compatibility API.
 */

import { entropyToMnemonicWorker, validateMnemonicWorker } from './bip39-worker';
import type { DeploymentManifest } from '../../runtime/deployment';
import type { VaultStorageSession } from '../storage/wrapper';
import type { SuiteCryptoOperations } from '../../vault-core/contracts/ports';
import { createAtomicJournal, type AtomicJournal } from '../lifecycle/journal';
import {
  canonicalizeJsonBytes,
} from '../../vault-core/canonical/jcs';
import { buildAadMetadata } from '../../vault-core/canonical/aad';
import { checkSupportedVersion } from '../../vault-core/contracts/versions';
import { SUITE_V1_KDF } from '../crypto/executor';
import { bytesToHexLower, sha256Hex, hexToBytesStrict, utf8Bytes } from '../../identity-compatibility/crypto';
import { normalizeMnemonicOlimpo } from '../../identity-compatibility/producers';
import { deriveP01KeysWorker, deriveP02KeysWorker } from './bip39-worker';
import { decodeDatV1 } from '../../identity-compatibility/dat';
import { validateMnemonicForProducer } from '../../identity-compatibility/mnemonic';
import { signMessage } from '../../identity-compatibility/signature';
import { serializeUnsignedTransaction } from '../../identity-compatibility/canonical';
import { createUuidV4, corpusTimestamp, describeCanonicalTransaction } from '../../identity-creation/profile';
import type { CurrentNetworkBinding, CurrentKeyBinding, CurrentProtectionModeClass } from '../../vault-core/contracts/current-binding';
import { THROTTLE_SCHEDULE, THROTTLE_MAX_SECONDS, MAX_FAILED_PASSWORD_COUNT, type RemovalStage } from '../../vault-core/contracts/sidecar';
import type { VaultPreviewV1 } from '../../vault-core/contracts/preview';
import { PREVIEW_SIGNING_ADDRESS_PREFIX_LENGTH, PREVIEW_SIGNING_ADDRESS_SUFFIX_LENGTH } from '../../vault-core/contracts/preview';
import { RECORD_BOUNDS } from '../../vault-core/contracts/records';

/** Credential-KEK HKDF label (sealed suite v1). */
const CREDENTIAL_KEK_LABEL = 'hush/vault/v1/credential-kek' as const;
/** KDF salt extension namespace (additive FEAT-010, non-critical, tolerated by v1). */
const KDF_SALT_EXTENSION = 'hush.vault.kdf-salt' as const;
/** Vault database name (sealed FEAT-004). */
const VAULT_DB_NAME = 'hushvoting-vault' as const;

/** Closed typed outcomes of sealed operations (safe; never secrets). */
export type SealedOutcome =
  | { readonly code: 'OK'; readonly detail?: unknown }
  | { readonly code: 'WRONG_PASSWORD_OR_DAMAGED' }
  | { readonly code: 'THROTTLED'; readonly cooldownDeadlineMs: number }
  | { readonly code: 'NETWORK_MISMATCH' }
  | { readonly code: 'UNSUPPORTED_VAULT' }
  | { readonly code: 'CORRUPT_VAULT' }
  | { readonly code: 'PROFILE_MISSING'; readonly safeCandidate: { readonly alias: string; readonly abbreviatedSigningAddress: string } }
  | { readonly code: 'SIGNING_KEY_MISMATCH' }
  | { readonly code: 'ENCRYPTION_KEY_MISMATCH' }
  | { readonly code: 'VERIFY_TIMEOUT' }
  | { readonly code: 'NETWORK_UNAVAILABLE' }
  | { readonly code: 'INVALID_INPUT'; readonly reason: string }
  | { readonly code: 'UNKNOWN_FAILURE'; readonly supportCode: string };

/** Safe public identity metadata surfaced after unlock (never secrets). */
export interface SealedSafeIdentity {
  readonly alias: string;
  readonly abbreviatedSigningAddress: string;
}

/** The ordinary-record plaintext carried INSIDE the encrypted current record.
 *
 * Concrete-key-only (AC-010-073+): the record holds the actual signing and
 * encryption private keys (concrete keys), never mnemonic/seed/phrase/recovery
 * material. The sealed record is the ONLY persistent secret store.
 */
export interface CurrentRecordPlaintext {
  readonly schemaVersion: 1;
  readonly alias: string;
  readonly visibility: 'private' | 'public';
  readonly producerId: string;
  readonly producerVersion: string;
  readonly lifecycleStatus: 'PendingRegistration' | 'Active';
  readonly networkBinding: CurrentNetworkBinding;
  readonly keyBinding: CurrentKeyBinding;
  /** Concrete signing private key (hex scalar; sealed inside the record). */
  readonly signingPrivateKey: string;
  /** Concrete encryption private key (hex scalar; sealed inside the record). */
  readonly encryptionPrivateKey: string;
  readonly protectionModeClass: CurrentProtectionModeClass;
  readonly generation: number;
  readonly transactionDigest: string | null;
}

/** One in-memory candidate (worker-held; never crosses to the page). */
export interface SealedCandidate {
  readonly ref: string;
  readonly kind: 'create' | 'words' | 'file';
  readonly mnemonic: string | null;
  readonly signingPrivateKey: string;
  readonly encryptionPrivateKey: string;
  readonly signingAddress: string;
  readonly encryptionAddress: string;
  readonly producerId: string;
  readonly producerVersion: string;
  readonly createdAtMs: number;
  revealedWords: boolean;
}

/** Unlocked session material (worker-held; wiped on Lock/removal). */
export interface UnlockedSession {
  readonly epoch: number;
  readonly signingPrivateKey: string;
  readonly encryptionPrivateKey: string;
  readonly dek: Uint8Array;
  /** Device-password-derived KEK retained only for the unlocked session. */
  readonly kek: Uint8Array;
  readonly record: CurrentRecordPlaintext;
  readonly preview: VaultPreviewV1;
}

/** Inputs for one sealed provisioning operation. */
export interface SealedProvisionInput {
  readonly candidateRef: string;
  readonly devicePassword: string;
  readonly alias: string;
  readonly visibility: 'private' | 'public';
  readonly configurationId: string;
  readonly networkBinding: CurrentNetworkBinding;
  readonly producerId: string;
}

/** Identity lookup result shape (sealed BFF mapping; only closed fields). */
export interface SealedIdentityLookup {
  readonly kind: 'exact' | 'missing' | 'timeout' | 'unavailable';
  readonly profileName?: string;
  readonly signingAddress?: string;
  readonly encryptionAddress?: string;
  readonly visibility?: 'private' | 'public';
}

/** Engine dependencies (production wiring in worker-entry; deterministic in tests). */
export interface SealedVaultDependencies {
  readonly storage: VaultStorageSession;
  readonly suite: SuiteCryptoOperations & { readonly randomBytes: (length: number) => Uint8Array; readonly suiteId: string };
  readonly manifest: DeploymentManifest;
  readonly nowMs: () => number;
  readonly randomId: (prefix: string) => string;
  /** Same-origin BFF identity lookup (exact both-key reply). */
  readonly lookupIdentity: (signingAddress: string) => Promise<SealedIdentityLookup>;
  /** Broadcast advisory (global Lock/removal/takeover). */
  readonly broadcast: (payload: unknown) => void;
  /** Notify the authority that cleanup must be forced (secret wipe). */
  readonly onForceCleanup: () => void;
}

function b64url(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unb64url(value: string): Uint8Array | null {
  try {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(normalized);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
}

function utf8Text(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/** Structural parsed-envelope view (safe fields only; never secrets). */
interface ParsedEnvelope {
  readonly envelopeFormatVersion: number;
  readonly parameterSuiteVersion: number;
  readonly recordSchemaVersion: number;
  readonly platformWrapperVersion: number;
  readonly suite: {
    readonly id: string;
    readonly kdf: { readonly algorithm: string; readonly minMemoryKiB: number; readonly iterations: number; readonly parallelism: number; readonly outputBytes: number };
  };
  readonly preview: VaultPreviewV1;
  readonly records: {
    readonly generation: { readonly active: number };
    readonly ordinary: {
      readonly generation: number;
      readonly producerId: string;
      readonly producerVersion: string;
      readonly keyPackage: { readonly wrappedDataKey: string; readonly wrappingNonce: string };
      readonly ciphertext: string;
      readonly encryptionNonce: string;
    };
  };
  readonly extensions?: { readonly extensions?: Record<string, unknown>; readonly criticalExtensions?: readonly string[] };
}

/** Normalize any byte view into a same-realm Uint8Array (cross-realm safe). */
function normalizeByteView(value: unknown): Uint8Array | null {
  if (value instanceof Uint8Array) {
    return new Uint8Array(value);
  }
  if (ArrayBuffer.isView(value) && (value as { BYTES_PER_ELEMENT?: number }).BYTES_PER_ELEMENT === 1) {
    const view = value as ArrayBufferView;
    return new Uint8Array(view.buffer, view.byteOffset, view.byteLength);
  }
  return null;
}

/** Serialized GCM payload = ciphertext || 16-byte tag (record storage shape). */
function joinCipherAndTag(ciphertext: Uint8Array, tag: Uint8Array): Uint8Array {
  const combined = new Uint8Array(ciphertext.byteLength + tag.byteLength);
  combined.set(ciphertext, 0);
  combined.set(tag, ciphertext.byteLength);
  return combined;
}

/** Split a serialized GCM payload back into ciphertext + tag. */
function splitCipherAndTag(bytes: Uint8Array): { readonly ciphertext: Uint8Array; readonly tag: Uint8Array } {
  if (bytes.byteLength < 16) {
    throw new Error('truncated GCM payload');
  }
  const tag = bytes.subarray(bytes.byteLength - 16);
  const ciphertext = bytes.subarray(0, bytes.byteLength - 16);
  return { ciphertext: new Uint8Array(ciphertext), tag: new Uint8Array(tag) };
}

/** Abbreviated signing address (8 + 6, preview contract). */
export function abbreviateSigningAddress(address: string): string {
  const prefix = address.slice(0, PREVIEW_SIGNING_ADDRESS_PREFIX_LENGTH);
  const suffix = address.slice(-PREVIEW_SIGNING_ADDRESS_SUFFIX_LENGTH);
  return `${prefix}…${suffix}`;
}

/** Deterministic cooldown seconds for the failed-attempt count (FEAT-003 schedule). */
export function cooldownSecondsFor(failedCount: number): number {
  if (failedCount <= 0) {
    return 0;
  }
  const index = failedCount - 1;
  if (index < THROTTLE_SCHEDULE.length) {
    return THROTTLE_SCHEDULE[index] ?? 0;
  }
  return THROTTLE_MAX_SECONDS;
}

interface ThrottleSidecar {
  readonly failedPasswordCount: number;
  readonly cooldownDeadline: number;
}

const THROTTLE_KEY = 'throttle' as const;
const REMOVAL_TOMBSTONE_KEY = 'removalTombstone' as const;

function readThrottle(value: unknown): ThrottleSidecar {
  if (typeof value !== 'object' || value === null) {
    return { failedPasswordCount: 0, cooldownDeadline: 0 };
  }
  const record = value as Record<string, unknown>;
  const count = typeof record.failedPasswordCount === 'number' ? Math.min(Math.max(0, Math.floor(record.failedPasswordCount)), MAX_FAILED_PASSWORD_COUNT) : 0;
  const deadline = typeof record.cooldownDeadline === 'number' && Number.isFinite(record.cooldownDeadline) ? record.cooldownDeadline : 0;
  return { failedPasswordCount: count, cooldownDeadline: deadline };
}

/**
 * The sealed vault engine. One instance per worker authority; owns the only
 * in-worker secret material. All operations are epoch/operation-scoped by the
 * caller (WorkerAuthority); this engine never sees page secrets except through
 * the explicit transfer methods below.
 */
export class SealedVaultEngine {
  private readonly storage: VaultStorageSession;
  private readonly suite: SealedVaultDependencies['suite'];
  private readonly manifest: DeploymentManifest;
  private readonly nowMs: () => number;
  private readonly randomId: (prefix: string) => string;
  private readonly lookupIdentity: SealedVaultDependencies['lookupIdentity'];
  private readonly broadcast: SealedVaultDependencies['broadcast'];
  private readonly journal: AtomicJournal;
  private readonly candidates = new Map<string, SealedCandidate>();
  private session: UnlockedSession | null = null;
  private phase: 'noLocalUser' | 'locked' | 'verificationOnly' | 'authenticated' | 'removalInProgress' = 'locked';

  constructor(deps: SealedVaultDependencies) {
    this.storage = deps.storage;
    this.suite = deps.suite;
    this.manifest = deps.manifest;
    this.nowMs = deps.nowMs;
    this.randomId = deps.randomId;
    this.lookupIdentity = deps.lookupIdentity;
    this.broadcast = deps.broadcast;
    this.journal = createAtomicJournal(deps.storage, {
      verifyCandidate: (bytes, generation) => this.verifyEnvelopeBytes(bytes, generation),
      nowMs: deps.nowMs,
    });
  }

  /** Current authority phase projection (safe). */
  snapshot(): { readonly phase: SealedVaultEngine['phase']; readonly hasCandidate: boolean; readonly hasSession: boolean } {
    return { phase: this.phase, hasCandidate: this.candidates.size > 0, hasSession: this.session !== null };
  }

  /** Wipe every in-worker secret (Lock/removal/authority loss). */
  wipeSecrets(): void {
    this.session?.dek.fill(0);
    this.session?.kek.fill(0);
    this.session = null;
    for (const key of this.candidates.keys()) {
      this.candidates.delete(key);
    }
    this.phase = 'locked';
  }

  // ---------------------------------------------------------------------
  // Candidate custody (create / words / file)
  // ---------------------------------------------------------------------

  /** Generate a fresh P-01 candidate (24 words) inside the worker. */
  createCandidate(_input: { readonly wordCount: 24 }): SealedOutcome & { readonly detail?: { readonly ref: string; readonly signingAddress: string; readonly encryptionAddress: string; readonly wordCount: 24 } } {
    if (this.candidates.size >= 4) {
      return { code: 'INVALID_INPUT', reason: 'candidate-limit' };
    }
    // CSPRNG entropy via the suite; BIP-39 mapping is worker-safe (bip39's
    // Node Buffer is unavailable in SharedWorkers).
    const mnemonic = entropyToMnemonicWorker(this.suite.randomBytes(32));
    const derived = deriveP01KeysWorker(mnemonic);
    if (derived === null) {
      return { code: 'UNKNOWN_FAILURE', supportCode: this.randomId('sc-') };
    }
    const ref = this.randomId('cand-');
    this.candidates.set(ref, {
      ref,
      kind: 'create',
      mnemonic,
      signingPrivateKey: derived.signingPrivateKey,
      encryptionPrivateKey: derived.encryptionPrivateKey,
      signingAddress: derived.signingAddress,
      encryptionAddress: derived.encryptionAddress,
      producerId: 'P-01',
      producerVersion: '1.0.0',
      createdAtMs: this.nowMs(),
      revealedWords: false,
    });
    return { code: 'OK', detail: { ref, signingAddress: derived.signingAddress, encryptionAddress: derived.encryptionAddress, wordCount: 24 } };
  }

  /** Reveal the candidate's recovery words (user-facing; 60 s bound, one reveal). */
  revealWords(candidateRef: string): SealedOutcome & { readonly detail?: { readonly words: readonly string[] } } {
    const candidate = this.candidates.get(candidateRef);
    if (!candidate || candidate.mnemonic === null) {
      return { code: 'INVALID_INPUT', reason: 'unknown-candidate' };
    }
    if (this.nowMs() - candidate.createdAtMs > 60_000) {
      return { code: 'INVALID_INPUT', reason: 'reveal-window-expired' };
    }
    candidate.revealedWords = true;
    return { code: 'OK', detail: { words: candidate.mnemonic.split(' ') } };
  }

  /** Conceal (visual/accessibility conceal) — the candidate stays alive. */
  concealCandidate(candidateRef: string): SealedOutcome {
    if (!this.candidates.has(candidateRef)) {
      return { code: 'INVALID_INPUT', reason: 'unknown-candidate' };
    }
    return { code: 'OK' };
  }

  /** Destructively destroy a candidate (regeneration/cancel). */
  destroyCandidate(candidateRef: string): SealedOutcome {
    if (this.candidates.delete(candidateRef)) {
      return { code: 'OK' };
    }
    return { code: 'INVALID_INPUT', reason: 'unknown-candidate' };
  }

  /** Validate a user-supplied mnemonic and derive the selected producer's keys (worker-held). */
  deriveWordsCandidate(input: { readonly mnemonic: string; readonly producerId: string; readonly wordCount: 12 | 24 }): SealedOutcome & { readonly detail?: { readonly ref: string; readonly signingAddress: string; readonly encryptionAddress: string; readonly producerId: string } } {
    const normalized = normalizeMnemonicOlimpo(input.mnemonic);
    if (!validateMnemonicWorker(normalized)) {
      return { code: 'INVALID_INPUT', reason: 'invalid-mnemonic' };
    }
    const words = normalized.split(' ');
    if (words.length !== input.wordCount) {
      return { code: 'INVALID_INPUT', reason: 'wrong-word-count' };
    }
    const producer = input.producerId;
    const validation = validateMnemonicForProducer(normalized, producer);
    if (!validation.valid) {
      return { code: 'INVALID_INPUT', reason: validation.code };
    }
    const derived = producer === 'P-02' ? deriveP02KeysWorker(normalized) : deriveP01KeysWorker(normalized);
    if (derived === null) {
      return { code: 'INVALID_INPUT', reason: 'derivation-failed' };
    }
    const ref = this.randomId('cand-');
    this.candidates.set(ref, {
      ref,
      kind: 'words',
      mnemonic: normalized,
      signingPrivateKey: derived.signingPrivateKey,
      encryptionPrivateKey: derived.encryptionPrivateKey,
      signingAddress: derived.signingAddress,
      encryptionAddress: derived.encryptionAddress,
      producerId: producer,
      producerVersion: '1.0.0',
      createdAtMs: this.nowMs(),
      revealedWords: false,
    });
    return { code: 'OK', detail: { ref, signingAddress: derived.signingAddress, encryptionAddress: derived.encryptionAddress, producerId: producer } };
  }

  /** Decrypt a HUSH .dat file inside the worker and hold the imported candidate. */
  async importFileCandidate(input: { readonly fileBytes: Uint8Array; readonly filePassword: string }): Promise<SealedOutcome & { readonly detail?: { readonly ref: string; readonly signingAddress: string; readonly encryptionAddress: string; readonly profileName: string; readonly visibility: 'private' | 'public' } }> {
    const decoded = await decodeDatV1(input.fileBytes, input.filePassword);
    if (!decoded.ok) {
      return { code: 'INVALID_INPUT', reason: decoded.code };
    }
    const { record } = decoded.value;
    const ref = this.randomId('cand-');
    this.candidates.set(ref, {
      ref,
      kind: 'file',
      mnemonic: typeof record.Mnemonic === 'string' && record.Mnemonic.length > 0 ? record.Mnemonic : null,
      signingPrivateKey: record.PrivateSigningKey,
      encryptionPrivateKey: record.PrivateEncryptKey,
      signingAddress: record.PublicSigningAddress,
      encryptionAddress: record.PublicEncryptAddress,
      producerId: 'P-01',
      producerVersion: '1.0.0',
      createdAtMs: this.nowMs(),
      revealedWords: false,
    });
    return {
      code: 'OK',
      detail: { ref, signingAddress: record.PublicSigningAddress, encryptionAddress: record.PublicEncryptAddress, profileName: record.ProfileName, visibility: record.IsPublic ? 'public' : 'private' },
    };
  }

  // ---------------------------------------------------------------------
  // Provisioning (current no-mnemonic network-bound record)
  // ---------------------------------------------------------------------

  /**
   * Provision the encrypted current vault from a worker-held candidate.
   * Builds the sealed envelope, commits it through the two-slot CAS journal,
   * and initializes the throttle sidecar. Failure never leaves partial slots.
   */
  async provision(input: SealedProvisionInput): Promise<SealedOutcome & { readonly detail?: { readonly recordRef: string; readonly alias: string; readonly abbreviatedSigningAddress: string; readonly signingAddress: string; readonly encryptionAddress: string } }> {
    const candidate = this.candidates.get(input.candidateRef);
    if (!candidate) {
      return { code: 'INVALID_INPUT', reason: 'unknown-candidate' };
    }
    if (input.alias.length < 1 || input.alias.length > 64) {
      return { code: 'INVALID_INPUT', reason: 'alias-bounds' };
    }
    if (input.networkBinding.canonicalNetworkId !== this.manifest.canonicalNetworkId || input.networkBinding.networkMagic !== this.manifest.networkMagic) {
      return { code: 'INVALID_INPUT', reason: 'network-mismatch' };
    }

    const salt = this.suite.randomBytes(16);
    const passwordKey = await this.suite.derivePasswordKey({
      passwordBytes: utf8Bytes(input.devicePassword),
      salt,
      memoryKiB: SUITE_V1_KDF.memoryKiB,
      iterations: SUITE_V1_KDF.iterations,
      parallelism: SUITE_V1_KDF.parallelism,
      outputBytes: SUITE_V1_KDF.outputBytes,
    });
    const kek = await this.suite.hkdf({ ikm: passwordKey, salt, info: utf8Bytes(CREDENTIAL_KEK_LABEL), outputBytes: 32 });
    const dek = this.suite.randomBytes(32);
    const wrappingNonce = this.suite.randomBytes(12);
    const encryptionNonce = this.suite.randomBytes(12);

    const preview: VaultPreviewV1 = {
      alias: input.alias,
      signingAddressPrefix: candidate.signingAddress.slice(0, PREVIEW_SIGNING_ADDRESS_PREFIX_LENGTH),
      signingAddressSuffix: candidate.signingAddress.slice(-PREVIEW_SIGNING_ADDRESS_SUFFIX_LENGTH),
      lifecycleStatus: 'PendingRegistration',
      envelopeFormatVersion: 1,
      parameterSuiteVersion: 1,
      recordSchemaVersion: 1,
    };

    const plaintext: CurrentRecordPlaintext = {
      schemaVersion: 1,
      alias: input.alias,
      visibility: input.visibility,
      producerId: candidate.producerId,
      producerVersion: candidate.producerVersion,
      lifecycleStatus: 'PendingRegistration',
      networkBinding: input.networkBinding,
      keyBinding: { signingAddress: candidate.signingAddress, encryptionAddress: candidate.encryptionAddress },
      signingPrivateKey: candidate.signingPrivateKey,
      encryptionPrivateKey: candidate.encryptionPrivateKey,
      protectionModeClass: 'device-password',
      generation: 1,
      transactionDigest: null,
    };

    const aad = buildAadMetadata({
      envelopeFormatVersion: 1,
      parameterSuiteVersion: 1,
      recordSchemaVersion: 1,
      platformWrapperVersion: 0,
      suiteId: this.suite.suiteId,
      kdfParameters: { algorithm: 'Argon2id', memoryKiB: SUITE_V1_KDF.memoryKiB, iterations: SUITE_V1_KDF.iterations, parallelism: SUITE_V1_KDF.parallelism },
      adapterBinding: 'browser',
      preview,
      vaultGeneration: 1,
      recordGeneration: 1,
      recordPurpose: 'ordinary',
      producerId: candidate.producerId,
      producerVersion: candidate.producerVersion,
      // AAD signing binding must be identical between wrap and unwrap; the
      // preview-derived 14-char binding is known before decryption.
      signingAddress: `${preview.signingAddressPrefix}${preview.signingAddressSuffix}`,
      criticalExtensions: [],
    });
    const aadBytes = canonicalizeJsonBytes(aad);

    const wrapped = await this.suite.aes256GcmEncrypt({ key: kek, nonce: wrappingNonce, plaintext: dek, aad: aadBytes });
    const recordCiphertext = await this.suite.aes256GcmEncrypt({
      key: dek,
      nonce: encryptionNonce,
      plaintext: canonicalizeJsonBytes(plaintext),
      aad: aadBytes,
    });

    const envelope = {
      envelopeFormatVersion: 1,
      parameterSuiteVersion: 1,
      recordSchemaVersion: 1,
      platformWrapperVersion: 0,
      suite: {
        id: 'hush/vault/suite/v1',
        kdf: {
          algorithm: 'Argon2id',
          minMemoryKiB: 19456,
          iterations: 2,
          parallelism: 1,
          saltBytesMin: 16,
          outputBytes: 32,
          calibrationTargetMs: 750,
          calibrationWindowMsMin: 500,
          calibrationWindowMsMax: 1000,
          hardTimeoutMs: 1500,
          browserMemoryCapKiB: 65536,
          ubuntuMemoryCapKiB: 262144,
        },
        hkdf: { algorithm: 'HKDF-SHA-256', hash: 'SHA-256', outputBytes: 32, labels: ['hush/vault/v1/credential-kek', 'hush/vault/v1/mnemonic-kek'] },
        cipher: { algorithm: 'AES-256-GCM', keyBytes: 32, nonceBytes: 12 },
        limits: { maxEnvelopeBytes: 1048576, maxMetadataBytes: 65536, maxRecordBytes: 524288, maxExtensionDepth: 4, maxCollections: 64, maxNestingDepth: 16 },
      },
      preview,
      records: {
        generation: { active: 1 },
        ordinary: {
          purpose: 'ordinary',
          generation: 1,
          producerId: candidate.producerId,
          producerVersion: candidate.producerVersion,
          schemaVersion: 1,
          keyPackage: { wrappedDataKey: b64url(joinCipherAndTag(wrapped.ciphertext, wrapped.tag)), wrappingNonce: b64url(wrappingNonce) },
          ciphertext: b64url(joinCipherAndTag(recordCiphertext.ciphertext, recordCiphertext.tag)),
          encryptionNonce: b64url(encryptionNonce),
        },
        mnemonic: null,
      },
      extensions: { extensions: { [KDF_SALT_EXTENSION]: { salt: b64url(salt), hkdfSalt: b64url(salt) } }, criticalExtensions: [] },
    };

    // Structural bounds guard before any write.
    const serialized = canonicalizeJsonBytes(envelope);
    if (serialized.byteLength > RECORD_BOUNDS.maxRecordBytes) {
      return { code: 'INVALID_INPUT', reason: 'record-too-large' };
    }

    const commit = await this.journal.commit({ expectedGeneration: 0, candidateGeneration: 1, candidateBytes: serialized });
    if (!commit.ok) {
      return { code: 'UNKNOWN_FAILURE', supportCode: this.randomId('sc-') };
    }
    const throttleWrite = await this.storage.writeRecord('operationalSidecars', THROTTLE_KEY, { failedPasswordCount: 0, cooldownDeadline: 0 });
    if (!throttleWrite.ok) {
      return { code: 'UNKNOWN_FAILURE', supportCode: this.randomId('sc-') };
    }

    // The provisioning is provisional until fresh exact online verification
    // promotes it; the worker holds the concrete keys (verificationOnly) so
    // the child flow can submit and the root can verify — never authenticated.
    this.phase = 'verificationOnly';
    this.session = {
      epoch: this.nowMs(),
      signingPrivateKey: candidate.signingPrivateKey,
      encryptionPrivateKey: candidate.encryptionPrivateKey,
      dek,
      kek,
      record: plaintext,
      preview,
    };
    this.candidates.delete(input.candidateRef);
    return {
      code: 'OK',
      detail: {
        recordRef: this.randomId('rec-'),
        alias: input.alias,
        abbreviatedSigningAddress: abbreviateSigningAddress(candidate.signingAddress),
        signingAddress: candidate.signingAddress,
        encryptionAddress: candidate.encryptionAddress,
      },
    };
  }

  // ---------------------------------------------------------------------
  // Unlock (returning user)
  // ---------------------------------------------------------------------

  /** Unlock with the device password: cooldown → KDF → decrypt → binding checks. */
  async unlock(input: { readonly devicePassword: string; readonly configurationId: string }): Promise<SealedOutcome> {
    const throttleValue = await this.storage.readRecord('operationalSidecars', THROTTLE_KEY);
    const throttle = readThrottle(throttleValue.ok ? throttleValue.value.record : undefined);
    const now = this.nowMs();
    if (throttle.cooldownDeadline > now) {
      return { code: 'THROTTLED', cooldownDeadlineMs: throttle.cooldownDeadline };
    }

    const state = await this.journal.readState();
    if (!state.ok || state.value.activeGeneration === 0) {
      return { code: 'CORRUPT_VAULT' };
    }
    const envelope = await this.readActiveEnvelope();
    if (envelope === null) {
      return { code: 'CORRUPT_VAULT' };
    }

    const versionCheck = checkSupportedVersion({
      envelopeFormatVersion: envelope.envelopeFormatVersion as 1,
      parameterSuiteVersion: envelope.parameterSuiteVersion as 1,
      recordSchemaVersion: envelope.recordSchemaVersion as 1,
      platformWrapperVersion: envelope.platformWrapperVersion as 0,
    });
    if (!versionCheck.ok) {
      return { code: 'UNSUPPORTED_VAULT' };
    }

    const saltExtension = (envelope.extensions?.extensions?.[KDF_SALT_EXTENSION] as { salt?: string } | undefined) ?? null;
    const salt = saltExtension?.salt ? unb64url(saltExtension.salt) : null;
    if (salt === null || salt.byteLength < 16) {
      // A sealed v1 envelope without the additive salt extension cannot unlock.
      return { code: 'UNSUPPORTED_VAULT' };
    }

    const record = envelope.records.ordinary;
    const wrappedDataKey = unb64url(record.keyPackage.wrappedDataKey);
    const wrappingNonce = unb64url(record.keyPackage.wrappingNonce);
    if (wrappedDataKey === null || wrappingNonce === null) {
      return { code: 'CORRUPT_VAULT' };
    }
    let unwrapParts: { readonly ciphertext: Uint8Array; readonly tag: Uint8Array };
    try {
      unwrapParts = splitCipherAndTag(wrappedDataKey);
    } catch {
      return { code: 'CORRUPT_VAULT' };
    }

    const aad = buildAadMetadata({
      envelopeFormatVersion: envelope.envelopeFormatVersion,
      parameterSuiteVersion: envelope.parameterSuiteVersion,
      recordSchemaVersion: envelope.recordSchemaVersion,
      platformWrapperVersion: envelope.platformWrapperVersion,
      suiteId: envelope.suite.id,
      kdfParameters: { algorithm: envelope.suite.kdf.algorithm, memoryKiB: envelope.suite.kdf.minMemoryKiB, iterations: envelope.suite.kdf.iterations, parallelism: envelope.suite.kdf.parallelism },
      adapterBinding: 'browser',
      preview: envelope.preview,
      vaultGeneration: envelope.records.generation.active,
      recordGeneration: record.generation,
      recordPurpose: 'ordinary',
      producerId: record.producerId,
      producerVersion: record.producerVersion,
      signingAddress: `${envelope.preview.signingAddressPrefix}${envelope.preview.signingAddressSuffix}`,
      criticalExtensions: [],
    });
    const aadBytes = canonicalizeJsonBytes(aad);

    const recordFailure = async (): Promise<SealedOutcome> => {
      const nextCount = Math.min(throttle.failedPasswordCount + 1, MAX_FAILED_PASSWORD_COUNT);
      const addedSeconds = cooldownSecondsFor(nextCount);
      const next = { failedPasswordCount: nextCount, cooldownDeadline: addedSeconds > 0 ? this.nowMs() + addedSeconds * 1000 : 0 };
      await this.storage.writeRecord('operationalSidecars', THROTTLE_KEY, next);
      return { code: 'WRONG_PASSWORD_OR_DAMAGED' };
    };

    let kek: Uint8Array;
    let passwordKey: Uint8Array;
    try {
      passwordKey = await this.suite.derivePasswordKey({
        passwordBytes: utf8Bytes(input.devicePassword),
        salt,
        memoryKiB: envelope.suite.kdf.minMemoryKiB,
        iterations: envelope.suite.kdf.iterations,
        parallelism: envelope.suite.kdf.parallelism,
        outputBytes: envelope.suite.kdf.outputBytes,
      });
      kek = await this.suite.hkdf({ ikm: passwordKey, salt, info: utf8Bytes(CREDENTIAL_KEK_LABEL), outputBytes: 32 });
    } catch {
      return recordFailure();
    }

    let dek: Uint8Array;
    let requiresLegacyWrapperRepair = false;
    try {
      dek = await this.suite.aes256GcmDecrypt({ key: kek, nonce: wrappingNonce, ciphertext: unwrapParts.ciphertext, tag: unwrapParts.tag, aad: aadBytes });
    } catch {
      if (envelope.records.generation.active <= 1 || record.generation <= 1) {
        return recordFailure();
      }
      // Compatibility repair for the bounded FEAT-010 development defect:
      // earlier mutations retained the original generation-1 DEK wrapper
      // while correctly authenticating current ciphertext under current AAD.
      const provisioningPreview: VaultPreviewV1 = {
        ...envelope.preview,
        lifecycleStatus: 'PendingRegistration',
      };
      const provisioningAad = buildAadMetadata({
        envelopeFormatVersion: envelope.envelopeFormatVersion,
        parameterSuiteVersion: envelope.parameterSuiteVersion,
        recordSchemaVersion: envelope.recordSchemaVersion,
        platformWrapperVersion: envelope.platformWrapperVersion,
        suiteId: envelope.suite.id,
        kdfParameters: { algorithm: envelope.suite.kdf.algorithm, memoryKiB: envelope.suite.kdf.minMemoryKiB, iterations: envelope.suite.kdf.iterations, parallelism: envelope.suite.kdf.parallelism },
        adapterBinding: 'browser',
        preview: provisioningPreview,
        vaultGeneration: 1,
        recordGeneration: 1,
        recordPurpose: 'ordinary',
        producerId: record.producerId,
        producerVersion: record.producerVersion,
        signingAddress: `${provisioningPreview.signingAddressPrefix}${provisioningPreview.signingAddressSuffix}`,
        criticalExtensions: [],
      });
      try {
        dek = await this.suite.aes256GcmDecrypt({
          key: kek,
          nonce: wrappingNonce,
          ciphertext: unwrapParts.ciphertext,
          tag: unwrapParts.tag,
          aad: canonicalizeJsonBytes(provisioningAad),
        });
        requiresLegacyWrapperRepair = true;
      } catch {
        return recordFailure();
      }
    }

    const ciphertext = unb64url(record.ciphertext);
    const encryptionNonce = unb64url(record.encryptionNonce);
    if (ciphertext === null || encryptionNonce === null) {
      return { code: 'CORRUPT_VAULT' };
    }
    let recordParts: { readonly ciphertext: Uint8Array; readonly tag: Uint8Array };
    try {
      recordParts = splitCipherAndTag(ciphertext);
    } catch {
      return { code: 'CORRUPT_VAULT' };
    }

    let plaintextBytes: Uint8Array;
    try {
      plaintextBytes = await this.suite.aes256GcmDecrypt({ key: dek, nonce: encryptionNonce, ciphertext: recordParts.ciphertext, tag: recordParts.tag, aad: aadBytes });
    } catch {
      return recordFailure();
    }

    const parsed = parseCurrentRecord(utf8Text(plaintextBytes), record.generation);
    if (!parsed.ok) {
      return { code: 'CORRUPT_VAULT' };
    }
    const current = parsed.record;

    // Preview must match the authenticated plaintext (display-only vs truth).
    if (
      current.alias !== envelope.preview.alias ||
      current.keyBinding.signingAddress.slice(0, PREVIEW_SIGNING_ADDRESS_PREFIX_LENGTH) !== envelope.preview.signingAddressPrefix ||
      current.keyBinding.signingAddress.slice(-PREVIEW_SIGNING_ADDRESS_SUFFIX_LENGTH) !== envelope.preview.signingAddressSuffix ||
      current.lifecycleStatus !== envelope.preview.lifecycleStatus
    ) {
      return { code: 'CORRUPT_VAULT' };
    }

    // Network binding mismatch fails BEFORE any unlock promotion (AC-010-021).
    if (current.networkBinding.canonicalNetworkId !== this.manifest.canonicalNetworkId || current.networkBinding.networkMagic !== this.manifest.networkMagic) {
      return { code: 'NETWORK_MISMATCH' };
    }

    // Exact key consistency: decrypting the record proves the wrapping chain;
    // the derived session holds the concrete keys for signing and the online
    // both-key check.
    this.session = {
      epoch: this.nowMs(),
      signingPrivateKey: current.signingPrivateKey,
      encryptionPrivateKey: current.encryptionPrivateKey,
      dek,
      kek,
      record: current,
      preview: envelope.preview,
    };
    this.phase = 'verificationOnly';

    if (requiresLegacyWrapperRepair) {
      const repair = await this.reencryptCurrentRecord(current);
      if (repair.code !== 'OK') {
        this.wipeSecrets();
        return { code: 'UNKNOWN_FAILURE', supportCode: this.randomId('sc-') };
      }
    }

    // Reset the throttle on successful unlock (FEAT-003 rule).
    await this.storage.writeRecord('operationalSidecars', THROTTLE_KEY, { failedPasswordCount: 0, cooldownDeadline: 0 });

    return {
      code: 'OK',
      detail: { safeIdentity: { alias: current.alias, abbreviatedSigningAddress: abbreviateSigningAddress(current.keyBinding.signingAddress) } },
    } as SealedOutcome;
  }

  // ---------------------------------------------------------------------
  // Online verification (exact both-key)
  // ---------------------------------------------------------------------

  /** Fresh exact online verification: worker-owned BFF lookup, both keys equal. */
  async verifyOnline(): Promise<SealedOutcome & { readonly detail?: { readonly profileName: string; readonly signingAddress: string; readonly encryptionAddress: string } }> {
    if (this.session === null || this.phase === 'locked' || this.phase === 'noLocalUser') {
      return { code: 'UNKNOWN_FAILURE', supportCode: this.randomId('sc-') };
    }
    const binding = this.session.record.keyBinding;
    const lookup = await this.lookupIdentity(binding.signingAddress);
    switch (lookup.kind) {
      case 'exact': {
        if (lookup.signingAddress !== binding.signingAddress) {
          return { code: 'SIGNING_KEY_MISMATCH' };
        }
        if (lookup.encryptionAddress !== binding.encryptionAddress) {
          return { code: 'ENCRYPTION_KEY_MISMATCH' };
        }
        this.phase = 'authenticated';
        return {
          code: 'OK',
          detail: {
            profileName: lookup.profileName ?? this.session.record.alias,
            signingAddress: binding.signingAddress,
            encryptionAddress: binding.encryptionAddress,
          },
        };
      }
      case 'missing':
        return {
          code: 'PROFILE_MISSING',
          safeCandidate: { alias: this.session.record.alias, abbreviatedSigningAddress: abbreviateSigningAddress(binding.signingAddress) },
        };
      case 'timeout':
        return { code: 'VERIFY_TIMEOUT' };
      case 'unavailable':
        return { code: 'NETWORK_UNAVAILABLE' };
    }
  }

  /** Record the retained transaction digest for staged creation reconciliation. */
  async retainTransactionDigest(digest: string): Promise<SealedOutcome> {
    if (this.session === null) {
      return { code: 'UNKNOWN_FAILURE', supportCode: this.randomId('sc-') };
    }
    if (!/^[0-9a-f]{64}$/i.test(digest)) {
      return { code: 'INVALID_INPUT', reason: 'digest-shape' };
    }
    const updated = { ...this.session.record, transactionDigest: digest };
    return this.reencryptCurrentRecord(updated);
  }

  /**
   * Promote the local lifecycle (PendingRegistration → Active) ONLY after a
   * fresh exact online verification succeeded inside the worker.
   */
  async promoteLifecycle(status: 'Active' | 'PendingRegistration'): Promise<SealedOutcome> {
    if (this.session === null) {
      return { code: 'UNKNOWN_FAILURE', supportCode: this.randomId('sc-') };
    }
    if (status === 'Active' && this.phase !== 'authenticated') {
      // Promotion to Active requires worker-owned exact verification first.
      return { code: 'UNKNOWN_FAILURE', supportCode: this.randomId('sc-') };
    }
    const updated = { ...this.session.record, lifecycleStatus: status };
    return this.reencryptCurrentRecord(updated);
  }

  /**
   * Sign and submit the canonical FullIdentity transaction (worker-owned).
   * Returns the closed submission outcome; the exact signed transaction is
   * retained in the record digest before the first network call.
   */
  async submitIdentityTransaction(input: { readonly alias: string; readonly visibility: 'private' | 'public'; readonly submit: (signedTransaction: string) => Promise<{ readonly ok: true; readonly reply: { readonly status?: string; readonly validationCode?: string | null; readonly successfull?: boolean } } | { readonly ok: false; readonly failure: string }> }): Promise<SealedOutcome & { readonly detail?: { readonly status: 'accepted' | 'pending' | 'alreadyExists' | 'terminalRejection' | 'unknownRejection' | 'transportFailure' | 'compatibilityError'; readonly validationCode?: string } }> {
    if (this.session === null || this.phase === 'locked' || this.phase === 'noLocalUser') {
      return { code: 'UNKNOWN_FAILURE', supportCode: this.randomId('sc-') };
    }
    const record = this.session.record;
    const txId = createUuidV4();
    const timestamp = corpusTimestamp();
    const described = describeCanonicalTransaction({
      normalizedAlias: input.alias,
      publicSigningAddress: record.keyBinding.signingAddress,
      publicEncryptAddress: record.keyBinding.encryptionAddress,
      visibility: input.visibility,
      transactionId: txId,
      timestamp,
    });
    if (!described.ok) {
      return { code: 'INVALID_INPUT', reason: described.code };
    }
    const unsignedJson = serializeUnsignedTransaction(described.value.unsignedTransaction);
    const signed = signMessage(unsignedJson, this.session.signingPrivateKey);
    if (!signed.ok) {
      return { code: 'UNKNOWN_FAILURE', supportCode: this.randomId('sc-') };
    }
    const signedTransaction = JSON.stringify({
      ...described.value.unsignedTransaction,
      UserSignature: { Signatory: record.keyBinding.signingAddress, Signature: signed.value.compactBase64 },
    });
    const digest = sha256Hex(utf8Bytes(signedTransaction));
    const retained = await this.retainTransactionDigest(digest);
    if (retained.code !== 'OK') {
      return { code: 'UNKNOWN_FAILURE', supportCode: this.randomId('sc-') };
    }
    const result = await input.submit(signedTransaction);
    if (!result.ok) {
      return { code: 'OK', detail: { status: 'transportFailure' } };
    }
    const reply = result.reply;
    switch (reply.status) {
      case 'ACCEPTED':
        return { code: 'OK', detail: { status: 'accepted' } };
      case 'PENDING':
        return { code: 'OK', detail: { status: 'pending' } };
      case 'ALREADY_EXISTS':
        return { code: 'OK', detail: { status: 'alreadyExists' } };
      case 'REJECTED':
        // Without the pinned editable-rejection allowlist (external hardening
        // artifact), every rejection fails closed as unknown.
        return { code: 'OK', detail: { status: 'unknownRejection', validationCode: typeof reply.validationCode === 'string' ? reply.validationCode : undefined } };
      default:
        return { code: 'OK', detail: { status: 'compatibilityError' } };
    }
  }

  /** Re-encrypt the current record with updated plaintext (same DEK, CAS new generation). */
  private async reencryptCurrentRecord(updated: CurrentRecordPlaintext): Promise<SealedOutcome> {
    if (this.session === null) {
      return { code: 'UNKNOWN_FAILURE', supportCode: this.randomId('sc-') };
    }
    const envelope = await this.readActiveEnvelope();
    if (envelope === null) {
      return { code: 'CORRUPT_VAULT' };
    }
    const record = envelope.records.ordinary;
    const nextGeneration = envelope.records.generation.active + 1;
    const nextPreview: VaultPreviewV1 = {
      alias: updated.alias,
      signingAddressPrefix: updated.keyBinding.signingAddress.slice(0, PREVIEW_SIGNING_ADDRESS_PREFIX_LENGTH),
      signingAddressSuffix: updated.keyBinding.signingAddress.slice(-PREVIEW_SIGNING_ADDRESS_SUFFIX_LENGTH),
      lifecycleStatus: updated.lifecycleStatus,
      envelopeFormatVersion: 1,
      parameterSuiteVersion: 1,
      recordSchemaVersion: 1,
    };
    const aad = buildAadMetadata({
      envelopeFormatVersion: envelope.envelopeFormatVersion,
      parameterSuiteVersion: envelope.parameterSuiteVersion,
      recordSchemaVersion: envelope.recordSchemaVersion,
      platformWrapperVersion: envelope.platformWrapperVersion,
      suiteId: envelope.suite.id,
      kdfParameters: { algorithm: envelope.suite.kdf.algorithm, memoryKiB: envelope.suite.kdf.minMemoryKiB, iterations: envelope.suite.kdf.iterations, parallelism: envelope.suite.kdf.parallelism },
      adapterBinding: 'browser',
      preview: nextPreview,
      vaultGeneration: nextGeneration,
      recordGeneration: nextGeneration,
      recordPurpose: 'ordinary',
      producerId: record.producerId,
      producerVersion: record.producerVersion,
      signingAddress: `${nextPreview.signingAddressPrefix}${nextPreview.signingAddressSuffix}`,
      criticalExtensions: [],
    });
    const aadBytes = canonicalizeJsonBytes(aad);
    // AAD binds both the encrypted record and the wrapped DEK. Every metadata
    // or generation mutation must therefore rewrite BOTH layers atomically.
    const wrappingNonce = this.suite.randomBytes(12);
    const rewrapped = await this.suite.aes256GcmEncrypt({
      key: this.session.kek,
      nonce: wrappingNonce,
      plaintext: this.session.dek,
      aad: aadBytes,
    });
    const encryptionNonce = this.suite.randomBytes(12);
    const reencrypted = await this.suite.aes256GcmEncrypt({
      key: this.session.dek,
      nonce: encryptionNonce,
      plaintext: canonicalizeJsonBytes({ ...updated, generation: nextGeneration }),
      aad: aadBytes,
    });
    const nextEnvelope = {
      ...envelope,
      preview: nextPreview,
      records: {
        ...envelope.records,
        generation: { active: nextGeneration },
        ordinary: {
          ...record,
          generation: nextGeneration,
          keyPackage: {
            wrappedDataKey: b64url(joinCipherAndTag(rewrapped.ciphertext, rewrapped.tag)),
            wrappingNonce: b64url(wrappingNonce),
          },
          ciphertext: b64url(joinCipherAndTag(reencrypted.ciphertext, reencrypted.tag)),
          encryptionNonce: b64url(encryptionNonce),
        },
      },
    } as Record<string, unknown>;
    const serialized = canonicalizeJsonBytes(nextEnvelope);
    const commit = await this.journal.commit({ expectedGeneration: envelope.records.generation.active, candidateGeneration: nextGeneration, candidateBytes: serialized });
    if (!commit.ok) {
      // Previous verified generation remains authoritative.
      return { code: 'UNKNOWN_FAILURE', supportCode: this.randomId('sc-') };
    }
    this.session = { ...this.session, record: { ...updated, generation: nextGeneration }, preview: nextPreview };
    return { code: 'OK' };
  }

  // ---------------------------------------------------------------------
  // Lock / change-password / removal
  // ---------------------------------------------------------------------

  /** Global lock: wipe secrets (the authority owns epoch invalidation). */
  lock(): SealedOutcome {
    this.wipeSecrets();
    return { code: 'OK' };
  }

  /** Change the device password: rewrap the DEK under a fresh KEK, CAS new generation. */
  async changeDevicePassword(input: { readonly currentPassword: string; readonly newPassword: string }): Promise<SealedOutcome> {
    if (this.session === null) {
      return { code: 'UNKNOWN_FAILURE', supportCode: this.randomId('sc-') };
    }
    const unlock = await this.unlock({ devicePassword: input.currentPassword, configurationId: this.manifest.configurationId });
    if (unlock.code !== 'OK') {
      return unlock;
    }
    const envelope = await this.readActiveEnvelope();
    if (envelope === null) {
      return { code: 'CORRUPT_VAULT' };
    }
    const salt = unb64url((envelope.extensions?.extensions?.[KDF_SALT_EXTENSION] as { salt?: string } | undefined)?.salt ?? '');
    if (salt === null || salt.byteLength < 16) {
      return { code: 'UNSUPPORTED_VAULT' };
    }
    const newSalt = this.suite.randomBytes(16);
    const newPasswordKey = await this.suite.derivePasswordKey({
      passwordBytes: utf8Bytes(input.newPassword),
      salt: newSalt,
      memoryKiB: SUITE_V1_KDF.memoryKiB,
      iterations: SUITE_V1_KDF.iterations,
      parallelism: SUITE_V1_KDF.parallelism,
      outputBytes: SUITE_V1_KDF.outputBytes,
    });
    const newKek = await this.suite.hkdf({ ikm: newPasswordKey, salt: newSalt, info: utf8Bytes(CREDENTIAL_KEK_LABEL), outputBytes: 32 });

    const record = envelope.records.ordinary;
    const wrappedDataKey = unb64url(record.keyPackage.wrappedDataKey);
    const wrappingNonce = unb64url(record.keyPackage.wrappingNonce);
    if (wrappedDataKey === null || wrappingNonce === null) {
      return { code: 'CORRUPT_VAULT' };
    }
    let unwrapParts: { readonly ciphertext: Uint8Array; readonly tag: Uint8Array };
    try {
      unwrapParts = splitCipherAndTag(wrappedDataKey);
    } catch {
      return { code: 'CORRUPT_VAULT' };
    }
    const oldAad = buildAadMetadata({
      envelopeFormatVersion: envelope.envelopeFormatVersion,
      parameterSuiteVersion: envelope.parameterSuiteVersion,
      recordSchemaVersion: envelope.recordSchemaVersion,
      platformWrapperVersion: envelope.platformWrapperVersion,
      suiteId: envelope.suite.id,
      kdfParameters: { algorithm: envelope.suite.kdf.algorithm, memoryKiB: envelope.suite.kdf.minMemoryKiB, iterations: envelope.suite.kdf.iterations, parallelism: envelope.suite.kdf.parallelism },
      adapterBinding: 'browser',
      preview: envelope.preview,
      vaultGeneration: envelope.records.generation.active,
      recordGeneration: record.generation,
      recordPurpose: 'ordinary',
      producerId: record.producerId,
      producerVersion: record.producerVersion,
      signingAddress: `${envelope.preview.signingAddressPrefix}${envelope.preview.signingAddressSuffix}`,
      criticalExtensions: [],
    });
    const oldAadBytes = canonicalizeJsonBytes(oldAad);

    let dek: Uint8Array;
    try {
      const passwordKey = await this.suite.derivePasswordKey({
        passwordBytes: utf8Bytes(input.currentPassword),
        salt,
        memoryKiB: envelope.suite.kdf.minMemoryKiB,
        iterations: envelope.suite.kdf.iterations,
        parallelism: envelope.suite.kdf.parallelism,
        outputBytes: envelope.suite.kdf.outputBytes,
      });
      const kek = await this.suite.hkdf({ ikm: passwordKey, salt, info: utf8Bytes(CREDENTIAL_KEK_LABEL), outputBytes: 32 });
      dek = await this.suite.aes256GcmDecrypt({ key: kek, nonce: wrappingNonce, ciphertext: unwrapParts.ciphertext, tag: unwrapParts.tag, aad: oldAadBytes });
    } catch {
      return { code: 'WRONG_PASSWORD_OR_DAMAGED' };
    }

    // The record ciphertext and the DEK wrap both bind the generation in
    // AAD: a password change re-encrypts the record under the new generation
    // AND rewraps the DEK under the new KEK with that same generation.
    const nextGeneration = envelope.records.generation.active + 1;
    const nextPreview: VaultPreviewV1 = { ...envelope.preview };
    const nextAad = buildAadMetadata({
      envelopeFormatVersion: envelope.envelopeFormatVersion,
      parameterSuiteVersion: envelope.parameterSuiteVersion,
      recordSchemaVersion: envelope.recordSchemaVersion,
      platformWrapperVersion: envelope.platformWrapperVersion,
      suiteId: envelope.suite.id,
      kdfParameters: { algorithm: envelope.suite.kdf.algorithm, memoryKiB: envelope.suite.kdf.minMemoryKiB, iterations: envelope.suite.kdf.iterations, parallelism: envelope.suite.kdf.parallelism },
      adapterBinding: 'browser',
      preview: nextPreview,
      vaultGeneration: nextGeneration,
      recordGeneration: nextGeneration,
      recordPurpose: 'ordinary',
      producerId: record.producerId,
      producerVersion: record.producerVersion,
      signingAddress: `${nextPreview.signingAddressPrefix}${nextPreview.signingAddressSuffix}`,
      criticalExtensions: [],
    });
    const nextAadBytes = canonicalizeJsonBytes(nextAad);

    const newWrappingNonce = this.suite.randomBytes(12);
    const rewrap = await this.suite.aes256GcmEncrypt({ key: newKek, nonce: newWrappingNonce, plaintext: dek, aad: nextAadBytes });
    const rewrapParts = joinCipherAndTag(rewrap.ciphertext, rewrap.tag);
    const encryptionNonce = this.suite.randomBytes(12);
    const reencrypted = await this.suite.aes256GcmEncrypt({
      key: dek,
      nonce: encryptionNonce,
      plaintext: canonicalizeJsonBytes({ ...this.session.record, generation: nextGeneration }),
      aad: nextAadBytes,
    });
    const nextEnvelope = {
      ...envelope,
      preview: nextPreview,
      records: {
        ...envelope.records,
        generation: { active: nextGeneration },
        ordinary: {
          ...record,
          generation: nextGeneration,
          keyPackage: { wrappedDataKey: b64url(rewrapParts), wrappingNonce: b64url(newWrappingNonce) },
          ciphertext: b64url(joinCipherAndTag(reencrypted.ciphertext, reencrypted.tag)),
          encryptionNonce: b64url(encryptionNonce),
        },
      },
      extensions: { extensions: { [KDF_SALT_EXTENSION]: { salt: b64url(newSalt), hkdfSalt: b64url(newSalt) } }, criticalExtensions: [] },
    } as Record<string, unknown>;
    const serialized = canonicalizeJsonBytes(nextEnvelope);

    const commit = await this.journal.commit({ expectedGeneration: envelope.records.generation.active, candidateGeneration: nextGeneration, candidateBytes: serialized });
    if (!commit.ok) {
      // Rollback: previous verified generation remains authoritative.
      return { code: 'UNKNOWN_FAILURE', supportCode: this.randomId('sc-') };
    }
    this.phase = 'locked';
    this.wipeSecrets();
    return { code: 'OK' };
  }

  /**
   * Global resumable removal: tombstone → delete slots → clear sidecars →
   * verify absence → clear tombstone. Never reports success before absence.
   */
  async removeLocalUser(): Promise<SealedOutcome> {
    const persist = async (stage: RemovalStage): Promise<void> => {
      await this.storage.writeRecord('operationalSidecars', REMOVAL_TOMBSTONE_KEY, { inProgress: true, startedAt: this.nowMs(), stage });
    };

    await persist('revoking-session');
    this.wipeSecrets();

    await persist('persisting-tombstone');
    await persist('deleting-slots');
    for (const slotKey of ['slot-a', 'slot-b'] as const) {
      await this.storage.deleteRecord('vaultSlots', slotKey);
    }
    await this.storage.deleteRecord('vaultJournal', 'current');

    await persist('clearing-caches');
    for (const key of ['throttle', 'removalTombstone', 'lease', 'persistenceAck', 'epoch'] as const) {
      await this.storage.deleteRecord('operationalSidecars', key);
    }

    await persist('verifying-absence');
    const journalCheck = await this.storage.readRecord('vaultJournal', 'current');
    const slotCheck = await this.storage.readRecord('vaultSlots', 'slot-a');
    if (journalCheck.ok && journalCheck.value.record !== undefined) {
      return { code: 'UNKNOWN_FAILURE', supportCode: this.randomId('sc-') };
    }
    if (slotCheck.ok && slotCheck.value.record !== undefined) {
      return { code: 'UNKNOWN_FAILURE', supportCode: this.randomId('sc-') };
    }

    await this.storage.deleteRecord('operationalSidecars', REMOVAL_TOMBSTONE_KEY);
    this.phase = 'noLocalUser';
    return { code: 'OK' };
  }

  /** Startup inspection: resolve the deterministic startup surface. */
  async inspectStartup(): Promise<SealedOutcome & { readonly detail?: { readonly surface: 'verifiedAbsent' | 'lockedVault' | 'removalTombstone' | 'quarantine'; readonly safeIdentity?: SealedSafeIdentity; readonly reason?: string } }> {
    const tombstone = await this.storage.readRecord('operationalSidecars', REMOVAL_TOMBSTONE_KEY);
    if (tombstone.ok && tombstone.value.record !== undefined) {
      return { code: 'OK', detail: { surface: 'removalTombstone' } };
    }
    const state = await this.journal.readState();
    if (!state.ok) {
      return { code: 'CORRUPT_VAULT' };
    }
    if (state.value.activeGeneration === 0) {
      // Verified absence requires NO slot residue either.
      const slotA = await this.storage.readRecord('vaultSlots', 'slot-a');
      const slotB = await this.storage.readRecord('vaultSlots', 'slot-b');
      if ((slotA.ok && slotA.value.record !== undefined) || (slotB.ok && slotB.value.record !== undefined)) {
        return { code: 'OK', detail: { surface: 'quarantine', reason: 'incompleteRemoval' } };
      }
      return { code: 'OK', detail: { surface: 'verifiedAbsent' } };
    }
    const envelope = await this.readActiveEnvelope();
    if (envelope === null) {
      return { code: 'OK', detail: { surface: 'quarantine', reason: 'corrupt' } };
    }
    const safeIdentity: SealedSafeIdentity = {
      alias: envelope.preview.alias,
      abbreviatedSigningAddress: `${envelope.preview.signingAddressPrefix}…${envelope.preview.signingAddressSuffix}`,
    };
    return { code: 'OK', detail: { surface: 'lockedVault', safeIdentity } };
  }

  // ---------------------------------------------------------------------
  // Internal helpers
  // ---------------------------------------------------------------------

  private async readActiveEnvelope(): Promise<ParsedEnvelope | null> {
    const state = await this.journal.readState();
    if (!state.ok || state.value.activeGeneration === 0) {
      return null;
    }
    const slot = await this.storage.readRecord('vaultSlots', state.value.activeSlot);
    if (!slot.ok || slot.value.record === undefined) {
      return null;
    }
    const candidate = slot.value.record as { bytes?: unknown };
    if (typeof candidate !== 'object' || candidate === null) {
      return null;
    }
    // Normalize any byte view (same-realm, cross-realm, or structured-clone
    // artifacts) into a same-realm Uint8Array before parsing.
    const bytes = normalizeByteView(candidate.bytes);
    if (bytes === null) {
      return null;
    }
    try {
      return JSON.parse(utf8Text(bytes));
    } catch {
      return null;
    }
  }

  private async verifyEnvelopeBytes(bytes: Uint8Array, generation: number): Promise<boolean> {
    try {
      const parsed = JSON.parse(utf8Text(bytes)) as Record<string, unknown>;
      if (parsed.envelopeFormatVersion !== 1 || parsed.parameterSuiteVersion !== 1 || parsed.recordSchemaVersion !== 1) {
        return false;
      }
      const records = parsed.records as { generation?: { active?: unknown }; ordinary?: { generation?: unknown; keyPackage?: unknown; ciphertext?: unknown; encryptionNonce?: unknown } };
      if (records?.generation?.active !== generation || records?.ordinary?.generation !== generation) {
        return false;
      }
      const ordinary = records.ordinary;
      if (typeof ordinary?.ciphertext !== 'string' || typeof ordinary?.encryptionNonce !== 'string' || typeof ordinary?.keyPackage !== 'object') {
        return false;
      }
      const raw = JSON.stringify(parsed);
      if (raw.length > RECORD_BOUNDS.maxRecordBytes) {
        return false;
      }
      return true;
    } catch {
      return false;
    }
  }
}

/** Strict parse of the current-record plaintext (fail closed on any deviation). */
export function parseCurrentRecord(text: string, expectedGeneration: number): { readonly ok: true; readonly record: CurrentRecordPlaintext } | { readonly ok: false } {
  try {
    const value = JSON.parse(text) as Record<string, unknown>;
    if (value.schemaVersion !== 1) return { ok: false };
    if (value.generation !== expectedGeneration) return { ok: false };
    if (typeof value.alias !== 'string' || value.alias.length < 1 || value.alias.length > 64) return { ok: false };
    if (value.visibility !== 'private' && value.visibility !== 'public') return { ok: false };
    if (typeof value.producerId !== 'string' || typeof value.producerVersion !== 'string') return { ok: false };
    if (value.lifecycleStatus !== 'PendingRegistration' && value.lifecycleStatus !== 'Active') return { ok: false };
    if (value.protectionModeClass !== 'device-password') return { ok: false };
    if (value.transactionDigest !== null && typeof value.transactionDigest !== 'string') return { ok: false };
    const nb = value.networkBinding as Record<string, unknown> | undefined;
    const kb = value.keyBinding as Record<string, unknown> | undefined;
    if (typeof nb?.canonicalNetworkId !== 'string' || typeof nb.networkMagic !== 'number' || typeof nb.configurationId !== 'string') return { ok: false };
    if (typeof kb?.signingAddress !== 'string' || typeof kb.encryptionAddress !== 'string') return { ok: false };
    // Addresses are hex public keys (P-01 compressed 66, P-02 uncompressed 130).
    if (!/^[A-Za-z0-9]{40,130}$/.test(kb.signingAddress) || !/^[A-Za-z0-9]{40,130}$/.test(kb.encryptionAddress)) return { ok: false };
    const signingPrivateKey = value.signingPrivateKey;
    const encryptionPrivateKey = value.encryptionPrivateKey;
    if (typeof signingPrivateKey !== 'string' || !/^[0-9a-f]{64}$/.test(signingPrivateKey)) return { ok: false };
    if (typeof encryptionPrivateKey !== 'string' || !/^[0-9a-f]{64}$/.test(encryptionPrivateKey)) return { ok: false };
    // No-mnemonic rule: any recovery-shaped field fails parsing (AC-010-073+).
    const serialized = JSON.stringify(value);
    for (const marker of ['mnemonic', 'seed', 'phrase', 'recovery', 'wordlist', 'bip39']) {
      if (serialized.toLowerCase().includes(marker)) return { ok: false };
    }
    return {
      ok: true,
      record: {
        schemaVersion: 1,
        alias: value.alias,
        visibility: value.visibility,
        producerId: value.producerId,
        producerVersion: value.producerVersion,
        lifecycleStatus: value.lifecycleStatus,
        networkBinding: { canonicalNetworkId: nb.canonicalNetworkId, networkMagic: nb.networkMagic, configurationId: nb.configurationId },
        keyBinding: { signingAddress: kb.signingAddress, encryptionAddress: kb.encryptionAddress },
        signingPrivateKey,
        encryptionPrivateKey,
        protectionModeClass: 'device-password',
        generation: value.generation,
        transactionDigest: typeof value.transactionDigest === 'string' ? value.transactionDigest : null,
      },
    };
  } catch {
    return { ok: false };
  }
}

/** Export helpers for tests (never secret-bearing). */
export const sealedVaultTestExports = {
  cooldownSecondsFor,
  readThrottle,
  abbreviateSigningAddress,
  parseCurrentRecord,
  KDF_SALT_EXTENSION,
  VAULT_DB_NAME,
  CREDENTIAL_KEK_LABEL,
  bytesToHexLower,
  hexToBytesStrict,
};
