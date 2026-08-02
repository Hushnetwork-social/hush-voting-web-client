/**
 * FEAT-003 vault-core contracts — opaque validated credential bundle and adapter ports.
 *
 * Vault provisioning accepts only an opaque, versioned `ValidatedCredentialBundle`
 * created inside an approved secret-owning boundary from FEAT-001 results. It never
 * accepts unclassified raw keys from React, XState, routing, or arbitrary callers.
 *
 * Adapter ports own: production CSPRNG/cryptography, encrypted storage and transactions,
 * OS key stores and secure-screen/device capability checks, secret-memory containers and
 * best-effort zeroization, worker/process isolation, and platform resource reporting.
 * Production and deterministic test ports are distinguishable and fail closed outside
 * test builds.
 *
 * Normative source: FEAT-003 FeatureDescription "Credential admission", "Boundary".
 */
import type { VaultResult } from './results';

/** Opaque validated credential bundle produced by the secret-owning boundary (FEAT-001). */
export interface ValidatedCredentialBundle {
  /** Opaque by contract: no raw key, mnemonic, or plaintext credential field exists here. */
  readonly __bundle: unique symbol;
  readonly producerId: string;
  readonly producerVersion: string;
  /** FEAT-001 pin binding. */
  readonly featiContractVersion: '1.0.0';
}

/** Safe public admission evidence the bundle exposes (never secret-bearing). */
export interface BundleAdmissionEvidence {
  readonly producerId: string;
  readonly producerVersion: string;
  readonly exactKeyConsistency: boolean;
  readonly mnemonicConsistency: 'none' | 'verified';
  readonly signingAddressPrefix: string;
  readonly signingAddressSuffix: string;
  readonly lifecycleStatus: 'PendingRegistration' | 'Active';
}

/**
 * Adapter ports (implemented by FEAT-004/005/006). The core contracts depend only on
 * these narrow ports; production randomness/crypto/storage/OS-protection live behind them.
 */
export interface VaultAdapterPorts {
  readonly randomness: RandomnessPort;
  readonly crypto: CryptoPort;
  readonly storage: StoragePort;
  readonly platformProtection: PlatformProtectionPort;
  readonly clock: ClockPort;
}

/** Production randomness is adapter-owned; no caller-supplied salts/keys/nonces. */
export interface RandomnessPort {
  readonly randomBytes: (length: number) => Uint8Array;
}

/** Closed deterministic suite operations for corpus generation/validation (test-only). */
export interface SuiteCryptoOperations {
  readonly derivePasswordKey: (params: {
    readonly passwordBytes: Uint8Array;
    readonly salt: Uint8Array;
    readonly memoryKiB: number;
    readonly iterations: number;
    readonly parallelism: number;
    readonly outputBytes: number;
  }) => Promise<Uint8Array>;
  readonly hkdf: (params: {
    readonly ikm: Uint8Array;
    readonly salt: Uint8Array;
    readonly info: Uint8Array;
    readonly outputBytes: number;
  }) => Promise<Uint8Array>;
  readonly aes256GcmEncrypt: (params: {
    readonly key: Uint8Array;
    readonly nonce: Uint8Array;
    readonly plaintext: Uint8Array;
    readonly aad: Uint8Array;
  }) => Promise<{ readonly ciphertext: Uint8Array; readonly tag: Uint8Array }>;
  readonly aes256GcmDecrypt: (params: {
    readonly key: Uint8Array;
    readonly nonce: Uint8Array;
    readonly ciphertext: Uint8Array;
    readonly tag: Uint8Array;
    readonly aad: Uint8Array;
  }) => Promise<Uint8Array>;
}

/** Cryptography port: production crypto behind the adapter boundary. */
export interface CryptoPort {
  readonly suite: SuiteCryptoOperations;
}

/** Transactional two-slot storage port (adapter-owned). */
export interface StoragePort {
  readonly readEnvelope: () => Promise<VaultResult<{ readonly envelopeBytes: Uint8Array }>>;
  readonly commitEnvelope: (params: {
    readonly expectedActiveGeneration: number;
    readonly inactiveSlot: Uint8Array;
    readonly activeSlot: Uint8Array;
  }) => Promise<VaultResult<{ readonly activeGeneration: number }>>;
  readonly readSidecar: () => Promise<VaultResult<{ readonly sidecarBytes: Uint8Array }>>;
  readonly writeSidecar: (sidecarBytes: Uint8Array) => Promise<VaultResult<{ readonly ok: true }>>;
  readonly clearAll: () => Promise<VaultResult<{ readonly ok: true }>>;
}

/** OS/browser platform protection port (native wrappers, secure screens, availability). */
export interface PlatformProtectionPort {
  readonly availability: () => Promise<VaultResult<{ readonly available: boolean; readonly backedByOs: boolean }>>;
  readonly wrap: (packageBytes: Uint8Array) => Promise<VaultResult<{ readonly wrapped: Uint8Array }>>;
  readonly unwrap: (wrapped: Uint8Array) => Promise<VaultResult<{ readonly packageBytes: Uint8Array }>>;
  readonly invalidate: () => Promise<VaultResult<{ readonly ok: true }>>;
}

/** Deterministic clock port (monotonic + bounded wall-clock evidence). */
export interface ClockPort {
  readonly monotonicMs: () => number;
  readonly wallClockMs: () => number;
}

/** Narrow deterministic test ports (fail closed outside test builds). */
export interface DeterministicTestPorts {
  readonly randomness: RandomnessPort;
  readonly crypto: SuiteCryptoOperations;
}
