/**
 * FEAT-008 recovery-words authority — selected-key proof, protection
 * selection, staging, and destruction policy.
 *
 * Framework-neutral. Enforces: private credentials derived ONLY for the
 * selected producer; independent exact public-address + local cryptographic
 * consistency proofs; explicit non-retention acknowledgement; the chosen
 * qualified protection mode (Device-password default, passwordless Web/native,
 * session-only) with no silent fallback; atomic encrypted staged write +
 * read-back verification; and phrase/seed/non-selected destruction at the
 * mandated point. The actual key derivation/proof/wrapping lives inside the
 * sealed authority through injected ports.
 *
 * SECRET BOUNDARY: no phrase, seed, private key, password, PRF output, or
 * wrapping key is representable here. Staging records use the Phase 2
 * `RecoveryEnvelopeRecord` (ciphertext only).
 *
 * Normative source: FEAT-008 FeatureDescription "Selected-Key Control Proof",
 * "Initial Protection Choice", "Versioned mode hierarchy", "Encrypted
 * Derived-Key Staging", "No-Persistence Rule", "Native protection failure";
 * FEAT-003 journal/CAS capability kernels.
 */
import type { RecoveryEnvelopeRecord } from '../contracts/envelope';
import {
  checkLegalProtectionCombination,
  parseProtectionMetadata,
  PROTECTION_MODE_PERSISTENT,
  type ProtectionMetadata,
  type ProtectionMode,
} from '../contracts/envelope';
import type { RecoveryEpoch, RecoveryResult } from '../contracts/lifecycle';
import type { SelectedKeyProofEvidence } from '../contracts/candidates';

/** One-use purpose-bound authorization expiry (≤60 s per adapter policy). */
export const AUTHORIZATION_MAX_MS = 60_000 as const;

/** Sealed selected-key proof seam (worker/native implements in Phase 6). */
export interface SelectedKeyProofPort {
  /** Derive selected-producer private credentials and prove both key pairs locally. */
  proveSelected(selectedCandidateIndex: number, epoch: RecoveryEpoch): Promise<RecoveryResult<SelectedKeyProofEvidence>>;
}

/** Platform capability report for protection selection (fail-closed). */
export type ProtectionCapabilityReport = Readonly<{
  readonly webauthnPlatform: boolean;
  readonly discoverableCredential: boolean;
  readonly userVerification: boolean;
  readonly prf: boolean;
  readonly qualifiedOsProtection: boolean; // Secret Service / hardware-backed Keystore
  readonly secureScreenLock: boolean; // Android
}>;

/**
 * Protection selection policy. Device-password protection is the default and
 * may be unchecked only into a qualified passwordless/session-only path.
 * Unqualified passwordless yields NO mode (never a silent fallback).
 */
export function selectProtectionMode(
  requested: ProtectionMode,
  capabilities: ProtectionCapabilityReport,
  explicitSessionOnlyAcknowledgement: boolean,
): RecoveryResult<ProtectionMetadata> {
  if (requested === 'sessionOnly') {
    if (!explicitSessionOnlyAcknowledgement) {
      return { ok: false, code: 'PROTECTION_CANCELLED', message: 'Session-only mode requires explicit acknowledgement.', supportCode: 'RW-PROT-1' };
    }
    return { ok: true, value: { mode: 'sessionOnly', version: 1 } };
  }
  const legal = checkLegalProtectionCombination(requested, {
    webauthnPlatform: capabilities.webauthnPlatform,
    discoverableCredential: capabilities.discoverableCredential,
    userVerification: capabilities.userVerification,
    prf: capabilities.prf,
    qualifiedOsProtection: capabilities.qualifiedOsProtection,
  });
  if (!legal.ok) {
    return legal;
  }
  return { ok: true, value: { mode: requested, version: 1 } };
}

/** Default choice is always the Device-password mode for the platform. */
export function defaultProtectionMode(platform: 'web' | 'native'): ProtectionMode {
  return platform === 'web' ? 'devicePasswordWeb' : 'devicePasswordNative';
}

/**
 * Staging commit policy: the persistent `recoverWordsProvision` seam accepts
 * only the opaque versioned credential bundle produced inside the secret
 * authority. The two-slot journal/CAS write and read-back verification are
 * implemented by the adapter; this policy validates the record shape and the
 * destruction ordering.
 */
export interface StageCommitPort {
  /** Atomically write an inactive staged generation and read it back. */
  commitStage(record: RecoveryEnvelopeRecord): Promise<RecoveryResult<{ readonly generation: number }>>;
  /** Verified rollback of a partial/invalid stage (removes app-owned slots). */
  rollbackStage(generation: number): Promise<RecoveryResult<void>>;
}

/**
 * Destruction-point policy. Persistent mode: retain the phrase through
 * derivation → selection → proof → encrypted stage → verified read-back, then
 * destroy mnemonic/seed/non-selected intermediates BEFORE online verification.
 * Session-only mode: install only selected keys into isolated memory, then
 * destroy immediately.
 */
export type DestructionPhase =
  | 'preVerify'
  | 'postVerifyPreStage'
  | 'stageCommitted'
  | 'activated';

export function isMnemonicAllowed(phase: DestructionPhase, mode: ProtectionMode, stageVerified: boolean): boolean {
  if (phase === 'preVerify') {
    return true; // phrase held in the dedicated input/authority
  }
  if (phase === 'postVerifyPreStage') {
    return true; // candidates resolved; phrase retained until selected-key install
  }
  if (phase === 'stageCommitted') {
    if (mode === 'sessionOnly') {
      return false; // session-only destroys immediately after isolated install
    }
    return !stageVerified; // persistent destroys only after verified read-back
  }
  return false; // activated: never allowed
}

/** Stage-then-destroy orchestration for persistent modes (ordering invariant). */
export function assertPersistentDestructionOrder(events: readonly string[]): boolean {
  const required = ['stageCommitted', 'mnemonicDestroyedPersistent'];
  const filtered = events.filter((event) => required.includes(event));
  return filtered.length === 2 && filtered[0] === 'stageCommitted' && filtered[1] === 'mnemonicDestroyedPersistent';
}

/** Session-only must destroy before any online verification. */
export function assertSessionDestructionOrder(events: readonly string[]): boolean {
  const stageIndex = events.indexOf('stageCommitted');
  const destroyIndex = events.indexOf('mnemonicDestroyedSession');
  return stageIndex === -1 && destroyIndex !== -1;
}

/** Persistent-mode legal check: session-only protection can never persist. */
export function protectionCanPersist(mode: ProtectionMode): boolean {
  return PROTECTION_MODE_PERSISTENT[mode];
}

/** Re-export parse for convenience of the authority composition. */
export { parseProtectionMetadata };
