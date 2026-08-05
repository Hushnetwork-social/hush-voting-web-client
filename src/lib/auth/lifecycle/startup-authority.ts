/**
 * FEAT-010 business authority — startup, staged reconciliation, root
 * verification, and same-key reset (Task 3.1).
 *
 * Framework-neutral kernel consumed by the sole FEAT-002 auth authority:
 * - bounded startup inspection with exact precedence (5 s deadline, Retry);
 * - child completion → opaque verification-only custody (never authenticated);
 * - one fresh no-cache exact both-key verification gates protected access;
 * - stale epoch/operation results are rejected and can never restore access;
 * - same-network authoritative absence offers EXPLICIT same-key recreation
 *   only; different-network absence can never enter this path.
 *
 * Normative: FeatureDescription "Startup and Reconciliation", "Unlock and
 * Authentication Boundary", AC-010-013/024…028/035/039…043/050.
 */
import {
  resolveStartupPrecedence,
  STARTUP_INSPECTION_TIMEOUT_MS,
  type StartupInspectionResult,
} from '../../vault-core/contracts/startup-inspection';
import {
  checkNetworkBinding,
  CURRENT_PROTECTION_MODE_CLASSES,
  type CurrentVaultRecordV1,
} from '../../vault-core/contracts/current-binding';
import type { DeploymentManifest } from '../../runtime/deployment';
import type { VerificationOnlyCompletion } from '../child-flow';

/** Opaque epoch for stale-result rejection. */
export type AuthorityEpoch = number;

/** Safe public binding pair used for exact verification. */
export interface VerificationBinding {
  readonly signingAddress: string;
  readonly encryptionAddress: string;
}

/** Typed root-verification outcomes (AC-010-035/039/040/041/042). */
export type RootVerificationOutcome =
  | { readonly kind: 'exactExisting' }
  | { readonly kind: 'authoritativeAbsentSameNetwork' }
  | { readonly kind: 'mismatch' }
  | { readonly kind: 'transportFailure' }
  | { readonly kind: 'stale' };

/** Verification port (injected; implemented by Phase 6 transports). */
export interface RootVerificationPort {
  /** One fresh no-cache exact lookup; never replayed. */
  verifyExact(binding: VerificationBinding, epoch: AuthorityEpoch): Promise<RootVerificationOutcome>;
}

/** Startup inspection ports (injected). */
export interface StartupInspectionPorts {
  /** Collect raw observations from every local identity authority (≤5 s). */
  inspect(): Promise<StartupInspectionResult[]>;
  /** Bounded inspection deadline in ms. */
  deadlineMs(): number;
}

/** Custody after local unlock / child completion — never Authenticated. */
export interface VerificationOnlyCustody {
  readonly epoch: AuthorityEpoch;
  /** Opaque verification-only token (Phase 2 contract). */
  readonly capability: string;
  readonly binding: VerificationBinding;
  /** Monotonic custody id for retry-without-reunlock. */
  readonly custodyId: number;
}

/** Startup verdict returned to the auth machine. */
export type StartupVerdict =
  | { readonly kind: 'inspection'; readonly result: StartupInspectionResult }
  | { readonly kind: 'inspectionTimedOut' }
  | { readonly kind: 'inspectionFailed' };

/** Strict runtime validation of the closed inspection union (fail closed). */
const VALID_INSPECTION_KINDS = ['removalTombstone', 'quarantine', 'staged', 'lockedVault', 'verifiedAbsent'] as const;
const VALID_QUARANTINE_REASONS = ['corrupt', 'unsupported', 'contradictory', 'incompleteRemoval'] as const;
const VALID_STAGED_KINDS = ['createUser', 'recoveryWords', 'credentialFile'] as const;

function isValidObservation(value: unknown): value is StartupInspectionResult {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const observation = value as Record<string, unknown>;
  if (!VALID_INSPECTION_KINDS.includes(observation.kind as (typeof VALID_INSPECTION_KINDS)[number])) return false;
  if (observation.kind === 'quarantine') {
    return VALID_QUARANTINE_REASONS.includes(observation.reason as (typeof VALID_QUARANTINE_REASONS)[number]);
  }
  if (observation.kind === 'staged') {
    return VALID_STAGED_KINDS.includes(observation.stagedKind as (typeof VALID_STAGED_KINDS)[number]);
  }
  if (observation.kind === 'lockedVault') {
    return CURRENT_PROTECTION_MODE_CLASSES.includes(observation.protectionModeClass as (typeof CURRENT_PROTECTION_MODE_CLASSES)[number]);
  }
  return true;
}

/**
 * Run bounded startup inspection with the exact precedence resolver.
 * Timeout/failure → typed retryable verdict; never a blank screen or
 * indefinite spinner (AC-010-024). Unknown observation kinds fail closed
 * instead of silently resolving to first-run (AC-010-026).
 */
export async function runStartupInspection(ports: StartupInspectionPorts): Promise<StartupVerdict> {
  const deadline = ports.deadlineMs() > 0 ? ports.deadlineMs() : STARTUP_INSPECTION_TIMEOUT_MS;
  let observations: StartupInspectionResult[];
  try {
    observations = await Promise.race([
      ports.inspect(),
      new Promise<never>((_, reject) => {
        setTimeout(() => reject(new Error('inspection-timeout')), deadline);
      }),
    ]);
  } catch {
    return { kind: 'inspectionTimedOut' };
  }
  if (!Array.isArray(observations) || observations.some((o) => !isValidObservation(o))) {
    return { kind: 'inspectionFailed' };
  }
  return { kind: 'inspection', result: resolveStartupPrecedence(observations) };
}

/** Boundary check before any child completion is accepted (AC-010-013). */
export function acceptChildCompletion(
  completion: VerificationOnlyCompletion | null | undefined,
  epoch: AuthorityEpoch,
  custodyCounter: number,
): { readonly ok: true; readonly custody: VerificationOnlyCustody } | { readonly ok: false } {
  if (completion === null || completion === undefined) {
    return { ok: false };
  }
  const binding: VerificationBinding = {
    signingAddress: completion.binding.signingAddress,
    encryptionAddress: completion.binding.encryptionAddress,
  };
  return {
    ok: true,
    custody: {
      epoch,
      capability: completion.capability,
      binding,
      custodyId: custodyCounter + 1,
    },
  };
}

/**
 * Perform one fresh exact root verification. Stale epochs are rejected and
 * never restore access (AC-010-053). Transport failure preserves the bounded
 * verification-only custody and offers Retry WITHOUT another local unlock
 * while the custody remains valid (AC-010-039).
 */
export async function performRootVerification(
  port: RootVerificationPort,
  custody: VerificationOnlyCustody,
  currentEpoch: AuthorityEpoch,
): Promise<RootVerificationOutcome> {
  if (currentEpoch !== custody.epoch) {
    return { kind: 'stale' };
  }
  return port.verifyExact(custody.binding, currentEpoch);
}

/** Same-key reset preconditions (AC-010-040/041/043). */
export type SameKeyResetVerdict =
  | { readonly kind: 'permitted' }
  | { readonly kind: 'wrongNetwork' }
  | { readonly kind: 'notAuthoritativeAbsence' }
  | { readonly kind: 'stale' };

/**
 * Gate explicit same-key profile recreation. Permitted ONLY on authoritative
 * absence on the SAME bound network; different-network absence never enters
 * this path (AC-010-043). Reuses the FEAT-007 exact-key creation lifecycle.
 */
export function prepareSameKeyRecreation(
  record: CurrentVaultRecordV1,
  manifest: DeploymentManifest,
  verification: RootVerificationOutcome,
  currentEpoch: AuthorityEpoch,
  custodyEpoch: AuthorityEpoch,
): SameKeyResetVerdict {
  if (currentEpoch !== custodyEpoch) {
    return { kind: 'stale' };
  }
  if (verification.kind !== 'authoritativeAbsentSameNetwork') {
    return { kind: 'notAuthoritativeAbsence' };
  }
  if (checkNetworkBinding(record, manifest).kind !== 'bound') {
    return { kind: 'wrongNetwork' };
  }
  return { kind: 'permitted' };
}
