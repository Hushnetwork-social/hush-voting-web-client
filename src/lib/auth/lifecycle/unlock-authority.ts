/**
 * FEAT-010 business authority — protection-mode unlock, cooldown, and
 * non-destructive current migration (Task 3.3).
 *
 * Rules enforced here (normative: FeatureDescription "Returning Locked
 * Screen", "Unlock and Authentication Boundary", "Legacy Vault Migration";
 * AC-010-029…038, 079…082):
 * - unlock ONLY through the recorded protection mode; no alternative-mode
 *   attempt, no fallback (device-password ⇎ passwordless);
 * - exact global persistent per-vault cooldown sequence;
 * - malformed cooldown sidecars reconstruct a bounded safe state (no
 *   permanent DoS);
 * - supported old vaults authenticate ONLY into the migration gate;
 * - migration emits current concrete-key-only network-bound records under
 *   qualified protection with rollback retention until new-mode proof.
 *
 * Framework-neutral, secret-free (secrets flow through dedicated sinks).
 */
import {
  CURRENT_PROTECTION_MODE_CLASSES,
  validateCurrentRecord,
  type CurrentProtectionModeClass,
  type CurrentVaultRecordV1,
} from '../../vault-core/contracts/current-binding';
import type { DeploymentManifest } from '../../runtime/deployment';

/** Exact cooldown sequence: attempts 5..10 then cap (AC-010-037). */
export const COOLDOWN_SECONDS: readonly number[] = [5, 10, 20, 40, 80, 160, 300] as const;
export const MAX_COOLDOWN_SECONDS = 300 as const;

/** Unlock attempt verdicts. */
export type UnlockVerdict =
  | { readonly kind: 'proceed'; readonly cooldownSeconds: number }
  | { readonly kind: 'throttled'; readonly cooldownSeconds: number; readonly deadlineMs: number }
  | { readonly kind: 'modeMismatch' };

/**
 * Evaluate an unlock request against the recorded protection mode.
 * ANY request whose mode differs from the recorded mode fails closed — no
 * alternate-mode attempt or fallback exists (AC-010-030/031/032).
 */
export function evaluateUnlockRequest(
  recordedMode: CurrentProtectionModeClass,
  requestedMode: CurrentProtectionModeClass,
): { readonly ok: true } | { readonly ok: false; readonly code: 'MODE_MISMATCH' } {
  if (recordedMode !== requestedMode) {
    return { ok: false, code: 'MODE_MISMATCH' };
  }
  return { ok: true };
}

/**
 * Compute the cooldown after `failedAttempts` failures.
 * Attempts 1–4: Argon2id cost only (0 added seconds). 5 → 5 s, 6 → 10 s,
 * 7 → 20 s, 8 → 40 s, 9 → 80 s, 10 → 160 s, 11+ → 300 s max.
 */
export function cooldownAfterFailures(failedAttempts: number): number {
  if (!Number.isSafeInteger(failedAttempts) || failedAttempts < 0) {
    return 0;
  }
  if (failedAttempts <= 4) {
    return 0;
  }
  const index = failedAttempts - 5;
  return COOLDOWN_SECONDS[Math.min(index, COOLDOWN_SECONDS.length - 1)];
}

/**
 * Reconstruct a bounded cooldown state from an untrusted sidecar.
 * Malformed/extreme values never create permanent denial of service or
 * destructive resets (AC-010-037/038).
 */
export function reconstructCooldownSidecar(
  raw: unknown,
  nowMs: number,
): { readonly failedAttempts: number; readonly deadlineMs: number } {
  if (raw === null || typeof raw !== 'object') {
    return { failedAttempts: 0, deadlineMs: 0 };
  }
  const sidecar = raw as Record<string, unknown>;
  const failedAttempts =
    typeof sidecar.failedAttempts === 'number' && Number.isSafeInteger(sidecar.failedAttempts)
      ? Math.max(0, Math.min(sidecar.failedAttempts, 1000))
      : 0;
  let deadlineMs = typeof sidecar.deadlineMs === 'number' && Number.isFinite(sidecar.deadlineMs) ? sidecar.deadlineMs : 0;
  // Bounded horizon: any deadline beyond 300 s from now is clamped (max cooldown).
  const maxDeadline = nowMs + MAX_COOLDOWN_SECONDS * 1000;
  if (deadlineMs > maxDeadline) {
    deadlineMs = maxDeadline;
  }
  if (deadlineMs < 0) {
    deadlineMs = 0;
  }
  return { failedAttempts, deadlineMs };
}

/** Migration gate verdicts (AC-010-079…082). */
export type MigrationVerdict =
  | { readonly kind: 'requiresMigration'; readonly historicalVersion: string }
  | { readonly kind: 'alreadyCurrent' }
  | { readonly kind: 'unsupported' }
  | { readonly kind: 'corrupt' }
  | { readonly kind: 'wrongNetwork' };

/**
 * Classify a stored vault for startup/unlock. Supported historical versions
 * enter the migration gate and can NEVER authenticate directly; unknown/newer
 * versions and corrupt payloads fail closed non-destructively.
 */
export function classifyVaultForMigration(
  payload: unknown,
  historicalSupportedVersions: ReadonlySet<string>,
  manifest: DeploymentManifest,
): MigrationVerdict {
  if (payload === null || typeof payload !== 'object') {
    return { kind: 'corrupt' };
  }
  const record = payload as Record<string, unknown>;

  // Contradictory record: claims both a current numeric schema and a
  // historical string version → fail closed as corrupt (never guess).
  if (record.schemaVersion === 1 && typeof record.version === 'string') {
    return { kind: 'corrupt' };
  }

  // Current record family: validate and network-bind.
  if (record.schemaVersion === 1 && historicalSupportedVersions.has('current-v1')) {
    const validation = validateCurrentRecord(payload);
    if (!validation.ok) {
      return { kind: 'corrupt' };
    }
    const current = payload as unknown as CurrentVaultRecordV1;
    if (checkCurrentNetworkBinding(current, manifest) !== 'bound') {
      return { kind: 'wrongNetwork' };
    }
    return { kind: 'alreadyCurrent' };
  }

  const version = typeof record.version === 'string' ? record.version : typeof record.schemaVersion === 'string' ? record.schemaVersion : null;
  if (version === null || version.length === 0) {
    return { kind: 'corrupt' };
  }
  if (historicalSupportedVersions.has(version)) {
    return { kind: 'requiresMigration', historicalVersion: version };
  }
  return { kind: 'unsupported' };
}

function checkCurrentNetworkBinding(record: CurrentVaultRecordV1, manifest: DeploymentManifest): 'bound' | 'mismatch' {
  if (
    record.networkBinding.canonicalNetworkId === manifest.canonicalNetworkId &&
    record.networkBinding.networkMagic === manifest.networkMagic &&
    record.networkBinding.configurationId === manifest.configurationId
  ) {
    return 'bound';
  }
  return 'mismatch';
}

/** Qualified-protection re-qualification rule for migration output. */
export function isQualifiedProtectionMode(mode: CurrentProtectionModeClass): boolean {
  return CURRENT_PROTECTION_MODE_CLASSES.includes(mode);
}

/** Rollback-retirement rule: obsolete generation deleted only after new-mode proof. */
export type RollbackRetirementVerdict =
  | { readonly kind: 'retire' }
  | { readonly kind: 'retain'; readonly reason: 'newModeNotProven' | 'generationMismatch' };

export function shouldRetireObsoleteGeneration(
  newModeUnlocked: boolean,
  onlineVerified: boolean,
  expectedGeneration: number,
  activeGeneration: number,
): RollbackRetirementVerdict {
  if (!newModeUnlocked || !onlineVerified) {
    return { kind: 'retain', reason: 'newModeNotProven' };
  }
  if (activeGeneration !== expectedGeneration) {
    return { kind: 'retain', reason: 'generationMismatch' };
  }
  return { kind: 'retire' };
}
