/**
 * FEAT-010 additive vault contracts — startup inspection union and
 * deterministic precedence (Task 2.3).
 *
 * Startup inspection produces ONE closed result from all local identity
 * authorities. Precedence (normative: FeatureDescription "Startup and
 * Reconciliation", AC-010-024…026):
 *   1. active removal tombstone → resume verified removal;
 *   2. quarantine/corrupt/unsupported/contradictory → blocked remediation;
 *   3. staged FEAT-007 creation → resume creation confirmation;
 *   4. staged FEAT-008 recovery → "Finish restoring your identity";
 *   5. staged FEAT-009 recovery → "Finish restoring your identity" (no
 *      source-file/password dependency);
 *   6. valid provisioned vault → mode-specific locked screen;
 *   7. verified absence of every local authority → three first-run choices.
 *
 * Multiple competing active/staged identities are contradictory: fail closed,
 * never choose by timestamp, last-write-wins, or silent deletion.
 *
 * Framework-neutral, secret-free.
 */
import type { CurrentProtectionModeClass } from './current-binding';

/** Bounded local-authority/startup inspection deadline (AC-010-024). */
export const STARTUP_INSPECTION_TIMEOUT_MS = 5_000 as const;

/** Staged onboarding kinds observed at startup (FEAT-007/008/009 handoffs). */
export type StagedKind = 'createUser' | 'recoveryWords' | 'credentialFile';

/** Closed startup inspection result (exactly one per startup). */
export type StartupInspectionResult =
  | { readonly kind: 'removalTombstone' }
  | { readonly kind: 'quarantine'; readonly reason: 'corrupt' | 'unsupported' | 'contradictory' | 'incompleteRemoval' }
  | { readonly kind: 'staged'; readonly stagedKind: StagedKind }
  | { readonly kind: 'lockedVault'; readonly protectionModeClass: CurrentProtectionModeClass }
  | { readonly kind: 'verifiedAbsent' };

/**
 * Resolve the deterministic startup surface from the raw observations.
 * Rules:
 * - one dominant observation resolves to its precedence slot;
 * - MULTIPLE distinct active/staged identities → quarantine (contradictory);
 * - multiple same-kind stage records are tolerated only when identical in
 *   kind (resume target unchanged); distinct kinds or multiple locked vaults
 *   are contradictory;
 * - verified absence requires NO active/staged/tombstone/quarantine signal
 *   at all.
 */
export function resolveStartupPrecedence(
  observations: readonly StartupInspectionResult[],
): StartupInspectionResult {
  if (observations.length === 0) {
    return { kind: 'verifiedAbsent' };
  }

  const has = (kind: StartupInspectionResult['kind']): boolean => observations.some((o) => o.kind === kind);

  if (has('removalTombstone')) {
    // A tombstone outranks everything; multiple tombstones are contradictory.
    return observations.filter((o) => o.kind === 'removalTombstone').length === 1
      ? { kind: 'removalTombstone' }
      : { kind: 'quarantine', reason: 'contradictory' };
  }
  if (has('quarantine')) {
    const quarantines = observations.filter((o): o is Extract<StartupInspectionResult, { kind: 'quarantine' }> => o.kind === 'quarantine');
    return quarantines.length === 1 ? quarantines[0] : { kind: 'quarantine', reason: 'contradictory' };
  }

  const staged = observations.filter((o): o is Extract<StartupInspectionResult, { kind: 'staged' }> => o.kind === 'staged');
  const locked = observations.filter((o): o is Extract<StartupInspectionResult, { kind: 'lockedVault' }> => o.kind === 'lockedVault');

  // Contradiction: multiple distinct staged identities, multiple locked
  // vaults, or a stage PLUS an active vault are competing identities.
  if (staged.length > 1 && new Set(staged.map((o) => o.stagedKind)).size > 1) {
    return { kind: 'quarantine', reason: 'contradictory' };
  }
  if (locked.length > 1) {
    return { kind: 'quarantine', reason: 'contradictory' };
  }
  if (staged.length >= 1 && locked.length >= 1) {
    return { kind: 'quarantine', reason: 'contradictory' };
  }

  // Identical duplicate stages collapse to the single resume target.
  if (staged.length >= 1) {
    return { kind: 'staged', stagedKind: staged[0].stagedKind };
  }
  if (locked.length === 1) {
    return locked[0];
  }
  // Nothing active/staged/tombstoned → verified absence (first-run).
  return { kind: 'verifiedAbsent' };
}

/** Convenience: does this result require a blocked remediation surface? */
export function isQuarantine(result: StartupInspectionResult): boolean {
  return result.kind === 'quarantine';
}
