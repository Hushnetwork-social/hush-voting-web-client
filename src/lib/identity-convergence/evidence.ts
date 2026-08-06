/**
 * FEAT-011 Task 2.7 — stable evidence/shared-ID schemas and release-state
 * ledger contract (framework-neutral).
 *
 * Mirrors `evidence-admission.md` and `acceptance-traceability-ledger.md`
 * §1/§6 as typed code so the Phase 7 validator compiles against the frozen
 * vocabulary: evidence classes, the immutable evidence record (no secrets, no
 * human-attestation fields, no export fields), Manual TestPack IDs, and the
 * `PASS|FAIL|NOT_SUPPLIED` external evidence states.
 */

/** Evidence classes (ledger §1). */
export type EvidenceClass =
  | 'EXECUTABLE_CLIENT'
  | 'EXECUTABLE_ROOT'
  | 'TWIN'
  | 'EXECUTABLE_NATIVE'
  | 'EXECUTABLE_STATIC'
  | 'MANUAL'
  | 'EXTERNAL';

/** External evidence states — the only legal values for MANUAL/EXTERNAL. */
export type ExternalEvidenceState = 'PASS' | 'FAIL' | 'NOT_SUPPLIED';

/** Manual TestPack obligation IDs (frozen; tasks 7.7/7.8). */
export type ManualTestPackId = 'MT-QUAL-UBUNTU-011-001' | 'MT-QUAL-ANDROID-011-001';

/** External evidence IDs (frozen; evidence-admission §5). */
export type ExternalEvidenceId =
  | 'EXT-CORPUS-011-001'
  | 'EXT-SECURITY-011-001'
  | 'EXT-MIGRATION-011-001';

/** Immutable evidence record — every field required; no secret-bearing fields exist. */
export interface EvidenceRecord {
  readonly stableId: string;
  readonly evidenceClass: EvidenceClass;
  readonly revision: string;
  readonly command: string;
  readonly exitCode: number;
  readonly counts: string;
  readonly warningsErrors: string;
  readonly digests: string;
  readonly capturePolicy: 'disabled' | 'enabled';
  readonly targetClass: string;
  readonly cleanupProof: string;
  readonly timestamp: string;
}

/** Never-recorded values (evidence-admission §1) — enforced by scan. */
export const NEVER_RECORDED_PATTERN =
  /password|mnemonic|private ?key|\.dat|transaction.?json|signature|full ?address|device.?id|endpoint.?credential|BEGIN .*PRIVATE/i;

/** Validate an evidence record (returns data, never throws). */
export function validateEvidenceRecord(record: EvidenceRecord): { readonly ok: true } | { readonly ok: false; readonly reason: string } {
  if (record.exitCode !== 0) {
    return { ok: false, reason: 'non-zero exit code' };
  }
  if (record.stableId.trim().length === 0 || record.revision.trim().length === 0 || record.command.trim().length === 0) {
    return { ok: false, reason: 'missing stableId/revision/command' };
  }
  if (record.capturePolicy === 'disabled' && record.evidenceClass === 'EXECUTABLE_ROOT' && !record.cleanupProof) {
    return { ok: false, reason: 'missing cleanup proof' };
  }
  const json = JSON.stringify(record);
  if (NEVER_RECORDED_PATTERN.test(json)) {
    return { ok: false, reason: 'secret-bearing value in evidence record' };
  }
  return { ok: true };
}

/** Manual/external evidence row — the ONLY allowed fields; statuses are strict. */
export interface ManualExternalEvidenceRow {
  readonly id: ManualTestPackId | ExternalEvidenceId;
  readonly evidenceClass: 'MANUAL' | 'EXTERNAL';
  readonly state: ExternalEvidenceState;
  readonly owner: string;
  readonly releaseImpact: string;
}

/** Release-state ledger contract — implementation vs release stay independent. */
export interface ReleaseStateLedger {
  readonly implementation: 'COMPLETED' | 'IN_PROGRESS' | 'NOT_STARTED';
  readonly releaseReadiness: 'BLOCKED_BY_EXTERNAL_DEPENDENCIES' | 'READY' | 'NOT_READY';
  readonly rows: ReadonlyArray<ManualExternalEvidenceRow>;
}

/** Ledger admission rule: release readiness is READY only when every row is PASS. */
export function releaseReadinessOf(rows: ReadonlyArray<ManualExternalEvidenceRow>): ReleaseStateLedger['releaseReadiness'] {
  if (rows.length === 0) {
    return 'NOT_READY';
  }
  return rows.every((r) => r.state === 'PASS') ? 'READY' : 'BLOCKED_BY_EXTERNAL_DEPENDENCIES';
}
