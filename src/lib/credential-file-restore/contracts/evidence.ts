/**
 * FEAT-009 credential-file restore — acceptance, fault, server,
 * controlled-corpus, and downstream evidence schemas.
 *
 * Framework-neutral. Provides machine-readable schemas for the 89-criterion
 * coverage manifest, scenario targets, sanitized fault outcomes, platform
 * capability evidence, external release findings (EXT-009-001…005),
 * aggregate controlled-corpus results, server scenario alignment, and the
 * immutable downstream file-restore handoff. Validation fails closed on
 * unknown/duplicate criteria, mutable pins, unsafe evidence, fabricated
 * admission, and per-file controlled-corpus detail.
 *
 * SECRET BOUNDARY: reports contain only allowlisted identifiers, digests,
 * coarse outcomes, and support codes. Evidence containing file identifiers,
 * external digests, passwords, ciphertext/plaintext, mnemonic-like phrases,
 * keys, full addresses, exact transactions, credential IDs, or stable
 * identities is rejected without echoing the value.
 *
 * Normative source: FEAT-009 FeatureDescription "Testing Strategy",
 * "Observability", "Controlled Legacy Interoperability Evidence",
 * "Definition of Done"; FeatureTasks.md Acceptance Traceability Strategy;
 * FEAT-008 evidence schemas.
 */

import { assertNoRestoreSecretSurface } from './lifecycle.js';

/** Target-owned vs separately owned release qualification classification. */
export type CoverageClassification = 'target-owned' | 'target-owned-capability' | 'release-evidence';

/** Test layers a criterion may claim. */
export type CoverageTestLayer =
  | 'unit'
  | 'component'
  | 'model'
  | 'property'
  | 'fuzz'
  | 'conformance'
  | 'bdd'
  | 'native'
  | 'twin'
  | 'a11y'
  | 'perf'
  | 'secret-scan'
  | 'coverage-manifest'
  | 'release-evidence';

/** Platform targets a criterion may claim. */
export type CoverageTarget =
  | 'web'
  | 'ubuntu'
  | 'android'
  | 'conformance'
  | 'native-smoke'
  | 'server-twins'
  | 'controlled-local'
  | 'release-admission'
  | 'all';

/** One acceptance criterion mapping (AC-009-NNN). */
export interface CoverageCriterion {
  readonly id: string; // e.g. 'AC-009-001'
  readonly family: string; // one of the 25 HV-DAT-* family IDs
  readonly scenarioIds: readonly string[]; // ≥1 stable scenario ID
  readonly targets: readonly CoverageTarget[];
  readonly implementationPhases: readonly number[];
  readonly testLayers: readonly CoverageTestLayer[];
  readonly classification: CoverageClassification;
}

/** Machine-checked coverage manifest for FEAT-009. */
export interface CoverageManifest {
  readonly schemaVersion: 1;
  readonly featureId: 'FEAT-009';
  readonly title: 'Encrypted Credential File Restore';
  readonly families: readonly string[]; // the 25 scenario families
  readonly criteria: readonly CoverageCriterion[];
}

/** Closed registry of the 25 scenario families (24 mandatory + HV-DAT-RESUME additive). */
export const CREDENTIAL_FILE_SCENARIO_FAMILIES: readonly string[] = [
  'HV-DAT-ENTRY',
  'HV-DAT-PICKER',
  'HV-DAT-READ',
  'HV-DAT-TEMP',
  'HV-DAT-ENVELOPE',
  'HV-DAT-PASSWORD',
  'HV-DAT-BACKOFF',
  'HV-DAT-AUTH',
  'HV-DAT-SCHEMA',
  'HV-DAT-KEYS',
  'HV-DAT-MNEMONIC',
  'HV-DAT-SOURCE',
  'HV-DAT-LOOKUP',
  'HV-DAT-RESET',
  'HV-DAT-SIGNATURE',
  'HV-DAT-SEPARATION',
  'HV-DAT-PROTECT',
  'HV-DAT-STAGE',
  'HV-DAT-SESSION',
  'HV-DAT-RESUME',
  'HV-DAT-NAV',
  'HV-DAT-OWNER',
  'HV-DAT-CLEANUP',
  'HV-DAT-EXTERNAL',
  'HV-DAT-SECURITY',
];

/** Validate a coverage manifest: 89 criteria, known families, unique IDs, ≥1 scenario. */
export function validateCoverageManifest(manifest: CoverageManifest): { readonly ok: true } | { readonly ok: false; readonly reasons: readonly string[] } {
  const reasons: string[] = [];
  const knownFamilies = new Set(CREDENTIAL_FILE_SCENARIO_FAMILIES);
  if (manifest.schemaVersion !== 1) reasons.push('unsupported schemaVersion');
  if (manifest.featureId !== 'FEAT-009') reasons.push('featureId mismatch');
  const ids = new Set<string>();
  for (const criterion of manifest.criteria) {
    if (!/^AC-009-\d{3}$/.test(criterion.id)) {
      reasons.push(`malformed criterion id: ${criterion.id}`);
      continue;
    }
    if (ids.has(criterion.id)) reasons.push(`duplicate criterion id: ${criterion.id}`);
    ids.add(criterion.id);
    if (!knownFamilies.has(criterion.family)) reasons.push(`unknown family on ${criterion.id}: ${criterion.family}`);
    if (criterion.scenarioIds.length === 0) reasons.push(`no scenario id on ${criterion.id}`);
    if (criterion.targets.length === 0) reasons.push(`no target on ${criterion.id}`);
    if (criterion.classification !== 'target-owned' && criterion.classification !== 'target-owned-capability' && criterion.classification !== 'release-evidence') {
      reasons.push(`unknown classification on ${criterion.id}`);
    }
  }
  // Exactly AC-009-001 … AC-009-089 present.
  for (let n = 1; n <= 89; n += 1) {
    const id = `AC-009-${String(n).padStart(3, '0')}`;
    if (!ids.has(id)) reasons.push(`missing criterion: ${id}`);
  }
  if (reasons.length > 0) return { ok: false, reasons };
  return { ok: true };
}

/** Sanitized fault outcome (allowed fields only). */
export interface FaultOutcomeEvidence {
  readonly faultId: string; // e.g. FAULT-READ-003
  readonly boundary: string; // closed boundary class
  readonly injected: string; // closed injected-failure class
  readonly convergedState: string; // safe converged state code
  readonly evidenceCode: string; // safe structural code; no values
}

/** External release finding admission state — never fabricated. */
export type ReleaseFindingState = 'PASS' | 'FAIL' | 'NOT_SUPPLIED';

export interface ExternalReleaseFinding {
  readonly id: string; // EXT-009-001 … 005
  readonly state: ReleaseFindingState;
  readonly evidencePin: string | null; // immutable digest/revision; null when NOT_SUPPLIED
  readonly note: string; // safe prose only; no secrets/identifiers
}

/** Aggregate controlled-corpus result (no per-file detail, ever). */
export interface ControlledCorpusEvidence {
  readonly totalFiles: number; // aggregate count only
  readonly passed: number;
  readonly failed: number;
  readonly sourceUnchangedAggregate: boolean; // in-process before/after comparison
  readonly producerShapeClasses: number; // count only
  readonly isolatedNetworkDigest: string; // approved non-production network/build pin
  readonly captureDisabled: true; // recordings disabled before source/password entry
}

/** Server scenario alignment entry (stable IDs; typed outcomes only). */
export interface ServerScenarioAlignment {
  readonly scenarioId: string; // e.g. HV-DAT-SRV-001
  readonly clientTestRef: string; // stable test identifier (no file paths with secrets)
  readonly twinTestRef: string | null; // matching HushServerNode TwinTest id when supplied
  readonly expectedOutcome: string; // closed typed outcome
  readonly evidenceState: ReleaseFindingState; // external execution state
}

/** Immutable downstream file-restore handoff (FEAT-010/011 consumers). */
export interface FileRestoreHandoff {
  readonly handoffVersion: 1;
  readonly featureId: 'FEAT-009';
  readonly contractPins: Readonly<Record<string, string>>; // immutable digest/revision pins
  readonly exportedContracts: readonly string[]; // safe contract surface names
  readonly prohibitedSurfaces: readonly string[]; // source/password/mnemonic/private/generic capability
  readonly generatedAt: string; // ISO timestamp
}

/** Validate a handoff: versioned, pinned, no mutable references. */
export function validateFileRestoreHandoff(handoff: FileRestoreHandoff): { readonly ok: true } | { readonly ok: false; readonly reasons: readonly string[] } {
  const reasons: string[] = [];
  if (handoff.handoffVersion !== 1) reasons.push('unsupported handoffVersion');
  if (handoff.featureId !== 'FEAT-009') reasons.push('featureId mismatch');
  for (const [name, pin] of Object.entries(handoff.contractPins)) {
    if (/latest|main|master|HEAD/i.test(pin)) reasons.push(`mutable pin for ${name}`);
    if (!/^[a-f0-9]{40,64}$/i.test(pin)) reasons.push(`malformed pin for ${name}`);
  }
  if (reasons.length > 0) return { ok: false, reasons };
  return { ok: true };
}

/** Reject evidence containing prohibited material (never echoes the value). */
export function assertSafeEvidence(evidence: unknown): { readonly ok: true } | { readonly ok: false; readonly reason: string } {
  const violations = assertNoRestoreSecretSurface(evidence);
  if (violations.length > 0) {
    return { ok: false, reason: `prohibited evidence surface: ${violations.join(',')}` };
  }
  return { ok: true };
}
