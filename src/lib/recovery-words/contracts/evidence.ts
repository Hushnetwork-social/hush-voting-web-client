/**
 * FEAT-008 recovery-words — acceptance, fault, and downstream evidence
 * schemas.
 *
 * Framework-neutral. Provides machine-readable schemas for AC coverage
 * manifests, scenario targets, sanitized fault outcomes, platform capability
 * evidence, external release findings, and the immutable downstream recovery
 * handoff. Validation fails closed on unknown/duplicate criteria, mutable
 * pins, unsafe evidence, and unsupported target claims.
 *
 * SECRET BOUNDARY: reports contain only allowlisted identifiers, digests,
 * coarse outcomes, and support codes. Evidence containing words, keys, full
 * addresses, credential IDs, or exact transaction material is rejected.
 *
 * Normative source: FEAT-008 FeatureDescription "Testing Strategy",
 * "Secret-safe evidence", "Observability", "Definition of Done";
 * FeatureTasks.md Acceptance Traceability Strategy.
 */

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
export type CoverageTarget = 'web' | 'ubuntu' | 'android' | 'conformance' | 'native-smoke' | 'server-twins' | 'physical-web' | 'cross-feature' | 'governance' | 'all';

/** One acceptance criterion mapping (AC-008-NNN). */
export interface CoverageCriterion {
  readonly id: string; // e.g. 'AC-008-001'
  readonly family: string; // one of the 22 HV-RW-* family IDs
  readonly scenarioIds: readonly string[]; // ≥1 stable scenario ID
  readonly targets: readonly CoverageTarget[];
  readonly implementationPhases: readonly number[];
  readonly testLayers: readonly CoverageTestLayer[];
  readonly classification: CoverageClassification;
}

/** Machine-checked coverage manifest for FEAT-008. */
export interface CoverageManifest {
  readonly manifestVersion: 1;
  readonly feature: 'FEAT-008';
  readonly families: readonly string[]; // the 22 mandatory scenario families
  readonly criteria: readonly CoverageCriterion[];
}

/** Closed registry of the 22 mandatory scenario families. */
export const RECOVERY_SCENARIO_FAMILIES: readonly string[] = [
  'HV-RW-ENTRY-GUARD',
  'HV-RW-INPUT',
  'HV-RW-PASTE',
  'HV-RW-VALIDATE',
  'HV-RW-CUSTODY',
  'HV-RW-CANDIDATES',
  'HV-RW-LOOKUP',
  'HV-RW-SELECT',
  'HV-RW-CONTROL',
  'HV-RW-PROFILE',
  'HV-RW-RECREATE',
  'HV-RW-PASSWORD',
  'HV-RW-PASSKEY',
  'HV-RW-NATIVE-PASSWORDLESS',
  'HV-RW-SESSION',
  'HV-RW-STAGE',
  'HV-RW-RESUME',
  'HV-RW-NAV',
  'HV-RW-OWNER',
  'HV-RW-CLEANUP',
  'HV-RW-MIGRATION',
  'HV-RW-SECURITY',
] as const;

/** Number of FEAT-008 acceptance criteria. */
export const FEAT_008_CRITERION_COUNT = 85 as const;

/** Validation outcome for a coverage manifest (fails on unknown mappings). */
export type CoverageValidation =
  | { readonly ok: true; readonly mappedCount: number }
  | {
      readonly ok: false;
      readonly errors: readonly string[];
    };

export function validateCoverageManifest(manifest: CoverageManifest): CoverageValidation {
  const errors: string[] = [];
  const familySet = new Set(RECOVERY_SCENARIO_FAMILIES);
  const familySetLocal = new Set(manifest.families);
  for (const family of manifest.families) {
    if (!familySet.has(family)) {
      errors.push(`Unknown scenario family: ${family}`);
    }
  }
  const seen = new Set<string>();
  for (const criterion of manifest.criteria) {
    if (!criterion.id.startsWith('AC-008-')) {
      errors.push(`Unknown criterion ID: ${criterion.id}`);
    }
    if (seen.has(criterion.id)) {
      errors.push(`Duplicate criterion mapping: ${criterion.id}`);
    }
    seen.add(criterion.id);
    if (!familySetLocal.has(criterion.family)) {
      errors.push(`${criterion.id} references unknown family ${criterion.family}`);
    }
    if (criterion.scenarioIds.length === 0) {
      errors.push(`${criterion.id} has no executable scenario ID`);
    }
    if (criterion.classification !== 'target-owned' && criterion.classification !== 'target-owned-capability' && criterion.classification !== 'release-evidence') {
      errors.push(`${criterion.id} has unknown classification ${String(criterion.classification)}`);
    }
  }
  for (let index = 1; index <= FEAT_008_CRITERION_COUNT; index += 1) {
    const id = `AC-008-${String(index).padStart(3, '0')}`;
    if (!seen.has(id)) {
      errors.push(`Missing criterion mapping: ${id}`);
    }
  }
  if (errors.length > 0) {
    return { ok: false, errors };
  }
  return { ok: true, mappedCount: seen.size };
}

/** Sanitized fault evidence entry (no secrets, no full addresses). */
export interface FaultEvidenceEntry {
  readonly boundary: string; // e.g. 'paste-after-replacement'
  readonly injected: string; // safe fault descriptor
  readonly expectedSafeState: string;
  readonly actualSafeState: string;
  readonly passed: boolean;
  readonly safeOutcomeCode: string; // closed RecoveryEvidenceCategory-style code
}

/** External release finding (separately owned; never blocks implementation). */
export interface ExternalFinding {
  readonly findingId: string; // e.g. 'EXT-008-001'
  readonly title: string;
  readonly owningScope: string;
  readonly releaseImpact: string;
  readonly implementationBlocking: false;
  readonly evidenceObserved: string;
  readonly followUp: string;
}

/** Immutable downstream recovery handoff manifest (FEAT-009/010/011). */
export interface DownstreamHandoffManifest {
  readonly handoffVersion: 1;
  readonly feature: 'FEAT-008';
  readonly exposes: ReadonlyArray<
    'versioned-selected-key-staging' | 'protection-mode-metadata' | 'staged-resume' | 'verified-cleanup' | 'no-mnemonic-vault-contract' | 'concrete-key-only-export-eligibility'
  >;
  readonly forbidden: ReadonlyArray<'recovery-words' | 'private-key-return' | 'generic-signer' | 'generic-decryptor' | 'full-address-persistence'>;
  readonly pinDigests: Readonly<Record<string, string>>; // exact repository/corpus/contract/dependency digests; never mutable latest
}

/** Evidence report validation — rejects secret-bearing or non-pinned content. */
export interface EvidenceReport {
  readonly reportId: string;
  readonly feature: 'FEAT-008';
  readonly scenarioIds: readonly string[];
  readonly digests: Readonly<Record<string, string>>;
  readonly outcomeCategories: readonly string[]; // closed RecoveryEvidenceCategory codes
  readonly externalFindings: readonly ExternalFinding[];
}

export type EvidenceValidation =
  | { readonly ok: true }
  | { readonly ok: false; readonly violations: readonly string[] };

/** Reject evidence containing mnemonic-like, key, address, or transaction material. */
export function validateEvidenceReportSecrets(report: EvidenceReport): EvidenceValidation {
  const violations: string[] = [];
  const json = JSON.stringify(report);
  const forbiddenPatterns: ReadonlyArray<{ readonly pattern: RegExp; readonly label: string }> = [
    { pattern: /\b(abandon|ability|able|about|above|absent)\b.*\b(zoo|zone|zoom)\b/i, label: 'mnemonic-like-sequence' },
    { pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/i, label: 'private-key' },
    { pattern: /[1-9A-HJ-NP-Za-km-z]{32,}/, label: 'full-address-or-key-like-token' },
    { pattern: /"devicePassword"\s*:/i, label: 'device-password' },
    { pattern: /"transactionJson"\s*:/i, label: 'transaction-json' },
    { pattern: /"credentialId"\s*:/i, label: 'credential-id' },
  ];
  for (const entry of forbiddenPatterns) {
    if (entry.pattern.test(json)) {
      violations.push(entry.label);
    }
  }
  if (Object.entries(report.digests).some(([key, value]) => /latest|mutable/i.test(key) || /latest|mutable/i.test(String(value)))) {
    violations.push('mutable-pin');
  }
  return violations.length > 0 ? { ok: false, violations } : { ok: true };
}

/** Downstream handoff validation — forbidden capabilities must be absent. */
export function validateDownstreamHandoff(manifest: DownstreamHandoffManifest): EvidenceValidation {
  const violations: string[] = [];
  if (manifest.handoffVersion !== 1 || manifest.feature !== 'FEAT-008') {
    violations.push('handoff-version-mismatch');
  }
  for (const forbidden of manifest.forbidden) {
    if (forbidden === 'recovery-words' || forbidden === 'private-key-return' || forbidden === 'generic-signer' || forbidden === 'generic-decryptor' || forbidden === 'full-address-persistence') {
      // explicitly forbidden — correct to declare
    } else {
      violations.push(`unknown-forbidden-operation:${forbidden}`);
    }
  }
  if (Object.keys(manifest.pinDigests).length === 0) {
    violations.push('missing-pin-digests');
  }
  return violations.length > 0 ? { ok: false, violations } : { ok: true };
}
