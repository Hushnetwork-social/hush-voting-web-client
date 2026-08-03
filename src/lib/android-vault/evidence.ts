/**
 * FEAT-006 Android qualification evidence schemas (Phase 2, Task 2.5),
 * TypeScript mirror of `src-tauri/src/android_vault/evidence.rs`.
 *
 * Machine-readable sanitized evidence: only broad API/security level, build
 * digest, scenario outcomes, and contract versions. Identifying or
 * secret-bearing fields reject the record. Missing mandatory physical classes
 * is a blocking machine result; emulator evidence can never substitute for
 * physical TEE evidence; StrongBox remains release-disabled until its own
 * physical protocol passes.
 */

/** Declared evidence classes (closed). */
export type EvidenceClass =
  | 'emulator'
  | 'physicalTee'
  | 'physicalOldestApi'
  | 'physicalCurrentApi'
  | 'physicalStrongBox'
  | 'package'
  | 'accessibility'
  | 'security';

export const EVIDENCE_CLASSES: readonly EvidenceClass[] = [
  'emulator',
  'physicalTee',
  'physicalOldestApi',
  'physicalCurrentApi',
  'physicalStrongBox',
  'package',
  'accessibility',
  'security',
] as const;

/** Release-blocking mandatory profiles. */
export const MANDATORY_EVIDENCE_CLASSES: readonly EvidenceClass[] = [
  'physicalTee',
  'physicalOldestApi',
  'physicalCurrentApi',
  'package',
  'accessibility',
  'security',
] as const;

export type BroadSecurityLevel = 'strongBox' | 'tee' | 'softwareOrUnknown';
export type BroadCapabilityClass = 'qualified' | 'capabilityCompatible' | 'blocked';

/** One sanitized scenario outcome. */
export interface ScenarioResult {
  readonly scenario: string;
  readonly passed: boolean;
}

/** One contract/version pin recorded in evidence. */
export interface ContractVersionPin {
  readonly name: string;
  readonly value: string;
}

/** One sanitized qualification report (broad fields only). */
export interface QualificationReport {
  readonly schemaVersion: number;
  readonly evidenceClass: EvidenceClass;
  readonly buildDigest: string;
  readonly apiLevel: number;
  readonly securityLevel: BroadSecurityLevel;
  readonly capabilityClass: BroadCapabilityClass;
  readonly scenarioResults: readonly ScenarioResult[];
  readonly contractVersions: readonly ContractVersionPin[];
}

/** Specific identifiers/secret markers — matched as substrings. */
const SUBSTRING_FORBIDDEN_MARKERS: readonly string[] = [
  'androidid',
  'android_id',
  'attestationid',
  'attestation_id',
  'imei',
  'macaddress',
  'ciphertext',
  'privatekey',
  'mnemonic',
  'password',
  'serial',
  'fingerprint',
  'timestamp',
  'identity',
];

/** Generic English words — matched only at token boundaries (so `uri` inside
 * `security` does not reject the legitimate evidence-class vocabulary). */
const WORD_FORBIDDEN_MARKERS: readonly string[] = [
  'uri',
  'path',
  'secret',
  'model',
  'alias',
  'address',
  'endpoint',
];

function containsAtBoundary(haystack: string, marker: string): boolean {
  const h = haystack.toLowerCase();
  const m = marker.toLowerCase();
  if (m.length === 0 || m.length > h.length) return false;
  for (let start = 0; start <= h.length - m.length; start += 1) {
    if (h.slice(start, start + m.length) === m) {
      const beforeOk = start === 0 || !/[a-z0-9]/.test(h[start - 1]);
      const after = start + m.length;
      const afterOk = after === h.length || !/[a-z0-9]/.test(h[after]);
      if (beforeOk && afterOk) return true;
    }
  }
  return false;
}

function fieldContainsForbiddenMarker(value: string): boolean {
  const lower = value.toLowerCase();
  return (
    SUBSTRING_FORBIDDEN_MARKERS.some((m) => lower.includes(m)) ||
    WORD_FORBIDDEN_MARKERS.some((m) => containsAtBoundary(lower, m))
  );
}

/** Whether every string field is free of forbidden evidence markers. */
export function isSanitized(r: QualificationReport): boolean {
  const fields = [r.buildDigest, r.evidenceClass];
  if (fields.some((f) => fieldContainsForbiddenMarker(f))) return false;
  if (r.scenarioResults.some((s) => fieldContainsForbiddenMarker(s.scenario))) return false;
  return r.contractVersions.every(
    (p) => !fieldContainsForbiddenMarker(p.name) && !fieldContainsForbiddenMarker(p.value),
  );
}

/** A physical evidence class requires a hardware-backed broad level; an
 * emulator report making a hardware claim is inconsistent. */
export function hardwareClaimIsConsistent(r: QualificationReport): boolean {
  const isPhysical = (
    r.evidenceClass === 'physicalTee' ||
    r.evidenceClass === 'physicalOldestApi' ||
    r.evidenceClass === 'physicalCurrentApi' ||
    r.evidenceClass === 'physicalStrongBox'
  );
  if (isPhysical) {
    return r.securityLevel === 'tee' || r.securityLevel === 'strongBox';
  }
  if (r.evidenceClass === 'emulator') {
    return r.securityLevel === 'softwareOrUnknown';
  }
  return true;
}

/** Emulator evidence can never claim a physical class. */
export function provenanceIsConsistent(r: QualificationReport): boolean {
  return r.evidenceClass !== 'emulator' || r.securityLevel === 'softwareOrUnknown';
}

/** Required-profile matrix validation result (machine-checkable). */
export interface ProfileMatrixResult {
  readonly schemaVersion: number;
  readonly allMandatoryPresent: boolean;
  readonly missingMandatory: readonly string[];
  readonly strongBoxReleaseEnabled: boolean;
}

/** Evaluate a report set against the mandatory matrix for one digest. */
export function evaluateProfileMatrix(
  reports: readonly QualificationReport[],
  buildDigest: string,
): ProfileMatrixResult {
  const present = new Set<EvidenceClass>();
  for (const r of reports) {
    if (
      r.buildDigest === buildDigest &&
      isSanitized(r) &&
      hardwareClaimIsConsistent(r) &&
      provenanceIsConsistent(r) &&
      r.scenarioResults.every((s) => s.passed)
    ) {
      present.add(r.evidenceClass);
    }
  }
  const missingMandatory = MANDATORY_EVIDENCE_CLASSES.filter((c) => !present.has(c));
  const strongBoxOk = reports.some(
    (r) =>
      r.evidenceClass === 'physicalStrongBox' &&
      r.buildDigest === buildDigest &&
      r.securityLevel === 'strongBox' &&
      r.scenarioResults.every((s) => s.passed),
  );
  return {
    schemaVersion: 1,
    allMandatoryPresent: missingMandatory.length === 0,
    missingMandatory,
    strongBoxReleaseEnabled: strongBoxOk,
  };
}
