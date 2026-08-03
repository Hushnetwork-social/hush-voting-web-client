/**
 * FEAT-006 Phase 2 Task 2.6 — evidence/handoff schema tests (TS).
 * Complete sanitized records pass; missing, identifying, secret-bearing, or
 * generic-capability content is rejected; emulator evidence can never
 * substitute for physical TEE evidence; StrongBox stays release-gated.
 */
import { describe, expect, it } from 'vitest';
import {
  evaluateProfileMatrix,
  hardwareClaimIsConsistent,
  isSanitized,
  MANDATORY_EVIDENCE_CLASSES,
  provenanceIsConsistent,
  QualificationReport,
} from './evidence';

const DIGEST = 'a1b2c3d4e5f60718293a4b5c6d7e8f901a2b3c4d5e6f708192a3b4c5d6e7f809';

function validReport(evidenceClass: QualificationReport['evidenceClass']): QualificationReport {
  return {
    schemaVersion: 1,
    evidenceClass,
    buildDigest: DIGEST,
    apiLevel: 36,
    securityLevel: 'tee',
    capabilityClass: 'qualified',
    scenarioResults: [
      { scenario: 'provision-unlock-verify', passed: true },
      { scenario: 'lifecycle-reboot', passed: true },
    ],
    contractVersions: [
      { name: 'wrapperVersion', value: '1' },
      { name: 'mobilePluginProtocol', value: '1.0' },
    ],
  };
}

describe('FEAT-006 qualification evidence schemas (TS)', () => {
  it('sanitized physical reports pass, and the matrix blocks missing classes', () => {
    const r = validReport('physicalCurrentApi');
    expect(isSanitized(r)).toBe(true);
    expect(hardwareClaimIsConsistent(r)).toBe(true);
    expect(provenanceIsConsistent(r)).toBe(true);
    const matrix = evaluateProfileMatrix([r], DIGEST);
    expect(matrix.allMandatoryPresent).toBe(false);
    expect(matrix.missingMandatory).toContain('physicalTee');
    expect(matrix.strongBoxReleaseEnabled).toBe(false);
  });

  it('complete mandatory matrix is green and StrongBox stays gated', () => {
    const reports = MANDATORY_EVIDENCE_CLASSES.map((c) => validReport(c));
    const matrix = evaluateProfileMatrix(reports, DIGEST);
    expect(matrix.allMandatoryPresent).toBe(true);
    expect(matrix.missingMandatory).toEqual([]);
    expect(matrix.strongBoxReleaseEnabled).toBe(false);

    const withStrongBox = [...reports, { ...validReport('physicalStrongBox'), securityLevel: 'strongBox' as const }];
    expect(evaluateProfileMatrix(withStrongBox, DIGEST).strongBoxReleaseEnabled).toBe(true);
  });

  it('identifying evidence is rejected', () => {
    const r = validReport('physicalTee');
    const bad = {
      ...r,
      scenarioResults: [...r.scenarioResults, { scenario: 'capture-serial-9F3E', passed: true }],
    };
    expect(isSanitized(bad)).toBe(false);
  });

  it('generic words match only at token boundaries', () => {
    expect('security'.toLowerCase().includes('uri')).toBe(true); // would be a false positive
    expect(isSanitized(validReport('security'))).toBe(true); // legitimate class passes
    const r = validReport('physicalTee');
    const bad = {
      ...r,
      scenarioResults: [...r.scenarioResults, { scenario: 'open-content-uri', passed: true }],
    };
    expect(isSanitized(bad)).toBe(false);
  });

  it('emulator cannot claim hardware qualification', () => {
    const emu = { ...validReport('emulator'), securityLevel: 'tee' as const };
    expect(hardwareClaimIsConsistent(emu)).toBe(false);
    expect(provenanceIsConsistent(emu)).toBe(false);
    const ok = { ...validReport('emulator'), securityLevel: 'softwareOrUnknown' as const };
    expect(provenanceIsConsistent(ok)).toBe(true);
  });

  it('stale digests never satisfy the matrix', () => {
    const matrix = evaluateProfileMatrix([validReport('physicalTee')], 'other-digest');
    expect(matrix.allMandatoryPresent).toBe(false);
  });
});
