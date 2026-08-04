/**
 * FEAT-008 Task 6.10 — integrity and regression tests for the downstream
 * handoff and release-finding composition.
 * Coverage targets: AC-008-039, 052–054, 062–063, 068–072, 082–085
 * (integration portion).
 */
import { describe, expect, it } from 'vitest';
import { validateDownstreamHandoff, validateEvidenceReportSecrets, type EvidenceReport } from '../contracts/evidence';
import { RECOVERY_DOWNSTREAM_HANDOFF_V1, RECOVERY_RELEASE_FINDINGS, releaseFindingsManifest } from './handoff.js';

describe('immutable downstream handoff (Task 6.10)', () => {
  it('exposes only approved versioned restore/resume/export inputs and forbids secret operations', () => {
    expect(validateDownstreamHandoff(RECOVERY_DOWNSTREAM_HANDOFF_V1).ok).toBe(true);
    expect(RECOVERY_DOWNSTREAM_HANDOFF_V1.forbidden).toContain('recovery-words');
    expect(RECOVERY_DOWNSTREAM_HANDOFF_V1.forbidden).toContain('private-key-return');
    expect(RECOVERY_DOWNSTREAM_HANDOFF_V1.forbidden).toContain('generic-signer');
    expect(RECOVERY_DOWNSTREAM_HANDOFF_V1.forbidden).toContain('generic-decryptor');
    expect(RECOVERY_DOWNSTREAM_HANDOFF_V1.forbidden).toContain('full-address-persistence');
  });

  it('pins exact digests (never mutable latest)', () => {
    expect(RECOVERY_DOWNSTREAM_HANDOFF_V1.pinDigests['identity-corpus']).toMatch(/^[a-f0-9]{64}$/);
    expect(Object.entries(RECOVERY_DOWNSTREAM_HANDOFF_V1.pinDigests).some(([, value]) => /latest|mutable/i.test(value))).toBe(false);
  });

  it('rejects a tampered handoff (empty pins / version mismatch)', () => {
    expect(validateDownstreamHandoff({ ...RECOVERY_DOWNSTREAM_HANDOFF_V1, pinDigests: {} }).ok).toBe(false);
    expect(validateDownstreamHandoff({ ...RECOVERY_DOWNSTREAM_HANDOFF_V1, handoffVersion: 2 as never }).ok).toBe(false);
  });
});

describe('release-finding composition (Task 6.10)', () => {
  it('records all external findings as non-blocking with owning scope and follow-up', () => {
    expect(RECOVERY_RELEASE_FINDINGS).toHaveLength(4);
    for (const finding of RECOVERY_RELEASE_FINDINGS) {
      expect(finding.implementationBlocking).toBe(false);
      expect(finding.findingId).toMatch(/^EXT-008-00[1-4]$/);
      expect(finding.owningScope.length).toBeGreaterThan(0);
      expect(finding.followUp.length).toBeGreaterThan(0);
    }
  });

  it('never marks an external finding as an implementation blocker', () => {
    const manifest = releaseFindingsManifest();
    expect(manifest.feature).toBe('FEAT-008');
    expect(manifest.findings.every((f) => f.implementationBlocking === false)).toBe(true);
  });

  it('evidence reports built from the findings are secret-safe', () => {
    const report: EvidenceReport = {
      reportId: 'FEAT-008-RW-EXT-1',
      feature: 'FEAT-008',
      scenarioIds: ['HV-RW-SRV-001'],
      digests: { 'identity-corpus': 'f1bec774' },
      outcomeCategories: ['lookup-complete'],
      externalFindings: RECOVERY_RELEASE_FINDINGS,
    };
    expect(validateEvidenceReportSecrets(report).ok).toBe(true);
  });
});
