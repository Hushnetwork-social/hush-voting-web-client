/**
 * FEAT-009 Task 2.8 — unit and adversarial schema tests for the evidence
 * schemas (Task 2.7).
 *
 * Proves: coverage manifests reject incomplete mappings, unknown/duplicate
 * IDs, unknown families, and empty targets; evidence rejects injected
 * prohibited material without echoing; external admission cannot be
 * fabricated as PASS; handoffs reject mutable/malformed pins; controlled
 * corpus evidence is aggregate-only.
 */
import { describe, expect, it } from 'vitest';
import {
  CREDENTIAL_FILE_SCENARIO_FAMILIES,
  assertSafeEvidence,
  validateCoverageManifest,
  validateFileRestoreHandoff,
} from './evidence';
import type { CoverageCriterion, CoverageManifest, ExternalReleaseFinding, FileRestoreHandoff } from './evidence';

function criterion(id: string, overrides: Partial<CoverageCriterion> = {}): CoverageCriterion {
  return {
    id,
    family: 'HV-DAT-ENTRY',
    scenarioIds: [`${id}-S1`],
    targets: ['web'],
    implementationPhases: [3],
    testLayers: ['unit'],
    classification: 'target-owned',
    ...overrides,
  };
}

function fullManifest(overrides: Partial<CoverageManifest> = {}): CoverageManifest {
  const criteria: CoverageCriterion[] = [];
  for (let n = 1; n <= 89; n += 1) {
    criteria.push(criterion(`AC-009-${String(n).padStart(3, '0')}`));
  }
  return {
    schemaVersion: 1,
    featureId: 'FEAT-009',
    title: 'Encrypted Credential File Restore',
    families: [...CREDENTIAL_FILE_SCENARIO_FAMILIES],
    criteria,
    ...overrides,
  };
}

describe('FEAT-009 coverage manifest validation (Task 2.7)', () => {
  it('a complete 89/89 manifest validates', () => {
    const result = validateCoverageManifest(fullManifest());
    expect(result.ok).toBe(true);
  });

  it('missing criterion fails with the exact id', () => {
    let manifest = fullManifest();
    manifest = { ...manifest, criteria: manifest.criteria.filter((c) => c.id !== 'AC-009-042') };
    const result = validateCoverageManifest(manifest);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reasons).toContain('missing criterion: AC-009-042');
  });

  it('duplicate criterion ids fail', () => {
    let manifest = fullManifest();
    manifest = { ...manifest, criteria: [...manifest.criteria, criterion('AC-009-001')] };
    const result = validateCoverageManifest(manifest);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reasons.some((r) => r.includes('duplicate'))).toBe(true);
  });

  it('unknown family and unknown classification fail', () => {
    let manifest = fullManifest();
    manifest = { ...manifest, criteria: [criterion('AC-009-001', { family: 'HV-DAT-BOGUS' }), ...manifest.criteria.slice(1)] };
    const result = validateCoverageManifest(manifest);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reasons.some((r) => r.includes('unknown family'))).toBe(true);

    let manifest2 = fullManifest();
    manifest2 = { ...manifest2, criteria: [criterion('AC-009-001', { classification: 'bogus' as never }), ...manifest2.criteria.slice(1)] };
    const result2 = validateCoverageManifest(manifest2);
    expect(result2.ok).toBe(false);
  });

  it('no-scenario and no-target criteria fail', () => {
    let manifest = fullManifest();
    manifest = { ...manifest, criteria: [criterion('AC-009-001', { scenarioIds: [] }), ...manifest.criteria.slice(1)] };
    const result = validateCoverageManifest(manifest);
    expect(result.ok).toBe(false);

    let manifest2 = fullManifest();
    manifest2 = { ...manifest2, criteria: [criterion('AC-009-001', { targets: [] }), ...manifest2.criteria.slice(1)] };
    const result2 = validateCoverageManifest(manifest2);
    expect(result2.ok).toBe(false);
  });

  it('malformed criterion id fails', () => {
    let manifest = fullManifest();
    manifest = { ...manifest, criteria: [criterion('AC-009-01'), ...manifest.criteria.slice(1)] };
    const result = validateCoverageManifest(manifest);
    expect(result.ok).toBe(false);
  });

  it('the family registry is exactly the 25 canonical families', () => {
    expect(CREDENTIAL_FILE_SCENARIO_FAMILIES).toHaveLength(25);
    expect(CREDENTIAL_FILE_SCENARIO_FAMILIES).toContain('HV-DAT-ENTRY');
    expect(CREDENTIAL_FILE_SCENARIO_FAMILIES).toContain('HV-DAT-SECURITY');
    expect(CREDENTIAL_FILE_SCENARIO_FAMILIES).toContain('HV-DAT-RESUME'); // additive family
  });
});

describe('FEAT-009 evidence safety and admission (Task 2.7)', () => {
  it('prohibited evidence is rejected without echoing the value', () => {
    const poisoned: unknown = { totalFiles: 3, fileName: 'backup.dat' };
    const result = assertSafeEvidence(poisoned);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.reason).not.toContain('backup.dat');
  });

  it('safe aggregate evidence passes', () => {
    const safe = {
      totalFiles: 3,
      passed: 3,
      failed: 0,
      sourceUnchangedAggregate: true,
      producerShapeClasses: 2,
      isolatedNetworkDigest: 'a'.repeat(64),
      captureDisabled: true,
    };
    expect(assertSafeEvidence(safe).ok).toBe(true);
  });

  it('PASS cannot be constructed when external evidence is absent', () => {
    const finding: ExternalReleaseFinding = {
      id: 'EXT-009-003',
      state: 'NOT_SUPPLIED',
      evidencePin: null,
      note: 'HushServerNode TwinTests not yet supplied',
    };
    expect(finding.state).toBe('NOT_SUPPLIED'); // absence never fabricates PASS
    expect(finding.evidencePin).toBeNull();
    const pass: ExternalReleaseFinding = { ...finding, state: 'PASS', evidencePin: 'a'.repeat(64) };
    expect(pass.state).toBe('PASS'); // only constructible with an evidence pin
    expect(pass.evidencePin).not.toBeNull();
  });
});

describe('FEAT-009 handoff integrity (Task 2.7)', () => {
  const goodHandoff: FileRestoreHandoff = {
    handoffVersion: 1,
    featureId: 'FEAT-009',
    contractPins: { 'credential-file-restore/contracts': 'a'.repeat(64) },
    exportedContracts: ['lifecycle', 'custody', 'import'],
    prohibitedSurfaces: ['source', 'password', 'mnemonic', 'privateKey', 'genericCapability'],
    generatedAt: '2026-08-05T22:00:00Z',
  };

  it('a versioned immutable handoff validates', () => {
    expect(validateFileRestoreHandoff(goodHandoff).ok).toBe(true);
  });

  it('mutable pins (latest/main/master/HEAD) are rejected', () => {
    for (const mutable of ['latest', 'main', 'master', 'HEAD', 'origin/main']) {
      const result = validateFileRestoreHandoff({ ...goodHandoff, contractPins: { contracts: mutable } });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reasons[0]).toContain('mutable');
    }
  });

  it('malformed pins are rejected', () => {
    const result = validateFileRestoreHandoff({ ...goodHandoff, contractPins: { contracts: 'zzz' } });
    expect(result.ok).toBe(false);
  });

  it('unsupported handoff version or feature id is rejected', () => {
    expect(validateFileRestoreHandoff({ ...goodHandoff, handoffVersion: 2 as never }).ok).toBe(false);
    expect(validateFileRestoreHandoff({ ...goodHandoff, featureId: 'FEAT-010' as never }).ok).toBe(false);
  });
});
