/**
 * FEAT-008 Task 2.8 — unit tests for evidence schemas and secret allowlists.
 * Coverage targets: AC-008-073–085 (schema layer); missing/unknown mappings,
 * mutable pins, unsafe evidence, and unsupported target claims fail
 * deterministically.
 */
import { describe, expect, it } from 'vitest';
import {
  FEAT_008_CRITERION_COUNT,
  RECOVERY_SCENARIO_FAMILIES,
  validateCoverageManifest,
  validateDownstreamHandoff,
  validateEvidenceReportSecrets,
  type CoverageCriterion,
  type CoverageManifest,
  type DownstreamHandoffManifest,
  type EvidenceReport,
} from './evidence.js';

function criterion(id: string, family = 'HV-RW-SECURITY'): CoverageCriterion {
  return {
    id,
    family,
    scenarioIds: [`SC-${id}`],
    targets: ['all'],
    implementationPhases: [7],
    testLayers: ['bdd'],
    classification: 'target-owned',
  };
}

function fullManifest(overrides: Partial<CoverageManifest> = {}): CoverageManifest {
  return {
    manifestVersion: 1,
    feature: 'FEAT-008',
    families: [...RECOVERY_SCENARIO_FAMILIES],
    criteria: Array.from({ length: FEAT_008_CRITERION_COUNT }, (_, index) => criterion(`AC-008-${String(index + 1).padStart(3, '0')}`)),
    ...overrides,
  };
}

describe('validateCoverageManifest', () => {
  it('passes a complete 85/85 manifest with the 22 canonical families', () => {
    const manifest = fullManifest();
    const result = validateCoverageManifest(manifest);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.mappedCount).toBe(FEAT_008_CRITERION_COUNT);
    }
  });

  it('fails on a missing criterion (84/85)', () => {
    const manifest = fullManifest();
    const criteria = manifest.criteria.filter((c) => c.id !== 'AC-008-042');
    const result = validateCoverageManifest({ ...manifest, criteria });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors.some((error) => error.includes('AC-008-042'))).toBe(true);
    }
  });

  it('fails on an unknown criterion ID', () => {
    const base = fullManifest();
    const criteria = [...base.criteria.slice(0, 84), criterion('AC-999-999')];
    expect(validateCoverageManifest({ ...base, criteria }).ok).toBe(false);
  });

  it('fails on a duplicate criterion mapping', () => {
    const manifest = fullManifest();
    const criteria = [...manifest.criteria, criterion('AC-008-001')];
    const result = validateCoverageManifest({ ...manifest, criteria });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.errors.some((error) => error.includes('Duplicate'))).toBe(true);
    }
  });

  it('fails on an unknown scenario family', () => {
    const manifest = fullManifest();
    expect(validateCoverageManifest({ ...manifest, families: ['HV-RW-BOGUS'] }).ok).toBe(false);
  });

  it('fails when a criterion names an unknown family', () => {
    const manifest = fullManifest();
    const criteria = [criterion('AC-008-001', 'HV-RW-NOPE'), ...manifest.criteria.slice(1)];
    expect(validateCoverageManifest({ ...manifest, criteria }).ok).toBe(false);
  });

  it('fails when a criterion has no executable scenario ID', () => {
    const manifest = fullManifest();
    const criteria = [{ ...manifest.criteria[0], scenarioIds: [] } as CoverageCriterion, ...manifest.criteria.slice(1)];
    expect(validateCoverageManifest({ ...manifest, criteria }).ok).toBe(false);
  });

  it('fails on an unsupported classification claim', () => {
    const manifest = fullManifest();
    const criteria = [{ ...manifest.criteria[0], classification: 'nonsense' as never } as CoverageCriterion, ...manifest.criteria.slice(1)];
    expect(validateCoverageManifest({ ...manifest, criteria }).ok).toBe(false);
  });
});

describe('validateEvidenceReportSecrets', () => {
  const baseReport: EvidenceReport = {
    reportId: 'RW-001',
    feature: 'FEAT-008',
    scenarioIds: ['HV-RW-INPUT-001'],
    digests: { 'identity-corpus': 'f1bec774' },
    outcomeCategories: ['lookup-complete'],
    externalFindings: [],
  };

  it('accepts a clean secret-safe report', () => {
    expect(validateEvidenceReportSecrets(baseReport).ok).toBe(true);
  });

  it('rejects mnemonic-like sequences', () => {
    const bad = { ...baseReport, scenarioIds: ['abandon ability about ... zoo'] };
    const result = validateEvidenceReportSecrets(bad);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.violations).toContain('mnemonic-like-sequence');
    }
  });

  it('rejects private keys, device passwords, and credential IDs', () => {
    const key = { ...baseReport, outcomeCategories: ['-----BEGIN RSA PRIVATE KEY-----'] };
    expect(validateEvidenceReportSecrets(key).ok).toBe(false);
    const password = {
      reportId: 'rw',
      feature: 'FEAT-008' as const,
      scenarioIds: [],
      digests: {},
      outcomeCategories: ['x'],
      externalFindings: [],
      devicePassword: 'hunter2',
    };
    expect(validateEvidenceReportSecrets(password as unknown as EvidenceReport).ok).toBe(false);
  });

  it('rejects mutable pins (latest)', () => {
    const bad = { ...baseReport, digests: { 'corpus': 'latest' } };
    const result = validateEvidenceReportSecrets(bad);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.violations).toContain('mutable-pin');
    }
  });

  it('rejects full-address-like tokens', () => {
    const bad = { ...baseReport, scenarioIds: ['N' + '1'.repeat(60)] };
    expect(validateEvidenceReportSecrets(bad).ok).toBe(false);
  });
});

describe('validateDownstreamHandoff', () => {
  const validHandoff: DownstreamHandoffManifest = {
    handoffVersion: 1,
    feature: 'FEAT-008',
    exposes: ['versioned-selected-key-staging', 'protection-mode-metadata', 'staged-resume', 'verified-cleanup', 'no-mnemonic-vault-contract', 'concrete-key-only-export-eligibility'],
    forbidden: ['recovery-words', 'private-key-return', 'generic-signer', 'generic-decryptor', 'full-address-persistence'],
    pinDigests: { 'identity-corpus': 'f1bec774', 'vault-corpus': 'e8dfdfa4' },
  };

  it('accepts a valid immutable handoff with pins', () => {
    expect(validateDownstreamHandoff(validHandoff).ok).toBe(true);
  });

  it('fails when pins are missing (mutable/empty)', () => {
    expect(validateDownstreamHandoff({ ...validHandoff, pinDigests: {} }).ok).toBe(false);
  });

  it('fails on version mismatch', () => {
    expect(validateDownstreamHandoff({ ...validHandoff, handoffVersion: 2 as never }).ok).toBe(false);
  });
});
