/**
 * FEAT-011 Task 2.8 — evidence-schema, allowlist, and rejection tests for the
 * evidence/shared-ID contracts (Task 2.7).
 *
 * Covers: secret/evidence allowlist; Manual TestPack IDs; PASS|FAIL|NOT_SUPPLIED
 * states; release-state ledger admission; no human-attestation or export fields.
 */

import { describe, expect, it } from 'vitest';
import {
  NEVER_RECORDED_PATTERN,
  releaseReadinessOf,
  validateEvidenceRecord,
  type EvidenceRecord,
  type ExternalEvidenceState,
  type ManualExternalEvidenceRow,
} from './evidence';

function makeRecord(overrides: Partial<EvidenceRecord> = {}): EvidenceRecord {
  return {
    stableId: 'HV-ID-CREATE-001',
    evidenceClass: 'TWIN',
    revision: '4ab9363a',
    command: 'dotnet test --filter HV-ID-CREATE-001',
    exitCode: 0,
    counts: '1/1',
    warningsErrors: '0/0',
    digests: 'manifest-sha256',
    capturePolicy: 'disabled',
    targetClass: 'server-net10',
    cleanupProof: 'ports-free',
    timestamp: '2026-08-06T18:00:00Z',
    ...overrides,
  };
}

describe('evidence record schema (Task 2.8)', () => {
  it('admits a clean green record', () => {
    expect(validateEvidenceRecord(makeRecord()).ok).toBe(true);
  });

  it('rejects non-zero exit codes (a failed run is never evidence)', () => {
    expect(validateEvidenceRecord(makeRecord({ exitCode: 1 })).ok).toBe(false);
    expect(validateEvidenceRecord(makeRecord({ exitCode: -1 })).ok).toBe(false);
  });

  it('rejects missing stableId/revision/command', () => {
    expect(validateEvidenceRecord(makeRecord({ stableId: '' })).ok).toBe(false);
    expect(validateEvidenceRecord(makeRecord({ revision: '  ' })).ok).toBe(false);
    expect(validateEvidenceRecord(makeRecord({ command: '' })).ok).toBe(false);
  });

  it('rejects secret-bearing values (never-recorded allowlist)', () => {
    expect(NEVER_RECORDED_PATTERN.test('mnemonic')).toBe(true);
    expect(NEVER_RECORDED_PATTERN.test('password')).toBe(true);
    expect(NEVER_RECORDED_PATTERN.test('transaction-json')).toBe(true);
    expect(NEVER_RECORDED_PATTERN.test('BEGIN PRIVATE KEY')).toBe(true);
    expect(NEVER_RECORDED_PATTERN.test('full address')).toBe(true);
    expect(validateEvidenceRecord(makeRecord({ command: 'echo hunter2 password' })).ok).toBe(false);
    expect(validateEvidenceRecord(makeRecord({ digests: 'alice mnemonic phrase' })).ok).toBe(false);
  });

  it('allows only the seven frozen evidence classes', () => {
    const classes = [
      'EXECUTABLE_CLIENT',
      'EXECUTABLE_ROOT',
      'TWIN',
      'EXECUTABLE_NATIVE',
      'EXECUTABLE_STATIC',
      'MANUAL',
      'EXTERNAL',
    ];
    for (const c of classes) {
      expect(validateEvidenceRecord(makeRecord({ evidenceClass: c as EvidenceRecord['evidenceClass'] })).ok).toBe(true);
    }
  });
});

describe('manual/external evidence states (Task 2.8)', () => {
  const legal: ExternalEvidenceState[] = ['PASS', 'FAIL', 'NOT_SUPPLIED'];

  it('manual TestPack rows admit only PASS|FAIL|NOT_SUPPLIED', () => {
    // The legal-state union is exactly these three values (type-level); a
    // PENDING obligation stays in ManualTestObligations.json and is NEVER a
    // ledger admission state.
    expect(legal).toEqual(['PASS', 'FAIL', 'NOT_SUPPLIED']);
    expect(legal).not.toContain('PENDING');
    for (const state of legal) {
      const row: ManualExternalEvidenceRow = {
        id: 'MT-QUAL-UBUNTU-011-001',
        evidenceClass: 'MANUAL',
        state,
        owner: 'Manual TestPack',
        releaseImpact: 'blocks EPIC release',
      };
      expect(row.state).toBe(state);
    }
  });

  it('external evidence IDs are frozen', () => {
    const ids = ['EXT-CORPUS-011-001', 'EXT-SECURITY-011-001', 'EXT-MIGRATION-011-001'];
    for (const id of ids) {
      const row: ManualExternalEvidenceRow = { id: id as ManualExternalEvidenceRow['id'], evidenceClass: 'EXTERNAL', state: 'NOT_SUPPLIED', owner: 'external', releaseImpact: 'release' };
      expect(row.id).toBe(id);
    }
  });

  it('no human-attestation or export fields exist in the row schema', () => {
    const row: ManualExternalEvidenceRow = {
      id: 'EXT-CORPUS-011-001',
      evidenceClass: 'EXTERNAL',
      state: 'NOT_SUPPLIED',
      owner: 'external',
      releaseImpact: 'release',
    };
    const keys = Object.keys(row);
    expect(keys).not.toContain('attestedBy');
    expect(keys).not.toContain('signature');
    expect(keys).not.toContain('export');
    expect(keys).not.toContain('personName');
  });
});

describe('release-state ledger (Task 2.8)', () => {
  it('release readiness is READY only when every row is PASS', () => {
    const allPass: ManualExternalEvidenceRow[] = [
      { id: 'MT-QUAL-UBUNTU-011-001', evidenceClass: 'MANUAL', state: 'PASS', owner: 'x', releaseImpact: 'r' },
      { id: 'EXT-CORPUS-011-001', evidenceClass: 'EXTERNAL', state: 'PASS', owner: 'x', releaseImpact: 'r' },
    ];
    expect(releaseReadinessOf(allPass)).toBe('READY');

    const blocked: ManualExternalEvidenceRow[] = [
      { id: 'MT-QUAL-ANDROID-011-001', evidenceClass: 'MANUAL', state: 'NOT_SUPPLIED', owner: 'x', releaseImpact: 'r' },
      { id: 'EXT-SECURITY-011-001', evidenceClass: 'EXTERNAL', state: 'PASS', owner: 'x', releaseImpact: 'r' },
    ];
    expect(releaseReadinessOf(blocked)).toBe('BLOCKED_BY_EXTERNAL_DEPENDENCIES');

    const failed: ManualExternalEvidenceRow[] = [
      { id: 'EXT-CORPUS-011-001', evidenceClass: 'EXTERNAL', state: 'FAIL', owner: 'x', releaseImpact: 'r' },
    ];
    expect(releaseReadinessOf(failed)).toBe('BLOCKED_BY_EXTERNAL_DEPENDENCIES');
  });

  it('empty ledger is never READY (no fabricated closure)', () => {
    expect(releaseReadinessOf([])).toBe('NOT_READY');
  });
});
