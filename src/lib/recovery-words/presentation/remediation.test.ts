/**
 * FEAT-008 Task 4.6 — unit and accessibility-contract tests for error,
 * progress, and remediation projections.
 * Coverage targets: AC-008-007, 009–015, 020, 026, 034–035, 042–052,
 * 056–057, 062–070, 079–080 (presentation portion); all typed codes, unknown
 * code fallback, no echoed secrets, announcement throttling, focus targets,
 * stateful accessible names.
 */
import { describe, expect, it } from 'vitest';
import type { RecoveryFailureCode } from '../contracts/lifecycle';
import {
  errorSummaryPositions,
  mapErrorToRemediation,
  shouldAnnounceProgress,
  showAllAccessibleName,
} from './remediation';

const ALL_CODES: RecoveryFailureCode[] = [
  'VAULT_NOT_VERIFIED_EMPTY',
  'WRONG_COUNT',
  'UNKNOWN_WORD',
  'CHECKSUM_FAILURE',
  'UNSUPPORTED_INPUT',
  'PRODUCER_DERIVATION_FAILURE',
  'PARTIAL_CANDIDATE_LOOKUP',
  'SIGNING_ENCRYPTION_MISMATCH',
  'EPOCH_EXPIRED',
  'STALE_EPOCH',
  'DOUBLE_DISPATCH',
  'OWNERSHIP_LOST',
  'NETWORK_UNAVAILABLE',
  'MALFORMED_PROFILE',
  'PROTECTION_CANCELLED',
  'ENCRYPTED_STAGE_FAILURE',
  'STAGED_RESTART_FAILURE',
  'PROFILE_DISAPPEARED',
  'REGISTRATION_REJECTED',
  'REGISTRATION_PENDING',
  'CLEANUP_FAILURE',
  'QUARANTINED',
  'UNKNOWN_OUTCOME',
  'ENVELOPE_MALFORMED',
  'MNEMONIC_RECORD_INJECTED',
  'UNSUPPORTED_RECOVERY_VERSION',
  'PROTECTION_METADATA_INVALID',
  'UNSUPPORTED_PROTECTION_MODE',
  'UNSUPPORTED_PROTECTION_VERSION',
  'UNQUALIFIED_PASSWORDLESS',
];

describe('mapErrorToRemediation', () => {
  it('maps every typed failure code to bounded copy, actions, and focus', () => {
    for (const code of ALL_CODES) {
      const remediation = mapErrorToRemediation(code);
      expect(remediation.code).toBe(code);
      expect(remediation.message.length).toBeGreaterThan(0);
      expect(remediation.message.length).toBeLessThan(160);
      expect(remediation.actions.length).toBeGreaterThanOrEqual(0);
      expect(['input', 'summary', 'primaryAction']).toContain(remediation.focusTarget);
    }
  });

  it('never echoes words, keys, addresses, or credentials in any message', () => {
    for (const code of ALL_CODES) {
      const message = mapErrorToRemediation(code).message;
      expect(message).not.toMatch(/abandon|ability|zoo|private|seed|mnemonic|BEGIN|PRIVATE KEY|credentialId/i);
    }
  });

  it('keeps the concealed grid for correctable word errors', () => {
    expect(mapErrorToRemediation('WRONG_COUNT').retainsGrid).toBe(true);
    expect(mapErrorToRemediation('UNKNOWN_WORD').retainsGrid).toBe(true);
    expect(mapErrorToRemediation('CHECKSUM_FAILURE').retainsGrid).toBe(true);
    expect(mapErrorToRemediation('NETWORK_UNAVAILABLE').retainsGrid).toBe(false);
  });

  it('fails closed on unknown codes with a generic safe message', () => {
    const unknown = mapErrorToRemediation('BOGUS_CODE' as RecoveryFailureCode);
    expect(unknown.message).toMatch(/unexpected/i);
    expect(unknown.actions).toContain('retry');
  });
});

describe('progress announcement semantics', () => {
  it('announces only when the coarse bucket changes (throttled)', () => {
    expect(shouldAnnounceProgress('running', 'idle')).toBe(true);
    expect(shouldAnnounceProgress('running', 'running')).toBe(false);
    expect(shouldAnnounceProgress('idle', 'running')).toBe(false); // never announce idle
    expect(shouldAnnounceProgress('done', 'running')).toBe(true);
  });
});

describe('accessibility contracts', () => {
  it('provides stateful accessible names for the show/hide control', () => {
    expect(showAllAccessibleName(true)).toBe('Show all recovery words');
    expect(showAllAccessibleName(false)).toBe('Hide all recovery words');
  });

  it('orders error-summary positions deterministically (numbered, never values)', () => {
    expect(errorSummaryPositions([17, 3, 11])).toEqual([3, 11, 17]);
    expect(errorSummaryPositions([])).toEqual([]);
  });
});
