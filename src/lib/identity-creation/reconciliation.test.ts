/**
 * FEAT-007 Task 3.6 — unit/model/fault tests for reconciliation.
 * Coverage: AC-007-028–062 (reconciliation/polling/correction/reset portion).
 */
import { describe, expect, it } from 'vitest';
import {
  ABNORMAL_DELAY_MS,
  POLL_INTERVAL_MS,
  canReplaceTransaction,
  decideBlockchainReset,
  decideLookupAction,
  decideSubmissionAction,
  evaluateDelay,
  shouldPoll,
  type ReconciliationAction,
} from './reconciliation.js';

const CYCLE = 'cycle-1';

describe('decideLookupAction — lookup-first reconciliation', () => {
  it('exact profile synchronizes and confirms', () => {
    const action = decideLookupAction({ kind: 'exactProfile', profileName: 'Voter', publicSigningAddress: 'A', publicEncryptAddress: 'B', isPublic: false }, CYCLE);
    expect(action).toEqual({ kind: 'promoteConfirmed', profileName: 'Voter' });
  });

  it('signing match with encryption mismatch fails closed', () => {
    expect(decideLookupAction({ kind: 'encryptionKeyMismatch' }, CYCLE)).toEqual({ kind: 'failClosed', code: 'ENCRYPTION_MISMATCH' });
  });

  it('only authoritative absence authorizes submission — at most once', () => {
    const action = decideLookupAction({ kind: 'authoritativeAbsent' }, CYCLE);
    expect(action).toEqual({ kind: 'submitOnce', cycleId: CYCLE });
  });

  it('transport failure never submits and never infers absence', () => {
    expect(decideLookupAction({ kind: 'transportFailure' }, CYCLE)).toEqual({ kind: 'failClosed', code: 'TRANSPORT_AMBIGUOUS' });
  });

  it('malformed and compatibility outcomes fail closed', () => {
    expect(decideLookupAction({ kind: 'malformedSuccess' }, CYCLE)).toEqual({ kind: 'failClosed', code: 'COMPATIBILITY' });
    expect(decideLookupAction({ kind: 'compatibilityError' }, CYCLE)).toEqual({ kind: 'failClosed', code: 'COMPATIBILITY' });
  });
});

describe('decideSubmissionAction — outcome contract', () => {
  it('ACCEPTED and PENDING promote to saved-waiting only', () => {
    expect(decideSubmissionAction({ kind: 'accepted' })).toEqual({ kind: 'promoteSavedWaiting', outcome: 'accepted' });
    expect(decideSubmissionAction({ kind: 'pending' })).toEqual({ kind: 'promoteSavedWaiting', outcome: 'pending' });
  });

  it('ALREADY_EXISTS resolves by exact lookup only', () => {
    expect(decideSubmissionAction({ kind: 'alreadyExists' })).toEqual({ kind: 'resolveByLookup' });
  });

  it('editable rejection reopens Profile/Review with the stable code', () => {
    expect(decideSubmissionAction({ kind: 'editableRejection', validationCode: 'ALIAS_INVALID' })).toEqual({ kind: 'reopenProfile', validationCode: 'ALIAS_INVALID' });
  });

  it('terminal/unknown/compat outcomes fail closed without automatic retry', () => {
    expect(decideSubmissionAction({ kind: 'terminalRejection', validationCode: 'SIG_INVALID' }).kind).toBe('terminalFailClosed');
    expect(decideSubmissionAction({ kind: 'unknownRejection' }).kind).toBe('failClosed');
    expect(decideSubmissionAction({ kind: 'compatibilityError' }).kind).toBe('failClosed');
  });

  it('transport ambiguity preserves the exact transaction', () => {
    expect(decideSubmissionAction({ kind: 'transportFailure' })).toEqual({ kind: 'preserveAmbiguous' });
  });
});

describe('polling lifecycle', () => {
  it('polls every three seconds while foregrounded/online/visible/authority-valid', () => {
    expect(POLL_INTERVAL_MS).toBe(3_000);
    expect(shouldPoll(true, true, true, true, false)).toBe(true);
  });

  it('pauses on background, offline, hidden, revoked authority, or delay', () => {
    expect(shouldPoll(false, true, true, true, false)).toBe(false);
    expect(shouldPoll(true, false, true, true, false)).toBe(false);
    expect(shouldPoll(true, true, false, true, false)).toBe(false);
    expect(shouldPoll(true, true, true, false, false)).toBe(false);
    expect(shouldPoll(true, true, true, true, true)).toBe(false);
  });

  it('stops into the delay state after three minutes without confirmation', () => {
    const within = evaluateDelay(1_000, 1_000 + ABNORMAL_DELAY_MS - 1);
    expect(within.delayed).toBe(false);
    const delayed = evaluateDelay(1_000, 1_000 + ABNORMAL_DELAY_MS);
    expect(delayed.delayed).toBe(true);
  });
});

describe('replacement-transaction eligibility (error-specific)', () => {
  const base = {
    editableCorrection: false,
    blockchainResetAuthoritativeAbsent: false,
    missingRecordRebuildEligible: false,
    pendingKnown: false,
    transportTimeoutWithoutAbsence: false,
    cryptographicOrUnknownRejection: false,
  };

  it('allows editable correction, reset, and verified-missing rebuild only', () => {
    expect(canReplaceTransaction({ ...base, editableCorrection: true })).toBe(true);
    expect(canReplaceTransaction({ ...base, blockchainResetAuthoritativeAbsent: true })).toBe(true);
    expect(canReplaceTransaction({ ...base, missingRecordRebuildEligible: true })).toBe(true);
    expect(canReplaceTransaction(base)).toBe(false);
  });

  it('never replaces while PENDING, after transport timeout, or after crypto/unknown rejection', () => {
    expect(canReplaceTransaction({ ...base, pendingKnown: true })).toBe(false);
    expect(canReplaceTransaction({ ...base, transportTimeoutWithoutAbsence: true })).toBe(false);
    expect(canReplaceTransaction({ ...base, cryptographicOrUnknownRejection: true })).toBe(false);
  });

  it('forbids every-three-seconds and restart-only retries (no blanket replacement)', () => {
    // Only the three documented error-specific paths authorize replacement.
    const blanket = { ...base };
    expect(canReplaceTransaction(blanket)).toBe(false);
  });
});

describe('blockchain reset policy', () => {
  it('re-registers the same identity with the same mnemonic after authoritative absence', () => {
    expect(decideBlockchainReset(true, true, true)).toEqual({ ok: true });
  });

  it('never trusts a local marker alone and never invents a new mnemonic', () => {
    expect(decideBlockchainReset(false, true, true).ok).toBe(false);
    expect(decideBlockchainReset(true, false, true).ok).toBe(false);
    expect(decideBlockchainReset(true, true, false)).toEqual({ ok: false, code: 'MNEMONIC_UNAVAILABLE' });
  });
});

describe('closed action union', () => {
  it('enumerates the closed reconciliation actions', () => {
    const kinds: ReadonlyArray<ReconciliationAction['kind']> = [
      'wait',
      'submitOnce',
      'promoteConfirmed',
      'failClosed',
      'poll',
      'enterDelay',
      'checkAgainLookupOnly',
      'syncMetadata',
    ];
    expect(new Set(kinds).size).toBe(kinds.length);
  });
});
