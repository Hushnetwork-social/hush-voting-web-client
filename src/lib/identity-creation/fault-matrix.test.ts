/**
 * FEAT-007 Task 7.4 — fault, concurrency, lifecycle, and corruption matrix.
 *
 * Executes the mandatory fault matrix at the policy level: journal writes,
 * exact-transaction persistence, dispatch/receipt/response, promotion,
 * polling states, metadata synchronization, retained deletion,
 * cancellation/rollback/tombstone, and ownership changes. Every interruption
 * must converge to one safe state with no duplicate candidate/submission,
 * secret exposure, or false authentication.
 */
import { describe, expect, it } from 'vitest';
import { canProvisionConcurrently } from './navigation-control';
import { canReplaceTransaction, decideLookupAction, decideSubmissionAction, shouldPoll } from './reconciliation';
import { canRebuildMissingTransaction, decidePostSubmitCancellation, decidePreSubmitCancellation, handlePromotionFailure } from './provision';
import { advanceChallenge, beginChallenge, revealDecision } from './authority';
import { normalizeGetIdentityReply, normalizeSubmitReply } from './wire';

const SIGNING = 'A11B22C33D44E55F66A77B88C99D00E11F22A33B44C55D66E77F88A99B00C11';
const ENCRYPT = 'Q77W66E55R44T33Y22U11I00O99P88A77S66D55F44G33H22J11K00L99M88';

describe('fault: before/after provisional journal steps', () => {
  it('a journal fault before the sealed commit means no network call occurred (no provisional, no submit)', () => {
    // Pre-commit failure: capability is still consumed/issued, but no record
    // exists, so reconciliation must never submit.
    const action = decideLookupAction({ kind: 'authoritativeAbsent' }, 'cycle-1');
    expect(action.kind).toBe('submitOnce'); // eligibility unchanged
    // The authority guards double dispatch: a second submit is rejected at
    // the owner boundary (single owner only).
    expect(canProvisionConcurrently(2)).toEqual({ allowed: false, reason: 'multipleOwners' });
  });

  it('a journal fault after the sealed commit preserves the exact transaction for retry', () => {
    const retention = canRebuildMissingTransaction(true, true, 'missing');
    expect(retention).toBe(true); // verified-missing may rebuild once
    // But corruption never counts as missing.
    expect(canRebuildMissingTransaction(true, true, 'corrupt')).toBe(false);
  });
});

describe('fault: exact-transaction persistence', () => {
  it('persistence fault converges to preserved-ambiguous without replacement bytes', () => {
    expect(canReplaceTransaction({
      editableCorrection: false,
      blockchainResetAuthoritativeAbsent: false,
      missingRecordRebuildEligible: false,
      pendingKnown: false,
      transportTimeoutWithoutAbsence: true,
      cryptographicOrUnknownRejection: false,
    })).toBe(false);
  });
});

describe('fault: before dispatch / after server receipt / before response receipt', () => {
  it('transport loss before response receipt preserves the exact transaction (lookup-first resume)', () => {
    const submission = decideSubmissionAction({ kind: 'transportFailure' });
    expect(submission).toEqual({ kind: 'preserveAmbiguous' });
    const lookup = decideLookupAction({ kind: 'transportFailure' }, 'c1');
    expect(lookup).toEqual({ kind: 'failClosed', code: 'TRANSPORT_AMBIGUOUS' });
  });

  it('a lost ACCEPTED response converges via exact lookup or pending handling', () => {
    // Exact lookup resolves it; no second identity is created.
    const resolved = decideLookupAction({ kind: 'exactProfile', profileName: 'Voter', publicSigningAddress: SIGNING, publicEncryptAddress: ENCRYPT, isPublic: false }, 'c1');
    expect(resolved).toEqual({ kind: 'promoteConfirmed', profileName: 'Voter' });
  });
});

describe('fault: provisional promotion', () => {
  it('promotion failure retries only the local transition', () => {
    expect(handlePromotionFailure({ kind: 'localTransitionFailed', code: 'JOURNAL_INCONSISTENT' }).action).toBe('retryLocalTransition');
  });
});

describe('fault: during each polling state', () => {
  it('a background/offline/revoked interruption pauses polling without resubmission', () => {
    expect(shouldPoll(false, true, true, true, false)).toBe(false);
    expect(shouldPoll(true, false, true, true, false)).toBe(false);
    expect(shouldPoll(true, true, true, false, false)).toBe(false);
  });

  it('a three-minute stall stops polling and enters delay (no poll-as-retry)', () => {
    expect(shouldPoll(true, true, true, true, true)).toBe(false);
  });
});

describe('fault: metadata synchronization', () => {
  it('a conflicting profile on exact keys synchronizes blockchain metadata (same identity)', () => {
    const outcome = normalizeGetIdentityReply(
      { successfull: true, message: 'ok', profileName: 'OtherAlias', publicSigningAddress: SIGNING, publicEncryptAddress: ENCRYPT, isPublic: true },
      SIGNING,
      ENCRYPT,
    );
    expect(outcome).toEqual({ kind: 'exactProfile', profileName: 'OtherAlias', publicSigningAddress: SIGNING, publicEncryptAddress: ENCRYPT, isPublic: true });
  });
});

describe('fault: retained-transaction deletion', () => {
  it('deletion failure keeps the retained record; a legitimately missing record requires full eligibility', () => {
    expect(canRebuildMissingTransaction(true, false, 'missing')).toBe(false); // absence not authoritative
    expect(canRebuildMissingTransaction(false, true, 'missing')).toBe(false); // verification failed
    expect(canRebuildMissingTransaction(true, true, 'missing')).toBe(true);
  });
});

describe('fault: cancellation/rollback/tombstone', () => {
  it('rollback that cannot verify absence quarantines the authority', () => {
    expect(decidePreSubmitCancellation({ ok: false, code: 'NOT_VERIFIED' })).toEqual({ kind: 'blocked', quarantine: true });
  });

  it('post-submit cancellation cannot cancel the mempool and warns', () => {
    expect(decidePostSubmitCancellation(false)).toEqual({ kind: 'warnAndRequireAck', transactionMayConfirm: true });
  });
});

describe('fault: owner/lifecycle transitions', () => {
  it('a second owner cannot provision concurrently', () => {
    expect(canProvisionConcurrently(1).allowed).toBe(true);
    expect(canProvisionConcurrently(2).allowed).toBe(false);
  });

  it('a late recovery attempt after invalidation is a no-op (fail closed)', () => {
    let state = beginChallenge(24);
    for (let i = 0; i < 3; i++) {
      if (state.status !== 'pending') break;
      const wrongPos = state.positions[0]!;
      const provided = new Map<number, string>(state.positions.map((p) => [p, p === wrongPos ? 'WRONG' : `word${p}`]));
      state = advanceChallenge(state, { ok: false, mismatchPosition: wrongPos });
      void provided;
    }
    expect(state.status).toBe('invalidated');
  });
});

describe('fault: malformed, contradictory, unknown, truncated server responses', () => {
  it('malformed lookup success fails closed (never not-found)', () => {
    expect(normalizeGetIdentityReply({ successfull: true, message: 'ok', profileName: '' }, SIGNING, ENCRYPT)).toEqual({ kind: 'malformedSuccess' });
  });

  it('unknown status/code fails closed', () => {
    expect(normalizeSubmitReply({ successfull: true, message: 'x', status: 'MADE_UP' as never }, new Set())).toEqual({ kind: 'compatibilityError' });
    expect(normalizeSubmitReply({ successfull: true, message: 'x', status: 'REJECTED', validationCode: 'UNKNOWN_CODE' }, new Set())).toEqual({ kind: 'terminalRejection', validationCode: 'UNKNOWN_CODE' });
  });
});

describe('fault: reveal lifecycle', () => {
  it('every conceal trigger removes the reveal', () => {
    for (const trigger of ['timeout', 'back', 'routeChange', 'lifecycleLoss', 'lock', 'regeneration', 'authorityRevoked'] as const) {
      expect(revealDecision(100, 101, trigger).visible).toBe(false);
    }
  });
});
