/**
 * FEAT-007 Task 3.4 — unit/fault tests for provisioning and promotion.
 * Coverage: AC-007-017–027, 032–033, 036, 044, 054–057.
 */
import { describe, expect, it } from 'vitest';
import {
  PASSWORD_CAPABILITY_MAX_MS,
  canRebuildMissingTransaction,
  consumeProvisionAuthorization,
  decidePostSubmitCancellation,
  decidePreSubmitCancellation,
  handlePromotionFailure,
  issueProvisionAuthorization,
} from './provision.js';

describe('password capability policy', () => {
  it('issues a one-use authorization valid for at most 60 seconds', () => {
    const auth = issueProvisionAuthorization(1_000);
    expect(auth.status).toBe('issued');
    expect(auth.expiresAtMs - auth.issuedAtMs).toBe(PASSWORD_CAPABILITY_MAX_MS);
  });

  it('consumes exactly once (caller persists the returned consumed state)', () => {
    const issued = issueProvisionAuthorization(1_000);
    const first = consumeProvisionAuthorization(issued, 1_000 + 5_000);
    expect(first.ok).toBe(true);
    if (!first.ok) return;
    // The consumed capability (returned by the first call) cannot be used again.
    const second = consumeProvisionAuthorization(first.auth, 1_000 + 10_000);
    expect(second.ok).toBe(false);
    if (!second.ok) expect(second.code).toBe('CONSUMED');
  });

  it('expires after 60 seconds and cannot be used again', () => {
    const issued = issueProvisionAuthorization(1_000);
    const late = consumeProvisionAuthorization(issued, 1_000 + PASSWORD_CAPABILITY_MAX_MS + 1);
    expect(late.ok).toBe(false);
    if (!late.ok) expect(late.code).toBe('EXPIRED');
  });

  it('fails closed when no authorization was issued', () => {
    const none = { status: 'none' as const, issuedAtMs: 0, expiresAtMs: 0 };
    const r = consumeProvisionAuthorization(none, 1_000);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('NONE');
  });
});

describe('promotion failure policy', () => {
  it('retries only the local transition; never rolls back or resubmits', () => {
    const outcome = handlePromotionFailure({ kind: 'localTransitionFailed', code: 'JOURNAL_INCONSISTENT' });
    expect(outcome.action).toBe('retryLocalTransition');
  });

  it('preserves credentials and reports fail-closed for non-local outcomes', () => {
    expect(handlePromotionFailure({ kind: 'promotedToConfirmed' })).toEqual({ action: 'preserveAndReport', failClosed: true });
  });
});

describe('missing-transaction rebuild eligibility', () => {
  it('requires authenticated verification AND authoritative absence for missing records', () => {
    expect(canRebuildMissingTransaction(true, true, 'missing')).toBe(true);
    expect(canRebuildMissingTransaction(false, true, 'missing')).toBe(false);
    expect(canRebuildMissingTransaction(true, false, 'missing')).toBe(false);
  });

  it('corruption is never missing — fails closed', () => {
    expect(canRebuildMissingTransaction(true, true, 'corrupt')).toBe(false);
    expect(canRebuildMissingTransaction(true, true, 'retained')).toBe(false);
    expect(canRebuildMissingTransaction(true, true, 'cleared')).toBe(false);
  });
});

describe('cancellation boundaries', () => {
  it('pre-submit cancellation restores first-run only after verified absence', () => {
    expect(decidePreSubmitCancellation({ ok: true, verifiedAbsent: true })).toEqual({ kind: 'safeRollback', verifiedAbsent: true });
  });

  it('rollback failure quarantines the authority', () => {
    expect(decidePreSubmitCancellation({ ok: false, code: 'NOT_VERIFIED' })).toEqual({ kind: 'blocked', quarantine: true });
  });

  it('post-submit cancellation warns when the transaction may still confirm', () => {
    expect(decidePostSubmitCancellation(false)).toEqual({ kind: 'warnAndRequireAck', transactionMayConfirm: true });
  });

  it('post-submit cancellation is unavailable for a confirmed profile', () => {
    expect(decidePostSubmitCancellation(true)).toEqual({ kind: 'confirmedProfile' });
  });
});
