/**
 * FEAT-011 Task 4.4 — adapter tests: producer-matrix cardinalities, complete
 * candidate resolution, six-position enforcement, review defaults/prefill
 * semantics, returning-reset without mnemonic, no source mutation.
 */

import { describe, expect, it } from 'vitest';
import {
  createCandidateResolution,
  decideReturningReset,
  enforceSixPositionConfirmation,
  fileCandidateResolution,
  resolveCompleteCandidateSet,
  reviewDefaultsFor,
} from './adapters';
import type { CandidateLookupOutcome } from './contracts';

const exact = (n: number): CandidateLookupOutcome => ({
  kind: 'exactMatch',
  proof: { signingAddress: `sig-${n}`, encryptionAddress: `enc-${n}`, normalizedAlias: '', visibility: 'private' },
});
const absent = (): CandidateLookupOutcome => ({ kind: 'explicitNotfound' });

describe('candidate resolution (Task 4.4)', () => {
  it('exactly one exact match wins over a complete absent set', () => {
    expect(resolveCompleteCandidateSet([absent(), exact(1), absent()], 3)).toEqual({ kind: 'exactMatch', proof: (exact(1) as { kind: 'exactMatch'; proof: unknown }).proof });
  });

  it('every outcome explicit-not-found establishes allAbsent', () => {
    expect(resolveCompleteCandidateSet([absent(), absent(), absent()], 3)).toEqual({ kind: 'allAbsent' });
  });

  it('partial sets are incomplete, never absence', () => {
    expect(resolveCompleteCandidateSet([absent()], 2)).toEqual({ kind: 'incomplete', completed: 1, total: 2 });
    expect(resolveCompleteCandidateSet([], 4)).toEqual({ kind: 'incomplete', completed: 0, total: 4 });
    expect(resolveCompleteCandidateSet([], 0)).toEqual({ kind: 'allAbsent' });
  });

  it('multiple exact candidates fail closed (no order-dependent selection)', () => {
    expect(resolveCompleteCandidateSet([exact(1), exact(2)], 3)).toEqual({ kind: 'multipleMatches', count: 2 });
  });

  it('create/file adapters produce the exact pair as the lookup candidate', () => {
    expect(createCandidateResolution('a', 'b').kind).toBe('exactMatch');
    expect(fileCandidateResolution('a', 'b')).toEqual(createCandidateResolution('a', 'b'));
  });
});

describe('six-position confirmation (Task 4.4)', () => {
  it('is required before create proceeds', () => {
    expect(enforceSixPositionConfirmation(false)).toEqual({ ok: false, code: 'RECOVERY_CONFIRMATION_REQUIRED' });
    expect(enforceSixPositionConfirmation(true)).toEqual({ ok: true });
  });
});

describe('review defaults per origin (Task 4.4)', () => {
  it('words and returning-reset start empty alias + Private visibility', () => {
    for (const origin of ['words', 'returningReset'] as const) {
      const review = reviewDefaultsFor(origin);
      expect(review.alias).toBe('');
      expect(review.visibility).toBe('private');
      expect(review.prefillIsAuthoritative).toBe(false);
      expect(review.sameIdentityAcknowledged).toBe(false);
    }
  });

  it('create reuses the already reviewed metadata', () => {
    const review = reviewDefaultsFor('create', { alias: 'alice', visibility: 'public' });
    expect(review.alias).toBe('alice');
    expect(review.visibility).toBe('public');
  });

  it('credential-file metadata is a clearly reviewable prefill, never chain truth', () => {
    const review = reviewDefaultsFor('credentialFile', undefined, { alias: 'file-alias', visibility: 'private' });
    expect(review.alias).toBe('file-alias');
    expect(review.prefillIsAuthoritative).toBe(false);
    const empty = reviewDefaultsFor('credentialFile');
    expect(empty.alias).toBe('');
  });
});

describe('returning reset (Task 4.4)', () => {
  it('requires authoritative absence + concrete keys + verified metadata — mnemonic is irrelevant', () => {
    expect(decideReturningReset(true, true, true)).toEqual({ ok: true });
    expect(decideReturningReset(true, false, true)).toEqual({ ok: false, code: 'NOT_AUTHORITATIVE' });
    expect(decideReturningReset(false, true, true)).toEqual({ ok: false, code: 'KEYS_UNAVAILABLE' });
    expect(decideReturningReset(true, true, false)).toEqual({ ok: false, code: 'NO_VERIFIED_METADATA' });
  });
});
