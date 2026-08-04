/**
 * FEAT-007 Task 3.2 — unit/property tests for generation and confirmation
 * authority. Coverage: AC-007-002, 005–016, 024, 063–065, 074.
 */
import { describe, expect, it } from 'vitest';
import {
  RECOVERY_CHALLENGE_POSITIONS,
  RECOVERY_MAX_ATTEMPTS,
  REVEAL_MAX_MS,
  advanceChallenge,
  beginChallenge,
  evaluateRecoveryAttempt,
  revealDecision,
  selectChallengePositions,
  secureShuffle,
} from './authority.js';

describe('selectChallengePositions', () => {
  it('selects six distinct positions within 1..24', () => {
    for (let i = 0; i < 50; i++) {
      const positions = selectChallengePositions(24);
      expect(positions).toHaveLength(RECOVERY_CHALLENGE_POSITIONS);
      expect(new Set(positions).size).toBe(RECOVERY_CHALLENGE_POSITIONS);
      for (const p of positions) {
        expect(p).toBeGreaterThanOrEqual(1);
        expect(p).toBeLessThanOrEqual(24);
      }
    }
  });

  it('produces unpredictable distinct selections across runs', () => {
    const seen = new Set<string>();
    for (let i = 0; i < 100; i++) {
      seen.add(selectChallengePositions(24).join(','));
    }
    expect(seen.size).toBeGreaterThan(1);
  });
});

describe('secureShuffle', () => {
  it('is a permutation of 0..n-1', () => {
    const result = secureShuffle(10);
    expect([...result].sort((a, b) => a - b)).toEqual([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  });

  it('handles empty input', () => {
    expect(secureShuffle(0)).toEqual([]);
  });
});

describe('evaluateRecoveryAttempt + advanceChallenge', () => {
  const words = Array.from({ length: 24 }, (_, i) => `word${i + 1}`);
  const expected = new Map<number, string>(words.map((w, i) => [i + 1, w]));

  it('passes when all requested positions match', () => {
    const positions = selectChallengePositions(24);
    const provided = new Map<number, string>(positions.map((p) => [p, expected.get(p)!]));
    const result = evaluateRecoveryAttempt(positions, provided, expected);
    expect(result).toEqual({ ok: true });
    const state = advanceChallenge(beginChallenge(24), result);
    expect(state.status).toBe('passed');
  });

  it('identifies only the requested mismatch position without echoing words', () => {
    const state = beginChallenge(24);
    if (state.status !== 'pending') throw new Error('expected pending');
    const positions = state.positions;
    const wrongPos = positions[0]!;
    const provided = new Map<number, string>(positions.map((p) => [p, p === wrongPos ? 'WRONGWORD' : expected.get(p)!]));
    const result = evaluateRecoveryAttempt(positions, provided, expected);
    expect(result.ok).toBe(false);
    if (!result.ok && 'mismatchPosition' in result) {
      expect(result.mismatchPosition).toBe(wrongPos);
      expect(JSON.stringify(result)).not.toContain('WRONGWORD');
      expect(JSON.stringify(result)).not.toContain(expected.get(wrongPos)!);
    }
  });

  it('invalidates the challenge after three failed attempts without regenerating the candidate', () => {
    let state = beginChallenge(24);
    for (let attempt = 1; attempt <= RECOVERY_MAX_ATTEMPTS; attempt++) {
      if (state.status !== 'pending') throw new Error('expected pending');
      const wrongPos = state.positions[0]!;
      const provided = new Map<number, string>(state.positions.map((p) => [p, p === wrongPos ? 'WRONGWORD' : expected.get(p)!]));
      const result = evaluateRecoveryAttempt(state.positions, provided, expected);
      state = advanceChallenge(state, result);
    }
    expect(state.status).toBe('invalidated');
  });

  it('locks the challenge as passed and stops counting attempts', () => {
    let state = beginChallenge(24);
    if (state.status !== 'pending') throw new Error('expected pending');
    const result = evaluateRecoveryAttempt(state.positions, new Map(state.positions.map((p) => [p, expected.get(p)!])), expected);
    state = advanceChallenge(state, result);
    expect(state.status).toBe('passed');
    // Subsequent attempts against a passed state are no-ops.
    expect(advanceChallenge(state, { ok: false, mismatchPosition: 1 }).status).toBe('passed');
  });
});

describe('revealDecision — 60-second bound and concealment', () => {
  const now = 1_000_000;

  it('is visible while within the 60-second reveal epoch', () => {
    expect(revealDecision(now, now + 30_000, null)).toEqual({ visible: true, reason: 'revealed', trigger: null });
  });

  it('conceals on timeout after 60 seconds', () => {
    const d = revealDecision(now, now + REVEAL_MAX_MS + 1, null);
    expect(d.visible).toBe(false);
    expect(d.trigger).toBe('timeout');
  });

  it('is concealed before an explicit reveal', () => {
    expect(revealDecision(null, now, null)).toEqual({ visible: false, reason: 'active', trigger: null });
  });

  it('conceals on every trigger (Back, lifecycle loss, Lock, regeneration, revocation)', () => {
    for (const trigger of ['timeout', 'back', 'routeChange', 'lifecycleLoss', 'lock', 'regeneration', 'authorityRevoked'] as const) {
      const d = revealDecision(now, now + 5_000, trigger);
      expect(d.visible).toBe(false);
      expect(d.trigger).toBe(trigger);
    }
  });
});
