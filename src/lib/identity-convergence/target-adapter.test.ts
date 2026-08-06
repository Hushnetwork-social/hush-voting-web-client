/**
 * FEAT-011 Task 4.8 — target-adapter tests: identical outcome vocabulary,
 * operation/version registry, forbidden generic operations, native signing
 * requirement, digest integrity, synthetic-in-production rejection,
 * no fallback, export absence.
 */

import { describe, expect, it } from 'vitest';
import { CONVERGENCE_OPERATIONS } from './contracts';
import { computeHandoffDigest, validateTargetHandoff, type TargetCoordinatorHandoff } from './target-adapter';

function makeHandoff(overrides: Partial<TargetCoordinatorHandoff> = {}): TargetCoordinatorHandoff {
  const base = {
    contractVersion: 1 as const,
    targetClass: 'ubuntu' as const,
    operations: [...CONVERGENCE_OPERATIONS],
    synthetic: false,
    handoffDigest: '',
  };
  const digest = computeHandoffDigest({ ...base, ...overrides });
  return { ...base, ...overrides, handoffDigest: overrides.handoffDigest ?? digest };
}

describe('target adapter validation (Task 4.8)', () => {
  it('a complete native handoff validates', () => {
    expect(validateTargetHandoff(makeHandoff(), true)).toEqual({ ok: true });
    expect(validateTargetHandoff(makeHandoff({ targetClass: 'web' }), false)).toEqual({ ok: true });
  });

  it('missing mandatory operations fail closed before sensitive entry', () => {
    const handoff = makeHandoff({ operations: CONVERGENCE_OPERATIONS.filter((o) => o !== 'sealAndSubmit') });
    expect(validateTargetHandoff(handoff, true)).toEqual({ ok: false, code: 'MISSING_OPERATION' });
  });

  it('unknown operations are forbidden (no generic capability)', () => {
    const handoff = makeHandoff({ operations: [...CONVERGENCE_OPERATIONS, 'export' as never] });
    expect(validateTargetHandoff(handoff, true)).toEqual({ ok: false, code: 'FORBIDDEN_OPERATION' });
  });

  it('native targets missing a signing operation fail closed (MISSING_OPERATION)', () => {
    const handoff = makeHandoff({ operations: CONVERGENCE_OPERATIONS.filter((o) => o !== 'localProof') });
    expect(validateTargetHandoff(handoff, true)).toEqual({ ok: false, code: 'MISSING_OPERATION' });
  });

  it('unknown target classes fail closed', () => {
    expect(validateTargetHandoff(makeHandoff({ targetClass: 'ios' as never }), true)).toEqual({ ok: false, code: 'UNKNOWN_TARGET' });
  });

  it('synthetic actors are never valid in production', () => {
    expect(validateTargetHandoff(makeHandoff({ synthetic: true }), true)).toEqual({ ok: false, code: 'SYNTHETIC_IN_PRODUCTION' });
    expect(validateTargetHandoff(makeHandoff({ synthetic: true }), false)).toEqual({ ok: true });
  });

  it('digest mismatch fails closed', () => {
    expect(validateTargetHandoff(makeHandoff({ handoffDigest: 'deadbeef' }), true)).toEqual({ ok: false, code: 'DIGEST_MISMATCH' });
  });

  it('unsupported contract version fails closed', () => {
    expect(validateTargetHandoff(makeHandoff({ contractVersion: 2 as never }), true)).toEqual({ ok: false, code: 'UNSUPPORTED_VERSION' });
  });

  it('the operation registry contains no export capability', () => {
    expect(CONVERGENCE_OPERATIONS.some((o) => /export|backup/i.test(o))).toBe(false);
    expect(CONVERGENCE_OPERATIONS).toContain('sealAndSubmit');
    expect(CONVERGENCE_OPERATIONS).toContain('lock');
    expect(CONVERGENCE_OPERATIONS).toContain('removal');
  });
});
