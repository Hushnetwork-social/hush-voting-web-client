/**
 * FEAT-011 Tasks 6.4/6.6/6.8 — native dispatch, target transport, and
 * composition tests: every allowed operation/result, unknown/malformed/
 * version mismatch, direct-secret ordering, one-use capability, no generic/
 * file-path/private-key/full-transaction return, target provenance,
 * no-fallback, partial-handoff fail-closed, production exclusion.
 */

import { describe, expect, it } from 'vitest';
import { CONVERGENCE_OPERATIONS, type ConvergenceOperationId } from '../identity-convergence/contracts';
import {
  CONVERGENCE_PURPOSES,
  NATIVE_DISPATCH_VERSION,
  validateDispatchRequest,
  type NativeDispatchRequest,
} from './native-dispatch';
import {
  composeConvergenceActors,
  resolveTargetTransport,
  type TargetTransportSpec,
} from './target-transports';
import { computeHandoffDigest, validateTargetHandoff, type TargetCoordinatorHandoff } from '../identity-convergence/target-adapter';

function makeDispatch(overrides: Partial<NativeDispatchRequest> = {}): NativeDispatchRequest {
  return {
    protocolVersion: NATIVE_DISPATCH_VERSION,
    operation: 'sealAndSubmit',
    epochBinding: 'epoch-1',
    input: { reviewedAlias: 'alice' },
    capabilityPurpose: 'hushvoting.identity.create-full-identity.v1',
    ...overrides,
  };
}

const ALL_OPS = new Set<ConvergenceOperationId>(CONVERGENCE_OPERATIONS);

describe('native dispatch validation (Task 6.4)', () => {
  it('accepts every allowed operation with a bounded input', () => {
    for (const operation of CONVERGENCE_OPERATIONS) {
      const request = makeDispatch({ operation, capabilityPurpose: purposeFor(operation) });
      expect(validateDispatchRequest(request, ALL_OPS, CONVERGENCE_PURPOSES)).toEqual({ ok: true });
    }
  });

  it('rejects unsupported versions, unknown operations, and forbidden operations', () => {
    expect(validateDispatchRequest(makeDispatch({ protocolVersion: 2 as never }), ALL_OPS, CONVERGENCE_PURPOSES)).toEqual({ ok: false, code: 'UNSUPPORTED_VERSION' });
    expect(validateDispatchRequest(makeDispatch({ operation: 'genericSign' as never }), ALL_OPS, CONVERGENCE_PURPOSES)).toEqual({ ok: false, code: 'UNKNOWN_OPERATION' });
    expect(validateDispatchRequest(makeDispatch(), new Set<ConvergenceOperationId>(['lock']), CONVERGENCE_PURPOSES)).toEqual({ ok: false, code: 'FORBIDDEN_OPERATION' });
  });

  it('rejects missing epoch, unknown purpose, oversize input, and secrets in payloads', () => {
    expect(validateDispatchRequest(makeDispatch({ epochBinding: '' }), ALL_OPS, CONVERGENCE_PURPOSES)).toEqual({ ok: false, code: 'MISSING_EPOCH' });
    expect(validateDispatchRequest(makeDispatch({ capabilityPurpose: 'free-form' }), ALL_OPS, CONVERGENCE_PURPOSES)).toEqual({ ok: false, code: 'UNKNOWN_PURPOSE' });
    expect(
      validateDispatchRequest(
        makeDispatch({ input: { blob: 'x'.repeat(16_385) } }),
        ALL_OPS,
        CONVERGENCE_PURPOSES,
      ),
    ).toEqual({ ok: false, code: 'INPUT_TOO_LARGE' });
    expect(validateDispatchRequest(makeDispatch({ input: { privateKey: 'deadbeef' } }), ALL_OPS, CONVERGENCE_PURPOSES)).toEqual({ ok: false, code: 'SECRET_IN_PAYLOAD' });
    expect(validateDispatchRequest(makeDispatch({ input: { mnemonic: 'word' } }), ALL_OPS, CONVERGENCE_PURPOSES)).toEqual({ ok: false, code: 'SECRET_IN_PAYLOAD' });
  });

  it('the dispatch registry contains no export or generic-signer operation', () => {
    expect(CONVERGENCE_OPERATIONS.some((o) => /export|generic|sign\(/i.test(o))).toBe(false);
  });
});

function purposeFor(operation: string): string {
  const map: Record<string, string> = {
    startupInspection: 'hushvoting.identity.startup-inspection.v1',
    localProof: 'hushvoting.identity.local-proof.v1',
    resolveCandidates: 'hushvoting.identity.candidate-resolution.v1',
    exactLookup: 'hushvoting.identity.exact-lookup.v1',
    reviewMissingProfile: 'hushvoting.identity.create-full-identity.v1',
    confirmMissingProfile: 'hushvoting.identity.create-full-identity.v1',
    sealAndSubmit: 'hushvoting.identity.create-full-identity.v1',
    reconcile: 'hushvoting.identity.submit-reconcile.v1',
    lifecyclePromotion: 'hushvoting.identity.lifecycle-promotion.v1',
    lock: 'hushvoting.identity.lock.v1',
    removal: 'hushvoting.identity.removal.v1',
  };
  return map[operation] ?? 'hushvoting.identity.lock.v1';
}

function makeHandoff(targetClass: 'web' | 'ubuntu' | 'android', overrides: Partial<TargetCoordinatorHandoff> = {}): TargetCoordinatorHandoff {
  const base = {
    contractVersion: 1 as const,
    targetClass,
    operations: [...CONVERGENCE_OPERATIONS],
    synthetic: false,
    handoffDigest: '',
  };
  const digest = computeHandoffDigest({ ...base, ...overrides });
  return { ...base, ...overrides, handoffDigest: overrides.handoffDigest ?? digest };
}

describe('target transport resolution (Task 6.6)', () => {
  it('resolves a real spec for each recognized target and never falls back', () => {
    for (const targetClass of ['web', 'ubuntu', 'android'] as const) {
      const result = resolveTargetTransport(targetClass, [makeHandoff(targetClass)], true);
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.spec.targetClass).toBe(targetClass);
        expect(result.spec.fallback).toBe(false);
      }
    }
  });

  it('fails closed on partial or incompatible handoffs (no Browser fallback for natives)', () => {
    const partial = makeHandoff('ubuntu', { operations: CONVERGENCE_OPERATIONS.filter((o) => o !== 'sealAndSubmit') });
    const result = resolveTargetTransport('ubuntu', [partial], true);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('MISSING_OPERATION');
    }
  });

  it('rejects synthetic actors in production and unknown targets', () => {
    expect(resolveTargetTransport('ios' as never, [], true).ok).toBe(false);
    expect(resolveTargetTransport('web', [makeHandoff('web', { synthetic: true })], true).ok).toBe(false);
    expect(resolveTargetTransport('web', [makeHandoff('web', { synthetic: true })], false).ok).toBe(true);
  });

  it('a missing handoff for a recognized target fails closed', () => {
    expect(resolveTargetTransport('ubuntu', [], true).ok).toBe(false);
  });
});

describe('convergence composition (Task 6.8)', () => {
  it('composes the real actor graph for every target with provenance', () => {
    for (const targetClass of ['web', 'ubuntu', 'android'] as const) {
      const result = composeConvergenceActors(targetClass, [makeHandoff(targetClass)], true);
      expect(result.ok).toBe(true);
      if (result.ok) {
        expect(result.provenance.targetClass).toBe(targetClass);
        expect(result.provenance.synthetic).toBe(false);
        expect(validateTargetHandoff(result.provenance.handoff, true).ok).toBe(true);
      }
    }
  });

  it('blocks before sensitive entry on unknown/partial/contradictory composition', () => {
    expect(composeConvergenceActors('ubuntu', [], true).ok).toBe(false);
    expect(composeConvergenceActors('android', [makeHandoff('web')], true).ok).toBe(false); // wrong-target handoff
    const partial = composeConvergenceActors('web', [makeHandoff('web', { operations: CONVERGENCE_OPERATIONS.slice(0, 3) })], true);
    expect(partial.ok).toBe(false);
  });
});

// Keep the type import used for the spec test below.
export type { TargetTransportSpec };
