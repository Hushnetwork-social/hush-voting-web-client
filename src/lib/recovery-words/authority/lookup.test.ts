/**
 * FEAT-008 Task 3.4 — unit/model/fault tests for complete lookup and
 * candidate resolution.
 * Coverage targets: AC-008-024–035 (authority portion); timeout at every
 * position, malformed/contradictory responses, retry-unresolved-only,
 * no-store/cache abstraction, progress thresholds.
 */
import { describe, expect, it } from 'vitest';
import type { PublicCandidateDescriptor } from '../../identity-compatibility/types';
import type { CandidateLookupOutcome } from '../contracts/candidates';
import { resolveLookup } from '../contracts/candidates';
import type { NetworkIdentifier, RecoveryEpoch } from '../contracts/lifecycle';
import {
  beginLookup,
  resolutionVerdict,
  retryUnresolved,
  runSequentialLookupPass,
  safeProgress,
  type RecoveryLookupPort,
} from './lookup.js';

const epoch = 'epoch-1' as RecoveryEpoch;
const network = 'hush-mainnet-1' as NetworkIdentifier;

function candidate(index: number): PublicCandidateDescriptor {
  return {
    producerId: `p-0${index}`,
    producerName: `p-0${index}`,
    precedence: index,
    producerIds: [`p-0${index}`],
    signingAddress: `S${index}`.padEnd(40, '1'),
    encryptionAddress: `E${index}`.padEnd(40, '2'),
    publicKeyEncoding: 'COMPRESSED',
  };
}

function portWith(results: ReadonlyMap<number, CandidateLookupOutcome>): RecoveryLookupPort {
  return {
    async lookupCandidate(c) {
      const outcome = results.get(Number(c.producerId.slice(-1)));
      if (!outcome) {
        return { kind: 'unresolved', reason: 'transport' };
      }
      return outcome;
    },
  };
}

describe('runSequentialLookupPass', () => {
  it('completes every candidate in precedence order', async () => {
    const candidates = [candidate(1), candidate(2), candidate(3)];
    const results = new Map<number, CandidateLookupOutcome>([
      [1, { kind: 'authoritativeNotFound' }],
      [2, { kind: 'exactProfile', profileAlias: 'A', visibility: 'private' }],
      [3, { kind: 'authoritativeNotFound' }],
    ]);
    const state = beginLookup(epoch, network, candidates, 0);
    const { state: after } = await runSequentialLookupPass(state, portWith(results), 100);
    expect(after.outcomes.size).toBe(3);
    expect(resolveLookup(after).kind).toBe('one');
  });

  it('records timeout as unresolved (never absence) and reports safe progress', async () => {
    const candidates = [candidate(1), candidate(2), candidate(3), candidate(4)];
    const results = new Map<number, CandidateLookupOutcome>([
      [1, { kind: 'authoritativeNotFound' }],
      [2, { kind: 'exactProfile', profileAlias: 'A', visibility: 'private' }],
      // 3 times out (no entry -> transport in this port; simulate timeout below)
      [4, { kind: 'authoritativeNotFound' }],
    ]);
    const state = beginLookup(epoch, network, candidates, 0);
    const slowPort: RecoveryLookupPort = {
      async lookupCandidate(c) {
        const index = Number(c.producerId.slice(-1));
        if (index === 3) {
          await new Promise((resolve) => setTimeout(resolve, 120));
        }
        return results.get(index) ?? { kind: 'unresolved', reason: 'transport' };
      },
    };
    const { state: after, unresolvedAfter } = await runSequentialLookupPass(state, slowPort, 100, 60);
    expect(unresolvedAfter).toBe(1);
    const verdict = resolveLookup(after);
    expect(verdict.kind).toBe('incomplete');
    if (verdict.kind === 'incomplete') {
      expect(verdict.unresolvedIndices).toEqual([2]);
    }
    const progress = safeProgress(after);
    expect(progress.done).toBe(3);
    expect(progress.total).toBe(4);
  });
});

describe('resolutionVerdict gate', () => {
  it('fails closed on a partial set (PARTIAL_CANDIDATE_LOOKUP)', () => {
    const candidates = [candidate(1), candidate(2)];
    const state = beginLookup(epoch, network, candidates, 0);
    const verdict = resolutionVerdict(state);
    expect(verdict.ok).toBe(false);
    if (!verdict.ok) {
      expect(verdict.code).toBe('PARTIAL_CANDIDATE_LOOKUP');
    }
  });

  it('yields zero/one/multiple only after the complete set resolves', async () => {
    const zero = beginLookup(epoch, network, [candidate(1), candidate(2)], 0);
    const zeroAfter = await runSequentialLookupPass(
      zero,
      portWith(new Map([[1, { kind: 'authoritativeNotFound' }], [2, { kind: 'authoritativeNotFound' }]])),
      100,
    );
    const v0 = resolutionVerdict(zeroAfter.state);
    expect(v0.ok && v0.value.kind).toBe('zero');

    const multiple = beginLookup(epoch, network, [candidate(1), candidate(2)], 0);
    const multipleAfter = await runSequentialLookupPass(
      multiple,
      portWith(new Map([[1, { kind: 'exactProfile', profileAlias: 'A', visibility: 'private' }], [2, { kind: 'exactProfile', profileAlias: 'B', visibility: 'public' }]])),
      100,
    );
    const vM = resolutionVerdict(multipleAfter.state);
    expect(vM.ok && vM.value.kind).toBe('multiple');
  });
});

describe('retryUnresolved', () => {
  it('retries ONLY unresolved candidates and never re-queries completed ones', async () => {
    let calls = 0;
    const countingPort: RecoveryLookupPort = {
      async lookupCandidate(c) {
        calls += 1;
        const index = Number(c.producerId.slice(-1));
        return index === 3 ? { kind: 'authoritativeNotFound' } : { kind: 'exactProfile', profileAlias: 'A', visibility: 'private' };
      },
    };
    const candidates = [candidate(1), candidate(2), candidate(3)];
    const state = beginLookup(epoch, network, candidates, 0);
    // First pass: candidate 3 unresolved (simulate via pre-seeded outcome)
    const preSeeded = {
      ...state,
      outcomes: new Map<number, CandidateLookupOutcome>([
        [0, { kind: 'exactProfile', profileAlias: 'A', visibility: 'private' }],
        [1, { kind: 'exactProfile', profileAlias: 'A', visibility: 'private' }],
        [2, { kind: 'unresolved', reason: 'timeout' }],
      ]),
    };
    calls = 0;
    const { state: after, retried } = await retryUnresolved(preSeeded, countingPort, 200);
    expect(retried).toBe(1);
    expect(calls).toBe(1);
    expect(resolveLookup(after).kind).toBe('multiple');
  });
});
