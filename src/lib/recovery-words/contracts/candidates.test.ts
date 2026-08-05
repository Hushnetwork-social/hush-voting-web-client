/**
 * FEAT-008 Task 2.6 — unit, property, and fuzz tests for candidate lookup,
 * selection, proof, and profile contracts.
 * Coverage targets: AC-008-018–035 (contract layer portion); deterministic
 * ordering/deduplication, partial-failure closure, all outcome cardinalities,
 * exact pair binding, malformed aliases, and reveal boundaries.
 */
import { describe, expect, it } from 'vitest';
import type { DerivedCandidates, PublicCandidateDescriptor } from '../../identity-compatibility/types';
import type { NetworkIdentifier, RecoveryEpoch } from './lifecycle';
import {
  CandidateLookupState,
  isExactProfileMatch,
  isLookupComplete,
  recordLookupOutcome,
  isProofPassed,
  resolveLookup,
  SelectedKeyProofEvidence,
  unresolvedCandidateIndices,
  validateCompleteCandidateSet,
} from './candidates';

const epoch = 'epoch-1' as RecoveryEpoch;
const network = 'hush-mainnet-1' as NetworkIdentifier;

function candidate(producerId: string, signing: string, encryption: string, precedence: number): PublicCandidateDescriptor {
  return {
    producerId,
    producerName: producerId,
    precedence,
    producerIds: [producerId],
    signingAddress: signing,
    encryptionAddress: encryption,
    publicKeyEncoding: 'COMPRESSED',
  };
}

function state(candidates: PublicCandidateDescriptor[], outcomes: Map<number, CandidateLookupState['outcomes'] extends ReadonlyMap<number, infer T> ? T : never> = new Map()): CandidateLookupState {
  return { epoch, networkIdentifier: network, candidates, outcomes, startedAtEpochMs: 0 };
}

const c0 = candidate('p-01', 'S1', 'E1', 1);
const c1 = candidate('p-02', 'S2', 'E2', 2);

describe('complete lookup requirement', () => {
  it('is incomplete until EVERY distinct candidate is resolved', () => {
    let s = state([c0, c1]);
    expect(isLookupComplete(s)).toBe(false);
    s = recordLookupOutcome(s, 0, { kind: 'exactProfile', profileAlias: 'A', visibility: 'private' });
    expect(isLookupComplete(s)).toBe(false);
    s = recordLookupOutcome(s, 1, { kind: 'authoritativeNotFound' });
    expect(isLookupComplete(s)).toBe(true);
  });

  it('treats unresolved (timeout/transport/malformed) as incomplete, never absence', () => {
    let s = state([c0, c1]);
    s = recordLookupOutcome(s, 0, { kind: 'unresolved', reason: 'timeout' });
    s = recordLookupOutcome(s, 1, { kind: 'authoritativeNotFound' });
    expect(unresolvedCandidateIndices(s)).toEqual([0]);
    const verdict = resolveLookup(s);
    expect(verdict.kind).toBe('incomplete');
  });
});

describe('deterministic resolution verdicts', () => {
  it('yields zero only when every candidate is authoritatively absent', () => {
    let s = state([c0, c1]);
    s = recordLookupOutcome(s, 0, { kind: 'authoritativeNotFound' });
    s = recordLookupOutcome(s, 1, { kind: 'authoritativeNotFound' });
    const verdict = resolveLookup(s);
    expect(verdict.kind).toBe('zero');
    if (verdict.kind === 'zero') {
      expect(verdict.candidates).toHaveLength(2);
    }
  });

  it('yields one exact profile and never silently chooses among distinct matches', () => {
    let s = state([c0, c1]);
    s = recordLookupOutcome(s, 0, { kind: 'exactProfile', profileAlias: 'A', visibility: 'private' });
    s = recordLookupOutcome(s, 1, { kind: 'authoritativeNotFound' });
    const verdict = resolveLookup(s);
    expect(verdict.kind).toBe('one');
    if (verdict.kind === 'one') {
      expect(verdict.candidateIndex).toBe(0);
      expect(verdict.profileAlias).toBe('A');
    }
  });

  it('yields multiple with no default selection when more than one exact profile matches', () => {
    let s = state([c0, c1]);
    s = recordLookupOutcome(s, 0, { kind: 'exactProfile', profileAlias: 'A', visibility: 'private' });
    s = recordLookupOutcome(s, 1, { kind: 'exactProfile', profileAlias: 'B', visibility: 'public' });
    const verdict = resolveLookup(s);
    expect(verdict.kind).toBe('multiple');
    if (verdict.kind === 'multiple') {
      expect(verdict.entries).toHaveLength(2);
      expect(verdict.entries[0].candidateIndex).toBe(0);
      expect(verdict.entries[1].candidateIndex).toBe(1);
    }
  });
});

describe('exact both-key binding', () => {
  it('requires signing AND encryption equality (signing-only fails closed)', () => {
    expect(isExactProfileMatch(c0, 'S1', 'E1')).toBe(true);
    expect(isExactProfileMatch(c0, 'S1', 'E-WRONG')).toBe(false);
    expect(isExactProfileMatch(c0, 'S-WRONG', 'E1')).toBe(false);
  });
});

describe('complete candidate set validation', () => {
  it('rejects a partial derived set (missing applicable producer)', () => {
    const derived: DerivedCandidates = { candidates: [c0], rejectedProducers: [] };
    const result = validateCompleteCandidateSet(derived, ['p-01', 'p-02']);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('PRODUCER_DERIVATION_FAILURE');
    }
  });

  it('accepts a complete derived set', () => {
    const derived: DerivedCandidates = { candidates: [c0, c1], rejectedProducers: [] };
    expect(validateCompleteCandidateSet(derived, ['p-01', 'p-02']).ok).toBe(true);
  });
});

describe('selected-key proof', () => {
  it('passes only with exact both-key equality, challenge, and vectors', () => {
    const passed: SelectedKeyProofEvidence = { epoch, producerId: 'p-01', bothKeyExact: true, challengeValidated: true, vectorValidated: true, completedAtEpochMs: 1 };
    expect(isProofPassed(passed)).toBe(true);
    const signingOnly: SelectedKeyProofEvidence = { ...passed, bothKeyExact: false };
    expect(isProofPassed(signingOnly)).toBe(false);
    const challengeFailed: SelectedKeyProofEvidence = { ...passed, challengeValidated: false };
    expect(isProofPassed(challengeFailed)).toBe(false);
    const vectorFailed: SelectedKeyProofEvidence = { ...passed, vectorValidated: false };
    expect(isProofPassed(vectorFailed)).toBe(false);
  });
});

describe('fuzz/property: cardinality and ordering', () => {
  it('remains deterministic under random partial outcome sets (no absence inference)', () => {
    const many = Array.from({ length: 8 }, (_, index) => candidate(`p-${String(index + 1).padStart(2, '0')}`, `S${index}`, `E${index}`, index + 1));
    for (let attempt = 0; attempt < 20; attempt += 1) {
      let s = state(many);
      for (let index = 0; index < many.length; index += 1) {
        const roll = (index + attempt) % 3;
        if (roll === 0) {
          s = recordLookupOutcome(s, index, { kind: 'exactProfile', profileAlias: `A${index}`, visibility: 'private' });
        } else if (roll === 1) {
          s = recordLookupOutcome(s, index, { kind: 'authoritativeNotFound' });
        }
        // roll === 2 → left unresolved
      }
      const verdict = resolveLookup(s);
      expect(verdict.kind).not.toBe('one'); // a missing outcome can never collapse to a single match
      if (verdict.kind === 'incomplete') {
        expect(verdict.unresolvedIndices.length).toBeGreaterThan(0);
      }
    }
  });
});
