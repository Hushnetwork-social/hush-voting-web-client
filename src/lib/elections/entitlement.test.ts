import { describe, expect, it } from 'vitest';
import { ELECTION_ENTITLEMENT_REASONS, electionEntitlementReason, parseElectionScopedAccess } from './entitlement';
const electionId = '11111111-2222-4333-8444-555555555555';
const valid = { ElectionId: electionId, SchemaVersion: 1, AllowedOperations: ['vote'], EntitlementReason: '' };
describe('FEAT-018 closed election authority wire boundary', () => {
  it.each(ELECTION_ENTITLEMENT_REASONS)('retains the typed reason %s without server copy', reason => {
    expect(parseElectionScopedAccess({ ...valid, EntitlementReason: reason, ErrorMessage: 'private raw text' }, electionId))
      .toEqual({ electionId, allowedOperations: [], reason });
  });
  it('fails closed for unknown codes, old nodes, another election and unknown operations', () => {
    for (const value of [null, {}, { ...valid, SchemaVersion: 99 }, { ...valid, ElectionId: 'another' },
      { ...valid, EntitlementReason: 'arbitrary raw private text' }, { ...valid, AllowedOperations: ['create'] },
      { ...valid, AllowedOperations: ['vote', 'vote'] }]) {
      expect(parseElectionScopedAccess(value, electionId)).toEqual({ electionId, allowedOperations: [], reason: 'ENTITLEMENT_SEMANTICS_UNSUPPORTED' });
    }
    expect(electionEntitlementReason({ private: 'text' })).toBe('ENTITLEMENT_SEMANTICS_UNSUPPORTED');
  });
  it('copies the validated operation set without accepting a global ready grant', () => {
    const parsed = parseElectionScopedAccess({ ...valid, entitlementReady: true }, electionId);
    expect(parsed).toEqual({ electionId, allowedOperations: ['vote'], reason: null });
    expect(parsed.allowedOperations).not.toBe(valid.AllowedOperations);
  });
});
