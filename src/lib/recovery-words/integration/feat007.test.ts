/**
 * FEAT-008 Task 6.8 — integration tests for FEAT-007 reuse, transport
 * normalization, and server scenario alignment.
 * Coverage targets: AC-008-024–035, 053–071, 073–076, 083–084
 * (integration portion).
 */
import { describe, expect, it } from 'vitest';
import { normalizeFeat007Reply, normalizeLookupOutcome, SERVER_SCENARIO_CONTRACT, validateServerScenarioContract, type Feat007GetIdentityReply } from './feat007';

const SIGNING = 'S'.repeat(40);
const ENCRYPTION = 'E'.repeat(40);

function reply(identity: Feat007GetIdentityReply['identity']): Feat007GetIdentityReply {
  return { identity };
}

describe('normalizeFeat007Reply (Task 6.8)', () => {
  it('maps exact both-key match to exactExisting', () => {
    const outcome = normalizeFeat007Reply(reply({ alias: 'Voter', visibility: 'private', signingAddress: SIGNING, encryptionAddress: ENCRYPTION }), SIGNING, ENCRYPTION, 'net' as never);
    expect(outcome).toEqual({ kind: 'exactExisting', signingAddress: SIGNING, encryptionAddress: ENCRYPTION, alias: 'Voter', visibility: 'private' });
  });

  it('maps authoritative absence to authoritativeAbsent', () => {
    expect(normalizeFeat007Reply(reply(null), SIGNING, ENCRYPTION, 'net' as never).kind).toBe('authoritativeAbsent');
    expect(normalizeFeat007Reply(null, SIGNING, ENCRYPTION, 'net' as never).kind).toBe('authoritativeAbsent');
  });

  it('maps signing-only mismatch to mismatch (fails closed)', () => {
    const outcome = normalizeFeat007Reply(reply({ alias: 'Voter', visibility: 'private', signingAddress: SIGNING, encryptionAddress: 'WRONG' }), SIGNING, ENCRYPTION, 'net' as never);
    expect(outcome.kind).toBe('mismatch');
  });
});

describe('normalizeLookupOutcome (Task 6.8)', () => {
  it('never treats transport failure as absence', () => {
    expect(normalizeLookupOutcome({ ok: false, failure: { kind: 'timeout' } })).toEqual({ kind: 'unresolved', reason: 'timeout' });
    expect(normalizeLookupOutcome({ ok: false, failure: { kind: 'transport' } })).toEqual({ kind: 'unresolved', reason: 'transport' });
  });

  it('maps absent and exact profiles deterministically', () => {
    expect(normalizeLookupOutcome({ ok: true, reply: reply(null) })).toEqual({ kind: 'authoritativeNotFound' });
    expect(normalizeLookupOutcome({ ok: true, reply: reply({ alias: 'Voter', visibility: 'public', signingAddress: 'S', encryptionAddress: 'E' }) })).toEqual({
      kind: 'exactProfile',
      profileAlias: 'Voter',
      visibility: 'public',
    });
  });
});

describe('server scenario contract (Task 6.8)', () => {
  it('publishes the matching HushServerNode TwinTest scenario IDs', () => {
    expect(SERVER_SCENARIO_CONTRACT.feature).toBe('FEAT-008');
    expect(SERVER_SCENARIO_CONTRACT.scenarios.length).toBe(8);
    expect(SERVER_SCENARIO_CONTRACT.scenarios.map((s) => s.id)).toContain('HV-RW-SRV-008');
  });

  it('validates deterministically and rejects tampering', () => {
    expect(validateServerScenarioContract(SERVER_SCENARIO_CONTRACT)).toEqual({ ok: true });
    expect(validateServerScenarioContract({ ...SERVER_SCENARIO_CONTRACT, feature: 'FEAT-009' } as never)).toEqual({ ok: false, code: 'WRONG_FEATURE' });
    const duplicate = { ...SERVER_SCENARIO_CONTRACT, scenarios: [...SERVER_SCENARIO_CONTRACT.scenarios, SERVER_SCENARIO_CONTRACT.scenarios[0]!] };
    expect(validateServerScenarioContract(duplicate)).toEqual({ ok: false, code: 'DUPLICATE_ID' });
    const unknown = { ...SERVER_SCENARIO_CONTRACT, scenarios: [{ ...SERVER_SCENARIO_CONTRACT.scenarios[0]!, id: 'HV-RW-SRV-999' }] };
    expect(validateServerScenarioContract(unknown)).toEqual({ ok: false, code: 'UNKNOWN_SCENARIO' });
  });
});
