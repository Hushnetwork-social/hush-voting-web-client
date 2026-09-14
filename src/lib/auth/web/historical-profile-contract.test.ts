// EPIC-001 -> FEAT-009 AC-009-041 / FEAT-008 AC-008-035;
// FEAT-009 Phase 3 Tasks 3.5/3.6, Phase 6 Tasks 6.1/6.2.
// Existing successful-profile boolean contract, not a new historical size limit.
import { describe, expect, it } from 'vitest';
import { createBridgeBffLookup } from './child-bridge';
import { normalizeGetIdentityReply } from '../../identity-creation/wire';
import { createWorkerBffIdentityLookup } from '../../browser-vault/production/worker-env';

const signing = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';
const encryption = '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5';

function reply(isPublic: unknown) {
  return { successfull: true, message: '', profileName: 'Historical profile',
    publicSigningAddress: signing, publicEncryptAddress: encryption, isPublic };
}

describe('HushVotingApp Twins — historical profile visibility contract', () => {
  it.each([undefined, null, 0, 'false', {}, []])('rejects non-boolean visibility %# without granting absence or a usable profile', async isPublic => {
    const payload = reply(isPublic);
    // The existing wire normalizer already defines this as malformed success.
    expect(normalizeGetIdentityReply(payload as never, signing, encryption).kind).toBe('malformedSuccess');
    const lookup = createBridgeBffLookup(async () => new Response(JSON.stringify({ reply: payload }), { status: 200 }));
    expect((await lookup(signing)).kind).toBe('transportFailure');
  });

  it.each([false, true])('preserves valid historical visibility %s', async isPublic => {
    const lookup = createBridgeBffLookup(async () => new Response(JSON.stringify({ reply: reply(isPublic) }), { status: 200 }));
    expect(await lookup(signing)).toEqual({ kind: 'exact', profileName: 'Historical profile',
      signingAddress: signing, encryptionAddress: encryption, isPublic });
  });

  it.each([undefined, null, 0, 'false', {}, []])('rejects non-boolean visibility %# at the worker lookup boundary', async isPublic => {
    const lookup = createWorkerBffIdentityLookup(async () => new Response(JSON.stringify({ reply: reply(isPublic) }), { status: 200 }));
    expect((await lookup(signing)).kind).toBe('unavailable');
  });

  it.each([false, true])('preserves worker visibility %s', async isPublic => {
    const lookup = createWorkerBffIdentityLookup(async () => new Response(JSON.stringify({ reply: reply(isPublic) }), { status: 200 }));
    expect(await lookup(signing)).toEqual({ kind: 'exact', profileName: 'Historical profile',
      signingAddress: signing, encryptionAddress: encryption, visibility: isPublic ? 'public' : 'private' });
  });
});
