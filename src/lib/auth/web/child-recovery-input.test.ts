import { afterEach, describe, expect, it, vi } from 'vitest';
import type { BrowserVaultClient } from '../../browser-vault/production/client';
import { RecoveryWordsChildRuntime, createBridgeBffLookup } from './child-bridge';
import { ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import { resetChildViews, resolveOnboardingChild } from '../../../app/auth/onboarding/onboarding-registry';

afterEach(() => { resetChildViews(); vi.unstubAllGlobals(); vi.useRealTimers(); vi.restoreAllMocks(); });

function view() {
  const child = resolveOnboardingChild('restoreRecoveryWords');
  if (child?.kind !== 'recoveryWords') throw new Error('Missing recovery view');
  return child.props;
}

// Post-entry tests arrange verified absence; recovery-entry.test.ts exercises the guard.
function runtimeWithEmptyCustody(context: ConstructorParameters<typeof RecoveryWordsChildRuntime>[0]) {
  const client = {
    ...context.client,
    dispatch(operation: Parameters<BrowserVaultClient['dispatch']>[0], ...args: Tail<Parameters<BrowserVaultClient['dispatch']>>) {
      if (operation === 'inspectStartup') return Promise.resolve({ outcome: 'OK', payload: { surface: 'verifiedAbsent' } });
      return context.client.dispatch(operation, ...args);
    },
  } as BrowserVaultClient;
  return new RecoveryWordsChildRuntime({ ...context, client });
}
type Tail<T extends unknown[]> = T extends [unknown, ...infer Rest] ? Rest : never;

describe('HushVotingApp TwinTests — recovery input errors', () => {
  // EPIC-001 -> FEAT-008 AC-008-051 -> Phase 3 Tasks 3.5/3.6,
  // Phase 6 Tasks 6.1/6.2. Projection evidence only, not authority custody proof.
  it('offers explicit session-only recovery after confirming an exact profile', async () => {
    const candidate = { ref: 'candidate', signingAddress: 'public-signing', encryptionAddress: 'public-encryption', producerIds: ['P-01'] };
    const dispatch = vi.fn(async (operation: string) => operation === 'deriveRecoveryCandidates'
      ? { outcome: 'OK', payload: { candidates: [candidate] } } : { outcome: 'OK' });
    const runtime = runtimeWithEmptyCustody({ client: { dispatch, submitSecret: vi.fn() } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: async () => ({ kind: 'exact', profileName: 'Alice',
        signingAddress: candidate.signingAddress, encryptionAddress: candidate.encryptionAddress, isPublic: false }), randomId: prefix => `${prefix}test` });
    try {
      await runtime.start();
      await runtime.onVerify([...Array<string>(23).fill('abandon'), 'art'].join(' '));
      await runtime.onConfirmExistingProfile();
      expect(view().view.screen).toBe('protection');
      expect(view().protection?.defaultPasswordChecked).toBe(true);
      expect(view().protection?.allowedModes).toContain('sessionOnly');
      expect(view().protection?.sessionOnlyAcknowledgementRequired).toBe(true);
    } finally { await runtime.cleanup(); }
  });

  // EPIC-001 -> FEAT-008 AC-008-064 -> Phase 3 Tasks 3.9/3.10; FEAT evidence only.
  it.each(['input', 'verified', 'staged'] as const)('cleans up the %s recovery boundary without deleting protected storage', async boundary => {
    const candidates = ['first', 'second'].map(ref => ({ ref, signingAddress: `${ref}-sign`, encryptionAddress: `${ref}-encrypt`, producerIds: ['P-01'] }));
    const dispatch = vi.fn(async (operation: string) => {
      if (operation === 'deriveRecoveryCandidates') return { outcome: 'OK', payload: { candidates } };
      if (operation === 'submitIdentityTransaction') return { outcome: 'OK', payload: { status: 'accepted' } };
      return { outcome: 'OK' };
    });
    const runtime = runtimeWithEmptyCustody({ client: { dispatch, submitSecret: vi.fn(), issueCapability: async () => ({ capabilityId: 'cap' }) } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: async () => ({ kind: 'authoritativeAbsent' }), randomId: prefix => `${prefix}test` });
    await runtime.start();
    if (boundary !== 'input') await runtime.onVerify([...Array<string>(23).fill('abandon'), 'art'].join(' '));
    if (boundary === 'staged') {
      runtime.onSelectCandidate(0);
      await runtime.onConfirmExistingProfile();
      await runtime.onConfirmRecreate('Recovered', 'private');
      view().onAcknowledgeProtection();
      await runtime.onProtect('device-password');
      expect(view().view.screen).toBe('registration');
    }
    dispatch.mockClear();
    await Promise.all([runtime.cleanup(), runtime.cleanup()]);
    expect(dispatch.mock.calls).toEqual(boundary === 'input' ? [] : boundary === 'verified'
      ? [['destroyCandidate', { candidateRef: 'first' }], ['destroyCandidate', { candidateRef: 'second' }]]
      : [['lockAll']]);
  });

  it('polls a staged registration every three seconds, coalesces Check again, and stops on cleanup', async () => {
    vi.useFakeTimers();
    vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('visible');
    vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(true);
    let finishVerify!: (value: unknown) => void;
    const dispatch = vi.fn((operation: string) => {
      if (operation === 'deriveRecoveryCandidates') return Promise.resolve({ outcome: 'OK', payload: { candidates: [{ ref: 'candidate', signingAddress: 's'.repeat(66), encryptionAddress: 'e'.repeat(66), producerIds: ['P-01'] }] } });
      if (operation === 'submitIdentityTransaction') return Promise.resolve({ outcome: 'OK', payload: { status: 'accepted' } });
      if (operation === 'verifyOnlineIdentity') return new Promise(resolve => { finishVerify = resolve; });
      return Promise.resolve({ outcome: 'OK' });
    });
    const runtime = runtimeWithEmptyCustody({ client: { submitSecret: vi.fn(), dispatch, issueCapability: async () => ({ capabilityId: 'cap' }) } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: async () => ({ kind: 'authoritativeAbsent' }), randomId: prefix => `${prefix}test` });
    await runtime.start();
    await runtime.onVerify([...Array<string>(23).fill('abandon'), 'art'].join(' '));
    await runtime.onConfirmExistingProfile();
    runtime.onConfirmRecreate('Recovered', 'private');
    view().onAcknowledgeProtection();
    await runtime.onProtect('device-password');
    expect(view().view.screen).toBe('registration');
    await vi.advanceTimersByTimeAsync(2999);
    expect(dispatch.mock.calls.filter(([op]) => op === 'verifyOnlineIdentity')).toHaveLength(0);
    await vi.advanceTimersByTimeAsync(1);
    expect(dispatch.mock.calls.filter(([op]) => op === 'verifyOnlineIdentity')).toHaveLength(1);
    await runtime.onCheckAgain();
    expect(dispatch.mock.calls.filter(([op]) => op === 'verifyOnlineIdentity')).toHaveLength(1);
    finishVerify({ outcome: 'PROFILE_MISSING' });
    await vi.advanceTimersByTimeAsync(3000);
    expect(dispatch.mock.calls.filter(([op]) => op === 'verifyOnlineIdentity')).toHaveLength(2);
    const cleanup = runtime.cleanup();
    finishVerify({ outcome: 'OK' });
    await cleanup;
    await vi.advanceTimersByTimeAsync(9000);
    expect(dispatch.mock.calls.filter(([op]) => op === 'verifyOnlineIdentity')).toHaveLength(2);
    expect(dispatch.mock.calls.filter(([op]) => op === 'promoteLifecycle')).toHaveLength(0);
    expect(dispatch.mock.calls.filter(([op]) => op === 'submitIdentityTransaction')).toHaveLength(1);
  });

  it('copies only an explicitly revealed candidate public address and revokes copying on concealment', async () => {
    const writeText = vi.fn(async () => undefined);
    vi.stubGlobal('navigator', { clipboard: { writeText } });
    const candidates = [{ ref: 'candidate', signingAddress: 'public-signing', encryptionAddress: 'public-encryption', producerIds: ['P-01'] }];
    const runtime = runtimeWithEmptyCustody({ client: { submitSecret: vi.fn(), dispatch: vi.fn(async () => ({ outcome: 'OK', payload: { candidates } })) } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: async () => ({ kind: 'authoritativeAbsent' }), randomId: prefix => `${prefix}test` });
    await runtime.start();
    await runtime.onVerify([...Array<string>(23).fill('abandon'), 'art'].join(' '));
    view().onCopyAddress('public-signing');
    expect(writeText).not.toHaveBeenCalled();
    view().onReveal(0);
    view().onCopyAddress('arbitrary-private-material');
    expect(writeText).not.toHaveBeenCalled();
    view().onCopyAddress('public-signing');
    view().onCopyAddress('public-encryption');
    expect(writeText.mock.calls).toEqual([['public-signing'], ['public-encryption']]);
    view().onReveal(null);
    view().onCopyAddress('public-signing');
    expect(writeText).toHaveBeenCalledTimes(2);
    await runtime.cleanup();
  });

  // FEAT-009 AC-009-041 / Phase 3 Tasks 3.5/3.6; FEAT-008 AC-008-035.
  // This gross-response probe does not define the missing historical size limit.
  it('fails closed on a gross oversized historical profile response', async () => {
    const lookup = createBridgeBffLookup(async () => new Response(JSON.stringify({ reply: {
      successfull: true, profileName: 'x'.repeat(65_536), publicSigningAddress: '02aa',
      publicEncryptAddress: '03bb', isPublic: false,
    } }), { status: 200 }));
    const outcome = await lookup('02aa');
    // Boolean assertion keeps oversized response values out of diagnostics.
    expect(outcome.kind === 'transportFailure').toBe(true);
  });

  it.each([{}, { reply: null }, { reply: {} }, { reply: { successfull: true } }])('does not expose profile recreation for a malformed lookup response', async payload => {
    const lookup = createBridgeBffLookup(async () => new Response(JSON.stringify(payload), { status: 200 }));
    await expect(lookup('public-test-signing-address')).resolves.toEqual({ kind: 'transportFailure' });
  });
  it.each(['UNKNOWN_WORD', 'INVALID_CHECKSUM'])('retains the correction grid after %s without starting server lookup', async (reason) => {
    const dispatch = vi.fn(async () => ({ outcome: 'INVALID_INPUT', payload: { reason, invalidPositions: reason === 'UNKNOWN_WORD' ? [3] : [] } }));
    const submitSecret = vi.fn();
    const lookupIdentity = vi.fn();
    const runtime = runtimeWithEmptyCustody({
      client: { dispatch, submitSecret } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity, randomId: prefix => `${prefix}test`,
    });
    await runtime.start();
    runtime.onSelectCount('12');
    await runtime.onVerify(Array<string>(12).fill('abandon').join(' '));
    expect(dispatch).toHaveBeenCalledWith('deriveRecoveryCandidates', { wordCount: 12 }, undefined, expect.any(String));
    expect(view().view.screen).toBe('wordEntry');
    expect(view().wordGrid?.canVerify).toBe(true);
    expect(view().wordGrid?.invalidPositions).toEqual(reason === 'UNKNOWN_WORD' ? [3] : []);
    expect(view().wordGrid?.checksumState).toBe(reason === 'INVALID_CHECKSUM' ? 'failed' : 'notRun');
    expect(lookupIdentity).not.toHaveBeenCalled();
    await runtime.cleanup();
  });

  it('checks all candidates before showing a match and requires explicit confirmation', async () => {
    const candidates = [
      { ref: 'web', signingAddress: 'web-signing-address', encryptionAddress: 'web-encryption-address', producerIds: ['P-01'] },
      { ref: 'legacy', signingAddress: 'legacy-signing-address', encryptionAddress: 'legacy-encryption-address', producerIds: ['P-02', 'P-03'] },
    ];
    const dispatch = vi.fn(async (operation: string) => operation === 'deriveRecoveryCandidates' ? { outcome: 'OK', payload: { candidates } } : { outcome: 'OK' });
    const lookupIdentity = vi.fn(async (signingAddress: string) => signingAddress === candidates[0].signingAddress
      ? { kind: 'exact' as const, profileName: 'Alice', signingAddress, encryptionAddress: candidates[0].encryptionAddress, isPublic: true }
      : { kind: 'authoritativeAbsent' as const });
    const runtime = runtimeWithEmptyCustody({ client: { dispatch, submitSecret: vi.fn() } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity, randomId: prefix => `${prefix}test` });
    await runtime.start();
    await runtime.onVerify([...Array<string>(23).fill('abandon'), 'art'].join(' '));
    expect(lookupIdentity.mock.calls.map(([address]) => address)).toEqual(candidates.map(candidate => candidate.signingAddress));
    expect(view().candidateReview?.outcome).toBe('exactlyOneExisting');
    expect(view().candidateReview?.entries).toHaveLength(1);
    expect(view().candidateReview?.entries[0]).toMatchObject({ profileAlias: 'Alice', visibility: 'public', selected: false });
    expect(dispatch).not.toHaveBeenCalledWith('destroyCandidate', expect.anything());
    await runtime.onConfirmExistingProfile();
    expect(view().view.screen).toBe('protection');
    expect(dispatch).toHaveBeenCalledWith('destroyCandidate', { candidateRef: 'legacy' });
    await runtime.cleanup();
  });

  it('does not offer a partial match when another candidate lookup fails', async () => {
    const candidates = ['one', 'two'].map(ref => ({ ref, signingAddress: `${ref}-sign`, encryptionAddress: `${ref}-encrypt`, producerIds: ['P-01'] }));
    const dispatch = vi.fn(async () => ({ outcome: 'OK', payload: { candidates } }));
    const lookupIdentity = vi.fn(async (signingAddress: string) => signingAddress === 'one-sign'
      ? { kind: 'exact' as const, profileName: 'Alice', signingAddress, encryptionAddress: 'one-encrypt', isPublic: false }
      : { kind: 'transportFailure' as const });
    const runtime = runtimeWithEmptyCustody({ client: { dispatch, submitSecret: vi.fn() } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity, randomId: prefix => `${prefix}test` });
    await runtime.start();
    await runtime.onVerify([...Array<string>(23).fill('abandon'), 'art'].join(' '));
    expect(view().candidateReview).toBeNull();
    expect(view().view.error?.code).toBe('NETWORK_UNAVAILABLE');
    expect(view().lookupProgress).toEqual({ done: 1, total: 2 });
    await runtime.cleanup();
  });

  it('makes cleanup idempotent and never clears a newer recovery view when old destruction completes', async () => {
    let finish!: (value: { outcome: string }) => void;
    const destruction = new Promise<{ outcome: string }>(resolve => { finish = resolve; });
    const dispatch = vi.fn(async (operation: string) => operation === 'destroyCandidate' ? destruction
      : { outcome: 'OK', payload: { candidates: [{ ref: 'old-candidate', signingAddress: 'old-sign', encryptionAddress: 'old-encrypt', producerIds: ['P-01'] }] } });
    const context = { client: { dispatch, submitSecret: vi.fn() } as unknown as BrowserVaultClient,
      manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: async () => ({ kind: 'authoritativeAbsent' as const }), randomId: (prefix: string) => `${prefix}test` };
    const old = runtimeWithEmptyCustody(context);
    await old.start();
    await old.onVerify([...Array<string>(23).fill('abandon'), 'art'].join(' '));
    const firstCleanup = old.cleanup();
    const current = runtimeWithEmptyCustody(context);
    await current.start();
    const secondCleanup = old.cleanup();
    expect(view().view.screen).toBe('wordEntry');
    finish({ outcome: 'OK' });
    await Promise.all([firstCleanup, secondCleanup]);
    expect(view().view.screen).toBe('wordEntry');
    expect(dispatch.mock.calls.filter(([operation]) => operation === 'destroyCandidate')).toHaveLength(1);
    await current.cleanup();
  });
});
