import { afterEach, describe, expect, it, vi } from 'vitest';
import type { BrowserVaultClient } from '../../browser-vault/production/client';
import { CreateUserChildRuntime, type BridgeLookupOutcome } from './child-bridge';
import { ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import { resetChildViews, resolveOnboardingChild } from '../../../app/auth/onboarding/onboarding-registry';

const words = [...Array<string>(23).fill('abandon'), 'art'];
const runtimes: CreateUserChildRuntime[] = [];
const signing = 'a'.repeat(66), encryption = 'b'.repeat(66);

async function waiting(admission: 'accepted' | 'pending' = 'accepted') {
  const dispatch = vi.fn(async (operation: string) => {
    if (operation === 'createCandidate') return { outcome: 'OK', payload: { ref: 'candidate-test' } };
    if (operation === 'revealRecovery') return { outcome: 'OK', payload: { words } };
    if (operation === 'provisionFromValidatedBundle') return { outcome: 'OK', payload: { signingAddress: signing, encryptionAddress: encryption } };
    if (operation === 'submitIdentityTransaction') return { outcome: 'OK', payload: { status: admission } };
    return { outcome: 'OK', payload: { words } };
  });
  const lookup = vi.fn<() => Promise<BridgeLookupOutcome>>(async () => ({ kind: 'authoritativeAbsent' }));
  const runtime = new CreateUserChildRuntime({ client: { dispatch, submitSecret: vi.fn(), issueCapability: async () => ({ capabilityId: 'test-cap' }) } as unknown as BrowserVaultClient,
    manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: lookup, randomId: prefix => `${prefix}test` });
  runtimes.push(runtime);
  runtime.onProfileContinue('Alice', 'private');
  await runtime.onGenerate();
  runtime.onAcknowledge(true);
  runtime.onRecoveryContinue();
  const child = resolveOnboardingChild('createUser');
  if (child?.kind !== 'createUser') throw new Error('Missing confirmation');
  runtime.onConfirmVerify(new Map(child.props.confirmPositions.map(position => [position, words[position - 1]])));
  await runtime.onProtect('test-device-password');
  await runtime.onCreateIdentity();
  return { runtime, dispatch, lookup };
}

afterEach(async () => {
  await Promise.all(runtimes.splice(0).map(runtime => runtime.cleanup()));
  resetChildViews(); vi.restoreAllMocks(); vi.useRealTimers();
});

describe('HushVotingApp TwinTests — identity confirmation polling', () => {
  // FEAT-007 AC-007-054 -> Phase 3 Tasks 3.3–3.6, Phase 7 Tasks 7.1/7.2.
  async function failedPromotion() {
    vi.useFakeTimers();
    const result = await waiting();
    const original = result.dispatch.getMockImplementation()!;
    result.dispatch.mockImplementation(async operation => operation === 'promoteLifecycle'
      ? { outcome: 'UNKNOWN_FAILURE', payload: { words } } : original(operation));
    result.lookup.mockResolvedValue({ kind: 'exact', profileName: 'Alice', signingAddress: signing, encryptionAddress: encryption, isPublic: false });
    result.runtime.onCheckAgain();
    await vi.advanceTimersByTimeAsync(0);
    return { ...result, original };
  }

  it('stops automatic network and local retries after promotion storage failure', async () => {
    const { lookup, dispatch } = await failedPromotion();
    const child = resolveOnboardingChild('createUser');
    expect(child?.kind === 'createUser' && child.props.view.error?.code).toBe('PROVISION_FAILED');
    const queries = lookup.mock.calls.length, operations = dispatch.mock.calls.length;
    await vi.advanceTimersByTimeAsync(12_000);
    expect(lookup).toHaveBeenCalledTimes(queries);
    expect(dispatch).toHaveBeenCalledTimes(operations);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('coalesces explicit save retries into only the local promotion operation', async () => {
    const { runtime, lookup, dispatch, original } = await failedPromotion();
    const queries = lookup.mock.calls.length;
    dispatch.mockClear();
    let release!: () => void;
    dispatch.mockImplementation(async operation => {
      if (operation === 'promoteLifecycle') await new Promise<void>(resolve => { release = resolve; });
      return original(operation);
    });
    runtime.onCheckAgain(); runtime.onCheckAgain();
    await vi.advanceTimersByTimeAsync(0);
    expect(lookup).toHaveBeenCalledTimes(queries);
    expect(dispatch.mock.calls.map(([operation]) => operation)).toEqual(['promoteLifecycle']);
    release();
    await vi.advanceTimersByTimeAsync(0);
    const child = resolveOnboardingChild('createUser');
    expect(child?.kind === 'createUser' && child.props.view.screen).toBe('finishCreating');
    expect(vi.getTimerCount()).toBe(0);
  });

  it('ignores a successful late local save after Lock', async () => {
    const { runtime, dispatch, original } = await failedPromotion();
    let release!: () => void;
    dispatch.mockImplementation(async operation => {
      if (operation === 'promoteLifecycle') await new Promise<void>(resolve => { release = resolve; });
      return original(operation);
    });
    runtime.onCheckAgain();
    await vi.advanceTimersByTimeAsync(0);
    runtime.onLock();
    release();
    await vi.advanceTimersByTimeAsync(0);
    const child = resolveOnboardingChild('createUser');
    expect(child?.kind === 'createUser' && child.props.view.screen).toBe('locked');
  });

  // EPIC-001 / FEAT-007 AC-007-041 / Phase 3 Tasks 3.5–3.6.
  it.each(['accepted', 'pending'] as const)('stops at three minutes after %s and keeps manual checks lookup-only', async admission => {
    vi.useFakeTimers();
    const { runtime, lookup, dispatch } = await waiting(admission);
    const screen = () => {
      const child = resolveOnboardingChild('createUser');
      return child?.kind === 'createUser' ? child.props.view.screen : null;
    };
    await vi.advanceTimersByTimeAsync(179_999);
    expect(screen()).toBe('waiting');
    const before = lookup.mock.calls.length;
    await vi.advanceTimersByTimeAsync(1);
    expect(screen()).toBe('delay');
    await vi.advanceTimersByTimeAsync(30_000);
    expect(lookup).toHaveBeenCalledTimes(before);
    runtime.onCheckAgain(); runtime.onCheckAgain();
    await vi.advanceTimersByTimeAsync(0);
    expect(lookup).toHaveBeenCalledTimes(before + 1);
    expect(screen()).toBe('delay');
    await vi.advanceTimersByTimeAsync(30_000);
    expect(lookup).toHaveBeenCalledTimes(before + 1);
    expect(dispatch.mock.calls.filter(call => call[0] === 'submitIdentityTransaction')).toHaveLength(1);
    expect(vi.getTimerCount()).toBe(0);
    lookup.mockResolvedValue({ kind: 'exact', profileName: 'Alice', signingAddress: signing, encryptionAddress: encryption, isPublic: false });
    runtime.onCheckAgain();
    await vi.advanceTimersByTimeAsync(0);
    expect(dispatch.mock.calls.filter(call => call[0] === 'promoteLifecycle')).toHaveLength(1);
    expect(vi.getTimerCount()).toBe(0);
  });

  it.each(['authoritativeAbsent', 'transportFailure'] as const)('a late %s reply cannot restart automatic polling after the deadline', async kind => {
    vi.useFakeTimers();
    const { runtime, lookup } = await waiting();
    await vi.advanceTimersByTimeAsync(177_000);
    let finish!: (outcome: BridgeLookupOutcome) => void;
    lookup.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    runtime.onCheckAgain();
    await vi.advanceTimersByTimeAsync(3_000);
    finish({ kind });
    await vi.advanceTimersByTimeAsync(0);
    const child = resolveOnboardingChild('createUser');
    expect(child?.kind === 'createUser' && child.props.view.screen).toBe('delay');
    const before = lookup.mock.calls.length;
    await vi.advanceTimersByTimeAsync(30_000);
    expect(lookup).toHaveBeenCalledTimes(before);
    expect(vi.getTimerCount()).toBe(0);
  });

  it('revokes authority only once when Lock triggers root cancellation and cleanup', async () => {
    const { runtime, dispatch } = await waiting();
    runtime.onLock();
    runtime.cancel();
    await runtime.cleanup();
    expect(dispatch.mock.calls.filter(call => call[0] === 'lockAll')).toHaveLength(1);
    expect(resolveOnboardingChild('createUser')).toBeNull();
  });

  it('queries every three seconds without submitting another transaction', async () => {
    vi.useFakeTimers();
    const { dispatch, lookup } = await waiting();
    const before = lookup.mock.calls.length;
    await vi.advanceTimersByTimeAsync(2999);
    expect(lookup).toHaveBeenCalledTimes(before);
    await vi.advanceTimersByTimeAsync(1);
    expect(lookup).toHaveBeenCalledTimes(before + 1);
    await vi.advanceTimersByTimeAsync(3000);
    expect(lookup).toHaveBeenCalledTimes(before + 2);
    expect(dispatch.mock.calls.filter(call => call[0] === 'submitIdentityTransaction')).toHaveLength(1);
  });

  it('coalesces manual checks and drops a late exact reply after cleanup', async () => {
    vi.useFakeTimers();
    const { runtime, lookup, dispatch } = await waiting();
    const before = lookup.mock.calls.length;
    let finish!: (outcome: BridgeLookupOutcome) => void;
    lookup.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    runtime.onCheckAgain(); runtime.onCheckAgain();
    await vi.advanceTimersByTimeAsync(3000);
    expect(lookup).toHaveBeenCalledTimes(before + 1);
    await runtime.cleanup();
    finish({ kind: 'exact', profileName: 'Alice', signingAddress: signing, encryptionAddress: encryption, isPublic: false });
    await vi.advanceTimersByTimeAsync(6000);
    expect(dispatch.mock.calls.some(call => call[0] === 'verifyOnlineIdentity' || call[0] === 'promoteLifecycle')).toBe(false);
    expect(resolveOnboardingChild('createUser')).toBeNull();
    expect(vi.getTimerCount()).toBe(0);
  });

  it('pauses while offline or hidden and stops after Lock', async () => {
    vi.useFakeTimers();
    const { runtime, lookup } = await waiting();
    const before = lookup.mock.calls.length;
    const online = vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(false);
    await vi.advanceTimersByTimeAsync(6000);
    expect(lookup).toHaveBeenCalledTimes(before);
    online.mockReturnValue(true);
    const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    await vi.advanceTimersByTimeAsync(6000);
    expect(lookup).toHaveBeenCalledTimes(before);
    visibility.mockReturnValue('visible');
    await vi.advanceTimersByTimeAsync(3000);
    expect(lookup).toHaveBeenCalledTimes(before + 1);
    runtime.onLock();
    await vi.advanceTimersByTimeAsync(6000);
    expect(lookup).toHaveBeenCalledTimes(before + 1);
    expect(vi.getTimerCount()).toBe(0);
  });
});
