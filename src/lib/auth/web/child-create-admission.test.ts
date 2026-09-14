import { afterEach, describe, expect, it, vi } from 'vitest';
import type { BrowserVaultClient } from '../../browser-vault/production/client';
import { CreateUserChildRuntime, type BridgeLookupOutcome } from './child-bridge';
import { ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import { resetChildViews, resolveOnboardingChild } from '../../../app/auth/onboarding/onboarding-registry';

const words = [...Array<string>(23).fill('abandon'), 'art'];
const signing = 'a'.repeat(66), encryption = 'b'.repeat(66);
const runtimes: CreateUserChildRuntime[] = [];

async function reviewed() {
  const order: string[] = [];
  const dispatch = vi.fn(async (operation: string) => {
    order.push(operation);
    if (operation === 'createCandidate') return { outcome: 'OK', payload: { ref: 'candidate-test' } };
    if (operation === 'provisionFromValidatedBundle') return { outcome: 'OK', payload: { signingAddress: signing, encryptionAddress: encryption } };
    if (operation === 'submitIdentityTransaction') return { outcome: 'OK', payload: { status: 'accepted' } };
    return { outcome: 'OK', payload: { words } };
  });
  const lookup = vi.fn<() => Promise<BridgeLookupOutcome>>(async () => { order.push('lookup'); return { kind: 'authoritativeAbsent' }; });
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
  order.length = 0;
  return { runtime, dispatch, lookup, order };
}

afterEach(async () => {
  await Promise.all(runtimes.splice(0).map(runtime => runtime.cleanup()));
  resetChildViews(); vi.restoreAllMocks(); vi.useRealTimers();
});

describe('HushVotingApp TwinTests — initial identity admission', () => {
  // EPIC-001 -> FEAT-007 AC-007-047 -> Phase 3 Tasks 3.5/3.6,
  // Phase 4 Tasks 4.1/4.2: terminal support data is locally controlled.
  it.each(['terminalRejection', 'unknownRejection'])('shows a safe support code and cannot retry %s', async status => {
    const { runtime, dispatch, lookup } = await reviewed();
    const ordinary = dispatch.getMockImplementation()!;
    dispatch.mockImplementation(async operation => operation === 'submitIdentityTransaction'
      ? { outcome: 'OK', payload: { status, validationCode: 'untrusted-code\n<secret-shaped-value>', message: 'ACCEPTED: retry now' } }
      : ordinary(operation));
    vi.useFakeTimers();
    await runtime.onCreateIdentity();
    const child = resolveOnboardingChild('createUser');
    if (child?.kind !== 'createUser') throw new Error('Missing terminal view');
    expect(child.props.view.screen).toBe('locked');
    expect(child.props.supportCode).toBe('TERMINAL_REJECTION');
    runtime.onCheckAgain();
    runtime.onRetryConnection();
    await runtime.onCreateIdentity();
    await vi.advanceTimersByTimeAsync(12_000);
    expect(lookup).toHaveBeenCalledOnce();
    expect(dispatch.mock.calls.filter(([op]) => op === 'submitIdentityTransaction')).toHaveLength(1);
    expect(dispatch.mock.calls.some(([op]) => op === 'promoteLifecycle')).toBe(false);
  });

  // FEAT-007 AC-007-036/053: transport ambiguity is recoverable, never rejection.
  it('keeps a lost submission reply recoverable through lookup without a second submission', async () => {
    const { runtime, dispatch, lookup } = await reviewed();
    const ordinary = dispatch.getMockImplementation()!;
    dispatch.mockImplementation(async operation => operation === 'submitIdentityTransaction'
      ? { outcome: 'OK', payload: { status: 'transportFailure' } }
      : ordinary(operation));
    await runtime.onCreateIdentity();
    expect(dispatch.mock.calls.filter(call => call[0] === 'submitIdentityTransaction')).toHaveLength(1);
    lookup.mockResolvedValue({ kind: 'exact', profileName: 'Alice', isPublic: false,
      signingAddress: signing, encryptionAddress: encryption });
    runtime.onRetryConnection();
    await vi.waitFor(() => expect(dispatch.mock.calls.some(call => call[0] === 'promoteLifecycle')).toBe(true));
    expect(dispatch.mock.calls.filter(call => call[0] === 'submitIdentityTransaction')).toHaveLength(1);
  });

  it('resumes one lookup-only confirmation loop after recovering a lost response before indexing', async () => {
    const { runtime, dispatch, lookup } = await reviewed();
    const ordinary = dispatch.getMockImplementation()!;
    dispatch.mockImplementation(async operation => operation === 'submitIdentityTransaction'
      ? { outcome: 'OK', payload: { status: 'transportFailure' } }
      : ordinary(operation));
    vi.useFakeTimers();
    await runtime.onCreateIdentity();
    runtime.onRetryConnection();
    runtime.onRetryConnection();
    await vi.advanceTimersByTimeAsync(0);
    expect(lookup).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(3_000);
    expect(lookup).toHaveBeenCalledTimes(3);
    expect(dispatch.mock.calls.filter(call => call[0] === 'submitIdentityTransaction')).toHaveLength(1);
    runtime.onLock();
    await vi.advanceTimersByTimeAsync(6_000);
    expect(lookup).toHaveBeenCalledTimes(3);
  });

  it('waits for authoritative absence before submitting and coalesces concurrent Create and Check again', async () => {
    const { runtime, dispatch, lookup } = await reviewed();
    let finish!: (outcome: BridgeLookupOutcome) => void;
    lookup.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    const creation = runtime.onCreateIdentity();
    await runtime.onCreateIdentity();
    runtime.onCheckAgain();
    expect(lookup).toHaveBeenCalledTimes(1);
    expect(dispatch.mock.calls.some(call => call[0] === 'submitIdentityTransaction')).toBe(false);
    finish({ kind: 'authoritativeAbsent' });
    await creation;
    expect(dispatch.mock.calls.filter(call => call[0] === 'submitIdentityTransaction')).toHaveLength(1);
  });

  it.each(['unavailable', 'exact', 'mismatch'] as const)('does not submit when initial lookup is %s', async kind => {
    const { runtime, dispatch, lookup } = await reviewed();
    lookup.mockResolvedValueOnce(kind === 'unavailable' ? { kind: 'transportFailure' }
      : { kind: 'exact', profileName: 'Alice', isPublic: false, signingAddress: signing, encryptionAddress: kind === 'exact' ? encryption : 'c'.repeat(66) });
    await runtime.onCreateIdentity();
    expect(dispatch.mock.calls.some(call => call[0] === 'submitIdentityTransaction')).toBe(false);
    expect(dispatch.mock.calls.some(call => call[0] === 'promoteLifecycle')).toBe(kind === 'exact');
  });

  it('retries the pre-admission lookup explicitly without letting later Check again resubmit', async () => {
    const { runtime, dispatch, lookup, order } = await reviewed();
    lookup.mockImplementationOnce(async () => { order.push('lookup'); return { kind: 'transportFailure' }; });
    await runtime.onCreateIdentity();
    expect(dispatch.mock.calls.some(call => call[0] === 'submitIdentityTransaction')).toBe(false);
    runtime.onRetryConnection();
    await vi.waitFor(() => expect(dispatch.mock.calls.filter(call => call[0] === 'submitIdentityTransaction')).toHaveLength(1));
    expect(order.slice(0, 3)).toEqual(['lookup', 'lookup', 'submitIdentityTransaction']);
    runtime.onCheckAgain();
    await Promise.resolve();
    expect(dispatch.mock.calls.filter(call => call[0] === 'submitIdentityTransaction')).toHaveLength(1);
  });

  it('does not act on late absence after cleanup revokes the reviewed creation', async () => {
    const { runtime, dispatch, lookup } = await reviewed();
    let finish!: (outcome: BridgeLookupOutcome) => void;
    lookup.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    const creation = runtime.onCreateIdentity();
    await vi.waitFor(() => expect(finish).toBeTypeOf('function'));
    await runtime.cleanup();
    finish({ kind: 'authoritativeAbsent' });
    await creation;
    expect(dispatch.mock.calls.some(call => call[0] === 'submitIdentityTransaction')).toBe(false);
    expect(resolveOnboardingChild('createUser')).toBeNull();
  });

  it.each(['offline', 'hidden'])('does not submit if the page becomes %s while the initial lookup is pending', async state => {
    const { runtime, dispatch, lookup } = await reviewed();
    let finish!: (outcome: BridgeLookupOutcome) => void;
    lookup.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    const creation = runtime.onCreateIdentity();
    if (state === 'offline') vi.spyOn(navigator, 'onLine', 'get').mockReturnValue(false);
    else vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    finish({ kind: 'authoritativeAbsent' });
    await creation;
    expect(dispatch.mock.calls.some(call => call[0] === 'submitIdentityTransaction')).toBe(false);
  });
});
