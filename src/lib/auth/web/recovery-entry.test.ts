import { afterEach, describe, expect, it, vi } from 'vitest';
import type { BrowserVaultClient } from '../../browser-vault/production/client';
import { RecoveryWordsChildRuntime } from './child-bridge';
import { ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import { resetChildViews, resolveOnboardingChild } from '../../../app/auth/onboarding/onboarding-registry';

// EPIC-001 -> FEAT-008 AC-008-001 -> Phase 5 Tasks 5.7/5.8,
// Phase 6 Tasks 6.1/6.2. Isolated FEAT evidence only.
const runtimes: RecoveryWordsChildRuntime[] = [];
const phrase = [...Array<string>(23).fill('abandon'), 'art'].join(' ');
function arrange(dispatch: ReturnType<typeof vi.fn>) {
  const submitSecret = vi.fn();
  const runtime = new RecoveryWordsChildRuntime({ client: { dispatch, submitSecret } as unknown as BrowserVaultClient,
    manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: vi.fn(), randomId: prefix => `${prefix}entry-test` });
  runtimes.push(runtime);
  return { runtime, submitSecret };
}
function view() {
  const child = resolveOnboardingChild('restoreRecoveryWords');
  if (child?.kind !== 'recoveryWords') throw new Error('Expected recovery child');
  return child.props;
}
afterEach(async () => {
  await Promise.all(runtimes.splice(0).map(runtime => runtime.cleanup()));
  resetChildViews();
});

describe('HushVotingApp TwinTests — recovery entry custody', () => {
  it('coalesces fresh inspection and cannot transfer a phrase while custody is unresolved', async () => {
    let release!: (result: unknown) => void;
    const dispatch = vi.fn(() => new Promise(resolve => { release = resolve; }));
    const { runtime, submitSecret } = arrange(dispatch);
    const start = runtime.start();
    const duplicate = runtime.start();
    expect(view().view.screen).toBe('vaultGuard');
    expect(view().wordGrid).toBeNull();
    await runtime.onVerify(phrase);
    expect(submitSecret).not.toHaveBeenCalled();
    expect(dispatch).toHaveBeenCalledExactlyOnceWith('inspectStartup');
    release({ outcome: 'OK', payload: { surface: 'verifiedAbsent' } });
    await Promise.all([start, duplicate]);
    expect(view().view.screen).toBe('wordEntry');
  });

  it.each([
    { outcome: 'OK', payload: { surface: 'lockedVault' } },
    { outcome: 'OK', payload: { surface: 'quarantine' } },
    { outcome: 'OK', payload: { surface: 'removalTombstone' } },
    { outcome: 'OK' }, { outcome: 'CORRUPT_VAULT' }, { outcome: 'AUTHORITY_BUSY' },
    { outcome: 'UNKNOWN_FAILURE' }, { outcome: 'TRANSPORT_UNAVAILABLE' },
  ])('blocks phrase input and derivation for nonempty or unresolved custody: %j', async result => {
    const dispatch = vi.fn().mockResolvedValue(result);
    const { runtime, submitSecret } = arrange(dispatch);
    await runtime.start();
    await runtime.onVerify(phrase);
    expect(view().view.screen).toBe('vaultGuard');
    expect(view().view.error?.code).toBe('VAULT_NOT_VERIFIED_EMPTY');
    expect(view().wordGrid).toBeNull();
    expect(submitSecret).not.toHaveBeenCalled();
    expect(dispatch).toHaveBeenCalledExactlyOnceWith('inspectStartup');
  });

  it('requires another actual inspection on Retry instead of opening word entry', async () => {
    const dispatch = vi.fn().mockResolvedValueOnce({ outcome: 'AUTHORITY_BUSY' })
      .mockResolvedValueOnce({ outcome: 'OK', payload: { surface: 'lockedVault' } })
      .mockResolvedValueOnce({ outcome: 'OK', payload: { surface: 'verifiedAbsent' } });
    const { runtime } = arrange(dispatch);
    await runtime.start();
    runtime.onRetry();
    await vi.waitFor(() => expect(view().view.error?.code).toBe('VAULT_NOT_VERIFIED_EMPTY'));
    expect(view().wordGrid).toBeNull();
    runtime.onRetry();
    await vi.waitFor(() => expect(view().view.screen).toBe('wordEntry'));
    expect(dispatch.mock.calls).toEqual([['inspectStartup'], ['inspectStartup'], ['inspectStartup']]);
  });

  it('ignores late success and subsequent Retry after cleanup revokes entry', async () => {
    let release!: (result: unknown) => void;
    const dispatch = vi.fn(() => new Promise(resolve => { release = resolve; }));
    const { runtime } = arrange(dispatch);
    const start = runtime.start();
    await runtime.cleanup();
    expect(dispatch).toHaveBeenCalledWith('inspectStartup');
    release({ outcome: 'OK', payload: { surface: 'verifiedAbsent' } });
    await start;
    runtime.onRetry();
    expect(resolveOnboardingChild('restoreRecoveryWords')).toBeNull();
    expect(dispatch).toHaveBeenCalledOnce();
  });
});
