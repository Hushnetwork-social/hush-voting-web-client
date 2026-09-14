import { afterEach, describe, expect, it, vi } from 'vitest';
import type { BrowserVaultClient } from '../../browser-vault/production/client';
import { CredentialFileChildRuntime } from './child-bridge';
import { ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import { resetChildViews, resolveOnboardingChild } from '../../../app/auth/onboarding/onboarding-registry';

// EPIC-001 -> FEAT-009 AC-009-001 -> Phase 3 Tasks 3.1/3.2.
const runtimes: CredentialFileChildRuntime[] = [];
function arrange(dispatch: ReturnType<typeof vi.fn>) {
  const submitSecret = vi.fn();
  const runtime = new CredentialFileChildRuntime({
    client: { dispatch, submitSecret } as unknown as BrowserVaultClient,
    manifest: ISOLATED_DEVNET_MANIFEST, lookupIdentity: vi.fn(), randomId: prefix => `${prefix}entry-test`,
  });
  runtimes.push(runtime);
  return { runtime, submitSecret };
}
function screen() {
  const child = resolveOnboardingChild('restoreCredentialFile');
  if (child?.kind !== 'credentialFile') throw new Error('Expected file child');
  return child.props.view.screen;
}
afterEach(async () => {
  await Promise.all(runtimes.splice(0).map(runtime => runtime.cleanup()));
  resetChildViews();
});

describe('HushVotingApp TwinTests — credential entry custody', () => {
  it('waits for fresh verified absence and coalesces checks before accepting a source', async () => {
    let release!: (value: unknown) => void;
    const dispatch = vi.fn(() => new Promise(resolve => { release = resolve; }));
    const { runtime, submitSecret } = arrange(dispatch);
    const slice = vi.fn();
    const pending = runtime.start();
    const duplicate = runtime.start();
    await runtime.onChooseFile({ size: 52, slice } as unknown as File);
    expect(screen()).toBe('capabilityPreflight');
    expect(slice).not.toHaveBeenCalled();
    expect(submitSecret).not.toHaveBeenCalled();
    expect(dispatch).toHaveBeenCalledExactlyOnceWith('inspectStartup');
    release({ outcome: 'OK', payload: { surface: 'verifiedAbsent' } });
    await Promise.all([pending, duplicate]);
    expect(screen()).toBe('picker');
  });

  it.each([
    { outcome: 'OK', payload: { surface: 'lockedVault' } },
    { outcome: 'OK', payload: { surface: 'quarantine' } },
    { outcome: 'OK', payload: { surface: 'removalTombstone' } },
    { outcome: 'OK' },
    { outcome: 'CORRUPT_VAULT' },
    { outcome: 'AUTHORITY_BUSY' },
    { outcome: 'UNKNOWN_FAILURE' },
    { outcome: 'TRANSPORT_UNAVAILABLE' },
  ])('blocks the picker and source reads for nonempty or unresolved custody: %j', async result => {
    const { runtime, submitSecret } = arrange(vi.fn().mockResolvedValue(result));
    await runtime.start();
    const slice = vi.fn();
    await runtime.onChooseFile({ size: 52, slice } as unknown as File);
    expect(screen()).toBe('terminal');
    expect(slice).not.toHaveBeenCalled();
    expect(submitSecret).not.toHaveBeenCalled();
  });

  it('cannot reopen a picker from a late successful inspection after cleanup', async () => {
    let release!: (value: unknown) => void;
    const dispatch = vi.fn(() => new Promise(resolve => { release = resolve; }));
    const { runtime } = arrange(dispatch);
    const pending = runtime.start();
    await runtime.cleanup();
    expect(dispatch).toHaveBeenCalledWith('inspectStartup');
    release({ outcome: 'OK', payload: { surface: 'verifiedAbsent' } });
    await pending;
    await runtime.start();
    expect(resolveOnboardingChild('restoreCredentialFile')).toBeNull();
    expect(dispatch).toHaveBeenCalledOnce();
  });
});
