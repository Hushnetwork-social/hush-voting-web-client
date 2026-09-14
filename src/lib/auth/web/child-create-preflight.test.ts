import { afterEach, describe, expect, it, vi } from 'vitest';
import type { BrowserVaultClient } from '../../browser-vault/production/client';
import { CreateUserChildRuntime } from './child-bridge';
import { ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import { resetChildViews, resolveOnboardingChild } from '../../../app/auth/onboarding/onboarding-registry';

// EPIC-001 -> FEAT-007 AC-007-002 -> Phase 6 Tasks 6.1/6.2.
// Fresh custody gating is necessary but does not replace FEAT-004's full
// primitive preflight. HV-ID-CREATE-ENTRY-002 remains pending that wiring.
const runtimes: CreateUserChildRuntime[] = [];
function arrange(dispatch: ReturnType<typeof vi.fn>) {
  const runtime = new CreateUserChildRuntime({
    client: { dispatch } as unknown as BrowserVaultClient,
    manifest: ISOLATED_DEVNET_MANIFEST,
    lookupIdentity: vi.fn(), randomId: prefix => `${prefix}preflight-test`,
  });
  runtimes.push(runtime);
  return runtime;
}
function view() {
  const child = resolveOnboardingChild('createUser');
  if (child?.kind !== 'createUser') throw new Error('Expected creation view');
  return child.props;
}
afterEach(async () => {
  await Promise.all(runtimes.splice(0).map(runtime => runtime.cleanup()));
  resetChildViews(); vi.useRealTimers();
});

describe('HushVotingApp TwinTests — fresh creation preflight custody', () => {
  it('does not report readiness or collect a profile while the authority check is held', async () => {
    vi.useFakeTimers();
    let release!: (value: unknown) => void;
    const dispatch = vi.fn(() => new Promise(resolve => { release = resolve; }));
    const runtime = arrange(dispatch);
    const start = runtime.start();
    await vi.advanceTimersByTimeAsync(1_000);
    expect(view().view.screen).toBe('preflight');
    expect(view().preflightOutcome.kind).not.toBe('passed');
    expect(dispatch).toHaveBeenCalledWith('inspectStartup');
    release({ outcome: 'OK', payload: { surface: 'verifiedAbsent' } });
    await start;
    expect(view().view.screen).toBe('profile');
  });

  it.each(['UNKNOWN_FAILURE', 'TRANSPORT_UNAVAILABLE'])('keeps %s retryable without automatic retries', async outcome => {
    vi.useFakeTimers();
    const dispatch = vi.fn().mockResolvedValueOnce({ outcome })
      .mockResolvedValueOnce({ outcome: 'OK', payload: { surface: 'verifiedAbsent' } });
    const runtime = arrange(dispatch);
    await runtime.start();
    await vi.advanceTimersByTimeAsync(1_000);
    expect(view().view.screen).toBe('preflight');
    expect(view().preflightOutcome.kind).toBe('temporaryUnavailable');
    expect(dispatch).toHaveBeenCalledTimes(1);
    runtime.onRetryPreflight();
    await vi.advanceTimersByTimeAsync(0);
    expect(view().view.screen).toBe('profile');
    expect(dispatch.mock.calls).toEqual([['inspectStartup'], ['inspectStartup']]);
  });

  it.each(['lockedVault', 'removalTombstone', 'quarantine', undefined])('never offers creation when fresh custody is %s', async surface => {
    vi.useFakeTimers();
    const runtime = arrange(vi.fn().mockResolvedValue({ outcome: 'OK', payload: { surface } }));
    await runtime.start();
    await vi.advanceTimersByTimeAsync(1_000);
    expect(view().view.screen).toBe('preflight');
    expect(view().preflightOutcome.kind).toBe('failClosed');
  });

  it('coalesces Retry and discards a late successful check after cleanup', async () => {
    let release!: (value: unknown) => void;
    const dispatch = vi.fn(() => new Promise(resolve => { release = resolve; }));
    const runtime = arrange(dispatch);
    const start = runtime.start();
    runtime.onRetryPreflight();
    runtime.onRetryPreflight();
    expect(dispatch).toHaveBeenCalledTimes(1);
    await runtime.cleanup();
    release({ outcome: 'OK', payload: { surface: 'verifiedAbsent' } });
    await start;
    expect(resolveOnboardingChild('createUser')).toBeNull();
  });
});
