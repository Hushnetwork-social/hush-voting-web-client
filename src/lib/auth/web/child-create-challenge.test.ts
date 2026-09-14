import { afterEach, describe, expect, it, vi } from 'vitest';
import type { BrowserVaultClient } from '../../browser-vault/production/client';
import { CreateUserChildRuntime } from './child-bridge';
import { ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import { resetChildViews, resolveOnboardingChild } from '../../../app/auth/onboarding/onboarding-registry';

// HushVotingApp TwinTests: exercise the delivered bridge with a controlled worker port.
const words = [...Array<string>(23).fill('abandon'), 'art'];
const runtimes = new Set<CreateUserChildRuntime>();
function view() {
  const child = resolveOnboardingChild('createUser');
  if (child?.kind !== 'createUser') throw new Error('Missing create view');
  return child.props;
}
async function setup() {
  const dispatch = vi.fn(async (operation: string) => operation === 'createCandidate'
    ? { outcome: 'OK', payload: { ref: 'candidate-test' } }
    : { outcome: 'OK', payload: { words } });
  const issueCapability = vi.fn();
  const runtime = new CreateUserChildRuntime({
    client: { dispatch, issueCapability } as unknown as BrowserVaultClient,
    manifest: ISOLATED_DEVNET_MANIFEST,
    lookupIdentity: async () => ({ kind: 'transportFailure' }),
    randomId: (prefix) => `${prefix}test`,
  });
  runtimes.add(runtime);
  runtime.onProfileContinue('Alice', 'private');
  await runtime.onGenerate();
  return { runtime, dispatch, issueCapability };
}
afterEach(() => {
  for (const runtime of runtimes) void runtime.cleanup();
  runtimes.clear();
  resetChildViews();
});

describe('creation bridge recovery confirmation', () => {
  it('conceals the published recovery phrase at the sixty-second deadline', async () => {
    vi.useFakeTimers();
    try {
      const { runtime } = await setup();
      await vi.advanceTimersByTimeAsync(59_999);
      expect(revealedWordCount(view())).toBe(24);
      await vi.advanceTimersByTimeAsync(1);
      expect(revealedWordCount(view())).toBe(0);
      runtime.onReviewAll();
      await vi.advanceTimersByTimeAsync(0);
      expect(revealedWordCount(view())).toBe(24);
      expect(view().recoveryAcknowledged).toBe(false);
      await vi.advanceTimersByTimeAsync(60_000);
      expect(revealedWordCount(view())).toBe(0);
      await runtime.cleanup();
    } finally { vi.useRealTimers(); }
  });

  it('removes the reveal before asynchronous candidate destruction finishes', async () => {
    const { runtime, dispatch } = await setup();
    dispatch.mockImplementationOnce(() => new Promise<never>(() => undefined));
    void runtime.cleanup();
    expect(resolveOnboardingChild('createUser')).toBeNull();
  });
  it('Lock revokes the real worker authority instead of only replacing the screen', async () => {
    const { runtime, dispatch } = await setup();
    runtime.onLock();
    await Promise.resolve();
    expect(dispatch).toHaveBeenCalledWith('lockAll');
    expect(revealedWordCount(view())).toBe(0);
  });
  it('cannot advance or provision before acknowledgement and the six-word challenge', async () => {
    const { runtime, issueCapability } = await setup();
    runtime.onRecoveryContinue();
    expect(view().view.screen).toBe('recovery');
    await runtime.onProtect('test-device-password');
    expect(issueCapability).not.toHaveBeenCalled();
  });

  it('renders six distinct requested positions without retaining revealed words in the publication', async () => {
    const { runtime } = await setup();
    runtime.onAcknowledge(true);
    runtime.onRecoveryContinue();
    expect(view().view.screen).toBe('confirmRecovery');
    expect(view().confirmPositions).toHaveLength(6);
    expect(new Set(view().confirmPositions).size).toBe(6);
    expect(view().confirmPositions.every(p => p >= 1 && p <= 24)).toBe(true);
    expect(revealedWordCount(view())).toBe(0);
    runtime.onConfirmVerify(new Map(view().confirmPositions.map(p => [p, words[p - 1]])));
    expect(view().view.screen).toBe('protect');
  });

  it('reports only a mismatched position and closes the third failed challenge without regeneration', async () => {
    const { runtime, dispatch } = await setup();
    runtime.onAcknowledge(true);
    runtime.onRecoveryContinue();
    const positions = view().confirmPositions;
    const answers = new Map(positions.map(p => [p, words[p - 1]]));
    answers.set(positions[0], 'incorrect');
    runtime.onConfirmVerify(answers);
    expect(view().view.screen).toBe('confirmRecovery');
    expect(view().confirmMismatchPosition).toBe(positions[0]);
    expect(view().view.error?.message).not.toContain(words[positions[0] - 1]);
    runtime.onConfirmVerify(answers);
    runtime.onConfirmVerify(answers);
    expect(view().view.screen).toBe('confirmRecovery');
    expect(view().confirmChallengeClosed).toBe(true);
    expect(revealedWordCount(view())).toBe(0);
    runtime.onConfirmVerify(new Map(positions.map(p => [p, words[p - 1]])));
    expect(view().view.screen).toBe('confirmRecovery');
    expect(dispatch.mock.calls.filter(([operation]) => operation === 'createCandidate')).toHaveLength(1);
  });
});

function revealedWordCount(child: ReturnType<typeof view>) {
  const target = document.createElement('ol');
  const detach = child.recoveryDisplay.attach(target);
  try { return target.children.length; } finally { detach(); }
}
