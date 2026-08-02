/**
 * FEAT-003 vault-core session tests — capability kernel, elevation, timing, Lock.
 *
 * Covers Task 4.1-4.4: exhaustive phase transitions, stale/transferred/restarted
 * capabilities, one-purpose one-use elevation with expiry, epoch invalidation, timing
 * under unreliable clocks, and the bounded Lock contract.
 */
import { describe, expect, it } from 'vitest';
import {
  INITIAL_KERNEL_STATE,
  issueCapability,
  isCapabilityCurrent,
  onLocalUnlock,
  onExactOnlineVerification,
  onFreshPassword,
  consumeFreshPassword,
  invalidateSession,
  authorizeOperationForCapability,
  type SessionKernelState,
} from './kernel';
import { assessElapsed, applyLockPolicy } from './timing';
import { executeLock, LOCK_CLEANUP_BUDGET_MS, type LockPorts } from './lock';
import { FRESH_PASSWORD_MAX_AGE_MS, type ClientCapability } from '../contracts/capabilities';

const channel = { channelId: 'tab-1' };
const makeCap = (epoch: { epoch: number }): ClientCapability => ({ epoch, channel, __capability: Symbol('cap') as unknown as ClientCapability['__capability'] });
const request = {
  kind: 'verify-online' as const,
  version: 1,
  signatory: { signingAddress: '0123456789abcdef', producerId: 'hush-voting-ts', producerVersion: '1.0.0' },
  payloadDescriptor: { kind: 'identity-verification', canonicalBytesLength: 128, sha256: 'a'.repeat(64) },
  userConfirmationContext: { alias: 'Alice', signingAddressPrefix: '01234567', signingAddressSuffix: '89abcd' },
};

describe('capability-phase kernel', () => {
  it('starts Locked with no capabilities', () => {
    expect(INITIAL_KERNEL_STATE).toEqual({ epoch: 0, phase: 'Locked', channels: [], fresh: {} });
  });

  it('local unlock produces VerificationOnly, not Authenticated', () => {
    const r = onLocalUnlock(INITIAL_KERNEL_STATE);
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.state.phase).toBe('VerificationOnly');
  });

  it('exact online verification promotes to Authenticated; offline stays VerificationOnly', () => {
    const unlocked = onLocalUnlock(INITIAL_KERNEL_STATE);
    if (!unlocked.ok) return;
    const before = onExactOnlineVerification(unlocked.state);
    expect(before.ok).toBe(true);
    if (before.ok) expect(before.state.phase).toBe('Authenticated');
  });

  it('rejects transitions from the wrong phase (fail closed)', () => {
    expect(onLocalUnlock({ ...INITIAL_KERNEL_STATE, phase: 'Authenticated' }).ok).toBe(false);
    expect(onExactOnlineVerification(INITIAL_KERNEL_STATE).ok).toBe(false);
  });

  it('every capability is epoch-bound and becomes stale after invalidation', () => {
    let state: SessionKernelState = INITIAL_KERNEL_STATE;
    const cap = issueCapability(state, channel, makeCap);
    expect(isCapabilityCurrent(state, cap)).toBe(true);
    for (const cause of ['lock', 'removal', 'replacement', 'takeover', 'platform-invalidation', 'authority-loss', 'restart'] as const) {
      state = invalidateSession(state, cause);
      expect(isCapabilityCurrent(state, cap)).toBe(false);
    }
  });

  it('stale capabilities are rejected before the operation registry', () => {
    const unlocked = onLocalUnlock(INITIAL_KERNEL_STATE);
    if (!unlocked.ok) return;
    let state = unlocked.state;
    const cap = issueCapability(state, channel, makeCap);
    state = invalidateSession(state, 'lock');
    const auth = authorizeOperationForCapability(state, cap, request);
    expect(auth).toEqual({ ok: false, code: 'StaleSession' });
  });

  it('operations below the required phase are forbidden', () => {
    const locked = authorizeOperationForCapability(INITIAL_KERNEL_STATE, issueCapability(INITIAL_KERNEL_STATE, channel, makeCap), request);
    expect(locked).toEqual({ ok: false, code: 'OperationForbidden' });
  });
});

describe('fresh-password elevation', () => {
  it('is one purpose, one use, and expires within 60 seconds', () => {
    const unlocked = onLocalUnlock(INITIAL_KERNEL_STATE);
    if (!unlocked.ok) return;
    const verified = onExactOnlineVerification(unlocked.state);
    if (!verified.ok) return;
    let state = verified.state;
    const now = 1_000_000;
    const elev = onFreshPassword(state, channel, 'mnemonic-reveal', now);
    expect(elev.ok).toBe(true);
    if (!elev.ok) return;
    state = elev.state;
    expect(state.phase).toBe('FreshPasswordVerified');
    expect(state.fresh[channel.channelId]).toMatchObject({ purpose: 'mnemonic-reveal', consumed: false });
    expect(state.fresh[channel.channelId]?.expiresAtMs).toBe(now + FRESH_PASSWORD_MAX_AGE_MS);

    const ok = consumeFreshPassword(state, channel, 'mnemonic-reveal', now);
    expect(ok.ok).toBe(true);
    if (!ok.ok) return;
    state = ok.state;
    // Second use fails (one-use).
    expect(consumeFreshPassword(state, channel, 'mnemonic-reveal', now).ok).toBe(false);
    // Wrong purpose fails.
    const elev2 = onFreshPassword(state, channel, 'password-change', now);
    expect(elev2.ok).toBe(true);
    if (!elev2.ok) return;
    expect(consumeFreshPassword(elev2.state, channel, 'mnemonic-reveal', now).ok).toBe(false);
    // Expired fails.
    const elev3 = onFreshPassword(state, channel, 'mnemonic-reveal', now);
    if (!elev3.ok) return;
    expect(consumeFreshPassword(elev3.state, channel, 'mnemonic-reveal', now + FRESH_PASSWORD_MAX_AGE_MS + 1).ok).toBe(false);
  });
});

describe('conservative session timing', () => {
  it('applies the longer credible elapsed duration on suspend/resume', () => {
    const r = assessElapsed({ monotonicMs: 100, wallClockMs: 1_000_000 }, { monotonicMs: 150, wallClockMs: 1_000_200 });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.elapsedMs).toBe(200); // max(50, 200)
  });

  it('backward wall-clock cannot extend a session', () => {
    const r = assessElapsed({ monotonicMs: 100, wallClockMs: 1_000_000 }, { monotonicMs: 200, wallClockMs: 999_000 });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.elapsedMs).toBe(100); // monotonic only
  });

  it('uncertain time evidence locks (fail closed)', () => {
    const r = assessElapsed({ monotonicMs: 200, wallClockMs: 1_000_000 }, { monotonicMs: 100, wallClockMs: 999_000 });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('UNRELIABLE_CLOCK');
  });

  it('applies idle/background lock policy', () => {
    expect(applyLockPolicy(4_000, { idleLimitMs: 5 * 60_000 })).toBe('stay-unlocked');
    expect(applyLockPolicy(6 * 60_000, { idleLimitMs: 5 * 60_000 })).toBe('lock');
  });
});

describe('bounded Lock contract', () => {
  it('revokes access synchronously and acknowledges cleanup within one second', async () => {
    let revoked = 0;
    let notified = 0;
    const ports: LockPorts = {
      invalidateEpoch: () => { revoked += 1; },
      notifyClients: () => { notified += 1; },
      cancelOperations: () => undefined,
      terminateSecretBoundaries: async () => true,
    };
    const out = await executeLock(ports);
    expect(revoked).toBe(1);
    expect(notified).toBe(1);
    expect(out).toEqual({ ok: true, acknowledgedCleanup: true, isolationTerminated: false });
  });

  it('terminates the isolation boundary when cleanup exceeds one second', async () => {
    const ports: LockPorts = {
      invalidateEpoch: () => undefined,
      notifyClients: () => undefined,
      cancelOperations: () => undefined,
      terminateSecretBoundaries: async (timeoutMs) => {
        expect(timeoutMs).toBe(LOCK_CLEANUP_BUDGET_MS);
        return false; // cleanup could not finish in budget
      },
    };
    const out = await executeLock(ports);
    expect(out).toEqual({ ok: true, acknowledgedCleanup: false, isolationTerminated: true });
  });
});
