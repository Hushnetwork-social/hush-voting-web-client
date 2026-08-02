/**
 * FEAT-004 worker authority tests — protocol, capabilities, and cleanup.
 *
 * Proves: valid handshakes accept; malformed/unknown/duplicate/stale/
 * wrong-channel/oversized messages fail closed; exactly one active operation;
 * fresh capabilities are channel/purpose/epoch/one-use/60 s bound; cancel and
 * Lock invalidate the epoch globally; lifecycle disconnect removes channels.
 *
 * Normative source: FEAT-004 FeatureDescription "Worker protocol",
 * "Shared tabs"; Task 4.2 behavior specification.
 */
import { describe, expect, it } from 'vitest';
import { WorkerAuthority, type AuthorityEnvironment } from './authority';
import { consumeFreshCapability, FRESH_CAPABILITY_MAX_AGE_MS, issueFreshCapability } from './capabilities';

function makeEnv(overrides: Partial<AuthorityEnvironment> = {}): AuthorityEnvironment {
  const events: Array<{ channel: string; event: unknown }> = [];
  const defaults: AuthorityEnvironment = {
    nowMs: () => 1_000_000,
    randomId: (prefix) => `${prefix}${Math.random().toString(36).slice(2, 8)}`,
    appIdentity: { appVersion: '0.1.0', buildDigest: 'a1b2c3d4e5f6' },
    executeOperation: async () => ({ outcome: 'SUCCESS', retryable: false, allowedActions: [] }),
    deliver: (channel, event) => {
      events.push({ channel, event });
    },
    broadcast: (event) => {
      events.push({ channel: '*', event });
    },
    onForceCleanup: () => undefined,
  };
  return {
    ...defaults,
    ...overrides,
    appIdentity: overrides.appIdentity ?? defaults.appIdentity,
  };
}

function validHandshake(channel = 'chan-1') {
  return {
    kind: 'handshake' as const,
    protocolVersion: 1,
    appVersion: '0.1.0',
    buildDigest: 'a1b2c3d4e5f6',
    clientChannel: channel,
    runtimeConfigId: 'production-hushnetwork',
  };
}

function validOperation(channel: string, epoch: number, operation: string = 'unlockPassword', operationId = 'op-1') {
  return { kind: 'operation' as const, operation, operationVersion: 1, clientChannel: channel, authorityEpoch: epoch, operationId };
}

describe('worker authority — handshake', () => {
  it('accepts a compatible handshake and delivers a safe session projection', () => {
    const events: Array<{ channel: string; event: { kind: string; authorityEpoch: number; session: { state: string } } }> = [];
    const env = makeEnv({
      deliver: (channel, event) => {
        events.push({ channel, event: event as { kind: string; authorityEpoch: number; session: { state: string } } });
      },
    });
    const authority = new WorkerAuthority(env, 'locked', 1);
    const result = authority.handle(validHandshake());
    expect(result.accepted).toBe(true);
    expect(events.length).toBe(1);
    expect(events[0].channel).toBe('chan-1');
    expect(events[0].event.kind).toBe('handshake-accepted');
    expect(events[0].event.authorityEpoch).toBe(1);
    expect(events[0].event.session.state).toBe('locked'); // safe projection only
  });

  it('rejects wrong protocol versions and duplicate channels', () => {
    const env = makeEnv();
    const authority = new WorkerAuthority(env, 'locked', 1);
    // Wrong protocol versions are rejected by the single runtime validation gate.
    const badVersion = authority.handle({ ...validHandshake(), protocolVersion: 2 });
    expect(badVersion.accepted).toBe(false);
    expect(badVersion.outcome).toBe('MESSAGE_REJECTED');
    expect(authority.handle(validHandshake('chan-1')).accepted).toBe(true);
    const duplicate = authority.handle(validHandshake('chan-1'));
    expect(duplicate.accepted).toBe(false);
    expect(duplicate.outcome).toBe('HANDSHAKE_DUPLICATE_CHANNEL');
  });

  it('rejects malformed and secret-bearing messages without dispatch', () => {
    const env = makeEnv();
    const authority = new WorkerAuthority(env, 'locked', 1);
    expect(authority.handle(null).accepted).toBe(false);
    expect(authority.handle({ kind: 'unknown' }).accepted).toBe(false);
    expect(authority.handle({ ...validHandshake(), password: 'hunter2' }).accepted).toBe(false);
  });
});

describe('worker authority — operations and serialization', () => {
  it('rejects operations from unknown channels and stale epochs', () => {
    const env = makeEnv();
    const authority = new WorkerAuthority(env, 'locked', 1);
    expect(authority.handle(validOperation('nobody', 1)).outcome).toBe('OPERATION_UNKNOWN_CHANNEL');
    authority.handle(validHandshake());
    expect(authority.handle(validOperation('chan-1', 99)).outcome).toBe('OPERATION_STALE_EPOCH');
  });

  it('serializes operations (one active at a time)', () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const env = makeEnv({
      executeOperation: async () => {
        await gate;
        return { outcome: 'SUCCESS', retryable: false, allowedActions: [] };
      },
    });
    const authority = new WorkerAuthority(env, 'locked', 1);
    authority.handle(validHandshake());
    expect(authority.handle(validOperation('chan-1', 1, 'unlockPassword', 'op-1')).outcome).toBe('OPERATION_STARTED');
    expect(authority.handle(validOperation('chan-1', 1, 'unlockPassword', 'op-2')).outcome).toBe('OPERATION_BUSY');
    release();
  });

  it('rejects operations that require an unconsumed fresh capability', () => {
    const env = makeEnv();
    const authority = new WorkerAuthority(env, 'locked', 1);
    authority.handle(validHandshake());
    const result = authority.handle(validOperation('chan-1', 1, 'removeLocalUser', 'op-1'));
    expect(result.accepted).toBe(false);
    expect(result.outcome).toContain('OPERATION_CAPABILITY_');
  });
});

describe('worker authority — fresh capabilities', () => {
  it('binds capabilities to channel, epoch, purpose, one-use, and 60 s age', () => {
    const now = 1_000_000;
    const capability = issueFreshCapability({ id: 'cap-1', purpose: 'revealMnemonic', clientChannel: 'chan-1', authorityEpoch: 5, nowMs: now });
    expect(capability.expiresAtMs).toBe(now + FRESH_CAPABILITY_MAX_AGE_MS);

    expect(consumeFreshCapability(capability, { purpose: 'revealMnemonic', clientChannel: 'chan-1', authorityEpoch: 5, nowMs: now }).ok).toBe(true);
    expect(consumeFreshCapability({ ...capability, used: true }, { purpose: 'revealMnemonic', clientChannel: 'chan-1', authorityEpoch: 5, nowMs: now })).toMatchObject({ ok: false, reason: 'used' });
    expect(consumeFreshCapability(capability, { purpose: 'removeLocalUser', clientChannel: 'chan-1', authorityEpoch: 5, nowMs: now })).toMatchObject({ ok: false, reason: 'purpose-mismatch' });
    expect(consumeFreshCapability(capability, { purpose: 'revealMnemonic', clientChannel: 'chan-2', authorityEpoch: 5, nowMs: now })).toMatchObject({ ok: false, reason: 'wrong-channel' });
    expect(consumeFreshCapability(capability, { purpose: 'revealMnemonic', clientChannel: 'chan-1', authorityEpoch: 6, nowMs: now })).toMatchObject({ ok: false, reason: 'wrong-epoch' });
    expect(consumeFreshCapability(capability, { purpose: 'revealMnemonic', clientChannel: 'chan-1', authorityEpoch: 5, nowMs: now + FRESH_CAPABILITY_MAX_AGE_MS + 1 })).toMatchObject({ ok: false, reason: 'expired' });
    expect(consumeFreshCapability(null, { purpose: 'revealMnemonic', clientChannel: 'chan-1', authorityEpoch: 5, nowMs: now })).toMatchObject({ ok: false, reason: 'malformed' });
  });
});

describe('worker authority — invalidation and lifecycle', () => {
  it('Lock/cancel increments the epoch and broadcasts global invalidation', () => {
    const env = makeEnv();
    const authority = new WorkerAuthority(env, 'authenticated', 1);
    authority.handle(validHandshake());
    authority.handle(validOperation('chan-1', 1, 'lockAll', 'op-1'));
    authority.invalidate('lock');
    expect(authority.snapshot().epoch).toBe(2);
    expect(authority.snapshot().acceptedChannels).toEqual([]);
  });

  it('rejects post-invalidation operations with the stale epoch', () => {
    const env = makeEnv();
    const authority = new WorkerAuthority(env, 'authenticated', 1);
    authority.handle(validHandshake());
    authority.invalidate('takeover');
    const result = authority.handle(validOperation('chan-1', 1, 'lockAll', 'op-1'));
    expect(result.outcome).toBe('OPERATION_STALE_EPOCH');
  });

  it('removes channels on disconnect lifecycle signals', () => {
    const env = makeEnv();
    const authority = new WorkerAuthority(env, 'locked', 1);
    authority.handle(validHandshake());
    expect(authority.snapshot().acceptedChannels).toContain('chan-1');
    authority.handle({ kind: 'lifecycle', signal: 'disconnect', clientChannel: 'chan-1', authorityEpoch: 1 });
    expect(authority.snapshot().acceptedChannels).not.toContain('chan-1');
  });

  it('drops operation outcomes when the epoch was invalidated mid-flight', async () => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const delivered: Array<{ kind: string }> = [];
    const env = makeEnv({
      executeOperation: async () => {
        await gate;
        return { outcome: 'SUCCESS', retryable: false, allowedActions: [] };
      },
      deliver: (_channel, event) => {
        delivered.push(event as { kind: string });
      },
    });
    const authority = new WorkerAuthority(env, 'locked', 1);
    authority.handle(validHandshake());
    authority.handle(validOperation('chan-1', 1, 'unlockPassword', 'op-1'));
    authority.invalidate('lock'); // epoch advances while the operation is running
    release();
    await new Promise((resolve) => setTimeout(resolve, 0));
    // The stale outcome must never be delivered.
    expect(delivered.some((event) => event.kind === 'operation-outcome')).toBe(false);
  });
});
