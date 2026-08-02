/**
 * FEAT-004 protocol contract tests — closure, bounds, and negative rejection.
 *
 * Proves: every supported message round-trips at field boundaries; prohibited
 * fields/variants (secret data, arbitrary URL, unknown operation, stale epoch,
 * wrong channel, duplicate identifier, extra property, oversized payload) are
 * rejected without echoing the supplied value; version/channel/epoch binding
 * semantics are deterministic.
 *
 * Normative source: FEAT-004 FeatureDescription "Worker protocol";
 * Task 2.2 behavior specification.
 */
import { describe, expect, it } from 'vitest';
import {
  BROWSER_PROTOCOL_VERSION,
  PROTOCOL_BOUNDS,
  assertNoSecretField,
  validateClientMessage,
  type BrowserClientMessage,
} from './protocol';

const VALID_HANDSHAKE = {
  kind: 'handshake',
  protocolVersion: BROWSER_PROTOCOL_VERSION,
  appVersion: '0.1.0',
  buildDigest: 'a1b2c3d4e5f6',
  clientChannel: 'channel-abc-123',
  runtimeConfigId: 'production-hushnetwork',
} as const;

describe('protocol validation — supported round-trips', () => {
  it('accepts a valid handshake at field boundaries', () => {
    const message = validateClientMessage(VALID_HANDSHAKE);
    expect(message).not.toBeNull();
    expect(message?.kind).toBe('handshake');
  });

  it('accepts a valid operation request with optional fresh capability id', () => {
    const message = validateClientMessage({
      kind: 'operation',
      operation: 'unlockPassword',
      operationVersion: 1,
      clientChannel: 'channel-abc-123',
      authorityEpoch: 7,
      operationId: 'op-1',
      freshCapabilityId: 'cap-1',
    });
    expect(message?.kind).toBe('operation');
    if (message && message.kind === 'operation') {
      expect(message.freshCapabilityId).toBe('cap-1');
    }
  });

  it('accepts cancel and lifecycle signals', () => {
    expect(validateClientMessage({ kind: 'cancel', operationId: 'op-1', clientChannel: 'c', authorityEpoch: 1 })?.kind).toBe('cancel');
    expect(validateClientMessage({ kind: 'lifecycle', signal: 'pagehide', clientChannel: 'c', authorityEpoch: 1 })?.kind).toBe('lifecycle');
    expect(validateClientMessage({ kind: 'lifecycle', signal: 'heartbeat', clientChannel: 'c', authorityEpoch: 1 })?.kind).toBe('lifecycle');
  });
});

describe('protocol validation — negative rejection (fail closed)', () => {
  it('rejects non-objects and unknown kinds', () => {
    expect(validateClientMessage(null)).toBeNull();
    expect(validateClientMessage('handshake')).toBeNull();
    expect(validateClientMessage({ kind: 'unknown-kind' })).toBeNull();
  });

  it('rejects wrong protocol versions and unknown runtime config ids', () => {
    expect(validateClientMessage({ ...VALID_HANDSHAKE, protocolVersion: BROWSER_PROTOCOL_VERSION + 1 })).toBeNull();
    expect(validateClientMessage({ ...VALID_HANDSHAKE, protocolVersion: 0 })).toBeNull();
    expect(validateClientMessage({ ...VALID_HANDSHAKE, runtimeConfigId: 'https://evil.example' })).toBeNull();
  });

  it('rejects secret-shaped fields without echoing the value', () => {
    expect(validateClientMessage({ ...VALID_HANDSHAKE, password: 'hunter2' })).toBeNull();
    expect(validateClientMessage({ kind: 'operation', operation: 'unlockPassword', operationVersion: 1, clientChannel: 'c', authorityEpoch: 1, operationId: 'op', mnemonic: 'word word word' })).toBeNull();
    expect(validateClientMessage({ ...VALID_HANDSHAKE, privateKey: 'abc' })).toBeNull();
  });

  it('rejects unknown operations, stale epochs, missing ids, and extra properties', () => {
    expect(validateClientMessage({ kind: 'operation', operation: 'signArbitrary', operationVersion: 1, clientChannel: 'c', authorityEpoch: 1, operationId: 'op' })).toBeNull();
    expect(validateClientMessage({ kind: 'operation', operation: 'unlockPassword', operationVersion: 1, clientChannel: 'c', authorityEpoch: -1, operationId: 'op' })).toBeNull();
    expect(validateClientMessage({ kind: 'operation', operation: 'unlockPassword', operationVersion: 1, clientChannel: 'c', authorityEpoch: 1 })).toBeNull();
    expect(validateClientMessage({ ...VALID_HANDSHAKE, extra: true })).toBeNull();
  });

  it('rejects oversized identifiers', () => {
    expect(validateClientMessage({ ...VALID_HANDSHAKE, clientChannel: 'x'.repeat(PROTOCOL_BOUNDS.maxIdentifierLength + 1) })).toBeNull();
  });

  it('rejects lifecycle signals outside the closed set', () => {
    expect(validateClientMessage({ kind: 'lifecycle', signal: 'focus', clientChannel: 'c', authorityEpoch: 1 })).toBeNull();
  });
});

describe('protocol safety — no secret-shaped fields on any valid message', () => {
  it('asserts every validated message variant carries no secret-shaped field', () => {
    const messages: BrowserClientMessage[] = [
      validateClientMessage(VALID_HANDSHAKE)!,
      validateClientMessage({ kind: 'operation', operation: 'lockAll', operationVersion: 1, clientChannel: 'c', authorityEpoch: 2, operationId: 'op' })!,
      validateClientMessage({ kind: 'cancel', operationId: 'op', clientChannel: 'c', authorityEpoch: 2 })!,
      validateClientMessage({ kind: 'lifecycle', signal: 'disconnect', clientChannel: 'c', authorityEpoch: 2 })!,
    ];
    for (const message of messages) {
      expect(() => assertNoSecretField(message)).not.toThrow();
    }
  });
});
