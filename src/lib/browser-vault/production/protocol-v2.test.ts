/**
 * FEAT-010 Task 7.3 — protocol v2 additive validation tests.
 *
 * Proves: the new operation kinds accept only their closed public payloads;
 * secret-transfer messages are the ONLY secret-bearing channel and are
 * bounded; issue-capability is strictly validated; unknown/malformed/secret-
 * shaped payloads fail closed; v1 message shapes remain valid under v2.
 */
import { describe, expect, it } from 'vitest';
import { validateClientMessage, BROWSER_PROTOCOL_VERSION } from '../contracts/protocol';

function base(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    kind: 'operation',
    operation: 'createCandidate',
    operationVersion: 1,
    clientChannel: 'chan-1',
    authorityEpoch: 1,
    operationId: 'op-1',
    ...overrides,
  };
}

describe('protocol v2 — operation payload validation', () => {
  it('accepts the closed payload for provisionFromValidatedBundle', () => {
    const message = validateClientMessage(base({ operation: 'provisionFromValidatedBundle', payload: { candidateRef: 'cand-1', alias: 'Alice', visibility: 'private' } }));
    expect(message).not.toBeNull();
    if (message !== null && message.kind === 'operation') {
      expect(message.payload).toEqual({ candidateRef: 'cand-1', alias: 'Alice', visibility: 'private' });
    }
  });

  it('rejects a secret-shaped payload field', () => {
    expect(validateClientMessage(base({ payload: { candidateRef: 'cand-1', password: 'hunter2' } }))).toBeNull();
    expect(validateClientMessage(base({ payload: { mnemonic: 'abandon' } }))).toBeNull();
    expect(validateClientMessage(base({ payload: { fileBytes: 'AAAA' } }))).toBeNull();
  });

  it('rejects unknown payload fields and unknown operations', () => {
    expect(validateClientMessage(base({ payload: { candidateRef: 'cand-1', extra: 'x' } }))).toBeNull();
    expect(validateClientMessage(base({ operation: 'genericSign' }))).toBeNull();
  });

  it('accepts the v2 candidate lifecycle operations', () => {
    expect(validateClientMessage(base({ operation: 'createCandidate' }))).not.toBeNull();
    expect(validateClientMessage(base({ operation: 'revealCandidateWords', payload: { candidateRef: 'cand-1' } }))).not.toBeNull();
    expect(validateClientMessage(base({ operation: 'deriveWordsCandidate', payload: { producerId: 'P-01', wordCount: 24 } }))).not.toBeNull();
    expect(validateClientMessage(base({ operation: 'promoteLifecycle', payload: { status: 'Active' } }))).not.toBeNull();
    expect(validateClientMessage(base({ operation: 'submitIdentityTransaction', payload: { alias: 'Alice', visibility: 'private' } }))).not.toBeNull();
  });

  it('keeps v1 operation shapes valid (additive only)', () => {
    expect(validateClientMessage(base({ operation: 'unlockPassword' }))).not.toBeNull();
    expect(validateClientMessage(base({ operation: 'verifyOnlineIdentity' }))).not.toBeNull();
    expect(validateClientMessage(base({ operation: 'lockAll' }))).not.toBeNull();
  });
});

describe('protocol v2 — secret transfer', () => {
  it('accepts bounded secret transfers per purpose', () => {
    const message = validateClientMessage({ kind: 'secret-transfer', operationId: 'op-1', clientChannel: 'chan-1', authorityEpoch: 1, purpose: 'devicePassword', value: 'secret-value' });
    expect(message).not.toBeNull();
    expect(validateClientMessage({ kind: 'secret-transfer', operationId: 'op-1', clientChannel: 'chan-1', authorityEpoch: 1, purpose: 'fileBytes', value: 'b'.repeat(1024) })).not.toBeNull();
  });

  it('rejects unknown purposes, empty values, and oversized file bytes', () => {
    expect(validateClientMessage({ kind: 'secret-transfer', operationId: 'op-1', clientChannel: 'chan-1', authorityEpoch: 1, purpose: 'privateKey', value: 'x' })).toBeNull();
    expect(validateClientMessage({ kind: 'secret-transfer', operationId: 'op-1', clientChannel: 'chan-1', authorityEpoch: 1, purpose: 'mnemonic', value: '' })).toBeNull();
    expect(validateClientMessage({ kind: 'secret-transfer', operationId: 'op-1', clientChannel: 'chan-1', authorityEpoch: 1, purpose: 'fileBytes', value: 'b'.repeat(2_000_000) })).toBeNull();
  });
});

describe('protocol v2 — capability issuance', () => {
  it('accepts approved purposes only', () => {
    expect(validateClientMessage({ kind: 'issue-capability', purpose: 'provision', clientChannel: 'chan-1', authorityEpoch: 1 })).not.toBeNull();
    expect(validateClientMessage({ kind: 'issue-capability', purpose: 'removeLocalUser', clientChannel: 'chan-1', authorityEpoch: 1 })).not.toBeNull();
    expect(validateClientMessage({ kind: 'issue-capability', purpose: 'genericSign', clientChannel: 'chan-1', authorityEpoch: 1 })).toBeNull();
  });
});

describe('protocol v2 — version', () => {
  it('bumps the protocol version to 2 (additive)', () => {
    expect(BROWSER_PROTOCOL_VERSION).toBe(2);
  });
});
