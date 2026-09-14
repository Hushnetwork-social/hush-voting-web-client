/** EPIC-001 -> FEAT-007 AC-007-024 -> Phase 7 Tasks 7.1/7.2.
 * Web authority evidence only; native adapter qualification remains separate.
 */
import { describe, expect, it, vi } from 'vitest';
import { WorkerAuthority, type AuthorityEnvironment } from '../authority/authority';

describe.each(['locked', 'verificationOnly', 'authenticated'] as const)('sealed Web operations in %s', (phase) => {
  it.each(['genericSign', 'genericDecrypt', 'exportPrivateKey'])('rejects %s before execution without changing authority', (operation) => {
    const executeOperation = vi.fn<AuthorityEnvironment['executeOperation']>();
    const deliver = vi.fn<AuthorityEnvironment['deliver']>();
    const authority = new WorkerAuthority({
      nowMs: () => 1000,
      randomId: (prefix) => `${prefix}-test`,
      appIdentity: { appVersion: '0.1.0', buildDigest: 'a1b2c3d4e5f6' },
      executeOperation,
      deliver,
      broadcast: vi.fn(),
      onForceCleanup: vi.fn(),
    }, phase, 1);
    expect(authority.handle({
      kind: 'handshake', protocolVersion: 2, appVersion: '0.1.0',
      buildDigest: 'a1b2c3d4e5f6', clientChannel: 'owned-channel',
      runtimeConfigId: 'production-hushnetwork',
    }).accepted).toBe(true);
    deliver.mockClear();
    const before = authority.snapshot();
    expect(authority.handle({
      kind: 'operation', operation, operationVersion: 1,
      clientChannel: 'owned-channel', authorityEpoch: 1, operationId: 'negative-probe',
    })).toEqual({ accepted: false, outcome: 'MESSAGE_REJECTED' });
    expect(executeOperation).not.toHaveBeenCalled();
    expect(deliver).not.toHaveBeenCalled();
    expect(authority.snapshot()).toEqual(before);
  });
});
