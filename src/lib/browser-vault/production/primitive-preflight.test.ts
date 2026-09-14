import { webcrypto } from 'node:crypto';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { probeWorkerPrimitives, type PrimitivePreflightEnvironment } from './primitive-preflight';

// EPIC-001 -> FEAT-004 capability preflight -> Phase 2 Tasks 2.1/2.2;
// FEAT-007 AC-007-002 -> Phase 6 Tasks 6.1/6.2. FEAT evidence only.
function environment(): PrimitivePreflightEnvironment {
  return {
    secureContext: true, sharedModuleWorker: true, crypto: webcrypto as unknown as Crypto,
    encode: text => new TextEncoder().encode(text),
    decode: bytes => new TextDecoder('utf-8', { fatal: true }).decode(bytes),
    transfer: bytes => structuredClone(bytes, { transfer: [bytes.buffer] }),
    persisted: async () => false, estimate: async () => ({ usage: 1024, quota: 1048576 }),
  };
}
afterEach(() => vi.restoreAllMocks());

describe('HushVotingApp TwinTests — worker primitive preflight', () => {
  it('executes real HKDF and AES round-trip and reports advisory persistence honestly', async () => {
    const operations: string[] = [];
    const original = webcrypto.subtle.importKey.bind(webcrypto.subtle);
    vi.spyOn(webcrypto.subtle, 'importKey').mockImplementation((...args: Parameters<typeof original>) => {
      operations.push(String(args[2])); return Reflect.apply(original, webcrypto.subtle, args);
    });
    expect(await probeWorkerPrimitives(environment())).toEqual({ ok: true, persisted: false, estimateAvailable: true });
    expect(operations).toEqual(['HKDF', 'AES-GCM']);
  });

  it.each(['insecure-context', 'worker-unavailable', 'transfer-unavailable'])('rejects %s before crypto or persistence work', async reason => {
    const base = environment();
    const persisted = vi.fn(base.persisted);
    const crypto = vi.spyOn(webcrypto, 'getRandomValues');
    expect(await probeWorkerPrimitives({ ...base, persisted,
      secureContext: reason !== 'insecure-context', sharedModuleWorker: reason !== 'worker-unavailable',
      transfer: reason === 'transfer-unavailable' ? bytes => bytes : base.transfer })).toEqual({ ok: false, reason });
    expect(crypto).not.toHaveBeenCalled(); expect(persisted).not.toHaveBeenCalled();
  });

  it.each(['random', 'hkdf', 'encrypt', 'decrypt'] as const)('rejects a runtime %s failure rather than trusting API presence', async operation => {
    if (operation === 'random') vi.spyOn(webcrypto, 'getRandomValues').mockImplementation(() => { throw new Error('Controlled primitive failure'); });
    else if (operation === 'hkdf') vi.spyOn(webcrypto.subtle, 'deriveBits').mockRejectedValue(new Error('Controlled primitive failure'));
    else vi.spyOn(webcrypto.subtle, operation).mockRejectedValue(new Error('Controlled primitive failure'));
    const persisted = vi.fn(async () => true);
    expect(await probeWorkerPrimitives({ ...environment(), persisted })).toEqual({ ok: false, reason: 'crypto-unavailable' });
    expect(persisted).not.toHaveBeenCalled();
  });

  it('treats unavailable advisory APIs as unknown, never as granted persistence', async () => {
    expect(await probeWorkerPrimitives({ ...environment(), persisted: async () => { throw new Error('Denied'); }, estimate: undefined }))
      .toEqual({ ok: true, persisted: null, estimateAvailable: false });
  });
});
