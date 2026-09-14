import { afterEach, describe, expect, it, vi } from 'vitest';
const { lookupIdentity } = vi.hoisted(() => ({ lookupIdentity: vi.fn(async () => ({ ok: true, reply: { successfull: false } })) }));
vi.mock('../server-transport', () => ({ createServerTransport: () => ({ lookupIdentity }) }));
import { POST } from './route';

afterEach(() => vi.clearAllMocks());

describe('identity BFF approved address formats', () => {
  it('forwards a historical uncompressed public address and returns a non-cacheable authoritative absence', async () => {
    const address = '04' + 'ab'.repeat(64);
    const response = await POST(new Request('http://localhost/api/identity', { method: 'POST', body: JSON.stringify({ publicSigningAddress: address }) }));
    expect(response.status).toBe(200);
    expect(lookupIdentity).toHaveBeenCalledWith({ publicSigningAddress: address });
    expect(response.headers.get('cache-control')).toContain('no-store');
    expect(await response.json()).toEqual({ reply: { successfull: false } });
  });
  it('rejects oversized addresses before invoking the node', async () => {
    const response = await POST(new Request('http://localhost/api/identity', { method: 'POST', body: JSON.stringify({ publicSigningAddress: 'a'.repeat(257) }) }));
    expect(response.status).toBe(400);
    expect(lookupIdentity).not.toHaveBeenCalled();
  });
});
