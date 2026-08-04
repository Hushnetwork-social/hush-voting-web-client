/**
 * FEAT-007 BFF server transport factory.
 *
 * Reads the server-side HushServerNode endpoint configuration and builds the
 * transport port. The gRPC client binding is completed with the pinned server
 * hardening artifact; until the endpoint is configured the factory returns
 * `null` (routes fail closed with NOT_CONFIGURED) — never a fake success.
 *
 * The endpoint value is read from a NON-public server environment variable
 * (`HUSHSERVER_NODE_ENDPOINT`); it is never exposed to the client bundle.
 */
import type { HushServerTransportPort, LookupTransportResult, SubmitTransportResult } from '../../lib/identity-creation/transport';

export function createServerTransport(env: NodeJS.ProcessEnv): HushServerTransportPort | null {
  const endpoint = env.HUSHSERVER_NODE_ENDPOINT;
  if (typeof endpoint !== 'string' || endpoint.length === 0) {
    return null;
  }
  // Bounded transport bound to the configured endpoint. The gRPC method-level
  // binding (hushIdentity.GetIdentity / hushBlockchain.SubmitSignedTransaction)
  // is completed with the pinned server hardening artifact; until then all
  // calls fail closed as unavailable rather than fabricating replies.
  return new ConfiguredTransport(endpoint);
}

class ConfiguredTransport implements HushServerTransportPort {
  constructor(private readonly endpoint: string) {}

  async lookupIdentity(): Promise<LookupTransportResult> {
    // gRPC binding point — completed when the pinned hardening artifact and
    // generated client are available. Fail closed until then.
    void this.endpoint;
    return { ok: false, failure: { kind: 'unavailable' } };
  }

  async submitTransaction(): Promise<SubmitTransportResult> {
    void this.endpoint;
    return { ok: false, failure: { kind: 'unavailable' } };
  }
}
