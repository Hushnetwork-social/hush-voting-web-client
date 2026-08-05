/**
 * FEAT-010 runtime contracts — deployment-bound transport.
 *
 * Binds the unchanged FEAT-007 `HushServerTransportPort` (GetIdentity /
 * SubmitSignedTransaction) to a closed deployment manifest:
 * - endpoint IDs resolve ONLY through the manifest (server-side for BFF,
 *   native-owned for Ubuntu/Android); page/WebView code never reads or
 *   overrides the endpoint (AC-010-014…016);
 * - every request retains the 10-second deadline, bounded bodies, no-store
 *   semantics, and the sealed wire normalization (AC-010-017/018);
 * - endpoint rotation requires the same canonical network (AC-010-022);
 * - an unconditional-unavailable implementation is a release/build failure,
 *   never an acceptable production transport (AC-010-014).
 *
 * The sealed wire normalizers from FEAT-007 (`normalizeGetIdentityReply`,
 * `normalizeSubmitReply`) remain the ONLY control-flow interpretation;
 * free-form `message` text is never parsed.
 *
 * Framework-neutral.
 */

import type { DeploymentManifest } from './deployment';

/** One endpoint resolution result (never a URL visible to page code). */
export type EndpointResolution =
  | { readonly ok: true; readonly endpointId: string }
  | { readonly ok: false; readonly code: 'UNKNOWN_ENDPOINT' | 'CROSS_NETWORK_ENDPOINT' | 'UNBOUND_MANIFEST' };

/**
 * Resolve an endpoint ID against the active manifest.
 * - unknown endpoint IDs fail closed;
 * - rotation to another manifest's endpoint is allowed only when that manifest
 *   binds the same canonical network (validated via `canRotateEndpoint`).
 */
export function resolveEndpointId(
  manifest: DeploymentManifest,
  endpointId: string,
  candidateManifests: readonly DeploymentManifest[] = [],
): EndpointResolution {
  if (manifest.endpointIds.includes(endpointId)) {
    return { ok: true, endpointId };
  }
  for (const candidate of candidateManifests) {
    if (!candidate.endpointIds.includes(endpointId)) continue;
    const sameNetwork =
      candidate.canonicalNetworkId === manifest.canonicalNetworkId &&
      candidate.networkMagic === manifest.networkMagic &&
      candidate.contractVersions.client === manifest.contractVersions.client &&
      candidate.contractVersions.server === manifest.contractVersions.server;
    if (!sameNetwork) {
      return { ok: false, code: 'CROSS_NETWORK_ENDPOINT' };
    }
    return { ok: true, endpointId };
  }
  return { ok: false, code: 'UNKNOWN_ENDPOINT' };
}

/** Per-RPC policy bound (sealed by FEAT-007; mirrored here for transport binding). */
export const DEPLOYMENT_RPC_TIMEOUT_MS = 10_000 as const;
/** Bounded BFF request size (signed transaction JSON). */
export const DEPLOYMENT_MAX_REQUEST_BYTES = 65_536 as const;

/**
 * Contract for a manifest-bound transport implementation (BFF server adapter
 * or native generated client). Implementations MUST invoke the unchanged RPCs
 * with the bound endpoint and deadline and MUST never return an unconditional
 * unavailable result. This interface is the Phase 6 implementation seam.
 */
export interface DeploymentBoundTransportPort {
  readonly endpointId: string;
  lookupIdentity(request: { readonly publicSigningAddress: string }): Promise<LookupPortResult>;
  submitTransaction(request: { readonly signedTransaction: string }): Promise<SubmitPortResult>;
}

import type { LookupTransportResult, SubmitTransportResult } from '../identity-creation/transport';

/** Re-exported closed transport result shapes (unchanged FEAT-007 vocabulary). */
export type LookupPortResult = LookupTransportResult;
export type SubmitPortResult = SubmitTransportResult;

/** Static gate: a transport that always returns unavailable fails admission. */
export function isUnconditionalUnavailableTransport(
  probe: Pick<DeploymentBoundTransportPort, 'lookupIdentity' | 'submitTransaction'>,
): Promise<boolean> {
  return Promise.all([
    probe.lookupIdentity({ publicSigningAddress: 'probe' }).then((r) => !r.ok && r.failure.kind === 'unavailable'),
    probe.submitTransaction({ signedTransaction: 'probe' }).then((r) => !r.ok && r.failure.kind === 'unavailable'),
  ]).then(([lookup, submit]) => lookup && submit);
}
