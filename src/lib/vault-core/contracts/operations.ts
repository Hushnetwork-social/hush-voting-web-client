/**
 * FEAT-003 vault-core contracts — closed versioned operation registry.
 *
 * Operations are a closed, versioned registry. Every operation validates: required
 * capability phase, session epoch and client channel, allowed operation kind/version,
 * canonical network and identity binding (network N/A in v1), operation-specific payload
 * kind and public signatory, bounded canonical bytes, and user-confirmation context where
 * signing applies. Unknown operations fail closed. There is no arbitrary-byte signing,
 * private-key export, or decrypted-vault operation.
 *
 * Current v1 registry: identity verification and approved profile-creation behavior only.
 * Future voting operations require separately reviewed operation kinds and context
 * validation.
 *
 * Normative source: FEAT-003 FeatureDescription "Session Core — Operation-scoped API".
 */

/** Closed operation kinds for v1. */
export type OperationKind = 'verify-online' | 'create-full-identity';

export const OPERATION_KINDS: readonly OperationKind[] = [
  'verify-online',
  'create-full-identity',
] as const;

/** Operation version per kind (monotonic). */
export const OPERATION_VERSION: Readonly<Record<OperationKind, number>> = {
  'verify-online': 1,
  'create-full-identity': 1,
} as const;

/** Minimum capability phase required for each v1 operation kind. */
export const OPERATION_MIN_PHASE: Readonly<Record<OperationKind, CapabilityPhase>> = {
  'verify-online': 'VerificationOnly',
  'create-full-identity': 'Authenticated',
} as const;

import type { CapabilityPhase } from './capabilities';

/** Bounded public signatory descriptor (no secrets). */
export interface PublicSignatory {
  readonly signingAddress: string;
  readonly producerId: string;
  readonly producerVersion: string;
}

/** One bounded operation request (public, canonical-bytes descriptor only). */
export interface OperationRequest {
  readonly kind: OperationKind;
  readonly version: number;
  readonly signatory: PublicSignatory;
  /** Bounded canonical payload descriptor; the payload itself never crosses the page. */
  readonly payloadDescriptor: {
    readonly kind: string;
    readonly canonicalBytesLength: number;
    readonly sha256: string;
  };
  readonly userConfirmationContext: {
    readonly alias: string;
    readonly signingAddressPrefix: string;
    readonly signingAddressSuffix: string;
  };
}

export type OperationAuthorization =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: 'UNKNOWN_OPERATION' | 'WRONG_VERSION' | 'INSUFFICIENT_PHASE' | 'INVALID_SIGNATORY' | 'INVALID_PAYLOAD' };

/** Deterministic authorization against the closed registry (kernel enforces at runtime). */
export function authorizeOperation(
  request: OperationRequest,
  phase: CapabilityPhase,
  options: { readonly phaseOrder: readonly CapabilityPhase[] },
): OperationAuthorization {
  if (!OPERATION_KINDS.includes(request.kind)) {
    return { ok: false, code: 'UNKNOWN_OPERATION' };
  }
  if (request.version !== OPERATION_VERSION[request.kind]) {
    return { ok: false, code: 'WRONG_VERSION' };
  }
  const required = OPERATION_MIN_PHASE[request.kind];
  if (options.phaseOrder.indexOf(phase) < options.phaseOrder.indexOf(required)) {
    return { ok: false, code: 'INSUFFICIENT_PHASE' };
  }
  if (request.signatory.signingAddress.length < 8) {
    return { ok: false, code: 'INVALID_SIGNATORY' };
  }
  if (request.payloadDescriptor.canonicalBytesLength <= 0 || !/^[0-9a-f]{64}$/.test(request.payloadDescriptor.sha256)) {
    return { ok: false, code: 'INVALID_PAYLOAD' };
  }
  return { ok: true };
}
