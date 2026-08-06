/**
 * FEAT-011 Tasks 6.3 — versioned native operation dispatcher and
 * direct-secret channel contract.
 *
 * Closed Tauri commands/bridge messages for startup inspection, local proof,
 * complete candidate resolution, provision, exact lookup, `CreateFullIdentity`
 * (seal/sign), submit/reconcile, lifecycle promotion, Lock, removal, and
 * cleanup — WITHOUT generic commands. Every dispatch carries a protocol
 * version, epoch binding, capability purpose, and bounded input; the WebView
 * receives only safe typed progress/outcomes. Secrets travel ONLY through the
 * named direct-secret channel, never inside dispatch payloads.
 */

import type { ConvergenceOperationId } from '../identity-convergence/contracts';
import { CONVERGENCE_OPERATIONS } from '../identity-convergence/contracts';

/** Closed native dispatch protocol version. */
export const NATIVE_DISPATCH_VERSION = 1 as const;

/** Maximum serialized dispatch input (defense in depth). */
export const NATIVE_DISPATCH_MAX_INPUT_BYTES = 16_384 as const;

/** Dispatchable operations (convergence registry + lifecycle seams). */
export type NativeDispatchOperation = ConvergenceOperationId;

/** Closed dispatch request — never carries secrets. */
export interface NativeDispatchRequest {
  readonly protocolVersion: typeof NATIVE_DISPATCH_VERSION;
  readonly operation: NativeDispatchOperation;
  readonly epochBinding: string;
  /** Bounded, schema-validated operation input (no free-form payload). */
  readonly input: object | null;
  /** Purpose string from the closed registry (never free-form control). */
  readonly capabilityPurpose: string;
}

/** Closed dispatch result — safe progress/outcome only. */
export type NativeDispatchResult =
  | { readonly ok: true; readonly outcome: string; readonly progress: number } // 0..1
  | { readonly ok: false; readonly code: string };

/** Direct-secret channel contract: the ONLY secret-bearing bridge surface. */
export interface NativeDirectSecretChannel {
  /** Transfers the secret directly to the authority for the given operation; cleared immediately after accepted transfer. */
  submitSecret(operationId: string, secret: string): void;
  clearTransient(): void;
}

/** Dispatch validation outcomes (fail closed on everything unexpected). */
export type DispatchValidationResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: 'UNSUPPORTED_VERSION' | 'UNKNOWN_OPERATION' | 'FORBIDDEN_OPERATION' | 'MISSING_EPOCH' | 'INPUT_TOO_LARGE' | 'UNKNOWN_PURPOSE' | 'SECRET_IN_PAYLOAD' };

/** Validate a dispatch request against the closed registry and policy. */
export function validateDispatchRequest(
  request: NativeDispatchRequest,
  allowedOperations: ReadonlySet<NativeDispatchOperation>,
  allowedPurposes: ReadonlySet<string>,
): DispatchValidationResult {
  if (request.protocolVersion !== NATIVE_DISPATCH_VERSION) {
    return { ok: false, code: 'UNSUPPORTED_VERSION' };
  }
  if (!(CONVERGENCE_OPERATIONS as readonly string[]).includes(request.operation)) {
    return { ok: false, code: 'UNKNOWN_OPERATION' };
  }
  if (!allowedOperations.has(request.operation)) {
    return { ok: false, code: 'FORBIDDEN_OPERATION' };
  }
  if (request.epochBinding.length === 0) {
    return { ok: false, code: 'MISSING_EPOCH' };
  }
  if (!allowedPurposes.has(request.capabilityPurpose)) {
    return { ok: false, code: 'UNKNOWN_PURPOSE' };
  }
  if (request.input !== null && new TextEncoder().encode(JSON.stringify(request.input)).length > NATIVE_DISPATCH_MAX_INPUT_BYTES) {
    return { ok: false, code: 'INPUT_TOO_LARGE' };
  }
  if (request.input !== null && /password|mnemonic|privateKey|secret|signature|transactionJson/i.test(JSON.stringify(request.input))) {
    return { ok: false, code: 'SECRET_IN_PAYLOAD' };
  }
  return { ok: true };
}

/** Default allowed purpose registry for the FEAT-011 convergence operations. */
export const CONVERGENCE_PURPOSES: ReadonlySet<string> = new Set([
  'hushvoting.identity.startup-inspection.v1',
  'hushvoting.identity.local-proof.v1',
  'hushvoting.identity.candidate-resolution.v1',
  'hushvoting.identity.exact-lookup.v1',
  'hushvoting.identity.create-full-identity.v1',
  'hushvoting.identity.submit-reconcile.v1',
  'hushvoting.identity.lifecycle-promotion.v1',
  'hushvoting.identity.lock.v1',
  'hushvoting.identity.removal.v1',
]);
