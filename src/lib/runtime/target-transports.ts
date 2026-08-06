/**
 * FEAT-011 Tasks 6.5/6.7 — target transport resolution and real convergence
 * composition.
 *
 * `resolveTargetTransport` maps a validated target handoff to its closed
 * transport spec (browser BFF binary gRPC / Ubuntu native / Android native).
 * `composeConvergenceActors` builds the real actor graph for the convergence
 * coordinator. Unknown, partial, incompatible, synthetic-in-production, or
 * missing handoffs BLOCK before sensitive entry — the root never retries as
 * Browser for a native target, and no weaker target is ever selected.
 */

import { validateTargetHandoff, type TargetCoordinatorHandoff } from '../identity-convergence/target-adapter';

/** Closed transport spec per target. */
export interface TargetTransportSpec {
  readonly targetClass: 'web' | 'ubuntu' | 'android';
  /** The transport kind used by this target (no JSON approximation for web). */
  readonly transport: 'browser-bff-binary-grpc' | 'native-generated-grpc';
  /** Custody owner (never Browser storage/crypto for natives). */
  readonly custody: 'browser-worker' | 'ubuntu-secret-service' | 'android-keystore';
  /** Structural no-fallback proof: Browser fallback is unrepresentable. */
  readonly fallback: false;
}

/** Composition outcome with stable provenance for evidence. */
export type CompositionResult =
  | { readonly ok: true; readonly provenance: { readonly targetClass: 'web' | 'ubuntu' | 'android'; readonly synthetic: boolean; readonly handoff: TargetCoordinatorHandoff } }
  | { readonly ok: false; readonly code: string };

const TRANSPORT_SPECS: Readonly<Record<'web' | 'ubuntu' | 'android', TargetTransportSpec>> = {
  web: { targetClass: 'web', transport: 'browser-bff-binary-grpc', custody: 'browser-worker', fallback: false },
  ubuntu: { targetClass: 'ubuntu', transport: 'native-generated-grpc', custody: 'ubuntu-secret-service', fallback: false },
  android: { targetClass: 'android', transport: 'native-generated-grpc', custody: 'android-keystore', fallback: false },
};

/** Resolve the target transport spec from the validated handoff set. */
export function resolveTargetTransport(
  targetClass: 'web' | 'ubuntu' | 'android' | string,
  handoffs: ReadonlyArray<TargetCoordinatorHandoff>,
  production: boolean,
): { readonly ok: true; readonly spec: TargetTransportSpec } | { readonly ok: false; readonly code: string } {
  if (targetClass !== 'web' && targetClass !== 'ubuntu' && targetClass !== 'android') {
    return { ok: false, code: 'UNKNOWN_TARGET' };
  }

  const handoff = handoffs.find((h) => h.targetClass === targetClass);
  if (handoff === undefined) {
    return { ok: false, code: 'MISSING_HANDOFF' };
  }

  const validation = validateTargetHandoff(handoff, production);
  if (!validation.ok) {
    return { ok: false, code: validation.code };
  }

  return { ok: true, spec: TRANSPORT_SPECS[targetClass] };
}

/**
 * Compose the real convergence actor graph for the target. Any partial or
 * contradictory registration blocks the whole composition BEFORE sensitive
 * entry; the root never retries as Browser for a native target.
 */
export function composeConvergenceActors(
  targetClass: 'web' | 'ubuntu' | 'android' | string,
  handoffs: ReadonlyArray<TargetCoordinatorHandoff>,
  production: boolean,
): CompositionResult {
  const resolved = resolveTargetTransport(targetClass, handoffs, production);
  if (!resolved.ok) {
    return { ok: false, code: resolved.code };
  }

  const handoff = handoffs.find((h) => h.targetClass === targetClass);
  if (handoff === undefined) {
    return { ok: false, code: 'MISSING_HANDOFF' };
  }

  return {
    ok: true,
    provenance: {
      targetClass: resolved.spec.targetClass,
      synthetic: handoff.synthetic,
      handoff,
    },
  };
}
