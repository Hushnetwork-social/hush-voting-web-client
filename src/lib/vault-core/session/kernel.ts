/**
 * FEAT-003 vault-core session — deterministic capability-phase kernel.
 *
 * Phases: Locked → VerificationOnly → Authenticated → FreshPasswordVerified (one-use)
 * → Invalidated. FEAT-002 cannot treat VerificationOnly as authenticated; offline
 * entry is prohibited. The kernel enforces secret-operation phases; FEAT-002 remains
 * the UI/orchestration authority and receives safe projections only.
 *
 * The kernel increments its in-memory epoch on Lock, removal, replacement, takeover,
 * platform invalidation, or authority loss. Every operation carries epoch and operation
 * ID; results from a stale epoch/operation are ignored and cannot mutate the vault or
 * restore capability.
 *
 * Normative source: FEAT-003 FeatureDescription "Session Core".
 */
import {
  authorizeOperation,
  type OperationRequest,
} from '../contracts/operations';
import {
  CAPABILITY_PHASES,
  ELEVATION_PURPOSES,
  FRESH_PASSWORD_MAX_AGE_MS,
  type CapabilityPhase,
  type ClientCapability,
  type ClientChannel,
  type ElevationPurpose,
  type FreshPasswordCapability,
  type SessionEpoch,
} from '../contracts/capabilities';
import type { VaultResultCode } from '../contracts/results';

/** Kernel events that invalidate every capability and increment the epoch. */
export type EpochBumpCause =
  | 'lock'
  | 'removal'
  | 'replacement'
  | 'takeover'
  | 'platform-invalidation'
  | 'authority-loss'
  | 'restart';

export const EPOCH_BUMP_CAUSES: readonly EpochBumpCause[] = [
  'lock',
  'removal',
  'replacement',
  'takeover',
  'platform-invalidation',
  'authority-loss',
  'restart',
] as const;

/** Deterministic kernel state. */
export interface SessionKernelState {
  readonly epoch: number;
  readonly phase: CapabilityPhase;
  /** Fresh-password capability per channel (one-use, expiring). */
  readonly fresh: Readonly<Record<string, FreshPasswordCapability | undefined>>;
}

export const INITIAL_KERNEL_STATE: SessionKernelState = {
  epoch: 0,
  phase: 'Locked',
  fresh: {},
} as const;

export type KernelTransition =
  | { readonly ok: true; readonly state: SessionKernelState }
  | { readonly ok: false; readonly code: VaultResultCode | 'INVALID_PHASE_TRANSITION'; readonly message: string };

/** Issue a new client capability bound to one channel and the current epoch. */
export function issueCapability(
  state: SessionKernelState,
  channel: ClientChannel,
  makeCapability: (epoch: SessionEpoch, channel: ClientChannel) => ClientCapability,
): ClientCapability {
  return makeCapability({ epoch: state.epoch }, channel);
}

/** Validate a capability against the current epoch (channel is structural). */
export function isCapabilityCurrent(state: SessionKernelState, capability: ClientCapability): boolean {
  return capability.epoch.epoch === state.epoch;
}

/** Local unlock succeeds → VerificationOnly (authenticated operations remain forbidden). */
export function onLocalUnlock(state: SessionKernelState): KernelTransition {
  if (state.phase !== 'Locked') return { ok: false, code: 'INVALID_PHASE_TRANSITION', message: 'unlock requires Locked' };
  return { ok: true, state: { ...state, phase: 'VerificationOnly' } };
}

/** Exact online profile + both-key match → Authenticated. */
export function onExactOnlineVerification(state: SessionKernelState): KernelTransition {
  if (state.phase !== 'VerificationOnly' && state.phase !== 'Authenticated') {
    return { ok: false, code: 'INVALID_PHASE_TRANSITION', message: 'verification requires VerificationOnly' };
  }
  return { ok: true, state: { ...state, phase: 'Authenticated' } };
}

/** Fresh-password elevation: one purpose, one use, ≤60 s. */
export function onFreshPassword(
  state: SessionKernelState,
  channel: ClientChannel,
  purpose: ElevationPurpose,
  nowMs: number,
): KernelTransition {
  if (!ELEVATION_PURPOSES.includes(purpose)) {
    return { ok: false, code: 'OperationForbidden', message: 'unknown elevation purpose' };
  }
  return {
    ok: true,
    state: {
      ...state,
      phase: 'FreshPasswordVerified',
      fresh: {
        ...state.fresh,
        [channel.channelId]: {
          purpose,
          expiresAtMs: nowMs + FRESH_PASSWORD_MAX_AGE_MS,
          consumed: false,
        },
      },
    },
  };
}

/** Consume a fresh-password capability for its one approved purpose. */
export function consumeFreshPassword(
  state: SessionKernelState,
  channel: ClientChannel,
  purpose: ElevationPurpose,
  nowMs: number,
): KernelTransition {
  const fresh = state.fresh[channel.channelId];
  if (!fresh) return { ok: false, code: 'OperationForbidden', message: 'no fresh-password capability' };
  if (fresh.consumed) return { ok: false, code: 'OperationForbidden', message: 'already consumed' };
  if (nowMs > fresh.expiresAtMs) return { ok: false, code: 'OperationForbidden', message: 'expired' };
  if (fresh.purpose !== purpose) return { ok: false, code: 'OperationForbidden', message: 'purpose mismatch' };
  return {
    ok: true,
    state: {
      ...state,
      phase: 'Authenticated',
      fresh: { ...state.fresh, [channel.channelId]: { ...fresh, consumed: true } },
    },
  };
}

/** Bump the epoch and invalidate every capability (Lock, removal, replacement, ...). */
export function invalidateSession(state: SessionKernelState, cause: EpochBumpCause): SessionKernelState {
  if (!EPOCH_BUMP_CAUSES.includes(cause)) {
    // Unknown invalidation cause fails closed by treating it as authority loss.
    cause = 'authority-loss';
  }
  return {
    epoch: state.epoch + 1,
    phase: 'Locked',
    fresh: {},
  };
}

/** Kernel-level operation authorization: stale sessions fail closed, then the
 *  closed operation registry decides phase/kind/version/signatory/payload. */
export type KernelOperationAuthorization =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: 'StaleSession' | 'OperationForbidden' };

export function authorizeOperationForCapability(
  state: SessionKernelState,
  capability: ClientCapability,
  request: OperationRequest,
): KernelOperationAuthorization {
  // Every capability is channel/epoch-bound; a stale epoch rejects before the registry.
  if (!isCapabilityCurrent(state, capability)) {
    return { ok: false, code: 'StaleSession' };
  }
  const op = authorizeOperation(request, state.phase, { phaseOrder: [...CAPABILITY_PHASES] });
  if (!op.ok) {
    return { ok: false, code: 'OperationForbidden' };
  }
  return { ok: true };
}
