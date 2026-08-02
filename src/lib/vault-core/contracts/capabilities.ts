/**
 * FEAT-003 vault-core contracts — opaque capability model and session vocabulary.
 *
 * The page receives safe public metadata and a non-persisted opaque session reference.
 * Capability phases: Locked → VerificationOnly → Authenticated → FreshPasswordVerified
 * (one-use) → Invalidated. FEAT-002 cannot treat VerificationOnly as authenticated;
 * offline entry is prohibited. Session references are channel/epoch-bound,
 * non-serializable/non-persisted, non-transferable, and invalid after Lock, removal,
 * replacement, takeover, authority loss, process death, or restart.
 *
 * Normative source: FEAT-003 FeatureDescription "Session Core".
 */

/** Capability phases enforced by the vault kernel (not UI conventions). */
export type CapabilityPhase =
  | 'Locked'
  | 'VerificationOnly'
  | 'Authenticated'
  | 'FreshPasswordVerified'
  | 'Invalidated';

export const CAPABILITY_PHASES: readonly CapabilityPhase[] = [
  'Locked',
  'VerificationOnly',
  'Authenticated',
  'FreshPasswordVerified',
  'Invalidated',
] as const;

/** Opaque session epoch (monotonic in-memory). */
export interface SessionEpoch {
  readonly epoch: number;
}

/** Opaque client channel binding (one authenticated communication channel). */
export interface ClientChannel {
  readonly channelId: string;
}

/**
 * Opaque, non-persisted client capability. Held in memory only; never serialized,
 * logged, telemetrized, stored, transferred, or placed in URLs. A new tab receives a
 * fresh capability from the shared authority — never another tab's bearer value.
 */
export interface ClientCapability {
  readonly epoch: SessionEpoch;
  readonly channel: ClientChannel;
  /** Structural brand so capabilities cannot be confused with public data. */
  readonly __capability: unique symbol;
}

/** Opaque operation identifier (per capability, for cancellation and stale-result rejection). */
export interface OperationId {
  readonly id: string;
}

/** Fresh-password elevation purpose (exactly one approved purpose, one use). */
export type ElevationPurpose = 'mnemonic-reveal' | 'password-change';

export const ELEVATION_PURPOSES: readonly ElevationPurpose[] = [
  'mnemonic-reveal',
  'password-change',
] as const;

/** FreshPasswordVerified capability is one-purpose, one-use, ≤60 s. */
export interface FreshPasswordCapability {
  readonly purpose: ElevationPurpose;
  readonly expiresAtMs: number;
  readonly consumed: boolean;
}

export const FRESH_PASSWORD_MAX_AGE_MS = 60_000 as const;

/** Approved idle-lock choices (EPIC-001). */
export const IDLE_LOCK_CHOICES_MINUTES: readonly (number | 'restart')[] = [
  1, 5, 15, 30, 60, 'restart',
] as const;

/** Approved background-lock choices (EPIC-001). */
export const BACKGROUND_LOCK_CHOICES: readonly (number | 'immediate' | 'restart')[] = [
  'immediate', 30, 120, 300, 900, 'restart',
] as const;

/** Defaults from EPIC-001: five-minute idle, 30-second background. */
export const DEFAULT_IDLE_LOCK_MINUTES = 5 as const;
export const DEFAULT_BACKGROUND_LOCK_SECONDS = 30 as const;
