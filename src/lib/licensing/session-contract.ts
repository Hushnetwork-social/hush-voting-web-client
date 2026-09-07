/**
 * FEAT-016 Task 6.3 — entitlement-bootstrap session contract (shared).
 *
 * The closed vocabulary exchanged between the page composition bridge and the
 * SharedWorker/native authority for the entitlement bootstrap. Page code may
 * import this module; it carries NO secret or exact-bytes material — only
 * safe snapshots, progress, and typed control intents.
 *
 * Normative source: FEAT-016 FeatureDescription "Web" (one SharedWorker-owned
 * loop; safe progress/projection only), "Authority and Target Composition",
 * "Security, Privacy, Performance, and Observability".
 */

import type { EntitlementPhase } from './coordinator';
import type { LicenceSafeProjection } from './projection';

/** Safe snapshot a page may render (never secrets/bytes/journal state). */
export interface LicenceBootstrapSnapshot {
  readonly phase: EntitlementPhase;
  /** Runtime-memory-only safe projection; null until compatible active truth. */
  readonly projection: LicenceSafeProjection | null;
  readonly lastOutcomeCode: string | null;
  /** Opaque pending transaction id when one exists (public on-chain ref). */
  readonly pendingTransactionId: string | null;
}

/** Closed page→authority control intents (retry/recovery/revalidation). */
export type LicenceBootstrapControlKind = 'retry' | 'recover' | 'revalidate';

/** Revalidation trigger vocabulary (closed; bounds the payload). */
export type LicenceRevalidationTrigger =
  | 'foreground'
  | 'reconnect'
  | 'expiry'
  | 'account-entry'
  | 'authoritative-rejection'
  | 'explicit-recovery';

/** Closed connectivity inputs forwarded from the page connectivity authority. */
export type LicenceConnectivityInput = 'online' | 'offline' | 'paused' | 'reconnecting';

/** Eligibility inputs for the authority-owned reconciliation loop. */
export interface LicenceBootstrapEligibility {
  readonly foregrounded?: boolean;
  readonly connectivity?: LicenceConnectivityInput;
}

/** Worker→page progress event payload (additive protocol event). */
export interface LicenceProgressPayload extends LicenceBootstrapSnapshot {
  /** Epoch at emission time (page-side filtering; not an authority secret). */
  readonly emittedAtMs: number;
}

/** Safe outcome payload of a bootstrap step (returned by every licence op). */
export type LicenceBootstrapStepResult =
  | { readonly ok: true; readonly snapshot: LicenceBootstrapSnapshot }
  | { readonly ok: false; readonly reason: 'not-authenticated' | 'invalid-input' | 'authority-unavailable' };

/** Closed op outcome codes the authority may surface for licence steps. */
export type LicenceBootstrapOpOutcome = 'OK' | 'INVALID_INPUT' | 'AUTHORITY_REJECTED';

export const LICENCE_REVALIDATION_TRIGGERS: readonly LicenceRevalidationTrigger[] = [
  'foreground',
  'reconnect',
  'expiry',
  'account-entry',
  'authoritative-rejection',
  'explicit-recovery',
] as const;

export function isLicenceRevalidationTrigger(value: unknown): value is LicenceRevalidationTrigger {
  return typeof value === 'string' && (LICENCE_REVALIDATION_TRIGGERS as readonly string[]).includes(value);
}

export function isLicenceConnectivityInput(value: unknown): value is LicenceConnectivityInput {
  return value === 'online' || value === 'offline' || value === 'paused' || value === 'reconnecting';
}

export function isLicenceBootstrapControlKind(value: unknown): value is LicenceBootstrapControlKind {
  return value === 'retry' || value === 'recover' || value === 'revalidate';
}
