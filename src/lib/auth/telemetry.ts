/**
 * FEAT-002 telemetry gate — opt-in, first-party, allowlisted, aggregate.
 *
 * Authentication never interrupts the user to request telemetry consent.
 * Events are emitted ONLY when a general application preference already
 * records explicit opt-in. Declining has no functional effect. Without
 * consent, no authentication telemetry is emitted at all.
 *
 * Allowed fields: platform, application version, coarse flow stage, typed
 * outcome, coarse duration. NEVER: stable user/device/session identifier,
 * alias, blockchain address, election identifier, credential material, file
 * details, password data, support free text, or raw exception.
 *
 * Normative source: FeatureDescription "Privacy, Logging, and Telemetry".
 */

import type { AllowlistedTelemetryEvent } from './ports';

/** Coarse flow stages allowed in telemetry (no fine-grained state). */
export type TelemetryStage = AllowlistedTelemetryEvent['coarseStage'];

/** Gate: only emit when explicit opt-in is already recorded. */
export function telemetryEnabled(preference: { explicitOptIn: boolean }): boolean {
  return preference.explicitOptIn;
}

/**
 * Validate an event against the allowlist. Rejects any prohibited field and
 * never forwards it to the sink. Returns null when the event is not allowed.
 */
export function validateTelemetryEvent(event: AllowlistedTelemetryEvent): AllowlistedTelemetryEvent | null {
  const forbidden = [
    'userId',
    'alias',
    'address',
    'electionId',
    'election',
    'mnemonic',
    'password',
    'credential',
    'fileName',
    'supportText',
    'stack',
    'exception',
    'rawError',
  ] as const;

  const serialized = JSON.stringify(event);
  for (const key of forbidden) {
    if (serialized.includes(`"${key}"`)) {
      return null;
    }
  }

  // Coarse stage + typed outcome allowlist at the value level.
  const stages: readonly TelemetryStage[] = [
    'initializing',
    'noLocalUser',
    'locked',
    'authenticated',
    'error',
    'removal',
  ];
  if (!stages.includes(event.coarseStage)) {
    return null;
  }
  if (event.typedOutcome !== null && typeof event.typedOutcome !== 'string') {
    return null;
  }
  if (event.coarseDurationMs !== null && (event.coarseDurationMs < 0 || event.coarseDurationMs > 24 * 60 * 60 * 1000)) {
    return null;
  }
  return event;
}

/** Emit one allowlisted event through the sink only when gated. */
export function emitTelemetry(
  preference: { explicitOptIn: boolean },
  sink: ((event: AllowlistedTelemetryEvent) => void) | null,
  event: AllowlistedTelemetryEvent,
): void {
  if (!telemetryEnabled(preference) || sink === null) {
    return;
  }
  const allowed = validateTelemetryEvent(event);
  if (allowed !== null) {
    sink(allowed);
  }
}
