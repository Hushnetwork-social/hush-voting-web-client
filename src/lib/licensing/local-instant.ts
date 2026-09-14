/**
 * FEAT-017 Task 4.3 — LocalLicenceInstant presentation primitive: renders the
 * authoritative server UTC instants of a licence in the user's local timezone
 * with an unambiguous UTC offset, while the source UTC data is never mutated
 * or replaced (D017-07). Upper-exclusive expiry semantics stay explicit, a
 * perpetual licence never invents an expiry, and pre-index one-year targets
 * show the authoritative term without fabricated effective/expiry instants.
 *
 * Determinism contract: every function is pure; timezone rendering uses a
 * FIXED locale and an explicit IANA timezone so tests pin UTC, positive and
 * negative offsets, daylight-transition boundaries, leap-year boundaries, and
 * invalid values. Offset text is computed arithmetically from wall-clock
 * parts (never parsed from a locale abbreviation), producing the canonical
 * `UTC+01:00` form from the approved wireframes. Abbreviations such as
 * "WEST" are NOT emitted because they are not available deterministically
 * across runtimes; the numeric UTC offset is the unambiguous timezone signal.
 *
 * SECRET/DATE BOUNDARY: this module never writes dates back to authority
 * state, never infers an expiry when the server sent none, and never invents
 * an activation instant for an unactivated target.
 *
 * Normative source: FEAT-017 FeatureDescription D017-07; design-summary.md
 * "Time display", "LocalLicenceInstant"; Wireframes-design.md A0/L1/C0/R0
 * (Effective from / Expires (exclusive) rows, Perpetual, One-year term);
 * planning-analysis-report §13.2.
 */

import { licenceUpgradeCopy } from './upgrade-copy';

const ISO_UTC_RE = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/;
/** Hard bound mirrored from the projection (`isIsoUtc`). */
const MAX_ISO_LENGTH = 64;

export type LicenceUtcInstantParseResult =
  | { readonly ok: true; readonly epochMs: number; readonly isoUtc: string }
  | { readonly ok: false; readonly reason: 'invalid-utc-instant' };

/**
 * Strict UTC ISO-8601 parse with round-trip validation: normalization of
 * impossible calendar dates (e.g. 29 February 2023) and out-of-range clock
 * values is detected and rejected — never coerced.
 */
export function parseLicenceUtcInstant(value: unknown): LicenceUtcInstantParseResult {
  if (typeof value !== 'string' || value.length === 0 || value.length > MAX_ISO_LENGTH) {
    return { ok: false, reason: 'invalid-utc-instant' };
  }
  const match = ISO_UTC_RE.exec(value);
  if (match === null) {
    return { ok: false, reason: 'invalid-utc-instant' };
  }
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const hour = Number(match[4]);
  const minute = Number(match[5]);
  const second = Number(match[6]);
  const millis = match[7] === undefined ? 0 : Number(match[7].padEnd(3, '0'));
  const epochMs = Date.UTC(year, month - 1, day, hour, minute, second, millis);
  if (!Number.isFinite(epochMs)) {
    return { ok: false, reason: 'invalid-utc-instant' };
  }
  const probe = new Date(epochMs);
  // Round-trip: an impossible input would normalize to different fields.
  if (
    probe.getUTCFullYear() !== year ||
    probe.getUTCMonth() + 1 !== month ||
    probe.getUTCDate() !== day ||
    probe.getUTCHours() !== hour ||
    probe.getUTCMinutes() !== minute ||
    probe.getUTCSeconds() !== second ||
    probe.getUTCMilliseconds() !== millis
  ) {
    return { ok: false, reason: 'invalid-utc-instant' };
  }
  return { ok: true, epochMs, isoUtc: value };
}

/**
 * Deterministic local clock facts for one UTC instant in one IANA timezone.
 * Null when the instant is invalid or the timezone is unknown — presentation
 * must never substitute a guessed zone.
 */
export interface LocalDateTimeFacts {
  /** Canonical IANA timezone id (never a guessed abbreviation). */
  readonly timeZoneId: string;
  readonly year: number;
  readonly month: number;
  readonly day: number;
  readonly hour: number;
  readonly minute: number;
  readonly second: number;
  /** Whole-minute UTC offset at THIS instant (DST-aware). */
  readonly offsetMinutes: number;
  /** Canonical unambiguous offset text, e.g. `UTC+01:00`. */
  readonly offsetText: string;
  /** `6 September 2026`. */
  readonly dateText: string;
  /** `21:35`. */
  readonly timeText: string;
  /** Source UTC instant is retained for semantics (never replaced). */
  readonly utcIso: string;
}

/** Canonical offset text `UTC+01:00` / `UTC-05:00` / `UTC+00:00`. */
export function canonicalUtcOffsetText(offsetMinutes: number): string {
  const sign = offsetMinutes < 0 ? '-' : '+';
  const absolute = Math.abs(offsetMinutes);
  const hours = Math.floor(absolute / 60);
  const minutes = absolute % 60;
  return `UTC${sign}${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}`;
}

/** Wall-clock parts of one instant in a timezone (formatToParts helper). */
function wallClockParts(epochMs: number, timeZone: string): Record<string, string> {
  const formatter = new Intl.DateTimeFormat('en-GB', {
    timeZone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
  });
  const parts = formatter.formatToParts(new Date(epochMs));
  const values: Record<string, string> = {};
  for (const part of parts) {
    if (part.type !== 'literal') {
      values[part.type] = part.value;
    }
  }
  return values;
}

function isValidTimeZone(timeZone: string): boolean {
  try {
    void new Intl.DateTimeFormat('en-GB', { timeZone }).format();
    return true;
  } catch {
    return false;
  }
}

/** Deterministic local facts; null on invalid instant or unknown timezone. */
export function localDateTimeFacts(utcIso: unknown, timeZone: string): LocalDateTimeFacts | null {
  const parsed = parseLicenceUtcInstant(utcIso);
  if (!parsed.ok || !isValidTimeZone(timeZone)) {
    return null;
  }
  const { epochMs } = parsed;
  const wall = wallClockParts(epochMs, timeZone);
  const year = Number(wall.year);
  const month = Number(wall.month);
  const day = Number(wall.day);
  const hour = Number(wall.hour);
  const minute = Number(wall.minute);
  const second = Number(wall.second);
  if (
    !Number.isInteger(year) ||
    !Number.isInteger(month) ||
    !Number.isInteger(day) ||
    !Number.isInteger(hour) ||
    !Number.isInteger(minute) ||
    !Number.isInteger(second)
  ) {
    return null;
  }
  // Offset is arithmetic: wall clock read as UTC minus the real instant.
  const wallAsUtcMs = Date.UTC(year, month - 1, day, hour, minute, second);
  const offsetMinutes = Math.round((wallAsUtcMs - epochMs) / 60_000);

  const longFormatter = new Intl.DateTimeFormat('en-GB', {
    timeZone,
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
  const dateParts = longFormatter.formatToParts(new Date(epochMs));
  const dayOfMonth = dateParts.find((part) => part.type === 'day')?.value ?? String(day);
  const monthName = dateParts.find((part) => part.type === 'month')?.value ?? '';
  const dateText = `${dayOfMonth} ${monthName} ${year}`;

  return {
    timeZoneId: timeZone,
    year,
    month,
    day,
    hour,
    minute,
    second,
    offsetMinutes,
    offsetText: canonicalUtcOffsetText(offsetMinutes),
    dateText,
    timeText: `${String(hour).padStart(2, '0')}:${String(minute).padStart(2, '0')}`,
    utcIso: parsed.isoUtc,
  };
}

/**
 * Canonical combined display `6 September 2026, 21:35 UTC+01:00` (the
 * wireframe form with the numeric offset as the unambiguous timezone signal).
 */
export function formatLicenceLocalDateTime(utcIso: unknown, timeZone: string): string | null {
  const facts = localDateTimeFacts(utcIso, timeZone);
  if (facts === null) {
    return null;
  }
  return `${facts.dateText}, ${facts.timeText} ${facts.offsetText}`;
}

// ---------------------------------------------------------------------------
// Licence validity semantics (perpetual / upper-exclusive range / term-only).
// ---------------------------------------------------------------------------

export type LicenceValidityKind = 'active-range' | 'perpetual' | 'term-only';

export interface LicenceValidityFacts {
  readonly kind: LicenceValidityKind;
  /**
   * Effective instant facts (authoritative UTC retained). Present for the
   * current licence and for an indexed result; null only when the authority
   * sent no effective instant (term-only pre-index presentation).
   */
  readonly effective: LocalDateTimeFacts | null;
  /**
   * Upper-exclusive expiry instant. Present ONLY for `active-range` — a
   * perpetual licence never invents an expiry.
   */
  readonly upperExclusiveExpiry: LocalDateTimeFacts | null;
  /** True only when the server sent no expiry (no invented date shown). */
  readonly perpetual: boolean;
  /** Upper-exclusive meaning note (active-range only). */
  readonly boundaryNote: string | null;
}

export type LicenceValidityProjectionResult =
  | { readonly ok: true; readonly facts: LicenceValidityFacts }
  | { readonly ok: false; readonly reason: 'invalid-effective' | 'invalid-expiry' | 'invalid-timezone' };

/**
 * Project the validity of an INDEXED current licence. `expiresAtUtc` present
 * means an upper-exclusive expiry boundary; absent/empty means perpetual —
 * expiry is never invented. Effective-from must always be present for an
 * indexed licence.
 */
export function projectLicenceValidity(input: {
  readonly effectiveFromUtc: unknown;
  readonly expiresAtUtc?: unknown;
  readonly timeZone: string;
}): LicenceValidityProjectionResult {
  if (!isValidTimeZone(input.timeZone)) {
    return { ok: false, reason: 'invalid-timezone' };
  }
  const effective = localDateTimeFacts(input.effectiveFromUtc, input.timeZone);
  if (effective === null) {
    return { ok: false, reason: 'invalid-effective' };
  }
  const hasExpiry =
    input.expiresAtUtc !== undefined && input.expiresAtUtc !== null && input.expiresAtUtc !== '';
  if (!hasExpiry) {
    return {
      ok: true,
      facts: {
        kind: 'perpetual',
        effective,
        upperExclusiveExpiry: null,
        perpetual: true,
        boundaryNote: null,
      },
    };
  }
  const expiry = localDateTimeFacts(input.expiresAtUtc, input.timeZone);
  if (expiry === null) {
    return { ok: false, reason: 'invalid-expiry' };
  }
  return {
    ok: true,
    facts: {
      kind: 'active-range',
      effective,
      upperExclusiveExpiry: expiry,
      perpetual: false,
      boundaryNote: licenceUpgradeCopy('validUntilBoundaryNote'),
    },
  };
}

/**
 * Term label for a pre-index TARGET (option/confirmation): derived ONLY from
 * the validated server term fields; no committed activation/expiry dates are
 * invented. `perpetual` → "Perpetual"; one year → "One-year term"; N years →
 * "N-year term" (only for recognized term kinds); unknown/absent → null
 * (row omitted). An unknown term kind is never coerced.
 */
export function licenceTermLabel(termKind: unknown, termYears: unknown): string | null {
  if (termKind === 'perpetual') {
    return licenceUpgradeCopy('valuePerpetual');
  }
  const kindAllowed = termKind === undefined || termKind === null || termKind === 'annual' || termKind === 'term';
  if (!kindAllowed) {
    return null;
  }
  if (typeof termYears === 'number' && Number.isInteger(termYears) && termYears >= 1) {
    if (termYears === 1) {
      return licenceUpgradeCopy('valueOneYearTerm');
    }
    return `${termYears}-year term`;
  }
  return null;
}
