/**
 * FEAT-017 Task 4.4 — LocalLicenceInstant tests.
 *
 * Proves deterministic UTC→local rendering: strict UTC parse with round-trip
 * rejection of impossible calendar/clock values (leap-year boundaries,
 * out-of-range fields); local facts across UTC, positive and negative
 * offsets, and daylight-transition boundaries; canonical `UTC±hh:mm` offset
 * text (never a guessed abbreviation); invalid timezones fail closed; a
 * perpetual licence never invents an expiry; upper-exclusive expiry carries
 * its boundary note; and pre-index term labels derive only from validated
 * server term fields (no committed dates).
 */

import { describe, expect, it } from 'vitest';
import {
  canonicalUtcOffsetText,
  formatLicenceLocalDateTime,
  licenceTermLabel,
  localDateTimeFacts,
  parseLicenceUtcInstant,
  projectLicenceValidity,
} from './local-instant';

const LISBON = 'Europe/Lisbon';
const NEW_YORK = 'America/New_York';
const LONDON = 'Europe/London';

describe('strict UTC instant parsing (round-trip, never coerced)', () => {
  it('accepts valid UTC ISO-8601 instants with optional millis', () => {
    expect(parseLicenceUtcInstant('2026-09-06T20:35:00Z').ok).toBe(true);
    expect(parseLicenceUtcInstant('2026-09-06T20:35:00.000Z').ok).toBe(true);
    expect(parseLicenceUtcInstant('2026-09-06T20:35:00.123Z').ok).toBe(true);
    // Leap-year boundary is valid.
    expect(parseLicenceUtcInstant('2024-02-29T12:00:00Z').ok).toBe(true);
    expect(parseLicenceUtcInstant('2000-02-29T00:00:00Z').ok).toBe(true);
  });

  it('rejects impossible calendar and clock values instead of normalizing them', () => {
    expect(parseLicenceUtcInstant('2023-02-29T12:00:00Z')).toEqual({
      ok: false,
      reason: 'invalid-utc-instant',
    });
    expect(parseLicenceUtcInstant('2026-13-01T00:00:00Z').ok).toBe(false);
    expect(parseLicenceUtcInstant('2026-00-01T00:00:00Z').ok).toBe(false);
    expect(parseLicenceUtcInstant('2026-01-32T00:00:00Z').ok).toBe(false);
    expect(parseLicenceUtcInstant('2026-01-01T24:00:00Z').ok).toBe(false);
    expect(parseLicenceUtcInstant('2026-01-01T23:60:00Z').ok).toBe(false);
    expect(parseLicenceUtcInstant('2026-01-01T23:59:60Z').ok).toBe(false);
  });

  it('rejects malformed, offset-bearing, and non-Z forms (UTC data is never rewritten)', () => {
    expect(parseLicenceUtcInstant('not-a-date').ok).toBe(false);
    expect(parseLicenceUtcInstant('2026/01/01T00:00:00Z').ok).toBe(false);
    expect(parseLicenceUtcInstant('2026-01-01T00:00:00+01:00').ok).toBe(false);
    expect(parseLicenceUtcInstant('2026-01-01t00:00:00z').ok).toBe(false);
    expect(parseLicenceUtcInstant('').ok).toBe(false);
    expect(parseLicenceUtcInstant(null).ok).toBe(false);
    expect(parseLicenceUtcInstant(1234567890).ok).toBe(false);
    expect(parseLicenceUtcInstant('2026-01-01T00:00:00.1234Z').ok).toBe(false);
    expect(parseLicenceUtcInstant('2026-01-01T00:00:00Z'.padEnd(70, ' ')).ok).toBe(false);
  });
});

describe('canonical offset text', () => {
  it('formats whole-minute offsets deterministically', () => {
    expect(canonicalUtcOffsetText(0)).toBe('UTC+00:00');
    expect(canonicalUtcOffsetText(60)).toBe('UTC+01:00');
    expect(canonicalUtcOffsetText(-300)).toBe('UTC-05:00');
    expect(canonicalUtcOffsetText(840)).toBe('UTC+14:00');
    expect(canonicalUtcOffsetText(345)).toBe('UTC+05:45');
  });
});

describe('local facts across timezones and DST boundaries', () => {
  it('renders UTC input in UTC unchanged', () => {
    const facts = localDateTimeFacts('2026-09-06T20:35:00Z', 'UTC');
    expect(facts).not.toBeNull();
    expect(facts?.dateText).toBe('6 September 2026');
    expect(facts?.timeText).toBe('20:35');
    expect(facts?.offsetText).toBe('UTC+00:00');
    expect(facts?.utcIso).toBe('2026-09-06T20:35:00Z');
  });

  it('renders Lisbon summer time with a positive offset (unambiguous timezone)', () => {
    const facts = localDateTimeFacts('2026-09-06T20:35:00Z', LISBON);
    expect(facts?.dateText).toBe('6 September 2026');
    expect(facts?.timeText).toBe('21:35');
    expect(facts?.offsetText).toBe('UTC+01:00');
    expect(facts?.timeZoneId).toBe(LISBON);
  });

  it('renders New York with a negative offset', () => {
    const facts = localDateTimeFacts('2026-09-06T20:35:00Z', NEW_YORK);
    expect(facts?.timeText).toBe('16:35');
    expect(facts?.offsetText).toBe('UTC-04:00'); // EDT
  });

  it('is DST-aware across the spring transition (Europe/London)', () => {
    const winter = localDateTimeFacts('2026-03-29T00:30:00Z', LONDON);
    const summer = localDateTimeFacts('2026-03-29T01:30:00Z', LONDON);
    expect(winter?.timeText).toBe('00:30');
    expect(winter?.offsetText).toBe('UTC+00:00');
    expect(summer?.timeText).toBe('02:30');
    expect(summer?.offsetText).toBe('UTC+01:00');
  });

  it('is DST-aware across the autumn transition (Europe/London)', () => {
    const before = localDateTimeFacts('2026-10-25T00:30:00Z', LONDON);
    const after = localDateTimeFacts('2026-10-25T01:30:00Z', LONDON);
    expect(before?.offsetText).toBe('UTC+01:00');
    expect(after?.offsetText).toBe('UTC+00:00');
  });

  it('handles extreme whole-day offsets (+14 / -11)', () => {
    expect(localDateTimeFacts('2026-09-06T20:35:00Z', 'Pacific/Kiritimati')?.offsetText).toBe(
      'UTC+14:00',
    );
    expect(localDateTimeFacts('2026-09-06T20:35:00Z', 'Pacific/Pago_Pago')?.offsetText).toBe(
      'UTC-11:00',
    );
  });

  it('fails closed for an unknown timezone and an invalid instant', () => {
    expect(localDateTimeFacts('2026-09-06T20:35:00Z', 'Mars/Olympus_Mons')).toBeNull();
    expect(localDateTimeFacts('junk', LISBON)).toBeNull();
  });

  it('formats the canonical combined display string', () => {
    expect(formatLicenceLocalDateTime('2026-09-06T20:35:00Z', LISBON)).toBe(
      '6 September 2026, 21:35 UTC+01:00',
    );
    expect(formatLicenceLocalDateTime('junk', LISBON)).toBeNull();
    expect(formatLicenceLocalDateTime('2026-09-06T20:35:00Z', 'Nope/Zone')).toBeNull();
  });
});

describe('licence validity projection', () => {
  it('never invents an expiry for a perpetual licence', () => {
    const result = projectLicenceValidity({
      effectiveFromUtc: '2026-09-06T20:35:00Z',
      expiresAtUtc: undefined,
      timeZone: LISBON,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.facts.kind).toBe('perpetual');
    expect(result.facts.perpetual).toBe(true);
    expect(result.facts.upperExclusiveExpiry).toBeNull();
    expect(result.facts.boundaryNote).toBeNull();
    expect(result.facts.effective?.utcIso).toBe('2026-09-06T20:35:00Z');
  });

  it('treats an empty expiry string as perpetual (no fabricated boundary)', () => {
    const result = projectLicenceValidity({
      effectiveFromUtc: '2026-09-06T20:35:00Z',
      expiresAtUtc: '',
      timeZone: LISBON,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.facts.perpetual).toBe(true);
  });

  it('projects an upper-exclusive active range with its boundary note', () => {
    const result = projectLicenceValidity({
      effectiveFromUtc: '2026-09-07T12:24:00Z',
      expiresAtUtc: '2027-09-07T12:24:00Z',
      timeZone: LISBON,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.facts.kind).toBe('active-range');
    expect(result.facts.perpetual).toBe(false);
    expect(result.facts.upperExclusiveExpiry?.dateText).toBe('7 September 2027');
    expect(result.facts.upperExclusiveExpiry?.offsetText).toBe('UTC+01:00');
    expect(result.facts.boundaryNote).toBe('Valid until the displayed expiry moment.');
  });

  it('keeps UTC data authoritative inside local facts', () => {
    const result = projectLicenceValidity({
      effectiveFromUtc: '2026-09-07T12:24:00.123Z',
      expiresAtUtc: '2027-09-07T12:24:00.123Z',
      timeZone: NEW_YORK,
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.facts.effective?.utcIso).toBe('2026-09-07T12:24:00.123Z');
    expect(result.facts.upperExclusiveExpiry?.utcIso).toBe('2027-09-07T12:24:00.123Z');
    expect(result.facts.effective?.offsetText).toBe('UTC-04:00');
  });

  it('handles a leap-day expiry boundary deterministically', () => {
    const result = projectLicenceValidity({
      effectiveFromUtc: '2024-02-29T00:00:00Z',
      expiresAtUtc: '2025-02-28T23:59:59Z',
      timeZone: 'UTC',
    });
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.facts.effective?.dateText).toBe('29 February 2024');
  });

  it('fails closed on invalid effective/expiry instants or timezones', () => {
    expect(
      projectLicenceValidity({ effectiveFromUtc: '2023-02-29T00:00:00Z', timeZone: LISBON }),
    ).toEqual({ ok: false, reason: 'invalid-effective' });
    expect(
      projectLicenceValidity({
        effectiveFromUtc: '2026-01-01T00:00:00Z',
        expiresAtUtc: 'not-a-date',
        timeZone: LISBON,
      }),
    ).toEqual({ ok: false, reason: 'invalid-expiry' });
    expect(
      projectLicenceValidity({
        effectiveFromUtc: '2026-01-01T00:00:00Z',
        timeZone: 'Nope/Zone',
      }),
    ).toEqual({ ok: false, reason: 'invalid-timezone' });
  });
});

describe('pre-index term labels (no committed dates)', () => {
  it('derives term text only from validated server term fields', () => {
    expect(licenceTermLabel('perpetual', 0)).toBe('Perpetual');
    expect(licenceTermLabel('annual', 1)).toBe('One-year term');
    expect(licenceTermLabel('annual', 3)).toBe('3-year term');
    expect(licenceTermLabel(undefined, undefined)).toBeNull();
    // An unknown term kind is never coerced into a year-term label.
    expect(licenceTermLabel('mystery', 1)).toBeNull();
    expect(licenceTermLabel('annual', 0)).toBeNull();
    expect(licenceTermLabel('annual', 1.5)).toBeNull();
    expect(licenceTermLabel('annual', -1)).toBeNull();
    expect(licenceTermLabel('term', 2)).toBe('2-year term');
  });
});
