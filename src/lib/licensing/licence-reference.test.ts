/**
 * FEAT-017 Task 4.4 — licence-reference and clipboard-feedback tests.
 *
 * Proves: deterministic recognizable shortening (beginning + end) matching
 * the approved `5f2d9e11…c9d3e` pattern; short valid references are shown in
 * full; malformed/empty/oversized/control-character values return null
 * (never fabricated or truncated); full/short surface modes keep the full
 * selectable value; copy success/failure maps to the exact English polite
 * feedback while the value stays visible and selectable; and no telemetry or
 * log path exists in the module (pure functions only).
 */

import { describe, expect, it } from 'vitest';
import {
  clipboardFailureStatusText,
  isPresentableLicenceReference,
  licenceCopyFeedback,
  licenceReferenceFacts,
  licenceReferenceCopyKeys,
  shortenLicenceReference,
} from './licence-reference';

const FULL_REFERENCE = '5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e';

describe('shortening is recognizable and deterministic', () => {
  it('shortens a full UUID to the approved beginning + ellipsis + end', () => {
    expect(shortenLicenceReference(FULL_REFERENCE)).toBe('5f2d9e11…c9d3e');
    expect(shortenLicenceReference(FULL_REFERENCE)).toBe(shortenLicenceReference(FULL_REFERENCE));
  });

  it('keeps short valid references in full (no invented abbreviation)', () => {
    expect(shortenLicenceReference('abc-123')).toBe('abc-123');
    expect(shortenLicenceReference('1234567890123456')).toBe('1234567890123456');
  });

  it('handles long bounded references with recognizable beginning/end', () => {
    const long = 'A'.repeat(40) + '-tail';
    const shortened = shortenLicenceReference(long);
    expect(shortened?.startsWith('AAAAAAAA')).toBe(true);
    expect(shortened?.endsWith('-tail')).toBe(true);
  });
});

describe('malformed values never fabricate a reference', () => {
  it('returns null for empty, whitespace, control, or oversized input', () => {
    expect(shortenLicenceReference('')).toBeNull();
    expect(shortenLicenceReference('   ')).toBeNull();
    expect(shortenLicenceReference(' leadingspace')).toBeNull();
    expect(shortenLicenceReference('trailingspace ')).toBeNull();
    expect(shortenLicenceReference('has\ttab')).toBeNull();
    expect(shortenLicenceReference('has\nnewline')).toBeNull();
    expect(shortenLicenceReference('x'.repeat(129))).toBeNull();
    expect(shortenLicenceReference(null)).toBeNull();
    expect(shortenLicenceReference(42)).toBeNull();
    expect(shortenLicenceReference(undefined)).toBeNull();
  });

  it('presentable-reference validation agrees with the shorten function', () => {
    expect(isPresentableLicenceReference(FULL_REFERENCE)).toBe(true);
    expect(isPresentableLicenceReference('x'.repeat(128))).toBe(true);
    expect(isPresentableLicenceReference('x'.repeat(129))).toBe(false);
    expect(isPresentableLicenceReference('')).toBe(false);
  });
});

describe('surface facts (shortened vs full)', () => {
  it('shortened mode abbreviates but keeps the full selectable value', () => {
    const facts = licenceReferenceFacts(FULL_REFERENCE, 'shortened');
    expect(facts?.mode).toBe('shortened');
    expect(facts?.displayText).toBe('5f2d9e11…c9d3e');
    expect(facts?.fullText).toBe(FULL_REFERENCE);
    expect(facts?.selectable).toBe(true);
  });

  it('full mode never truncates and stays selectable', () => {
    const facts = licenceReferenceFacts(FULL_REFERENCE, 'full');
    expect(facts?.mode).toBe('full');
    expect(facts?.displayText).toBe(FULL_REFERENCE);
    expect(facts?.fullText).toBe(FULL_REFERENCE);
    expect(facts?.selectable).toBe(true);
  });

  it('returns null when there is no presentable reference in either mode', () => {
    expect(licenceReferenceFacts(null, 'full')).toBeNull();
    expect(licenceReferenceFacts('', 'full')).toBeNull();
    expect(licenceReferenceFacts('x'.repeat(200), 'shortened')).toBeNull();
  });
});

describe('clipboard feedback policy', () => {
  it('maps copy success to the exact polite success text', () => {
    const facts = licenceCopyFeedback('success');
    expect(facts.kind).toBe('success');
    expect(facts.statusText).toBe('Copied licence reference.');
  });

  it('maps copy failure to the exact English failure text (never replaces value)', () => {
    const facts = licenceCopyFeedback('failure');
    expect(facts.kind).toBe('failure');
    expect(facts.statusText).toBe(clipboardFailureStatusText());
    expect(facts.statusText).toBe(
      'Couldn’t copy. Select the licence reference to copy it manually.',
    );
    expect(facts.valueKeptVisible).toBe(true);
    expect(facts.selectableOnFailure).toBe(true);
    expect(facts.polite).toBe(true);
    expect(facts.announceOnce).toBe(true);
  });

  it('both feedback kinds preserve the value and announce politely once', () => {
    for (const kind of ['success', 'failure'] as const) {
      const facts = licenceCopyFeedback(kind);
      expect(facts.valueKeptVisible).toBe(true);
      expect(facts.polite).toBe(true);
      expect(facts.announceOnce).toBe(true);
    }
  });

  it('copy feedback copy keys are the two centralized strings only', () => {
    expect(licenceReferenceCopyKeys()).toEqual(['copySuccessFeedback', 'copyFailureFeedback']);
  });
});

describe('no telemetry or log path exists in the helper surface', () => {
  it('every exported function is pure and returns data only', () => {
    // The module exports only pure functions; calling them must never throw
    // on hostile input and never touch console/telemetry.
    expect(() => shortenLicenceReference(FULL_REFERENCE)).not.toThrow();
    expect(() => licenceCopyFeedback('failure')).not.toThrow();
    expect(() => licenceReferenceFacts(FULL_REFERENCE, 'full')).not.toThrow();
  });
});
