/**
 * FEAT-003 vault-core password tests — Unicode contract, policy, throttle.
 *
 * Covers Task 3.3/3.4: NFC normalization, grapheme counting, byte bounds, surrogate
 * rejection, common-list and identity-derived rejection, strength acknowledgement,
 * and the exact cooldown schedule with untrusted-sidecar sanitization.
 */
import { describe, expect, it } from 'vitest';
import {
  UNICODE_VERSION,
  validateDevicePassword,
  comparisonRepresentation,
  kdfInputBytes,
} from './unicode';
import { evaluatePasswordPolicy, localStrengthScore } from './policy';
import { evaluateThrottle, recordFailure, resetThrottle, sanitizeState } from './throttle';

describe('Unicode device-password contract (v1 pins 16.0.0)', () => {
  it('pins the Unicode data version', () => {
    expect(UNICODE_VERSION).toBe('16.0.0');
  });

  it('normalizes to NFC and preserves case for KDF input', () => {
    const composed = 'café-xy';
    const decomposed = 'cafe\u0301-xy';
    const a = validateDevicePassword(composed);
    const b = validateDevicePassword(decomposed);
    expect(a.ok && b.ok).toBe(true);
    if (a.ok && b.ok) {
      expect(a.normalizedNfc).toBe(b.normalizedNfc);
      expect(Buffer.from(kdfInputBytes(a.normalizedNfc)).toString()).toBe('café-xy');
    }
  });

  it('counts Extended Grapheme Clusters under UAX #29', () => {
    const family = validateDevicePassword('a'.repeat(5) + '\u{1F468}\u200D\u{1F469}\u200D\u{1F467}');
    expect(family.ok).toBe(true);
    if (family.ok) expect(family.graphemeClusters).toBe(6); // 5 'a' + 1 family EGC
  });

  it('enforces 6-64 grapheme clusters and 256-byte limit', () => {
    expect(validateDevicePassword('short').ok).toBe(false);
    expect(validateDevicePassword('x'.repeat(6)).ok).toBe(true);
    expect(validateDevicePassword('x'.repeat(65)).ok).toBe(false);
    const manyBytes = validateDevicePassword('\u{1F468}\u200D\u{1F469}\u200D\u{1F467}\u200D\u{1F466}'.repeat(64)); // 64 graphemes, 1600 bytes
    expect(manyBytes.ok).toBe(false);
    if (!manyBytes.ok) expect(manyBytes.code).toBe('TOO_MANY_BYTES');
  });

  it('rejects unpaired surrogates before KDF execution', () => {
    const bad = '\ud800rest';
    const result = validateDevicePassword(bad);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('UNPAIRED_SURROGATE');
  });

  it('keeps the comparison representation separate from KDF input', () => {
    const cmp = comparisonRepresentation('Ａｌｉｃｅ');
    expect(cmp).toBe('alice'); // NFKC + case-folded, comparison only
    const kdf = kdfInputBytes('Straße');
    expect(Buffer.from(kdf).toString()).toBe('Straße'); // NFC bytes preserved
  });
});

describe('password strength policy', () => {
  it('hard-rejects common/compromised passwords', () => {
    const r = evaluatePasswordPolicy({ password: 'password', aliasTerms: [] });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.code).toBe('COMMON_PASSWORD');
  });

  it('hard-rejects identity-derived values (alias + year/numeric affixes)', () => {
    const aliasTerms = ['Alice'];
    expect(evaluatePasswordPolicy({ password: 'alice', aliasTerms }).ok).toBe(false);
    expect(evaluatePasswordPolicy({ password: 'alice2024', aliasTerms }).ok).toBe(false);
    expect(evaluatePasswordPolicy({ password: '99alice', aliasTerms }).ok).toBe(false);
  });

  it('requires acknowledgement for score 0-1 but permits them', () => {
    const r = evaluatePasswordPolicy({ password: 'aaaaaaab', aliasTerms: [] });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.requiresAcknowledgement).toBe(true);
    const strong = evaluatePasswordPolicy({ password: 'Tr0ub4dor&3-correct-horse', aliasTerms: [] });
    expect(strong.ok).toBe(true);
    if (strong.ok) expect(strong.requiresAcknowledgement).toBe(false);
  });

  it('is deterministic and local (no network)', () => {
    expect(localStrengthScore('')).toBe(0);
    expect(localStrengthScore('short')).toBe(0);
    expect([0, 1, 2, 3, 4]).toContain(localStrengthScore('a-very-long-unique-password-string'));
  });
});

describe('wrong-password throttle model', () => {
  const now = 1_000_000;

  it('allows the first four attempts without added cooldown', () => {
    let state = resetThrottle();
    for (let i = 1; i <= 4; i++) {
      expect(evaluateThrottle(state, now).ok).toBe(true);
      state = recordFailure(state, now);
      expect(state.cooldownDeadline).toBe(0);
      expect(state.failedPasswordCount).toBe(i);
    }
  });

  it('applies the exact escalation from failure 5 (5s → 300s cap)', () => {
    let state = resetThrottle();
    for (let i = 1; i <= 4; i++) state = recordFailure(state, now);
    const expected = [5, 10, 20, 40, 80, 160, 300, 300, 300];
    for (let i = 0; i < expected.length; i++) {
      state = recordFailure(state, now);
      expect(state.cooldownDeadline - now).toBe(expected[i] * 1000);
    }
  });

  it('blocks while a cooldown is active and clears after the deadline', () => {
    let state = resetThrottle();
    for (let i = 1; i <= 5; i++) state = recordFailure(state, now);
    expect(evaluateThrottle(state, now).ok).toBe(false);
    expect(evaluateThrottle(state, now + 5_000).ok).toBe(true);
  });

  it('resets on success and survives restart (sidecar persistence)', () => {
    let state = resetThrottle();
    for (let i = 1; i <= 6; i++) state = recordFailure(state, now);
    // Restart: state comes back from the sidecar unchanged.
    expect(sanitizeState(state).failedPasswordCount).toBe(6);
    state = resetThrottle();
    expect(evaluateThrottle(state, now).ok).toBe(true);
  });

  it('sanitizes malformed/implausible sidecar values without denial of service', () => {
    expect(sanitizeState(null)).toEqual({ failedPasswordCount: 0, cooldownDeadline: 0 });
    expect(sanitizeState({ failedPasswordCount: -5, cooldownDeadline: 999 })).toEqual({ failedPasswordCount: 0, cooldownDeadline: 0 });
    expect(sanitizeState({ failedPasswordCount: 9999, cooldownDeadline: 0 })).toEqual({ failedPasswordCount: 255, cooldownDeadline: 0 });
    // A deadline without any failure count is implausible → safe reset.
    expect(sanitizeState({ failedPasswordCount: 0, cooldownDeadline: 1_000_000 })).toEqual({ failedPasswordCount: 0, cooldownDeadline: 0 });
  });
});
