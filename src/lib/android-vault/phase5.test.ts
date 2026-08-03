/**
 * FEAT-006 Phase 5 Task 5.2/5.6 — safe-state + composition tests (TS).
 * Every typed Android result renders one safe state with approved actions;
 * unsafe fallback/raw detail never renders; runtime selection is exhaustive
 * and mutually exclusive; synthetic actors are release-excluded.
 */
import { describe, expect, it } from 'vitest';
import { ANDROID_RESULT_CODES, RECOVERY_ACTIONS_BY_CODE } from './contracts';
import { ALL_SAFE_STATE_VIEWS, safeStateViewFromUnknown } from './safe-states';
import {
  buildAndroidRegistrations,
  canSelectAndroidVault,
  productionRegistrationsAreNonSynthetic,
  runtimeExcludesOtherAdapters,
} from './composition';

describe('FEAT-006 Android safe-state projections', () => {
  it('every closed code renders one safe view with approved actions', () => {
    for (const code of ANDROID_RESULT_CODES) {
      const view = ALL_SAFE_STATE_VIEWS[code];
      expect(view.heading.length).toBeGreaterThan(0);
      expect(view.actions.map((a) => a.kind).sort()).toEqual(
        [...RECOVERY_ACTIONS_BY_CODE[code]].sort(),
      );
    }
  });

  it('never echoes raw detail or offers continue-anyway', () => {
    const containsAtBoundary = (haystack: string, marker: string): boolean => {
      const h = haystack.toLowerCase();
      const m = marker.toLowerCase();
      for (let start = 0; start <= h.length - m.length; start += 1) {
        if (h.slice(start, start + m.length) === m) {
          const beforeOk = start === 0 || !/[a-z0-9]/.test(h[start - 1]);
          const after = start + m.length;
          const afterOk = after === h.length || !/[a-z0-9]/.test(h[after]);
          if (beforeOk && afterOk) return true;
        }
      }
      return false;
    };
    for (const code of ANDROID_RESULT_CODES) {
      const view = ALL_SAFE_STATE_VIEWS[code];
      const text = `${view.heading} ${view.body} ${view.liveRegion}`.toLowerCase();
      // Specific identifiers are substring-checked; generic words are
      // boundary-checked (so `uri` inside `security` does not false-positive).
      const substringMarkers = ['alias', 'exception', 'serial', 'androidid', 'ciphertext', 'model'];
      const wordMarkers = ['uri', 'path'];
      expect(substringMarkers.some((m) => text.includes(m))).toBe(false);
      expect(wordMarkers.some((m) => containsAtBoundary(text, m))).toBe(false);
      for (const action of view.actions) {
        expect(['retry', 'openSecuritySettings', 'updateApp', 'removeLocalUser', 'portableRecovery', 'resumeRemoval', 'cancel']).toContain(action.kind);
      }
      expect(text).not.toContain('continue anyway');
    }
  });

  it('unknown values fail closed to generic guidance', () => {
    const view = safeStateViewFromUnknown('decryptVault');
    expect(view.code).toBe('staleSession');
    expect(view.actions).toEqual([{ kind: 'retry' }]);
    const view2 = safeStateViewFromUnknown(42);
    expect(view2.code).toBe('staleSession');
  });

  it('retryable semantics match the closed contract', () => {
    expect(ALL_SAFE_STATE_VIEWS.temporaryKeystoreFailure.retryable).toBe(true);
    expect(ALL_SAFE_STATE_VIEWS.secureLockRequired.retryable).toBe(false);
    expect(ALL_SAFE_STATE_VIEWS.buildProtocolMismatch.retryable).toBe(false);
  });
});

describe('FEAT-006 Android runtime composition', () => {
  const ok = {
    runtime: 'androidMobile' as const,
    webviewRustHandshakeOk: true,
    rustKotlinHandshakeOk: true,
    preflight: 'passed' as const,
  };

  it('selects Android only for exact mobile runtime + handshakes + preflight', () => {
    expect(canSelectAndroidVault(ok)).toBe(true);
    expect(canSelectAndroidVault({ ...ok, runtime: 'tauriDesktop' })).toBe(false);
    expect(canSelectAndroidVault({ ...ok, runtime: 'web' })).toBe(false);
    expect(canSelectAndroidVault({ ...ok, webviewRustHandshakeOk: false })).toBe(false);
    expect(canSelectAndroidVault({ ...ok, rustKotlinHandshakeOk: false })).toBe(false);
    expect(canSelectAndroidVault({ ...ok, preflight: 'failed' })).toBe(false);
    expect(canSelectAndroidVault({ ...ok, preflight: 'notRun' })).toBe(false);
  });

  it('registrations fail closed to unavailable and are never synthetic', () => {
    const okRegs = buildAndroidRegistrations(ok);
    expect(okRegs.every((r) => r.availability === 'mandatory')).toBe(true);
    expect(productionRegistrationsAreNonSynthetic(okRegs)).toBe(true);
    const badRegs = buildAndroidRegistrations({ ...ok, runtime: 'web' });
    expect(badRegs.every((r) => r.availability === 'unavailable')).toBe(true);
  });

  it('runtime adapters are mutually exclusive', () => {
    expect(runtimeExcludesOtherAdapters({ runtime: 'androidMobile', ubuntuSelectable: false, browserSelectable: false })).toBe(true);
    expect(runtimeExcludesOtherAdapters({ runtime: 'androidMobile', ubuntuSelectable: true, browserSelectable: false })).toBe(false);
    expect(runtimeExcludesOtherAdapters({ runtime: 'tauriDesktop', ubuntuSelectable: true, browserSelectable: false })).toBe(true);
    expect(runtimeExcludesOtherAdapters({ runtime: 'web', ubuntuSelectable: false, browserSelectable: true })).toBe(true);
  });
});
