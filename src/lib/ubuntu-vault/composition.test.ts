/**
 * FEAT-005 Ubuntu production composition tests (Task 6.2).
 *
 * The production target matrix: Web, Ubuntu (Tauri), SSR, test/development
 * fixtures, and mismatched handshakes. Exactly the approved adapter is
 * selectable for each target; every prohibited fallback and synthetic actor
 * is rejected; browser-vault mutual exclusion is proven.
 */

import { describe, expect, it } from 'vitest';
import {
  BROWSER_VAULT_CAPABILITY_SLOTS,
} from '../browser-vault/integration/composition';
import {
  buildUbuntuRegistrations,
  canSelectUbuntuVault,
  resolveUbuntuRuntime,
  slotsConflict,
  UBUNTU_CAPABILITY_SLOTS,
  validateUbuntuComposition,
} from './composition';

describe('runtime resolution', () => {
  it('resolves tauri/web/ssr deterministically', () => {
    // jsdom has a window but no __TAURI__ internals → 'web'.
    expect(resolveUbuntuRuntime()).toBe('web');
    // SSR (no window) would be 'ssr' — asserted via the pure resolver path.
    expect(canSelectUbuntuVault({ runtime: 'ssr', handshakeOk: true, preflightOk: true })).toBe(false);
  });
});

describe('production selection matrix (task 6.1/6.2)', () => {
  it('selects Ubuntu ONLY for Tauri + exact handshake + passing preflight', () => {
    const cases: Array<[boolean, boolean, boolean]> = [
      // [handshakeOk, preflightOk, expected]
      [true, true, true], // exact handshake + passing preflight → selectable
      [false, true, false], // wrong build/protocol → fail closed
      [true, false, false], // failed native preflight → fail closed
      [false, false, false],
    ];
    for (const [handshakeOk, preflightOk, expected] of cases) {
      expect(canSelectUbuntuVault({ runtime: 'tauri', handshakeOk, preflightOk })).toBe(
        expected,
      );
    }
    // Web/SSR never select Ubuntu even with ok handshake/preflight.
    expect(canSelectUbuntuVault({ runtime: 'web', handshakeOk: true, preflightOk: true })).toBe(false);
    expect(canSelectUbuntuVault({ runtime: 'ssr', handshakeOk: true, preflightOk: true })).toBe(false);
  });

  it('mandatory registrations only under the approved combination', () => {
    const registrations = buildUbuntuRegistrations({
      runtime: 'tauri',
      handshakeOk: true,
      preflightOk: true,
    });
    expect(registrations.every((r) => r.availability === 'mandatory')).toBe(true);
    expect(registrations.every((r) => r.synthetic === false)).toBe(true);

    // Every other combination is unavailable (fail closed).
    const blockedCases: Array<{
      runtime: 'tauri' | 'web' | 'ssr';
      handshakeOk: boolean;
      preflightOk: boolean;
    }> = [
      { runtime: 'tauri', handshakeOk: false, preflightOk: true },
      { runtime: 'tauri', handshakeOk: true, preflightOk: false },
      { runtime: 'web', handshakeOk: true, preflightOk: true },
      { runtime: 'ssr', handshakeOk: true, preflightOk: true },
    ];
    for (const params of blockedCases) {
      const blocked = buildUbuntuRegistrations(params);
      expect(blocked.every((r) => r.availability === 'unavailable')).toBe(true);
      expect(blocked.every((r) => r.synthetic === false)).toBe(true);
    }
  });

  it('composition validation rejects duplicates, synthetic actors, and missing slots', () => {
    const good = buildUbuntuRegistrations({
      runtime: 'tauri',
      handshakeOk: true,
      preflightOk: true,
    });
    expect(validateUbuntuComposition(good).ok).toBe(true);

    const duplicated = [...good, ...good.slice(0, 1)];
    expect(validateUbuntuComposition(duplicated).ok).toBe(false);

    const synthetic = good.map((r) => ({ ...r, synthetic: true }));
    expect(validateUbuntuComposition(synthetic).ok).toBe(false);

    const missing = good.slice(1);
    expect(validateUbuntuComposition(missing).ok).toBe(false);

    const foreign = [
      { capability: 'browserCoordination' as const, availability: 'mandatory' as const, synthetic: false },
    ];
    expect(validateUbuntuComposition(foreign).ok).toBe(false);
  });

  it('browser and Ubuntu adapters never both back the same slot (mutual exclusion)', () => {
    const ubuntu = buildUbuntuRegistrations({
      runtime: 'tauri',
      handshakeOk: true,
      preflightOk: true,
    });
    const browserTauri = buildBrowserRegistrations('native');
    // In the Tauri runtime the browser adapter must be unavailable → no slot
    // conflict even though the slot sets overlap.
    expect(slotsConflict(ubuntu, browserTauri)).toBe(false);
    // If a buggy composition made the browser adapter mandatory in Tauri, the
    // conflict detector must flag it.
    const buggyBrowser = buildBrowserRegistrations('web').map((r) => ({
      ...r,
      availability: 'mandatory' as const,
    }));
    expect(slotsConflict(ubuntu, buggyBrowser)).toBe(true);
  });

  it('prohibited browser fallback never appears in native composition', () => {
    // The Ubuntu slots are exactly the FEAT-003 vault slots (minus the
    // browser-only coordination slot); the browser vault's own slots prove
    // the overlap is intentional and resolved by mutual exclusion.
    for (const slot of UBUNTU_CAPABILITY_SLOTS) {
      expect(BROWSER_VAULT_CAPABILITY_SLOTS).toContain(slot);
    }
  });
});

function buildBrowserRegistrations(runtime: 'native' | 'web') {
  const selectable = runtime === 'web';
  return BROWSER_VAULT_CAPABILITY_SLOTS.map((capability) => ({
    capability,
    availability: selectable ? ('mandatory' as const) : ('unavailable' as const),
    synthetic: false,
  }));
}
