/**
 * FEAT-005 bridge composition tests — runtime gating.
 *
 * Proves the Ubuntu native projections are registered ONLY for the Tauri
 * desktop runtime; browser compositions observe no Ubuntu actor and cannot
 * claim OS-backed protection. Mirrors the browser-vault runtime-target
 * exclusion contract.
 *
 * Normative source: FEAT-005 FeatureDescription "Conceptual Architecture";
 * `src/lib/runtime/runtime-target.ts`.
 */
import { afterEach, describe, expect, it } from 'vitest';
import { isUbuntuTauriRuntime } from './index';

describe('ubuntu-vault runtime gating', () => {
  afterEach(() => {
    Reflect.deleteProperty(window, '__TAURI_INTERNALS__');
  });

  it('is active only for the Tauri desktop runtime', () => {
    expect(isUbuntuTauriRuntime('tauri')).toBe(true);
    expect(isUbuntuTauriRuntime('web')).toBe(false);
  });

  it('detects the scoped Tauri bridge when present', () => {
    Object.defineProperty(window, '__TAURI_INTERNALS__', {
      configurable: true,
      value: {},
    });
    expect(isUbuntuTauriRuntime()).toBe(true);
  });

  it('browser composition is never treated as Ubuntu runtime', () => {
    expect(isUbuntuTauriRuntime()).toBe(false);
  });
});
