/**
 * FEAT-010 Task 4.4 — locked/home/connectivity/protected-boundary tests.
 *
 * Proves every protection mode, safe preview bound, typed error/cooldown,
 * connectivity/reconnect state, home action, FEAT-011 absence, and same-turn
 * protected-unmount decision (normative: FeatureDescription "Returning Locked
 * Screen", "Authenticated Home"; AC-010-027…039, 044…062).
 */
import { describe, expect, it } from 'vitest';
import {
  abbreviatedAddress,
  projectHome,
  projectLockedView,
  projectUnlockProgress,
  SESSION_ONLY_WARNING,
  synchronouslyDeniesProtectedContent,
  type SafeIdentityPreview,
} from './locked-home-projection';

const preview: SafeIdentityPreview = {
  alias: 'safe-alias',
  abbreviatedSigningAddress: 'AB12CD34…WXYZ90',
  networkContext: 'HushNetwork devnet',
};

describe('projectLockedView', () => {
  it('projects the Device-password mode with exact copy and field', () => {
    const view = projectLockedView('device-password', preview);
    expect(view).toMatchObject({
      mode: 'device-password',
      unlockLabel: 'Unlock HushVoting!',
      recoveryLabel: 'Forgot device password?',
      showDevicePasswordField: true,
    });
  });

  it('projects passwordless modes with device wording and NO Device-password field', () => {
    const webauthn = projectLockedView('webauthn-prf', preview);
    expect(webauthn).toMatchObject({ unlockLabel: 'Unlock with this device', recoveryLabel: "Can't unlock with this device?", showDevicePasswordField: false });

    for (const mode of ['ubuntu-secret-service', 'android-keystore'] as const) {
      const view = projectLockedView(mode, preview);
      expect(view).toMatchObject({ unlockLabel: 'Unlock with device protection', recoveryLabel: "Can't unlock with this device?", showDevicePasswordField: false });
    }
  });

  it('discloses the unlocked-OS-session honestly on Ubuntu', () => {
    const view = projectLockedView('ubuntu-secret-service', preview);
    expect(view).toMatchObject({ disclosure: 'Access follows the unlocked OS session.' });
    const android = projectLockedView('android-keystore', preview);
    expect(android).not.toHaveProperty('disclosure');
  });

  it('never falls back to a Device-password field for unknown modes', () => {
    const view = projectLockedView('plaintext' as 'device-password', preview);
    expect(view).toEqual({ kind: 'blocked', supportCode: 'LOCKED-UNKNOWN-MODE' });
  });

  it('projects session-only with its own disclosure and no field', () => {
    const view = projectLockedView('sessionOnly', preview);
    expect(view).toMatchObject({ showDevicePasswordField: false, disclosure: 'Session-only — no returning local user is stored.' });
  });
});

describe('projectUnlockProgress', () => {
  it('projects cooldown/retry/verification states with safe fields', () => {
    expect(projectUnlockProgress('cooldown', false, 1_700_000)).toEqual({ state: 'cooldown', retryAllowed: false, cooldownDeadlineMs: 1_700_000 });
    expect(projectUnlockProgress('verifying', true)).toEqual({ state: 'verifying', retryAllowed: true });
    expect(projectUnlockProgress('retryableFailure', true)).toEqual({ state: 'retryableFailure', retryAllowed: true });
  });
});

describe('projectHome', () => {
  it('mounts a minimal real home without fake downstream content', () => {
    const home = projectHome(preview, 'online', false);
    expect(home).toMatchObject({
      alias: 'safe-alias',
      lockLabel: 'Lock HushVoting!',
      connectivity: 'online',
      showSessionOnlyWarning: false,
      exportActionAbsent: true,
    });
    expect(home).not.toHaveProperty('elections');
    expect(home).not.toHaveProperty('roles');
    expect(home).not.toHaveProperty('feeds');
  });

  it('shows session-only warning only for session-only sessions', () => {
    expect(projectHome(preview, 'reconnecting', true).showSessionOnlyWarning).toBe(true);
    expect(projectHome(preview, 'offline', false).showSessionOnlyWarning).toBe(false);
    expect(SESSION_ONLY_WARNING).toBe('Session-only — Lock or closing the app removes this local session.');
  });
});

describe('synchronouslyDeniesProtectedContent', () => {
  it('denies protected rendering the same turn the capability is revoked', () => {
    expect(synchronouslyDeniesProtectedContent(true)).toBe(false); // mount allowed
    expect(synchronouslyDeniesProtectedContent(false)).toBe(true); // synchronous deny
  });
});

describe('abbreviatedAddress', () => {
  it('renders first-eight/last-six abbreviated addresses', () => {
    const full = 'A1B2C3D4E5F6A7B8C9D0E1F2A3B4C5D6E7F8A9B0';
    expect(abbreviatedAddress(full)).toBe(`${full.slice(0, 8)}…${full.slice(-6)}`);
    expect(abbreviatedAddress('short')).toBe('short');
  });
});
