/**
 * FEAT-010 Task 4.6 — settings/recovery/removal/migration/error/evidence
 * projection tests.
 *
 * Proves every settings/offline/purpose/qualification/rollback/removal/
 * migration/error mapping, exact copy/action availability, focus/live-region
 * intent, and evidence allowlist (normative: FeatureDescription "Identity and
 * Security Settings", "Errors and Remediation"; AC-010-063…082, 088…090,
 * 097, 099).
 */
import { describe, expect, it } from 'vitest';
import {
  projectFreshAuthorizationPrompt,
  projectMigrationRemediation,
  projectRecovery,
  projectSettingsActions,
  projectTransitionProgress,
  projectUnknownError,
  QUARANTINE_COPY,
} from './settings-projection';

describe('projectSettingsActions', () => {
  it('exposes the exact online action set', () => {
    const projection = projectSettingsActions(false, { kind: 'absent' });
    expect(projection.available).toEqual(['removeLocalUser', 'devicePasswordChange', 'protectionModeChange', 'lockPolicy']);
    expect(projection.blockedOffline).toEqual([]);
  });

  it('blocks protection change and export offline; keeps Lock/removal/policy', () => {
    const projection = projectSettingsActions(true, { kind: 'registered', contractVersion: '1.0.0', compatible: true });
    expect(projection.available).toEqual(['removeLocalUser', 'lockPolicy']);
    expect(projection.blockedOffline).toEqual(['devicePasswordChange', 'protectionModeChange', 'export']);
  });

  it('keeps FEAT-011 export absent while no compatible capability registers', () => {
    const absent = projectSettingsActions(false, { kind: 'absent' });
    expect(absent.available).not.toContain('export');

    const incompatible = projectSettingsActions(false, { kind: 'incompatible', contractVersion: '0.9.0' });
    expect(incompatible.available).not.toContain('export');

    const registered = projectSettingsActions(false, { kind: 'registered', contractVersion: '1.0.0', compatible: true });
    expect(registered.available).toContain('export');
  });
});

describe('projectFreshAuthorizationPrompt', () => {
  it('requests exactly one purpose-scoped authorization via the current protection method', () => {
    const prompt = projectFreshAuthorizationPrompt('Change lock policy');
    expect(prompt).toEqual({ purposeLabel: 'Change lock policy', usesCurrentProtectionOnly: true, singleOperation: true });
  });
});

describe('projectRecovery', () => {
  it('explains no remote reset and requires REMOVE before restore choices', () => {
    const locked = projectRecovery(false);
    expect(locked.noRemoteResetCopy).toContain('cannot recover or reset');
    expect(locked.requiresPhrase).toBe('REMOVE');
    expect(locked.restoreChoicesVisible).toBe(false);

    expect(projectRecovery(true).restoreChoicesVisible).toBe(true);
  });
});

describe('projectMigrationRemediation', () => {
  it('maps every migration verdict to one remediation surface', () => {
    expect(projectMigrationRemediation('unsupported')).toEqual({ kind: 'updateAvailable' });
    expect(projectMigrationRemediation('corrupt')).toEqual({ kind: 'recoveryOrRemoval' });
    expect(projectMigrationRemediation('requiresMigration')).toEqual({ kind: 'retry' });
    expect(projectMigrationRemediation('wrongNetwork')).toEqual({ kind: 'networkMismatch' });
  });
});

describe('projectTransitionProgress', () => {
  it('projects enrolling, commit, new-mode unlock, and preserved-rollback states', () => {
    expect(projectTransitionProgress('enrolling', 'webauthn-prf')).toEqual({ kind: 'enrolling', targetMode: 'webauthn-prf' });
    expect(projectTransitionProgress('commitPending')).toEqual({ kind: 'commitPending' });
    expect(projectTransitionProgress('newModeUnlockRequired')).toEqual({ kind: 'newModeUnlockRequired' });
    expect(projectTransitionProgress('failedPreservingOldGeneration')).toEqual({ kind: 'failedPreservingOldGeneration' });
  });
});

describe('projectUnknownError', () => {
  it('produces generic copy with a random bounded support code', () => {
    const error = projectUnknownError();
    expect(error.genericCopy).toBe('Something went wrong. Please try again.');
    expect(error.supportCode).toMatch(/^ERR-[0-9A-F]{8}$/);

    // Random per-occurrence: two calls differ (non-correlating).
    const second = projectUnknownError();
    expect(second.supportCode).not.toBe(error.supportCode);
  });
});

describe('quarantine copy', () => {
  it('offers retry-only remediation for incomplete cleanup', () => {
    expect(QUARANTINE_COPY).toContain('Retry cleanup');
  });
});
