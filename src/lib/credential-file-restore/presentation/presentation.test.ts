/**
 * FEAT-009 Task 4.2/4.4/4.6 — unit, model, serialization, truth-state,
 * navigation, copy, accessibility-contract, and remediation tests for the
 * presentation projections (Tasks 4.1/4.3/4.5).
 *
 * Proves: every closed authority state maps once to a deterministic
 * view/action set; illegal/unknown combinations fail closed; no projection
 * serializes prohibited data; success truth table; exact copy; focus and
 * countdown semantics; stage-specific Back; and registration rules.
 */
import { describe, expect, it } from 'vitest';
import {
  CREDENTIAL_FILE_ACTOR_REGISTRATION,
  assertCredentialFileKind,
  backForStage,
  completionResult,
  composeRestoreView,
  rootNavigationPolicy,
  validateCredentialFileRegistration,
} from './onboarding.js';
import { EXACT_COPY, mapErrorToRemediation } from './remediation.js';
import {
  copyKeyForStage,
  focusTargetForFailure,
  isIdentityRestored,
  mapRestoreStageToScreen,
  permittedActionsForStage,
  toRestoreViewState,
} from './view.js';
import type { RestoreScreen } from './view.js';
import type { RestoreStage } from '../contracts/lifecycle.js';
import { assertNoRestoreSecretSurface } from '../contracts/lifecycle.js';

describe('FEAT-009 stage → screen mapping (Task 4.1)', () => {
  it('every authority stage maps to exactly one closed screen', () => {
    const stages: readonly RestoreStage[] = [
      'vaultGuard', 'capabilityPreflight', 'picker', 'reading', 'password', 'decrypting',
      'validating', 'lookup', 'profileReview', 'protection', 'staging', 'resumeGate',
      'activating', 'success', 'locked', 'quarantined', 'terminal',
    ];
    const screens = new Set<RestoreScreen>();
    for (const stage of stages) {
      const screen = mapRestoreStageToScreen(stage);
      expect(screen).toBeDefined();
      screens.add(screen);
    }
    expect(screens.size).toBe(stages.length); // 1:1, no aliasing
  });

  it('unknown stage fails closed to terminal-like remediation', () => {
    const unknown = 'futureStage' as RestoreStage;
    // The union is closed; a cast value must not produce a first-run screen.
    const screen = mapRestoreStageToScreen(unknown);
    expect(['locked', 'quarantined', 'terminal']).toContain(screen);
  });
});

describe('FEAT-009 copy and success truth (Task 4.1/4.5)', () => {
  it('exact copy keys exist for every required state', () => {
    expect(EXACT_COPY.readingCredentialFile).toBe('Reading credential file…');
    expect(EXACT_COPY.backupReadyForPassword).toBe('Backup ready for password');
    expect(EXACT_COPY.identityRestored).toBe('Identity restored');
    expect(EXACT_COPY.finishRestoringYourIdentity).toBe('Finish restoring your identity');
    expect(EXACT_COPY.backupPasswordIncorrectOrDamaged).toBe('The backup password is incorrect or the credential file is damaged.');
    expect(EXACT_COPY.invalidOrInconsistentIdentityKeys).toBe('This credential file contains invalid or inconsistent identity keys and cannot be restored.');
    expect(EXACT_COPY.serverRejectedIdentityProof).toBe('HushServerNode rejected the identity proof.');
    expect(EXACT_COPY.credentialFileSelected).toBe('Credential file selected'); // never filename-based
  });

  it('Identity restored is unavailable before exact online activation', () => {
    // Selection/decrypt/parse/proof/lookup/stage are NOT restored.
    for (const stage of ['picker', 'reading', 'password', 'decrypting', 'validating', 'lookup', 'staging', 'resumeGate', 'activating'] as const) {
      expect(isIdentityRestored(stage, 'none')).toBe(false);
      expect(copyKeyForStage(stage)).not.toBe('identityRestored');
    }
    // Only the success stage after exact activation.
    expect(isIdentityRestored('success', 'existing')).toBe(true);
    expect(isIdentityRestored('success', 'created')).toBe(true);
    expect(isIdentityRestored('success', 'none')).toBe(false); // impossible via authority; fail closed
  });

  it('progress copy is accurate per stage', () => {
    expect(copyKeyForStage('reading')).toBe('readingCredentialFile');
    expect(copyKeyForStage('decrypting')).toBe('decryptingBackup');
    expect(copyKeyForStage('validating')).toBe('validatingIdentityKeys');
    expect(copyKeyForStage('lookup')).toBe('checkingBlockchainIdentity');
    expect(copyKeyForStage('protection')).toBe('protectThisDevice');
    expect(copyKeyForStage('staging')).toBe('savingEncryptedIdentity');
  });
});

describe('FEAT-009 permitted actions (Task 4.1)', () => {
  it('actions are legal only in enumerated stages', () => {
    expect(permittedActionsForStage('picker')).toContain('chooseFile');
    expect(permittedActionsForStage('password')).toEqual(
      expect.arrayContaining(['submitPassword', 'togglePasswordVisibility', 'enableEmptyPasswordOption', 'chooseDifferentFile', 'back']),
    );
    expect(permittedActionsForStage('profileReview')).toContain('createIdentity');
    expect(permittedActionsForStage('resumeGate')).toContain('unlockStagedResume');
    expect(permittedActionsForStage('quarantined')).toEqual(['retryCleanup']);
    expect(permittedActionsForStage('success')).not.toContain('chooseFile');
  });
});

describe('FEAT-009 deterministic view projection (Task 4.1)', () => {
  it('a password failure projects the combined message, countdown, and stage-correct actions', () => {
    const state = toRestoreViewState({
      stage: 'password',
      progress: null,
      failureCode: 'AUTHENTICATION_FAILED',
      backoffRemainingSeconds: 4,
      passwordField: { visible: false, emptyOptionChecked: false, emptyOptionEnabled: true },
      protectionChoices: null,
      profile: null,
      reveal: null,
    });
    expect(state.screen).toBe('password');
    expect(state.copyKey).toBe('backupReadyForPassword');
    expect(state.failureCode).toBe('AUTHENTICATION_FAILED');
    expect(state.backoff).toEqual({ active: true, remainingSeconds: 4 });
    expect(state.focusTarget).toBe('countdownStatus');
    expect(state.canSubmitPassword).toBe(true);
    expect(state.passwordFieldState?.byteLimit).toBe(4096);
  });

  it('no projection serializes secret material', () => {
    const states = [
      toRestoreViewState({ stage: 'picker', progress: null, failureCode: null, backoffRemainingSeconds: 0, passwordField: null, protectionChoices: null, profile: null, reveal: null }),
      toRestoreViewState({ stage: 'password', progress: null, failureCode: 'BACKOFF_ACTIVE', backoffRemainingSeconds: 2, passwordField: { visible: true, emptyOptionChecked: false, emptyOptionEnabled: true }, protectionChoices: null, profile: null, reveal: null }),
      toRestoreViewState({ stage: 'success', progress: null, failureCode: null, backoffRemainingSeconds: 0, passwordField: null, protectionChoices: ['devicePassword'], profile: { alias: 'a', isPublic: true, signingAddressAbbreviated: 'aa…bb', encryptionAddressAbbreviated: 'cc…dd', networkLabel: 'HushLocal', source: 'blockchain', aliasEditable: false, publicAcknowledgementRequired: false }, reveal: null }),
    ];
    for (const state of states) {
      expect(assertNoRestoreSecretSurface(state)).toEqual([]);
    }
  });

  it('reveal data is transient and explicit (full addresses only on demand)', () => {
    const state = toRestoreViewState({
      stage: 'profileReview',
      progress: null,
      failureCode: null,
      backoffRemainingSeconds: 0,
      passwordField: null,
      protectionChoices: null,
      profile: null,
      reveal: { token: 'reveal-1', fullSigningAddress: 'a'.repeat(66), fullEncryptionAddress: 'b'.repeat(66) },
    });
    expect(state.reveal?.fullSigningAddress).toBe('a'.repeat(66));
  });
});

describe('FEAT-009 remediation table (Task 4.5)', () => {
  it('combined auth failure copy never claims cause', () => {
    const remediation = mapErrorToRemediation('AUTHENTICATION_FAILED');
    expect(remediation.message).toBe('The backup password is incorrect or the credential file is damaged.');
    expect(remediation.actions).toContain('submitPassword');
    expect(remediation.actions).toContain('chooseDifferentFile');
  });

  it('inconsistent-key failures share the safe combined message with typed codes', () => {
    for (const code of ['SIGNING_KEY_MISMATCH', 'ENCRYPTION_KEY_MISMATCH', 'KEY_PROOF_FAILED', 'MNEMONIC_KEY_MISMATCH', 'UNSUPPORTED_KEY_ENCODING'] as const) {
      const remediation = mapErrorToRemediation(code);
      expect(remediation.message).toBe('This credential file contains invalid or inconsistent identity keys and cannot be restored.');
      expect(remediation.actions).not.toContain('submitPassword'); // no retry password after semantic failure
    }
  });

  it('unknown codes fail closed with a generic safe message', () => {
    const remediation = mapErrorToRemediation('UNKNOWN_OUTCOME');
    expect(remediation.message).toBe('Something went wrong; please try again.');
    expect(remediation.actions).toContain('back');
  });

  it('no remediation echoes raw values', () => {
    const keys = Object.keys(EXACT_COPY);
    for (const key of keys) {
      expect(EXACT_COPY[key]).not.toMatch(/fileName|password value|privateKey/i);
    }
  });
});

describe('FEAT-009 child-actor registration and navigation (Task 4.3)', () => {
  it('registration is mandatory and non-synthetic', () => {
    expect(CREDENTIAL_FILE_ACTOR_REGISTRATION).toEqual({
      capability: 'onboardingRestoreCredentialFile',
      availability: 'mandatory',
      synthetic: false,
    });
  });

  it('duplicate or synthetic registration fails closed', () => {
    expect(validateCredentialFileRegistration(false, false).ok).toBe(true);
    expect(validateCredentialFileRegistration(true, false).ok).toBe(false);
    expect(validateCredentialFileRegistration(false, true).ok).toBe(false);
  });

  it('only the credential-file kind is accepted', () => {
    expect(assertCredentialFileKind('restoreCredentialFile').ok).toBe(true);
    expect(assertCredentialFileKind('restoreRecoveryWords').ok).toBe(false);
  });

  it('visible URL stays root for every stage', () => {
    expect(rootNavigationPolicy().visibleUrl).toBe('/');
  });

  it('stage-specific Back: clear → destroy → lock', () => {
    expect(backForStage('picker')).toBe('clearInputs');
    expect(backForStage('password')).toBe('clearInputs');
    expect(backForStage('validating')).toBe('destroyAuthority');
    expect(backForStage('lookup')).toBe('destroyAuthority');
    expect(backForStage('staging')).toBe('lock');
    expect(backForStage('resumeGate')).toBe('lock');
  });

  it('completion results map deterministically', () => {
    expect(completionResult('restoredExistingProfile', 'user-1').code).toBe('ONBOARDING_COMPLETED');
    expect(completionResult('createdMissingProfile', 'user-1').code).toBe('ONBOARDING_COMPLETED');
    expect(completionResult('sessionOnlyRestored', 'user-1').code).toBe('ONBOARDING_COMPLETED');
    expect(completionResult('cancelled', 'user-1')).toEqual({ code: 'ONBOARDING_BACK' });
    expect(completionResult('quarantined', 'user-1')).toEqual({ code: 'UNKNOWN_FAILURE', supportCode: 'DAT-QUARANTINE-1' });
  });
});

describe('FEAT-009 focus/accessibility contract (Task 4.5)', () => {
  it('focus targets are deterministic per failure class', () => {
    expect(focusTargetForFailure('AUTHENTICATION_FAILED')).toBe('countdownStatus');
    expect(focusTargetForFailure('PICKER_CANCELLED')).toBe('retryButton');
    expect(focusTargetForFailure('SIGNING_KEY_MISMATCH')).toBe('errorSummary');
    expect(focusTargetForFailure('QUARANTINED')).toBe('remediation');
  });

  it('composeRestoreView returns view + remediation consistently', () => {
    const composed = composeRestoreView({
      stage: 'password',
      progress: null,
      failureCode: 'AUTHENTICATION_FAILED',
      backoffRemainingSeconds: 8,
      passwordField: { visible: false, emptyOptionChecked: false, emptyOptionEnabled: true },
      protectionChoices: null,
      profile: null,
      reveal: null,
    });
    expect(composed.view.failureCode).toBe('AUTHENTICATION_FAILED');
    expect(composed.remediation?.message).toBe('The backup password is incorrect or the credential file is damaged.');
    expect(composed.view.backoff?.remainingSeconds).toBe(8);
  });
});
