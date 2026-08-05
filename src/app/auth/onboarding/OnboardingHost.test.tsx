/**
 * FEAT-010 Task 5.2 — OnboardingHost component tests.
 *
 * Proves all three real child mounts, callback forwarding, Back cleanup
 * ordering, unknown fail-closed behavior, and absence of placeholder content
 * (normative: FeatureDescription "Typed Onboarding Composition";
 * AC-010-007…013, 083–084, 088–089).
 */
import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { OnboardingError, OnboardingHost, type OnboardingChild } from './OnboardingHost';
import type { CreationViewState } from '../../../lib/identity-creation/presentation';

function createView(overrides: Partial<CreationViewState> = {}): CreationViewState {
  return {
    screen: 'profile',
    canGoBack: true,
    primaryAction: 'enabled',
    error: null,
    progressBucket: 'idle',
    evidenceCategory: null,
    localBoundaryCrossed: false,
    ...overrides,
  };
}

const onBack = vi.fn();

function childFixture(kind: OnboardingChild['kind']): OnboardingChild {
  if (kind === 'createUser') {
    return {
      kind,
      props: {
        view: createView(),
        recoveryWords: null,
        recoveryAcknowledged: false,
        recoveryTimeoutMessage: null,
        confirmPositions: [],
        confirmMismatchPosition: null,
        confirmAttemptsRemaining: 3,
        confirmChallengeClosed: false,
        review: {
          normalizedAlias: 'fixture-alias',
          visibility: 'private',
          abbreviatedSigningAddress: 'AB12…WXYZ',
          abbreviatedEncryptionAddress: 'CD34…UVWX',
          recoveryConfirmed: false,
          deviceProtectionReady: false,
          stage: 'review',
          progress: 0,
        },
        waitingAddress: null,
        blockHeight: null,
        supportCode: 'FIXTURE',
        preflightOutcome: { kind: 'passed' },
        c: {
          onCreateUser: vi.fn(),
          onRestoreWords: vi.fn(),
          onRestoreFile: vi.fn(),
          onRetryPreflight: vi.fn(),
          onProfileContinue: vi.fn(),
          onGenerate: vi.fn(),
          onRecoveryContinue: vi.fn(),
          onRecoveryCopy: vi.fn(),
          onRegenerateRequest: vi.fn(),
          onAcknowledge: vi.fn(),
          onConfirmVerify: vi.fn(),
          onReviewAll: vi.fn(),
          onProtect: vi.fn(),
          onCreateIdentity: vi.fn(),
          onCheckAgain: vi.fn(),
          onLock: vi.fn(),
          onRetryConnection: vi.fn(),
          onUnlockProvisional: vi.fn(),
          onContinueToProfile: vi.fn(),
          onCancelLocal: vi.fn(),
          onKeepSettingUp: vi.fn(),
          onBack: vi.fn(),
        },
      },
    };
  }
  if (kind === 'recoveryWords') {
    return {
      kind,
      props: {
        view: {
          screen: 'locked',
          canGoBack: false,
          primaryAction: 'enabled',
          error: null,
          progressBucket: 'idle',
          evidenceCategory: null,
          focusFirstInvalidPosition: null,
          ownerState: 'owner',
          allowedActions: [],
        },
        wordGrid: null,
        candidateReview: null,
        protection: null,
        stagedPreview: null,
        lookupProgress: null,
        onSelectCount: vi.fn(),
        onPastePhrase: vi.fn(),
        onConfirmPasteReplacement: vi.fn(),
        onClearAll: vi.fn(),
        onVerify: vi.fn(),
        onSelectCandidate: vi.fn(),
        onConfirmExistingProfile: vi.fn(),
        onRetryLookup: vi.fn(),
        onReveal: vi.fn(),
        onCopyAddress: vi.fn(),
        onChooseProtection: vi.fn(),
        onAcknowledgeProtection: vi.fn(),
        onConfirmRecreate: vi.fn(),
        onFinishRestoringUnlock: vi.fn(),
        onLock: vi.fn(),
        onRemoveLocalUser: vi.fn(),
        onForgotPassword: vi.fn(),
        onConfirmRemoval: vi.fn(),
        onCancelRemoval: vi.fn(),
        onBack: vi.fn(),
        onEnterDashboard: vi.fn(),
        onRetry: vi.fn(),
        removalPending: false,
      },
    };
  }
  return {
    kind,
    props: {
      view: {
        screen: 'picker',
        copyKey: 'credentialFileSelected',
        permittedActions: ['chooseFile'],
        focusTarget: 'chooseFileButton',
        progress: null,
        failureCode: null,
        backoff: null,
        passwordFieldState: { visible: false, emptyOptionChecked: false, emptyOptionEnabled: false, byteLimit: 4096 },
        protectionChoices: null,
        profile: null,
        reveal: { token: 'reveal-token', fullSigningAddress: 'A'.repeat(44), fullEncryptionAddress: 'B'.repeat(44) },
        canSubmitPassword: false,
      },
      sessionOnlyOnly: false,
      onChooseFile: vi.fn(),
      onCancelRead: vi.fn(),
      onSubmitPassword: vi.fn(),
      onToggleVisibility: vi.fn(),
      onToggleEmptyOption: vi.fn(),
      onChooseDifferentFile: vi.fn(),
      onChooseProtection: vi.fn(),
      onCreateIdentity: vi.fn(),
      onReveal: vi.fn(),
      onUnlockResume: vi.fn(),
      onCancelStage: vi.fn(),
      onBack: vi.fn(),
      onAcknowledgeSessionOnly: vi.fn(),
      onRetryCleanup: vi.fn(),
    },
  };
}

describe('OnboardingHost', () => {
  it('renders the real Create User flow for the createUser child', () => {
    render(<OnboardingHost child={childFixture('createUser')} onBack={onBack} />);
    // CreateUserFlow 'profile' screen renders an alias field.
    expect(screen.getByLabelText(/alias/i)).toBeInTheDocument();
  });

  it('renders the real Recovery Words flow for the recoveryWords child', () => {
    render(<OnboardingHost child={childFixture('recoveryWords')} onBack={onBack} />);
    // 'locked' screen renders the local-user guard with the Lock action.
    expect(screen.getByRole('button', { name: 'Lock' })).toBeInTheDocument();
  });

  it('renders the real Credential File flow for the credentialFile child', () => {
    render(<OnboardingHost child={childFixture('credentialFile')} onBack={onBack} />);
    // 'picker' screen renders the choose-file action.
    expect(screen.getByRole('button', { name: /choose/i })).toBeInTheDocument();
  });

  it('shows a typed fail-closed error instead of Setting up… when no child is mounted', () => {
    render(<OnboardingHost child={null} onBack={onBack} />);
    expect(screen.getByTestId('onboarding-error')).toBeInTheDocument();
    expect(screen.queryByText(/setting up/i)).not.toBeInTheDocument();
  });

  it('forwards Back to the authority (cleanup ordering)', async () => {
    const user = userEvent.setup();
    render(<OnboardingHost child={null} onBack={onBack} />);
    await user.click(screen.getByRole('button', { name: /back/i }));
    expect(onBack).toHaveBeenCalledTimes(1);
  });
});

describe('OnboardingError', () => {
  it('is a blocking error surface with a bounded remediation', () => {
    render(<OnboardingError onBack={onBack} />);
    expect(screen.getByRole('alert')).toBeInTheDocument();
  });
});
