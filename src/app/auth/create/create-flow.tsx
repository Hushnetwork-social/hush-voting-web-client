/**
 * FEAT-007 create-user UI — flow orchestrator (thin renderer).
 *
 * Renders the correct screen from the closed `CreationViewState` produced by
 * the presentation authority (Phase 4). React never owns business transitions,
 * secrets, or history decisions; it forwards typed callbacks upward. All
 * screens are self-contained and driven only by safe projections.
 */

import type { CreationViewState } from '../../../lib/identity-creation/presentation';
import { CancellingScreen, ConnectionScreen, CorrectingScreen, DelayScreen, FinishCreatingScreen, TerminalScreen, WaitingScreen } from './status';
import { EntryScreen, PreflightScreen } from './entry';
import { GenerateScreen, ProfileScreen } from './profile';
import { ConfirmRecoveryScreen, RecoveryScreen } from './recovery';
import { ProtectScreen, ReviewScreen } from './protect';

export interface CreateUserCallbacks {
  readonly onCreateUser: () => void;
  readonly onRestoreWords: () => void;
  readonly onRestoreFile: () => void;
  readonly onRetryPreflight: () => void;
  readonly onProfileContinue: (alias: string, visibility: 'private' | 'public') => void;
  readonly onGenerate: () => void;
  readonly onRecoveryContinue: () => void;
  readonly onRecoveryCopy: () => void;
  readonly onRegenerateRequest: () => void;
  readonly onAcknowledge: (value: boolean) => void;
  readonly onConfirmVerify: (answers: ReadonlyMap<number, string>) => void;
  readonly onReviewAll: () => void;
  readonly onProtect: (password: string) => void;
  readonly onCreateIdentity: () => void;
  readonly onCheckAgain: () => void;
  readonly onLock: () => void;
  readonly onRetryConnection: () => void;
  readonly onUnlockProvisional: () => void;
  readonly onContinueToProfile: () => void;
  readonly onCancelLocal: () => void;
  readonly onKeepSettingUp: () => void;
  readonly onBack: () => void;
}

export interface CreateUserFlowProps {
  readonly view: CreationViewState;
  /** Safe projections passed down per screen (bounded reveal words). */
  readonly recoveryWords: readonly string[] | null;
  readonly recoveryAcknowledged: boolean;
  readonly recoveryTimeoutMessage: string | null;
  readonly confirmPositions: readonly number[];
  readonly confirmMismatchPosition: number | null;
  readonly confirmAttemptsRemaining: number;
  readonly confirmChallengeClosed: boolean;
  readonly review: import('../../../lib/identity-creation/contracts').CreationReviewProjection;
  readonly waitingAddress: string | null;
  readonly blockHeight: number | null;
  readonly supportCode: string;
  readonly preflightOutcome: import('../../../lib/identity-creation/authority').PreflightOutcome;
  readonly c: CreateUserCallbacks;
}

/** Thin renderer: view state → one screen. */
export function CreateUserFlow(props: CreateUserFlowProps) {
  const { view, c } = props;
  switch (view.screen) {
    case 'entry':
      return <EntryScreen onCreateUser={c.onCreateUser} onRestoreWords={c.onRestoreWords} onRestoreFile={c.onRestoreFile} />;
    case 'preflight':
      return <PreflightScreen outcome={props.preflightOutcome} onRetry={c.onRetryPreflight} onBack={c.onBack} />;
    case 'profile':
      return <ProfileScreen onContinue={c.onProfileContinue} onBack={c.onBack} />;
    case 'generate':
      return (
        <GenerateScreen
          onGenerate={c.onGenerate}
          onBack={c.onBack}
          progressVisible={view.progressBucket === 'running' || view.progressBucket === 'pending'}
          progressComplete={view.progressBucket === 'done'}
        />
      );
    case 'recovery':
      return (
        <RecoveryScreen
          words={props.recoveryWords}
          onCopy={c.onRecoveryCopy}
          onRegenerateRequest={c.onRegenerateRequest}
          onContinue={c.onRecoveryContinue}
          onBack={c.onBack}
          acknowledged={props.recoveryAcknowledged}
          onAcknowledge={c.onAcknowledge}
          timeoutMessage={props.recoveryTimeoutMessage}
        />
      );
    case 'confirmRecovery':
      return (
        <ConfirmRecoveryScreen
          positions={props.confirmPositions}
          onVerify={c.onConfirmVerify}
          onReviewAll={c.onReviewAll}
          onBack={c.onBack}
          mismatchPosition={props.confirmMismatchPosition}
          attemptsRemaining={props.confirmAttemptsRemaining}
          challengeClosed={props.confirmChallengeClosed}
        />
      );
    case 'protect':
      return <ProtectScreen onProtect={c.onProtect} onBack={c.onBack} submitting={view.primaryAction === 'inProgress'} />;
    case 'review':
      return <ReviewScreen review={props.review} onCreate={c.onCreateIdentity} onBack={c.onBack} submitting={view.primaryAction === 'inProgress'} />;
    case 'waiting':
      return <WaitingScreen onCheckAgain={c.onCheckAgain} onLock={c.onLock} abbreviatedSigningAddress={props.waitingAddress} blockHeight={props.blockHeight} />;
    case 'delay':
      return <DelayScreen onCheckAgain={c.onCheckAgain} onLock={c.onLock} />;
    case 'connection':
      return <ConnectionScreen onRetry={c.onRetryConnection} onLock={c.onLock} />;
    case 'finishCreating':
      return <FinishCreatingScreen onUnlock={c.onUnlockProvisional} abbreviatedSigningAddress={props.waitingAddress} />;
    case 'correcting':
      return <CorrectingScreen onContinueToProfile={c.onContinueToProfile} validationCode={props.supportCode} />;
    case 'cancelling':
      return <CancellingScreen onCancelLocal={c.onCancelLocal} onKeepSettingUp={c.onKeepSettingUp} />;
    case 'locked':
      return <TerminalScreen supportCode={props.supportCode} onBack={c.onBack} />;
    default:
      return <EntryScreen onCreateUser={c.onCreateUser} onRestoreWords={c.onRestoreWords} onRestoreFile={c.onRestoreFile} />;
  }
}
