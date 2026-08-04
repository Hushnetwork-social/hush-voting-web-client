/**
 * FEAT-008 recovery-words UI — recovery flow router.
 *
 * Renders exactly one surface from the closed `RecoveryViewState` produced by
 * the Phase 4 presentation mapping. The router is a thin renderer: it never
 * decides policy, never holds secret state, and dispatches only the actions
 * the view state allows. Guards (ownership, quarantine, local-user) short-
 * circuit before any recovery form is mounted.
 */
import type { RecoveryViewState } from '../../../lib/recovery-words/presentation/view';
import type { WordGridProjection, CandidateReviewProjection, ProtectionProjection, StagedPreviewProjection } from '../../../lib/recovery-words/contracts/projection';
import type { ProtectionMode } from '../../../lib/recovery-words/contracts/envelope';
import { WordEntryScreen } from './word-entry';
import { CandidateReviewScreen, LookupProgress } from './candidate-review';
import { FinishRestoringScreen, ProtectionScreen, RecreateScreen, StagingScreen, SuccessScreen } from './lifecycle';
import { LocalUserGuard, OwnerBlockedScreen, QuarantineScreen, RemovalConfirmation } from './guards';

export interface RecoveryFlowProps {
  readonly view: RecoveryViewState;
  readonly wordGrid: WordGridProjection | null;
  readonly candidateReview: CandidateReviewProjection | null;
  readonly protection: ProtectionProjection | null;
  readonly stagedPreview: StagedPreviewProjection | null;
  readonly lookupProgress: { readonly done: number; readonly total: number } | null;
  readonly onSelectCount: (count: '12' | '24') => void;
  readonly onPastePhrase: (phrase: string) => void;
  readonly onConfirmPasteReplacement: (confirm: boolean) => void;
  readonly onClearAll: () => void;
  readonly onVerify: (phrase: string) => void;
  readonly onSelectCandidate: (index: number) => void;
  readonly onConfirmExistingProfile: () => void;
  readonly onRetryLookup: () => void;
  readonly onReveal: (index: number | null) => void;
  readonly onCopyAddress: (address: string) => void;
  readonly onChooseProtection: (mode: ProtectionMode) => void;
  readonly onAcknowledgeProtection: () => void;
  readonly onConfirmRecreate: (alias: string, visibility: 'private' | 'public') => void;
  readonly onFinishRestoringUnlock: () => void;
  readonly onLock: () => void;
  readonly onRemoveLocalUser: () => void;
  readonly onForgotPassword: () => void;
  readonly onConfirmRemoval: () => void;
  readonly onCancelRemoval: () => void;
  readonly onBack: () => void;
  readonly onEnterDashboard: () => void;
  readonly onRetry: () => void;
  readonly removalPending: boolean;
}

/** Thin renderer — screen routing only; policy stays in the authority. */
export function RecoveryFlow(props: RecoveryFlowProps) {
  const { view } = props;

  if (view.ownerState === 'blockedByOtherOwner') {
    return <OwnerBlockedScreen onRetry={props.onRetry} />;
  }

  switch (view.screen) {
    case 'entry':
      // The three-choice entry is rendered by the FEAT-002 auth shell.
      return null;
    case 'vaultGuard':
      if (view.error?.code === 'QUARANTINED') {
        return <QuarantineScreen onRetry={props.onRetry} />;
      }
      return <LocalUserGuard onLock={props.onLock} onRemoveLocalUser={props.onRemoveLocalUser} onForgotPassword={props.onForgotPassword} removalPending={props.removalPending} />;
    case 'wordEntry':
    case 'verifying':
    case 'deriving':
      return props.wordGrid ? (
        <WordEntryScreen
          grid={props.wordGrid}
          onSelectCount={props.onSelectCount}
          onPastePhrase={props.onPastePhrase}
          onConfirmPasteReplacement={props.onConfirmPasteReplacement}
          onClearAll={props.onClearAll}
          onVerify={props.onVerify}
          onBack={props.onBack}
        />
      ) : null;
    case 'lookup':
    case 'resolving':
      if (props.lookupProgress) {
        return <LookupProgress done={props.lookupProgress.done} total={props.lookupProgress.total} />;
      }
      return props.candidateReview ? (
        <CandidateReviewScreen
          review={props.candidateReview}
          onSelectCandidate={props.onSelectCandidate}
          onConfirmExistingProfile={props.onConfirmExistingProfile}
          onRetryLookup={props.onRetryLookup}
          onReveal={props.onReveal}
          onCopyAddress={props.onCopyAddress}
          onBack={props.onBack}
        />
      ) : null;
    case 'candidateSelection':
    case 'profileSelection':
    case 'existingProfileVerify':
      return props.candidateReview ? (
        <CandidateReviewScreen
          review={props.candidateReview}
          onSelectCandidate={props.onSelectCandidate}
          onConfirmExistingProfile={props.onConfirmExistingProfile}
          onRetryLookup={props.onRetryLookup}
          onReveal={props.onReveal}
          onCopyAddress={props.onCopyAddress}
          onBack={props.onBack}
        />
      ) : null;
    case 'protection':
      return props.protection ? (
        <ProtectionScreen protection={props.protection} onChooseMode={props.onChooseProtection} onAcknowledge={props.onAcknowledgeProtection} onBack={props.onBack} />
      ) : null;
    case 'staging':
      return <StagingScreen failed={view.error !== null} onBack={props.onBack} />;
    case 'recreateReview':
      return <RecreateScreen networkLabel={props.candidateReview?.networkLabel ?? 'this network'} onConfirm={props.onConfirmRecreate} onBack={props.onBack} />;
    case 'registration':
    case 'activating':
      return <StagingScreen failed={false} onBack={props.onBack} />;
    case 'finishRestoring':
      return props.stagedPreview ? <FinishRestoringScreen preview={props.stagedPreview} onUnlock={props.onFinishRestoringUnlock} onLock={props.onLock} /> : null;
    case 'success':
      return <SuccessScreen onEnterDashboard={props.onEnterDashboard} />;
    case 'locked':
      return <LocalUserGuard onLock={props.onLock} onRemoveLocalUser={props.onRemoveLocalUser} onForgotPassword={props.onForgotPassword} removalPending={props.removalPending} />;
    case 'quarantined':
      return <QuarantineScreen onRetry={props.onRetry} />;
    case 'terminal':
      return <QuarantineScreen onRetry={props.onRetry} />;
    default:
      return null;
  }
}

export { RemovalConfirmation };
