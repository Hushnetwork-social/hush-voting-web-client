/**
 * FEAT-008 recovery-words UI — candidate and profile-resolution review
 * surfaces (Task 5.3).
 *
 * Safe lookup progress, exactly-one confirmation, multiple-existing
 * selection, zero-match explanation, source-guided candidate selection,
 * uncertain guidance, explicit full-address reveal/copy, historical alias
 * rendering, and network review. No candidate is preselected; full public
 * addresses are a transient explicit reveal only.
 */
import { useState } from 'react';
import type { CandidateReviewProjection } from '../../../lib/recovery-words/contracts/projection';
import { RecoveryActionButton, RecoveryBackButton, RecoveryPanel, RecoveryStatusRegion } from './surfaces';
import { CANDIDATE_REVIEW, LOOKUP } from './copy';
import { SafeAlias } from '../SafeAlias';
import { useProgressDelay } from '../use-progress-delay';
export { SafeAlias } from '../SafeAlias';

export interface CandidateReviewProps {
  readonly review: CandidateReviewProjection;
  readonly onSelectCandidate: (index: number) => void;
  readonly onConfirmExistingProfile: () => void;
  readonly onRetryLookup: () => void;
  readonly onReveal: (index: number | null) => void;
  readonly onCopyAddress: (address: string) => void;
  readonly onBack: () => void;
}

export function LookupProgress({ done, total }: { done: number; total: number }) {
  const ready = useProgressDelay();
  if (!ready) return null;
  return (
    <RecoveryStatusRegion>
      {LOOKUP.progress(done, total)}
    </RecoveryStatusRegion>
  );
}

export function CandidateReviewScreen({ review, onSelectCandidate, onConfirmExistingProfile, onReveal, onCopyAddress, onBack }: CandidateReviewProps) {
  const [revealedIndex, setRevealedIndex] = useState<number | null>(null);
  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);

  const handleRevealToggle = (index: number) => {
    const next = revealedIndex === index ? null : index;
    setRevealedIndex(next);
    onReveal(next);
  };

  const title =
    review.outcome === 'exactlyOneExisting'
      ? CANDIDATE_REVIEW.existingTitle
      : review.outcome === 'multipleExisting'
        ? CANDIDATE_REVIEW.multipleTitle
        : CANDIDATE_REVIEW.zeroTitle;

  const detail =
    review.outcome === 'exactlyOneExisting'
      ? CANDIDATE_REVIEW.existingDetail
      : review.outcome === 'multipleExisting'
        ? CANDIDATE_REVIEW.multipleDetail
        : CANDIDATE_REVIEW.zeroDetail;

  return (
    <RecoveryPanel title={title}>
      <p className="mb-4 text-sm text-[var(--text-muted)]">{detail}</p>
      {review.outcome.startsWith('zero') && (
        <p className="mb-4 rounded-xl bg-[var(--surface-strong)] p-3 text-sm text-[var(--text)]" data-testid="zero-hint">
          {CANDIDATE_REVIEW.zeroHint}
        </p>
      )}

      <p className="mb-2 text-sm font-medium text-[var(--text)]">{CANDIDATE_REVIEW.network}: {review.networkLabel}</p>

      <ul className="flex flex-col gap-3" data-testid="candidate-list">
        {review.entries.map((entry) => {
          const isSelected = selectedIndex === entry.candidateIndex || entry.selected;
          const revealed = revealedIndex === entry.candidateIndex;
          return (
            <li key={entry.candidateIndex} className="rounded-xl bg-[var(--surface-strong)] p-4">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-sm font-semibold text-[var(--text)]">{entry.sourceLabel}</span>
                {entry.profileAlias !== null && (
                  <span className="text-xs text-[var(--text-muted)]">
                    {CANDIDATE_REVIEW.alias}: <SafeAlias alias={entry.profileAlias} />
                  </span>
                )}
              </div>
              <dl className="mt-2 grid grid-cols-1 gap-1 text-xs text-[var(--text-muted)] sm:grid-cols-2">
                {entry.visibility !== null && <div>
                  <dt className="font-medium">Visibility</dt>
                  <dd>{entry.visibility === 'public' ? 'Public' : 'Private'}</dd>
                </div>}
                <div>
                  <dt className="font-medium">{CANDIDATE_REVIEW.signing}</dt>
                  <dd className="break-all">{revealed && review.revealState.fullSigningAddress ? review.revealState.fullSigningAddress : entry.abbreviatedSigningAddress}</dd>
                </div>
                <div>
                  <dt className="font-medium">{CANDIDATE_REVIEW.encryption}</dt>
                  <dd className="break-all">{revealed && review.revealState.fullEncryptionAddress ? review.revealState.fullEncryptionAddress : entry.abbreviatedEncryptionAddress}</dd>
                </div>
              </dl>

              <div className="mt-3 flex flex-wrap items-center gap-2">
                <RecoveryActionButton
                  variant="secondary"
                  onClick={() => handleRevealToggle(entry.candidateIndex)}
                  disabled={revealedIndex !== null && revealedIndex !== entry.candidateIndex}
                >
                  {revealed ? CANDIDATE_REVIEW.concealFull : CANDIDATE_REVIEW.revealFull}
                </RecoveryActionButton>
                {revealed && review.revealState.fullSigningAddress !== null && (
                  <RecoveryActionButton variant="secondary" onClick={() => onCopyAddress(review.revealState.fullSigningAddress!)}>
                    Copy signing address
                  </RecoveryActionButton>
                )}
                {revealed && review.revealState.fullEncryptionAddress !== null && (
                  <RecoveryActionButton variant="secondary" onClick={() => onCopyAddress(review.revealState.fullEncryptionAddress!)}>
                    Copy encryption address
                  </RecoveryActionButton>
                )}
                {review.outcome !== 'exactlyOneExisting' && (
                  <RecoveryActionButton variant={isSelected ? 'primary' : 'secondary'} onClick={() => { setSelectedIndex(entry.candidateIndex); onSelectCandidate(entry.candidateIndex); }}>
                    {isSelected ? CANDIDATE_REVIEW.selected : CANDIDATE_REVIEW.select}
                  </RecoveryActionButton>
                )}
              </div>
            </li>
          );
        })}
      </ul>

      {review.outcome.startsWith('zero') && review.uncertainGuidance !== null && (
        <div className="mt-4 rounded-xl bg-[var(--surface-strong)] p-3">
          <p className="text-sm font-medium text-[var(--text)]">{CANDIDATE_REVIEW.notSure}</p>
          <p className="mt-1 text-xs text-[var(--text-muted)]">{CANDIDATE_REVIEW.notSureGuidance}</p>
        </div>
      )}

      <div className="mt-4 flex items-center justify-between gap-3">
        <RecoveryBackButton onClick={onBack} />
        <RecoveryActionButton variant="primary" onClick={onConfirmExistingProfile} disabled={review.busy || (review.selectionRequired && selectedIndex === null)}>
          {review.outcome.startsWith('zero') ? 'Continue to review profile' : CANDIDATE_REVIEW.continue}
        </RecoveryActionButton>
      </div>
    </RecoveryPanel>
  );
}
