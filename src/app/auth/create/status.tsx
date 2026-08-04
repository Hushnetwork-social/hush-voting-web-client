/**
 * FEAT-007 create-user UI — status and remediation surfaces (Task 5.5):
 * provisional resume (Finish creating), waiting gate, three-minute delay,
 * waiting for connection, editable alias correction, cancellation, and
 * fail-closed terminal state.
 *
 * The waiting gate states honestly that mempool admission is not block
 * confirmation, offers safe Lock/close guidance, and never looks like an
 * endless unexplained spinner. Live-region announcements happen on state
 * change only.
 */

import { STATUS } from './copy';
import { ActionButton, BackButton, StatusRegion, SurfacePanel } from './surfaces';

export interface WaitingProps {
  readonly onCheckAgain: () => void;
  readonly onLock: () => void;
  readonly abbreviatedSigningAddress: string | null;
  readonly blockHeight: number | null;
}

/** Mempool waiting gate — busy signal + explicit safe exit. */
export function WaitingScreen({ onCheckAgain, onLock, abbreviatedSigningAddress, blockHeight }: WaitingProps) {
  return (
    <SurfacePanel title={STATUS.waiting.title}>
      <StatusRegion>{STATUS.waiting.live}</StatusRegion>
      <p className="mt-3 text-sm text-[var(--text-muted)]">{STATUS.waiting.detail}</p>
      <p className="mt-2 text-sm text-[var(--text-muted)]">{STATUS.waiting.safeExit}</p>
      {abbreviatedSigningAddress ? (
        <p className="mt-2 font-mono text-xs text-[var(--text-muted)]" data-testid="waiting-address">
          {abbreviatedSigningAddress}
          {blockHeight !== null ? ` · block ${blockHeight}` : ''}
        </p>
      ) : null}
      <div className="mt-4 flex flex-wrap gap-3">
        <ActionButton variant="secondary" onClick={onCheckAgain}>
          {STATUS.waiting.checkAgain}
        </ActionButton>
        <ActionButton variant="secondary" onClick={onLock}>
          {STATUS.waiting.lock}
        </ActionButton>
      </div>
    </SurfacePanel>
  );
}

export interface DelayProps {
  readonly onCheckAgain: () => void;
  readonly onLock: () => void;
}

/** Three-minute abnormal delay — lookup-only Check again, no resubmit. */
export function DelayScreen({ onCheckAgain, onLock }: DelayProps) {
  return (
    <SurfacePanel title={STATUS.delay.title}>
      <p className="text-sm text-[var(--text-muted)]">{STATUS.delay.detail}</p>
      <div className="mt-4 flex flex-wrap gap-3">
        <ActionButton variant="secondary" onClick={onCheckAgain}>
          {STATUS.delay.checkAgain}
        </ActionButton>
        <ActionButton variant="secondary" onClick={onLock}>
          {STATUS.delay.lock}
        </ActionButton>
      </div>
    </SurfacePanel>
  );
}

export interface ConnectionProps {
  readonly onRetry: () => void;
  readonly onLock: () => void;
}

/** Waiting for connection — exact transaction preserved encrypted. */
export function ConnectionScreen({ onRetry, onLock }: ConnectionProps) {
  return (
    <SurfacePanel title={STATUS.connection.title}>
      <StatusRegion>Offline.</StatusRegion>
      <p className="mt-3 text-sm text-[var(--text-muted)]">{STATUS.connection.detail}</p>
      <div className="mt-4 flex flex-wrap gap-3">
        <ActionButton variant="secondary" onClick={onRetry}>
          {STATUS.connection.retry}
        </ActionButton>
        <ActionButton variant="secondary" onClick={onLock}>
          {STATUS.connection.lock}
        </ActionButton>
      </div>
    </SurfacePanel>
  );
}

export interface FinishCreatingProps {
  readonly onUnlock: () => void;
  readonly abbreviatedSigningAddress: string | null;
}

/** Provisional resume — Finish creating your identity (safe context only). */
export function FinishCreatingScreen({ onUnlock, abbreviatedSigningAddress }: FinishCreatingProps) {
  return (
    <SurfacePanel title={STATUS.finishCreating.title}>
      <p className="text-sm text-[var(--text-muted)]">{STATUS.finishCreating.detail}</p>
      {abbreviatedSigningAddress ? (
        <p className="mt-2 font-mono text-xs text-[var(--text-muted)]">{abbreviatedSigningAddress}</p>
      ) : null}
      <div className="mt-4">
        <ActionButton onClick={onUnlock}>{STATUS.finishCreating.action}</ActionButton>
      </div>
    </SurfacePanel>
  );
}

export interface CorrectingProps {
  readonly onContinueToProfile: () => void;
  readonly validationCode: string;
}

/** Editable pre-admission rejection — only Profile/Review reopens. */
export function CorrectingScreen({ onContinueToProfile, validationCode }: CorrectingProps) {
  return (
    <SurfacePanel title={STATUS.correcting.title}>
      <p className="text-sm text-[var(--text-muted)]">{STATUS.correcting.detail}</p>
      <div className="mt-4">
        <ActionButton onClick={onContinueToProfile}>{STATUS.correcting.action}</ActionButton>
      </div>
      <p className="mt-3 font-mono text-xs text-[var(--text-muted)]">Ref: {validationCode}</p>
    </SurfacePanel>
  );
}

export interface CancellingProps {
  readonly onCancelLocal: () => void;
  readonly onKeepSettingUp: () => void;
}

/** Cancellation — destructive confirmation + ambiguous-submission warning. */
export function CancellingScreen({ onCancelLocal, onKeepSettingUp }: CancellingProps) {
  return (
    <SurfacePanel title={STATUS.cancelling.title}>
      <p className="text-sm text-[var(--warning)]">{STATUS.cancelling.detail}</p>
      <div className="mt-4 flex flex-wrap gap-3">
        <ActionButton variant="danger" onClick={onCancelLocal}>
          {STATUS.cancelling.cancelAction}
        </ActionButton>
        <ActionButton variant="secondary" onClick={onKeepSettingUp}>
          {STATUS.cancelling.keepAction}
        </ActionButton>
      </div>
    </SurfacePanel>
  );
}

export interface TerminalProps {
  readonly supportCode: string;
  readonly onBack: () => void;
}

/** Fail-closed terminal state — sanitized support code only. */
export function TerminalScreen({ supportCode, onBack }: TerminalProps) {
  return (
    <SurfacePanel title={STATUS.terminal.title}>
      <p className="text-sm text-[var(--text-muted)]">{STATUS.terminal.detail}</p>
      <p className="mt-2 font-mono text-sm text-[var(--text)]" data-testid="support-code">
        {supportCode}
      </p>
      <div className="mt-4">
        <BackButton onClick={onBack} label="Back to start" />
      </div>
    </SurfacePanel>
  );
}
