/**
 * FEAT-005 Ubuntu auth UI surfaces — provider, fallback, recovery, upgrade.
 *
 * Components are self-contained and driven ONLY by closed safe projections
 * from the FEAT-002 bridge; they never receive raw native detail and never
 * hold secret values. A11y-first: semantic roles/names, keyboard operation,
 * visible focus, live regions for state changes, and no secret content in
 * titles or announcements. The visual hierarchy uses complementary surfaces,
 * spacing, and radius — borders only for focus/selected/warning/error.
 */

import { useId, useState } from 'react';
import type { ProviderAvailability } from '../../../lib/ubuntu-vault';
import {
  FALLBACK_ACKNOWLEDGEMENT_LABEL,
  FALLBACK_EXPLANATION,
  providerStatusDetail,
  providerStatusTitle,
  UPGRADE_OFFER_DETAIL,
  UPGRADE_OFFER_TITLE,
} from './copy';

/** Shared panel surface (complementary dark surface; no white outlines). */
export function SurfacePanel({
  title,
  children,
  role,
  ariaLive,
}: {
  title: string;
  children: React.ReactNode;
  role?: 'status' | 'region' | 'alert';
  ariaLive?: 'polite' | 'assertive';
}) {
  const titleId = useId();
  return (
    <section
      role={role}
      aria-live={ariaLive}
      aria-labelledby={titleId}
      className="rounded-2xl bg-[var(--surface)] px-5 py-4 shadow-sm"
      data-testid="ubuntu-surface"
    >
      <h2 id={titleId} className="mb-2 text-base font-semibold text-[var(--text)]">
        {title}
      </h2>
      {children}
    </section>
  );
}

/** Safe action button (focus ring only, no default outline styling). */
export function ActionButton({
  children,
  onClick,
  variant = 'primary',
  disabled = false,
}: {
  children: React.ReactNode;
  onClick: () => void;
  variant?: 'primary' | 'secondary' | 'danger';
  disabled?: boolean;
}) {
  const styles = {
    primary: 'bg-[var(--primary)] text-[var(--on-primary)] hover:opacity-90',
    secondary: 'bg-[var(--surface-elevated)] text-[var(--text)] hover:opacity-90',
    danger: 'bg-[var(--surface-elevated)] text-[var(--tertiary)] hover:opacity-90',
  }[variant];
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`rounded-lg px-4 py-2 text-sm font-semibold transition-opacity focus-visible:outline-2 focus-visible:outline-[var(--focus)] focus-visible:outline-offset-2 disabled:cursor-not-allowed disabled:opacity-50 ${styles}`}
    >
      {children}
    </button>
  );
}

/** Provider status surface (one closed state → safe actions). */
export function ProviderStatusPanel({
  state,
  onUnlockKeyring,
  onRetry,
  onEnableOsProtection,
  onPortableRecovery,
  onCancel,
}: {
  state: Exclude<ProviderAvailability, 'unavailable'>;
  onUnlockKeyring?: () => void;
  onRetry?: () => void;
  onEnableOsProtection?: () => void;
  onPortableRecovery?: () => void;
  onCancel?: () => void;
}) {
  return (
    <SurfacePanel title={providerStatusTitle(state)} role="status" ariaLive="polite">
      <p className="mb-3 text-sm text-[var(--muted)]">{providerStatusDetail(state)}</p>
      <div className="flex flex-wrap gap-2">
        {state === 'availableLocked' && onUnlockKeyring && (
          <ActionButton onClick={onUnlockKeyring}>Unlock Ubuntu keyring</ActionButton>
        )}
        {state === 'promptCancelled' && onRetry && (
          <ActionButton onClick={onRetry}>Retry</ActionButton>
        )}
        {state === 'temporarilyUnavailable' && onRetry && (
          <ActionButton onClick={onRetry}>Retry</ActionButton>
        )}
        {state === 'unqualifiedProvider' && onEnableOsProtection && (
          <ActionButton onClick={onEnableOsProtection}>Enable Ubuntu keyring</ActionButton>
        )}
        {state === 'protectionInvalidated' && onPortableRecovery && (
          <ActionButton onClick={onPortableRecovery}>Portable recovery</ActionButton>
        )}
        {onCancel && <ActionButton variant="secondary" onClick={onCancel}>Cancel</ActionButton>}
      </div>
    </SurfacePanel>
  );
}

/** Confirmed-absence informed fallback (acknowledgement required). */
export function FallbackAcknowledgment({
  onRetryOrEnable,
  onContinueFallback,
}: {
  onRetryOrEnable: () => void;
  onContinueFallback: (acknowledged: boolean) => void;
}) {
  const [acknowledged, setAcknowledged] = useState(false);
  return (
    <SurfacePanel
      title="Ubuntu keyring protection was not found"
      role="region"
      ariaLive="polite"
    >
      <p className="mb-2 text-sm text-[var(--muted)]">{FALLBACK_EXPLANATION}</p>
      <p className="mb-3 text-sm text-[var(--muted)]">
        Retry or enable the Ubuntu keyring first. Password-only protection is a
        secondary choice and is never labeled OS-backed or hardware-backed.
      </p>
      <label className="mb-4 flex items-start gap-2 text-sm text-[var(--text)]">
        <input
          type="checkbox"
          checked={acknowledged}
          onChange={(event) => setAcknowledged(event.target.checked)}
          aria-required="true"
          className="mt-1 size-4 accent-[var(--primary)] focus-visible:outline-2 focus-visible:outline-[var(--focus)]"
        />
        <span>{FALLBACK_ACKNOWLEDGEMENT_LABEL}</span>
      </label>
      <div className="flex flex-wrap gap-2">
        <ActionButton onClick={onRetryOrEnable}>Retry / Enable Ubuntu keyring</ActionButton>
        <ActionButton
          variant="secondary"
          disabled={!acknowledged}
          onClick={() => onContinueFallback(acknowledged)}
        >
          Continue with password-only protection
        </ActionButton>
      </div>
    </SurfacePanel>
  );
}

/** Later-qualified-provider automatic-upgrade offer (atomic, no downgrade). */
export function UpgradeOffer({
  onAddProtection,
  onNotNow,
}: {
  onAddProtection: () => void;
  onNotNow: () => void;
}) {
  return (
    <SurfacePanel title={UPGRADE_OFFER_TITLE} role="region" ariaLive="polite">
      <p className="mb-3 text-sm text-[var(--muted)]">{UPGRADE_OFFER_DETAIL}</p>
      <div className="flex flex-wrap gap-2">
        <ActionButton onClick={onAddProtection}>Add Ubuntu keyring protection</ActionButton>
        <ActionButton variant="secondary" onClick={onNotNow}>Not now</ActionButton>
      </div>
    </SurfacePanel>
  );
}

/** Provider invalidation / verified rollback recovery surface. */
export function RollbackRecoveryPanel({
  variant,
  onRestoreWords,
  onRestoreFile,
  onRecoverRollback,
  onCancel,
}: {
  variant: 'invalidated' | 'rollbackAvailable';
  onRestoreWords: () => void;
  onRestoreFile: () => void;
  onRecoverRollback?: () => void;
  onCancel: () => void;
}) {
  const [confirmed, setConfirmed] = useState(false);
  const rollback = variant === 'rollbackAvailable';
  return (
    <SurfacePanel
      title={rollback ? 'A previous verified copy is available' : 'Recovery required'}
      role="region"
      ariaLive="polite"
    >
      <p className="mb-3 text-sm text-[var(--muted)]">
        {rollback
          ? 'You can recover the previous verified copy. This requires explicit confirmation and exact online identity verification; nothing is changed silently.'
          : 'Your encrypted vault files were preserved. Restore your identity with your recovery words or an encrypted credential file; no replacement key is guessed.'}
      </p>
      {rollback && (
        <label className="mb-4 flex items-start gap-2 text-sm text-[var(--text)]">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={(event) => setConfirmed(event.target.checked)}
            aria-required="true"
            className="mt-1 size-4 accent-[var(--primary)] focus-visible:outline-2 focus-visible:outline-[var(--focus)]"
          />
          <span>I confirm recovering the previous verified copy.</span>
        </label>
      )}
      <div className="flex flex-wrap gap-2">
        {rollback && onRecoverRollback && (
          <ActionButton disabled={!confirmed} onClick={onRecoverRollback}>
            Recover previous copy
          </ActionButton>
        )}
        <ActionButton onClick={onRestoreWords}>Restore Recovery Words</ActionButton>
        <ActionButton variant="secondary" onClick={onRestoreFile}>
          Restore Credential File
        </ActionButton>
        <ActionButton variant="secondary" onClick={onCancel}>Cancel</ActionButton>
      </div>
    </SurfacePanel>
  );
}
