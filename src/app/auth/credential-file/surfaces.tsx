/**
 * FEAT-009 credential-file UI — shared surfaces and copy.
 *
 * Complementary surfaces, spacing, and radius per the HushVoting frontend
 * rules: no heavy nested cards, borders reserved for focus/selected/
 * warning/error states. All components are thin renderers over Phase 4
 * projections; secret inputs are uncontrolled and submit directly to the
 * authority sink (never React state).
 */
import type { ReactNode } from 'react';
import { useInlineOnboardingBack } from '../onboarding/back-context';

/** Exact required copy (single source; matches presentation EXACT_COPY). */
export const COPY = {
  entry: {
    title: 'Restore credential file',
    detail: 'Import an encrypted HUSH credential file',
  },
  picker: {
    title: 'Choose your credential file',
    detail: 'Select the encrypted HUSH backup you want to restore.',
    choose: 'Choose a file',
    different: 'Choose a different file',
    selected: 'Credential file selected',
    selectedLabel: 'Selected credential file',
    selectedFallback: 'File name unavailable',
  },
  reading: {
    title: 'Reading credential file…',
    cancel: 'Cancel',
  },
  password: {
    title: 'Backup ready for password',
    label: 'Backup-file password',
    explainer: 'This password decrypts the selected backup only. It is not your HushVoting vault password.',
    submit: 'Decrypt backup',
    show: 'Show backup-file password',
    hide: 'Hide backup-file password',
    noPassword: 'This backup was created without a password',
    noPasswordWarning: 'This file has no password protection beyond possession.',
  },
  progress: {
    decrypting: 'Decrypting backup…',
    validating: 'Validating identity keys…',
    checking: 'Checking blockchain identity…',
    saving: 'Saving encrypted identity…',
    waiting: 'Waiting for blockchain final approval',
  },
  profile: {
    missing: 'Your credential file restored control of this identity, but no profile currently exists on this blockchain.',
    create: 'Create HushNetwork identity',
    network: 'Network',
    signing: 'Signing address',
    encryption: 'Encryption address',
    reveal: 'Reveal full address',
    copy: 'Copy full address',
    aliasLabel: 'Profile name',
    visibilityLabel: 'Visibility',
  },
  protection: {
    title: 'Protect this device',
    createVaultPassword: 'Create a HushVoting vault password',
    devicePasswordLabel: 'Device password (recommended)',
    passwordless: 'Passwordless (platform security)',
    sessionOnly: 'Session only — nothing saved on this device',
    sessionOnlyWarning: 'Keys stay only in memory; you will need this file again after closing.',
  },
  resume: {
    title: 'Finish restoring your identity',
    unlock: 'Unlock',
    cancelStage: 'Cancel restore',
  },
  success: {
    title: 'Identity restored',
    mnemonicNotice: 'Your unchanged backup still contains encrypted recovery words; HushVoting did not copy them.',
  },
  errors: {
    combined: 'The backup password is incorrect or the credential file is damaged.',
    inconsistentKeys: 'This credential file contains invalid or inconsistent identity keys and cannot be restored.',
    invalidFile: 'This file is not a valid HUSH credential backup.',
    serverProof: 'HushServerNode rejected the identity proof.',
    quarantine: 'Restore is blocked until local cleanup is verified.',
    wait: 'Please wait before trying again.',
    generic: 'Something went wrong; please try again.',
  },
} as const;

/** Shared panel: complementary surface, restrained radius, no heavy borders. */
export function RestorePanel({ title, children, aside }: { readonly title: string; readonly children: ReactNode; readonly aside?: ReactNode }) {
  return (
    <section className="mx-auto w-full max-w-xl px-4 py-8" data-testid="restore-panel">
      <div className="restore-surface bg-[var(--surface-strong)] p-6 shadow-sm">
        <div className="mb-4 flex items-start justify-between gap-3">
          <h2 className="w-full max-w-none text-xl font-semibold leading-snug text-[var(--text)]">{title}</h2>
          {aside}
        </div>
        {children}
      </div>
    </section>
  );
}

/** Back control (in-app Back shares one authority with browser/Android Back). */
export function RestoreBackButton({ onBack, label = 'Back' }: { readonly onBack: () => void; readonly label?: string }) {
  const showInlineBack = useInlineOnboardingBack();
  if (!showInlineBack) return null;
  return (
    <button type="button" onClick={onBack} className="rounded-lg px-3 py-2 text-sm font-medium text-[var(--text-muted)] hover:text-[var(--text)]" data-testid="restore-back">
      {label}
    </button>
  );
}

/** Primary action button (44×44 CSS px minimum target). */
export function RestorePrimaryButton({
  children,
  onClick,
  disabled = false,
  fullWidth = false,
  type = 'button',
  testId,
}: {
  readonly children: ReactNode;
  readonly onClick?: () => void;
  readonly disabled?: boolean;
  readonly fullWidth?: boolean;
  readonly type?: 'button' | 'submit';
  readonly testId: string;
}) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`button-default ${fullWidth ? 'w-full' : ''}`}
      data-testid={testId}
    >
      {children}
    </button>
  );
}

/** Safe status region (text + status semantics). */
export function RestoreStatusRegion({ children, role = 'status' }: { readonly children: ReactNode; readonly role?: 'status' | 'alert' }) {
  return (
    <p role={role} className="mt-3 text-sm font-medium text-[var(--text)]" data-testid="restore-status">
      {children}
    </p>
  );
}

/** Safe error region (never echoes secret/identifier values). */
export function RestoreErrorRegion({ children }: { readonly children: ReactNode }) {
  return (
    <div role="alert" className="mt-3 rounded-xl bg-[var(--surface-error)] p-3 text-sm text-[var(--text-error)]" data-testid="restore-error">
      {children}
    </div>
  );
}

/** Accessible countdown (announces changes; avoids high-frequency updates). */
export function BackoffCountdown({ remainingSeconds }: { readonly remainingSeconds: number }) {
  if (remainingSeconds <= 0) {
    return null;
  }
  return (
    <p aria-live="polite" className="mt-2 text-sm text-[var(--text-muted)]" data-testid="backoff-countdown">
      Please wait {remainingSeconds} second{remainingSeconds === 1 ? '' : 's'} before trying again.
    </p>
  );
}
