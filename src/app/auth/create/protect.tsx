/**
 * FEAT-007 create-user UI — device protection and safe final review
 * (Task 5.3).
 *
 * Device password is the ONLY persistent secret step: inputs are uncontrolled
 * and transferred directly to the secret authority (SecretSubmissionSink
 * boundary); they never enter React/XState business state and clear after
 * transfer. Review shows only safe public fields with abbreviated addresses.
 */

import { useRef, useState } from 'react';
import type { CreationReviewProjection } from '../../../lib/identity-creation/contracts.js';
import { PROTECT, REVIEW } from './copy';
import { ActionButton, BackButton, FieldError, StatusRegion, SurfacePanel } from './surfaces';

export interface ProtectProps {
  readonly onProtect: (password: string) => void;
  readonly onBack: () => void;
  readonly submitting: boolean;
}

/** Wireframe 5 — Protect this device (direct authority boundary). */
export function ProtectScreen({ onProtect, onBack, submitting }: ProtectProps) {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [show, setShow] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const passwordRef = useRef<HTMLInputElement>(null);

  const submit = () => {
    if (password.length === 0) {
      setError(PROTECT.policy(6));
      passwordRef.current?.focus();
      return;
    }
    if (password !== confirm) {
      setError(PROTECT.mismatch);
      return;
    }
    setError(null);
    // Direct transfer to the secret authority; clear local buffers.
    onProtect(password);
    setPassword('');
    setConfirm('');
  };

  return (
    <SurfacePanel title={PROTECT.title}>
      <p className="mb-4 text-sm text-[var(--text-muted)]">{PROTECT.detail}</p>
      <p className="mb-3 text-xs text-[var(--text-muted)]">{PROTECT.cannotReset}</p>
      <label htmlFor="device-password" className="mb-1 block text-sm font-medium text-[var(--text)]">
        {PROTECT.label}
      </label>
      <div className="flex gap-2">
        <input
          id="device-password"
          ref={passwordRef}
          type={show ? 'text' : 'password'}
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password"
          aria-describedby={error ? 'device-password-error' : undefined}
          className="min-h-11 w-full rounded-xl border border-transparent bg-[var(--surface-strong)] px-3 text-sm text-[var(--text)] focus:border-[var(--accent)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)]"
        />
        <button
          type="button"
          onClick={() => setShow((v) => !v)}
          aria-pressed={show}
          className="min-h-11 shrink-0 rounded-xl px-3 text-sm font-medium text-[var(--text-muted)] hover:text-[var(--text)]"
        >
          {show ? PROTECT.hide : PROTECT.show}
        </button>
      </div>
      <label htmlFor="device-password-confirm" className="mt-3 mb-1 block text-sm font-medium text-[var(--text)]">
        {PROTECT.confirmLabel}
      </label>
      <input
        id="device-password-confirm"
        type={show ? 'text' : 'password'}
        value={confirm}
        onChange={(e) => setConfirm(e.target.value)}
        autoComplete="new-password"
        className="min-h-11 w-full rounded-xl border border-transparent bg-[var(--surface-strong)] px-3 text-sm text-[var(--text)] focus:border-[var(--accent)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)]"
      />
      {error ? <FieldError id="device-password-error">{error}</FieldError> : null}
      <div className="mt-4 flex items-center gap-3">
        <BackButton onClick={onBack} />
        <ActionButton onClick={submit} busy={submitting}>
          {PROTECT.action}
        </ActionButton>
      </div>
    </SurfacePanel>
  );
}

export interface ReviewProps {
  readonly review: CreationReviewProjection;
  readonly onCreate: () => void;
  readonly onBack: () => void;
  readonly submitting: boolean;
}

/** Wireframe 6 — Review and Create Identity (safe fields only). */
export function ReviewScreen({ review, onCreate, onBack, submitting }: ReviewProps) {
  const rows = [
    { label: REVIEW.alias, value: review.normalizedAlias },
    { label: REVIEW.visibility, value: review.visibility === 'public' ? 'Public' : 'Private' },
    { label: REVIEW.signingAddress, value: review.abbreviatedSigningAddress },
  ];
  return (
    <SurfacePanel title={REVIEW.title}>
      <p className="mb-3 text-sm text-[var(--text-muted)]">{REVIEW.detail}</p>
      <dl className="divide-y divide-[var(--surface-strong)] rounded-xl bg-[var(--surface-strong)] px-4">
        {rows.map((row) => (
          <div key={row.label} className="flex justify-between gap-4 py-2 text-sm">
            <dt className="text-[var(--text-muted)]">{row.label}</dt>
            <dd className="font-medium text-[var(--text)]">{row.value}</dd>
          </div>
        ))}
        <div className="flex justify-between gap-4 py-2 text-sm">
          <dt className="text-[var(--text-muted)]">{REVIEW.recovery}</dt>
          <dd className="font-medium text-[var(--text)]">{REVIEW.recoveryConfirmed}</dd>
        </div>
        <div className="flex justify-between gap-4 py-2 text-sm">
          <dt className="text-[var(--text-muted)]">{REVIEW.deviceProtection}</dt>
          <dd className="font-medium text-[var(--text)]">{REVIEW.deviceProtectionReady}</dd>
        </div>
      </dl>
      <div className="mt-4 flex items-center gap-3">
        <BackButton onClick={onBack} />
        <ActionButton onClick={onCreate} busy={submitting} disabled={submitting}>
          {submitting ? REVIEW.submitting : REVIEW.action}
        </ActionButton>
      </div>
    </SurfacePanel>
  );
}
