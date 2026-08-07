/**
 * FEAT-007 create-user UI — shared surface primitives.
 *
 * Complementary dark surfaces, spacing, and radius separate sections (no
 * white outline separators). Borders only for focus/selected/warning/error.
 * A11y-first: semantic headings/roles, visible focus, live regions, and
 * 44×44 px minimum interactive targets.
 */

import { useId } from 'react';
import { useInlineOnboardingBack } from '../onboarding/back-context';

/** Shared complementary surface panel (never heavy-card-in-card). */
export function SurfacePanel({ title, children }: { title: string; children: React.ReactNode }) {
  const titleId = useId();
  return (
    <section aria-labelledby={titleId} className="rounded-[0.85rem] bg-[var(--surface-strong)] p-6 shadow-sm" data-testid="create-surface">
      <h2 id={titleId} className="mb-2 text-base font-semibold text-[var(--text)]">
        {title}
      </h2>
      {children}
    </section>
  );
}

/** Primary/secondary action with focus ring and 44×44 min target. */
export function ActionButton({
  children,
  onClick,
  variant = 'primary',
  disabled = false,
  busy = false,
  fullWidth = false,
}: {
  children: React.ReactNode;
  onClick: () => void;
  variant?: 'primary' | 'secondary' | 'danger';
  disabled?: boolean;
  busy?: boolean;
  fullWidth?: boolean;
}) {
  const base =
    'inline-flex min-h-11 items-center justify-center px-4 py-2 text-sm font-semibold transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-50';
  const styles = {
    primary: 'button-default',
    secondary: 'rounded-[0.85rem] bg-[var(--surface-stronger)] text-[var(--text)] hover:bg-[var(--surface-highest)]',
    danger: 'rounded-[0.85rem] bg-[var(--danger)] text-white hover:bg-[var(--danger-strong)]',
  };
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled || busy}
      className={`${base} ${styles[variant]}${fullWidth ? ' w-full' : ''}`}
      data-testid="create-action"
    >
      {busy ? '…' : children}
    </button>
  );
}

/** Back control (hidden at the safe root). */
export function BackButton({ onClick, label = 'Back' }: { onClick: () => void; label?: string }) {
  const showInlineBack = useInlineOnboardingBack();
  if (!showInlineBack) return null;
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex min-h-11 items-center gap-1 rounded-xl px-3 text-sm font-medium text-[var(--text-muted)] hover:text-[var(--text)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)]"
      data-testid="create-back"
    >
      ‹ {label}
    </button>
  );
}

/** Field error (safe text only; never echoes secrets). */
export function FieldError({ id, children }: { id: string; children: string }) {
  return (
    <p id={id} role="alert" className="mt-1 text-sm font-medium text-[var(--danger)]">
      {children}
    </p>
  );
}

/** Live status region for state changes (aria-live polite). */
export function StatusRegion({ children }: { children: React.ReactNode }) {
  return (
    <div aria-live="polite" role="status" className="mt-3 text-sm text-[var(--text-muted)]" data-testid="create-status">
      {children}
    </div>
  );
}
