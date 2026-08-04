/**
 * FEAT-008 recovery-words UI — shared surface primitives.
 *
 * Complementary dark surfaces, spacing, and radius separate sections (no
 * white outline separators). Borders only for focus/selected/warning/error.
 * A11y-first: semantic headings/roles, visible focus, live regions, 44×44 px
 * minimum interactive targets, 320 px reflow.
 */
import { useId } from 'react';

/** Shared complementary surface panel (never heavy-card-in-card). */
export function RecoveryPanel({ title, children }: { title: string; children: React.ReactNode }) {
  const titleId = useId();
  return (
    <section aria-labelledby={titleId} className="rounded-2xl bg-[var(--surface)] px-5 py-4 shadow-sm" data-testid="recovery-surface">
      <h2 id={titleId} className="mb-2 text-base font-semibold text-[var(--text)]">
        {title}
      </h2>
      {children}
    </section>
  );
}

/** Primary/secondary/danger action with focus ring and 44×44 min target. */
export function RecoveryActionButton({
  children,
  onClick,
  variant = 'primary',
  disabled = false,
  busy = false,
}: {
  children: React.ReactNode;
  onClick: () => void;
  variant?: 'primary' | 'secondary' | 'danger';
  disabled?: boolean;
  busy?: boolean;
}) {
  const base =
    'inline-flex min-h-11 items-center justify-center rounded-xl px-4 py-2 text-sm font-semibold transition-colors focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)] disabled:cursor-not-allowed disabled:opacity-50';
  const styles = {
    primary: 'bg-[var(--accent)] text-white hover:bg-[var(--accent-strong)]',
    secondary: 'bg-[var(--surface-strong)] text-[var(--text)] hover:bg-[var(--surface-stronger)]',
    danger: 'bg-[var(--danger)] text-white hover:bg-[var(--danger-strong)]',
  };
  return (
    <button type="button" onClick={onClick} disabled={disabled || busy} className={`${base} ${styles[variant]}`} data-testid="recovery-action">
      {busy ? '…' : children}
    </button>
  );
}

/** Back/lock control (root-only navigation label per stage). */
export function RecoveryBackButton({ onClick, label = 'Back' }: { onClick: () => void; label?: string }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="inline-flex min-h-11 items-center gap-1 rounded-xl px-3 text-sm font-medium text-[var(--text-muted)] hover:text-[var(--text)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)]"
      data-testid="recovery-back"
    >
      ‹ {label}
    </button>
  );
}

/** Field error (safe text only; never echoes secrets). */
export function RecoveryFieldError({ id, children }: { id: string; children: string }) {
  return (
    <p id={id} role="alert" className="mt-1 text-sm font-medium text-[var(--danger)]">
      {children}
    </p>
  );
}

/** Live status region for state changes (aria-live polite). */
export function RecoveryStatusRegion({ children }: { children: React.ReactNode }) {
  return (
    <div aria-live="polite" role="status" className="mt-3 text-sm text-[var(--text-muted)]" data-testid="recovery-status">
      {children}
    </div>
  );
}

/** Accessible word input — DOM-owned buffer; value never lifted to app state. */
export function WordInput({
  id,
  label,
  concealed,
  invalid,
  onValue,
}: {
  id: string;
  label: string;
  concealed: boolean;
  invalid: boolean;
  onValue: (value: string) => void;
}) {
  return (
    <label htmlFor={id} className="flex flex-col gap-1 text-xs font-medium text-[var(--text-muted)]">
      {label}
      <input
        id={id}
        type={concealed ? 'password' : 'text'}
        autoComplete="off"
        autoCorrect="off"
        autoCapitalize="off"
        spellCheck={false}
        aria-invalid={invalid || undefined}
        onChange={(event) => onValue(event.target.value)}
        className={`min-h-11 rounded-xl border bg-[var(--surface-strong)] px-3 py-2 text-sm text-[var(--text)] focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--accent)] ${
          invalid ? 'border-[var(--danger)]' : 'border-transparent'
        }`}
        data-testid={`word-input-${id}`}
      />
    </label>
  );
}
