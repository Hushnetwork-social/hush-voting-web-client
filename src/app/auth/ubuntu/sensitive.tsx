/**
 * FEAT-005 sensitive Ubuntu UI — recovery-word reveal, removal progress, and
 * authenticated Security settings (Task 5.3).
 *
 * Recovery words are the ONE bounded WebView exception: delivered once to one
 * minimal semantic component, concealed within 60 seconds or any earlier
 * security event (focus loss, route change, minimize, suspend, Lock, close).
 * Clipboard copy is explicit + warned; cleanup is best effort and never reads
 * unrelated clipboard content. Removal progress is non-cancellable once
 * confirmed and never reports success while incomplete.
 */

import { useEffect, useRef, useState } from 'react';
import type { ProtectionMode } from '../../../lib/ubuntu-vault';
import {
  CLIPBOARD_CLEANUP_SECONDS,
  protectionModeDescription,
  protectionModeLabel,
  REMOVAL_INCOMPLETE_DETAIL,
  REMOVAL_INCOMPLETE_TITLE,
  REMOVAL_PROGRESS_LABEL,
  REVEAL_CONCEAL_SECONDS,
  REVEAL_LIMITATIONS,
} from './copy';
import { ActionButton, SurfacePanel } from './surfaces';

/** Best-effort clipboard write with warned copy semantics (exported as a
 * test seam; production behavior is identical). */
export async function writeClipboard(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

/** Best-effort clipboard cleanup after the delay — never reads content. */
function scheduleClipboardCleanup(delaySeconds: number): (() => void) | null {
  try {
    const timeout = window.setTimeout(() => {
      // Best-effort overwrite with an empty value; may fail or be defeated by
      // clipboard managers — stated honestly in the UI.
      void navigator.clipboard.writeText('').catch(() => undefined);
    }, delaySeconds * 1000);
    return () => window.clearTimeout(timeout);
  } catch {
    return null;
  }
}

/** Recovery-word reveal (one bounded delivery; synthetic words in tests). */
export function RevealPanel({
  words,
  onConceal,
  lifecycleSignal,
}: {
  words: readonly string[];
  onConceal: () => void;
  /** External security events (focus loss, minimize, suspend, Lock, route). */
  lifecycleSignal?: number;
}) {
  const [remainingSeconds, setRemainingSeconds] = useState(REVEAL_CONCEAL_SECONDS);
  const [copied, setCopied] = useState(false);
  const concealed = useRef(false);

  const conceal = () => {
    if (!concealed.current) {
      concealed.current = true;
      onConceal();
    }
  };

  // Deterministic 60-second concealment (timeout fires conceal directly).
  useEffect(() => {
    const timeout = window.setTimeout(conceal, REVEAL_CONCEAL_SECONDS * 1000);
    return () => window.clearTimeout(timeout);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Countdown display only (never drives concealment).
  useEffect(() => {
    const interval = window.setInterval(() => {
      setRemainingSeconds((current) => Math.max(0, current - 1));
    }, 1000);
    return () => window.clearInterval(interval);
  }, []);

  // Focus loss / window blur → immediate conceal.
  useEffect(() => {
    const handleBlur = () => conceal();
    window.addEventListener('blur', handleBlur);
    return () => window.removeEventListener('blur', handleBlur);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // External lifecycle signal (route change, minimize, suspend, Lock) →
  // immediate conceal.
  useEffect(() => {
    if (lifecycleSignal !== undefined) {
      conceal();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lifecycleSignal]);

  const handleCopy = async () => {
    const ok = await writeClipboard(words.join(' '));
    if (ok) {
      setCopied(true);
      scheduleClipboardCleanup(CLIPBOARD_CLEANUP_SECONDS);
    }
  };

  return (
    <SurfacePanel
      title="Recovery words"
      role="region"
      ariaLive="polite"
    >
      <p className="mb-1 text-sm text-[var(--muted)]" aria-hidden="true">
        Conceals automatically in {remainingSeconds}s or sooner on focus loss.
      </p>
      <p className="mb-3 text-sm font-semibold text-[var(--tertiary)]" role="status">
        {remainingSeconds}s remaining before concealment
      </p>
      <ol className="mb-4 grid list-none grid-cols-2 gap-2 pl-0 sm:grid-cols-3">
        {words.map((word, index) => (
          <li key={`${word}-${index}`} className="rounded-lg bg-[var(--surface-elevated)] px-3 py-2 text-sm text-[var(--text)]">
            <span className="mr-2 inline-block w-6 text-right text-[var(--muted)]" aria-hidden="true">
              {index + 1}.
            </span>
            {word}
          </li>
        ))}
      </ol>
      <div className="flex flex-wrap items-center gap-2">
        <ActionButton variant="secondary" onClick={() => void handleCopy()}>
          Copy with warning
        </ActionButton>
        {copied && (
          <span role="status" className="text-xs text-[var(--muted)]">
            Copied — clipboard managers may retain it; cleanup is best effort.
          </span>
        )}
        <ActionButton onClick={onConceal}>Conceal and close</ActionButton>
      </div>
      <p className="mt-3 text-xs text-[var(--muted)]">{REVEAL_LIMITATIONS}</p>
    </SurfacePanel>
  );
}

/** Non-cancellable removal progress / incomplete resume. */
export function RemovalProgressPanel({
  incomplete,
  onRetryRemoval,
}: {
  incomplete: boolean;
  onRetryRemoval: () => void;
}) {
  if (incomplete) {
    return (
      <SurfacePanel title={REMOVAL_INCOMPLETE_TITLE} role="alert" ariaLive="assertive">
        <p className="mb-3 text-sm text-[var(--muted)]">{REMOVAL_INCOMPLETE_DETAIL}</p>
        <div className="flex flex-wrap gap-2">
          <ActionButton onClick={onRetryRemoval}>Retry removal</ActionButton>
        </div>
      </SurfacePanel>
    );
  }
  return (
    <SurfacePanel title="Removal" role="status" ariaLive="polite">
      <p className="mb-3 text-sm text-[var(--muted)]">{REMOVAL_PROGRESS_LABEL}</p>
      <div
        role="progressbar"
        aria-valuetext={REMOVAL_PROGRESS_LABEL}
        className="h-1.5 w-full overflow-hidden rounded-full bg-[var(--surface-elevated)]"
      >
        <div className="h-full w-1/2 animate-pulse rounded-full bg-[var(--primary)]" />
      </div>
    </SurfacePanel>
  );
}

/** Authenticated Security settings — honest protection summary (full-width). */
export function SecuritySettings({
  mode,
  fallbackAcknowledged,
  upgradeEligibleAfterUnlock,
  onAddProtection,
  onReveal,
  onRemoveLocalUser,
  onLock,
}: {
  mode: ProtectionMode;
  fallbackAcknowledged: boolean;
  upgradeEligibleAfterUnlock: boolean;
  onAddProtection: () => void;
  onReveal: () => void;
  onRemoveLocalUser: () => void;
  onLock: () => void;
}) {
  return (
    <section
      aria-labelledby="security-settings-title"
      className="w-full rounded-2xl bg-[var(--surface)] px-5 py-4"
      data-testid="security-settings"
    >
      <h2 id="security-settings-title" className="mb-2 text-lg font-semibold text-[var(--text)]">
        Security
      </h2>
      <dl className="mb-4 grid gap-3 sm:grid-cols-2">
        <div className="rounded-xl bg-[var(--surface-elevated)] p-3">
          <dt className="text-xs uppercase tracking-wide text-[var(--muted)]">Protection</dt>
          <dd className="mt-1 text-sm font-semibold text-[var(--text)]">
            {protectionModeLabel(mode)}
          </dd>
          <dd className="mt-1 text-xs text-[var(--muted)]">
            {protectionModeDescription(mode)}
          </dd>
        </div>
        <div className="rounded-xl bg-[var(--surface-elevated)] p-3">
          <dt className="text-xs uppercase tracking-wide text-[var(--muted)]">Fallback state</dt>
          <dd className="mt-1 text-sm text-[var(--text)]">
            {mode === 'passwordOnly'
              ? fallbackAcknowledged
                ? 'Acknowledged password-only protection'
                : 'Password-only protection (not acknowledged)'
              : 'Not applicable'}
          </dd>
          {mode === 'passwordOnly' && upgradeEligibleAfterUnlock && (
            <dd className="mt-1 text-xs text-[var(--tertiary)]">
              Ubuntu keyring protection can be added after your next successful unlock.
            </dd>
          )}
        </div>
      </dl>
      <div className="flex flex-wrap gap-2">
        {mode === 'passwordOnly' && upgradeEligibleAfterUnlock && (
          <ActionButton onClick={onAddProtection}>Add Ubuntu keyring protection</ActionButton>
        )}
        <ActionButton variant="secondary" onClick={onReveal}>Reveal recovery words</ActionButton>
        <ActionButton variant="danger" onClick={onRemoveLocalUser}>Remove local user</ActionButton>
        <ActionButton variant="secondary" onClick={onLock}>Lock</ActionButton>
      </div>
    </section>
  );
}
