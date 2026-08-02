/**
 * FEAT-004 browser-vault UI hooks — bounded progress, conceal, clipboard.
 *
 * - `useBoundedProgress`: accessible indeterminate status that appears only
 *   after 250 ms; never fabricates percentage progress.
 * - `useAutoConceal`: conceals sensitive content after a bound or on
 *   blur/background/navigation/Lock; used by the mnemonic reveal.
 * - `useClipboardCleanup`: explicit warned copy with best-effort empty
 *   clipboard overwrite after 30 s while foregrounded; never reads the
 *   clipboard; denied writes surface a safe message.
 *
 * Normative source: FEAT-004 FeatureDescription "Asynchronous execution and
 * cancellation", "Mnemonic Reveal and Clipboard".
 */
import { useCallback, useEffect, useRef, useState } from 'react';

/** True once `delayMs` elapsed (default 250 ms — accessibility threshold). */
export function useBoundedProgress(delayMs = 250, active = true): boolean {
  const [shown, setShown] = useState(false);
  useEffect(() => {
    if (!active) {
      return;
    }
    const handle = setTimeout(() => setShown(true), delayMs);
    return () => clearTimeout(handle);
  }, [active, delayMs]);
  return active && shown;
}

/** Conceal state after a lifetime bound or on sensitive lifecycle events. */
export function useAutoConceal(lifetimeMs: number, events: { readonly onConceal: () => void }): { readonly visible: boolean; readonly conceal: () => void } {
  const [visible, setVisible] = useState(true);
  const onConcealRef = useRef(events.onConceal);
  useEffect(() => {
    onConcealRef.current = events.onConceal;
  }, [events.onConceal]);

  const conceal = useCallback(() => {
    setVisible(false);
    onConcealRef.current();
  }, []);

  useEffect(() => {
    if (!visible) {
      return;
    }
    const timer = setTimeout(conceal, lifetimeMs);
    const onBlur = () => conceal();
    const onVisibility = () => {
      if (document.visibilityState !== 'visible') {
        conceal();
      }
    };
    window.addEventListener('blur', onBlur);
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      clearTimeout(timer);
      window.removeEventListener('blur', onBlur);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [visible, lifetimeMs, conceal]);

  return { visible, conceal };
}

/** Best-effort clipboard overwrite result. */
export type ClipboardCleanupResult = 'cleared' | 'denied' | 'skipped';

export interface ClipboardController {
  /** Explicit user-triggered copy with the standard warning copy. */
  readonly copy: (text: string) => Promise<boolean>;
  /** Best-effort empty overwrite (foreground only, never reads the clipboard). */
  readonly cleanupAfter: (delayMs: number) => Promise<ClipboardCleanupResult>;
}

/** Clipboard controller bound to injected navigator.clipboard (testable). */
export function useClipboardController(clipboard: Pick<Clipboard, 'writeText'> | null): ClipboardController {
  const copy = useCallback(
    async (text: string) => {
      if (clipboard === null) {
        return false;
      }
      try {
        await clipboard.writeText(text);
        return true;
      } catch {
        return false;
      }
    },
    [clipboard],
  );

  const cleanupAfter = useCallback(
    async (delayMs: number): Promise<ClipboardCleanupResult> => {
      if (clipboard === null) {
        return 'skipped';
      }
      await new Promise((resolve) => setTimeout(resolve, delayMs));
      if (typeof document !== 'undefined' && document.visibilityState !== 'visible') {
        return 'skipped'; // never write while backgrounded
      }
      try {
        await clipboard.writeText('');
        return 'cleared';
      } catch {
        return 'denied';
      }
    },
    [clipboard],
  );

  return { copy, cleanupAfter };
}
