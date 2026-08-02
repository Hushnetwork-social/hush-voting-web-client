/**
 * FEAT-004 browser-vault UI — purpose-scoped mnemonic reveal + clipboard.
 *
 * The one approved transient mnemonic exception: a dedicated minimal component
 * after a fresh reveal-only password capability. Words render once as a
 * semantic ordered list, conceal after 60 seconds or earlier lifecycle events
 * (blur, background, navigation, Lock, authority loss, explicit close), and
 * are never placed in global/component business state, XState, persistence,
 * logs, traces, or serializable snapshots.
 *
 * Copy is never automatic: an explicit warned Copy action writes once, then a
 * best-effort empty overwrite is attempted after 30 seconds while foregrounded
 * (or immediately on conceal). The clipboard is never read.
 *
 * Normative source: FEAT-004 FeatureDescription "Mnemonic Reveal and
 * Clipboard"; FEAT-003 fresh elevation contract.
 */
import { useEffect, useRef, useState } from 'react';
import { REVEAL_COPY } from './copy';
import { useAutoConceal, useClipboardController } from './hooks';

export interface RevealWordsProps {
  /** The words are handed to this dedicated component ONCE by the authority. */
  readonly words: readonly string[];
  readonly onConcealed: () => void;
  readonly clipboard: Pick<Clipboard, 'writeText'> | null;
}

/** Transient reveal with semantic ordered words, bounded conceal, warned copy. */
export function RevealWords({ words, onConcealed, clipboard }: RevealWordsProps) {
  const [copied, setCopied] = useState(false);
  const [copyDenied, setCopyDenied] = useState(false);
  const cleanupRef = useRef<Promise<void> | null>(null);
  const { visible, conceal } = useAutoConceal(60_000, { onConceal: onConcealed });
  const controller = useClipboardController(clipboard);

  useEffect(() => {
    if (!visible && cleanupRef.current === null) {
      cleanupRef.current = controller
        .cleanupAfter(0)
        .then(() => undefined)
        .catch(() => undefined);
    }
  }, [visible, controller]);

  if (!visible) {
    return <div aria-hidden="true" />;
  }

  async function handleCopy() {
    const ok = await controller.copy(words.join(' '));
    setCopied(ok);
    setCopyDenied(!ok);
    if (ok) {
      // Best-effort empty overwrite after 30 s while foregrounded (no reads).
      void controller
        .cleanupAfter(30_000)
        .then(() => setCopied(false))
        .catch(() => undefined);
    }
  }

  return (
    <section aria-label={REVEAL_COPY.heading} className="vault-reveal">
      <h2>{REVEAL_COPY.heading}</h2>
      <p>{REVEAL_COPY.intro}</p>
      <p>{REVEAL_COPY.concealAfter}</p>
      <ol className="vault-reveal-words">
        {words.map((word, index) => (
          <li key={index}>{word}</li>
        ))}
      </ol>
      <p>{REVEAL_COPY.copyWarning}</p>
      <button type="button" onClick={handleCopy}>
        {copied ? REVEAL_COPY.copied : REVEAL_COPY.copy}
      </button>
      {copyDenied && <p role="alert">{REVEAL_COPY.copyDenied}</p>}
      <button type="button" onClick={conceal}>
        Conceal now
      </button>
    </section>
  );
}
