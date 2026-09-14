/** FEAT-007 AC-007-016: the bounded reveal never becomes React data. */
export interface RecoveryWordDisplay {
  readonly attach: (target: HTMLOListElement) => () => void;
  readonly copy: () => Promise<boolean>;
}

export function createRecoveryWordDisplay() {
  let words: readonly string[] | null = null;
  let target: HTMLOListElement | null = null;
  let revoked = false;
  const render = () => {
    if (!target) return;
    target.replaceChildren();
    if (!words || revoked) return;
    const doc = target.ownerDocument;
    for (const [index, word] of words.entries()) {
      const item = doc.createElement('li');
      item.className = 'flex gap-2 rounded-lg bg-[var(--surface-strong)] px-3 py-1.5 text-sm text-[var(--text)]';
      const number = doc.createElement('span');
      number.className = 'font-mono text-xs text-[var(--text-muted)]';
      number.textContent = String(index + 1).padStart(2, '0');
      const value = doc.createElement('span');
      value.textContent = word;
      item.append(number, value);
      target.append(item);
    }
  };
  const display: RecoveryWordDisplay = Object.freeze({
    attach(next: HTMLOListElement) {
      target?.replaceChildren();
      if (revoked) { next.replaceChildren(); return () => undefined; }
      target = next;
      render();
      return () => {
        next.replaceChildren();
        if (target === next) target = null;
      };
    },
    async copy() {
      if (revoked || !words || !target?.isConnected || document.visibilityState !== 'visible') return false;
      try {
        if (!navigator.clipboard?.writeText) return false;
        await navigator.clipboard.writeText(words.join(' '));
        return true;
      } catch { return false; }
    },
  });
  return {
    display,
    update(next: readonly string[] | null) { words = revoked ? null : next; render(); },
    dispose() { revoked = true; words = null; render(); target = null; },
  };
}
