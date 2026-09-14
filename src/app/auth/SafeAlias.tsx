// FEAT-008 AC-008-035 / FEAT-009 AC-009-041: presentation only.
import { validateAlias } from '../../lib/identity-creation/profile';

// The existing profile contract's unsafe controls. Legitimate ZWJ/ZWNJ stay.
const UNSAFE_CONTROLS = /[\u0000-\u001f\u007f-\u009f\u00ad\u200b\u200e\u200f\u2028-\u202e\u2060\u2066-\u2069\ufeff]/gu;

/** Preserve chain metadata; sanitize only text rendered in the interface. */
export function SafeAlias({ alias }: { alias: string | null }) {
  if (alias === null || alias.length === 0) {
    return <span className="text-[var(--text-muted)]">—</span>;
  }
  const display = alias.replace(UNSAFE_CONTROLS, '\ufffd');
  return (
    <span className="break-all">
      <bdi data-testid="safe-alias" dir="auto">{display}</bdi>
      {!validateAlias(alias).ok && <span className="block text-xs text-[var(--text-muted)]" data-testid="historical-alias-notice">
        This historical profile name may need updating.
      </span>}
    </span>
  );
}
