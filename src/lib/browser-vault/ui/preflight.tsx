/**
 * FEAT-004 browser-vault UI — preflight, durability, and progress surfaces.
 *
 * - `PreflightStatus`: presents capability results BEFORE any secret is
 *   collected; unsupported vs temporary (retryable) are distinct.
 * - `PersistenceWarning`: explicit durability acknowledgement required in a
 *   user-initiated Create/Restore flow.
 * - `BoundedProgress`: accessible indeterminate status after 250 ms with
 *   `aria-busy`; never a fabricated percentage.
 * - `VaultErrorSurface`: every FEAT-003/browser result code maps to ONE
 *   actionable, privacy-safe message (no raw exceptions, paths, DB keys,
 *   ciphertext, or free-form errors).
 *
 * All components are presentational: they receive typed props and never touch
 * the secret authority directly.
 *
 * Normative source: FEAT-004 FeatureDescription "Capability Preflight",
 * "Error Handling and User Feedback", "Storage persistence".
 */
import { PREFLIGHT_COPY, PERSISTENCE_WARNING, VAULT_ERROR_COPY } from './copy';
import { useBoundedProgress } from './hooks';

/** Non-secret preflight outcome (subset projected to the UI). */
export interface PreflightView {
  readonly ok: boolean;
  readonly retryable: boolean;
  readonly secureOrigin: boolean;
  readonly unsupportedCount: number;
}

export function PreflightStatus({ report }: { readonly report: PreflightView }) {
  if (report.ok) {
    return null;
  }
  const message = report.retryable
    ? PREFLIGHT_COPY.retryable
    : report.secureOrigin
      ? PREFLIGHT_COPY.unsupported
      : PREFLIGHT_COPY.secureOrigin;
  return (
    <div role="status" aria-live="polite" className="vault-preflight">
      <p>{message}</p>
      {report.retryable && (
        <p className="vault-preflight-action">You can retry this step.</p>
      )}
    </div>
  );
}

export function PersistenceWarning({ onAcknowledge }: { readonly onAcknowledge: () => void }) {
  return (
    <div role="alert" className="vault-persistence-warning">
      <p>{PERSISTENCE_WARNING}</p>
      <button type="button" onClick={onAcknowledge}>
        I understand — continue
      </button>
    </div>
  );
}

/** Indeterminate accessible progress shown only after the 250 ms threshold. */
export function BoundedProgress({ active = true }: { readonly active?: boolean }) {
  const visible = useBoundedProgress(250, active);
  if (!visible) {
    return null;
  }
  return (
    <div role="status" aria-busy="true" aria-live="polite" className="vault-progress">
      <span>Processing…</span>
    </div>
  );
}

/** One privacy-safe error surface per closed result code. */
export function VaultErrorSurface({ code, onAction }: { readonly code: string; readonly onAction?: () => void }) {
  const entry = VAULT_ERROR_COPY[code as keyof typeof VAULT_ERROR_COPY];
  if (!entry) {
    // Unknown/future code: generic text + allowed action (never raw detail).
    return (
      <div role="alert" className="vault-error">
        <p>Something went wrong. Please try again.</p>
        {onAction && (
          <button type="button" onClick={onAction}>
            Retry
          </button>
        )}
      </div>
    );
  }
  return (
    <div role="alert" className="vault-error">
      <p>{entry.message}</p>
      {onAction && (
        <button type="button" onClick={onAction}>
          {entry.action}
        </button>
      )}
    </div>
  );
}
