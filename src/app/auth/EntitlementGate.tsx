/**
 * FEAT-016 Task 5.1 — the minimal, blocking, accessible entitlement gate.
 *
 * Rendered only while identity is authenticated but entitlement is not ready
 * (the machine is inside compound `authenticated` outside `entitlementReady`).
 * Shows ONLY branding/safe alias/coarse network state/closed stage copy and
 * the allowed actions (Lock always; Retry for recoverable delayed, unavailable
 * and compatible-service checks). It never mounts navigation, plan details,
 * Back, Cancel, Continue, or a replacement action.
 *
 * React contains no signing/secret/transaction/persistence/transport/polling
 * authority: actions route through typed intents to the adapter/statechart.
 *
 * Normative source: FEAT-016 FeatureDescription "User Experience" (minimal
 * gate, exact copy, Ready/Back/accessibility); Wireframes-design.md G0–G6;
 * `lib/auth/presentation/entitlement-presentation.ts`.
 */

'use client';

import { useEffect, useRef } from 'react';
import type { AuthRenderProjection } from '../../lib/auth/react/adapter';
import { entitlementGatePresentation, safeRedactedSupportCode } from '../../lib/auth/presentation/entitlement-presentation';
import type { AuthIntent } from '../../lib/auth/types';

export interface EntitlementGateHandlers {
  readonly dispatch: (intent: AuthIntent) => void;
}

interface EntitlementGateProps {
  readonly projection: AuthRenderProjection;
  readonly handlers: EntitlementGateHandlers;
}

export function EntitlementGate({ projection, handlers }: EntitlementGateProps) {
  const headingRef = useRef<HTMLHeadingElement | null>(null);
  const presentation = entitlementGatePresentation(projection.entitlementStage, projection.connectivity);
  const redactedCode = safeRedactedSupportCode(projection.supportCode);

  // Deterministic focus placement on meaningful transitions (never per poll).
  useEffect(() => {
    if (presentation?.focusHeading === true) {
      headingRef.current?.focus();
    }
  }, [presentation?.key, presentation?.focusHeading]);

  if (presentation === null) {
    // Ready (or unknown projection) — protected workspace mounts elsewhere.
    return null;
  }

  const showRetry = presentation.controls.retry;

  return (
    <div className="entitlement-gate" aria-busy={presentation.ariaBusy} data-testid="entitlement-gate">
      <h1
        ref={headingRef}
        tabIndex={-1}
        className="entitlement-gate-heading"
        data-testid="entitlement-gate-heading"
      >
        {presentation.bodyCopy}
      </h1>
      <p className="entitlement-gate-status" role="status" aria-live="polite">
        {presentation.statusLabel}
      </p>

      {projection.safeIdentity !== null && (
        <p className="entitlement-gate-meta">
          <span className="auth-safe-alias">{projection.safeIdentity.alias}</span>
          <span className="auth-network-state" data-testid="gate-network-state">
            {projection.connectivity === 'offline'
              ? 'Offline'
              : projection.connectivity === 'paused'
                ? 'Network paused'
                : projection.connectivity === 'reconnecting'
                  ? 'Reconnecting'
                  : projection.connectivity === 'online'
                    ? 'Online'
                    : ''}
          </span>
        </p>
      )}

      {projection.entitlementStage === 'entitlementUnsupported' && redactedCode !== null && (
        <p className="entitlement-gate-meta">
          Support code {redactedCode}
        </p>
      )}

      <div className="entitlement-gate-actions">
        {showRetry && (
          <button
            type="button"
            className="button-primary"
            onClick={() => handlers.dispatch({ type: 'INTENT.ENTITLEMENT_RETRY' })}
          >
            Retry
          </button>
        )}
        <button
          type="button"
          className="button-secondary"
          onClick={() => handlers.dispatch({ type: 'INTENT.LOCK' })}
        >
          Lock
        </button>
      </div>
    </div>
  );
}
