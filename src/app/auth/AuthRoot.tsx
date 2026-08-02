'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { AuthAdapter, useAuthProjection, synchronouslyPermitsProtectedContent } from '../../lib/auth/react/adapter';
import { createProductionComposition, createDevelopmentComposition } from '../../lib/auth/composition';
import { emitTelemetry } from '../../lib/auth/telemetry';
import type { AllowlistedTelemetryEvent } from '../../lib/auth/ports';
import type { AuthIntent, CapabilityId } from '../../lib/auth/types';
import type { AuthMachineInput } from '../../lib/auth/state/machine';
import { AuthGate } from './AuthGate';

/** Explicit production switch: dev/test actors are impossible to select here. */
const ALLOW_DEVELOPMENT_ACTORS = process.env.NODE_ENV !== 'production';

/** Telemetry preference: only an already-recorded explicit opt-in enables emission. */
const TELEMETRY_PREFERENCE = { explicitOptIn: false };

/** Render projection → coarse telemetry stage. */
function coarseStage(authState: string): AllowlistedTelemetryEvent['coarseStage'] {
  switch (authState) {
    case 'initializing':
      return 'initializing';
    case 'noLocalUser':
    case 'onboarding':
      return 'noLocalUser';
    case 'authenticated':
      return 'authenticated';
    case 'removingLocalUser':
      return 'removal';
    case 'recoverableError':
    case 'blockedError':
      return 'error';
    default:
      return 'locked';
  }
}

/** Build the one authoritative machine input for this instance. */
function buildMachineInput(): AuthMachineInput {
  if (ALLOW_DEVELOPMENT_ACTORS) {
    const composition = createDevelopmentComposition(true);
    return {
      actors: composition.actors,
      registeredCapabilities: new Set<CapabilityId>(['localUserAuthority', 'secretAuthority', 'identityVerification', 'browserCoordination']),
      safeCoordination: true,
    };
  }
  const composition = createProductionComposition([], () => null);
  return {
    actors: composition.actors,
    registeredCapabilities: new Set<CapabilityId>(),
    safeCoordination: false,
  };
}

export default function AuthRoot() {
  // Single authority per application instance, created once via lazy state init
  // (safe: no ref reads/writes during render).
  const [adapter] = useState<AuthAdapter>(() => new AuthAdapter(buildMachineInput()));
  const projection = useAuthProjection(adapter);

  // Telemetry gate: no event is emitted without explicit opt-in (currently off).
  // Emitted at most once per instance; never during render.
  const emittedRef = useRef(false);
  useEffect(() => {
    if (emittedRef.current || !TELEMETRY_PREFERENCE.explicitOptIn || projection === null) {
      return;
    }
    emittedRef.current = true;
    emitTelemetry(TELEMETRY_PREFERENCE, null, {
      platform: 'web',
      applicationVersion: '0.1.0',
      coarseStage: coarseStage(projection.authState),
      typedOutcome: projection.outcomeCode,
      coarseDurationMs: null,
    });
  }, [projection]);

  const handlers = useMemo(
    () => ({
      dispatch: (intent: AuthIntent) => adapter.send(intent),
      submitSecret: (secret: string) => adapter.submitSecret(secret),
    }),
    [adapter],
  );

  // Synchronous protected boundary: no protected content behind the gate.
  const protectedAllowed = synchronouslyPermitsProtectedContent(projection);

  if (protectedAllowed) {
    return (
      <main className="app-shell antialiased" data-testid="authenticated-shell">
        <header className="topbar">
          <span className="brand">HushVoting!</span>
          <span className="foundation-badge">Authenticated</span>
        </header>
        <section className="hero" aria-labelledby="authenticated-title">
          <h1 id="authenticated-title">You are signed in on this device.</h1>
          <p className="hero-summary">
            Election workflows arrive with downstream features. This surface proves
            the protected boundary only mounts after authentication.
          </p>
        </section>
      </main>
    );
  }

  if (projection === null) {
    return null;
  }

  return <AuthGate projection={projection} handlers={handlers} />;
}
