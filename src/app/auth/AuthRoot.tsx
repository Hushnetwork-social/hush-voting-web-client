'use client';

import Image from 'next/image';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AuthAdapter, useAuthProjection, synchronouslyPermitsProtectedContent } from '../../lib/auth/react/adapter';
import { createProductionComposition } from '../../lib/auth/composition';
import { registerCapability } from '../../lib/auth/registry';
import { VAULT_CAPABILITY_SLOTS } from '../../lib/vault-core/integration';
import { emitTelemetry } from '../../lib/auth/telemetry';
import type { AllowlistedTelemetryEvent } from '../../lib/auth/ports';
import type { AuthIntent, CapabilityId } from '../../lib/auth/types';
import type { AuthMachineInput } from '../../lib/auth/state/machine';
import { AuthGate } from './AuthGate';

/** Telemetry preference: only an already-recorded explicit opt-in enables emission. */
const TELEMETRY_PREFERENCE = { explicitOptIn: false };

const FIRST_RUN_INTENTS = new Set<AuthIntent['type']>([
  'INTENT.CREATE_USER',
  'INTENT.RESTORE_CREDENTIAL_FILE',
  'INTENT.RESTORE_RECOVERY_WORDS',
]);

function createOpaqueHistoryToken(depth: number): string {
  const bytes = new Uint8Array(8);
  crypto.getRandomValues(bytes);
  const randomPart = Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('').slice(0, 10);
  return `nav-${randomPart}-${depth}`;
}

function historyToken(state: unknown): string | null {
  if (state === null || typeof state !== 'object') {
    return null;
  }
  const token = (state as { hvToken?: unknown }).hvToken;
  return typeof token === 'string' && /^nav-[a-z0-9]+-\d+$/.test(token) ? token : null;
}

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
async function buildMachineInput(): Promise<AuthMachineInput> {
  if (process.env.NODE_ENV !== 'production') {
    // Dev-only synthetic actors live behind a dynamic import so production
    // bundlers prune the module (verified by the Phase 7 bundle scan).
    const dev = await import('../../lib/auth/testing/composition.dev');
    const composition = dev.createDevelopmentComposition(true);
    return {
      actors: composition.actors,
      registeredCapabilities: new Set<CapabilityId>(['localUserAuthority', 'secretAuthority', 'identityVerification', 'browserCoordination']),
      safeCoordination: true,
    };
  }
  // Vault core slots (FEAT-003) are declared explicitly; while no production storage
  // adapter (FEAT-004/005/006) is registered they stay `unavailable`, so the
  // composition fails closed with explicit diagnostics — never a reference actor.
  const vaultRegistrations = VAULT_CAPABILITY_SLOTS.map((slot) => registerCapability(slot.capability, slot.availability));
  const composition = createProductionComposition(vaultRegistrations, () => null);
  return {
    actors: composition.actors,
    registeredCapabilities: new Set<CapabilityId>(),
    safeCoordination: false,
  };
}

export default function AuthRoot() {
  // Single authority per application instance. Re-entering the authentication
  // history entry rebuilds the authority so it re-detects the correct entry
  // state without persisting authentication state in browser history.
  const [adapter, setAdapter] = useState<AuthAdapter | null>(null);
  const [authorityGeneration, setAuthorityGeneration] = useState(0);
  const entryHistoryTokenRef = useRef<string | null>(null);
  const flowHistoryTokensRef = useRef(new Set<string>());

  const rebuildAuthority = useCallback(() => {
    setAdapter((current) => {
      current?.stop();
      return null;
    });
    setAuthorityGeneration((current) => current + 1);
  }, []);

  useEffect(() => {
    let cancelled = false;
    let createdAdapter: AuthAdapter | null = null;
    void buildMachineInput().then((input) => {
      if (!cancelled) {
        createdAdapter = new AuthAdapter(input);
        setAdapter(createdAdapter);
      }
    });
    return () => {
      cancelled = true;
      createdAdapter?.stop();
    };
  }, [authorityGeneration]);

  useEffect(() => {
    const entryToken = entryHistoryTokenRef.current ?? createOpaqueHistoryToken(1);
    entryHistoryTokenRef.current = entryToken;
    window.history.replaceState({ hvToken: entryToken }, '', '/');

    const handlePopState = (event: PopStateEvent) => {
      if (historyToken(event.state) === entryHistoryTokenRef.current) {
        rebuildAuthority();
      }
    };

    window.addEventListener('popstate', handlePopState);
    return () => window.removeEventListener('popstate', handlePopState);
  }, [rebuildAuthority]);

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
      dispatch: (intent: AuthIntent) => {
        if (FIRST_RUN_INTENTS.has(intent.type)) {
          const flowToken = createOpaqueHistoryToken(2);
          flowHistoryTokensRef.current.add(flowToken);
          window.history.pushState({ hvToken: flowToken }, '', '/');
        } else if (
          intent.type === 'INTENT.BACK_FROM_ONBOARDING' &&
          flowHistoryTokensRef.current.has(historyToken(window.history.state) ?? '')
        ) {
          window.history.back();
          return;
        }
        adapter?.send(intent);
      },
      submitSecret: (secret: string) => adapter?.submitSecret(secret),
    }),
    [adapter],
  );

  // Synchronous protected boundary: no protected content behind the gate.
  const protectedAllowed = synchronouslyPermitsProtectedContent(projection);

  if (protectedAllowed) {
    return (
      <main className="app-shell antialiased" data-testid="authenticated-shell">
        <header className="topbar">
          <span className="brand">
            <span className="brand-mark" aria-hidden="true">
              <Image
                src="/assets/hushvoting-logo.png"
                alt=""
                width={48}
                height={48}
                priority
                data-testid="hushvoting-logo"
              />
            </span>
            <span>HushVoting!</span>
          </span>
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
