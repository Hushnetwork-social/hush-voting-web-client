'use client';

import Image from 'next/image';
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { AuthAdapter, useAuthProjection, synchronouslyPermitsProtectedContent } from '../../lib/auth/react/adapter';
import { buildEmptyActors } from '../../lib/auth/composition';
import { emitTelemetry } from '../../lib/auth/telemetry';
import type { AllowlistedTelemetryEvent } from '../../lib/auth/ports';
import type { AuthIntent, CapabilityId } from '../../lib/auth/types';
import type { AuthMachineInput } from '../../lib/auth/state/machine';
import type { TrustedTargetDescriptor } from '../../lib/runtime/target';
import type { TargetAwareActorRegistration, TargetClass } from '../../lib/auth/composition-target';
import { AuthGate } from './AuthGate';

/** Telemetry preference: only an already-recorded explicit opt-in enables emission. */
const TELEMETRY_PREFERENCE = { explicitOptIn: false };

/** Module-level secret sink (set by buildMachineInput; read by the adapter). */
let activeSecretSink: ((operationId: string, secret: string) => void) | null = null;

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

/**
 * Build the one authoritative machine input for this instance.
 *
 * FEAT-010: ordinary development and production share ONE real target-aware
 * composition. Synthetic actors are reachable ONLY through the separately
 * named test-harness command (`HUSH_TEST_HARNESS=1` in non-production); the
 * harness branch is statically eliminated from production bundles (NODE_ENV
 * guard), verified by the CI exclusion gate (AC-010-001/002).
 * With no deployment manifest configured, composition fails closed with
 * explicit diagnostics — never a null-provider actor graph.
 */
async function buildMachineInput(): Promise<AuthMachineInput> {
  if (process.env.NODE_ENV !== 'production' && process.env.NEXT_PUBLIC_HUSH_TEST_HARNESS === '1') {
    // Build-isolated synthetic harness (tests only; reached ONLY through the
    // separately named `npm run dev:harness` command; statically pruned from
    // production and ordinary-development bundles — verified by the CI
    // exclusion gate, AC-010-002).
    const dev = await import('../../lib/auth/testing/composition.dev');
    const composition = dev.createDevelopmentComposition(true);
    return {
      actors: composition.actors,
      registeredCapabilities: new Set<CapabilityId>(['localUserAuthority', 'secretAuthority', 'identityVerification', 'browserCoordination']),
      safeCoordination: true,
    };
  }

  const { resolveManifest } = await import('../../lib/runtime/manifests');
  const { readNativeTargetDescriptor } = await import('../../lib/runtime/native-bridge');
  const { createTargetComposition } = await import('../../lib/auth/composition-target-builder');

  const configurationId = process.env.HUSH_DEPLOYMENT_CONFIGURATION ?? 'isolated-local-devnet-v1';
  const resolution = resolveManifest(configurationId);
  if (!resolution.ok) {
    // Fail closed: no approved environment → blocked composition, never null
    // providers and never a fabricated environment.
    return blockedMachineInput();
  }
  const manifest = resolution.manifest;

  // Trusted target handshake: absent bridge → Browser; native descriptor is
  // validated by the composition builder; a failed native handshake never
  // falls back to Browser (AC-010-006).
  const handshakeOutcome = await readNativeTargetDescriptor();
  if (handshakeOutcome.kind === 'failed') {
    return blockedMachineInput();
  }
  const handshake = handshakeOutcome.kind === 'descriptor' ? handshakeOutcome.descriptor : null;

  // Real registrations: browser vault slots are real FEAT-004 actors; native
  // targets declare their qualified capability classes (FEAT-005/006).
  const registrations = buildRealRegistrations(handshake);

  // Web target: assemble the real actor graph over the sealed vault client
  // (Task 7.3). Native targets keep honest fail-closed providers until their
  // bridge adapters register (partial-registration contract, AC-010-004).
  let webComposition: { readonly actors: import('../../lib/auth/ports').AuthActors } | null = null;
  if (handshake === null) {
    try {
      const webModule = await import('../../lib/auth/web/web-composition');
      webComposition = webModule.getWebComposition(manifest);
      activeSecretSink = webModule.submitWebSecret;
    } catch {
      webComposition = null;
    }
  }

  const verdict = createTargetComposition({
    manifest,
    handshake,
    pinnedContractVersion: manifest.contractVersions.adapter,
    extension: { kind: 'absent' },
    registrations,
    actorProvider: (capability) => {
      if (webComposition === null) {
        return null;
      }
      const actors = webComposition.actors;
      switch (capability) {
        case 'onboardingCreateUser':
          return actors.onboarding.createUser;
        case 'onboardingRestoreCredentialFile':
          return actors.onboarding.restoreCredentialFile;
        case 'onboardingRestoreRecoveryWords':
          return actors.onboarding.restoreRecoveryWords;
        default:
          return (actors as unknown as Record<string, unknown>)[capability] ?? null;
      }
    },
  });
  if (!verdict.ok) {
    return blockedMachineInput();
  }
  return {
    actors: verdict.actors,
    registeredCapabilities: new Set<CapabilityId>(registrations.map((r) => r.capability as CapabilityId)),
    safeCoordination: true,
  };
}

/** Fail-closed machine input (no null providers, no fabricated environment). */
function blockedMachineInput(): AuthMachineInput {
  return {
    actors: buildEmptyActors(),
    registeredCapabilities: new Set<CapabilityId>(),
    safeCoordination: false,
  };
}

/** Real target-aware registrations (web: FEAT-004 browser vault; native: platform classes). */
function buildRealRegistrations(handshake: TrustedTargetDescriptor | null): TargetAwareActorRegistration[] {
  const target: TargetClass = handshake === null ? 'web' : handshake.platform;
  const targets: readonly TargetClass[] = [target];
  const version = '1.0.0';
  const mandatory: CapabilityId[] = ['localUserAuthority', 'secretAuthority', 'identityVerification', 'browserCoordination', 'removal'];
  const optional: CapabilityId[] = ['onboardingCreateUser', 'onboardingRestoreCredentialFile', 'onboardingRestoreRecoveryWords'];
  return [
    ...mandatory.map((capability) => ({ capability, targetClasses: targets, contractVersion: version, provider: 'real' as const, synthetic: false })),
    ...optional.map((capability) => ({ capability, targetClasses: targets, contractVersion: version, provider: 'real' as const, synthetic: false })),
  ];
}

export interface AuthRootProps {
  /**
   * Optional machine-input provider (harness/testing entry). Defaults to the
   * real target-aware composition; the harness provider exists ONLY in the
   * separately named test-harness command and test fixtures.
   */
  readonly machineInputProvider?: () => Promise<AuthMachineInput>;
}

export default function AuthRoot({ machineInputProvider }: AuthRootProps = {}) {
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
    void (machineInputProvider ?? buildMachineInput)().then((input) => {
      if (!cancelled) {
        createdAdapter = new AuthAdapter(input, { secretSink: activeSecretSink ?? undefined });
        setAdapter(createdAdapter);
      }
    });
    return () => {
      cancelled = true;
      createdAdapter?.stop();
    };
  }, [authorityGeneration, machineInputProvider]);

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
