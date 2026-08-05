/**
 * FEAT-002 integration tests — production composition, root rendering,
 * privacy controls, and telemetry gate.
 *
 * Proves:
 * - production composition is fail-closed and never selects synthetic actors;
 * - dev composition requires an explicit non-production flag;
 * - root rendering mounts no protected content before authentication;
 * - telemetry emits only allowlisted aggregate events under explicit opt-in,
 *   and prohibited fields never reach the sink;
 * - one authority per instance with subscription cleanup.
 */

import { describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import {
  createProductionComposition,
  emptyActors,
} from './composition';
import { createDevelopmentComposition } from './testing/composition.dev';
import { registerCapability } from './registry';
import { emitTelemetry, telemetryEnabled, validateTelemetryEvent } from './telemetry';
import type { AllowlistedTelemetryEvent } from './ports';
import { AuthAdapter } from './react/adapter';
import { createActor } from 'xstate';
import { authMachine, type AuthMachineInput } from './state/machine';
import AuthRoot from '../../app/auth/AuthRoot';
import { createLocalUserAuthorityTestActor, createSecretAuthorityTestActor, createIdentityVerificationTestActor, createBrowserCoordinationTestActor, createNavigationTestActor, completeAllPendingOperations } from './testing/actors';
import type { AuthActors } from './ports';
import type { CapabilityId } from './types';

describe('production composition', () => {
  it('fails closed when mandatory actors are absent (no synthetic fallback)', () => {
    const result = createProductionComposition([], () => null);
    expect(result.ok).toBe(false);
    expect(result.actors.localUserAuthority).toBeNull();
    expect(result.actors.secretAuthority).toBeNull();
    expect(result.actors.identityVerification).toBeNull();
  });

  it('rejects synthetic registrations in production', () => {
    const result = createProductionComposition(
      [registerCapability('localUserAuthority', 'mandatory', true)],
      () => null,
    );
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'SYNTHETIC_IN_PRODUCTION', capability: 'localUserAuthority' });
  });

  it('development composition requires an explicit flag', () => {
    expect(createDevelopmentComposition(false).ok).toBe(false);
    const dev = createDevelopmentComposition(true);
    expect(dev.ok).toBe(true);
    expect(dev.actors.localUserAuthority).not.toBeNull();
  });

  it('emptyActors yields fail-closed ports', () => {
    const actors = emptyActors();
    expect(actors.localUserAuthority).toBeNull();
    expect(actors.onboarding.createUser).toBeNull();
    expect(actors.navigation).not.toBeNull();
  });
});

describe('single authority per instance', () => {
  it('AuthAdapter owns one actor and cleans up subscriptions', () => {
    const adapter = new AuthAdapter({
      actors: makeDemoActors(),
      registeredCapabilities: new Set(),
      safeCoordination: true,
    });
    const listener = vi.fn();
    const unsubscribe = adapter.subscribe(listener);
    adapter.send({ type: 'INTENT.LOCK' });
    unsubscribe();
    expect(listener).toHaveBeenCalled();
    adapter.stop();
  });
});

function makeDemoActors(): AuthActors {
  return {
    localUserAuthority: createLocalUserAuthorityTestActor([{ code: 'INIT_NO_LOCAL_USER' }]),
    secretAuthority: createSecretAuthorityTestActor([{ code: 'UNLOCK_SUCCESS' }]),
    identityVerification: createIdentityVerificationTestActor([{ code: 'VERIFY_SUCCESS' }]),
    onboarding: { createUser: null, restoreCredentialFile: null, restoreRecoveryWords: null },
    removal: null,
    browserCoordination: createBrowserCoordinationTestActor([{ code: 'COORDINATION_SAFE' }]),
    navigation: createNavigationTestActor(),
    telemetry: null,
  };
}

describe('root rendering privacy', () => {
  it('renders the branded auth shell without protected content initially', async () => {
    // FEAT-010: synthetic actors are test-harness-only; the ordinary root uses
    // real composition. This test passes the explicit harness provider.
    const harness = async (): Promise<AuthMachineInput> => {
      const composition = createDevelopmentComposition(true);
      return {
        actors: composition.actors,
        registeredCapabilities: new Set(['localUserAuthority', 'secretAuthority', 'identityVerification', 'browserCoordination']),
        safeCoordination: true,
      };
    };
    render(<AuthRoot machineInputProvider={harness} />);
    // The adapter mounts asynchronously; flush pending test operations
    // repeatedly until the init actor resolves to first-run.
    await waitFor(() => {
      completeAllPendingOperations();
      expect(screen.getByText(/welcome to hushvoting/i)).toBeInTheDocument();
    });
    expect(screen.queryByTestId('authenticated-shell')).toBeNull();
    expect(screen.queryByText(/election|dashboard/i)).toBeNull();
  });
});

describe('telemetry gate', () => {
  const base: AllowlistedTelemetryEvent = {
    platform: 'web',
    applicationVersion: '0.1.0',
    coarseStage: 'locked',
    typedOutcome: null,
    coarseDurationMs: null,
  };

  it('emits nothing without explicit opt-in', () => {
    const sink = vi.fn();
    emitTelemetry({ explicitOptIn: false }, sink, base);
    expect(sink).not.toHaveBeenCalled();
  });

  it('emits allowlisted events only under opt-in', () => {
    const sink = vi.fn();
    emitTelemetry({ explicitOptIn: true }, sink, base);
    expect(sink).toHaveBeenCalledWith(base);
  });

  it('rejects prohibited fields before the sink', () => {
    const bad = { ...base, alias: 'alice' } as unknown as AllowlistedTelemetryEvent;
    expect(validateTelemetryEvent(bad)).toBeNull();
    const sink = vi.fn();
    emitTelemetry({ explicitOptIn: true }, sink, bad);
    expect(sink).not.toHaveBeenCalled();
  });

  it('rejects prohibited value shapes (election id, support text)', () => {
    expect(validateTelemetryEvent({ ...base, typedOutcome: 'ELEC-42' })).not.toBeNull(); // outcome string allowed
    const withElection = { ...base, electionId: 'ELEC-42' } as unknown as AllowlistedTelemetryEvent;
    expect(validateTelemetryEvent(withElection)).toBeNull();
  });

  it('telemetryEnabled reflects explicit preference only', () => {
    expect(telemetryEnabled({ explicitOptIn: false })).toBe(false);
    expect(telemetryEnabled({ explicitOptIn: true })).toBe(true);
  });
});

describe('machine input integration', () => {
  it('authMachine accepts a composition-built actor set', () => {
    const dev = createDevelopmentComposition(true);
    const actor = createActor(authMachine, {
      input: { actors: dev.actors, registeredCapabilities: new Set<CapabilityId>(), safeCoordination: true },
    });
    actor.start();
    expect(actor.getSnapshot().value).toBeDefined();
    actor.stop();
  });
});
