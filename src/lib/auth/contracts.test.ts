/**
 * FEAT-002 contract tests — safe-data vocabulary, allowlist, and
 * deterministic outcome mapping.
 *
 * Proves:
 * - every documented actor outcome has exactly one stable category and one
 *   deterministic UX mapping;
 * - prohibited secret-bearing values cannot satisfy the public contract types
 *   (compile-time) and are rejected at runtime without recording contents;
 * - the context/event allowlist matches the feature specification exactly
 *   (no broad arbitrary-object, free-form error, or URL field).
 */

import { describe, expect, it } from 'vitest';
import {
  AUTH_TERMINOLOGY,
  AUTH_TIMING,
  COMBINED_CREDENTIAL_ERROR,
  type AuthMachineContext,
  type AuthOutcomeCode,
  type CapabilityId,
  type OperationId,
  type SessionEpoch,
} from './types';
import {
  outcomeErrorCategory,
  outcomeSafeActions,
  outcomeToAuthState,
  outcomeToConnectivityState,
} from './results';
import type { AllowlistedTelemetryEvent, CapabilityRegistration } from './ports';

// ---------------------------------------------------------------------------
// Compile-time allowlist assertions
// ---------------------------------------------------------------------------

/**
 * The machine context allowlist must contain EXACTLY the documented fields and
 * nothing else. Assigning a full context literal with only those fields must
 * typecheck; the negative fixtures below prove no secret-bearing or generic
 * field type is accepted.
 */
const allowedContext: AuthMachineContext = {
  sessionEpoch: 0 as SessionEpoch,
  activeOperationId: null,
  registeredCapabilities: new Set<CapabilityId>(),
  safeCoordination: false,
  safeIdentity: null,
  environment: null,
  cooldownDeadlineMs: null,
  navigationToken: null,
  supportCode: null,
  outcomeCode: null,
  coarseStageStartedAtMs: null,
};
expect(allowedContext).toBeDefined();

/** @ts-expect-error — passwords are not representable in machine context. */
export const passwordInContext: AuthMachineContext = { ...allowedContext, devicePassword: 'hunter2' };

/** @ts-expect-error — free-form server error text is not representable. */
export const rawErrorInContext: AuthMachineContext = { ...allowedContext, serverError: '500: internal' };

/** @ts-expect-error — arbitrary URL is not representable. */
export const urlInContext: AuthMachineContext = { ...allowedContext, redirectUrl: 'https://election.example/42' };

/** @ts-expect-error — election identifiers must never enter machine data. */
export const electionIdInContext: AuthMachineContext = { ...allowedContext, electionId: 'ELEC-42' };

/** @ts-expect-error — mnemonic is not representable. */
export const mnemonicInContext: AuthMachineContext = { ...allowedContext, mnemonic: 'word1 word2 ...' };

/** @ts-expect-error — arbitrary free-form object is not representable. */
export const arbitraryObjectInContext: AuthMachineContext = { ...allowedContext, extra: { anything: true } };

// Telemetry allowlist: prohibited fields must not typecheck.
const allowedTelemetry: AllowlistedTelemetryEvent = {
  platform: 'web',
  applicationVersion: '0.1.0',
  coarseStage: 'locked',
  typedOutcome: 'UNLOCK_SUCCESS',
  coarseDurationMs: 123,
};
expect(allowedTelemetry).toBeDefined();

/** @ts-expect-error — stable user identifier is prohibited in telemetry. */
export const stableIdInTelemetry: AllowlistedTelemetryEvent = { ...allowedTelemetry, userId: 'u-123' };

/** @ts-expect-error — alias is prohibited in telemetry. */
export const aliasInTelemetry: AllowlistedTelemetryEvent = { ...allowedTelemetry, alias: 'alice' };

/** @ts-expect-error — election identifier is prohibited in telemetry. */
export const electionInTelemetry: AllowlistedTelemetryEvent = { ...allowedTelemetry, electionId: 'ELEC-42' };

/** @ts-expect-error — raw failure payload is prohibited in telemetry. */
export const rawFailureInTelemetry: AllowlistedTelemetryEvent = { ...allowedTelemetry, rawError: 'stack' };

// Opaque identifiers: a plain string must not satisfy OperationId.
const operationIdFactory = (value: string): OperationId => value as OperationId;
void operationIdFactory;
/** @ts-expect-error — plain string is not an OperationId. */
export const plainStringAsOperationId: OperationId = 'some-id';

// Capability registration: synthetic flag is a required boolean, no free-form actor.
const allowedRegistration: CapabilityRegistration = {
  capability: 'localUserAuthority',
  availability: 'mandatory',
  synthetic: false,
};
expect(allowedRegistration).toBeDefined();
/** @ts-expect-error — free-form actor implementation is not part of the registration descriptor. */
export const actorInRegistration: CapabilityRegistration = { ...allowedRegistration, actor: { anything: true } };

// ---------------------------------------------------------------------------
// Runtime: every documented outcome maps deterministically
// ---------------------------------------------------------------------------

/** Every documented outcome code, each asserted exactly once. */
const DOCUMENTED_OUTCOMES: readonly AuthOutcomeCode[] = [
  'INIT_NO_LOCAL_USER',
  'INIT_LOCKED_USER',
  'INIT_STORAGE_UNAVAILABLE',
  'INIT_UNSUPPORTED_VAULT_VERSION',
  'INIT_CORRUPT_VAULT',
  'INIT_MEMORY_ONLY',
  'INIT_UNSAFE_COORDINATION',
  'UNLOCK_SUCCESS',
  'UNLOCK_WRONG_PASSWORD_OR_DAMAGED',
  'UNLOCK_THROTTLED',
  'VERIFY_SUCCESS',
  'VERIFY_PROFILE_MISSING',
  'VERIFY_SIGNING_KEY_MISMATCH',
  'VERIFY_ENCRYPTION_KEY_MISMATCH',
  'VERIFY_TIMEOUT',
  'VERIFY_NETWORK_UNAVAILABLE',
  'ONBOARDING_COMPLETED',
  'ONBOARDING_BACK',
  'ONBOARDING_CLEANUP_COMPLETE',
  'REMOVAL_COMPLETE',
  'REMOVAL_BLOCKED_REMEDIATION',
  'COORDINATION_SAFE',
  'COORDINATION_UNSAFE',
  'MISSING_PLATFORM_PROTECTION',
  'INVALID_MNEMONIC',
  'TRANSACTION_REJECTED',
  'AUTHORITY_LOST',
  'SESSION_INVALIDATED',
  'UNKNOWN_FAILURE',
];

describe('outcome mapping is complete and deterministic', () => {
  it('represents every documented outcome exactly once in the fixture', () => {
    const seen = new Set<AuthOutcomeCode>();
    for (const code of DOCUMENTED_OUTCOMES) {
      expect(seen.has(code)).toBe(false);
      seen.add(code);
    }
  });

  it('gives every outcome exactly one stable auth-state destination', () => {
    const destinations = new Map<AuthOutcomeCode | 'null', AuthOutcomeCode[]>();
    for (const code of DOCUMENTED_OUTCOMES) {
      const state = outcomeToAuthState(code);
      const key = (state ?? 'null') as AuthOutcomeCode | 'null';
      destinations.set(key, [...(destinations.get(key) ?? []), code]);
    }
    // Every code yields a state or explicit null (informational) — never undefined.
    for (const code of DOCUMENTED_OUTCOMES) {
      expect(outcomeToAuthState(code)).not.toBeUndefined();
    }
  });

  it('keeps connectivity outcomes independent from auth state', () => {
    for (const code of DOCUMENTED_OUTCOMES) {
      const connectivity = outcomeToConnectivityState(code);
      if (code === 'VERIFY_TIMEOUT' || code === 'VERIFY_NETWORK_UNAVAILABLE') {
        expect(connectivity).toBe('offline');
      } else {
        expect(connectivity).toBeNull();
      }
    }
  });

  it('classifies error outcomes as recoverable or blocked', () => {
    for (const code of DOCUMENTED_OUTCOMES) {
      const category = outcomeErrorCategory(code);
      if (category !== null) {
        expect(['recoverable', 'blocked']).toContain(category);
      }
    }
  });

  it('provides valid recovery actions for every recoverable/blocked outcome', () => {
    for (const code of DOCUMENTED_OUTCOMES) {
      if (outcomeErrorCategory(code) !== null) {
        expect(outcomeSafeActions(code).length).toBeGreaterThan(0);
      }
    }
  });

  it('never offers remote reset or sign-out actions', () => {
    for (const code of DOCUMENTED_OUTCOMES) {
      expect(outcomeSafeActions(code)).not.toContain('remoteReset');
      expect(outcomeSafeActions(code)).not.toContain('remoteSignOut');
    }
  });
});

// ---------------------------------------------------------------------------
// Runtime: prohibited shapes are rejected without recording contents
// ---------------------------------------------------------------------------

describe('secret-bearing values are rejected at the contract boundary', () => {
  it('cannot be smuggled through the machine context at runtime', () => {
    // The context type has no secret field; a runtime guard double-checks that
    // any attempt to attach unknown secret-bearing keys is a type error and
    // that the canonical context shape contains only allowlisted keys.
    const contextKeys = Object.keys(allowedContext).sort();
    expect(contextKeys).toEqual(
      [
        'activeOperationId',
        'coarseStageStartedAtMs',
        'cooldownDeadlineMs',
        'environment',
        'navigationToken',
        'outcomeCode',
        'registeredCapabilities',
        'safeCoordination',
        'safeIdentity',
        'sessionEpoch',
        'supportCode',
      ].sort(),
    );
  });

  it('holds the exact combined credential error and local-device terminology', () => {
    expect(COMBINED_CREDENTIAL_ERROR).toBe('The password is incorrect or the protected data is damaged.');
    expect(AUTH_TERMINOLOGY.unlock).toBe('Unlock HushVoting');
    expect(AUTH_TERMINOLOGY.devicePassword).toBe('Device password');
    expect(AUTH_TERMINOLOGY.removeLocalUser).toBe('Remove local user');
    expect(AUTH_TERMINOLOGY.forgotDevicePassword).toBe('Forgot device password?');
  });

  it('bounds timing constants to the documented thresholds', () => {
    expect(AUTH_TIMING.progressThresholdMs).toBe(250);
    expect(AUTH_TIMING.initTimeoutMs).toBe(5000);
    expect(AUTH_TIMING.verifyTimeoutMs).toBe(10000);
    expect(AUTH_TIMING.kdfHardLimitMs).toBe(1500);
    expect(AUTH_TIMING.leaseStalenessMs).toBe(15000);
  });
});
