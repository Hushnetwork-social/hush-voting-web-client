/**
 * FEAT-003 vault-core contracts tests — typed results, operations, bundle, capabilities.
 *
 * Covers Task 2.3/2.4: closed discriminated result union (18 v1 codes), operation
 * registry authorization, opaque credential bundle admission, and capability vocabulary.
 */
import { describe, expect, it } from 'vitest';
import {
  VAULT_RESULT_CODES,
  VAULT_RESULT_REGISTRY,
  assertRegistryExhaustive,
  failure,
  success,
} from './results';
import {
  authorizeOperation,
  OPERATION_KINDS,
  OPERATION_VERSION,
  type OperationRequest,
} from './operations';
import { admitCredentialBundle } from './bundle';
import type { BundleAdmissionEvidence, ValidatedCredentialBundle } from './ports';
import {
  CAPABILITY_PHASES,
  ELEVATION_PURPOSES,
  FRESH_PASSWORD_MAX_AGE_MS,
  IDLE_LOCK_CHOICES_MINUTES,
  BACKGROUND_LOCK_CHOICES,
  type CapabilityPhase,
} from './capabilities';
import { THROTTLE_SCHEDULE, cooldownSecondsForAttempt } from './sidecar';

const PHASE_ORDER: readonly CapabilityPhase[] = ['Locked', 'VerificationOnly', 'Authenticated', 'FreshPasswordVerified', 'Invalidated'];

describe('closed typed result union (v1)', () => {
  it('is exhaustive: every code has exactly one registry entry', () => {
    expect(() => assertRegistryExhaustive()).not.toThrow();
    expect(VAULT_RESULT_CODES).toHaveLength(18);
  });

  it('does NOT emit NetworkMismatch in v1 (Deep-Dive override)', () => {
    expect(VAULT_RESULT_CODES).not.toContain('NetworkMismatch');
  });

  it('produces safe typed failures with bounded fields only', () => {
    const f = failure('Throttled', { retryDeadlineMs: 1234, supportCode: 'A1B2C3' });
    expect(f).toMatchObject({ ok: false, code: 'Throttled', retryable: true, allowedActions: ['retry'] });
    expect(f.retryDeadlineMs).toBe(1234);
    expect(f.supportCode).toBe('A1B2C3');
    expect(Object.keys(f).sort()).toEqual(['allowedActions', 'code', 'ok', 'retryDeadlineMs', 'retryable', 'supportCode']);
  });

  it('never carries secrets, paths, or platform exceptions in the shape', () => {
    for (const code of VAULT_RESULT_CODES) {
      const f = failure(code);
      expect(f).not.toHaveProperty('exception');
      expect(f).not.toHaveProperty('path');
      expect(f).not.toHaveProperty('keyAlias');
      expect(f).not.toHaveProperty('ciphertext');
      expect(f).not.toHaveProperty('message');
    }
  });

  it('registers safe allowed actions for every code', () => {
    for (const code of VAULT_RESULT_CODES) {
      expect(VAULT_RESULT_REGISTRY[code].code).toBe(code);
      expect(Array.isArray(VAULT_RESULT_REGISTRY[code].allowedActions)).toBe(true);
    }
  });

  it('constructs successes with a closed shape', () => {
    expect(success({ activeGeneration: 1 })).toEqual({ ok: true, value: { activeGeneration: 1 } });
  });
});

describe('closed operation registry', () => {
  const baseRequest: OperationRequest = {
    kind: 'verify-online',
    version: 1,
    signatory: { signingAddress: '0123456789abcdef', producerId: 'hush-voting-ts', producerVersion: '1.0.0' },
    payloadDescriptor: { kind: 'identity-verification', canonicalBytesLength: 128, sha256: 'a'.repeat(64) },
    userConfirmationContext: { alias: 'Alice', signingAddressPrefix: '01234567', signingAddressSuffix: '89abcd' },
  };

  it('authorizes known operations at the required phase', () => {
    expect(authorizeOperation(baseRequest, 'VerificationOnly', { phaseOrder: PHASE_ORDER })).toEqual({ ok: true });
    const create: OperationRequest = { ...baseRequest, kind: 'create-full-identity' };
    const insufficient = authorizeOperation(create, 'VerificationOnly', { phaseOrder: PHASE_ORDER });
    expect(insufficient.ok).toBe(false);
    if (!insufficient.ok) expect(insufficient.code).toBe('INSUFFICIENT_PHASE');
    expect(authorizeOperation(create, 'Authenticated', { phaseOrder: PHASE_ORDER })).toEqual({ ok: true });
  });

  it('fails closed for unknown operations, wrong versions, bad signatories, bad payloads', () => {
    expect(authorizeOperation({ ...baseRequest, kind: 'vote' as never }, 'Authenticated', { phaseOrder: PHASE_ORDER })).toEqual({ ok: false, code: 'UNKNOWN_OPERATION' });
    expect(authorizeOperation({ ...baseRequest, version: 99 }, 'Authenticated', { phaseOrder: PHASE_ORDER })).toEqual({ ok: false, code: 'WRONG_VERSION' });
    expect(authorizeOperation({ ...baseRequest, signatory: { ...baseRequest.signatory, signingAddress: 'short' } }, 'VerificationOnly', { phaseOrder: PHASE_ORDER })).toEqual({ ok: false, code: 'INVALID_SIGNATORY' });
    expect(authorizeOperation({ ...baseRequest, payloadDescriptor: { ...baseRequest.payloadDescriptor, sha256: 'zz' } }, 'VerificationOnly', { phaseOrder: PHASE_ORDER })).toEqual({ ok: false, code: 'INVALID_PAYLOAD' });
  });

  it('keeps the registry closed and versioned', () => {
    expect(OPERATION_KINDS).toEqual(['verify-online', 'create-full-identity']);
    expect(OPERATION_VERSION).toEqual({ 'verify-online': 1, 'create-full-identity': 1 });
  });
});

describe('opaque credential bundle admission', () => {
  const bundle = {
    __bundle: Symbol('bundle') as unknown as ValidatedCredentialBundle['__bundle'],
    producerId: 'hush-voting-ts',
    producerVersion: '1.0.0',
    featiContractVersion: '1.0.0' as const,
  } satisfies ValidatedCredentialBundle;
  const evidence: BundleAdmissionEvidence = {
    producerId: 'hush-voting-ts',
    producerVersion: '1.0.0',
    exactKeyConsistency: true,
    mnemonicConsistency: 'verified',
    signingAddressPrefix: '01234567',
    signingAddressSuffix: '89abcd',
    lifecycleStatus: 'PendingRegistration',
  };

  it('admits a fully consistent bundle', () => {
    expect(admitCredentialBundle(bundle, evidence)).toEqual({ ok: true, evidence });
  });

  it('rejects producer/version, key-consistency, and contract mismatches atomically', () => {
    expect(admitCredentialBundle(bundle, { ...evidence, producerId: 'other' }).ok).toBe(false);
    expect(admitCredentialBundle(bundle, { ...evidence, exactKeyConsistency: false }).ok).toBe(false);
    expect(
      admitCredentialBundle({ ...bundle, featiContractVersion: '2.0.0' } as unknown as ValidatedCredentialBundle, evidence).ok
    ).toBe(false);
  });
});

describe('capability vocabulary and timing defaults', () => {
  it('enumerates the five capability phases and two elevation purposes', () => {
    expect(CAPABILITY_PHASES).toEqual(['Locked', 'VerificationOnly', 'Authenticated', 'FreshPasswordVerified', 'Invalidated']);
    expect(ELEVATION_PURPOSES).toEqual(['mnemonic-reveal', 'password-change']);
  });

  it('pins fresh-password elevation to 60 seconds maximum', () => {
    expect(FRESH_PASSWORD_MAX_AGE_MS).toBe(60_000);
  });

  it('pins approved idle/background lock choices', () => {
    expect(IDLE_LOCK_CHOICES_MINUTES).toEqual([1, 5, 15, 30, 60, 'restart']);
    expect(BACKGROUND_LOCK_CHOICES).toEqual(['immediate', 30, 120, 300, 900, 'restart']);
  });
});

describe('wrong-password throttling schedule', () => {
  it('applies the exact escalation after failure 4', () => {
    expect(THROTTLE_SCHEDULE.slice(0, 4)).toEqual([null, null, null, null]);
    expect(THROTTLE_SCHEDULE.slice(4)).toEqual([5, 10, 20, 40, 80, 160, 300]);
    // Attempts 1-4 pay only the Argon2id cost: no added cooldown.
    expect(cooldownSecondsForAttempt(1)).toBe(0);
    expect(cooldownSecondsForAttempt(2)).toBe(0);
    expect(cooldownSecondsForAttempt(3)).toBe(0);
    expect(cooldownSecondsForAttempt(4)).toBe(0);
    expect(cooldownSecondsForAttempt(5)).toBe(5);
    expect(cooldownSecondsForAttempt(10)).toBe(160);
    expect(cooldownSecondsForAttempt(11)).toBe(300);
    expect(cooldownSecondsForAttempt(12)).toBe(300);
    expect(cooldownSecondsForAttempt(99)).toBe(300);
    expect(cooldownSecondsForAttempt(0)).toBe(0);
  });
});
