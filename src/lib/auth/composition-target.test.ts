/**
 * FEAT-010 Task 2.6 — exhaustive child-flow handoff, type-boundary, and
 * target-aware actor-set tests.
 *
 * Covers every invalid registration class (missing/duplicate/synthetic/
 * incompatible/partial/unknown/target-contradictory), secret-free completion
 * boundaries, FEAT-011 absent/present compatibility, and exact child
 * projection coverage (normative: FeatureDescription "Typed Onboarding
 * Composition", "Production Composition Architecture"; AC-010-001…013, 046).
 */
import { describe, expect, it } from 'vitest';
import {
  CHILD_FLOW_KINDS,
  validateChildRenderProjection,
  validateVerificationOnlyCompletion,
} from './child-flow';
import {
  MANDATORY_TARGET_CAPABILITIES,
  projectForTarget,
  validateTargetAwareActorSet,
  type SettingsExtensionState,
  type TargetAwareActorRegistration,
} from './composition-target';

// ---------------------------------------------------------------------------
// Child-flow projection boundary
// ---------------------------------------------------------------------------

describe('validateChildRenderProjection', () => {
  it('accepts every closed child kind with a safe opaque view', () => {
    for (const childKind of CHILD_FLOW_KINDS) {
      const result = validateChildRenderProjection(childKind, { safe: 'view' }, ['CHILD.BACK', 'CHILD.SUBMIT']);
      expect(result.ok).toBe(true);
    }
  });

  it('rejects unknown child kinds (Setting up… is not a fallback)', () => {
    const result = validateChildRenderProjection('elections' as never, { safe: 'view' }, ['CHILD.BACK']);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'UNKNOWN_CHILD_KIND' });
  });

  it('rejects missing views', () => {
    for (const view of [null, undefined]) {
      const result = validateChildRenderProjection('createUser', view, ['CHILD.BACK']);
      expect(result.ok).toBe(false);
      expect(result.diagnostics).toContainEqual({ code: 'MISSING_VIEW' });
    }
  });

  it('rejects secret-shaped view fields', () => {
    for (const marker of ['password', 'mnemonic', 'seedPhrase', 'privateKey', 'decryptedFile', 'transaction', 'endpoint', 'nativeHandle', 'authority', 'capability']) {
      const result = validateChildRenderProjection('createUser', { [marker]: 'x' }, ['CHILD.BACK']);
      expect(result.ok).toBe(false);
      expect(result.diagnostics).toContainEqual({ code: 'FORBIDDEN_FIELD' });
    }
  });

  it('rejects unknown or missing actions', () => {
    const unknown = validateChildRenderProjection('createUser', { safe: 'view' }, ['CHILD.DELETE_USER' as never]);
    expect(unknown.ok).toBe(false);
    expect(unknown.diagnostics).toContainEqual({ code: 'FORBIDDEN_ACTION' });

    const empty = validateChildRenderProjection('createUser', { safe: 'view' }, []);
    expect(empty.ok).toBe(false);
    expect(empty.diagnostics).toContainEqual({ code: 'FORBIDDEN_ACTION' });
  });
});

describe('validateVerificationOnlyCompletion', () => {
  const validCompletion = {
    capability: 'verification-only-abc123',
    binding: { signingAddress: 'A'.repeat(44), encryptionAddress: 'B'.repeat(44) },
    outcome: 'provisioned',
  };

  it('accepts a valid verification-only completion', () => {
    const result = validateVerificationOnlyCompletion(validCompletion);
    expect(result.ok).toBe(true);
    expect(result.completion?.outcome).toBe('provisioned');
    expect(result.completion?.binding.signingAddress).toBe('A'.repeat(44));
  });

  it('rejects secret-shaped or authority-shaped completion fields', () => {
    // `capability` is deliberately excluded: its value is the sanctioned opaque
    // verification-only token (see the 'can never yield authenticated' test).
    for (const marker of ['password', 'mnemonic', 'privateKey', 'transaction', 'signedBytes', 'endpoint', 'authority', 'decryptedFile', 'seedPhrase']) {
      const poisoned = { ...validCompletion, [marker]: 'secret-material' };
      const result = validateVerificationOnlyCompletion(poisoned);
      expect(result.ok).toBe(false);
      expect(result.diagnostics).toContainEqual({ code: 'FORBIDDEN_FIELD' });
    }
  });

  it('rejects secret-shaped binding fields', () => {
    const poisoned = { ...validCompletion, binding: { ...validCompletion.binding, seed: 'abandon abandon' } };
    const result = validateVerificationOnlyCompletion(poisoned);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'FORBIDDEN_FIELD' });
  });

  it('rejects malformed bindings, missing capability, and unknown outcomes', () => {
    const badBinding = validateVerificationOnlyCompletion({ ...validCompletion, binding: { signingAddress: 'short', encryptionAddress: 'B'.repeat(44) } });
    expect(badBinding.ok).toBe(false);

    const noCapability = validateVerificationOnlyCompletion({ ...validCompletion, capability: '' });
    expect(noCapability.ok).toBe(false);

    const unknownOutcome = validateVerificationOnlyCompletion({ ...validCompletion, outcome: 'authenticated' });
    expect(unknownOutcome.ok).toBe(false);
  });

  it('rejects non-object payloads', () => {
    for (const payload of [null, undefined, 'text', 42, []]) {
      expect(validateVerificationOnlyCompletion(payload).ok).toBe(false);
    }
  });

  it('can never yield an authenticated capability (only verification-only)', () => {
    const result = validateVerificationOnlyCompletion({ ...validCompletion, capability: 'authenticated-access' });
    // The capability is opaque: even a hostile string is treated as opaque
    // verification-only data; protected access requires root fresh verification.
    expect(result.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Target-aware actor-set composition
// ---------------------------------------------------------------------------

function registration(overrides: Partial<TargetAwareActorRegistration>): TargetAwareActorRegistration {
  return {
    capability: 'localUserAuthority',
    targetClasses: ['web'],
    contractVersion: '1.0.0',
    provider: 'real',
    synthetic: false,
    ...overrides,
  };
}

function completeSet(target: 'web' | 'ubuntu' | 'android' = 'web'): TargetAwareActorRegistration[] {
  const classes: TargetAwareActorRegistration['targetClasses'] = [target];
  return MANDATORY_TARGET_CAPABILITIES.map((capability) =>
    registration({ capability, targetClasses: classes }),
  );
}

const absentExtension: SettingsExtensionState = { kind: 'absent' };

describe('validateTargetAwareActorSet', () => {
  it('accepts a complete real set for each target', () => {
    for (const target of ['web', 'ubuntu', 'android'] as const) {
      const result = validateTargetAwareActorSet(completeSet(target), target, '1.0.0', absentExtension);
      expect(result.ok).toBe(true);
    }
  });

  it('accepts a compatible registered FEAT-011 extension', () => {
    const result = validateTargetAwareActorSet(completeSet(), 'web', '1.0.0', { kind: 'registered', contractVersion: '1.0.0', compatible: true });
    expect(result.ok).toBe(true);
  });

  it('rejects an incompatible FEAT-011 extension', () => {
    const result = validateTargetAwareActorSet(completeSet(), 'web', '1.0.0', { kind: 'incompatible', contractVersion: '0.9.0' });
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'EXTENSION_INCOMPATIBLE' });
  });

  it('rejects missing mandatory capabilities', () => {
    const partial = completeSet().slice(1);
    const result = validateTargetAwareActorSet(partial, 'web', '1.0.0', absentExtension);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'MISSING_MANDATORY', capability: 'localUserAuthority' });
  });

  it('rejects duplicate registrations', () => {
    const set = [...completeSet(), registration({ capability: 'localUserAuthority' })];
    const result = validateTargetAwareActorSet(set, 'web', '1.0.0', absentExtension);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'DUPLICATE_REGISTRATION', capability: 'localUserAuthority' });
  });

  it('rejects synthetic actors', () => {
    const set = completeSet().map((r) => (r.capability === 'secretAuthority' ? { ...r, synthetic: true } : r));
    const result = validateTargetAwareActorSet(set, 'web', '1.0.0', absentExtension);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'SYNTHETIC_IN_PRODUCTION', capability: 'secretAuthority' });
  });

  it('rejects null providers (incomplete composition)', () => {
    const set = completeSet().map((r) => (r.capability === 'identityVerification' ? { ...r, provider: 'null' as const } : r));
    const result = validateTargetAwareActorSet(set, 'web', '1.0.0', absentExtension);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'NULL_PROVIDER', capability: 'identityVerification' });
  });

  it('rejects registrations that do not serve the resolved target', () => {
    const webSet = completeSet('web');
    const result = validateTargetAwareActorSet(webSet, 'ubuntu', '1.0.0', absentExtension);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'INVALID_TARGET', capability: 'localUserAuthority' });
  });

  it('rejects incompatible or unpinned contract versions', () => {
    const set = completeSet().map((r) => (r.capability === 'removal' ? { ...r, contractVersion: '1.1.0' } : r));
    const result = validateTargetAwareActorSet(set, 'web', '1.0.0', absentExtension);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'INCOMPATIBLE_VERSION', capability: 'removal', version: '1.1.0' });
  });

  it('rejects unknown capabilities', () => {
    const set = [...completeSet(), registration({ capability: 'electionHub' as never })];
    const result = validateTargetAwareActorSet(set, 'web', '1.0.0', absentExtension);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'UNKNOWN_CAPABILITY', capability: 'electionHub' });
  });

  it('rejects web+native mixed target contradictions (no fallback sets)', () => {
    const set = completeSet().map((r) =>
      r.capability === 'browserCoordination' ? { ...r, targetClasses: ['web', 'ubuntu'] as const } : r,
    );
    const result = validateTargetAwareActorSet(set, 'ubuntu', '1.0.0', absentExtension);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'TARGET_CONTRADICTION', capability: 'browserCoordination' });
  });

  it('rejects registrations serving two native classes at once', () => {
    const set = completeSet('ubuntu').map((r) =>
      r.capability === 'secretAuthority' ? { ...r, targetClasses: ['ubuntu', 'android'] as const } : r,
    );
    const result = validateTargetAwareActorSet(set, 'ubuntu', '1.0.0', absentExtension);
    expect(result.ok).toBe(false);
    expect(result.diagnostics).toContainEqual({ code: 'TARGET_CONTRADICTION', capability: 'secretAuthority' });
  });

  it('fails the whole set atomically (no individually valid actor is used)', () => {
    const set = [
      ...completeSet().slice(0, 2), // valid subset
      registration({ capability: 'removal', targetClasses: ['web'], contractVersion: '9.9.9' }),
      registration({ capability: 'localUserAuthority', synthetic: true }),
    ];
    const result = validateTargetAwareActorSet(set, 'web', '1.0.0', absentExtension);
    expect(result.ok).toBe(false);
    expect(result.diagnostics.length).toBeGreaterThanOrEqual(3);
  });
});

describe('projectForTarget', () => {
  it('projects only the registrations serving the resolved target', () => {
    const set = [...completeSet('web'), ...completeSet('ubuntu')];
    expect(projectForTarget(set, 'web').length).toBe(MANDATORY_TARGET_CAPABILITIES.length);
    expect(projectForTarget(set, 'ubuntu').length).toBe(MANDATORY_TARGET_CAPABILITIES.length);
    expect(projectForTarget(set, 'android').length).toBe(0);
  });
});
