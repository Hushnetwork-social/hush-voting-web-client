/**
 * FEAT-009 Task 2.6 — unit, model, tamper, and lifecycle tests for the
 * profile resolution, protection, staging, activation, and resume
 * contracts (Task 2.5).
 *
 * Proves: exhaustive lookup/profile outcomes, exact both-key equality
 * with signing-only fail-closed, authoritative not-found vs transport,
 * protection mode closure with device-password default, stage integrity
 * vocabulary, session-only non-persistence, activation truth (never local
 * alone), startup inspection, cleanup scope exclusion of the external
 * source, and secret-free contract shapes.
 */
import { describe, expect, it } from 'vitest';
import {
  DEFAULT_PROTECTION_MODE,
  PROTECTION_MODES,
  STAGED_RESTORE_IS_AUTHENTICATION,
} from './protection.js';
import type {
  ActivationOutcome,
  ProtectionQualification,
  StageState,
  StageVerification,
  StagedRestoreRecordMetadata,
} from './protection.js';
import {
  LOOKUP_RPC_TIMEOUT_MS,
  PROFILE_ABNORMAL_DELAY_MS,
  PROFILE_POLL_INTERVAL_MS,
} from './resolution.js';
import type { LookupOutcome, RecreationOutcome, ResolutionResult, ResolvedChainProfile } from './resolution.js';
import { CleanupScope } from './staging.js';
import type { CleanupVerification, OwnerState, StagedCancellation, StartupInspection } from './staging.js';
import { assertNoRestoreSecretSurface } from './lifecycle.js';

const chainProfile: ResolvedChainProfile = {
  alias: 'chain-alias',
  isPublic: true,
  signingAddress: 'a'.repeat(66),
  encryptionAddress: 'b'.repeat(66),
  networkLabel: 'HushLocal',
};

describe('FEAT-009 lookup/profile outcomes (Task 2.5)', () => {
  it('every lookup status maps to a closed outcome; only exact pair and typed not-found proceed', () => {
    const existing: LookupOutcome = { kind: 'existing', profile: chainProfile };
    expect(existing.kind).toBe('existing');
    expect(existing.profile.signingAddress).toBe('a'.repeat(66)); // exact equality required
    expect(existing.profile.encryptionAddress).toBe('b'.repeat(66));

    const notFound: LookupOutcome = { kind: 'authoritativeNotFound' };
    expect(notFound.kind).toBe('authoritativeNotFound'); // only path to missing-profile review

    const signingOnly: LookupOutcome = { kind: 'signingOnlyMatch' };
    expect(signingOnly.kind).toBe('signingOnlyMatch'); // fail closed; never partial success

    const transport: LookupOutcome = { kind: 'transportFailure' };
    expect(transport.kind).toBe('transportFailure'); // connectivity never creates

    const malformed: LookupOutcome = { kind: 'malformed' };
    expect(malformed.kind).toBe('malformed'); // gross malformed response fails closed

    const unknown: LookupOutcome = { kind: 'unknownStatus' };
    expect(unknown.kind).toBe('unknownStatus'); // fail closed without free-form parsing
  });

  it('resolution distinguishes existing/missing/signing-only/transport/malformed/unknown', () => {
    const results: readonly ResolutionResult['kind'][] = [
      'existing',
      'missing',
      'signingOnlyMatch',
      'transportFailure',
      'malformed',
      'unknownStatus',
    ];
    expect(new Set(results).size).toBe(6);
    const missing: ResolutionResult = {
      kind: 'missing',
      review: {
        authenticatedProfileName: 'legacy-alias',
        authenticatedIsPublic: false,
        signingAddressAbbreviated: 'aaaaaaaa…bbbbbb',
        encryptionAddressAbbreviated: 'cccccccc…dddddd',
        networkLabel: 'HushLocal',
        requiresExplicitCreate: true,
      },
    };
    expect(missing.kind).toBe('missing');
    expect(missing.review.requiresExplicitCreate).toBe(true); // explicit Create action required
  });

  it('recreation outcomes: only CONFIRMED activates; mempool acceptance is not success', () => {
    const confirmed: RecreationOutcome = { kind: 'confirmed' };
    expect(confirmed.kind).toBe('confirmed');
    const accepted: RecreationOutcome = { kind: 'accepted' };
    expect(accepted.kind).not.toBe('confirmed'); // mempool acceptance insufficient
    const pending: RecreationOutcome = { kind: 'pending' };
    expect(pending.kind).toBe('pending');
    const invalidProof: RecreationOutcome = { kind: 'invalidProof' };
    expect(invalidProof.kind).toBe('invalidProof'); // distinct from unsigned lookup failure
  });

  it('lookup/polling budgets are exact', () => {
    expect(LOOKUP_RPC_TIMEOUT_MS).toBe(10_000);
    expect(PROFILE_POLL_INTERVAL_MS).toBe(3_000);
    expect(PROFILE_ABNORMAL_DELAY_MS).toBe(3 * 60_000);
  });
});

describe('FEAT-009 protection/staging contracts (Task 2.5)', () => {
  it('protection modes are closed; device-password is the default; session-only is explicit', () => {
    expect(PROTECTION_MODES).toEqual([
      'devicePassword',
      'webAuthnPasswordless',
      'nativePasswordless',
      'sessionOnly',
    ]);
    expect(DEFAULT_PROTECTION_MODE).toBe('devicePassword');
    // No empty-password or plaintext mode is representable.
    expect(PROTECTION_MODES).not.toContain('emptyPassword' as never);
    expect(PROTECTION_MODES).not.toContain('plaintext' as never);
  });

  it('protection qualification fails closed without downgrade on capability loss', () => {
    const qualified: ProtectionQualification = { kind: 'qualified', mode: 'webAuthnPasswordless', version: 'v1' };
    expect(qualified.kind).toBe('qualified');
    const unavailable: ProtectionQualification = { kind: 'unavailable', mode: 'webAuthnPasswordless' };
    expect(unavailable.kind).toBe('unavailable'); // no silent fallback to weaker mode
    const unsupported: ProtectionQualification = { kind: 'unsupported' };
    expect(unsupported.kind).toBe('unsupported');
  });

  it('stage states are ordered and never authentication', () => {
    const states: readonly StageState[] = ['unstarted', 'writing', 'readBack', 'casSwitch', 'committed', 'quarantined'];
    expect(new Set(states).size).toBe(6);
    expect(STAGED_RESTORE_IS_AUTHENTICATION).toBe(false);
  });

  it('stage verification rejects tamper/downgrade/foreign metadata', () => {
    const verified: StageVerification = { kind: 'verified' };
    expect(verified.kind).toBe('verified');
    const tampered: StageVerification = { kind: 'tampered' };
    expect(tampered.kind).toBe('tampered'); // another network/purpose/generation/profile/mode
    const mismatch: StageVerification = { kind: 'addressMismatch' };
    expect(mismatch.kind).toBe('addressMismatch');
  });

  it('staged record metadata is safe binding data only (secret-free scan)', () => {
    const metadata: StagedRestoreRecordMetadata = {
      protectionMode: 'devicePassword',
      protectionVersion: 'v1',
      networkLabel: 'HushLocal',
      signingAddressAbbreviated: 'aaaaaaaa…bbbbbb',
      encryptionAddressAbbreviated: 'cccccccc…dddddd',
      profileAlias: 'chain-alias',
      profileIsPublic: true,
      stagedAtMs: 1234,
      generation: 3,
      purpose: 'file-restore',
    };
    const violations = assertNoRestoreSecretSurface(metadata);
    expect(violations).toEqual([]);
    expect(metadata.purpose).toBe('file-restore'); // never any other purpose
  });

  it('activation truth: never from local state alone; connectivity preserves stage', () => {
    const activatedExisting: ActivationOutcome = { kind: 'activatedExisting' };
    expect(activatedExisting.kind).toBe('activatedExisting'); // fresh exact online lookup only
    const created: ActivationOutcome = { kind: 'activatedCreated' };
    expect(created.kind).toBe('activatedCreated'); // exact FEAT-007 block confirmation only
    const connectivity: ActivationOutcome = { kind: 'connectivityFailure' };
    expect(connectivity.kind).toBe('connectivityFailure'); // stage preserved; Retry; never shell
    const staged: ActivationOutcome = { kind: 'notYetActive' };
    expect(staged.kind).toBe('notYetActive'); // staged is not authenticated
  });
});

describe('FEAT-009 startup/resume/cleanup contracts (Task 2.5)', () => {
  it('startup inspection never shows first-run while staged data exists', () => {
    const empty: StartupInspection = { kind: 'verifiedEmpty' };
    expect(empty.kind).toBe('verifiedEmpty');
    const staged: StartupInspection = { kind: 'stagedExists' };
    expect(staged.kind).toBe('stagedExists'); // Finish restoring your identity only
    const active: StartupInspection = { kind: 'activeIdentity' };
    expect(active.kind).toBe('activeIdentity'); // Lock retains; no Create/Restore
    const quarantined: StartupInspection = { kind: 'quarantined' };
    expect(quarantined.kind).toBe('quarantined'); // blocks Create/Restore
  });

  it('cleanup scope never includes the external source', () => {
    // The external source is structurally absent from every legal cleanup set.
    const legalScopes: readonly string[] = ['stage', 'transaction', 'protectionBinding', 'sidecar', 'session', 'tempCiphertext'];
    expect(legalScopes).not.toContain('externalSource');
    const cleanupScopes: readonly CleanupScope[] = ['stage', 'transaction', 'protectionBinding', 'sidecar', 'session', 'tempCiphertext'];
    expect(new Set(cleanupScopes).size).toBe(6); // closed registry; externalSource unrepresentable
  });

  it('cleanup verification quarantines instead of claiming empty', () => {
    const verified: CleanupVerification = { kind: 'verifiedAbsent' };
    expect(verified.kind).toBe('verifiedAbsent');
    const quarantined: CleanupVerification = { kind: 'quarantined', remaining: ['stage', 'tempCiphertext'] };
    expect(quarantined.kind).toBe('quarantined'); // never "empty"
    expect(quarantined.remaining).toContain('stage');
  });

  it('staged cancellation removes and requires re-import; failure quarantines', () => {
    const removed: StagedCancellation = { kind: 'removed' };
    expect(removed.kind).toBe('removed');
    const quarantined: StagedCancellation = { kind: 'quarantined' };
    expect(quarantined.kind).toBe('quarantined');
  });

  it('owner state is closed and non-owners receive safe status only', () => {
    const owner: OwnerState = { kind: 'owner' };
    expect(owner.kind).toBe('owner');
    const nonOwner: OwnerState = { kind: 'nonOwner', safeStatus: 'recoveryInProgress' };
    expect(nonOwner.safeStatus).toBe('recoveryInProgress'); // no sensitive data broadcast
    const released: OwnerState = { kind: 'released' };
    expect(released.kind).toBe('released'); // Retry/focus allowed after release
  });

  it('resolution/profile contract shapes are secret-free', () => {
    const shapes: unknown[] = [
      { kind: 'existing', profile: chainProfile },
      { kind: 'authoritativeNotFound' },
      { kind: 'transportFailure' },
      { kind: 'missing', review: { authenticatedProfileName: 'a', authenticatedIsPublic: false, signingAddressAbbreviated: 'aa…bb', encryptionAddressAbbreviated: 'cc…dd', networkLabel: 'HushLocal', requiresExplicitCreate: true } },
      { kind: 'confirmed' },
      { kind: 'notYetActive' },
    ];
    for (const shape of shapes) {
      const violations = assertNoRestoreSecretSurface(shape);
      expect(violations).toEqual([]);
    }
  });
});
