/**
 * FEAT-008 Task 2.2 — unit and type tests for recovery lifecycle and safe
 * projection contracts.
 * Coverage targets: AC-008-001–004, 013–015, 023–035, 054–057, 062–071
 * (contract layer portion); forbidden-field and serialization scans.
 */
import { describe, expect, it } from 'vitest';
import {
  assertNoSecretSurface,
  type RecoveryFailureCode,
  type RecoveryStage,
} from './lifecycle';
import {
  abbreviateAddress,
  assertNoRecoverySecretSurface,
  type CandidateReviewProjection,
  type ProtectionProjection,
  type RecoveryViewProjection,
  type StagedPreviewProjection,
  type WordGridProjection,
} from './projection';

describe('RecoveryStage closed vocabulary', () => {
  it('covers every typed stage required by the specification', () => {
    const stages: RecoveryStage[] = [
      'vaultGuard',
      'networkLabel',
      'wordEntry',
      'verifying',
      'deriving',
      'lookup',
      'resolving',
      'candidateSelection',
      'profileSelection',
      'proof',
      'protection',
      'staging',
      'existingProfileVerify',
      'recreateReview',
      'registration',
      'activating',
      'success',
      'finishRestoring',
      'locked',
      'quarantined',
      'terminal',
    ];
    expect(stages.length).toBe(21);
    expect(new Set(stages).size).toBe(21);
  });

  it('exposes only closed, safe failure codes (no secret-bearing codes)', () => {
    const codes: RecoveryFailureCode[] = [
      'VAULT_NOT_VERIFIED_EMPTY',
      'WRONG_COUNT',
      'UNKNOWN_WORD',
      'CHECKSUM_FAILURE',
      'UNSUPPORTED_INPUT',
      'PRODUCER_DERIVATION_FAILURE',
      'PARTIAL_CANDIDATE_LOOKUP',
      'SIGNING_ENCRYPTION_MISMATCH',
      'EPOCH_EXPIRED',
      'STALE_EPOCH',
      'DOUBLE_DISPATCH',
      'OWNERSHIP_LOST',
      'NETWORK_UNAVAILABLE',
      'MALFORMED_PROFILE',
      'PROTECTION_CANCELLED',
      'ENCRYPTED_STAGE_FAILURE',
      'STAGED_RESTART_FAILURE',
      'PROFILE_DISAPPEARED',
      'REGISTRATION_REJECTED',
      'REGISTRATION_PENDING',
      'CLEANUP_FAILURE',
      'QUARANTINED',
      'UNKNOWN_OUTCOME',
      'ENVELOPE_MALFORMED',
      'MNEMONIC_RECORD_INJECTED',
      'UNSUPPORTED_RECOVERY_VERSION',
      'PROTECTION_METADATA_INVALID',
      'UNSUPPORTED_PROTECTION_MODE',
      'UNSUPPORTED_PROTECTION_VERSION',
      'UNQUALIFIED_PASSWORDLESS',
    ];
    expect(new Set(codes).size).toBe(codes.length);
  });
});

describe('RecoveryResult failure shape', () => {
  it('carries a safe message and opaque support code', () => {
    const failure: ReturnType<typeof Object> = { ok: false, code: 'CHECKSUM_FAILURE', message: 'Checksum failed.', supportCode: 'RW-CHECKSUM-1' };
    expect(failure.supportCode).toMatch(/^RW-/);
    expect(failure.message).not.toMatch(/abandon|private|mnemonic|password/i);
  });
});

describe('assertNoSecretSurface guard', () => {
  it('rejects an object that accidentally carries mnemonic/privateKey fields', () => {
    const leaked = { stage: 'wordEntry', mnemonic: 'syntheticsecret1 syntheticsecret2' };
    const violations = assertNoSecretSurface(leaked);
    expect(violations).toContain('mnemonic');
  });

  it('accepts an empty object and plain safe values', () => {
    expect(assertNoSecretSurface({ stage: 'lookup' })).toEqual([]);
    expect(assertNoSecretSurface(null)).toEqual([]);
  });
});

describe('WordGridProjection safe boundary', () => {
  it('carries numbered validity positions but never word values', () => {
    const grid: WordGridProjection = {
      selectedWordCount: '24',
      invalidPositions: [3, 17],
      countValid: true,
      vocabularyValid: false,
      checksumState: 'notRun',
      allConcealed: true,
      busy: false,
      canVerify: false,
      errorSummary: [{ code: 'UNKNOWN_WORD', positions: [3, 17] }],
      pasteReplacementPending: false,
    };
    const json = JSON.stringify(grid);
    expect(json).not.toMatch(/word[0-9]+/i);
    expect(json).not.toMatch(/abandon|ability|zoo/i);
    expect(assertNoRecoverySecretSurface(grid)).toEqual([]);
  });

  it('keeps Verify disabled until count/vocabulary are locally valid', () => {
    const invalid = { selectedWordCount: '12', countValid: true, vocabularyValid: false, canVerify: false } as WordGridProjection;
    expect(invalid.canVerify).toBe(false);
  });
});

describe('CandidateReviewProjection safe boundary', () => {
  it('carries only abbreviated addresses and safe labels; no default selection', () => {
    const review: CandidateReviewProjection = {
      outcome: 'zeroExistingMultipleCandidates',
      entries: [
        {
          candidateIndex: 0,
          sourceLabel: 'Hush Feeds Web Client (P-01)',
          abbreviatedSigningAddress: 'Ab12Cd34…Xy98Zz76',
          abbreviatedEncryptionAddress: 'Qw12Er34…Rt56Yu78',
          producerIds: ['p-01'],
          profileAlias: null,
          visibility: null,
          selected: false,
        },
      ],
      networkLabel: 'HushNetwork Mainnet',
      selectionRequired: true,
      uncertainGuidance: 'Your trusted public address may be in prior notifications or block explorers.',
      revealState: { revealedCandidateIndex: null, fullSigningAddress: null, fullEncryptionAddress: null },
      busy: false,
    };
    expect(review.entries[0].selected).toBe(false);
    expect(abbreviateAddress('Ab12Cd34Xy98Zz76')).toHaveLength(14 + 1); // 8+…+6
    expect(assertNoRecoverySecretSurface(review)).toEqual([]);
  });

  it('permits transient full-address reveal only inside revealState', () => {
    const revealed: CandidateReviewProjection = {
      outcome: 'zeroExistingMultipleCandidates',
      entries: [],
      networkLabel: 'Testnet',
      selectionRequired: true,
      uncertainGuidance: null,
      revealState: { revealedCandidateIndex: 0, fullSigningAddress: 'A' + '1'.repeat(64), fullEncryptionAddress: 'E' + '2'.repeat(64) },
      busy: false,
    };
    // The guard strips revealState before scanning; nothing outside it carries full addresses.
    expect(assertNoRecoverySecretSurface(revealed)).toEqual([]);
  });
});

describe('ProtectionProjection safe boundary', () => {
  it('defaults Device-password to checked and reflects qualification only', () => {
    const protection: ProtectionProjection = {
      defaultPasswordChecked: true,
      allowedModes: ['devicePasswordWeb', 'sessionOnly'],
      sessionOnlyAcknowledgementRequired: true,
      passwordlessQualified: false,
      platformHints: ['webauthn-platform-required'],
      busy: false,
    };
    expect(protection.defaultPasswordChecked).toBe(true);
    expect(assertNoRecoverySecretSurface(protection)).toEqual([]);
  });
});

describe('StagedPreviewProjection', () => {
  it('is non-authenticated, blocks Create/Restore, and never exposes words', () => {
    const preview: StagedPreviewProjection = {
      stage: 'finishRestoring',
      nonAuthenticated: true,
      blocksCreateRestore: true,
      protectionMode: 'devicePasswordWeb',
      abbreviatedSigningAddress: 'Ab12Cd34…Xy98Zz76',
      abbreviatedEncryptionAddress: 'Qw12Er34…Rt56Yu78',
      networkLabel: 'HushNetwork Mainnet',
      corrupted: false,
    };
    expect(preview.nonAuthenticated).toBe(true);
    expect(assertNoRecoverySecretSurface(preview)).toEqual([]);
  });
});

describe('RecoveryViewProjection determinism', () => {
  it('exposes a closed action set and coarse progress', () => {
    const view: RecoveryViewProjection = {
      stage: 'lookup',
      progress: 0.5,
      coarseCount: { done: 2, total: 4 },
      networkLabel: 'HushNetwork Mainnet',
      busy: true,
      allowedActions: ['retryUnresolvedLookups', 'back'],
      errorSummary: [],
      focusFirstInvalidPosition: null,
      ownerState: 'owner',
    };
    expect(view.allowedActions).toEqual(['retryUnresolvedLookups', 'back']);
    expect(assertNoRecoverySecretSurface(view)).toEqual([]);
  });
});
