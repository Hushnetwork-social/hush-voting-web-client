/**
 * FEAT-008 Task 3.8 — unit/model/fault tests for exact activation,
 * missing-profile recreation, and staged resume.
 * Coverage targets: AC-008-055–063, 071 (authority portion); exact/mismatch/
 * disappeared/connectivity outcomes, metadata sync, recreate review, resume.
 */
import { describe, expect, it } from 'vitest';
import type { NetworkIdentifier, RecoveryEpoch } from '../contracts/lifecycle';
import {
  evaluateExistingProfileActivation,
  evaluateStartup,
  prepareRecreateReview,
  validateRecreateConfirmation,
  type FreshProfileOutcome,
  type RecreateReviewInput,
  type StagedInspection,
} from './activation.js';

const epoch = 'epoch-1' as RecoveryEpoch;
const network = 'hush-mainnet-1' as NetworkIdentifier;

const reviewInput: RecreateReviewInput = {
  epoch,
  networkIdentifier: network,
  signingAddress: 'S'.repeat(40),
  encryptionAddress: 'E'.repeat(40),
};

describe('existing-profile activation', () => {
  it('activates only on exact both-key match', () => {
    const outcome: FreshProfileOutcome = { kind: 'exactExisting', signingAddress: 'S'.repeat(40), encryptionAddress: 'E'.repeat(40), alias: 'Voter', visibility: 'private' };
    const result = evaluateExistingProfileActivation(outcome);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.action).toBe('activate');
    }
  });

  it('transitions disappearance to explicit recreate review, never silent submission', () => {
    const result = evaluateExistingProfileActivation({ kind: 'authoritativeAbsent' });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.action).toBe('recreateReview');
    }
  });

  it('fails closed on mismatch (signing-only match)', () => {
    const result = evaluateExistingProfileActivation({ kind: 'mismatch' });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('SIGNING_ENCRYPTION_MISMATCH');
    }
  });

  it('preserves the sealed stage on transport failure (no offline shell)', () => {
    const result = evaluateExistingProfileActivation({ kind: 'transportFailure' });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.action).toBe('remainStaged');
    }
  });
});

describe('missing-profile recreation', () => {
  it('starts alias empty, visibility Private, Public requires acknowledgement, exact recovered keys', () => {
    const review = prepareRecreateReview(reviewInput);
    expect(review.reviewAlias).toBe('');
    expect(review.reviewVisibility).toBe('private');
    expect(review.publicAcknowledgementRequired).toBe(true);
    expect(review.usesExactRecoveredKeys).toBe(true);
  });

  it('requires a non-empty alias before submission', () => {
    expect(validateRecreateConfirmation('', 'private', false).ok).toBe(false);
    expect(validateRecreateConfirmation('  ', 'private', false).ok).toBe(false);
  });

  it('requires the Public acknowledgement before public submission', () => {
    expect(validateRecreateConfirmation('Voter', 'public', false).ok).toBe(false);
    const ok = validateRecreateConfirmation('Voter', 'public', true);
    expect(ok.ok).toBe(true);
  });

  it('accepts a Private submission without Public acknowledgement', () => {
    const ok = validateRecreateConfirmation('Voter', 'private', false);
    expect(ok.ok).toBe(true);
    if (ok.ok) {
      expect(ok.value.alias).toBe('Voter');
      expect(ok.value.visibility).toBe('private');
    }
  });
});

describe('staged resume', () => {
  it('shows Finish restoring when a supported stage exists; never first-run', () => {
    const inspection: StagedInspection = { staged: true, protectionMode: 'devicePasswordWeb', corrupted: false, signingAddress: 'S'.repeat(40), encryptionAddress: 'E'.repeat(40) };
    const result = evaluateStartup(inspection);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.surface).toBe('finishRestoring');
    }
  });

  it('shows first-run only on verified-empty local state', () => {
    const result = evaluateStartup({ staged: false, protectionMode: null, corrupted: false, signingAddress: null, encryptionAddress: null });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.surface).toBe('firstRun');
    }
  });

  it('fails closed on corruption/unsupported version', () => {
    const result = evaluateStartup({ staged: true, protectionMode: null, corrupted: true, signingAddress: null, encryptionAddress: null });
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('STAGED_RESTART_FAILURE');
    }
  });
});
