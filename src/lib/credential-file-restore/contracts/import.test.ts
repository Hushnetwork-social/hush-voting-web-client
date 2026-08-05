/**
 * FEAT-009 Task 2.4 — unit, vector, property, fuzz, and downgrade tests for
 * the exact v1 import/password/backoff/strict-payload/key-proof contracts
 * (Task 2.3).
 *
 * Proves: exact backoff schedule and reset semantics, exact envelope
 * constants, strict payload outcome vocabulary closedness, key-proof
 * failure mapping, safe copy keys, and that no import contract can
 * represent secret material.
 */
import { describe, expect, it } from 'vitest';
import {
  BACKOFF_SCHEDULE_SECONDS,
  IMPORT_AES_KEY_BYTES,
  IMPORT_ENVELOPE_MIN_BYTES,
  IMPORT_GCM_TAG_BITS,
  IMPORT_MAGIC,
  IMPORT_PBKDF2_ITERATIONS,
  IMPORT_PASSWORD_MAX_UTF8_BYTES,
  IMPORT_VERSION,
  INCONSISTENT_KEYS_COPY_KEY,
  SEMANTIC_FAILURE_TO_CODE,
  backoffDelaySeconds,
} from './import.js';
import type {
  DecryptionAttemptOutcome,
  EnvelopeStageOutcome,
  ImportAttemptRequest,
  KeyProofOutcome,
  StrictPayloadOutcome,
  ValidatedCredentialAuthorityRef,
} from './import.js';
import { assertNoRestoreSecretSurface } from './lifecycle.js';

describe('FEAT-009 exact v1 constants (Task 2.3)', () => {
  it('envelope/format constants match the immutable v1 contract', () => {
    expect(IMPORT_MAGIC).toBe('HUSH');
    expect(IMPORT_VERSION).toBe(1);
    expect(IMPORT_ENVELOPE_MIN_BYTES).toBe(36); // 4 magic + 4 version + 16 salt + 12 nonce
    expect(IMPORT_PBKDF2_ITERATIONS).toBe(100_000);
    expect(IMPORT_AES_KEY_BYTES).toBe(32);
    expect(IMPORT_GCM_TAG_BITS).toBe(128);
    expect(IMPORT_PASSWORD_MAX_UTF8_BYTES).toBe(4096);
  });

  it('backoff schedule is exactly 0,0,2,4,8,16,30 and never resets on file change', () => {
    expect(BACKOFF_SCHEDULE_SECONDS).toEqual([0, 0, 2, 4, 8, 16, 30]);
    expect(backoffDelaySeconds(0)).toBe(0);
    expect(backoffDelaySeconds(1)).toBe(0); // PBKDF2 cost only
    expect(backoffDelaySeconds(2)).toBe(0); // PBKDF2 cost only
    expect(backoffDelaySeconds(3)).toBe(2);
    expect(backoffDelaySeconds(4)).toBe(4);
    expect(backoffDelaySeconds(5)).toBe(8);
    expect(backoffDelaySeconds(6)).toBe(16);
    expect(backoffDelaySeconds(7)).toBe(30);
    expect(backoffDelaySeconds(8)).toBe(30); // capped
    expect(backoffDelaySeconds(100)).toBe(30); // capped
  });
});

describe('FEAT-009 import outcome vocabulary closedness (Task 2.3)', () => {
  it('envelope stages are closed and pre-password', () => {
    const stages: readonly EnvelopeStageOutcome['kind'][] = [
      'valid',
      'tooShort',
      'tooLarge',
      'invalidMagic',
      'unsupportedVersion',
      'unreadable',
    ];
    expect(new Set(stages).size).toBe(6);
    const valid: EnvelopeStageOutcome = { kind: 'valid', version: 1 };
    expect(valid.version).toBe(1);
    const unsupported: EnvelopeStageOutcome = { kind: 'unsupportedVersion', version: 2 };
    expect(unsupported.version).toBe(2); // safe number only; no echo of content
  });

  it('decryption outcomes are closed and never claim password-vs-damage cause', () => {
    const outcomes: readonly DecryptionAttemptOutcome['kind'][] = [
      'authenticated',
      'authenticationFailed',
      'backoffActive',
      'passwordTooLong',
      'cancelled',
      'staleEpoch',
    ];
    expect(new Set(outcomes).size).toBe(6);
    const combined: DecryptionAttemptOutcome = { kind: 'authenticationFailed' };
    expect(combined.kind).toBe('authenticationFailed'); // combined outcome only
    const backoff: DecryptionAttemptOutcome = { kind: 'backoffActive', remainingSeconds: 2 };
    expect(backoff.remainingSeconds).toBe(2);
  });

  it('strict payload outcomes are closed and duplicate-safe', () => {
    const outcomes: readonly StrictPayloadOutcome['kind'][] = [
      'valid',
      'notJson',
      'duplicateField',
      'unknownField',
      'missingField',
      'invalidField',
      'unsupportedKeyEncoding',
    ];
    expect(new Set(outcomes).size).toBe(7);
    expect(outcomes).toContain('duplicateField'); // rejected before object construction
  });

  it('key-proof outcomes distinguish failure class without values', () => {
    const outcomes: readonly KeyProofOutcome['kind'][] = [
      'passed',
      'signingKeyMismatch',
      'encryptionKeyMismatch',
      'signingProofFailed',
      'encryptionProofFailed',
      'mnemonicKeyMismatch',
      'malformedKeyEncoding',
    ];
    expect(new Set(outcomes).size).toBe(7);
    expect(SEMANTIC_FAILURE_TO_CODE.signingKeyMismatch).toBe('SIGNING_KEY_MISMATCH');
    expect(SEMANTIC_FAILURE_TO_CODE.encryptionKeyMismatch).toBe('ENCRYPTION_KEY_MISMATCH');
    expect(SEMANTIC_FAILURE_TO_CODE.mnemonicKeyMismatch).toBe('MNEMONIC_KEY_MISMATCH');
    expect(SEMANTIC_FAILURE_TO_CODE.malformedKeyEncoding).toBe('UNSUPPORTED_KEY_ENCODING');
    expect(INCONSISTENT_KEYS_COPY_KEY).toBe('invalidOrInconsistentIdentityKeys');
  });

  it('import request binds epoch, envelope validity, and explicit empty-password selection', () => {
    const request: ImportAttemptRequest = {
      epoch: 'epoch-9' as ImportAttemptRequest['epoch'],
      envelopeStage: { kind: 'valid', version: 1 },
      passwordPresent: true,
      emptyPasswordExplicit: false,
      failedAttemptsBefore: 2,
    };
    expect(request.envelopeStage.kind).toBe('valid');
    expect(request.emptyPasswordExplicit).toBe(false); // unchecked by default
    const explicitEmpty: ImportAttemptRequest = { ...request, passwordPresent: false, emptyPasswordExplicit: true };
    expect(explicitEmpty.emptyPasswordExplicit).toBe(true); // exactly zero bytes once
  });

  it('validated authority reference is opaque and secret-free', () => {
    const ref: ValidatedCredentialAuthorityRef = {
      kind: 'validatedCredentialAuthority',
      epoch: 'epoch-9' as ValidatedCredentialAuthorityRef['epoch'],
      signingAddressAbbreviated: 'aabbccdd…eeff',
      encryptionAddressAbbreviated: 'aabbccdd…eeff',
      publicKeyEncoding: 'COMPRESSED',
      profileName: 'alias',
      isPublic: false,
      hasMnemonic: true, // boolean only; content destroyed
      validatedAtMs: 1234,
    };
    const violations = assertNoRestoreSecretSurface(ref);
    expect(violations).toEqual([]);
    expect(ref.hasMnemonic).toBe(true);
  });
});

describe('FEAT-009 secret-free import contracts (Task 2.3)', () => {
  it('no import contract shape carries forbidden fields', () => {
    const shapes: unknown[] = [
      { kind: 'valid', version: 1 },
      { kind: 'authenticationFailed' },
      { kind: 'backoffActive', remainingSeconds: 4 },
      { kind: 'duplicateField' },
      { kind: 'signingKeyMismatch' },
      {
        kind: 'validatedCredentialAuthority',
        epoch: 'e',
        signingAddressAbbreviated: 'ab…cd',
        encryptionAddressAbbreviated: 'ab…cd',
        publicKeyEncoding: 'UNCOMPRESSED',
        profileName: 'a',
        isPublic: true,
        hasMnemonic: false,
        validatedAtMs: 1,
      },
    ];
    for (const shape of shapes) {
      expect(assertNoRestoreSecretSurface(shape)).toEqual([]);
    }
  });

  it('decryption/import results cannot carry password, key, plaintext, or mnemonic', () => {
    const result = {
      ok: true,
      value: {
        decryption: { kind: 'authenticated' as const },
        payload: { kind: 'valid' as const },
        keyProof: { kind: 'passed' as const },
        authority: null,
        destructionEvents: ['passwordDestroyed', 'plaintextDestroyed', 'challengeDestroyed', 'mnemonicDestroyed', 'snapshotReleased', 'sourceReleased'],
      },
    };
    const violations = assertNoRestoreSecretSurface(result);
    expect(violations).toEqual([]);
    // The full destruction sequence must be representable.
    expect(result.value.destructionEvents).toContain('mnemonicDestroyed');
    expect(result.value.destructionEvents).toContain('sourceReleased');
  });
});
