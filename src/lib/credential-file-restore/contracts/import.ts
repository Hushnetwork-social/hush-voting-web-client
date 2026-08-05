/**
 * FEAT-009 credential-file restore — exact v1 import, password, strict
 * payload, and key-proof contracts.
 *
 * Framework-neutral additive strict-import facade over the FEAT-001
 * compatibility API. Defines: envelope stage outcomes, exact password-byte
 * semantics, the authority-wide failure backoff schedule, one-attempt
 * decryption outcomes, strict authenticated payload result vocabulary,
 * concrete both-pair proof requirements, optional mnemonic consistency,
 * secret destruction events, and the opaque validated-credential-authority
 * boundary. It never copies mutable legacy logic into UI modules and never
 * changes v1 semantics (no normalization, AAD, migration, or new password
 * policy).
 *
 * SECRET BOUNDARY: no import contract can carry the Backup-file password,
 * derived AES key, plaintext, decrypted JSON, mnemonic, seed, private key,
 * challenge, or parser intermediates. All such values live inside the
 * secret authority and are destroyed per attempt.
 *
 * Normative source: FEAT-009 FeatureDescription "HUSH .dat v1
 * Compatibility Contract", "Backup-File Password UX and Semantics",
 * "Decryption and Error Privacy", "Concrete Credential Validation and
 * Ownership Proof", "Mnemonic Handling", "Source Release Boundary";
 * FEAT-001 compatibility API/corpus; legacy .NET credential service as
 * interoperability evidence.
 */

import type { RestoreEpoch, RestoreFailureCode, RestoreResult } from './lifecycle';

/** Exact v1 envelope constants (FEAT-001 contract; never modified). */
export const IMPORT_ENVELOPE_MIN_BYTES = 36; // magic 4 + version 4 + salt 16 + nonce 12
export const IMPORT_MAGIC = 'HUSH';
export const IMPORT_VERSION = 1;
export const IMPORT_PBKDF2_ITERATIONS = 100_000;
export const IMPORT_AES_KEY_BYTES = 32;
export const IMPORT_GCM_TAG_BITS = 128;
export const IMPORT_PASSWORD_MAX_UTF8_BYTES = 4096;

/**
 * Authority-wide non-persistent failure backoff (seconds added per failed
 * authenticated-decryption attempt). First two failures are PBKDF2 cost
 * only; then 2/4/8/16/30. Choosing another file does not reset the
 * counter; successful complete credential validation or authority loss
 * resets it. Nothing is persisted (no counter, fingerprint, password hash,
 * or deadline).
 */
export const BACKOFF_SCHEDULE_SECONDS: readonly number[] = [0, 0, 2, 4, 8, 16, 30];

export function backoffDelaySeconds(failedAttempts: number): number {
  if (failedAttempts <= 0) return 0;
  if (failedAttempts <= BACKOFF_SCHEDULE_SECONDS.length) {
    return BACKOFF_SCHEDULE_SECONDS[failedAttempts - 1] ?? 0;
  }
  return BACKOFF_SCHEDULE_SECONDS[BACKOFF_SCHEDULE_SECONDS.length - 1] ?? 0;
}

/** Closed pre-password structural envelope stage outcomes. */
export type EnvelopeStageOutcome =
  | { readonly kind: 'valid'; readonly version: 1 } // structure OK; password work may proceed
  | { readonly kind: 'tooShort' } // below 36 bytes
  | { readonly kind: 'tooLarge' } // over 1 MiB + overflow byte
  | { readonly kind: 'invalidMagic' }
  | { readonly kind: 'unsupportedVersion'; readonly version: number } // safe number only
  | { readonly kind: 'unreadable' }; // platform read failure (pre-password)

/** One exact decryption attempt outcome (inside the authority). */
export type DecryptionAttemptOutcome =
  | { readonly kind: 'authenticated' } // exact v1 PBKDF2/AES-GCM success; strict parse follows
  | { readonly kind: 'authenticationFailed' } // combined wrong-password-or-damaged; never claims cause
  | { readonly kind: 'backoffActive'; readonly remainingSeconds: number } // attempt rejected by schedule
  | { readonly kind: 'passwordTooLong' } // over 4,096 UTF-8 bytes; rejected before PBKDF2
  | { readonly kind: 'cancelled' } // cancellation during derivation; state destroyed
  | { readonly kind: 'staleEpoch' }; // completion from a stale epoch; dropped

/** Closed strict-payload outcome vocabulary (no decrypted values, ever). */
export type StrictPayloadOutcome =
  | { readonly kind: 'valid' } // exact FEAT-001 schema satisfied
  | { readonly kind: 'notJson' }
  | { readonly kind: 'duplicateField' } // rejected before object construction
  | { readonly kind: 'unknownField' }
  | { readonly kind: 'missingField' }
  | { readonly kind: 'invalidField' } // wrong-type/null-disallowed/oversized/bound violation
  | { readonly kind: 'unsupportedKeyEncoding' }; // malformed/unsupported key encoding/algorithm

/** Closed concrete key-proof outcome (typed internal codes; no values). */
export type KeyProofOutcome =
  | { readonly kind: 'passed' } // both pairs + domain-separated proofs + optional mnemonic consistency
  | { readonly kind: 'signingKeyMismatch' }
  | { readonly kind: 'encryptionKeyMismatch' }
  | { readonly kind: 'signingProofFailed' } // domain-separated signing consistency check failed
  | { readonly kind: 'encryptionProofFailed' } // Approved encryption consistency check failed
  | { readonly kind: 'mnemonicKeyMismatch' }
  | { readonly kind: 'malformedKeyEncoding' };

/** Opaque validated credential authority reference (no secret fields). */
export interface ValidatedCredentialAuthorityRef {
  readonly kind: 'validatedCredentialAuthority';
  readonly epoch: RestoreEpoch;
  readonly signingAddressAbbreviated: string; // safe display value
  readonly encryptionAddressAbbreviated: string;
  readonly publicKeyEncoding: 'COMPRESSED' | 'UNCOMPRESSED';
  readonly profileName: string; // authenticated safe metadata (review only)
  readonly isPublic: boolean;
  readonly hasMnemonic: boolean; // boolean only; content already destroyed
  readonly validatedAtMs: number;
}

/** Secret destruction event order — the authority emits these in sequence. */
export type ImportDestructionEvent =
  | 'passwordDestroyed' // password bytes + PBKDF2 input + derived AES key dropped
  | 'plaintextDestroyed' // decrypted buffers/parser objects/partial values dropped
  | 'challengeDestroyed' // domain-separated proof challenge dropped
  | 'mnemonicDestroyed' // mnemonic/seed/intermediates dropped after consistency
  | 'snapshotReleased' // import ciphertext snapshot cleared
  | 'sourceReleased'; // handle/descriptor/URI grant closed; temp copy verified deleted

/** One import attempt request (secret submission stays inside the authority). */
export interface ImportAttemptRequest {
  readonly epoch: RestoreEpoch;
  readonly envelopeStage: EnvelopeStageOutcome; // must be 'valid' before password work
  readonly passwordPresent: boolean; // exact bytes live only in the authority sink
  readonly emptyPasswordExplicit: boolean; // explicit unchecked-by-default no-password option
  readonly failedAttemptsBefore: number; // for backoff schedule computation
}

export type ImportAttemptResult = RestoreResult<{
  readonly decryption: DecryptionAttemptOutcome;
  readonly payload: StrictPayloadOutcome | null;
  readonly keyProof: KeyProofOutcome | null;
  readonly authority: ValidatedCredentialAuthorityRef | null; // only on full success
  readonly destructionEvents: readonly ImportDestructionEvent[];
}>;

/** Safe semantic failure code mapping (internal typed code → public copy key). */
export const SEMANTIC_FAILURE_TO_CODE: Readonly<Record<KeyProofOutcome['kind'], RestoreFailureCode>> = {
  passed: 'UNKNOWN_OUTCOME', // never used as a failure
  signingKeyMismatch: 'SIGNING_KEY_MISMATCH',
  encryptionKeyMismatch: 'ENCRYPTION_KEY_MISMATCH',
  signingProofFailed: 'KEY_PROOF_FAILED',
  encryptionProofFailed: 'KEY_PROOF_FAILED',
  mnemonicKeyMismatch: 'MNEMONIC_KEY_MISMATCH',
  malformedKeyEncoding: 'UNSUPPORTED_KEY_ENCODING',
};

/** Public copy key for the combined inconsistent-key message (safe). */
export const INCONSISTENT_KEYS_COPY_KEY = 'invalidOrInconsistentIdentityKeys';
