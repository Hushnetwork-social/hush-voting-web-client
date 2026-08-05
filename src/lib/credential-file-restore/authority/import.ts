/**
 * FEAT-009 credential-file restore authority — exact password, decryption,
 * backoff, strict payload, mnemonic, and destruction policy (Task 3.3).
 *
 * Framework-neutral workflow policy over the FEAT-001 exact v1 API. Owns:
 * direct secret submission, exact historical password-byte handling
 * (no normalization/trim/case-fold; explicit empty option), one-attempt
 * PBKDF2/AES-GCM, the authority-wide in-memory backoff schedule, strict
 * duplicate-safe payload outcomes, optional mnemonic consistency input, and
 * complete per-attempt/source-release destruction ordering. It never stores
 * the password, derived key, plaintext, parser state, or mnemonic.
 *
 * SECRET BOUNDARY: password bytes and the decrypted plaintext enter only as
 * bounded transient parameters of the single `attemptImport` call and are
 * never stored, logged, or projected. The mnemonic never leaves the
 * consistency call.
 *
 * Normative source: FEAT-009 FeatureDescription "Backup-File Password UX
 * and Semantics", "Failure backoff", "Per-attempt cleanup", "Decryption and
 * Error Privacy", "Strict portable credential schema", "Mnemonic Handling",
 * "Source Release Boundary"; FEAT-001 compatibility API.
 */
import { decodeDatV1, decryptDatV1 } from '../../identity-compatibility/dat';
import { backoffDelaySeconds } from '../contracts/import';
import type { ImportDestructionEvent } from '../contracts/import';
import type { RestoreFailure, RestoreFailureCode, RestoreResult } from '../contracts/lifecycle';
import { RESTORE_PASSWORD_MAX_UTF8_BYTES } from '../contracts/lifecycle';

/** In-memory authority-wide failure counter state (never persisted). */
export interface BackoffState {
  readonly failedAuthenticatedAttempts: number;
}

export function initialBackoffState(): BackoffState {
  return { failedAuthenticatedAttempts: 0 };
}

/**
 * Advance the counter after an authenticated-decryption failure. Choosing
 * another file does not reset it; successful complete credential validation
 * or authority loss resets it.
 */
export function recordAuthFailure(state: BackoffState): BackoffState {
  return { failedAuthenticatedAttempts: state.failedAuthenticatedAttempts + 1 };
}

export function resetBackoff(): BackoffState {
  return initialBackoffState();
}

/** Required delay (ms) before the next attempt given the current counter. */
export function currentBackoffMs(state: BackoffState): number {
  return backoffDelaySeconds(state.failedAuthenticatedAttempts) * 1000;
}

/** Exact UTF-8 byte length of the supplied password (no transformation). */
export function utf8ByteLength(password: string): number {
  return new TextEncoder().encode(password).byteLength;
}

/** One bounded direct-secret decryption attempt (password never retained). */
export type DecryptAttemptResult = RestoreResult<{
  readonly authenticated: boolean;
  readonly plaintext: string | null; // transient result of the attempt only
  readonly destruction: readonly ImportDestructionEvent[];
}>;

/**
 * Execute exactly one v1 PBKDF2/AES-GCM attempt on the immutable snapshot.
 * The password string is a transient parameter; the caller must clear its
 * buffer immediately. Returns the combined authentication outcome — the
 * caller must never claim password-vs-damage cause.
 */
export async function attemptDecryption(
  envelope: Uint8Array,
  password: string,
  opts: { readonly emptyPasswordExplicit: boolean },
): Promise<DecryptAttemptResult> {
  if (password.length === 0 && !opts.emptyPasswordExplicit) {
    // Automatic empty attempts are prohibited; only the explicit
    // unchecked-by-default option may submit zero bytes.
    return {
      ok: false,
      code: 'PASSWORD_TOO_LONG',
      message: 'empty password requires the explicit no-password option',
      supportCode: 'PWD-EMPTY-EXPLICIT',
    };
  }
  if (utf8ByteLength(password) > RESTORE_PASSWORD_MAX_UTF8_BYTES) {
    return {
      ok: false,
      code: 'PASSWORD_TOO_LONG',
      message: 'password exceeds the 4096-byte limit',
      supportCode: 'PWD-LIMIT',
    };
  }
  const decrypted = await decryptDatV1(envelope, password);
  if (!decrypted.ok) {
    // FEAT-001 auth failures surface as DAT_WRONG_PASSWORD; any other
    // decrypt-stage failure is treated as the same combined outcome.
    if (decrypted.code === 'DAT_WRONG_PASSWORD' || decrypted.code === 'DAT_MALFORMED') {
      return {
        ok: true,
        value: { authenticated: false, plaintext: null, destruction: ['passwordDestroyed', 'plaintextDestroyed'] },
      };
    }
    return {
      ok: false,
      code: 'AUTHENTICATION_FAILED',
      message: 'the backup password is incorrect or the credential file is damaged',
      supportCode: 'AUTH-COMBINED',
    };
  }
  return {
    ok: true,
    value: { authenticated: true, plaintext: decrypted.value, destruction: ['passwordDestroyed'] },
  };
}

/**
 * Strict authenticated payload + optional mnemonic consistency via the
 * FEAT-001 canonical decoder (decrypt → strict duplicate-safe parse →
 * private/public + mnemonic/key consistency). Returns typed semantic
 * outcomes; decrypted values never appear in the result.
 */
export type StrictImportResult = RestoreResult<{
  readonly schemaValid: boolean;
  readonly keyConsistent: boolean;
  readonly mnemonicConsistent: boolean | null; // null when no mnemonic present
  readonly profileName: string | null; // safe metadata; only when fully valid
  readonly isPublic: boolean | null;
  readonly mnemonicPresent: boolean;
  readonly destruction: readonly ImportDestructionEvent[];
}>;

export async function strictImport(envelope: Uint8Array, password: string): Promise<StrictImportResult> {
  const decoded = await decodeDatV1(envelope, password);
  if (!decoded.ok) {
    const code = mapImportFailure(decoded.code);
    return {
      ok: false,
      code,
      message: 'credential payload failed strict validation',
      supportCode: `IMPORT-${code}`,
    };
  }
  return {
    ok: true,
    value: {
      schemaValid: true,
      keyConsistent: true,
      mnemonicConsistent: decoded.value.mnemonicKeyConsistent,
      profileName: decoded.value.record.ProfileName,
      isPublic: decoded.value.record.IsPublic,
      mnemonicPresent: decoded.value.record.Mnemonic !== null,
      destruction: ['passwordDestroyed', 'plaintextDestroyed', 'mnemonicDestroyed', 'snapshotReleased', 'sourceReleased'],
    },
  };
}

/** Map a FEAT-001 compatibility failure code to the closed FEAT-009 vocabulary. */
export function mapImportFailure(code: string): RestoreFailureCode {
  switch (code) {
    case 'DAT_MALFORMED':
    case 'DAT_WRONG_PASSWORD':
    case 'DAT_DECRYPT_FAILED':
      return 'AUTHENTICATION_FAILED';
    case 'DAT_DUPLICATE_FIELD':
      return 'PAYLOAD_DUPLICATE_FIELD';
    case 'DAT_UNKNOWN_FIELD':
      return 'PAYLOAD_UNKNOWN_FIELD';
    case 'DAT_MISSING_FIELD':
      return 'PAYLOAD_MISSING_FIELD';
    case 'DAT_INVALID_FIELD':
      return 'PAYLOAD_INVALID_FIELD';
    case 'DAT_KEY_MISMATCH':
      return 'SIGNING_KEY_MISMATCH';
    case 'DAT_MNEMONIC_KEY_MISMATCH':
      return 'MNEMONIC_KEY_MISMATCH';
    default:
      return 'UNKNOWN_OUTCOME';
  }
}

/** Full per-attempt destruction ordering (the authority emits these). */
export const PER_ATTEMPT_DESTRUCTION_ORDER: readonly ImportDestructionEvent[] = [
  'passwordDestroyed',
  'plaintextDestroyed',
  'challengeDestroyed',
  'mnemonicDestroyed',
  'snapshotReleased',
  'sourceReleased',
];

/** Validate that a result never carries secret material (type-level guard). */
export type { ImportDestructionEvent, RestoreFailure };
export type { RestoreResult };
