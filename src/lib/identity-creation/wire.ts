/**
 * FEAT-007 identity-creation — wire normalizers and closed outcome mapping.
 *
 * Normalizes the UNCHANGED HushServerNode replies (`GetIdentity`,
 * `SubmitSignedTransaction`) into closed outcomes. Only transport-successful
 * authoritative responses drive control flow; `Message` is display/diagnostic
 * text and is never parsed. Unknown statuses/codes, malformed successes, and
 * contradictions fail closed as compatibility errors.
 *
 * Framework-neutral. The editable-rejection allowlist is supplied by the
 * pinned external HushServerNode hardening artifact; an empty allowlist fails
 * closed (no editable correction is ever authorized without the artifact).
 *
 * Normative source: FEAT-007 FeatureDescription "Immutable HushServerNode Wire
 * Contract", "Submission Outcome Contract".
 */

/** Existing transaction status enum (unchanged). */
export type TransactionStatus = 'UNSPECIFIED' | 'ACCEPTED' | 'ALREADY_EXISTS' | 'PENDING' | 'REJECTED';

/** Raw GetIdentity reply fields (transport-layer view). */
export interface GetIdentityReply {
  readonly successfull: boolean;
  readonly message: string;
  readonly profileName?: string | null;
  readonly publicSigningAddress?: string | null;
  readonly publicEncryptAddress?: string | null;
  readonly isPublic?: boolean | null;
}

/** Raw SubmitSignedTransaction reply fields (transport-layer view). */
export interface SubmitSignedTransactionReply {
  readonly successfull: boolean;
  readonly message: string;
  readonly status?: TransactionStatus | null;
  readonly validationCode?: string | null;
}

export type LookupOutcome =
  | { readonly kind: 'authoritativeAbsent' } // transport-successful Successfull=false
  | { readonly kind: 'exactProfile'; readonly profileName: string; readonly publicSigningAddress: string; readonly publicEncryptAddress: string; readonly isPublic: boolean }
  | { readonly kind: 'signingKeyMismatch' } // signing differs from local
  | { readonly kind: 'encryptionKeyMismatch' } // signing matches, encryption differs → fail closed
  | { readonly kind: 'malformedSuccess' }
  | { readonly kind: 'compatibilityError' } // unknown enum/contradiction/unspecified
  | { readonly kind: 'transportFailure' }; // timeout/cancel/TLS/DNS/HTTP/gRPC/parse — never not-found

export type SubmissionOutcome =
  | { readonly kind: 'accepted' }
  | { readonly kind: 'pending' }
  | { readonly kind: 'alreadyExists' }
  | { readonly kind: 'editableRejection'; readonly validationCode: string }
  | { readonly kind: 'terminalRejection'; readonly validationCode: string }
  | { readonly kind: 'unknownRejection' } // REJECTED + code outside allowlist → fail closed
  | { readonly kind: 'transportFailure' }
  | { readonly kind: 'compatibilityError' }; // UNSPECIFIED/unknown enum/contradiction

export const ALLOWED_TRANSACTION_STATUSES: readonly TransactionStatus[] = ['UNSPECIFIED', 'ACCEPTED', 'ALREADY_EXISTS', 'PENDING', 'REJECTED'];

function isTransactionStatus(value: unknown): value is TransactionStatus {
  return typeof value === 'string' && (ALLOWED_TRANSACTION_STATUSES as readonly string[]).includes(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function isValidAddress(value: unknown): value is string {
  return isNonEmptyString(value) && /^[A-Za-z0-9]+$/.test(value);
}

/**
 * Normalize a GetIdentity reply. A transport-successful response with
 * `Successfull=false` is the authoritative not-found outcome. A successful
 * reply must contain structurally valid fields; anything else fails closed.
 */
export function normalizeGetIdentityReply(reply: GetIdentityReply | null | undefined, localSigningAddress: string, localEncryptionAddress: string): LookupOutcome {
  if (reply === null || reply === undefined || typeof reply !== 'object') {
    return { kind: 'malformedSuccess' };
  }
  if (reply.successfull === false) {
    // Authoritative not-found for this flow (transport succeeded).
    return { kind: 'authoritativeAbsent' };
  }
  if (reply.successfull !== true) {
    return { kind: 'compatibilityError' };
  }
  const { profileName, publicSigningAddress, publicEncryptAddress, isPublic } = reply;
  if (!isNonEmptyString(profileName) || !isValidAddress(publicSigningAddress) || !isValidAddress(publicEncryptAddress) || typeof isPublic !== 'boolean') {
    return { kind: 'malformedSuccess' };
  }
  if (publicSigningAddress !== localSigningAddress) {
    return { kind: 'signingKeyMismatch' };
  }
  if (publicEncryptAddress !== localEncryptionAddress) {
    return { kind: 'encryptionKeyMismatch' };
  }
  return { kind: 'exactProfile', profileName, publicSigningAddress, publicEncryptAddress, isPublic };
}

/**
 * Normalize a SubmitSignedTransaction reply. `Message` is never parsed.
 * Unknown/unspecified/contradictory status or code combinations fail closed.
 */
export function normalizeSubmitReply(reply: SubmitSignedTransactionReply | null | undefined, editableCodeAllowlist: ReadonlySet<string>): SubmissionOutcome {
  if (reply === null || reply === undefined || typeof reply !== 'object') {
    return { kind: 'compatibilityError' };
  }
  const status = reply.status ?? null;
  if (status === null || status === 'UNSPECIFIED') {
    return { kind: 'compatibilityError' };
  }
  if (!isTransactionStatus(status)) {
    return { kind: 'compatibilityError' };
  }
  // Contradiction: transport-successful reply with successfull !== true/false.
  if (reply.successfull !== true && reply.successfull !== false) {
    return { kind: 'compatibilityError' };
  }
  switch (status) {
    case 'ACCEPTED':
      return reply.successfull === true ? { kind: 'accepted' } : { kind: 'compatibilityError' };
    case 'PENDING':
      return reply.successfull === true ? { kind: 'pending' } : { kind: 'compatibilityError' };
    case 'ALREADY_EXISTS':
      return reply.successfull === true ? { kind: 'alreadyExists' } : { kind: 'compatibilityError' };
    case 'REJECTED': {
      const code = reply.validationCode ?? null;
      if (code === null || code.length === 0) {
        // A rejection without a stable code cannot drive correction.
        return { kind: 'unknownRejection' };
      }
      if (editableCodeAllowlist.has(code)) {
        return { kind: 'editableRejection', validationCode: code };
      }
      // Signature/signatory/key-binding/payload/encoding/malformed and unknown
      // codes are terminal; never retry automatically.
      return { kind: 'terminalRejection', validationCode: code };
    }
    default:
      return { kind: 'compatibilityError' };
  }
}
