/**
 * FEAT-016 Task 6.3 — exact licence sealing seam (framework-neutral).
 *
 * Closes the Phase 3 review seam ("Exact-bytes seam must be explicit in
 * Phase 6"): the credential authority signs the canonical unsigned licence
 * envelope produced by `direct-free.ts` and seals the EXACT signed bytes
 * before the first submission. The sealed record always carries the signed
 * form in production; retry/restart reuse is byte-identical because signing
 * is deterministic (P-01 RFC 6979) over the same canonical bytes.
 *
 * Query envelopes: one fresh `signedAt` per attempt over the frozen FEAT-015
 * `{actorAddress, method, request:{}, signedAt}` canonical bytes; the compact
 * base64 signature travels ONLY in the three metadata headers (never in the
 * canonical JSON, never as a pending record).
 *
 * SECRET BOUNDARY: functions here take key material as explicit parameters;
 * callers are ONLY the approved credential authorities (SharedWorker sealed
 * engine, native Rust). Page/React code never imports this module.
 *
 * Normative source: FEAT-016 FeatureDescription "Licence Transaction and
 * Pending Journal" (construction and seal-before-submit); FEAT-015 frozen
 * query/transaction contract; Phase 3 code review note 1.
 */

import { signMessage, verifyMessage } from '../identity-compatibility/signature';
import { sha256Hex, utf8Bytes } from '../identity-compatibility/crypto';
import {
  LICENCE_QUERY_METHOD,
  licenceQuerySignedJson,
  type LicenceFreshQueryEnvelope,
} from './contracts';
import { licenceTransactionDigest } from './canonical';

/** Exact outer member name of the user signature (FEAT-015/Hush codec). */
export const LICENCE_USER_SIGNATURE_MEMBER = 'UserSignature' as const;

/** Bounded fresh-query header set produced inside the authority. */
export interface LicenceQuerySignature {
  readonly signatory: string;
  readonly signedAt: string;
  readonly signature: string; // compact base64 over the canonical envelope JSON
}

/** Sealing result for one canonical unsigned licence transaction. */
export type LicenceSealingResult =
  | { readonly ok: true; readonly signedJson: string; readonly signedDigest: string }
  | { readonly ok: false; readonly code: 'missing-signer' | 'malformed-unsigned' | 'signature-failed' };

/** Reject anything that is not a canonical licence outer envelope (with or without signature). */
function isLicenceOuterEnvelopeJson(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > 65_536) {
    return false;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    return false;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return false;
  }
  const record = parsed as Record<string, unknown>;
  if (typeof record.TransactionId !== 'string' || typeof record.PayloadKind !== 'string') {
    return false;
  }
  if (typeof record.TransactionTimeStamp !== 'string' || typeof record.Payload !== 'object' || record.Payload === null) {
    return false;
  }
  if (typeof record.PayloadSize !== 'number' || !Number.isInteger(record.PayloadSize)) {
    return false;
  }
  return true;
}

/** Reject anything that is not the canonical unsigned licence envelope. */
export function isLicenceCanonicalUnsignedJson(value: unknown): value is string {
  if (!isLicenceOuterEnvelopeJson(value)) {
    return false;
  }
  return (JSON.parse(value) as Record<string, unknown>).UserSignature === undefined;
}

/** True when the record's exact bytes already carry the sealed signature. */
export function isLicenceSignedTransactionJson(value: unknown): value is string {
  if (!isLicenceOuterEnvelopeJson(value)) {
    return false;
  }
  const signature = (JSON.parse(value) as Record<string, unknown>)[LICENCE_USER_SIGNATURE_MEMBER];
  if (typeof signature !== 'object' || signature === null) {
    return false;
  }
  const member = signature as Record<string, unknown>;
  return typeof member.Signatory === 'string' && member.Signatory.length > 0 && typeof member.Signature === 'string' && member.Signature.length > 0;
}

/**
 * Seal one canonical unsigned licence envelope with the user's real signing
 * key: sign the exact canonical bytes, then append the frozen
 * `UserSignature:{Signatory, Signature}` member (deterministic member order:
 * the canonical unsigned members first, then UserSignature). The returned
 * `signedDigest` is sha-256 over the sealed UTF-8 bytes (the digest the
 * purpose-bound record stores).
 */
export function sealLicenceTransaction(input: {
  readonly unsignedJson: string;
  readonly signingPrivateKeyHex: string;
  readonly signingAddress: string;
}): LicenceSealingResult {
  if (!isLicenceCanonicalUnsignedJson(input.unsignedJson)) {
    return { ok: false, code: 'malformed-unsigned' };
  }
  if (!/^[0-9a-fA-F]{64}$/.test(input.signingPrivateKeyHex)) {
    return { ok: false, code: 'missing-signer' };
  }
  if (typeof input.signingAddress !== 'string' || input.signingAddress.length === 0) {
    return { ok: false, code: 'missing-signer' };
  }
  const signed = signMessage(input.unsignedJson, input.signingPrivateKeyHex);
  if (!signed.ok) {
    return { ok: false, code: 'signature-failed' };
  }
  const parsed = JSON.parse(input.unsignedJson) as Record<string, unknown>;
  const signedJson = JSON.stringify({
    ...parsed,
    [LICENCE_USER_SIGNATURE_MEMBER]: {
      Signatory: input.signingAddress,
      Signature: signed.value.compactBase64,
    },
  });
  return { ok: true, signedJson, signedDigest: sha256Hex(utf8Bytes(signedJson)) };
}

/**
 * Verify a sealed licence transaction against the exact canonical unsigned
 * bytes and the signatory public key (compact base64 — the Approved FEAT-001
 * encoding the server classifier accepts). Deterministic test/parity guard;
 * production verification is server-side.
 */
export function verifyLicenceSeal(input: {
  readonly unsignedJson: string;
  readonly signedJson: string;
  readonly publicSigningKeyHex: string;
}): boolean {
  if (!isLicenceCanonicalUnsignedJson(input.unsignedJson) || !isLicenceSignedTransactionJson(input.signedJson)) {
    return false;
  }
  const signature = (JSON.parse(input.signedJson) as { UserSignature: { Signature: string } }).UserSignature.Signature;
  // Compact base64 → hex for the shared verifier.
  const compactHex = base64ToHex(signature);
  if (compactHex === null) {
    return false;
  }
  return verifyMessage(input.unsignedJson, compactHex, input.publicSigningKeyHex, 'compact');
}

/**
 * Build one fresh signed-query envelope header set inside the authority.
 * `signedAt` is minted per attempt; the signature binds the ordinal
 * deep-sorted canonical JSON bytes with the user's signing key. A
 * read-query signature is NEVER a blockchain transaction and is never
 * persisted as a pending record.
 */
export function signLicenceQueryEnvelope(input: {
  readonly actorAddress: string;
  readonly signedAt: string;
  readonly signingPrivateKeyHex: string;
}): { readonly ok: true; readonly headers: LicenceQuerySignature } | { readonly ok: false; readonly code: 'missing-signer' | 'signature-failed' } {
  if (!/^[0-9a-fA-F]{64}$/.test(input.signingPrivateKeyHex)) {
    return { ok: false, code: 'missing-signer' };
  }
  const envelope: LicenceFreshQueryEnvelope = {
    actorAddress: input.actorAddress as LicenceFreshQueryEnvelope['actorAddress'],
    method: LICENCE_QUERY_METHOD,
    request: {},
    signedAt: input.signedAt,
  };
  const canonicalJson = licenceQuerySignedJson(envelope);
  const signed = signMessage(canonicalJson, input.signingPrivateKeyHex);
  if (!signed.ok) {
    return { ok: false, code: 'signature-failed' };
  }
  return {
    ok: true,
    headers: {
      signatory: input.actorAddress.toLowerCase(),
      signedAt: input.signedAt,
      signature: signed.value.compactBase64,
    },
  };
}

/** Compact base64 signature → 64-byte compact hex (null on malformed). */
export function base64ToHex(value: string): string | null {
  try {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(normalized);
    if (binary.length !== 64) {
      return null;
    }
    let hex = '';
    for (let i = 0; i < binary.length; i += 1) {
      hex += binary.charCodeAt(i).toString(16).padStart(2, '0');
    }
    return hex;
  } catch {
    return null;
  }
}

/** Recompute the canonical unsigned envelope from a sealed transaction (digest helper). */
export function licenceDigestOfUnsignedJson(unsignedJson: string): string {
  return licenceTransactionDigest(unsignedJson);
}

/** Fresh UTC timestamp for one query/transaction attempt (3-digit ms ISO). */
export function licenceFreshTimestampUtc(nowMs: number): string {
  return new Date(nowMs).toISOString();
}
