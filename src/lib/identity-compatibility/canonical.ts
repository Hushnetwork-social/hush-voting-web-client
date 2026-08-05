/**
 * FEAT-001 identity compatibility API — canonical transaction serialization.
 *
 * Produces the exact bytes of the historical signed-transaction representation:
 * the TypeScript producer serializes the unsigned transaction with
 * JSON.stringify in declaration order (TransactionId, PayloadKind,
 * TransactionTimeStamp, Payload, PayloadSize) with a 3-digit-millisecond ISO
 * timestamp and a computed PayloadSize (UTF-8 byte length of the payload JSON).
 * No RFC 8785/JCS and no new transaction digest is introduced.
 */
import { utf8Bytes } from './crypto';

/** The identity payload shape signed by the historical producers. */
export interface CanonicalPayload {
  readonly IdentityAlias: string;
  readonly PublicSigningAddress: string;
  readonly PublicEncryptAddress: string;
  readonly IsPublic: boolean;
}

/** Input for canonical unsigned-transaction serialization. */
export interface CanonicalUnsignedTransaction {
  readonly TransactionId: string;
  readonly PayloadKind: string;
  readonly TransactionTimeStamp: string;
  readonly Payload: CanonicalPayload;
  readonly PayloadSize: number;
}

/** UTF-8 byte length of a payload's JSON serialization. */
export function payloadSizeBytes(payload: CanonicalPayload): number {
  return utf8Bytes(JSON.stringify(payload)).length;
}

/**
 * Serialize an unsigned transaction to its canonical JSON string, exactly as
 * the historical TypeScript producer did. The PayloadSize from the input is
 * preserved (it was computed by the producer); callers that build fresh
 * transactions should use `payloadSizeBytes` to compute it.
 */
export function serializeUnsignedTransaction(tx: CanonicalUnsignedTransaction): string {
  return JSON.stringify({
    TransactionId: tx.TransactionId,
    PayloadKind: tx.PayloadKind,
    TransactionTimeStamp: tx.TransactionTimeStamp,
    Payload: tx.Payload,
    PayloadSize: tx.PayloadSize,
  });
}

/** Canonical UTF-8 bytes of a transaction JSON string. */
export function canonicalBytes(json: string): Uint8Array {
  return utf8Bytes(json);
}
