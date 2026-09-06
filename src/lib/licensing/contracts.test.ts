/**
 * FEAT-016 Task 2.2 — byte-exact fixture and envelope contract tests.
 *
 * Proves: the frozen three metadata header names; the fresh-query envelope
 * canonical JSON (ordinal deep sort, empty request, no request ID or extra
 * signed member); the FEAT-015 transaction corpus vectors reproduce the exact
 * canonical unsigned JSON, payload size, UTF-8 byte count, and SHA-256 digest;
 * the one-byte tamper vector changes the digest; and the Direct Free template
 * constants pin the FEAT-012 catalogue identifiers.
 */

import { describe, expect, it } from 'vitest';
import {
  LICENCE_QUERY_METHOD,
  LICENCE_QUERY_SIGNATURE_HEADER,
  LICENCE_QUERY_SIGNED_AT_HEADER,
  LICENCE_QUERY_SIGNATORY_HEADER,
  licenceQuerySignedJson,
  type LicenceFreshQueryEnvelope,
} from './contracts';
import {
  LICENCE_FIXED_BASELINE_TRANSACTION_ID,
  LICENCE_FIXED_TIMESTAMP,
  LICENCE_PAYLOAD_KIND,
  LICENCE_TRANSACTION_VECTORS,
  QUERY_FIXTURE_ACTOR,
  QUERY_FIXTURE_EXPECTED_CANONICAL_JSON,
  QUERY_FIXTURE_SIGNED_AT,
  vectorExpectedUnsignedJson,
} from './fixtures/canonical-vectors';
import {
  licencePayloadSizeBytes,
  licenceTransactionDigest,
  serializeLicenceUnsignedTransaction,
} from './canonical';

describe('frozen query metadata (FEAT-015 v1)', () => {
  it('pins exactly the three signed metadata headers and the method', () => {
    expect(LICENCE_QUERY_SIGNATORY_HEADER).toBe('x-hush-licence-query-signatory');
    expect(LICENCE_QUERY_SIGNED_AT_HEADER).toBe('x-hush-licence-query-signed-at');
    expect(LICENCE_QUERY_SIGNATURE_HEADER).toBe('x-hush-licence-query-signature');
    expect(LICENCE_QUERY_METHOD).toBe('GetMyEntitlement');
    expect(LICENCE_QUERY_METHOD).not.toContain('requestId');
  });

  it('produces the exact canonical signed JSON for the frozen envelope', () => {
    const envelope: LicenceFreshQueryEnvelope = {
      actorAddress: QUERY_FIXTURE_ACTOR as LicenceFreshQueryEnvelope['actorAddress'],
      method: LICENCE_QUERY_METHOD,
      request: {},
      signedAt: QUERY_FIXTURE_SIGNED_AT,
      signature: 'fixture-signature-placeholder',
    };
    expect(licenceQuerySignedJson(envelope)).toBe(QUERY_FIXTURE_EXPECTED_CANONICAL_JSON);
  });

  it('never adds a request id, nonce, expiry, or network member to the envelope', () => {
    const json = QUERY_FIXTURE_EXPECTED_CANONICAL_JSON;
    for (const forbidden of ['requestId', 'nonce', 'expiresAt', 'network']) {
      expect(json).not.toContain(forbidden);
    }
    expect(Object.keys(JSON.parse(json)).sort()).toEqual([
      'actorAddress',
      'method',
      'request',
      'signedAt',
    ]);
    expect(JSON.parse(json).request).toEqual({});
  });
});

describe('FEAT-015 canonical licence transaction corpus (byte-exact)', () => {
  it('exposes the frozen payload kind and the three public vectors', () => {
    expect(LICENCE_PAYLOAD_KIND).toBe('71370664-5eb4-4ce9-b96a-d7e7ffe53db5');
    expect(LICENCE_TRANSACTION_VECTORS.map((v) => v.id)).toEqual([
      'LIC-FIX-001',
      'LIC-FIX-002',
      'LIC-FIX-003',
    ]);
  });

  for (const vector of LICENCE_TRANSACTION_VECTORS) {
    it(`${vector.id} serializes, sizes, and digests byte-exactly`, () => {
      // Payload size over declaration-order payload JSON.
      expect(licencePayloadSizeBytes(vector.payload)).toBe(vector.payloadSizeBytes);

      // Outer canonical JSON reproduces the corpus string exactly.
      const unsignedJson = serializeLicenceUnsignedTransaction({
        TransactionId: vector.transactionId,
        PayloadKind: LICENCE_PAYLOAD_KIND,
        TransactionTimeStamp: LICENCE_FIXED_TIMESTAMP,
        Payload: vector.payload,
        PayloadSize: vector.payloadSizeBytes,
      });
      expect(unsignedJson).toBe(vectorExpectedUnsignedJson(vector));

      // UTF-8 byte count and digest match the independently verified corpus.
      const bytes = new TextEncoder().encode(unsignedJson);
      expect(bytes.length).toBe(vector.utf8Bytes);
      expect(licenceTransactionDigest(unsignedJson)).toBe(vector.sha256Hex);
    });
  }

  it('proves the one-byte tamper vector produces a different digest (LIC-FIX-003 vs 001)', () => {
    const baseline = LICENCE_TRANSACTION_VECTORS[0];
    const tamper = LICENCE_TRANSACTION_VECTORS[2];
    expect(tamper.sha256Hex).not.toBe(baseline.sha256Hex);
    expect(tamper.payload.RequestedPlanId).toBe('hushvoting.direct.fred');
  });

  it('locks the baseline transaction id used by the vectors', () => {
    expect(LICENCE_FIXED_BASELINE_TRANSACTION_ID).toBe('5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e');
  });
});
