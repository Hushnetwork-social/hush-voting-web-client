/**
 * FEAT-016 Task 2.1/2.2 — pinned canonical fixture vectors (TS mirror).
 *
 * Byte-exact embedding of the public FEAT-015 synthetic canonical corpus
 * (`HushNode.HushVoting.Licence.Transactions/Fixtures/v1.0.0/licence-transaction-vectors.json`)
 * plus the frozen signed-query envelope vector locked by the server contract
 * tests. Provenance: generated from `hush-server-node` FEAT-015 assets on
 * 2026-09-06; never edit the digest values — the fixture tests assert them.
 */

import type { LicencePayload } from '../canonical';

export const LICENCE_PAYLOAD_KIND = '71370664-5eb4-4ce9-b96a-d7e7ffe53db5';
export const LICENCE_CATALOGUE_VERSION_V1 = 'hushvoting-licence-catalogue/v1.0.0';
export const LICENCE_PLAN_DIRECT_FREE = 'hushvoting.direct.free';

/** Frozen query envelope fixture (server contract test vector). */
export const QUERY_FIXTURE_ACTOR = '0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5';
export const QUERY_FIXTURE_SIGNED_AT = '2026-09-06T00:00:00Z';
export const QUERY_FIXTURE_EXPECTED_CANONICAL_JSON =
  '{"actorAddress":"0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5",' +
  '"method":"GetMyEntitlement","request":{},"signedAt":"2026-09-06T00:00:00Z"}';

/** Canonical fixed inputs shared by the transaction vectors. */
export const LICENCE_FIXED_TIMESTAMP = '2026-09-06T00:00:00.000Z';
export const LICENCE_FIXED_BASELINE_TRANSACTION_ID = '5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e';
export const LICENCE_FIXED_UPGRADE_TRANSACTION_ID = '8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55';

export interface LicenceTransactionVector {
  readonly id: string;
  readonly case: string;
  readonly intent: string;
  readonly transactionId: string;
  readonly payload: LicencePayload;
  readonly payloadSizeBytes: number;
  readonly utf8Bytes: number;
  readonly sha256Hex: string;
}

export const LICENCE_TRANSACTION_VECTORS: ReadonlyArray<LicenceTransactionVector> = [
  {
    id: 'LIC-FIX-001',
    case: 'baseline_direct_free',
    intent: 'baseline_free',
    transactionId: LICENCE_FIXED_BASELINE_TRANSACTION_ID,
    payload: {
      TransitionIntent: 'baseline_free',
      RequestedPlanId: LICENCE_PLAN_DIRECT_FREE,
      ObservedCatalogueVersion: LICENCE_CATALOGUE_VERSION_V1,
    },
    payloadSizeBytes: 144,
    utf8Bytes: 332,
    sha256Hex: 'a7e344b590e2eebc8b29d3b09fba0178e66e61a810756ae50a7942f4a76cd993',
  },
  {
    id: 'LIC-FIX-002',
    case: 'confirmed_upgrade_veritas2000',
    intent: 'confirmed_upgrade',
    transactionId: LICENCE_FIXED_UPGRADE_TRANSACTION_ID,
    payload: {
      TransitionIntent: 'confirmed_upgrade',
      RequestedPlanId: 'hushvoting.veritas.2000',
      ObservedCatalogueVersion: LICENCE_CATALOGUE_VERSION_V1,
      ExpectedCurrentLicenceTransactionId: LICENCE_FIXED_BASELINE_TRANSACTION_ID,
      ExpectedCurrentPlanId: LICENCE_PLAN_DIRECT_FREE,
    },
    payloadSizeBytes: 275,
    utf8Bytes: 463,
    sha256Hex: '27a380b4242bb06d3c6068953fff31f0a6179c0b80e73631e3b47b9ddcbe2cd0',
  },
  {
    id: 'LIC-FIX-003',
    case: 'one_byte_tamper_baseline',
    intent: 'baseline_free',
    transactionId: LICENCE_FIXED_BASELINE_TRANSACTION_ID,
    payload: {
      TransitionIntent: 'baseline_free',
      RequestedPlanId: 'hushvoting.direct.fred', // one-byte tamper; never valid
      ObservedCatalogueVersion: LICENCE_CATALOGUE_VERSION_V1,
    },
    payloadSizeBytes: 144,
    utf8Bytes: 332,
    sha256Hex: '901d5b8b377d2c3def446d2bff22ccc224e91242df3875d384bf313a9ab548aa',
  },
];

/** Canonical unsigned JSON for a vector (writer must reproduce byte-exact). */
export function vectorExpectedUnsignedJson(vector: LicenceTransactionVector): string {
  return (
    '{"TransactionId":"' +
    vector.transactionId +
    '","PayloadKind":"' +
    LICENCE_PAYLOAD_KIND +
    '","TransactionTimeStamp":"' +
    LICENCE_FIXED_TIMESTAMP +
    '","Payload":' +
    JSON.stringify(vector.payload) +
    ',"PayloadSize":' +
    vector.payloadSizeBytes +
    '}'
  );
}
