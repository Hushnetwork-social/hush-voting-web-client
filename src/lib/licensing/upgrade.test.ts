/**
 * FEAT-017 Task 3.2 — confirmed-upgrade construction and binding policy tests.
 *
 * Proves the closed `confirmed_upgrade` envelope builder is byte-exact against
 * the frozen FEAT-015 corpus (LIC-FIX-002), rejects every catalogue-independent
 * unsafe input before signing (self-target, Direct Free, alias, malformed
 * current/transaction/timestamp, non-v1 catalogue), and exposes the purpose
 * coherence guard (an upgrade-intent record without its binding is never
 * submitable as a baseline — Phase 2 review recommendation #3) plus the
 * display-name resolution rule (only validated fresh data at snapshot time —
 * recommendation #4).
 */

import { describe, expect, it } from 'vitest';
import {
  LICENCE_TRANSACTION_VECTORS,
  LICENCE_FIXED_BASELINE_TRANSACTION_ID,
  LICENCE_FIXED_TIMESTAMP,
  LICENCE_FIXED_UPGRADE_TRANSACTION_ID,
  vectorExpectedUnsignedJson,
} from './fixtures/canonical-vectors';
import { buildDirectFreeUnsignedTransaction } from './direct-free';
import type { LicencePendingTransactionRecord } from './pending-transaction';
import type { LicenceSafeProjection } from './projection';
import {
  buildConfirmedUpgradeUnsignedTransaction,
  isBoundedPlanId,
  isPendingRecordPurposeCoherent,
  licenceTransitionIntentOfPendingRecord,
  resolveUpgradeTargetDisplayName,
} from './upgrade';

const CATALOGUE_V1 = 'hushvoting-licence-catalogue/v1.0.0';
const EXPECTED_CURRENT = LICENCE_FIXED_BASELINE_TRANSACTION_ID;
const EXPECTED_CURRENT_PLAN = 'hushvoting.direct.free';
const TARGET_PLAN = 'hushvoting.veritas.2000';

function validInput(overrides: Partial<Parameters<typeof buildConfirmedUpgradeUnsignedTransaction>[0]> = {}) {
  return {
    expectedCurrentLicenceTransactionId: EXPECTED_CURRENT,
    expectedCurrentPlanId: EXPECTED_CURRENT_PLAN,
    requestedPlanId: TARGET_PLAN,
    observedCatalogueVersion: CATALOGUE_V1,
    transactionId: LICENCE_FIXED_UPGRADE_TRANSACTION_ID,
    transactionTimestampUtc: LICENCE_FIXED_TIMESTAMP,
    ...overrides,
  };
}

describe('buildConfirmedUpgradeUnsignedTransaction', () => {
  it('reproduces the frozen LIC-FIX-002 confirmed_upgrade envelope byte-exactly', () => {
    const vector = LICENCE_TRANSACTION_VECTORS[1];
    expect(vector.case).toBe('confirmed_upgrade_veritas2000');
    const built = buildConfirmedUpgradeUnsignedTransaction(validInput());
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    expect(built.payload).toEqual(vector.payload);
    expect(built.payloadSize).toBe(275);
    expect(built.canonicalUnsignedJson).toBe(vectorExpectedUnsignedJson(vector));
    expect(built.digest).toBe(vector.sha256Hex);
  });

  it('emits the payload in the frozen FEAT-015 declaration order', () => {
    const built = buildConfirmedUpgradeUnsignedTransaction(validInput());
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    const payloadOrder = Object.keys(JSON.parse(JSON.stringify(built.payload)) as Record<string, unknown>);
    expect(payloadOrder).toEqual([
      'TransitionIntent',
      'RequestedPlanId',
      'ObservedCatalogueVersion',
      'ExpectedCurrentLicenceTransactionId',
      'ExpectedCurrentPlanId',
    ]);
  });

  it('rejects a non-UUID or unbounded expected current reference', () => {
    expect(
      buildConfirmedUpgradeUnsignedTransaction(
        validInput({ expectedCurrentLicenceTransactionId: 'not-a-uuid' }),
      ),
    ).toEqual({ ok: false, reason: 'malformed-current-reference' });
    expect(
      buildConfirmedUpgradeUnsignedTransaction(
        validInput({ expectedCurrentLicenceTransactionId: 'x'.repeat(200) }),
      ),
    ).toEqual({ ok: false, reason: 'malformed-current-reference' });
  });

  it('rejects self-target and Direct Free upgrade targets', () => {
    expect(
      buildConfirmedUpgradeUnsignedTransaction(
        validInput({ requestedPlanId: EXPECTED_CURRENT_PLAN }),
      ),
    ).toEqual({ ok: false, reason: 'self-target-or-direct-free' });
    expect(
      buildConfirmedUpgradeUnsignedTransaction(
        validInput({ requestedPlanId: 'hushvoting.direct.free' }),
      ),
    ).toEqual({ ok: false, reason: 'self-target-or-direct-free' });
  });

  it('rejects empty/unbounded plan ids', () => {
    expect(
      buildConfirmedUpgradeUnsignedTransaction(validInput({ requestedPlanId: '' })),
    ).toEqual({ ok: false, reason: 'malformed-plan-id' });
    expect(
      buildConfirmedUpgradeUnsignedTransaction(
        validInput({ expectedCurrentPlanId: 'y'.repeat(200) }),
      ),
    ).toEqual({ ok: false, reason: 'malformed-plan-id' });
  });

  it('rejects non-v1 and unbounded catalogue releases', () => {
    expect(
      buildConfirmedUpgradeUnsignedTransaction(
        validInput({ observedCatalogueVersion: 'hushvoting-licence-catalogue/v9.0.0' }),
      ),
    ).toEqual({ ok: false, reason: 'stale-or-unbounded-catalogue' });
    expect(
      buildConfirmedUpgradeUnsignedTransaction(
        validInput({ observedCatalogueVersion: '' }),
      ),
    ).toEqual({ ok: false, reason: 'stale-or-unbounded-catalogue' });
  });

  it('rejects a new transaction id that aliases the expected old reference', () => {
    expect(
      buildConfirmedUpgradeUnsignedTransaction(
        validInput({ transactionId: EXPECTED_CURRENT }),
      ),
    ).toEqual({ ok: false, reason: 'alias-new-transaction' });
    expect(
      buildConfirmedUpgradeUnsignedTransaction(validInput({ transactionId: 'not-a-uuid' })),
    ).toEqual({ ok: false, reason: 'malformed-transaction-id' });
  });

  it('rejects malformed transaction timestamps', () => {
    expect(
      buildConfirmedUpgradeUnsignedTransaction(
        validInput({ transactionTimestampUtc: '2026-09-06' }),
      ),
    ).toEqual({ ok: false, reason: 'malformed-timestamp' });
    expect(
      buildConfirmedUpgradeUnsignedTransaction(
        validInput({ transactionTimestampUtc: '2026-09-06T00:00:00+01:00' }),
      ),
    ).toEqual({ ok: false, reason: 'malformed-timestamp' });
  });
});

function envelopeRecord(exactJson: string, binding?: LicencePendingTransactionRecord['upgradeBinding']): LicencePendingTransactionRecord {
  return {
    schemaVersion: 1,
    purpose: 'pending_licence_transaction',
    transaction: { exactJson, digest: 'a'.repeat(64) },
    transactionId: LICENCE_FIXED_UPGRADE_TRANSACTION_ID,
    identityBinding: 'actor',
    networkBinding: 'network',
    targetBinding: 'web-sharedworker',
    createdUtc: LICENCE_FIXED_TIMESTAMP,
    attemptEvidence: [],
    recoveryState: 'sealed',
    ...(binding === undefined ? {} : { upgradeBinding: binding }),
  };
}

function upgradeEnvelopeJson(): string {
  const built = buildConfirmedUpgradeUnsignedTransaction(validInput());
  if (!built.ok) throw new Error('fixture build failed');
  return built.canonicalUnsignedJson;
}

function baselineEnvelopeJson(): string {
  const built = buildDirectFreeUnsignedTransaction(
    {
      TransitionIntent: 'baseline_free',
      RequestedPlanId: 'hushvoting.direct.free',
      ObservedCatalogueVersion: CATALOGUE_V1,
    },
    LICENCE_FIXED_BASELINE_TRANSACTION_ID,
    LICENCE_FIXED_TIMESTAMP,
  );
  if (!built.ok) throw new Error('fixture build failed');
  return built.canonicalUnsignedJson;
}

const UPGRADE_BINDING: LicencePendingTransactionRecord['upgradeBinding'] = {
  kind: 'confirmed_upgrade',
  expectedCurrentLicenceTransactionId: EXPECTED_CURRENT,
  expectedCurrentPlanId: EXPECTED_CURRENT_PLAN,
  requestedPlanId: TARGET_PLAN,
  observedCatalogueVersion: CATALOGUE_V1,
};

describe('licenceTransitionIntentOfPendingRecord + purpose coherence', () => {
  it('reads the frozen payload intent of upgrade and baseline envelopes', () => {
    const upgrade = envelopeRecord(upgradeEnvelopeJson(), UPGRADE_BINDING);
    expect(licenceTransitionIntentOfPendingRecord(upgrade)).toBe('confirmed_upgrade');
    const baseline = envelopeRecord(baselineEnvelopeJson());
    expect(licenceTransitionIntentOfPendingRecord(baseline)).toBe('baseline_free');
    expect(licenceTransitionIntentOfPendingRecord(envelopeRecord('not-json'))).toBeNull();
  });

  it('an upgrade-intent record without its binding is never submitable as a baseline', () => {
    // Phase 2 review recommendation #3: opening an upgrade payload without the
    // binding must fail closed — the record codec would read it as a baseline.
    expect(isPendingRecordPurposeCoherent(envelopeRecord(upgradeEnvelopeJson()))).toBe(false);
    expect(
      isPendingRecordPurposeCoherent(envelopeRecord(upgradeEnvelopeJson(), UPGRADE_BINDING)),
    ).toBe(true);
  });

  it('baseline records are coherent only without a binding; corrupt envelopes never submit', () => {
    expect(isPendingRecordPurposeCoherent(envelopeRecord(baselineEnvelopeJson()))).toBe(true);
    expect(
      isPendingRecordPurposeCoherent(envelopeRecord(baselineEnvelopeJson(), UPGRADE_BINDING)),
    ).toBe(false);
    expect(isPendingRecordPurposeCoherent(envelopeRecord('{broken'))).toBe(false);
  });
});

describe('resolveUpgradeTargetDisplayName (fresh-data-only display resolution)', () => {
  function projection(overrides: Partial<LicenceSafeProjection> = {}): LicenceSafeProjection {
    return {
      kind: 'licence-safe-projection',
      schemaVersion: 1,
      identityBinding: 'actor' as LicenceSafeProjection['identityBinding'],
      networkBinding: 'network' as LicenceSafeProjection['networkBinding'],
      licenceReference: EXPECTED_CURRENT as LicenceSafeProjection['licenceReference'],
      planId: 'hushvoting.veritas.500',
      planFamily: 'veritas',
      displayName: 'HushVoting! Veritas 500',
      safeDescription: 'Veritas 500 licence',
      effectiveFromUtc: '2026-01-01T00:00:00.000Z',
      termKind: 'annual',
      termYears: 1,
      eligibleVoterCap: 500,
      unlimitedElections: false,
      allowedGovernanceOptionIds: [],
      catalogueVersion: CATALOGUE_V1,
      higherOptions: [
        {
          planId: TARGET_PLAN,
          displayName: 'HushVoting! Veritas 2k',
          safeDescription: 'Annual Veritas 2000 licence',
          eligibleVoterCap: 2000,
          unlimitedElections: true,
          termKind: 'annual',
          termYears: 1,
        },
      ],
      enterprise: null,
      provenance: 'indexed-query',
      ...overrides,
    };
  }

  it('resolves an offered target from its validated server option copy', () => {
    expect(resolveUpgradeTargetDisplayName(projection(), TARGET_PLAN)).toBe('HushVoting! Veritas 2k');
  });

  it('reads a target that just became current from the fresh current display', () => {
    const upgraded = projection({
      planId: TARGET_PLAN,
      displayName: 'HushVoting! Veritas 2k',
      higherOptions: [],
    });
    expect(resolveUpgradeTargetDisplayName(upgraded, TARGET_PLAN)).toBe('HushVoting! Veritas 2k');
  });

  it('never invents copy for a target that is neither current nor offered', () => {
    expect(resolveUpgradeTargetDisplayName(projection(), 'hushvoting.veritas.10000')).toBeNull();
    expect(resolveUpgradeTargetDisplayName(null, TARGET_PLAN)).toBeNull();
  });
});

describe('isBoundedPlanId', () => {
  it('accepts bounded non-empty ids and rejects everything else', () => {
    expect(isBoundedPlanId(TARGET_PLAN)).toBe(true);
    expect(isBoundedPlanId('')).toBe(false);
    expect(isBoundedPlanId('x'.repeat(200))).toBe(false);
    expect(isBoundedPlanId(42)).toBe(false);
    expect(isBoundedPlanId(null)).toBe(false);
    expect(isBoundedPlanId(undefined)).toBe(false);
  });
});
