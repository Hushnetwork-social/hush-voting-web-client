/**
 * FEAT-017 Task 2.4 — page-safe confirmed-upgrade snapshot vocabulary tests.
 *
 * Proves the closed upgrade-operation status/identity vocabulary supports the
 * five operation snapshots (pending, delayed, stale, local-success,
 * competing-activation) without authorization fields: the builder rejects
 * impossible combinations, guards recognize only the closed values, and the
 * serialized snapshot shape structurally excludes exact bytes, signatures,
 * key material, journal state, custody bindings, vault handles, endpoints,
 * and free-form server text.
 */

import { describe, expect, it } from 'vitest';
import {
  LICENCE_UPGRADE_OPERATION_STATUSES,
  buildLicenceUpgradeSafeOperation,
  isLicenceUpgradeOperationStatus,
  isLicenceUpgradeStaleReason,
  type LicenceUpgradeOperationIdentity,
  type LicenceUpgradeSafeOperation,
} from './session-contract';

const CATALOGUE_V1 = 'hushvoting-licence-catalogue/v1.0.0';

function operationIdentity(): LicenceUpgradeOperationIdentity {
  return {
    pendingTransactionId: '8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55',
    expectedCurrentPlanId: 'hushvoting.direct.free',
    targetPlanId: 'hushvoting.veritas.2000',
    observedCatalogueVersion: CATALOGUE_V1,
    sealedAtUtc: '2026-09-07T14:00:00.000Z',
  };
}

/** Serialization used by privacy scans: page-visible shape only. */
function snapshotPublicJson(snapshot: LicenceUpgradeSafeOperation): string {
  return JSON.stringify(snapshot);
}

describe('FEAT-017 upgrade operation status vocabulary', () => {
  it('pins exactly the five closed operation statuses', () => {
    expect(LICENCE_UPGRADE_OPERATION_STATUSES).toEqual([
      'pending',
      'delayed',
      'stale',
      'local-success',
      'competing-activation',
    ]);
  });

  it('recognizes only the closed statuses and stale reasons', () => {
    for (const status of LICENCE_UPGRADE_OPERATION_STATUSES) {
      expect(isLicenceUpgradeOperationStatus(status)).toBe(true);
    }
    for (const bad of ['resolved', 'active', 'cancelled', '', 42, null, undefined]) {
      expect(isLicenceUpgradeOperationStatus(bad)).toBe(false);
    }
    for (const reason of ['current-changed', 'catalogue-changed', 'stale-rejection']) {
      expect(isLicenceUpgradeStaleReason(reason)).toBe(true);
    }
    expect(isLicenceUpgradeStaleReason('plan-changed')).toBe(false);
  });
});

describe('buildLicenceUpgradeSafeOperation', () => {
  it('builds pending/delayed snapshots only with a sealed operation identity', () => {
    for (const status of ['pending', 'delayed'] as const) {
      const built = buildLicenceUpgradeSafeOperation({
        status,
        operation: operationIdentity(),
        currentPlanId: 'hushvoting.direct.free',
        currentPlanDisplayName: 'HushVoting! Direct Free',
        targetPlanDisplayName: 'HushVoting! Veritas 2k',
      });
      expect(built.ok).toBe(true);
      if (built.ok) {
        expect(built.snapshot.status).toBe(status);
        expect(built.snapshot.kind).toBe('licence-upgrade-safe-operation');
        expect(built.snapshot.operation?.targetPlanId).toBe('hushvoting.veritas.2000');
      }
      // No operation identity => impossible lifecycle snapshot rejected.
      expect(buildLicenceUpgradeSafeOperation({ status, operation: null })).toEqual({
        ok: false,
        reason: 'invalid-input',
      });
    }
  });

  it('builds a stale snapshot only with a closed reason', () => {
    const stale = buildLicenceUpgradeSafeOperation({
      status: 'stale',
      reason: 'current-changed',
      operation: null,
      currentPlanId: 'hushvoting.veritas.500',
      currentPlanDisplayName: 'HushVoting! Veritas 500',
    });
    expect(stale.ok).toBe(true);
    if (stale.ok) {
      expect(stale.snapshot.status).toBe('stale');
      if (stale.snapshot.status === 'stale') {
        expect(stale.snapshot.reason).toBe('current-changed');
      }
    }
    expect(
      buildLicenceUpgradeSafeOperation({ status: 'stale', reason: 'unknown-reason' as never }),
    ).toEqual({ ok: false, reason: 'invalid-input' });
    expect(buildLicenceUpgradeSafeOperation({ status: 'stale' })).toEqual({
      ok: false,
      reason: 'invalid-input',
    });
    // reason is not legal on non-stale arms.
    expect(
      buildLicenceUpgradeSafeOperation({
        status: 'pending',
        operation: operationIdentity(),
        reason: 'current-changed',
      }),
    ).toEqual({ ok: false, reason: 'invalid-input' });
  });

  it('builds resolved snapshots (local-success / competing-activation)', () => {
    const local = buildLicenceUpgradeSafeOperation({
      status: 'local-success',
      operation: operationIdentity(),
      currentPlanId: 'hushvoting.veritas.2000',
      currentPlanDisplayName: 'HushVoting! Veritas 2k',
      targetPlanDisplayName: 'HushVoting! Veritas 2k',
    });
    expect(local.ok).toBe(true);
    if (local.ok) {
      expect(local.snapshot.status).toBe('local-success');
      expect(local.snapshot.currentPlanId).toBe('hushvoting.veritas.2000');
    }

    const competing = buildLicenceUpgradeSafeOperation({
      status: 'competing-activation',
      operation: null,
      currentPlanId: 'hushvoting.veritas.10000',
      currentPlanDisplayName: 'HushVoting! Veritas 10k',
    });
    expect(competing.ok).toBe(true);
    if (competing.ok) {
      expect(competing.snapshot.status).toBe('competing-activation');
      expect(competing.snapshot.operation).toBeNull();
    }
  });
});

describe('snapshot privacy boundary (no authorization fields)', () => {
  it('serialized snapshots never carry exact bytes, signatures, bindings, or journal state', () => {
    const built = buildLicenceUpgradeSafeOperation({
      status: 'pending',
      operation: operationIdentity(),
      currentPlanId: 'hushvoting.direct.free',
      currentPlanDisplayName: 'HushVoting! Direct Free',
      targetPlanDisplayName: 'HushVoting! Veritas 2k',
    });
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    const serialized = snapshotPublicJson(built.snapshot);
    for (const forbidden of [
      'exactJson',
      'digest',
      'signature',
      'UserSignature',
      'identityBinding',
      'networkBinding',
      'targetBinding',
      'recoveryState',
      'attemptEvidence',
      'vaultHandle',
      'endpoint',
      'serverMessage',
      'password',
      'mnemonic',
      'privateKey',
      'TransitionIntent',
    ]) {
      expect(serialized).not.toContain(forbidden);
    }
    // Only safe identity/display members survive serialization.
    const shape = JSON.parse(serialized) as Record<string, unknown>;
    expect(Object.keys(shape).sort()).toEqual([
      'currentPlanDisplayName',
      'currentPlanId',
      'kind',
      'operation',
      'status',
      'targetPlanDisplayName',
    ]);
  });

  it('an operation identity serializes only safe public members', () => {
    const identity = operationIdentity();
    const serialized = JSON.stringify(identity);
    expect(Object.keys(identity).sort()).toEqual([
      'expectedCurrentPlanId',
      'observedCatalogueVersion',
      'pendingTransactionId',
      'sealedAtUtc',
      'targetPlanId',
    ]);
    for (const forbidden of ['identity', 'network', 'signature', 'digest', 'binding', 'exact']) {
      expect(serialized).not.toContain(forbidden);
    }
  });
});
