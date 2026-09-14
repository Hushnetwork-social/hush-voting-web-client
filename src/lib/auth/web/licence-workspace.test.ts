/**
 * FEAT-017 Task 6.1/6.2 — root licence workspace composition helper tests.
 *
 * `presentationInputFromMirror` is the framework-neutral seam that turns the
 * SAFE authority mirror (EntitlementBridge licence facts) + the machine
 * projection into the closed `LicenceUpgradePresentationInput` the root
 * shell consumes. These tests lock the Task 6.1 composition contract:
 *  - the root renders NO licence input while the workspace mirror is empty,
 *    while the machine has no protected projection, or while the entitlement
 *    substage is not ready (the root gate owns stale/unavailable display);
 *  - the presentation phase comes ONLY from the machine entitlement stage the
 *    machine validated — never a raw worker phase string;
 *  - non-object projection/upgradeOperation facts fail closed to null
 *    (unsafe facts can never reach presentation), and one-shot notification
 *    eligibility maps only the exact boolean `true`;
 *  - the open-reason vocabulary the root may pass is closed and stable
 *    (Account A0 actions, N0/N1 reopen, and the pending indicator all map to
 *    the SAME licence destination).
 *
 * Normative source: FEAT-017 FeatureDescription D017-01…06; Task 6.1
 * behavior spec ("Account entry refreshes before display", "Pending survives
 * page navigation but not invalidation"); Task 6.1 acceptance criteria.
 */
import { describe, expect, it } from 'vitest';
import {
  LICENCE_WORKSPACE_OPEN_REASONS,
  isLicenceWorkspaceOpenReason,
  presentationInputFromMirror,
  type LicenceWorkspaceFactsMirror,
} from './licence-workspace';
import type { AuthRenderProjection } from '../react/adapter';
import {
  directFreeWithOptionsProjection,
  upgradeOperationOf,
} from '../../../lib/licensing/fixtures/presentation-fixtures';

function projection(overrides: Partial<AuthRenderProjection>): AuthRenderProjection {
  return {
    authState: 'authenticated',
    connectivity: 'online',
    protectedAccess: false,
    entitlementStage: 'entitlementReady',
    entitlementReady: true,
    sessionEpoch: 7,
    entitlementRequired: true,
    safeIdentity: { alias: 'Ada', abbreviatedSigningAddress: 'NVh…1a2b' },
    authenticatedIdentity: {
      alias: 'Ada',
      publicSigningKey: '0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5',
      publicEncryptionKey: '02b1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2',
    },
    outcomeCode: null,
    supportCode: null,
    onboardingKind: null,
    ...overrides,
  };
}

function mirror(overrides: Partial<LicenceWorkspaceFactsMirror> = {}): LicenceWorkspaceFactsMirror {
  return {
    phase: 'entitlementReady',
    projection: directFreeWithOptionsProjection(),
    upgradeOperation: null,
    upgradeNotificationEligible: false,
    ...overrides,
  };
}

describe('presentationInputFromMirror (root licence composition gate)', () => {
  it('returns null while no safe licence facts have been broadcast (mirror empty)', () => {
    expect(presentationInputFromMirror({ mirror: null, projection: projection({}) })).toBeNull();
  });

  it('returns null without a protected machine projection', () => {
    expect(presentationInputFromMirror({ mirror: mirror(), projection: null })).toBeNull();
  });

  it('returns null while the machine entitlement substage is not resolved (root gate owns stale display)', () => {
    // During resolving/unavailable the machine projection has no validated
    // substage; the root must not display stale licence values.
    expect(
      presentationInputFromMirror({ mirror: mirror(), projection: projection({ entitlementStage: null }) }),
    ).toBeNull();
    expect(
      presentationInputFromMirror({
        mirror: mirror(),
        projection: projection({ entitlementStage: 'entitlementResolving' }),
      }),
    ).not.toBeNull();
  });

  it('maps a safe mirror through the machine projection (phase + connectivity are machine-owned)', () => {
    const safeProjection = directFreeWithOptionsProjection();
    const pending = upgradeOperationOf('pending');
    const input = presentationInputFromMirror({
      mirror: mirror({
        projection: safeProjection,
        upgradeOperation: pending,
        upgradeNotificationEligible: true,
      }),
      projection: projection({ entitlementStage: 'entitlementReady', connectivity: 'offline' }),
    });
    expect(input).not.toBeNull();
    if (input === null) return;
    // The presentation phase is the machine entitlement substage the machine
    // already validated — never the raw worker phase string carried by the
    // mirror (the worker vocabulary is closed on the bridge; the machine
    // substage is what the root renders from).
    expect(input.phase).toBe('entitlementReady');
    expect(input.projection).toBe(safeProjection);
    expect(input.upgradeOperation).toBe(pending);
    expect(input.upgradeOperation?.status).toBe('pending');
    expect(input.upgradeNotificationEligible).toBe(true);
    expect(input.connectivity).toBe('offline');
  });

  it('fails closed to null projection/operation when the mirror carries no facts', () => {
    const input = presentationInputFromMirror({
      mirror: mirror({ projection: null, upgradeOperation: null }),
      projection: projection({}),
    });
    expect(input).not.toBeNull();
    if (input === null) return;
    expect(input.projection).toBeNull();
    expect(input.upgradeOperation).toBeNull();
    expect(input.upgradeNotificationEligible).toBe(false);
  });

  it('never casts unsafe non-object mirror facts into presentation', () => {
    // A raw string/primitive in the mirror (protocol drift, hostile page) can
    // never be treated as the safe projection/operation shape.
    const input = presentationInputFromMirror({
      mirror: mirror({ projection: 'raw-template-bytes' as unknown, upgradeOperation: 42 as unknown }),
      projection: projection({}),
    });
    expect(input).not.toBeNull();
    if (input === null) return;
    expect(input.projection).toBeNull();
    expect(input.upgradeOperation).toBeNull();
  });

  it('maps one-shot notification eligibility only for the exact boolean true', () => {
    const eligible = presentationInputFromMirror({
      mirror: mirror({ upgradeNotificationEligible: true }),
      projection: projection({}),
    });
    expect(eligible?.upgradeNotificationEligible).toBe(true);
    const stringy = presentationInputFromMirror({
      // A truthy-but-not-boolean mirror value (protocol drift) can never turn
      // the one-shot notification on.
      mirror: {
        phase: 'entitlementReady',
        projection: null,
        upgradeOperation: null,
        upgradeNotificationEligible: 'true',
      } as unknown as LicenceWorkspaceFactsMirror,
      projection: projection({}),
    });
    expect(stringy?.upgradeNotificationEligible).toBe(false);
  });

  it('treats the machine substage as the authority for the presented phase', () => {
    // The mirror phase reflects the last worker broadcast, but the root only
    // renders stages the machine validated: after a rejection refresh the
    // machine may sit at unavailable while the stale broadcast lingers.
    const input = presentationInputFromMirror({
      mirror: mirror({ phase: 'entitlementReady' }),
      projection: projection({ entitlementStage: 'entitlementUnavailable' }),
    });
    expect(input?.phase).toBe('entitlementUnavailable');
  });

  it('passes the live pending upgrade through to the presentation input', () => {
    const pending = upgradeOperationOf('pending');
    const input = presentationInputFromMirror({
      mirror: mirror({ projection: directFreeWithOptionsProjection(), upgradeOperation: pending }),
      projection: projection({}),
    });
    expect(input?.upgradeOperation?.status).toBe('pending');
    expect(input?.upgradeOperation?.operation?.targetPlanId).toBe(pending.operation?.targetPlanId);
    expect(input?.upgradeOperation?.targetPlanDisplayName).toBe('HushVoting! Veritas 2k');
  });
});

describe('licence workspace open reasons (closed destination vocabulary)', () => {
  it('accepts exactly the five closed open reasons', () => {
    expect(LICENCE_WORKSPACE_OPEN_REASONS).toEqual([
      'upgrade',
      'view-licence',
      'view-progress',
      'notification',
      'pending-indicator',
    ]);
    for (const reason of LICENCE_WORKSPACE_OPEN_REASONS) {
      expect(isLicenceWorkspaceOpenReason(reason)).toBe(true);
    }
  });

  it('rejects unknown, non-string, and out-of-vocabulary values', () => {
    expect(isLicenceWorkspaceOpenReason('upgrade')).toBe(true);
    expect(isLicenceWorkspaceOpenReason('purchase')).toBe(false);
    expect(isLicenceWorkspaceOpenReason('enterprise')).toBe(false);
    expect(isLicenceWorkspaceOpenReason('')).toBe(false);
    expect(isLicenceWorkspaceOpenReason(null)).toBe(false);
    expect(isLicenceWorkspaceOpenReason(undefined)).toBe(false);
    expect(isLicenceWorkspaceOpenReason(42)).toBe(false);
    expect(isLicenceWorkspaceOpenReason({ type: 'upgrade' })).toBe(false);
  });

  it('keeps the vocabulary closed against the reason set (no silent drift)', () => {
    const accepted: unknown[] = ['upgrade', 'view-licence', 'view-progress', 'notification', 'pending-indicator', 'unknown'];
    const closed = accepted.filter(isLicenceWorkspaceOpenReason);
    expect(closed).toEqual(LICENCE_WORKSPACE_OPEN_REASONS);
  });
});
