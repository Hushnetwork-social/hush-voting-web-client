/**
 * FEAT-016 Task 3.4 — Direct Free construction + submission policy tests.
 *
 * Proves: baseline construction accepts ONLY the server no-active template
 * (exact `baseline_free` + `hushvoting.direct.free` + observed catalogue);
 * the canonical unsigned JSON and digest are byte-exact against the FEAT-015
 * corpus (LIC-FIX-001) when the frozen fixed inputs are used; upgrade/tampered
 * templates are impossible or rejected; local/default template construction
 * cannot exist; and admission outcomes map to reconciliation decisions that
 * never grant access.
 */

import { describe, expect, it } from 'vitest';
import * as directFreeModule from './direct-free';
import {
  LICENCE_CATALOGUE_VERSION_V1,
  LICENCE_PLAN_DIRECT_FREE,
  LICENCE_TRANSITION_INTENT_BASELINE_FREE,
  type LicenceDirectFreeTemplate,
} from './contracts';
import {
  buildDirectFreeUnsignedTransaction,
  decideSubmissionOutcome,
  isSupportedCatalogueVersion,
} from './direct-free';
import {
  LICENCE_FIXED_BASELINE_TRANSACTION_ID,
  LICENCE_FIXED_TIMESTAMP,
  LICENCE_TRANSACTION_VECTORS,
  vectorExpectedUnsignedJson,
} from './fixtures/canonical-vectors';

const V1_TEMPLATE: LicenceDirectFreeTemplate = {
  TransitionIntent: LICENCE_TRANSITION_INTENT_BASELINE_FREE,
  RequestedPlanId: LICENCE_PLAN_DIRECT_FREE,
  ObservedCatalogueVersion: LICENCE_CATALOGUE_VERSION_V1,
};

describe('Direct Free construction (server template only)', () => {
  it('builds the canonical baseline byte-exactly (LIC-FIX-001 parity)', () => {
    const built = buildDirectFreeUnsignedTransaction(
      V1_TEMPLATE,
      LICENCE_FIXED_BASELINE_TRANSACTION_ID,
      LICENCE_FIXED_TIMESTAMP,
    );
    expect(built.ok).toBe(true);
    if (!built.ok) return;
    const vector = LICENCE_TRANSACTION_VECTORS[0];
    expect(built.canonicalUnsignedJson).toBe(vectorExpectedUnsignedJson(vector));
    expect(built.payloadSize).toBe(vector.payloadSizeBytes);
    expect(built.digest).toBe(vector.sha256Hex);
    // Baseline payload carries exactly three members (no upgrade members).
    expect(Object.keys(built.payload).sort()).toEqual([
      'ObservedCatalogueVersion',
      'RequestedPlanId',
      'TransitionIntent',
    ]);
  });

  it('rejects non-baseline intents and non-Direct-Free plan ids (never local fallback)', () => {
    const upgrade = {
      TransitionIntent: 'confirmed_upgrade',
      RequestedPlanId: LICENCE_PLAN_DIRECT_FREE,
      ObservedCatalogueVersion: LICENCE_CATALOGUE_VERSION_V1,
    };
    expect(
      buildDirectFreeUnsignedTransaction(upgrade as never, 'x', LICENCE_FIXED_TIMESTAMP),
    ).toEqual({ ok: false, reason: 'not-server-template' });

    const wrongPlan = {
      TransitionIntent: LICENCE_TRANSITION_INTENT_BASELINE_FREE,
      RequestedPlanId: 'hushvoting.veritas.2000',
      ObservedCatalogueVersion: LICENCE_CATALOGUE_VERSION_V1,
    };
    expect(
      buildDirectFreeUnsignedTransaction(wrongPlan as never, 'x', LICENCE_FIXED_TIMESTAMP),
    ).toEqual({ ok: false, reason: 'not-server-template' });
  });

  it('rejects empty or unbounded observed catalogue versions', () => {
    const empty = { ...V1_TEMPLATE, ObservedCatalogueVersion: '' };
    expect(
      buildDirectFreeUnsignedTransaction(empty, 'x', LICENCE_FIXED_TIMESTAMP),
    ).toEqual({ ok: false, reason: 'stale-or-unbounded-catalogue' });
  });

  it('pins the supported catalogue version predicate', () => {
    expect(isSupportedCatalogueVersion(LICENCE_CATALOGUE_VERSION_V1)).toBe(true);
    expect(isSupportedCatalogueVersion('hushvoting-licence-catalogue/v2.0.0')).toBe(false);
  });

  it('cannot construct from arbitrary payloads (no generic builder exists)', () => {
    // The only builder takes the closed server template type — a client-authored
    // payload is unrepresentable without a deliberate type error.
    const exported = Object.keys(directFreeModule);
    expect(exported).not.toContain('buildFromPayload');
    expect(exported).not.toContain('buildLocalDefault');
  });
});

describe('admission outcome policy', () => {
  it('maps ACCEPTED/PENDING to query-only reconciliation (never access)', () => {
    expect(decideSubmissionOutcome('accepted')).toEqual({ kind: 'reconcileByQuery' });
    expect(decideSubmissionOutcome('pending')).toEqual({ kind: 'reconcileByQuery' });
  });

  it('maps ALREADY_EXISTS to an immediate fresh query', () => {
    expect(decideSubmissionOutcome('alreadyExists')).toEqual({ kind: 'queryImmediately' });
  });

  it('maps terminal validation to fail-closed and uncertainty to preserve-and-reconcile', () => {
    expect(decideSubmissionOutcome('terminalRejected')).toEqual({ kind: 'failClosed' });
    expect(decideSubmissionOutcome('uncertain')).toEqual({ kind: 'preserveAndReconcile' });
  });
});
