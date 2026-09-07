/**
 * FEAT-017 Task 4.2 — workflow, action, navigation, focus, and notification
 * projection tests.
 *
 * Proves the closed presentation contract: exactly one documented surface and
 * permitted action set per authority state (no invented screen/option/success/
 * date/recovery); Account action precedence (Upgrade / View licence /
 * View progress, pending first); no-higher, recognized current Enterprise,
 * incompatible/no-active gates; stale refresh clears selection; C0 facts only
 * from a fresh validated draft; P0/D0/R0/S0 facts only from the matching safe
 * operation; Back verdicts are identical for browser and Android and never
 * resurrect a discarded confirmation or replay activation; restored history
 * rebuilds from authority only (never confirmation); quiet polling never
 * announces while meaningful transitions announce once; N0 stays reachable
 * until reconciliation; N1 is one-shot, non-navigating, never claims
 * competing activation.
 */

import { describe, expect, it } from 'vitest';
import type { LicenceSafeProjection } from './projection';
import type { LicenceUpgradePresentationInput } from './upgrade-presentation';
import {
  draftFromHigherOption,
  hasLiveUpgradeOperation,
  licenceAnnouncementPolicy,
  licenceFocusTargetFor,
  projectAccountLicenceSummary,
  projectActivationNotification,
  projectConfirmationViewFacts,
  projectCurrentLicenceDetail,
  projectDelayedViewFacts,
  projectLicenceBackVerdict,
  projectLicenceEntryViewFacts,
  projectLicenceWorkspaceViewFacts,
  projectOptionsViewFacts,
  projectPendingIndicator,
  projectProgressViewFacts,
  projectRestoredLicenceSurface,
  projectResultViewFacts,
  projectStaleViewFacts,
  OS_LEVEL_BACK_ORIGINS,
} from './upgrade-presentation';
import {
  directFreeNoHigherProjection,
  directFreeWithOptionsProjection,
  enterpriseActiveProjection,
  FIXTURE_TIME_ZONE,
  upgradeOperationOf,
  veritas2000ActiveProjection,
  VERITAS_2000_PLAN,
} from './fixtures/presentation-fixtures';

const TIME_ZONE = FIXTURE_TIME_ZONE;

function inputOf(
  overrides: Partial<LicenceUpgradePresentationInput> = {},
): LicenceUpgradePresentationInput {
  return {
    phase: 'entitlementReady',
    projection: directFreeWithOptionsProjection(),
    upgradeOperation: null,
    upgradeNotificationEligible: false,
    connectivity: 'online',
    ...overrides,
  };
}

function optionOf(projection: LicenceSafeProjection, planId: string) {
  const option = projection.higherOptions.find((candidate) => candidate.planId === planId);
  if (option === undefined) {
    throw new Error(`fixture option missing: ${planId}`);
  }
  return option;
}

describe('Account (A0/A0P) summary and action precedence', () => {
  it('shows the exact current plan, cap, perpetual validity, and shortened reference', () => {
    const facts = projectAccountLicenceSummary(inputOf(), TIME_ZONE);
    expect(facts.available).toBe(true);
    expect(facts.planDisplayName).toBe('HushVoting! Direct Free');
    expect(facts.active).toBe(true);
    expect(facts.conciseCapText).toBe('Up to 100 eligible voters');
    expect(facts.conciseValidityText).toBe('Perpetual');
    expect(facts.shortReference).toBe('5f2d9e11…c9d3e');
    expect(facts.action).toBe('upgrade');
    expect(facts.pendingTargetName).toBeNull();
  });

  it('shows View licence when no higher plan is available (D017-05)', () => {
    const facts = projectAccountLicenceSummary(
      inputOf({ projection: directFreeNoHigherProjection() }),
      TIME_ZONE,
    );
    expect(facts.action).toBe('view-licence');
    expect(facts.planDisplayName).toBe('HushVoting! Direct Free');
  });

  it('never offers self-service activation for a recognized active Enterprise current', () => {
    const facts = projectAccountLicenceSummary(
      inputOf({ projection: enterpriseActiveProjection() }),
      TIME_ZONE,
    );
    expect(facts.action).toBe('view-licence');
    expect(facts.planDisplayName).toBe('HushVoting! Enterprise');
  });

  it('gives View progress precedence while a local operation is pending (A0P)', () => {
    const facts = projectAccountLicenceSummary(
      inputOf({
        upgradeOperation: upgradeOperationOf('pending'),
      }),
      TIME_ZONE,
    );
    expect(facts.action).toBe('view-progress');
    expect(facts.pendingTargetName).toBe('HushVoting! Veritas 2k');
    expect(facts.pendingStatusText).toBe('Waiting for indexed activation');
    expect(facts.currentLimitsRemain).toBe(true);
    // The current licence is still the old indexed plan — never the target.
    expect(facts.planDisplayName).toBe('HushVoting! Direct Free');
  });

  it('shows no remembered licence block while resolving/unavailable/no-active', () => {
    for (const phase of ['resolving', 'entitlementUnavailable', 'entitlementUnsupported'] as const) {
      const facts = projectAccountLicenceSummary(inputOf({ phase, projection: null }), TIME_ZONE);
      expect(facts.available).toBe(false);
      expect(facts.action).toBe('unavailable');
      expect(facts.planDisplayName).toBeNull();
      expect(facts.shortReference).toBeNull();
      expect(facts.pendingTargetName).toBeNull();
    }
    const noActive = projectAccountLicenceSummary(
      inputOf({ phase: 'entitlementReady', projection: null }),
      TIME_ZONE,
    );
    expect(noActive.available).toBe(false);
    expect(noActive.action).toBe('unavailable');
  });

  it('shows the shortened reference as a display-only public reference', () => {
    const facts = projectAccountLicenceSummary(inputOf(), TIME_ZONE);
    expect(facts.shortReference).not.toContain(facts.planDisplayName ?? '');
    expect(facts.shortReference?.length).toBeLessThan(20);
  });
});

describe('options view (L1/L2) facts', () => {
  it('preserves exact server order of higher options with safe display facts', () => {
    const facts = projectOptionsViewFacts(inputOf(), TIME_ZONE, null);
    expect(facts?.view).toBe('options');
    expect(facts?.options.map((option) => option.planId)).toEqual([
      'hushvoting.veritas.500',
      'hushvoting.veritas.2000',
      'hushvoting.veritas.10000',
    ]);
    const veritas2k = facts?.options[1];
    expect(veritas2k?.displayName).toBe('HushVoting! Veritas 2k');
    expect(veritas2k?.capText).toBe('Up to 2,000 eligible voters');
    expect(veritas2k?.electionsText).toBe('Unlimited');
    expect(veritas2k?.termText).toBe('One-year term');
    expect(veritas2k?.governanceText).toBeNull();
    expect(facts?.noHigher).toBe(false);
    expect(facts?.noHigherMessage).toBeNull();
  });

  it('renders L2 with the exact no-higher copy and informational Enterprise', () => {
    const facts = projectOptionsViewFacts(
      inputOf({ projection: directFreeNoHigherProjection() }),
      TIME_ZONE,
      null,
    );
    expect(facts?.noHigher).toBe(true);
    expect(facts?.noHigherMessage).toBe('No higher self-service plan is available.');
    expect(facts?.enterprise).toBeNull();
  });

  it('keeps Enterprise informational with the exact tag and no action', () => {
    const facts = projectOptionsViewFacts(inputOf(), TIME_ZONE, null);
    expect(facts?.enterprise?.displayName).toBe('HushVoting! Enterprise');
    expect(facts?.enterprise?.tag).toBe('Contact provider — not yet available');
    expect(facts?.enterprise?.actionable).toBe(false);
  });

  it('locks selection and surfaces the pending target while an operation is live', () => {
    const facts = projectOptionsViewFacts(
      inputOf({ upgradeOperation: upgradeOperationOf('pending') }),
      TIME_ZONE,
      null,
    );
    expect(facts?.selectionLocked).toBe(true);
    expect(facts?.lockedTargetName).toBe('HushVoting! Veritas 2k');
  });

  it('marks the draft-selected option without making selection authoritative', () => {
    const draft = draftFromHigherOption(
      optionOf(directFreeWithOptionsProjection(), VERITAS_2000_PLAN),
    );
    const facts = projectOptionsViewFacts(inputOf(), TIME_ZONE, draft);
    expect(facts?.options.find((option) => option.selected)?.planId).toBe(VERITAS_2000_PLAN);
  });

  it('returns no licence content while the fresh query gate or recovery owns the screen', () => {
    expect(projectOptionsViewFacts(inputOf({ phase: 'resolving' }), TIME_ZONE, null)).toBeNull();
    expect(
      projectOptionsViewFacts(inputOf({ connectivity: 'offline' }), TIME_ZONE, null),
    ).toBeNull();
    expect(
      projectOptionsViewFacts(
        inputOf({ phase: 'entitlementReady', projection: null }),
        TIME_ZONE,
        null,
      ),
    ).toBeNull();
  });
});

describe('confirmation (C0) facts come only from a fresh validated draft', () => {
  const draft = draftFromHigherOption(
    optionOf(directFreeWithOptionsProjection(), VERITAS_2000_PLAN),
  );

  it('renders current/target comparison, reference, catalogue, term, and consequences', () => {
    const facts = projectConfirmationViewFacts(inputOf(), draft, TIME_ZONE);
    expect(facts?.view).toBe('confirmation');
    expect(facts?.heading).toBe('Confirm licence activation');
    expect(facts?.currentSide.displayName).toBe('HushVoting! Direct Free');
    expect(facts?.currentSide.validityText).toBe('Perpetual');
    expect(facts?.currentSide.governanceText).toBe('No customer trustees');
    expect(facts?.targetSide.displayName).toBe('HushVoting! Veritas 2k');
    expect(facts?.targetSide.capText).toBe('Up to 2,000 eligible voters');
    expect(facts?.targetSide.termText).toBe('One-year term');
    expect(facts?.reference?.fullText).toBe('5f2d9e11-3c44-4a80-b8e7-6b2f1a0c9d3e');
    expect(facts?.catalogueVersion).toBe('hushvoting-licence-catalogue/v1.0.0');
    expect(facts?.consequences.length).toBe(5);
  });

  it('rejects a draft that is no longer a fresh higher option (stale-safe)', () => {
    const projection = directFreeWithOptionsProjection();
    const staleDraft = draftFromHigherOption(optionOf(projection, VERITAS_2000_PLAN));
    // New truth where Veritas 2k is the current plan: the draft is obsolete.
    const newTruth = veritas2000ActiveProjection();
    expect(projectConfirmationViewFacts(inputOf({ projection: newTruth }), staleDraft, TIME_ZONE)).toBeNull();
  });

  it('rejects confirmation while a live operation locks selection or a stale result awaits review', () => {
    expect(
      projectConfirmationViewFacts(
        inputOf({ upgradeOperation: upgradeOperationOf('pending') }),
        draft,
        TIME_ZONE,
      ),
    ).toBeNull();
    expect(
      projectConfirmationViewFacts(
        inputOf({ upgradeOperation: upgradeOperationOf('delayed') }),
        draft,
        TIME_ZONE,
      ),
    ).toBeNull();
    expect(
      projectConfirmationViewFacts(
        inputOf({ upgradeOperation: upgradeOperationOf('stale') }),
        draft,
        TIME_ZONE,
      ),
    ).toBeNull();
  });

  it('returns null without a draft (no transaction, no invented screen)', () => {
    expect(projectConfirmationViewFacts(inputOf(), null, TIME_ZONE)).toBeNull();
  });
});

describe('progress / delayed / result / stale view facts', () => {
  it('projects P0 only from a live pending operation with current-limit continuity', () => {
    const facts = projectProgressViewFacts(
      inputOf({ upgradeOperation: upgradeOperationOf('pending') }),
    );
    expect(facts?.view).toBe('progress');
    expect(facts?.heading).toBe('Upgrade pending');
    expect(facts?.waitingMessage).toBe(
      'Waiting for the network to activate HushVoting! Veritas 2k…',
    );
    expect(facts?.currentRemainsMessage).toBe('HushVoting! Direct Free remains active.');
    expect(facts?.targetName).toBe('HushVoting! Veritas 2k');
    expect(facts?.currentName).toBe('HushVoting! Direct Free');
    expect(facts?.ariaBusy).toBe(true);
    expect(projectProgressViewFacts(inputOf())).toBeNull();
  });

  it('projects D0 only from the delayed operation with exact Retry explainer', () => {
    const facts = projectDelayedViewFacts(
      inputOf({ upgradeOperation: upgradeOperationOf('delayed') }),
    );
    expect(facts?.view).toBe('delayed');
    expect(facts?.heading).toBe('Licence activation is taking longer than expected.');
    expect(facts?.currentMessage).toBe(
      'Your current HushVoting! Direct Free licence remains active.',
    );
    expect(facts?.retryExplainer).toContain('Retry safely resends the same protected transaction.');
    expect(projectDelayedViewFacts(inputOf())).toBeNull();
    expect(projectDelayedViewFacts(inputOf({ upgradeOperation: upgradeOperationOf('pending') }))).toBeNull();
  });

  it('projects R0 only on exact local success with the fresh indexed current detail', () => {
    const facts = projectResultViewFacts(
      inputOf({
        upgradeOperation: upgradeOperationOf('local-success'),
        projection: veritas2000ActiveProjection(),
      }),
      TIME_ZONE,
    );
    expect(facts?.view).toBe('result');
    expect(facts?.heading).toBe('Licence activated');
    expect(facts?.activeMessage).toBe('HushVoting! Veritas 2k is now active.');
    expect(facts?.current?.displayName).toBe('HushVoting! Veritas 2k');
    // Upper-exclusive expiry from indexed truth is present — never invented.
    const expiry = facts?.current?.metricRows.find((row) => row.label === 'Validity');
    expect(expiry?.value).toContain('Expires ');
    expect(facts?.current?.reference?.fullText).toBe('8c6a1b77-4d2e-4f91-a4c0-9e7b2d8f1a55');
    expect(projectResultViewFacts(inputOf(), TIME_ZONE)).toBeNull();
    expect(
      projectResultViewFacts(
        inputOf({ upgradeOperation: upgradeOperationOf('competing-activation') }),
        TIME_ZONE,
      ),
    ).toBeNull();
  });

  it('projects S0 only from a typed stale operation and clears the selection', () => {
    const facts = projectStaleViewFacts(
      inputOf({ upgradeOperation: upgradeOperationOf('stale', { reason: 'catalogue-changed' }) }),
      TIME_ZONE,
    );
    expect(facts?.view).toBe('stale');
    expect(facts?.notice).toBe(
      'Your licence or available plans have changed. Please review the updated options.',
    );
    expect(facts?.reason).toBe('catalogue-changed');
    // Fresh options contain no retained selection.
    expect(facts?.fresh?.options.every((option) => !option.selected)).toBe(true);
    expect(projectStaleViewFacts(inputOf(), TIME_ZONE)).toBeNull();
  });
});

describe('workspace view validation (one screen per authority state)', () => {
  it('maps every requested view to facts only when the authority permits it', () => {
    const ready = inputOf();
    expect(projectLicenceWorkspaceViewFacts(ready, 'options', null, TIME_ZONE)?.view).toBe('options');
    expect(
      projectLicenceWorkspaceViewFacts(
        ready,
        'confirmation',
        draftFromHigherOption(optionOf(directFreeWithOptionsProjection(), VERITAS_2000_PLAN)),
        TIME_ZONE,
      )?.view,
    ).toBe('confirmation');
    expect(
      projectLicenceWorkspaceViewFacts(
        inputOf({ upgradeOperation: upgradeOperationOf('pending') }),
        'progress',
        null,
        TIME_ZONE,
      )?.view,
    ).toBe('progress');
    // Confirmation is impossible while a live operation exists.
    expect(
      projectLicenceWorkspaceViewFacts(
        inputOf({ upgradeOperation: upgradeOperationOf('pending') }),
        'confirmation',
        draftFromHigherOption(optionOf(directFreeWithOptionsProjection(), VERITAS_2000_PLAN)),
        TIME_ZONE,
      ),
    ).toBeNull();
  });

  it('entry gate/recovery mapping never leaks licence content in gate states', () => {
    expect(projectLicenceEntryViewFacts(inputOf({ phase: 'resolving' }))).toEqual({
      view: 'gate',
      reuseEntitlementGate: true,
      heading: null,
    });
    const offline = projectLicenceEntryViewFacts(inputOf({ connectivity: 'offline' }));
    expect(offline.view).toBe('recovery');
    if (offline.view === 'recovery') {
      expect(offline.reason).toBe('offline');
      expect(offline.rememberNothing).toBe(true);
    }
    const unsupported = projectLicenceEntryViewFacts(
      inputOf({ phase: 'entitlementUnsupported', projection: null }),
    );
    expect(unsupported.view).toBe('recovery');
  });
});

describe('Back/history contract (browser, in-app, Android equivalence)', () => {
  it('browser and Android produce identical verdicts for every surface', () => {
    const surfaces = [
      'account',
      'gate',
      'options',
      'confirmation',
      'progress',
      'delayed',
      'result',
      'stale',
      'recovery',
    ] as const;
    for (const surface of surfaces) {
      const browser = projectLicenceBackVerdict(surface, 'browser');
      for (const origin of OS_LEVEL_BACK_ORIGINS) {
        expect(projectLicenceBackVerdict(surface, origin)).toEqual(browser);
      }
    }
  });

  it('applies draft-discard vs pending-leave vs result-leave transitions', () => {
    expect(projectLicenceBackVerdict('account', 'browser')).toEqual({ kind: 'close-account' });
    expect(projectLicenceBackVerdict('options', 'browser')).toEqual({
      kind: 'leave-discard-draft',
    });
    expect(projectLicenceBackVerdict('stale', 'browser')).toEqual({ kind: 'leave-discard-draft' });
    expect(projectLicenceBackVerdict('confirmation', 'browser')).toEqual({
      kind: 'leave-discard-draft',
    });
    expect(projectLicenceBackVerdict('progress', 'browser')).toEqual({ kind: 'leave-keep-pending' });
    expect(projectLicenceBackVerdict('delayed', 'browser')).toEqual({ kind: 'leave-keep-pending' });
    expect(projectLicenceBackVerdict('result', 'browser')).toEqual({ kind: 'leave-after-result' });
  });

  it('the in-app confirmation control returns to options and retains the draft', () => {
    expect(projectLicenceBackVerdict('confirmation', 'inApp')).toEqual({
      kind: 'return-to-options',
      draftRetained: true,
    });
  });

  it('no Back verdict can resurrect a confirmation or replay activation', () => {
    for (const surface of [
      'options',
      'confirmation',
      'progress',
      'delayed',
      'result',
      'stale',
      'gate',
      'recovery',
    ] as const) {
      for (const origin of ['browser', 'inApp', 'android'] as const) {
        const verdict = projectLicenceBackVerdict(surface, origin);
        expect(verdict.kind).not.toBe('activate');
        expect(verdict.kind).not.toBe('resubmit');
      }
    }
  });
});

describe('restored history rebuilds from authority only (never a draft)', () => {
  it('restores options/progress/result/stale/gate/recovery — never confirmation', () => {
    const restored = [
      projectRestoredLicenceSurface(inputOf()),
      projectRestoredLicenceSurface(inputOf({ phase: 'resolving' })),
      projectRestoredLicenceSurface(
        inputOf({ upgradeOperation: upgradeOperationOf('pending') }),
      ),
      projectRestoredLicenceSurface(
        inputOf({ upgradeOperation: upgradeOperationOf('delayed') }),
      ),
      projectRestoredLicenceSurface(
        inputOf({
          upgradeOperation: upgradeOperationOf('local-success'),
          projection: veritas2000ActiveProjection(),
        }),
      ),
      projectRestoredLicenceSurface(
        inputOf({ upgradeOperation: upgradeOperationOf('stale') }),
      ),
      projectRestoredLicenceSurface(
        inputOf({ upgradeOperation: upgradeOperationOf('competing-activation') }),
      ),
      projectRestoredLicenceSurface(inputOf({ connectivity: 'offline' })),
    ];
    for (const surface of restored) {
      expect(surface).not.toBe('confirmation');
    }
    expect(restored[0]).toBe('options');
    expect(restored[1]).toBe('gate');
    expect(restored[2]).toBe('progress');
    expect(restored[3]).toBe('delayed');
    expect(restored[4]).toBe('result');
    expect(restored[5]).toBe('stale');
    expect(restored[6]).toBe('options'); // competing truth accepted; no success claim
    expect(restored[7]).toBe('recovery');
  });

  it('competing activation never restores to result or claims local success', () => {
    expect(
      projectRestoredLicenceSurface(
        inputOf({ upgradeOperation: upgradeOperationOf('competing-activation') }),
      ),
    ).toBe('options');
  });
});

describe('focus and announcement policy', () => {
  it('assigns the deterministic focus target per view', () => {
    expect(licenceFocusTargetFor('stale')).toBe('notice-heading');
    expect(licenceFocusTargetFor('confirmation')).toBe('heading');
    expect(licenceFocusTargetFor('progress')).toBe('heading');
    expect(licenceFocusTargetFor('result')).toBe('heading');
  });

  it('never announces the same surface twice (quiet three-second polling)', () => {
    for (const view of ['options', 'progress', 'delayed', 'result', 'stale'] as const) {
      expect(licenceAnnouncementPolicy(view, view).announce).toBe(false);
    }
  });

  it('announces meaningful entries once and stays polite', () => {
    expect(licenceAnnouncementPolicy('gate', 'progress').announce).toBe(true);
    expect(licenceAnnouncementPolicy('gate', 'delayed').announce).toBe(true);
    expect(licenceAnnouncementPolicy('progress', 'result').announce).toBe(true);
    expect(licenceAnnouncementPolicy('options', 'stale').announce).toBe(true);
    expect(licenceAnnouncementPolicy('gate', 'result').polite).toBe(true);
  });

  it('options/confirmation/gate entries do not announce (heading focus is enough)', () => {
    expect(licenceAnnouncementPolicy('gate', 'options').announce).toBe(false);
    expect(licenceAnnouncementPolicy('options', 'confirmation').announce).toBe(false);
    expect(licenceAnnouncementPolicy('none', 'options').announce).toBe(false);
  });
});

describe('N0 persistent pending indicator', () => {
  it('is visible on the workspace while a live operation is pending (D017-01)', () => {
    const facts = projectPendingIndicator(
      inputOf({ upgradeOperation: upgradeOperationOf('pending') }),
      'workspace',
    );
    expect(facts.visible).toBe(true);
    expect(facts.visibleLabel).toBe('Upgrade pending · HushVoting! Veritas 2k');
    expect(facts.accessibleLabel).toBe(
      'Upgrade pending for HushVoting! Veritas 2k. View progress.',
    );
  });

  it('is hidden only when the user is already on the operation progress surface', () => {
    const pendingInput = inputOf({ upgradeOperation: upgradeOperationOf('pending') });
    expect(projectPendingIndicator(pendingInput, 'licence-progress').visible).toBe(false);
    expect(projectPendingIndicator(pendingInput, 'licence-delayed').visible).toBe(false);
    expect(projectPendingIndicator(pendingInput, 'workspace').visible).toBe(true);
    expect(projectPendingIndicator(pendingInput, 'account').visible).toBe(true);
  });

  it('is absent without a live operation or after reconciliation', () => {
    expect(projectPendingIndicator(inputOf(), 'workspace').visible).toBe(false);
    expect(
      projectPendingIndicator(
        inputOf({ upgradeOperation: upgradeOperationOf('local-success') }),
        'workspace',
      ).visible,
    ).toBe(false);
    expect(
      projectPendingIndicator(
        inputOf({ upgradeOperation: upgradeOperationOf('competing-activation') }),
        'workspace',
      ).visible,
    ).toBe(false);
  });

  it('never submits, retries, or creates a selection by construction', () => {
    const facts = projectPendingIndicator(
      inputOf({ upgradeOperation: upgradeOperationOf('delayed') }),
      'workspace',
    );
    expect(facts.visible).toBe(true);
    // The indicator carries only labels + target name (no control payload).
    expect(Object.keys(facts).sort()).toEqual([
      'accessibleLabel',
      'targetPlanName',
      'visible',
      'visibleLabel',
    ]);
  });
});

describe('N1 one-time activation notification', () => {
  const localSuccess = inputOf({
    upgradeOperation: upgradeOperationOf('local-success'),
    projection: veritas2000ActiveProjection(),
    upgradeNotificationEligible: true,
  });

  it('is visible exactly while eligibility is armed and the user is elsewhere', () => {
    const facts = projectActivationNotification(localSuccess, 'workspace');
    expect(facts.visible).toBe(true);
    expect(facts.message).toBe('Your HushVoting! Veritas 2k licence is now active');
    expect(facts.planName).toBe('HushVoting! Veritas 2k');
    expect(facts.noFocusMovement).toBe(true);
    expect(facts.noRedirect).toBe(true);
    expect(facts.announceOnce).toBe(true);
    expect(facts.viewLicenceAction).toBe(true);
    expect(facts.dismissAction).toBe(true);
  });

  it('is hidden when R0/progress already surfaces the result', () => {
    expect(projectActivationNotification(localSuccess, 'licence-result').visible).toBe(false);
    expect(projectActivationNotification(localSuccess, 'licence-progress').visible).toBe(false);
    expect(projectActivationNotification(localSuccess, 'licence-delayed').visible).toBe(false);
  });

  it('is hidden without one-shot eligibility (no repeat notifications)', () => {
    const acked = inputOf({
      upgradeOperation: upgradeOperationOf('local-success'),
      projection: veritas2000ActiveProjection(),
      upgradeNotificationEligible: false,
    });
    expect(projectActivationNotification(acked, 'workspace').visible).toBe(false);
  });

  it('never claims a competing-device activation as local success', () => {
    const competing = inputOf({
      upgradeOperation: upgradeOperationOf('competing-activation'),
      projection: veritas2000ActiveProjection(),
      upgradeNotificationEligible: true,
    });
    const facts = projectActivationNotification(competing, 'workspace');
    expect(facts.visible).toBe(false);
    expect(facts.message).toBeNull();
  });

  it('is visible from the workspace or options but never redirects focus', () => {
    expect(projectActivationNotification(localSuccess, 'licence-options').visible).toBe(true);
    expect(projectActivationNotification(localSuccess, 'account').visible).toBe(true);
  });
});

describe('helper predicates and data boundaries', () => {
  it('recognizes live pending/delayed operations only', () => {
    expect(hasLiveUpgradeOperation(upgradeOperationOf('pending'))).toBe(true);
    expect(hasLiveUpgradeOperation(upgradeOperationOf('delayed'))).toBe(true);
    expect(hasLiveUpgradeOperation(upgradeOperationOf('local-success'))).toBe(false);
    expect(hasLiveUpgradeOperation(upgradeOperationOf('competing-activation'))).toBe(false);
    expect(hasLiveUpgradeOperation(upgradeOperationOf('stale'))).toBe(false);
    expect(hasLiveUpgradeOperation(null)).toBe(false);
  });

  it('current licence detail renders local dates from UTC data with governance labels', () => {
    const detail = projectCurrentLicenceDetail(veritas2000ActiveProjection(), TIME_ZONE);
    expect(detail.displayName).toBe('HushVoting! Veritas 2k');
    expect(detail.effectiveFromText).toBe('7 September 2026, 13:24 UTC+01:00');
    const governance = detail.metricRows.find((row) => row.label === 'Governance');
    expect(governance?.value).toBe('No customer trustees; 3-of-5 trustees; 7-of-10 trustees');
    const term = detail.metricRows.find((row) => row.label === 'Term');
    expect(term?.value).toBe('One-year term');
  });
});
