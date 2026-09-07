/**
 * FEAT-017 Task 4.1 — closed licence workflow, action, navigation, focus, and
 * notification presentation model (A0, L0, L1/L2, S0, C0, P0, D0, R0, N0/N1,
 * E0 from the design contract).
 *
 * Every projection maps safe authority state (the coordinator snapshot
 * vocabulary: phase, safe current projection, the page-safe upgrade-operation
 * snapshot, one-shot notification eligibility) into EXACTLY ONE documented
 * surface with a closed copy/action/focus/busy/live-region/Back contract.
 * Presentation can never invent authority: no option, success, date,
 * identifier, governance label, or recovery action is inferred outside the
 * safe snapshot; unrecognized ids/values are omitted, never fabricated; no
 * raw template, signature, bytes, journal, admission code, plan rank, or
 * free-form server text is representable. Draft selection is presentation-
 * only (it never creates a transaction) and dies on leave/reload/Forward —
 * restored history can only rebuild from authority state.
 *
 * Framework-neutral and secret-free (mirrors entitlement-presentation.ts).
 * Phase 5 components consume these facts; Phase 6 wires them to the root
 * composition; integration of the real upgrade op happens through the closed
 * authority only (see coordinator.ts / session-contract.ts).
 *
 * Normative source: FEAT-017 FeatureDescription D017-01…09 + recovery and
 * accessibility matrix; design-summary.md screen/state contract + canonical
 * copy; Wireframes-design.md screen inventory, history contract, focus
 * management, live regions; planning-analysis-report §5, §6, §11.
 */

import type { EntitlementPhase } from './coordinator';
import type {
  LicenceSafeEnterprise,
  LicenceSafeHigherOption,
  LicenceSafeProjection,
} from './projection';
import type {
  LicenceUpgradeSafeOperation,
  LicenceUpgradeStaleReason,
} from './session-contract';
import {
  LICENCE_CONFIRMATION_CONSEQUENCES,
  activationNotificationMessage,
  currentRemainsActiveMessage,
  delayedCurrentMessage,
  delayedTargetMessage,
  governanceLabels,
  licenceUpgradeCopy,
  pendingIndicatorAccessibleLabel,
  pendingIndicatorVisibleLabel,
  pendingWaitingMessage,
  resultActiveMessage,
  upToEligibleVotersText,
} from './upgrade-copy';
import {
  formatLicenceLocalDateTime,
  licenceTermLabel,
  projectLicenceValidity,
  type LicenceValidityFacts,
} from './local-instant';
import { licenceReferenceFacts, type LicenceReferenceFacts } from './licence-reference';

/** Connectivity vocabulary consumed from the page connectivity authority. */
export type LicenceConnectivityVariant = 'online' | 'paused' | 'offline' | 'reconnecting' | 'unknown';

/**
 * Authority view handed to presentation. Structural subset of the coordinator
 * snapshot vocabulary (CoordinatorSnapshot / LicenceProgressPayload); carries
 * no exact bytes, signatures, bindings, or journal state.
 */
export interface LicenceUpgradePresentationInput {
  readonly phase: EntitlementPhase | 'no-session';
  /** Safe indexed current projection; null until compatible active truth. */
  readonly projection: LicenceSafeProjection | null;
  /** Page-safe confirmed-upgrade operation; null when none/terminal-cleared. */
  readonly upgradeOperation: LicenceUpgradeSafeOperation | null;
  /** One-shot local-success notification eligibility (authority-owned). */
  readonly upgradeNotificationEligible: boolean;
  readonly connectivity?: LicenceConnectivityVariant;
}

function connectivityOf(input: LicenceUpgradePresentationInput): LicenceConnectivityVariant {
  return input.connectivity ?? 'online';
}

/** A live (sealed, unreconciled) local operation exists. */
export function hasLiveUpgradeOperation(
  operation: LicenceUpgradeSafeOperation | null,
): operation is Extract<LicenceUpgradeSafeOperation, { readonly status: 'pending' | 'delayed' }> {
  return operation !== null && (operation.status === 'pending' || operation.status === 'delayed');
}

function phaseOf(input: LicenceUpgradePresentationInput): EntitlementPhase | 'no-session' {
  return input.phase;
}

// ---------------------------------------------------------------------------
// Account (A0 / A0P) summary projection.
// ---------------------------------------------------------------------------

export type LicenceAccountAction = 'upgrade' | 'view-licence' | 'view-progress' | 'unavailable';

/** Closed A0/A0P facts; `available=false` renders no licence block (gate). */
export interface LicenceAccountSummaryFacts {
  readonly kind: 'licence-account-summary';
  /**
   * False while the authority has no compatible active truth (resolving,
   * unavailable, unsupported, no-active): Account must not keep stale values.
   */
  readonly available: boolean;
  readonly planDisplayName: string | null;
  readonly active: boolean;
  /** Concise cap/limit line from safe fields ('Up to 100 eligible voters'). */
  readonly conciseCapText: string | null;
  /** Concise validity line ('Perpetual' or local upper-exclusive expiry). */
  readonly conciseValidityText: string | null;
  /** Recognizably shortened public reference (never a secret). */
  readonly shortReference: string | null;
  /** One contextual account action with pending precedence (D017-05/03). */
  readonly action: LicenceAccountAction;
  /** Pending target (A0P sibling surface); null when no live operation. */
  readonly pendingTargetName: string | null;
  readonly pendingStatusText: string | null;
  readonly currentLimitsRemain: boolean;
}

/** Concise single-line cap/election fact for a safe projection. */
export function conciseLicenceCapText(projection: LicenceSafeProjection): string | null {
  if (typeof projection.eligibleVoterCap === 'number' && projection.eligibleVoterCap > 0) {
    return upToEligibleVotersText(projection.eligibleVoterCap);
  }
  if (projection.unlimitedElections === true) {
    return licenceUpgradeCopy('valueUnlimited');
  }
  return null;
}

/** Concise validity line for Account; null only when truth is unusable. */
export function conciseLicenceValidityText(
  projection: LicenceSafeProjection,
  timeZone: string,
): string | null {
  const validity = projectLicenceValidity({
    effectiveFromUtc: projection.effectiveFromUtc,
    expiresAtUtc: projection.expiresAtUtc,
    timeZone,
  });
  if (!validity.ok) {
    return null;
  }
  if (validity.facts.perpetual) {
    return licenceUpgradeCopy('valuePerpetual');
  }
  if (validity.facts.upperExclusiveExpiry === null) {
    return null;
  }
  const local = formatLicenceLocalDateTime(
    validity.facts.upperExclusiveExpiry.utcIso,
    timeZone,
  );
  return local === null ? null : `${licenceUpgradeCopy('licenceValidityPrefix')}${local}`;
}

/** Project the closed Account licence summary (A0 / A0P). */
export function projectAccountLicenceSummary(
  input: LicenceUpgradePresentationInput,
  timeZone: string,
): LicenceAccountSummaryFacts {
  const live = hasLiveUpgradeOperation(input.upgradeOperation);
  if (phaseOf(input) === 'entitlementReady' && input.projection !== null) {
    const pendingTargetName =
      live && input.upgradeOperation.targetPlanDisplayName !== null
        ? input.upgradeOperation.targetPlanDisplayName
        : null;
    const action: LicenceAccountAction = live
      ? 'view-progress'
      : input.projection.planFamily === 'enterprise'
        ? 'view-licence'
        : input.projection.higherOptions.length > 0
          ? 'upgrade'
          : 'view-licence';
    const reference = licenceReferenceFacts(input.projection.licenceReference, 'shortened');
    return {
      kind: 'licence-account-summary',
      available: true,
      planDisplayName: input.projection.displayName,
      active: true,
      conciseCapText: conciseLicenceCapText(input.projection),
      conciseValidityText: conciseLicenceValidityText(input.projection, timeZone),
      shortReference: reference === null ? null : reference.displayText,
      action,
      pendingTargetName,
      pendingStatusText:
        live && pendingTargetName !== null
          ? licenceUpgradeCopy('waitingForIndexedActivation')
          : null,
      currentLimitsRemain: live,
    };
  }
  // Terminal local-success also refreshes Account through the fresh current
  // projection above; any other state renders no licence block (no memory).
  return {
    kind: 'licence-account-summary',
    available: false,
    planDisplayName: null,
    active: false,
    conciseCapText: null,
    conciseValidityText: null,
    shortReference: null,
    action: 'unavailable',
    pendingTargetName: null,
    pendingStatusText: null,
    currentLimitsRemain: false,
  };
}

// ---------------------------------------------------------------------------
// Current licence detail facts (L1/L2/S0/R0 + C0 current side).
// ---------------------------------------------------------------------------

/** One definition-list metric row (label + safe value, never color-only). */
export interface LicenceMetricRow {
  readonly label: string;
  readonly value: string;
}

export interface LicenceCurrentDetailFacts {
  readonly displayName: string;
  readonly description: string;
  readonly active: boolean;
  readonly metricRows: readonly LicenceMetricRow[];
  /** `Effective from:` row local text (UTC retained in data). */
  readonly effectiveFromText: string | null;
  readonly validity: LicenceValidityFacts | null;
  /** Full selectable/copyable public reference facts. */
  readonly reference: LicenceReferenceFacts | null;
}

/** Eligible-voters row value from safe fields. */
export function eligibleVotersMetricValue(projection: LicenceSafeProjection): string | null {
  if (typeof projection.eligibleVoterCap === 'number' && projection.eligibleVoterCap > 0) {
    return upToEligibleVotersText(projection.eligibleVoterCap);
  }
  if (projection.unlimitedElections === true) {
    return licenceUpgradeCopy('valueUnlimited');
  }
  return null; // no cap and no unlimited flag: row omitted, never invented
}

/**
 * Build the metric rows of the CURRENT indexed licence from safe server
 * fields only. Rows whose data is absent are omitted; governance labels map
 * only the frozen FEAT-012 ids and unknown ids are omitted (never inferred).
 */
export function currentLicenceMetricRows(
  projection: LicenceSafeProjection,
  timeZone: string,
): LicenceMetricRow[] {
  const rows: LicenceMetricRow[] = [];
  const votersValue = eligibleVotersMetricValue(projection);
  if (votersValue !== null) {
    rows.push({ label: licenceUpgradeCopy('metricEligibleVoters'), value: votersValue });
  }
  if (projection.unlimitedElections === true) {
    rows.push({ label: licenceUpgradeCopy('metricElections'), value: licenceUpgradeCopy('valueUnlimited') });
  }
  const validity = projectLicenceValidity({
    effectiveFromUtc: projection.effectiveFromUtc,
    expiresAtUtc: projection.expiresAtUtc,
    timeZone,
  });
  if (validity.ok) {
    if (validity.facts.perpetual) {
      rows.push({ label: licenceUpgradeCopy('metricValidity'), value: licenceUpgradeCopy('valuePerpetual') });
    } else if (validity.facts.upperExclusiveExpiry !== null) {
      const expiryLocal = formatLicenceLocalDateTime(validity.facts.upperExclusiveExpiry.utcIso, timeZone);
      if (expiryLocal !== null) {
        rows.push({
          label: licenceUpgradeCopy('metricValidity'),
          value: `${licenceUpgradeCopy('licenceValidityPrefix')}${expiryLocal}`,
        });
      }
    }
  }
  const governance = governanceLabels(projection.allowedGovernanceOptionIds);
  if (governance.length > 0) {
    rows.push({ label: licenceUpgradeCopy('metricGovernance'), value: governance.join('; ') });
  }
  const term = licenceTermLabel(projection.termKind, projection.termYears);
  if (term !== null && term !== licenceUpgradeCopy('valuePerpetual')) {
    rows.push({ label: licenceUpgradeCopy('metricTerm'), value: term });
  }
  return rows;
}

/** Full detail facts of the current indexed licence (L1 current block/R0). */
export function projectCurrentLicenceDetail(
  projection: LicenceSafeProjection,
  timeZone: string,
): LicenceCurrentDetailFacts {
  const validity = projectLicenceValidity({
    effectiveFromUtc: projection.effectiveFromUtc,
    expiresAtUtc: projection.expiresAtUtc,
    timeZone,
  });
  const effectiveFromText = formatLicenceLocalDateTime(projection.effectiveFromUtc, timeZone);
  return {
    displayName: projection.displayName,
    description: projection.safeDescription,
    active: true,
    metricRows: currentLicenceMetricRows(projection, timeZone),
    effectiveFromText: effectiveFromText === null ? null : effectiveFromText,
    validity: validity.ok ? validity.facts : null,
    reference: licenceReferenceFacts(projection.licenceReference, 'full'),
  };
}

// ---------------------------------------------------------------------------
// Higher-option / Enterprise display facts (L1/L2/S0 + C0 target side).
// ---------------------------------------------------------------------------

/** One server-ordered higher Veritas option with safe display facts. */
export interface LicenceHigherOptionFacts {
  readonly planId: string;
  readonly displayName: string;
  readonly description: string;
  readonly capText: string | null;
  readonly electionsText: string | null;
  /** Term text only from server term fields; pre-index = no committed dates. */
  readonly termText: string | null;
  /**
   * Per-option governance is NOT part of the frozen v1 transport; it is
   * always null here so presentation never infers it from a client catalogue.
   */
  readonly governanceText: null;
  /** Draft selection state (presentation only; selection is not authority). */
  readonly selected: boolean;
}

export interface LicenceEnterpriseFacts {
  readonly displayName: string;
  readonly description: string;
  readonly tag: string;
  /** Enterprise is informational only; never actionable by construction. */
  readonly actionable: false;
}

/** Project one higher-option display entry from the safe option metadata. */
export function projectHigherOptionFacts(
  option: LicenceSafeHigherOption,
  selected: boolean,
): LicenceHigherOptionFacts {
  let capText: string | null = null;
  if (typeof option.eligibleVoterCap === 'number' && option.eligibleVoterCap > 0) {
    capText = upToEligibleVotersText(option.eligibleVoterCap);
  } else if (option.unlimitedElections === true) {
    capText = licenceUpgradeCopy('valueUnlimited');
  }
  return {
    planId: option.planId,
    displayName: option.displayName,
    description: option.safeDescription,
    capText,
    electionsText: option.unlimitedElections === true ? licenceUpgradeCopy('valueUnlimited') : null,
    termText: licenceTermLabel(option.termKind, option.termYears),
    governanceText: null,
    selected,
  };
}

/** Project the informational Enterprise entry (never actionable). */
export function projectEnterpriseFacts(enterprise: LicenceSafeEnterprise): LicenceEnterpriseFacts {
  return {
    displayName: enterprise.displayName,
    description: enterprise.safeDescription,
    tag: licenceUpgradeCopy('enterpriseTag'),
    actionable: false,
  };
}

// ---------------------------------------------------------------------------
// Draft selection (presentation-only; creates no transaction).
// ---------------------------------------------------------------------------

/**
 * Presentation-only selection of one higher option. References the option's
 * safe metadata from a FRESH projection and dies on leave/reload/Forward.
 * It never creates, signs, or submits anything (Activate hands the plan id to
 * the closed authority which re-validates against its own fresh query).
 */
export interface LicenceDraftSelection {
  readonly planId: string;
  readonly displayName: string;
  readonly description: string;
  readonly capText: string | null;
  readonly electionsText: string | null;
  readonly termText: string | null;
}

/** Draft from a fresh higher option (facts must come from that option). */
export function draftFromHigherOption(option: LicenceSafeHigherOption): LicenceDraftSelection {
  return {
    planId: option.planId,
    displayName: option.displayName,
    description: option.safeDescription,
    capText:
      typeof option.eligibleVoterCap === 'number' && option.eligibleVoterCap > 0
        ? upToEligibleVotersText(option.eligibleVoterCap)
        : null,
    electionsText: option.unlimitedElections === true ? licenceUpgradeCopy('valueUnlimited') : null,
    termText: licenceTermLabel(option.termKind, option.termYears),
  };
}

/**
 * Validate a draft against the FRESH options of the current truth. A draft
 * whose plan is no longer a fresh higher option is invalid (stale) — it can
 * never reach confirmation.
 */
export function draftMatchesFreshOptions(
  projection: LicenceSafeProjection | null,
  draft: LicenceDraftSelection | null,
): boolean {
  if (draft === null || projection === null) {
    return false;
  }
  if (projection.planId === draft.planId) {
    return false; // the requested plan is already the current plan
  }
  return projection.higherOptions.some((option) => option.planId === draft.planId);
}

// ---------------------------------------------------------------------------
// Licence workspace views (closed per-surface facts).
// ---------------------------------------------------------------------------

/**
 * Closed licence workspace view. Phase 5 renders components from these; the
 * model never invents a screen or action for an authority state.
 */
export type LicenceWorkspaceView =
  | 'gate' // L0 fresh query: existing root gate owns the screen
  | 'options' // L1 (higher options) or L2 (no higher) via optionsFacts.noHigher
  | 'confirmation' // C0 (validated fresh draft only)
  | 'progress' // P0 pending
  | 'delayed' // D0
  | 'result' // R0 exact local success
  | 'stale' // S0 (typed stale notice; selection cleared)
  | 'recovery'; // E0 typed recovery / existing root gate reuse

export interface LicenceGateViewFacts {
  readonly view: 'gate';
  /** L0 reuses the existing entitlement gate; this is a pointer, not copy. */
  readonly reuseEntitlementGate: true;
  readonly heading: null;
}

export interface LicenceOptionsViewFacts {
  readonly view: 'options';
  readonly heading: string;
  readonly subtitle: string;
  readonly current: LicenceCurrentDetailFacts | null;
  readonly options: readonly LicenceHigherOptionFacts[];
  readonly noHigher: boolean;
  readonly noHigherMessage: string | null;
  readonly enterprise: LicenceEnterpriseFacts | null;
  /** Live pending/delayed op locks selection (D017-03); target shown. */
  readonly selectionLocked: boolean;
  readonly lockedTargetName: string | null;
}

export interface LicenceConfirmationViewFacts {
  readonly view: 'confirmation';
  readonly heading: string;
  readonly subtitle: string;
  readonly currentSide: {
    readonly displayName: string;
    readonly capText: string | null;
    readonly validityText: string | null;
    readonly governanceText: string | null;
    readonly termText: string | null;
  };
  readonly targetSide: {
    readonly displayName: string;
    readonly description: string;
    readonly capText: string | null;
    readonly electionsText: string | null;
    readonly termText: string | null;
  };
  /** Full current licence reference (selectable + copy). */
  readonly reference: LicenceReferenceFacts | null;
  readonly catalogueVersion: string;
  readonly consequences: readonly string[];
}

export interface LicenceProgressViewFacts {
  readonly view: 'progress';
  readonly heading: string;
  readonly waitingMessage: string | null;
  readonly statusText: string;
  readonly currentRemainsMessage: string | null;
  readonly existingLimitsMessage: string;
  readonly reassurance: string;
  readonly currentName: string | null;
  readonly targetName: string | null;
  /** P0 entry announces once; three-second polls stay silent. */
  readonly ariaBusy: true;
}

export interface LicenceDelayedViewFacts {
  readonly view: 'delayed';
  readonly heading: string;
  readonly targetMessage: string | null;
  readonly currentMessage: string | null;
  readonly retryExplainer: string;
}

export interface LicenceResultViewFacts {
  readonly view: 'result';
  readonly heading: string;
  readonly activeMessage: string | null;
  readonly current: LicenceCurrentDetailFacts | null;
}

export interface LicenceStaleViewFacts {
  readonly view: 'stale';
  readonly heading: string;
  readonly notice: string;
  readonly reason: LicenceUpgradeStaleReason | null;
  /** Fresh options after refresh (no prior selection retained). */
  readonly fresh: LicenceOptionsViewFacts | null;
}

export type LicenceRecoveryReason =
  | 'no-active'
  | 'unavailable'
  | 'unsupported'
  | 'repair'
  | 'offline'
  | 'locked-out'
  | 'unknown';

export interface LicenceRecoveryViewFacts {
  readonly view: 'recovery';
  /** Closed reason only; copy/actions reuse the existing root gate. */
  readonly reason: LicenceRecoveryReason;
  /** Never render remembered licence content in recovery. */
  readonly rememberNothing: true;
}

export type LicenceWorkspaceViewFacts =
  | LicenceGateViewFacts
  | LicenceOptionsViewFacts
  | LicenceConfirmationViewFacts
  | LicenceProgressViewFacts
  | LicenceDelayedViewFacts
  | LicenceResultViewFacts
  | LicenceStaleViewFacts
  | LicenceRecoveryViewFacts;

/** Map an entitlement phase + connectivity to the closed recovery reason. */
export function licenceRecoveryReasonOf(input: LicenceUpgradePresentationInput): LicenceRecoveryReason {
  const connectivity = connectivityOf(input);
  if (connectivity === 'offline' || connectivity === 'reconnecting') {
    return 'offline';
  }
  switch (phaseOf(input)) {
    case 'entitlementUnavailable':
      return 'unavailable';
    case 'entitlementUnsupported':
      return 'unsupported';
    case 'entitlementRepair':
      return 'repair';
    case 'lockedOut':
      return 'locked-out';
    case 'entitlementReady':
      return input.projection === null ? 'no-active' : 'unknown';
    default:
      return 'unknown';
  }
}

/** Recovery gate is owned by the existing FEAT-016 root authority. */
export function isLicenceRecoveryRequired(input: LicenceUpgradePresentationInput): boolean {
  const connectivity = connectivityOf(input);
  if (connectivity === 'offline' || connectivity === 'reconnecting') {
    return true;
  }
  const phase = phaseOf(input);
  return (
    phase === 'no-session' ||
    phase === 'entitlementUnavailable' ||
    phase === 'entitlementUnsupported' ||
    phase === 'entitlementRepair' ||
    phase === 'lockedOut' ||
    (phase === 'entitlementReady' && input.projection === null)
  );
}

/** Build fresh options facts (L1/L2) from current truth. */
export function projectOptionsViewFacts(
  input: LicenceUpgradePresentationInput,
  timeZone: string,
  selectedDraft: LicenceDraftSelection | null,
): LicenceOptionsViewFacts | null {
  if (isLicenceRecoveryRequired(input)) {
    return null; // offline/unavailable/unsupported/no-active: never licence content
  }
  if (phaseOf(input) === 'resolving') {
    return null; // gate owns the screen until fresh truth arrives
  }
  if (input.projection === null) {
    return null;
  }
  const live = hasLiveUpgradeOperation(input.upgradeOperation);
  const lockedTargetName = live && input.upgradeOperation.targetPlanDisplayName !== null
    ? input.upgradeOperation.targetPlanDisplayName
    : null;
  const options = input.projection.higherOptions.map((option) =>
    projectHigherOptionFacts(option, selectedDraft !== null && selectedDraft.planId === option.planId),
  );
  return {
    view: 'options',
    heading: licenceUpgradeCopy('titleLicence'),
    subtitle: licenceUpgradeCopy('optionsSubtitle'),
    current: projectCurrentLicenceDetail(input.projection, timeZone),
    options,
    noHigher: options.length === 0,
    noHigherMessage: options.length === 0 ? licenceUpgradeCopy('noHigherMessage') : null,
    enterprise:
      input.projection.enterprise === null
        ? null
        : projectEnterpriseFacts(input.projection.enterprise),
    selectionLocked: live,
    lockedTargetName,
  };
}

/** C0 facts; null unless a draft matches the FRESH options and no lock/stale. */
export function projectConfirmationViewFacts(
  input: LicenceUpgradePresentationInput,
  draft: LicenceDraftSelection | null,
  timeZone: string,
): LicenceConfirmationViewFacts | null {
  if (draft === null || input.projection === null) {
    return null;
  }
  if (hasLiveUpgradeOperation(input.upgradeOperation)) {
    return null; // one selection lock; confirmation is closed while pending
  }
  if (input.upgradeOperation !== null && input.upgradeOperation.status === 'stale') {
    return null; // typed stale requires fresh review first
  }
  if (!draftMatchesFreshOptions(input.projection, draft)) {
    return null; // the requested change is no longer available on fresh truth
  }
  const currentSide = {
    displayName: input.projection.displayName,
    capText: conciseLicenceCapText(input.projection),
    validityText: conciseLicenceValidityText(input.projection, timeZone),
    governanceText: (() => {
      const labels = governanceLabels(input.projection.allowedGovernanceOptionIds);
      return labels.length > 0 ? labels.join('; ') : null;
    })(),
    // A perpetual term is already shown by validityText; never duplicated.
    termText: (() => {
      const term = licenceTermLabel(input.projection.termKind, input.projection.termYears);
      return term === null || term === licenceUpgradeCopy('valuePerpetual') ? null : term;
    })(),
  };
  return {
    view: 'confirmation',
    heading: licenceUpgradeCopy('titleConfirmActivation'),
    subtitle: licenceUpgradeCopy('confirmSubtitle'),
    currentSide,
    targetSide: {
      displayName: draft.displayName,
      description: draft.description,
      capText: draft.capText,
      electionsText: draft.electionsText,
      termText: draft.termText,
    },
    reference: licenceReferenceFacts(input.projection.licenceReference, 'full'),
    catalogueVersion: input.projection.catalogueVersion,
    consequences: [...LICENCE_CONFIRMATION_CONSEQUENCES],
  };
}

/** Resolve the live operation display name of the current plan (fresh truth). */
function currentPlanNameOf(input: LicenceUpgradePresentationInput): string | null {
  if (input.projection !== null) {
    return input.projection.displayName;
  }
  if (input.upgradeOperation !== null && input.upgradeOperation.currentPlanDisplayName !== null) {
    return input.upgradeOperation.currentPlanDisplayName;
  }
  return null;
}

/** P0 facts for a live pending operation (old indexed licence stays current). */
export function projectProgressViewFacts(
  input: LicenceUpgradePresentationInput,
): LicenceProgressViewFacts | null {
  const operation = input.upgradeOperation;
  if (!hasLiveUpgradeOperation(operation)) {
    return null;
  }
  const currentName = currentPlanNameOf(input);
  const targetName = operation.targetPlanDisplayName;
  return {
    view: 'progress',
    heading: licenceUpgradeCopy('titleUpgradePending'),
    waitingMessage: targetName === null ? null : pendingWaitingMessage(targetName),
    statusText: licenceUpgradeCopy('waitingForIndexedActivation'),
    currentRemainsMessage:
      currentName === null ? null : currentRemainsActiveMessage(currentName),
    existingLimitsMessage: licenceUpgradeCopy('existingLimitsContinue'),
    reassurance: licenceUpgradeCopy('reassuranceLeaving'),
    currentName,
    targetName,
    ariaBusy: true,
  };
}

/** D0 facts for a delayed/paused live operation (exact Retry available). */
export function projectDelayedViewFacts(
  input: LicenceUpgradePresentationInput,
): LicenceDelayedViewFacts | null {
  const operation = input.upgradeOperation;
  if (operation === null || operation.status !== 'delayed') {
    return null;
  }
  const currentName = currentPlanNameOf(input);
  const targetName = operation.targetPlanDisplayName;
  return {
    view: 'delayed',
    heading: licenceUpgradeCopy('titleDelayed'),
    targetMessage: targetName === null ? null : delayedTargetMessage(targetName),
    currentMessage: currentName === null ? null : delayedCurrentMessage(currentName),
    retryExplainer: licenceUpgradeCopy('delayedRetryExplainer'),
  };
}

/** R0 facts after exact indexed local success. */
export function projectResultViewFacts(
  input: LicenceUpgradePresentationInput,
  timeZone: string,
): LicenceResultViewFacts | null {
  const operation = input.upgradeOperation;
  if (operation === null || operation.status !== 'local-success') {
    return null;
  }
  const activeMessage =
    operation.targetPlanDisplayName === null
      ? null
      : resultActiveMessage(operation.targetPlanDisplayName);
  return {
    view: 'result',
    heading: licenceUpgradeCopy('titleLicenceActivated'),
    activeMessage,
    current: input.projection === null ? null : projectCurrentLicenceDetail(input.projection, timeZone),
  };
}

/** S0 facts after a typed stale outcome (selection cleared; fresh review). */
export function projectStaleViewFacts(
  input: LicenceUpgradePresentationInput,
  timeZone: string,
): LicenceStaleViewFacts | null {
  const operation = input.upgradeOperation;
  if (operation === null || operation.status !== 'stale') {
    return null;
  }
  const fresh =
    input.projection === null
      ? null
      : projectOptionsViewFacts(input, timeZone, null);
  return {
    view: 'stale',
    heading: licenceUpgradeCopy('titleLicence'),
    notice: licenceUpgradeCopy('staleNotice'),
    reason: operation.reason,
    fresh,
  };
}

/**
 * Closed gate/recovery view facts for the licence workspace entry (L0/E0).
 */
export function projectLicenceEntryViewFacts(
  input: LicenceUpgradePresentationInput,
): LicenceGateViewFacts | LicenceRecoveryViewFacts {
  if (isLicenceRecoveryRequired(input)) {
    return { view: 'recovery', reason: licenceRecoveryReasonOf(input), rememberNothing: true };
  }
  return { view: 'gate', reuseEntitlementGate: true, heading: null };
}

/**
 * Deterministic per-view facts of the licence workspace. `view` is the
 * requested surface; each builder validates it against authority state so
 * presentation can never render a screen the authority does not permit.
 */
export function projectLicenceWorkspaceViewFacts(
  input: LicenceUpgradePresentationInput,
  view: LicenceWorkspaceView,
  draft: LicenceDraftSelection | null,
  timeZone: string,
): LicenceWorkspaceViewFacts | null {
  switch (view) {
    case 'gate':
      return projectLicenceEntryViewFacts(input).view === 'gate'
        ? { view: 'gate', reuseEntitlementGate: true, heading: null }
        : null;
    case 'recovery':
      return isLicenceRecoveryRequired(input)
        ? { view: 'recovery', reason: licenceRecoveryReasonOf(input), rememberNothing: true }
        : null;
    case 'options':
      return projectOptionsViewFacts(input, timeZone, draft);
    case 'confirmation':
      return projectConfirmationViewFacts(input, draft, timeZone);
    case 'progress':
      return projectProgressViewFacts(input);
    case 'delayed':
      return projectDelayedViewFacts(input);
    case 'result':
      return projectResultViewFacts(input, timeZone);
    case 'stale':
      return projectStaleViewFacts(input, timeZone);
    default: {
      const never: never = view;
      return never;
    }
  }
}

/**
 * The surface the licence workspace restores to after reload/Forward/
 * remount/restored history: derived from AUTHORITY STATE ONLY (no draft, no
 * history step). It can never restore a discarded confirmation or invoke
 * activation. Live pending/delayed restore to their progress surface; a
 * retained local-success terminal restores to the result; typed stale
 * restores to S0; fresh truth restores to options.
 */
export function projectRestoredLicenceSurface(
  input: LicenceUpgradePresentationInput,
): LicenceWorkspaceView {
  if (isLicenceRecoveryRequired(input)) {
    return 'recovery';
  }
  if (phaseOf(input) === 'resolving') {
    return 'gate';
  }
  const operation = input.upgradeOperation;
  if (operation !== null) {
    switch (operation.status) {
      case 'pending':
        return 'progress';
      case 'delayed':
        return 'delayed';
      case 'local-success':
        return 'result';
      case 'stale':
        return 'stale';
      case 'competing-activation':
        return 'options';
    }
  }
  return 'options';
}

// ---------------------------------------------------------------------------
// Back / history contract (browser, in-app, and Android equivalence).
// ---------------------------------------------------------------------------

export type LicenceBackOrigin = 'browser' | 'inApp' | 'android';

export type LicenceBackVerdict =
  | { readonly kind: 'close-account' } // A0: close flyout, restore trigger focus
  | { readonly kind: 'leave-discard-draft' } // unsubmitted: exit flow; draft discarded
  | { readonly kind: 'return-to-options'; readonly draftRetained: true } // C0 in-app back
  | { readonly kind: 'leave-keep-pending' } // submitted P0/D0: exit; operation continues + N0
  | { readonly kind: 'leave-after-result' }; // R0 exit

/**
 * Deterministic Back verdict per surface + origin. Browser and Android Back
 * are the shared OS-level transition (draft discard / pending leave); the
 * in-app control differs only on C0 where its label is the dedicated
 * secondary action "Back to plans" (returns to options with the draft still
 * highlighted). Every outcome is idempotent: no activation can be replayed
 * and no discarded confirmation can be restored.
 */
export function projectLicenceBackVerdict(
  surface: LicenceWorkspaceView | 'account',
  origin: LicenceBackOrigin,
): LicenceBackVerdict {
  switch (surface) {
    case 'account':
      return { kind: 'close-account' };
    case 'confirmation':
      return origin === 'inApp'
        ? { kind: 'return-to-options', draftRetained: true }
        : { kind: 'leave-discard-draft' };
    case 'progress':
    case 'delayed':
      return { kind: 'leave-keep-pending' };
    case 'result':
      return { kind: 'leave-after-result' };
    case 'options':
    case 'stale':
    case 'recovery':
    case 'gate':
      return { kind: 'leave-discard-draft' };
    default: {
      const never: never = surface;
      return never;
    }
  }
}

/**
 * Shared typed Back transition source: browser and Android ALWAYS dispatch
 * through the same projection as each other (equivalence by construction).
 */
export const OS_LEVEL_BACK_ORIGINS: readonly LicenceBackOrigin[] = ['browser', 'android'] as const;

// ---------------------------------------------------------------------------
// Focus management and live-region policy.
// ---------------------------------------------------------------------------

export type LicenceFocusTarget = 'heading' | 'notice-heading' | 'status' | 'option-control' | 'none';

/** Focus destination on entering a licence workspace view. */
export function licenceFocusTargetFor(view: LicenceWorkspaceView): LicenceFocusTarget {
  switch (view) {
    case 'stale':
      return 'notice-heading';
    case 'confirmation':
    case 'result':
    case 'delayed':
    case 'progress':
      return 'heading';
    case 'options':
    case 'gate':
    case 'recovery':
      return 'heading';
    default: {
      const never: never = view;
      return never;
    }
  }
}

/**
 * Live-region announcement policy for one view change. Meaningful entries
 * announce once (polite); staying on the same view across three-second query
 * refreshes never announces (no poll spam); N1 never moves focus.
 */
export interface LicenceAnnouncementPolicy {
  readonly announce: boolean;
  readonly polite: boolean;
  readonly focus: LicenceFocusTarget;
}

export function licenceAnnouncementPolicy(
  previousView: LicenceWorkspaceView | 'none',
  nextView: LicenceWorkspaceView,
): LicenceAnnouncementPolicy {
  if (previousView === nextView) {
    // Same surface (e.g. repeated query result): silent; no announcement spam.
    return { announce: false, polite: true, focus: 'none' };
  }
  const focus = licenceFocusTargetFor(nextView);
  switch (nextView) {
    case 'progress':
    case 'delayed':
    case 'result':
    case 'stale':
    case 'recovery':
      return { announce: true, polite: true, focus };
    case 'confirmation':
    case 'options':
    case 'gate':
      return { announce: false, polite: true, focus };
    default: {
      const never: never = nextView;
      return never;
    }
  }
}

// ---------------------------------------------------------------------------
// N0 (persistent global pending indicator) and N1 (one-time activation
// notification) projections.
// ---------------------------------------------------------------------------

/** Surfaces the user can currently be on (for N0/N1 placement rules). */
export type LicenceCurrentSurface =
  | 'workspace'
  | 'account'
  | 'licence-options'
  | 'licence-confirmation'
  | 'licence-progress'
  | 'licence-delayed'
  | 'licence-result'
  | 'gate'
  | 'recovery';

export interface LicencePendingIndicatorFacts {
  /** Visible only while a live operation exists and the user is not already on it. */
  readonly visible: boolean;
  readonly visibleLabel: string | null;
  readonly accessibleLabel: string | null;
  readonly targetPlanName: string | null;
}

/**
 * N0 — persistent global pending control. Reachable while the Account flyout
 * is closed and while the user works anywhere under the old indexed limits;
 * hidden only while the user is already on the operation's own progress
 * surface. Never submits, retries, or creates a selection.
 */
export function projectPendingIndicator(
  input: LicenceUpgradePresentationInput,
  currentSurface: LicenceCurrentSurface,
): LicencePendingIndicatorFacts {
  const operation = input.upgradeOperation;
  if (!hasLiveUpgradeOperation(operation)) {
    return { visible: false, visibleLabel: null, accessibleLabel: null, targetPlanName: null };
  }
  const targetName = operation.targetPlanDisplayName;
  if (currentSurface === 'licence-progress' || currentSurface === 'licence-delayed') {
    return { visible: false, visibleLabel: null, accessibleLabel: null, targetPlanName: targetName };
  }
  if (targetName === null) {
    return { visible: false, visibleLabel: null, accessibleLabel: null, targetPlanName: null };
  }
  return {
    visible: true,
    visibleLabel: pendingIndicatorVisibleLabel(targetName),
    accessibleLabel: pendingIndicatorAccessibleLabel(targetName),
    targetPlanName: targetName,
  };
}

export interface LicenceActivationNotificationFacts {
  /** Visible exactly while one-shot eligibility is armed AND user is elsewhere. */
  readonly visible: boolean;
  readonly message: string | null;
  readonly planName: string | null;
  /** Actions: View licence (enters L0 → details) or Dismiss (removes once). */
  readonly viewLicenceAction: true;
  readonly dismissAction: true;
  /** N1 never redirects, never steals focus, never repeats. */
  readonly noFocusMovement: true;
  readonly noRedirect: true;
  readonly announceOnce: true;
}

/**
 * N1 — one-time activation notification while the user is elsewhere.
 * Eligibility is authority-owned and one-shot (local-success, before
 * acknowledgement). Never shown when R0/progress already surfaces the result,
 * never claims a competing-device activation as local success.
 */
export function projectActivationNotification(
  input: LicenceUpgradePresentationInput,
  currentSurface: LicenceCurrentSurface,
): LicenceActivationNotificationFacts {
  const operation = input.upgradeOperation;
  const eligible =
    input.upgradeNotificationEligible &&
    operation !== null &&
    operation.status === 'local-success' &&
    currentSurface !== 'licence-progress' &&
    currentSurface !== 'licence-delayed' &&
    currentSurface !== 'licence-result';
  if (!eligible) {
    return {
      visible: false,
      message: null,
      planName: null,
      viewLicenceAction: true,
      dismissAction: true,
      noFocusMovement: true,
      noRedirect: true,
      announceOnce: true,
    };
  }
  const planName = operation.targetPlanDisplayName;
  return {
    visible: true,
    message: planName === null ? null : activationNotificationMessage(planName),
    planName,
    viewLicenceAction: true,
    dismissAction: true,
    noFocusMovement: true,
    noRedirect: true,
    announceOnce: true,
  };
}
