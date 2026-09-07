/**
 * FEAT-017 Task 4.3 — shared English copy for the Account licence summary and
 * the full-width licence workflow (A0, L0, L1/L2, S0, C0, P0, D0, R0, N0, N1,
 * E0). The ONLY source of the canonical FEAT-017 strings: presentation
 * modules and (Phase 5) UI components resolve every new string through this
 * module so no scattered, provider-derived, or server-parsed text can reach a
 * screen. English-only per D017-07.
 *
 * All static strings are the exact copy from design-summary.md "Canonical
 * Copy" and the approved wireframes. Section-band labels ("Current licence",
 * "Available higher plans", …) are stored in natural case; the existing
 * `text-transform: uppercase` presentation token (globals.css) applies the
 * visual band styling — copy text itself never changes case per device.
 *
 * Interpolated values ({plan}/{target} names, caps, dates, references) are
 * ALWAYS bounded validated presentation facts resolved by the authority or
 * the presentation helpers — never free-form provider text and never
 * client-authored policy. This module performs no date/ref formatting itself;
 * see local-instant.ts and licence-reference.ts.
 *
 * SECRET/POLICY BOUNDARY: nothing here can carry raw transaction bytes,
 * signatures, bindings, journal state, prices, payment, provider contact,
 * or any actionable Enterprise/renewal/downgrade/cancellation path.
 *
 * Normative source: FEAT-017 FeatureDescription D017-07; design-summary.md
 * "Canonical Copy"; Wireframes-design.md screen copy; FEAT-012 frozen
 * governance-option vocabulary; planning-analysis-report §8.
 */

/** Closed canonical static copy (one key per string; exact approved text). */
export const LICENCE_UPGRADE_COPY = {
  // Account + workspace action labels (canonical copy table).
  actionUpgrade: 'Upgrade',
  actionViewLicence: 'View licence',
  actionViewProgress: 'View progress',
  actionReviewPlan: 'Review plan',
  actionActivateLicence: 'Activate licence',
  actionBackToPlans: 'Back to plans',
  actionContinueWorking: 'Continue working',
  actionRetry: 'Retry',
  actionDismiss: 'Dismiss',
  actionReturnToWorkspace: 'Return to workspace',
  actionViewCurrentLicence: 'View current licence',
  actionCopy: 'Copy',
  actionBack: 'Back',
  accountRefLabel: 'Ref',

  // Status / pending / notification copy.
  statusActive: 'Active',
  statusUpgradePending: 'Upgrade pending',
  currentLimitsRemainInEffect: 'Current limits remain in effect',
  waitingForIndexedActivation: 'Waiting for indexed activation',

  // Licence workspace titles/subtitles.
  titleLicence: 'Licence',
  titleConfirmActivation: 'Confirm licence activation',
  confirmSubtitle: 'Review the exact licence change before activating it.',
  titleUpgradePending: 'Upgrade pending',
  titleDelayed: 'Licence activation is taking longer than expected.',
  titleLicenceActivated: 'Licence activated',
  optionsSubtitle: 'Review your current licence and available higher self-service plans.',

  // Section bands (natural case; uppercase is a CSS presentation token).
  sectionCurrentLicence: 'Current licence',
  sectionAvailableHigherPlans: 'Available higher plans',
  sectionEnterprise: 'Enterprise',
  sectionLicenceReference: 'Licence reference',
  sectionCatalogueVersion: 'Catalogue version',
  sectionWhatHappens: 'What happens',
  labelCurrent: 'Current',
  labelTarget: 'Target',
  labelPendingTarget: 'Pending target',
  labelSelected: 'Selected',

  // No-higher, stale, and Enterprise copy.
  noHigherMessage: 'No higher self-service plan is available.',
  staleNotice: 'Your licence or available plans have changed. Please review the updated options.',
  enterpriseTag: 'Contact provider — not yet available',

  // Progress/delayed body copy.
  reassuranceLeaving:
    'You can continue working. Leaving this page does not cancel, restart, or resubmit the activation.',
  existingLimitsContinue:
    'Existing limits continue until indexed activation confirms the change.',
  delayedRetryExplainer:
    'Retry safely resends the same protected transaction. It does not select or create another upgrade.',

  // Confirmation consequence list (C0, in order).
  consequenceIndexedOnly: 'The target becomes active only after indexed network confirmation.',
  consequenceSupersedes: 'Once indexed, it immediately supersedes the current licence.',
  consequenceOneYearTerm: 'The new term lasts one year from the committed activation instant.',
  consequenceNoDowngrade: 'Downgrade, cancellation, and renewal before expiry are unavailable.',
  consequenceNoPayment: 'No price or payment is part of this v1 activation.',

  // Metric labels and simple values.
  metricEligibleVoters: 'Eligible voters',
  metricElections: 'Elections',
  metricValidity: 'Validity',
  metricGovernance: 'Governance',
  metricTerm: 'Term',
  valueUnlimited: 'Unlimited',
  valuePerpetual: 'Perpetual',
  valueOneYearTerm: 'One-year term',
  valueNoCustomerTrustees: 'No customer trustees',

  // Local-instant labels (upper-exclusive semantics kept explicit).
  effectiveFromLabel: 'Effective from:',
  expiresExclusiveLabel: 'Expires (exclusive):',
  validUntilBoundaryNote: 'Valid until the displayed expiry moment.',
  licenceValidityPrefix: 'Expires ',

  // Reference / clipboard feedback copy.
  copySuccessFeedback: 'Copied licence reference.',
  copyFailureFeedback: 'Couldn’t copy. Select the licence reference to copy it manually.',
} as const;

export type LicenceUpgradeCopyKey = keyof typeof LICENCE_UPGRADE_COPY;

/** Typed accessor: the ONLY string read path for static FEAT-017 copy. */
export function licenceUpgradeCopy(key: LicenceUpgradeCopyKey): string {
  return LICENCE_UPGRADE_COPY[key];
}

/** Every static key in one frozen list (copy-coverage scans iterate this). */
export const LICENCE_UPGRADE_COPY_KEYS: readonly LicenceUpgradeCopyKey[] =
  Object.keys(LICENCE_UPGRADE_COPY) as LicenceUpgradeCopyKey[];

/**
 * Frozen FEAT-012 governance-option label map (stable canonical ids only).
 * Unknown ids resolve to null and are OMITTED by presentation — a label is
 * never inferred, and no client catalogue or rank table is implied.
 */
export const GOVERNANCE_OPTION_LABELS: Readonly<Record<string, string>> = {
  'no-customer-trustees': LICENCE_UPGRADE_COPY.valueNoCustomerTrustees,
  'trustees-3of5': '3-of-5 trustees',
  'trustees-7of10': '7-of-10 trustees',
  'trustees-8of13': '8-of-13 trustees',
} as const;

export const KNOWN_GOVERNANCE_OPTION_IDS = Object.keys(GOVERNANCE_OPTION_LABELS) as readonly string[];

/** Resolve a canonical governance-option label; null when unknown (never fabricate). */
export function governanceOptionLabel(optionId: string): string | null {
  const label = GOVERNANCE_OPTION_LABELS[optionId];
  return typeof label === 'string' ? label : null;
}

/** Join multiple mapped governance labels deterministically. */
export function governanceLabels(optionIds: readonly string[]): string[] {
  const labels: string[] = [];
  for (const id of optionIds) {
    const label = governanceOptionLabel(id);
    if (label !== null && !labels.includes(label)) {
      labels.push(label);
    }
  }
  return labels;
}

// ---------------------------------------------------------------------------
// Interpolated copy (values are bounded validated presentation facts only).
// ---------------------------------------------------------------------------

/** N0 visible control: "Upgrade pending · Veritas 2k". */
export function pendingIndicatorVisibleLabel(targetPlanName: string): string {
  return `${LICENCE_UPGRADE_COPY.statusUpgradePending} · ${targetPlanName}`;
}

/** N0 accessible name: "Upgrade pending for HushVoting! Veritas 2k. View progress." */
export function pendingIndicatorAccessibleLabel(targetPlanName: string): string {
  return `${LICENCE_UPGRADE_COPY.statusUpgradePending} for ${targetPlanName}. ${LICENCE_UPGRADE_COPY.actionViewProgress}.`;
}

/** N1 message: "Your HushVoting! Veritas 2k licence is now active". */
export function activationNotificationMessage(planName: string): string {
  return `Your ${planName} licence is now active`;
}

/** R0 heading-adjacent line: "HushVoting! Veritas 2k is now active." */
export function resultActiveMessage(planName: string): string {
  return `${planName} is now active.`;
}

/** P0 primary waiting line: "Waiting for the network to activate HushVoting! Veritas 2k…". */
export function pendingWaitingMessage(targetPlanName: string): string {
  return `Waiting for the network to activate ${targetPlanName}…`;
}

/** P0 current-licence line: "HushVoting! Direct Free remains active." */
export function currentRemainsActiveMessage(currentPlanName: string): string {
  return `${currentPlanName} remains active.`;
}

/** D0 target line: "HushVoting! Veritas 2k may still be waiting for indexed confirmation." */
export function delayedTargetMessage(targetPlanName: string): string {
  return `${targetPlanName} may still be waiting for indexed confirmation.`;
}

/** D0 current line: "Your current HushVoting! Direct Free licence remains active." */
export function delayedCurrentMessage(currentPlanName: string): string {
  return `Your current ${currentPlanName} licence remains active.`;
}

/** Cap metric: "Up to 2,000 eligible voters". */
export function upToEligibleVotersText(cap: number): string {
  return `Up to ${cap.toLocaleString('en-GB')} eligible voters`;
}

/** Multi-year term text (term label is fabricated only from numeric term years). */
export function multiYearTermText(termYears: number): string {
  return `${termYears}-year term`;
}

/** Frozen consequence bullets shown on C0 (exact order and text). */
export const LICENCE_CONFIRMATION_CONSEQUENCES: readonly string[] = [
  LICENCE_UPGRADE_COPY.consequenceIndexedOnly,
  LICENCE_UPGRADE_COPY.consequenceSupersedes,
  LICENCE_UPGRADE_COPY.consequenceOneYearTerm,
  LICENCE_UPGRADE_COPY.consequenceNoDowngrade,
  LICENCE_UPGRADE_COPY.consequenceNoPayment,
] as const;
