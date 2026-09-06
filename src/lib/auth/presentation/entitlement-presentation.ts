/**
 * FEAT-016 Task 4.3 — safe entitlement gate presentation model.
 *
 * Exhaustive render-safe mapping from entitlement stage (+ connectivity) to
 * approved copy, control availability, busy semantics, live-region policy,
 * and deterministic focus placement. This is the ONLY presentation vocabulary
 * for the gate: exact approved copy from the FEAT-016 contract; no raw gRPC,
 * transaction, plan, address, or free-form server text ever reaches it.
 *
 * Normative source: FEAT-016 FeatureDescription "User Experience" (exact
 * stage copy; Ready/Back/accessibility); Wireframes-design.md G0–G7.
 */

/** Control policy per stage. */
export interface EntitlementGateControls {
  /** Retry available (recoverable error/delayed/unsupported checks). */
  readonly retry: boolean;
  /** Lock is always available while the gate is visible. */
  readonly lock: boolean;
}

export interface EntitlementStagePresentation {
  /** Deterministic copy key (stage or explicit offline variant). */
  readonly key: string;
  /** `role="status"`-safe status text. */
  readonly statusLabel: string;
  /** Primary body copy. */
  readonly bodyCopy: string;
  /** True when a busy indicator is appropriate (no announcement spam). */
  readonly busy: boolean;
  /** `aria-busy` on the gate. */
  readonly ariaBusy: boolean;
  readonly controls: EntitlementGateControls;
  /** Autofocus target: heading role name for screen readers. */
  readonly focusHeading: boolean;
  /** Live-region announcements only on meaningful changes (no poll spam). */
  readonly liveAnnounce: boolean;
}

export type PresentationEntitlementStage =
  | 'entitlementResolving'
  | 'baselineSigning'
  | 'baselineSubmitting'
  | 'awaitingIndex'
  | 'confirmationDelayed'
  | 'entitlementUnavailable'
  | 'entitlementUnsupported'
  | 'entitlementRepair';

export type GateConnectivityVariant = 'online' | 'paused' | 'offline' | 'reconnecting' | 'unknown';

/** Approved support-code format; anything else is redacted to null. */
const SUPPORT_CODE_RE = /^[A-Z0-9]{4}-[A-Z0-9]{4}$/;

/** Bound/redact an optional machine support code (never free-form text). */
export function safeRedactedSupportCode(code: string | null): string | null {
  if (code === null) {
    return null;
  }
  return SUPPORT_CODE_RE.test(code) ? code : null;
}

const RETRY_ONLY: EntitlementGateControls = { retry: true, lock: true };
const LOCK_ONLY: EntitlementGateControls = { retry: false, lock: true };

const RESOLVING: EntitlementStagePresentation = {
  key: 'resolving',
  statusLabel: 'Checking licence',
  bodyCopy: 'Checking your HushVoting! licence…',
  busy: true,
  ariaBusy: true,
  controls: LOCK_ONLY,
  focusHeading: true,
  liveAnnounce: true,
};

const BASELINE_SETUP: EntitlementStagePresentation = {
  key: 'baselineSetup',
  statusLabel: 'Setting up Direct Free',
  bodyCopy: 'Setting up HushVoting! Direct Free…',
  busy: true,
  ariaBusy: true,
  controls: LOCK_ONLY,
  focusHeading: false,
  liveAnnounce: true,
};

const AWAITING_INDEX: EntitlementStagePresentation = {
  key: 'awaitingIndex',
  statusLabel: 'Waiting for network activation',
  bodyCopy: 'Waiting for the network to activate your licence…',
  busy: true,
  ariaBusy: true,
  controls: LOCK_ONLY,
  focusHeading: false,
  liveAnnounce: false, // no three-second announcement spam
};

const DELAYED: EntitlementStagePresentation = {
  key: 'confirmationDelayed',
  statusLabel: 'Activation is delayed',
  bodyCopy: 'Licence activation is taking longer than expected.',
  busy: false,
  ariaBusy: false,
  controls: RETRY_ONLY,
  focusHeading: true,
  liveAnnounce: true,
};

const UNAVAILABLE: EntitlementStagePresentation = {
  key: 'entitlementUnavailable',
  statusLabel: 'Licence cannot be verified',
  bodyCopy:
    'We couldn’t verify your licence. HushVoting! cannot open until verification succeeds.',
  busy: false,
  ariaBusy: false,
  controls: RETRY_ONLY,
  focusHeading: true,
  liveAnnounce: true,
};

const UNSUPPORTED: EntitlementStagePresentation = {
  key: 'entitlementUnsupported',
  statusLabel: 'Compatibility update needed',
  bodyCopy: 'Your client or licence needs an update before HushVoting! can open.',
  busy: false,
  ariaBusy: false,
  controls: RETRY_ONLY,
  focusHeading: true,
  liveAnnounce: true,
};

const REPAIR: EntitlementStagePresentation = {
  key: 'entitlementRepair',
  statusLabel: 'Repairing licence setup',
  bodyCopy: 'We’re repairing your licence setup. This may take a moment.',
  busy: true,
  ariaBusy: true,
  controls: LOCK_ONLY,
  focusHeading: true,
  liveAnnounce: true,
};

const OFFLINE: EntitlementStagePresentation = {
  key: 'offline',
  statusLabel: 'Connection lost',
  bodyCopy: 'Connection lost. Reconnect to continue.',
  busy: false,
  ariaBusy: false,
  controls: LOCK_ONLY,
  focusHeading: true,
  liveAnnounce: true,
};

/**
 * Presentation for one gated stage. Connectivity offline/reconnecting wins
 * over an active business stage; paused shows the delayed variant copy.
 */
export function entitlementGatePresentation(
  stage: PresentationEntitlementStage | 'entitlementReady' | null,
  connectivity: GateConnectivityVariant,
): EntitlementStagePresentation | null {
  if (connectivity === 'offline' || connectivity === 'reconnecting') {
    return OFFLINE;
  }
  if (stage === null || stage === 'entitlementReady') {
    return null; // ready → workspace mounts; nothing renders the gate
  }
  switch (stage) {
    case 'entitlementResolving':
      return RESOLVING;
    case 'baselineSigning':
    case 'baselineSubmitting':
      return BASELINE_SETUP;
    case 'awaitingIndex':
      return connectivity === 'paused' ? DELAYED : AWAITING_INDEX;
    case 'confirmationDelayed':
      return DELAYED;
    case 'entitlementUnavailable':
      return UNAVAILABLE;
    case 'entitlementUnsupported':
      return UNSUPPORTED;
    case 'entitlementRepair':
      return REPAIR;
  }
}

/** Deterministic busy/live-region guidance for the status region. */
export function gateLiveRegionPolicy(presentation: EntitlementStagePresentation | null): {
  readonly announce: boolean;
  readonly polite: boolean;
} {
  if (presentation === null) {
    return { announce: false, polite: true };
  }
  return { announce: presentation.liveAnnounce, polite: true };
}
