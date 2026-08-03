/**
 * FEAT-006 Android safe-state projections (Phase 5, Task 5.1).
 *
 * Every closed Android result maps deterministically to one safe view:
 * heading, body copy, approved actions, retry semantics, and a live-region
 * announcement. No hardware class, exact model, alias, path, identity, raw
 * exception, or support-code echo is ever displayed. Unknown values fail
 * closed to generic safe guidance. This module is pure and fully testable;
 * the shared FEAT-002 shell renders the returned views.
 *
 * Normative source: FEAT-006 FeatureDescription "Unsupported-Environment UX",
 * "Error, Throttling, and Diagnostics"; contracts RECOVERY_ACTIONS_BY_CODE.
 */

import {
  AndroidResultCode,
  ANDROID_RESULT_CODES,
  isRetryableCode,
  RECOVERY_ACTIONS_BY_CODE,
} from './contracts';

/** Approved UI actions (rendered only from the closed recovery-action set). */
export type SafeAction =
  | { readonly kind: 'retry' }
  | { readonly kind: 'openSecuritySettings' }
  | { readonly kind: 'updateApp' }
  | { readonly kind: 'removeLocalUser' }
  | { readonly kind: 'portableRecovery' }
  | { readonly kind: 'resumeRemoval' }
  | { readonly kind: 'cancel' };

/** One safe Android remediation view (no secret/raw detail fields). */
export interface SafeStateView {
  readonly code: AndroidResultCode;
  readonly heading: string;
  readonly body: string;
  /** Approved actions in order (from the closed recovery-action set). */
  readonly actions: readonly SafeAction[];
  readonly retryable: boolean;
  /** Bounded retry deadline in seconds (0 = none). */
  readonly retryDeadlineSecs: number;
  /** Accessible live-region announcement (non-secret). */
  readonly liveRegion: string;
  /** Whether this view is informational only (no destructive action). */
  readonly informational: boolean;
}

/** Renderable copy per closed code (no secret/raw detail, no continue-anyway). */
const COPY: Readonly<Record<AndroidResultCode, { heading: string; body: string; informational: boolean }>> = {
  ok: { heading: 'Ready', body: '', informational: true },
  secureLockRequired: {
    heading: 'Secure screen lock required',
    body: 'HushVoting protects your credentials with your device screen lock plus a hardware-backed key. Set up a secure lock screen to continue, or remove your local HushVoting user on this device.',
    informational: false,
  },
  deviceLocked: {
    heading: 'Device locked',
    body: 'Unlock your device to continue.',
    informational: true,
  },
  hardwareBackedKeystoreUnavailable: {
    heading: 'Hardware-backed protection unavailable',
    body: 'This device does not provide the required hardware-backed key protection. Update the app or use another supported device.',
    informational: false,
  },
  unsupportedKnownBadBuild: {
    heading: 'This device build is not supported',
    body: 'This device/build is blocked for security reasons. Update your Android system or use another supported device.',
    informational: false,
  },
  temporaryKeystoreFailure: {
    heading: 'Security service busy',
    body: 'The security service did not respond. Try again shortly.',
    informational: true,
  },
  platformProtectionInvalidated: {
    heading: 'Local protection changed',
    body: 'Your encrypted files are preserved, but the local protection key changed. You can update the app, remove the local user, or restore from recovery words or an exported credential file.',
    informational: false,
  },
  wrapperIntegrityFailure: {
    heading: 'Protected data check failed',
    body: 'The protected data could not be verified. No password was attempted. Contact support with the support code.',
    informational: false,
  },
  buildProtocolMismatch: {
    heading: 'App version mismatch',
    body: 'The app components do not match. Update HushVoting to continue.',
    informational: false,
  },
  storageUnavailable: {
    heading: 'Storage unavailable',
    body: 'Local storage is not accessible right now. Try again shortly.',
    informational: true,
  },
  storageQuotaExceeded: {
    heading: 'Storage full',
    body: 'Local storage is full. Free some space and try again.',
    informational: true,
  },
  unsupportedWrapperVersion: {
    heading: 'Newer protected format detected',
    body: 'This protected data uses a newer format. Update HushVoting to continue. Your files are preserved.',
    informational: false,
  },
  staleSession: {
    heading: 'Session ended',
    body: 'Your session ended. Sign in again.',
    informational: true,
  },
  cleanupRemovalIncomplete: {
    heading: 'Removal incomplete',
    body: 'Removing the local user did not finish. Retry to complete it safely.',
    informational: false,
  },
  kdfResourceLimit: {
    heading: 'Security processing limit',
    body: 'This device cannot run the required secure processing within safe limits. Update the app or use another supported device.',
    informational: false,
  },
  networkTimeout: {
    heading: 'Verification timed out',
    body: 'Could not verify your identity online. Check your connection and retry.',
    informational: true,
  },
  wrongPasswordOrDamagedData: {
    heading: 'Password or data issue',
    body: 'The password did not match, or the local data is damaged. Try again, or restore from recovery words or an exported credential file.',
    informational: false,
  },
};

/** Map a closed recovery action to the safe UI action (closed vocabulary). */
function toSafeAction(action: string): SafeAction {
  switch (action) {
    case 'retry':
      return { kind: 'retry' };
    case 'openSecuritySettings':
      return { kind: 'openSecuritySettings' };
    case 'updateApp':
      return { kind: 'updateApp' };
    case 'removeLocalUser':
      return { kind: 'removeLocalUser' };
    case 'portableRecovery':
      return { kind: 'portableRecovery' };
    case 'resumeRemoval':
      return { kind: 'resumeRemoval' };
    default:
      return { kind: 'cancel' };
  }
}

/** Resolve the safe view for one closed result code. */
export function safeStateView(code: AndroidResultCode): SafeStateView {
  const copy = COPY[code];
  const actions = (RECOVERY_ACTIONS_BY_CODE[code] ?? []).map(toSafeAction);
  return {
    code,
    heading: copy.heading,
    body: copy.body,
    actions,
    retryable: isRetryableCode(code),
    retryDeadlineSecs: 0,
    liveRegion: `${copy.heading}. ${copy.body}`,
    informational: copy.informational,
  };
}

/** Resolve a safe view from an unknown value; fails closed to generic guidance. */
export function safeStateViewFromUnknown(value: unknown): SafeStateView {
  if (typeof value === 'string' && (ANDROID_RESULT_CODES as readonly string[]).includes(value)) {
    return safeStateView(value as AndroidResultCode);
  }
  return {
    code: 'staleSession',
    heading: 'Something went wrong',
    body: 'Try again. If this continues, update HushVoting.',
    actions: [{ kind: 'retry' }],
    retryable: true,
    retryDeadlineSecs: 0,
    liveRegion: 'Something went wrong. Try again.',
    informational: false,
  };
}

/** Every declared code resolves to a safe view (exhaustiveness guard). */
export const ALL_SAFE_STATE_VIEWS: Readonly<Record<AndroidResultCode, SafeStateView>> = Object.fromEntries(
  ANDROID_RESULT_CODES.map((code) => [code, safeStateView(code)]),
) as Readonly<Record<AndroidResultCode, SafeStateView>>;
