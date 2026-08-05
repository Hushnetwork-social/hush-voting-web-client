/**
 * FEAT-010 presentation logic — locked/home/connectivity/lifecycle
 * projections (Task 4.3).
 *
 * Produces protection-mode-specific locked views, verification/cooldown/
 * remediation views, the minimal authenticated home, connectivity status,
 * session-only disclosure, and the synchronous capability-revocation gate.
 * Locked views fetch no protected content; local unlock never projects
 * protected access; home contains no elections/roles/feeds; FEAT-011 export
 * is absent until a compatible real capability registers (AC-010-027…039,
 * 044…062).
 *
 * Framework-neutral, secret-free.
 */
import type { CurrentProtectionModeClass } from '../../vault-core/contracts/current-binding';

/** Presentation classes (session-only is not a protection mode). */
export type LockedPresentationMode = CurrentProtectionModeClass | 'sessionOnly';

/** Safe remembered-identity preview fields (AC-010-028). */
export interface SafeIdentityPreview {
  readonly alias: string;
  readonly abbreviatedSigningAddress: string;
  readonly networkContext: string;
}

/** One locked-view projection with exact normative copy. */
export interface LockedViewProjection {
  readonly mode: LockedPresentationMode;
  /** Primary unlock action label (exact). */
  readonly unlockLabel: string;
  /** Recovery action label (exact; wording differs by mode, AC-010-033). */
  readonly recoveryLabel: string;
  /** Device-password field is shown ONLY for the Device-password mode. */
  readonly showDevicePasswordField: boolean;
  /** Honest disclosure (e.g., Ubuntu unlocked-OS-session). */
  readonly disclosure?: string;
}

/** Exact normative copy (FeatureDescription "Returning Locked Screen"). */
const UNLOCK_LABELS: Readonly<Record<CurrentProtectionModeClass, string>> = {
  'device-password': 'Unlock HushVoting!',
  'webauthn-prf': 'Unlock with this device',
  'ubuntu-secret-service': 'Unlock with device protection',
  'android-keystore': 'Unlock with device protection',
} as const;

const RECOVERY_LABELS: Readonly<Record<CurrentProtectionModeClass, string>> = {
  'device-password': 'Forgot device password?',
  'webauthn-prf': "Can't unlock with this device?",
  'ubuntu-secret-service': "Can't unlock with this device?",
  'android-keystore': "Can't unlock with this device?",
} as const;

/** Ubuntu passwordless honest disclosure (AC-010-031). */
const UBUNTU_DISCLOSURE = 'Access follows the unlocked OS session.';

/**
 * Project the locked view for the recorded protection mode. Any unknown
 * mode class fails closed to a typed blocking presentation (never a
 * Device-password fallback).
 */
export function projectLockedView(
  mode: LockedPresentationMode,
  preview: SafeIdentityPreview,
): LockedViewProjection | { readonly kind: 'blocked'; readonly supportCode: string } {
  if (mode === 'sessionOnly') {
    return {
      mode,
      unlockLabel: 'Unlock HushVoting!',
      recoveryLabel: 'Forgot device password?',
      showDevicePasswordField: false,
      disclosure: 'Session-only — no returning local user is stored.',
    };
  }
  if (!(mode in UNLOCK_LABELS)) {
    return { kind: 'blocked', supportCode: 'LOCKED-UNKNOWN-MODE' };
  }
  return {
    mode,
    unlockLabel: UNLOCK_LABELS[mode],
    recoveryLabel: RECOVERY_LABELS[mode],
    showDevicePasswordField: mode === 'device-password',
    ...(mode === 'ubuntu-secret-service' ? { disclosure: UBUNTU_DISCLOSURE } : {}),
    ...preview,
  };
}

/** Cooldown/verification/remediation projection (safe fields only). */
export interface UnlockProgressProjection {
  readonly state: 'unlocking' | 'verifying' | 'cooldown' | 'retryableFailure';
  readonly cooldownDeadlineMs?: number;
  readonly retryAllowed: boolean;
}

export function projectUnlockProgress(
  state: UnlockProgressProjection['state'],
  retryAllowed: boolean,
  cooldownDeadlineMs?: number,
): UnlockProgressProjection {
  return { state, retryAllowed, cooldownDeadlineMs };
}

/** Minimal authenticated home projection (AC-010-044/045). */
export interface HomeProjection {
  readonly alias: string;
  readonly abbreviatedSigningAddress: string;
  readonly networkContext: string;
  readonly connectivity: 'online' | 'offline' | 'reconnecting';
  /** Always-available Lock action (exact copy). */
  readonly lockLabel: 'Lock HushVoting!';
  readonly showSessionOnlyWarning: boolean;
  /** FEAT-011 export is ABSENT until a compatible real capability registers. */
  readonly exportActionAbsent: true;
}

export function projectHome(
  preview: SafeIdentityPreview,
  connectivity: HomeProjection['connectivity'],
  sessionOnly: boolean,
): HomeProjection {
  return {
    alias: preview.alias,
    abbreviatedSigningAddress: preview.abbreviatedSigningAddress,
    networkContext: preview.networkContext,
    connectivity,
    lockLabel: 'Lock HushVoting!',
    showSessionOnlyWarning: sessionOnly,
    exportActionAbsent: true,
  };
}

/**
 * Synchronous protected-render gate: protected content mounts ONLY when the
 * capability is present; any revocation denies protected rendering in the
 * same event turn and stale async outcomes cannot restore it (AC-010-052/053).
 */
export function synchronouslyDeniesProtectedContent(accessCapable: boolean): boolean {
  return !accessCapable;
}

/** Session-only warning copy (AC-010-062). */
export const SESSION_ONLY_WARNING = 'Session-only — Lock or closing the app removes this local session.';

/** Safe identity summary while locked (no avatars/full addresses fetched). */
export function abbreviatedAddress(fullAddress: string): string {
  if (fullAddress.length <= 14) return fullAddress;
  return `${fullAddress.slice(0, 8)}…${fullAddress.slice(-6)}`;
}
