/**
 * FEAT-002 shared-session timer policy — aggregate idle and background rules.
 *
 * Pure and framework-neutral. Trusted, rate-limited keyboard/pointer/touch/
 * wheel/scroll/accessibility activation from any VISIBLE HushVoting instance
 * resets the shared idle timer. Synthetic events, timers, network responses,
 * animation, media, and background synchronization never do. The background
 * timer runs only while every instance is hidden/backgrounded or the screen
 * is off.
 *
 * Normative source: FeatureDescription "Aggregate idle and background policy".
 */

import { AUTH_TIMING } from '../types.js';

/** Activity sources that may reset the shared idle timer. */
export type TrustedActivityKind = 'keyboard' | 'pointer' | 'touch' | 'wheel' | 'scroll' | 'accessibility';

export interface ActivityEvent {
  readonly kind: TrustedActivityKind;
  readonly isTrusted: boolean;
  /** Instance visibility at the moment of the event. */
  readonly instanceVisible: boolean;
  readonly timestampMs: number;
}

export interface VisibilitySnapshot {
  readonly visibleInstances: number;
  readonly hiddenInstances: number;
  readonly screenOff: boolean;
}

/** All instances hidden/backgrounded, or the screen is off. */
export function isBackgrounded(snapshot: VisibilitySnapshot): boolean {
  return snapshot.screenOff || snapshot.visibleInstances === 0;
}

/** Trusted activity from a visible instance qualifies as an idle reset. */
export function qualifiesAsIdleReset(event: ActivityEvent): boolean {
  return event.isTrusted && event.instanceVisible;
}

/**
 * Rate limit trusted resets (bounded writes; a burst of events cannot
 * advance the deadline repeatedly within a short window).
 */
export function isRateLimited(nowMs: number, lastResetMs: number | null, windowMs: number): boolean {
  if (lastResetMs === null) {
    return false;
  }
  return nowMs - lastResetMs < windowMs;
}

/** Minimum spacing between accepted idle resets. */
export const IDLE_RESET_WINDOW_MS = 1000;

/** Compute the next idle deadline from a reset. */
export function nextIdleDeadline(nowMs: number, idleTimeoutMs: number): number {
  return nowMs + idleTimeoutMs;
}

/** Compute the next background deadline (used only while backgrounded). */
export function nextBackgroundDeadline(nowMs: number, backgroundTimeoutMs: number): number {
  return nowMs + backgroundTimeoutMs;
}

/**
 * Decide whether a background timeout should trigger a lock, given the last
 * foreground activity and the configured policy values (EPIC-001 defaults
 * are injected; this function stays deterministic).
 */
export function shouldLockAfterBackground(nowMs: number, backgroundStartedAtMs: number, backgroundTimeoutMs: number): boolean {
  return nowMs - backgroundStartedAtMs >= backgroundTimeoutMs;
}

/** Human-scale bounded policy values used by the reference implementation. */
export const REFERENCE_POLICY = {
  idleTimeoutMs: 10 * 60 * 1000, // 10 minutes of trusted visible activity
  backgroundTimeoutMs: 2 * 60 * 1000, // 2 minutes fully hidden
  resetWindowMs: IDLE_RESET_WINDOW_MS,
} as const;

/** Validate injected policy values are within EPIC-001 approved bounds. */
export function isPolicyWithinBounds(idleTimeoutMs: number, backgroundTimeoutMs: number): boolean {
  const idleOk = idleTimeoutMs >= 60_000 && idleTimeoutMs <= 30 * 60_000;
  const backgroundOk = backgroundTimeoutMs >= 15_000 && backgroundTimeoutMs <= 15 * 60_000;
  return idleOk && backgroundOk;
}

export { AUTH_TIMING };
