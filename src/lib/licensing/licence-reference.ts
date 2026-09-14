/**
 * FEAT-017 Task 4.3 — public licence reference presentation helpers
 * (shortening, full-value selection, clipboard feedback policy).
 *
 * The licence reference is the PUBLIC originating transaction UUID of the
 * indexed assignment (FEAT-015). It is not a secret and not authorization.
 * Account shows a recognizably shortened form; details and confirmation show
 * the full selectable value. Copy feedback is a deterministic, accessible,
 * English-only policy: success/failure announce once through a polite region
 * and NEVER hide or replace the value — on failure the full reference remains
 * selectable so the user can copy it manually.
 *
 * This module performs no clipboard write (Web/native clipboard adapters are
 * integration work) and emits no telemetry/log/trace by construction. It only
 * decides the bounded display text and the closed feedback model.
 *
 * Normative source: FEAT-017 FeatureDescription D017-08/D017-09 + recovery
 * contract; design-summary.md "Reference display", "Clipboard failure";
 * Wireframes-design.md A0/L1/C0/R0 (shortened `5f2d9e11…c9d3e` pattern,
 * full selectable text, polite copy feedback); planning-analysis-report §4,
 * §6.2.
 */

import {
  LICENCE_UPGRADE_COPY,
  licenceUpgradeCopy,
  type LicenceUpgradeCopyKey,
} from './upgrade-copy';

/** Maximum reference length mirrored from the projection bounds. */
export const LICENCE_REFERENCE_MAX_LENGTH = 128 as const;

/** Head characters retained when shortening (approved A0 pattern). */
export const LICENCE_REFERENCE_SHORT_HEAD = 8 as const;
/** Tail characters retained when shortening (approved A0 pattern `…c9d3e`). */
export const LICENCE_REFERENCE_SHORT_TAIL = 5 as const;
/** References at or below this length are shown in full. */
export const LICENCE_REFERENCE_FULL_BELOW = 16 as const;

/**
 * Validate a licence reference for presentation: bounded text with no control
 * characters or surrounding whitespace. Malformed/oversized values return
 * null so presentation never invents or truncates authority material.
 */
export function isPresentableLicenceReference(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0 || value.length > LICENCE_REFERENCE_MAX_LENGTH) {
    return false;
  }
  if (value.trim() !== value) {
    return false;
  }
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code < 0x21 || code === 0x7f) {
      return false; // control characters and DEL are never presentable
    }
  }
  return true;
}

/**
 * Shorten a public licence reference into a recognizably abbreviated form
 * that keeps its beginning and end (approved `5f2d9e11…c9d3e` pattern).
 * References that are short, malformed, or unbounded are never fabricated:
 * short valid references return in full; invalid values return null.
 */
export function shortenLicenceReference(reference: unknown): string | null {
  if (!isPresentableLicenceReference(reference)) {
    return null;
  }
  if (reference.length <= LICENCE_REFERENCE_FULL_BELOW) {
    return reference;
  }
  const head = reference.slice(0, LICENCE_REFERENCE_SHORT_HEAD);
  const tail = reference.slice(reference.length - LICENCE_REFERENCE_SHORT_TAIL);
  return `${head}…${tail}`;
}

/**
 * Closed display mode of a licence reference in one surface:
 *  - 'full' for details/confirmation (selectable + copy action);
 *  - 'shortened' for the Account summary (no copy action);
 *  - null when no presentable reference exists (never a placeholder).
 */
export type LicenceReferenceDisplayMode = 'full' | 'shortened';

/** Facts one surface needs to render a licence reference safely. */
export interface LicenceReferenceFacts {
  /** Mode decides which control surface is offered (short/full + copy). */
  readonly mode: LicenceReferenceDisplayMode;
  /** The exact text to show in this surface. */
  readonly displayText: string;
  /** The full reference remains available for selection/copy in details. */
  readonly fullText: string;
  /** True whenever full text can be selected by the user. */
  readonly selectable: boolean;
}

/**
 * Build the closed display facts for one licence reference in one surface.
 * Shortening happens only for 'shortened'; 'full' never truncates.
 */
export function licenceReferenceFacts(
  reference: unknown,
  mode: LicenceReferenceDisplayMode,
): LicenceReferenceFacts | null {
  if (!isPresentableLicenceReference(reference)) {
    return null;
  }
  if (mode === 'shortened') {
    const displayText = shortenLicenceReference(reference);
    if (displayText === null) {
      return null;
    }
    return { mode, displayText, fullText: reference, selectable: true };
  }
  return { mode, displayText: reference, fullText: reference, selectable: true };
}

/** Closed clipboard feedback outcome (only this vocabulary reaches UI copy). */
export type LicenceCopyFeedbackKind = 'success' | 'failure';

/** Exact polite feedback for one copy action (single announcement). */
export interface LicenceCopyFeedbackFacts {
  readonly kind: LicenceCopyFeedbackKind;
  readonly statusText: string;
  /** Copy feedback never replaces or hides the reference value. */
  readonly valueKeptVisible: true;
  /** Full text stays selectable on failure so the user can copy manually. */
  readonly selectableOnFailure: true;
  /** Live-region semantics are polite; announced once per action. */
  readonly polite: true;
  /** Never repeated by a later poll/render. */
  readonly announceOnce: true;
}

/** Map one copy outcome to the closed feedback model + exact English copy. */
export function licenceCopyFeedback(kind: LicenceCopyFeedbackKind): LicenceCopyFeedbackFacts {
  const statusText =
    kind === 'success'
      ? licenceUpgradeCopy('copySuccessFeedback')
      : licenceUpgradeCopy('copyFailureFeedback');
  return {
    kind,
    statusText,
    valueKeptVisible: true,
    selectableOnFailure: true,
    polite: true,
    announceOnce: true,
  };
}

/** The failure copy is the canonical clipboard-failure string (design table). */
export function clipboardFailureStatusText(): string {
  return LICENCE_UPGRADE_COPY.copyFailureFeedback;
}

/** Narrow helper used by Phase 5 tests to pin the copy key set. */
export function licenceReferenceCopyKeys(): LicenceUpgradeCopyKey[] {
  return ['copySuccessFeedback', 'copyFailureFeedback'];
}
