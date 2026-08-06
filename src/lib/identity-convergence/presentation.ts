/**
 * FEAT-011 Phase 5 — closed presentation projections for the identity
 * convergence journeys (framework-neutral; follows the FEAT-010
 * `root-projection.ts` convention).
 *
 * Presentation decides copy, visible actions, progress, focus, and safe
 * resume ONLY; it never decides business transitions and never holds secrets.
 * Every screen maps to one bounded projection with a typed action set, a11y
 * metadata (focus target, live region, error summary), and truthful wording —
 * no premature "logged in/restored/created/authenticated".
 *
 * Normative source: FeatureDescription "UX and Accessibility",
 * "Authoritative HappyPath"; Wireframes-design.md; design-summary.md.
 */

import type { MissingProfileOrigin, PublicIdentityProjection } from './contracts';

/** Closed convergence screens (presentation vocabulary). */
export type ConvergenceScreen =
  | 'firstRun' // exactly three primary choices; no password, no export
  | 'returningUnlock' // FEAT-010 unlock path for a returning local user
  | 'localProof' // create/words/file proof progress (child-owned)
  | 'lookupProgress' // exact lookup in flight (never claims absence/authentication)
  | 'existingProfile' // exact both-key success; auto-enters the authenticated shell
  | 'missingProfileReview' // explicit same-key registration review
  | 'submitting' // one exact transaction being submitted
  | 'waiting' // ACCEPTED/matching PENDING; polling; NOT confirmed
  | 'delayed' // three-minute abnormal delay; Check again is lookup-only
  | 'correction' // editable alias correction (allowlisted)
  | 'retryable' // transport ambiguity / incomplete candidates
  | 'terminalBlocked' // contradiction / cryptographic rejection
  | 'authenticated'; // exact indexed both-key confirmation mounted the shell

/** Typed action set — the ONLY actions a screen may expose. */
export type ConvergenceAction =
  | 'selectCreate'
  | 'selectWords'
  | 'selectFile'
  | 'confirmSixPosition'
  | 'confirmMissingProfile'
  | 'cancelRegistration'
  | 'retryLookup'
  | 'checkAgain'
  | 'back'
  | 'dismiss';

/** Safe copy block (never echoes secrets or full identifiers). */
export interface ConvergenceCopy {
  readonly heading: string;
  readonly body: string;
  readonly actionLabel: string | null;
}

/** Bounded projection for one screen. */
export interface ConvergenceViewProjection {
  readonly screen: ConvergenceScreen;
  readonly actions: ReadonlyArray<ConvergenceAction>;
  readonly copy: ConvergenceCopy;
  /** a11y metadata (WCAG 2.2 AA): initial focus target, live region text, error summary. */
  readonly a11y: {
    readonly focusTarget: string | null; // test id of the element to receive initial focus
    readonly liveRegion: 'polite' | 'assertive' | null;
    readonly liveRegionText: string | null;
    readonly errorSummary: ReadonlyArray<{ readonly field: string; readonly message: string }>;
  };
  /** Safe identity metadata for authenticated screens (abbreviated addresses only). */
  readonly identity: PublicIdentityProjection | null;
}

/** First-run entry: exactly three equal primary choices; no export action. */
export function projectFirstRun(): ConvergenceViewProjection {
  return {
    screen: 'firstRun',
    actions: ['selectCreate', 'selectWords', 'selectFile'],
    copy: {
      heading: 'Set up this device',
      body: 'Create a new identity, restore recovery words, or restore a credential file.',
      actionLabel: null,
    },
    a11y: {
      focusTarget: 'first-run-heading',
      liveRegion: null,
      liveRegionText: null,
      errorSummary: [],
    },
    identity: null,
  };
}

/** Returning user: routes to the FEAT-010 unlock path, never first-run. */
export function projectReturningUnlock(): ConvergenceViewProjection {
  return {
    screen: 'returningUnlock',
    actions: ['dismiss'],
    copy: {
      heading: 'Welcome back',
      body: 'Unlock this device to continue.',
      actionLabel: 'Unlock',
    },
    a11y: {
      focusTarget: 'unlock-field',
      liveRegion: 'polite',
      liveRegionText: 'Device is locked.',
      errorSummary: [],
    },
    identity: null,
  };
}

/** Local proof progress (child-owned; create requires six-position confirmation). */
export function projectLocalProof(stage: 'generating' | 'recovery' | 'protecting' | 'confirming'): ConvergenceViewProjection {
  const copy = {
    generating: { heading: 'Generating your identity', body: 'Creating a new cryptographic identity on this device.' },
    recovery: { heading: 'Recovery words', body: 'Write these words down and keep them safe.' },
    confirming: { heading: 'Recovery check', body: 'Confirm the recovery words in order.' },
    protecting: { heading: 'Protect this device', body: 'Choose a device protection method.' },
  }[stage];

  return {
    screen: 'localProof',
    actions: stage === 'confirming' ? ['confirmSixPosition'] : [],
    copy: { ...copy, actionLabel: stage === 'confirming' ? 'Confirm' : null },
    a11y: {
      focusTarget: stage === 'confirming' ? 'six-position-input' : null,
      liveRegion: 'polite',
      liveRegionText: copy.heading,
      errorSummary: [],
    },
    identity: null,
  };
}

/** Lookup progress — never claims absence or authentication. */
export function projectLookupProgress(): ConvergenceViewProjection {
  return {
    screen: 'lookupProgress',
    actions: [],
    copy: {
      heading: 'Checking the blockchain',
      body: 'Looking up your identity. This can take a few seconds.',
      actionLabel: null,
    },
    a11y: { focusTarget: null, liveRegion: 'polite', liveRegionText: 'Checking the blockchain.', errorSummary: [] },
    identity: null,
  };
}

/**
 * Exact existing-profile success: the blockchain alias/visibility are shown
 * safely and the authenticated application mounts automatically — no extra
 * Continue button (AC-011-010).
 */
export function projectExistingProfile(identity: PublicIdentityProjection): ConvergenceViewProjection {
  return {
    screen: 'existingProfile',
    actions: [],
    copy: {
      heading: `Welcome, ${identity.normalizedAlias}`,
      body: 'Your identity is confirmed on the blockchain.',
      actionLabel: null,
    },
    a11y: { focusTarget: 'authenticated-shell', liveRegion: 'assertive', liveRegionText: 'Identity confirmed.', errorSummary: [] },
    identity,
  };
}

/**
 * Explicit missing-profile review: words/returning start empty + Private;
 * credential-file may prefill as review-only; copy explains the SAME
 * cryptographic identity is being registered. Creation starts only on the
 * explicit confirmation action.
 */
export function projectMissingProfileReview(origin: MissingProfileOrigin, _review: { readonly alias: string; readonly visibility: 'private' | 'public' }): ConvergenceViewProjection {
  const prefillNote = origin === 'credentialFile' ? 'These details come from your credential file and can be changed.' : null;
  return {
    screen: 'missingProfileReview',
    actions: ['confirmMissingProfile', 'cancelRegistration'],
    copy: {
      heading: 'Register this identity',
      body:
        origin === 'words' || origin === 'returningReset'
          ? 'No blockchain identity was found for your recovery words. The same cryptographic identity will be registered.'
          : origin === 'credentialFile'
            ? 'No blockchain identity was found for this credential file. The same cryptographic identity will be registered.'
            : 'No blockchain identity was found yet. The same cryptographic identity will be registered.',
      actionLabel: 'Confirm registration',
    },
    a11y: {
      focusTarget: 'profile-alias-input',
      liveRegion: 'polite',
      liveRegionText: prefillNote ?? 'Review your identity details.',
      errorSummary: [],
    },
    identity: null,
  };
}

/** Truthful submission progress: submitted is never confirmed. */
export function projectWaiting(delayed: boolean): ConvergenceViewProjection {
  return delayed
    ? {
        screen: 'delayed',
        actions: ['checkAgain'],
        copy: {
          heading: 'Confirmation is taking longer than usual',
          body: 'Your registration was submitted. Blockchain confirmation is delayed — you can check again.',
          actionLabel: 'Check again',
        },
        a11y: { focusTarget: 'check-again-button', liveRegion: 'polite', liveRegionText: 'Confirmation delayed.', errorSummary: [] },
        identity: null,
      }
    : {
        screen: 'waiting',
        actions: [],
        copy: {
          heading: 'Waiting for confirmation',
          body: 'Your registration was submitted and is waiting for blockchain confirmation. You are not signed in yet.',
          actionLabel: null,
        },
        a11y: { focusTarget: null, liveRegion: 'polite', liveRegionText: 'Waiting for confirmation.', errorSummary: [] },
        identity: null,
      };
}

/** Editable alias correction (allowlisted code only). */
export function projectCorrection(fieldErrors: ReadonlyArray<{ readonly field: string; readonly message: string }>): ConvergenceViewProjection {
  return {
    screen: 'correction',
    actions: ['confirmMissingProfile', 'cancelRegistration'],
    copy: {
      heading: 'Fix your identity details',
      body: 'Some details could not be registered. Please correct them.',
      actionLabel: 'Try again',
    },
    a11y: { focusTarget: 'profile-alias-input', liveRegion: 'assertive', liveRegionText: 'Please correct the highlighted fields.', errorSummary: fieldErrors },
    identity: null,
  };
}

/** Retryable transport/candidate ambiguity — never absence, never authentication. */
export function projectRetryable(reason: string): ConvergenceViewProjection {
  return {
    screen: 'retryable',
    actions: ['retryLookup'],
    copy: {
      heading: 'Connection issue',
      body: `${reason} Nothing was changed. You can try again.`,
      actionLabel: 'Retry',
    },
    a11y: { focusTarget: 'retry-button', liveRegion: 'polite', liveRegionText: 'Connection issue.', errorSummary: [] },
    identity: null,
  };
}

/** Terminal fail-closed state (identity contradiction / cryptographic rejection). */
export function projectTerminalBlocked(message: string): ConvergenceViewProjection {
  return {
    screen: 'terminalBlocked',
    actions: ['dismiss'],
    copy: {
      heading: 'This identity cannot be used',
      body: message,
      actionLabel: 'OK',
    },
    a11y: { focusTarget: 'terminal-message', liveRegion: 'assertive', liveRegionText: 'Identity cannot be used.', errorSummary: [] },
    identity: null,
  };
}

/** Authenticated shell entry after exact indexed confirmation. */
export function projectAuthenticated(identity: PublicIdentityProjection): ConvergenceViewProjection {
  return {
    screen: 'authenticated',
    actions: [],
    copy: {
      heading: `Welcome, ${identity.normalizedAlias}`,
      body: 'Your identity is confirmed.',
      actionLabel: null,
    },
    a11y: { focusTarget: 'authenticated-shell', liveRegion: 'assertive', liveRegionText: 'Identity confirmed.', errorSummary: [] },
    identity,
  };
}

/** Map a coordinator result to its truthful screen. */
export function projectCoordinatorResult(
  result: { readonly kind: string },
  identity: PublicIdentityProjection | null,
  review?: { readonly origin: MissingProfileOrigin; readonly alias: string; readonly visibility: 'private' | 'public' },
): ConvergenceViewProjection {
  switch (result.kind) {
    case 'confirmed':
      return identity !== null ? projectExistingProfile(identity) : projectAuthenticatedFallback();
    case 'delayed':
      return projectWaiting(true);
    case 'reviewing':
      return projectMissingProfileReview(review?.origin ?? 'words', { alias: review?.alias ?? '', visibility: review?.visibility ?? 'private' });
    case 'waiting':
      return projectWaiting(false);
    case 'retryable':
      return projectRetryable('The lookup could not be completed.');
    case 'alreadyExists':
      return projectLookupProgress();
    case 'rejectedEditable':
      return projectCorrection([]);
    case 'rejectedTerminal':
      return projectTerminalBlocked('The registration was rejected and cannot be retried automatically.');
    case 'staleEpoch':
      return projectRetryable('This session is no longer current.');
    default:
      return projectLookupProgress();
  }
}

function projectAuthenticatedFallback(): ConvergenceViewProjection {
  return {
    screen: 'authenticated',
    actions: [],
    copy: { heading: 'Welcome', body: 'Your identity is confirmed.', actionLabel: null },
    a11y: { focusTarget: 'authenticated-shell', liveRegion: 'assertive', liveRegionText: 'Identity confirmed.', errorSummary: [] },
    identity: null,
  };
}
