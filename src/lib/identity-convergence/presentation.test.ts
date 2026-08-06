/**
 * FEAT-011 Tasks 5.2/5.4/5.6/5.8 — presentation and a11y contract tests:
 * exact action count/order/names, returning routing, six-position challenge,
 * review defaults, truthful copy, auto-entry without Continue, lifecycle
 * screens, WCAG invariants, secret-free projections, no export surface.
 */

import { describe, expect, it } from 'vitest';
import {
  actionLabelPresentForActionableScreens,
  copyIsTruthful,
  errorSummaryIsValid,
  liveRegionIsAppropriate,
  projectionIsSecretFree,
} from './a11y-contract';
import type { PublicIdentityProjection } from './contracts';
import {
  projectCoordinatorResult,
  projectCorrection,
  projectExistingProfile,
  projectFirstRun,
  projectLocalProof,
  projectMissingProfileReview,
  projectRetryable,
  projectReturningUnlock,
  projectTerminalBlocked,
  projectWaiting,
} from './presentation';

const IDENTITY: PublicIdentityProjection = {
  normalizedAlias: 'alice',
  visibility: 'public',
  abbreviatedSigningAddress: 'A1B2C3D4…BCDEF0',
  abbreviatedEncryptionAddress: 'F0EDCBA9…43210F',
  profileReference: 'ref-1' as never,
};

describe('root entry and routing (Task 5.2)', () => {
  it('first-run exposes exactly three primary choices in order, with no export action', () => {
    const p = projectFirstRun();
    expect(p.screen).toBe('firstRun');
    expect(p.actions).toEqual(['selectCreate', 'selectWords', 'selectFile']);
    expect(p.copy.actionLabel).toBeNull();
    expect(JSON.stringify(p)).not.toMatch(/export|backup|\.dat/i);
  });

  it('returning users route to unlock, never first-run', () => {
    const p = projectReturningUnlock();
    expect(p.screen).toBe('returningUnlock');
    expect(p.actions).toEqual(['dismiss']);
  });

  it('six-position challenge is the only action on the confirming stage', () => {
    const confirming = projectLocalProof('confirming');
    expect(confirming.actions).toEqual(['confirmSixPosition']);
    expect(projectLocalProof('generating').actions).toEqual([]);
  });
});

describe('exact profile and authenticated entry (Task 5.2)', () => {
  it('existing profile shows safe identity metadata and auto-enters without a Continue button', () => {
    const p = projectExistingProfile(IDENTITY);
    expect(p.screen).toBe('existingProfile');
    expect(p.actions).toEqual([]); // no Continue — automatic entry
    expect(p.copy.heading).toContain('alice');
    expect(p.identity).toEqual(IDENTITY);
    expect(JSON.stringify(p)).not.toContain('A1B2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF0123456789ABCDEF0');
  });
});

describe('missing-profile review (Task 5.4)', () => {
  it('words review starts empty + Private with same-identity copy', () => {
    const p = projectMissingProfileReview('words', { alias: '', visibility: 'private' });
    expect(p.screen).toBe('missingProfileReview');
    expect(p.copy.body).toMatch(/same cryptographic identity/i);
    expect(p.copy.body).not.toMatch(/logged in|restored|created|authenticated/i);
  });

  it('credential-file prefill is review-only (never chain truth)', () => {
    const p = projectMissingProfileReview('credentialFile', { alias: 'file-alias', visibility: 'private' });
    expect(p.a11y.liveRegionText).toMatch(/credential file/);
  });

  it('confirmation is an explicit action; cancellation is available', () => {
    const p = projectMissingProfileReview('words', { alias: '', visibility: 'private' });
    expect(p.actions).toContain('confirmMissingProfile');
    expect(p.actions).toContain('cancelRegistration');
  });
});

describe('waiting/delay/correction/retry/terminal (Task 5.4)', () => {
  it('waiting copy distinguishes submitted from confirmed', () => {
    const p = projectWaiting(false);
    expect(p.screen).toBe('waiting');
    expect(p.copy.body).toMatch(/not signed in yet/i);
  });

  it('delayed state offers lookup-only Check again', () => {
    const p = projectWaiting(true);
    expect(p.screen).toBe('delayed');
    expect(p.actions).toEqual(['checkAgain']);
  });

  it('correction surfaces field-specific errors', () => {
    const p = projectCorrection([{ field: 'alias', message: 'Alias is too long.' }]);
    expect(p.screen).toBe('correction');
    expect(p.a11y.errorSummary).toHaveLength(1);
  });

  it('retryable and terminal states never claim absence or success', () => {
    const retry = projectRetryable('The lookup timed out.');
    expect(retry.screen).toBe('retryable');
    expect(retry.actions).toEqual(['retryLookup']);
    expect(retry.copy.body).toMatch(/Nothing was changed/i);
    expect(projectTerminalBlocked('x').screen).toBe('terminalBlocked');
  });
});

describe('coordinator result mapping (Task 5.6)', () => {
  it('maps every result to its truthful screen', () => {
    expect(projectCoordinatorResult({ kind: 'confirmed' }, IDENTITY).screen).toBe('existingProfile');
    expect(projectCoordinatorResult({ kind: 'waiting' }, null).screen).toBe('waiting');
    expect(projectCoordinatorResult({ kind: 'delayed' }, null).screen).toBe('delayed');
    expect(projectCoordinatorResult({ kind: 'retryable' }, null).screen).toBe('retryable');
    expect(projectCoordinatorResult({ kind: 'alreadyExists' }, null).screen).toBe('lookupProgress');
    expect(projectCoordinatorResult({ kind: 'rejectedEditable' }, null).screen).toBe('correction');
    expect(projectCoordinatorResult({ kind: 'rejectedTerminal' }, null).screen).toBe('terminalBlocked');
    expect(projectCoordinatorResult({ kind: 'staleEpoch' }, null).screen).toBe('retryable');
    expect(projectCoordinatorResult({ kind: 'unknown' }, null).screen).toBe('lookupProgress');
  });
});

describe('WCAG 2.2 AA contract (Task 5.8)', () => {
  it('every projection satisfies copy, live-region, error, action-label, and secret-free rules', () => {
    const projections = [
      projectFirstRun(),
      projectReturningUnlock(),
      projectLocalProof('confirming'),
      projectLocalProof('protecting'),
      projectExistingProfile(IDENTITY),
      projectMissingProfileReview('words', { alias: '', visibility: 'private' }),
      projectMissingProfileReview('credentialFile', { alias: 'f', visibility: 'private' }),
      projectWaiting(false),
      projectWaiting(true),
      projectCorrection([{ field: 'alias', message: 'x' }]),
      projectRetryable('x'),
      projectTerminalBlocked('x'),
      projectCoordinatorResult({ kind: 'confirmed' }, IDENTITY),
    ];

    for (const p of projections) {
      expect(copyIsTruthful(p), p.screen).toBe(true);
      expect(liveRegionIsAppropriate(p), p.screen).toBe(true);
      expect(errorSummaryIsValid(p), p.screen).toBe(true);
      expect(actionLabelPresentForActionableScreens(p), p.screen).toBe(true);
      expect(projectionIsSecretFree(p), p.screen).toBe(true);
    }
  });

  it('no projection carries a full address', () => {
    for (const p of [
      projectExistingProfile(IDENTITY),
      projectCoordinatorResult({ kind: 'confirmed' }, IDENTITY),
    ]) {
      const json = JSON.stringify(p);
      expect(json).not.toContain('A1B2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF0123456789ABCDEF0');
      expect(json).not.toContain('F0EDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210F');
    }
  });
});
