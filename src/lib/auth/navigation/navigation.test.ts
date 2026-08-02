/**
 * FEAT-002 navigation + lifecycle + adapter tests.
 *
 * Proves:
 * - the visible URL stays `/`; history entries carry only an opaque token;
 * - Back traverses Dashboard → Election Dashboard → election page without
 *   identifiers; refresh/new tab starts at the dashboard;
 * - malformed/stale tokens and failed revalidation fall back to `/`;
 * - pagehide shields protected content; pageshow revalidates before restore;
 * - the thin adapter projects protected access synchronously (no effect gate).
 */

import { describe, expect, it } from 'vitest';
import {
  InMemoryNavigationStack,
  normalizeToRootPath,
  pushOpaqueHistoryEntry,
  readOpaqueHistoryToken,
  replaceWithOpaqueHistoryEntry,
  resumeAfterRevalidation,
  type HistoryLike,
} from './navigation';
import { NAVIGATION_ROOT_PATH } from './constants';
import {
  LifecycleShield,
  shouldShowProtectedContent,
  type PageLifecycleEnvironment,
} from './lifecycle';
import { synchronouslyPermitsProtectedContent, type AuthRenderProjection } from '../react/adapter';

function makeHistory(): HistoryLike & { entries: unknown[] } {
  const entries: unknown[] = [null];
  return {
    state: entries[entries.length - 1],
    entries,
    pushState: (state) => {
      entries.push(state);
    },
    replaceState: (state) => {
      entries[entries.length - 1] = state;
    },
    go: () => undefined,
  };
}

describe('root-only visible URL', () => {
  it('always normalizes any path to /', () => {
    expect(normalizeToRootPath('/elections/ELEC-42')).toBe(NAVIGATION_ROOT_PATH);
    expect(normalizeToRootPath('/')).toBe(NAVIGATION_ROOT_PATH);
  });

  it('history entries carry only an opaque token with visible URL /', () => {
    const history = makeHistory();
    const stack = new InMemoryNavigationStack();
    const token = stack.push('electionDashboard');
    pushOpaqueHistoryEntry(history, token);

    const last = history.entries[history.entries.length - 1];
    expect(last).toMatchObject({ hvToken: token });
    // No destination/identifier is stored in the history entry.
    expect(JSON.stringify(last)).not.toMatch(/election|dashboard|ELEC|token-detail/i);

    // The opaque token round-trips; malformed states are rejected.
    expect(readOpaqueHistoryToken(history.entries[history.entries.length - 1])).toBe(token);
    expect(readOpaqueHistoryToken({ hvToken: 'not-a-token' })).toBeNull();
    expect(readOpaqueHistoryToken(null)).toBeNull();
    expect(readOpaqueHistoryToken('string')).toBeNull();
  });

  it('replaces the current entry with an opaque token', () => {
    const history = makeHistory();
    const stack = new InMemoryNavigationStack();
    const token = stack.push('electionPage');
    replaceWithOpaqueHistoryEntry(history, token);
    expect(readOpaqueHistoryToken(history.entries[history.entries.length - 1])).toBe(token);
  });
});

describe('opaque same-URL history hierarchy', () => {
  it('Back traverses election page → Election Dashboard → User Elections Dashboard', () => {
    const stack = new InMemoryNavigationStack();
    stack.push('electionDashboard');
    stack.push('electionPage');

    expect(stack.back()).toBe('electionDashboard');
    expect(stack.back()).toBe('userElectionsDashboard');
    // Never below the dashboard.
    expect(stack.back()).toBe('userElectionsDashboard');
  });

  it('tokens resolve only within the same tab stack and reject stale tokens', () => {
    const stack = new InMemoryNavigationStack();
    const token = stack.push('electionDashboard');

    expect(stack.resolve(token)).toBe('electionDashboard');
    // A token with depth beyond the current stack is stale → null.
    expect(stack.resolve('nav-zzz999-99' as never)).toBeNull();
    expect(stack.resolve('garbage' as never)).toBeNull();
  });

  it('resume after failed revalidation falls back to the dashboard', () => {
    const stack = new InMemoryNavigationStack();
    const token = stack.push('electionDashboard');
    expect(resumeAfterRevalidation(stack, token, true)).toBe('electionDashboard');
    expect(resumeAfterRevalidation(stack, token, false)).toBe('userElectionsDashboard');
    expect(stack.resolve(token)).toBeNull(); // stack was reset
  });
});

describe('lifecycle shielding', () => {
  it('pagehide shields synchronously and pageshow stays shielded until revalidation', () => {
    const listeners: { pagehide: (() => void) | null; pageshow: ((persisted: boolean) => void) | null } = {
      pagehide: null,
      pageshow: null,
    };
    const env: PageLifecycleEnvironment = {
      documentHidden: false,
      addPagehideListener: (cb) => {
        listeners.pagehide = cb;
      },
      addPageshowListener: (cb) => {
        listeners.pageshow = cb;
      },
    };
    const shield = new LifecycleShield(env);
    expect(shield.snapshot()).toBe('visible');

    listeners.pagehide?.();
    expect(shield.snapshot()).toBe('shielded');

    shield.revalidated();
    expect(shield.snapshot()).toBe('visible');

    listeners.pageshow?.(true);
    expect(shield.snapshot()).toBe('shielded');
  });

  it('protected content renders only with live authority + background policy', () => {
    expect(shouldShowProtectedContent('shielded', true, true)).toBe(false);
    expect(shouldShowProtectedContent('visible', false, true)).toBe(false);
    expect(shouldShowProtectedContent('visible', true, false)).toBe(false);
    expect(shouldShowProtectedContent('visible', true, true)).toBe(true);
  });
});

describe('thin adapter protected projection', () => {
  it('permits protected content only from an authenticated projection, synchronously', () => {
    const locked: AuthRenderProjection = {
      authState: 'locked',
      connectivity: 'online',
      protectedAccess: false,
      safeIdentity: null,
      outcomeCode: null,
      supportCode: null,
      onboardingKind: null,
    };
    const authenticated: AuthRenderProjection = {
      authState: 'authenticated',
      connectivity: 'online',
      protectedAccess: true,
      safeIdentity: null,
      outcomeCode: null,
      supportCode: null,
      onboardingKind: null,
    };
    expect(synchronouslyPermitsProtectedContent(locked)).toBe(false);
    expect(synchronouslyPermitsProtectedContent(authenticated)).toBe(true);
    expect(synchronouslyPermitsProtectedContent(null)).toBe(false);
  });
});
