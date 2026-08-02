/**
 * FEAT-002 private navigation — root-only visible URL + opaque same-URL
 * history with typed in-memory destinations.
 *
 * The address bar stays `/` throughout normal use. History entries keep the
 * visible URL `/` and contain only an opaque token; the token resolves through
 * that tab's in-memory stack and carries no election/workflow identifier.
 * Unknown external paths normalize to `/` before protected rendering.
 *
 * Hierarchy (normative):
 *   User Elections Dashboard → Election Dashboard → Election-specific page
 *
 * Normative source: FeatureDescription "Navigation and URL Privacy",
 * "Opaque same-URL history", "Resume after Lock", "Page suspension and
 * restoration".
 */

import { NAVIGATION_ROOT_PATH } from './constants.js';
import type { NavigationToken, TypedDestinationKind } from '../types.js';

/** Per-tab in-memory destination stack (never persisted). */
export class InMemoryNavigationStack {
  private readonly stack: TypedDestinationKind[] = [];

  constructor(initial: TypedDestinationKind = 'userElectionsDashboard') {
    this.stack.push(initial);
  }

  /** Push a destination, returning a fresh opaque token. */
  push(destination: TypedDestinationKind): NavigationToken {
    this.stack.push(destination);
    return this.tokenForDepth(this.stack.length);
  }

  /** Resolve an opaque token against this tab's stack; null if unknown/stale. */
  resolve(token: NavigationToken): TypedDestinationKind | null {
    const depth = this.depthForToken(token);
    if (depth === null || depth < 1 || depth > this.stack.length) {
      return null;
    }
    return this.stack[depth - 1] ?? null;
  }

  /** Back: pop one level; never below the dashboard. */
  back(): TypedDestinationKind {
    if (this.stack.length > 1) {
      this.stack.pop();
    }
    return this.stack[this.stack.length - 1] ?? 'userElectionsDashboard';
  }

  /** Reset to the dashboard (refresh/new tab/uncertain resume). */
  reset(): void {
    this.stack.length = 0;
    this.stack.push('userElectionsDashboard');
  }

  private tokenForDepth(depth: number): NavigationToken {
    // Opaque token: random, per-tab, memory-only, carries no destination data.
    // crypto is preferred for entropy; Math.random is an acceptable fallback
    // because the token grants no authority (it only resolves in-memory state).
    return `nav-${randomOpaquePart()}-${depth}` as NavigationToken;
  }

  private depthForToken(token: NavigationToken): number | null {
    const match = /^nav-[a-z0-9]+-(\d+)$/.exec(token);
    if (match === null) {
      return null;
    }
    return Number(match[1]);
  }
}

/** 10-character random opaque part for navigation tokens. */
function randomOpaquePart(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.getRandomValues === 'function') {
    const bytes = new Uint8Array(8);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('').slice(0, 10);
  }
  return Math.random().toString(36).slice(2, 12);
}

/** Browser history abstraction (injected so tests are deterministic). */
export interface HistoryLike {
  readonly state: unknown;
  pushState(state: unknown, unused: string, url?: string): void;
  replaceState(state: unknown, unused: string, url?: string): void;
  go(delta: number): void;
}

/** Normalize any external path to `/` before protected rendering. */
export function normalizeToRootPath(path: string): string {
  return path === NAVIGATION_ROOT_PATH ? NAVIGATION_ROOT_PATH : NAVIGATION_ROOT_PATH;
}

/**
 * Write one opaque same-URL history entry. `state` may contain ONLY the
 * opaque token and no destination, election, or workflow detail.
 */
export function pushOpaqueHistoryEntry(
  history: HistoryLike,
  token: NavigationToken,
): void {
  history.pushState({ hvToken: token }, '', NAVIGATION_ROOT_PATH);
}

/** Replace the current entry with an opaque one (used before protected render). */
export function replaceWithOpaqueHistoryEntry(
  history: HistoryLike,
  token: NavigationToken,
): void {
  history.replaceState({ hvToken: token }, '', NAVIGATION_ROOT_PATH);
}

/** Read the opaque token from a history entry; null when absent or malformed. */
export function readOpaqueHistoryToken(state: unknown): NavigationToken | null {
  if (state === null || typeof state !== 'object') {
    return null;
  }
  const candidate = (state as { hvToken?: unknown }).hvToken;
  if (typeof candidate !== 'string') {
    return null;
  }
  if (!/^nav-[a-z0-9]+-\d+$/.test(candidate)) {
    return null;
  }
  return candidate as NavigationToken;
}

/**
 * Resume decision: after unlock, revalidate the in-memory position. Removed
 * election, changed authorization, stale workflow, malformed token, failed
 * validation, reload, process death, removal, or any uncertainty → fall back
 * to `/` and the User Elections Dashboard.
 */
export function resumeAfterRevalidation(
  stack: InMemoryNavigationStack,
  token: NavigationToken | null,
  revalidated: boolean,
): TypedDestinationKind {
  if (!revalidated) {
    stack.reset();
    return 'userElectionsDashboard';
  }
  const destination = token === null ? null : stack.resolve(token);
  if (destination === null) {
    stack.reset();
    return 'userElectionsDashboard';
  }
  return destination;
}
