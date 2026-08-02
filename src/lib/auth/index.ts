/**
 * FEAT-002 authentication contracts — public exports.
 *
 * Public ownership notes for downstream consumers:
 * - FEAT-003 (session/vault authority): implements `SecretAuthorityPort` +
 *   `LocalUserAuthorityPort`; consumes `SessionEpoch`/`OperationId` scoping.
 * - FEAT-004/005/006 (browser/Ubuntu/Android vault adapters): implement the
 *   secret-authority and local-user surfaces with typed results; never leak
 *   secrets into machine data.
 * - FEAT-007/008/009 (onboarding child flows): implement `OnboardingPort` for
 *   their kind; Back must confirm secret cleanup before `noLocalUser`.
 * - FEAT-010 (lifecycle hardening): consumes removal/coordination contracts
 *   and the invalidation vocabulary.
 *
 * No dependency on React, Next.js, DOM, storage, transport, XState, or UI
 * state. Expected actor failures are typed data; nothing here throws for
 * expected input errors; diagnostics never contain credentials.
 */

export * from './types.js';
export * from './results.js';
export * from './ports.js';
export * from './registry.js';
