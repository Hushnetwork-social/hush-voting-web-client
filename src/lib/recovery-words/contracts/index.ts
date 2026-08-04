/**
 * FEAT-008 recovery-words contracts — public barrel.
 *
 * Framework-neutral closed vocabulary for the Recovery Words workflow:
 * lifecycle/operations, safe projections, no-mnemonic envelope + protection
 * modes, candidate lookup/selection/proof/profile, and evidence schemas.
 *
 * SECRET BOUNDARY: nothing exported here can represent recovery words, seeds,
 * private keys, Device passwords, WebAuthn PRF output, wrapping keys, full
 * candidate linkage, or transactions. The secret authority owns all
 * credential material.
 */
export * from './lifecycle.js';
export * from './projection.js';
export * from './envelope.js';
export * from './candidates.js';
export * from './evidence.js';
