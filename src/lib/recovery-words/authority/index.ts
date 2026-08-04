/**
 * FEAT-008 recovery-words authority — public barrel.
 *
 * Platform-neutral workflow policies for the Recovery Words journey:
 * word validation/derivation, complete lookup/resolution, selected-key proof
 * + protection + staging/destruction, activation/recreation/resume, and
 * navigation/ownership/cleanup convergence.
 *
 * SECRET BOUNDARY: no phrase, seed, private key, password, PRF output,
 * wrapping key, or transaction is representable here.
 */
export * from './word.js';
export * from './lookup.js';
export * from './proof.js';
export * from './activation.js';
export * from './convergence.js';
