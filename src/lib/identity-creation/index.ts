/**
 * FEAT-007 identity-creation — public module surface.
 *
 * Framework-neutral contracts and pure logic for the Create User workflow:
 * lifecycle/review projections, alias/profile validation, canonical
 * FullIdentity transaction description, and closed wire normalizers.
 *
 * Secret boundary: this module never represents or returns passwords,
 * mnemonics, private keys, transaction JSON, signatures, or generic
 * capabilities. It is safe to import from XState/React/renderer code.
 */
export * from './contracts.js';
export * from './profile.js';
export * from './wire.js';
