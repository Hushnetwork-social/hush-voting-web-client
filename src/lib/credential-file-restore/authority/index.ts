/**
 * FEAT-009 credential-file restore authority — public barrel.
 *
 * Platform-neutral workflow policies for the Restore Credential File
 * journey: bounded snapshot/envelope/source-release, exact v1 import with
 * backoff and destruction, concrete key proof + identity resolution,
 * protection/staging/activation/recreation/resume, and navigation/owner/
 * cleanup convergence.
 *
 * SECRET BOUNDARY: no source identifier, password, plaintext, mnemonic,
 * private key, full ordinary address, exact transaction, or generic
 * capability is representable here. The sealed platform authority owns all
 * credential material.
 */
export * from './snapshot.js';
export * from './import.js';
export * from './proof.js';
export * from './provision.js';
export * from './convergence.js';
