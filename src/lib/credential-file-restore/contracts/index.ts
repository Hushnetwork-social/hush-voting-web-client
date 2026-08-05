/**
 * FEAT-009 credential-file restore — contracts public barrel.
 *
 * Framework-neutral closed vocabulary for the Restore Credential File
 * workflow. Extended incrementally per contract task (2.1 → 2.3 → 2.5 →
 * 2.7) so the repository compiles at every commit.
 *
 * SECRET BOUNDARY: nothing exported here can represent source identifiers,
 * source bytes, Backup-file passwords, derived keys, plaintext, mnemonic,
 * private keys, full addresses, exact transactions, or generic
 * capabilities. The secret authority owns all credential material.
 */
export * from './lifecycle.js';
export * from './custody.js';
export * from './projection.js';
export * from './import.js';
export * from './resolution.js';
export * from './protection.js';
export * from './staging.js';
export * from './evidence.js';
