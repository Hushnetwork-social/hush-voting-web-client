/**
 * FEAT-003 vault-core — public exports.
 *
 * Framework-neutral reference core and contracts for the Credential Vault and Session
 * authority. No React, Next.js, DOM storage, XState, Web Crypto production execution, or
 * platform APIs. Production randomness/cryptography/storage/OS-protection are adapter-owned
 * (FEAT-004/005/006). Expected failures are closed typed data.
 *
 * Normative source: FEAT-003 FeatureDescription; planning-analysis-report.md.
 */
export * from './contracts';
