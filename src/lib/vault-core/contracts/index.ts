/**
 * FEAT-003 vault-core contracts — public exports.
 *
 * Framework-neutral: no React, Next.js, DOM, storage, transport, XState, or platform
 * APIs. Expected failures are closed typed data; nothing here throws for expected input
 * errors; diagnostics never contain credentials. Production salts, keys, and nonces are
 * adapter-owned and never accepted from callers.
 *
 * Normative source: FEAT-003 FeatureDescription "Logical Vault Model", "Version Model",
 * "Cryptographic Suite", "Session Core", "Typed Result Contract".
 */
export * from './versions';
export * from './records';
export * from './preview';
export * from './extensions';
export * from './suite';
export * from './envelope';
export * from './sidecar';
export * from './registry';
export * from './results';
export * from './ports';
export * from './operations';
export * from './capabilities';
export * from './bundle';
