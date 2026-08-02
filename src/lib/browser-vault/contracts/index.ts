/**
 * FEAT-004 browser-vault contracts — public exports.
 *
 * Closed protocol, preflight, storage layout, evidence report, and downstream
 * operation contracts for the production web adapter. No secret-bearing
 * structures are exported; the boundary with FEAT-003 vault-core contracts is
 * additive and versioned.
 */
export * from './protocol';
export * from './preflight';
export * from './storage';
export * from './reports';
export * from './operations';
