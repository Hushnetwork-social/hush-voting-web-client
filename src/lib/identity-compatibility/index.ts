/**
 * FEAT-001 identity compatibility API — public surface.
 *
 * Framework-neutral entry point for deterministic identity compatibility:
 *   1. derive public candidate descriptors with producer provenance;
 *   2. resolve candidates against caller-supplied controlled lookup outcomes;
 *   3. derive private credentials only for one selected producer.
 * Plus pure .dat v1, canonical transaction, and signature compatibility ops.
 *
 * No dependency on React, Next.js, DOM, storage, transport, Zustand, routes,
 * or UI state. Expected failures are typed data with stable codes; nothing
 * throws for expected input errors; diagnostics never contain credentials.
 */
export * from './types';
export * from './crypto';
export * from './producers';
export * from './mnemonic';
export * from './candidates';
export * from './credentials';
export * from './dat';
export * from './canonical';
export * from './signature';
