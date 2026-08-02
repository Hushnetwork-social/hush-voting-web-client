/**
 * FEAT-003 vault integration — public exports.
 *
 * Additive integration boundary between the vault core contracts and the unchanged
 * FEAT-002 production composition / FEAT-001 validated-bundle admission. No React,
 * XState, storage, or platform behavior exists here; no reference/test actor can be
 * selected through these exports.
 */
export * from './admission';
export * from './composition';
