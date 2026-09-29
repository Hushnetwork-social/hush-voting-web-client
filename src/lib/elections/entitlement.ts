/** FEAT-018 E03: closed, page-safe election authority contract. No server copy or secrets. */
export const ELECTION_ENTITLEMENT_REASONS = [
  'ENTITLEMENT_NOT_ACTIVE', 'ENTITLEMENT_LIMIT_EXCEEDED', 'ENTITLEMENT_PROFILE_NOT_ALLOWED',
  'ENTITLEMENT_AUTHORITY_UNAVAILABLE', 'ENTITLEMENT_CAPTURE_UNAVAILABLE',
  'ENTITLEMENT_SEMANTICS_UNSUPPORTED', 'ROSTER_REPLACEMENT_AFTER_LINK',
] as const;
export type ElectionEntitlementReason = typeof ELECTION_ENTITLEMENT_REASONS[number];
export const ELECTION_CAPTURED_OPERATIONS = [
  'vote', 'close', 'approve', 'finalize', 'submitFinalizationShare', 'continuity', 'void', 'audit', 'report', 'results',
] as const;
export type ElectionCapturedOperation = typeof ELECTION_CAPTURED_OPERATIONS[number];

export function electionEntitlementReason(value: unknown): ElectionEntitlementReason | null {
  if (value === '' || value === undefined || value === null) return null;
  return ELECTION_ENTITLEMENT_REASONS.includes(value as ElectionEntitlementReason)
    ? value as ElectionEntitlementReason : 'ENTITLEMENT_SEMANTICS_UNSUPPORTED';
}

export function isElectionId(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(value)
    && value !== '00000000-0000-0000-0000-000000000000';
}

export interface ElectionScopedAccess {
  readonly electionId: string;
  readonly allowedOperations: readonly ElectionCapturedOperation[];
  readonly reason: ElectionEntitlementReason | null;
}

/** Decode only the additive server scope, bound to the requested election. Older/malformed
 * responses never restore access. The authenticated worker supplies actor/session binding. */
export function parseElectionScopedAccess(value: unknown, expectedElectionId: string): ElectionScopedAccess {
  const blocked = (reason: ElectionEntitlementReason): ElectionScopedAccess => ({ electionId: expectedElectionId, allowedOperations: [], reason });
  if (!isElectionId(expectedElectionId) || value === null || typeof value !== 'object' || Array.isArray(value))
    return blocked('ENTITLEMENT_SEMANTICS_UNSUPPORTED');
  const wire = value as Record<string, unknown>;
  if (wire.SchemaVersion !== 1 || wire.ElectionId !== expectedElectionId || typeof wire.EntitlementReason !== 'string')
    return blocked('ENTITLEMENT_SEMANTICS_UNSUPPORTED');
  const reason = electionEntitlementReason(wire.EntitlementReason);
  if (reason !== null) return blocked(reason);
  if (!Array.isArray(wire.AllowedOperations) || wire.AllowedOperations.length > ELECTION_CAPTURED_OPERATIONS.length
      || wire.AllowedOperations.some(op => !ELECTION_CAPTURED_OPERATIONS.includes(op))
      || new Set(wire.AllowedOperations).size !== wire.AllowedOperations.length)
    return blocked('ENTITLEMENT_SEMANTICS_UNSUPPORTED');
  return { electionId: expectedElectionId, allowedOperations: [...wire.AllowedOperations], reason: null };
}
