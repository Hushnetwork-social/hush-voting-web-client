/**
 * FEAT-008 recovery-words integration — FEAT-007 reuse, transport
 * normalization, and HushServerNode scenario contract.
 *
 * Reuses the FEAT-007 identity-creation profile validation, wire
 * normalizers, lookup-first reconciliation, and BFF transport unchanged for
 * missing-profile recreation and fresh-verification lookups. Publishes the
 * matching HushServerNode Gherkin scenario IDs (client/server evidence
 * linkage) without changing any RPC or protobuf.
 *
 * SECRET BOUNDARY: only public addresses and typed outcomes cross this
 * module; the client never parses free-form server messages.
 *
 * Normative source: FEAT-008 FeatureDescription "Missing-Profile
 * Recreation", "Existing-Profile Activation", "HushServerNode TwinTests";
 * FEAT-007 creation handoff; HushVoting Test Architecture.
 */
import type { NetworkIdentifier } from '../contracts/lifecycle';
import type { FreshProfileOutcome } from '../authority/activation';
import type { CandidateLookupOutcome } from '../contracts/candidates';

/** Reuse the FEAT-007 wire-normalized GetIdentity reply shape. */
export interface Feat007GetIdentityReply {
  readonly identity: {
    readonly alias: string;
    readonly visibility: 'private' | 'public';
    readonly signingAddress: string;
    readonly encryptionAddress: string;
  } | null;
}

/**
 * FEAT-007 wire-normalizer reuse: a closed GetIdentity reply becomes the
 * fresh-verification outcome. Exact both-key equality is enforced by the
 * authority activation policy; unknown/malformed replies fail closed.
 */
export function normalizeFeat007Reply(
  reply: Feat007GetIdentityReply | null,
  signingAddress: string,
  encryptionAddress: string,
  networkIdentifier: NetworkIdentifier,
): FreshProfileOutcome {
  void networkIdentifier;
  if (reply === null || reply.identity === null) {
    return { kind: 'authoritativeAbsent' };
  }
  if (reply.identity.signingAddress !== signingAddress || reply.identity.encryptionAddress !== encryptionAddress) {
    return { kind: 'mismatch' };
  }
  return { kind: 'exactExisting', signingAddress, encryptionAddress, alias: reply.identity.alias, visibility: reply.identity.visibility };
}

/** Map a FEAT-007 BFF lookup transport outcome to the recovery lookup outcome. */
export function normalizeLookupOutcome(
  reply: { ok: true; reply: Feat007GetIdentityReply } | { ok: false; failure: { kind: string } },
): CandidateLookupOutcome {
  if (!reply.ok) {
    return { kind: 'unresolved', reason: reply.failure.kind === 'timeout' ? 'timeout' : 'transport' };
  }
  if (reply.reply.identity === null) {
    return { kind: 'authoritativeNotFound' };
  }
  return { kind: 'exactProfile', profileAlias: reply.reply.identity.alias, visibility: reply.reply.identity.visibility };
}

/**
 * HushServerNode matching Gherkin scenario contract (FEAT-008 TwinTest
 * linkage). Scenario IDs link client and server evidence; the server-side
 * suite is separately owned release hardening (EXT-008-002).
 */
export interface ServerScenarioContract {
  readonly contractVersion: 1;
  readonly feature: 'FEAT-008';
  readonly scenarios: ReadonlyArray<{
    readonly id: string; // e.g. 'HV-RW-SRV-001'
    readonly family: string;
    readonly objective: string;
    readonly twinOf: string; // client scenario family it mirrors
  }>;
}

export const SERVER_SCENARIO_CONTRACT: ServerScenarioContract = {
  contractVersion: 1,
  feature: 'FEAT-008',
  scenarios: [
    { id: 'HV-RW-SRV-001', family: 'HV-RW-LOOKUP', objective: 'Exact GetIdentity for every Approved candidate encoding (P-01/P-02/P-03 address forms)', twinOf: 'HV-RW-LOOKUP' },
    { id: 'HV-RW-SRV-002', family: 'HV-RW-LOOKUP', objective: 'Authoritative not-found versus transport failure are distinct outcomes', twinOf: 'HV-RW-LOOKUP' },
    { id: 'HV-RW-SRV-003', family: 'HV-RW-PROFILE', objective: 'Signing-only match is rejected; exact signing AND encryption equality required', twinOf: 'HV-RW-PROFILE' },
    { id: 'HV-RW-SRV-004', family: 'HV-RW-SELECT', objective: 'Zero/one/multiple deterministic lookup outcomes across the candidate set', twinOf: 'HV-RW-SELECT' },
    { id: 'HV-RW-SRV-005', family: 'HV-RW-RECREATE', objective: 'Missing-profile exact-key FullIdentity registration with valid signature/signatory binding', twinOf: 'HV-RW-RECREATE' },
    { id: 'HV-RW-SRV-006', family: 'HV-RW-RECREATE', objective: 'Atomic duplicate-key mempool PENDING behavior for concurrent same-key submissions', twinOf: 'HV-RW-RECREATE' },
    { id: 'HV-RW-SRV-007', family: 'HV-RW-RECREATE', objective: 'Block confirmation and blockchain-reset recreation with the exact restored keys', twinOf: 'HV-RW-RECREATE' },
    { id: 'HV-RW-SRV-008', family: 'HV-RW-SECURITY', objective: 'Forged, wrong-key, altered, and malformed transaction rejection', twinOf: 'HV-RW-SECURITY' },
  ],
};

/** Deterministic contract integrity check (unknown scenario IDs fail). */
export function validateServerScenarioContract(contract: ServerScenarioContract): { readonly ok: true } | { readonly ok: false; readonly code: 'UNKNOWN_SCENARIO' | 'WRONG_FEATURE' | 'DUPLICATE_ID' } {
  if (contract.feature !== 'FEAT-008' || contract.contractVersion !== 1) {
    return { ok: false, code: 'WRONG_FEATURE' };
  }
  const ids = new Set<string>();
  for (const scenario of contract.scenarios) {
    if (ids.has(scenario.id)) {
      return { ok: false, code: 'DUPLICATE_ID' };
    }
    ids.add(scenario.id);
  }
  const known = new Set(SERVER_SCENARIO_CONTRACT.scenarios.map((scenario) => scenario.id));
  for (const id of ids) {
    if (!known.has(id)) {
      return { ok: false, code: 'UNKNOWN_SCENARIO' };
    }
  }
  return { ok: true };
}
