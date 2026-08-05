/**
 * FEAT-009 credential-file restore integration — server scenario contract,
 * conformance/harness tooling, and downstream handoff (Tasks 6.7, 6.9).
 *
 * Publishes: stable HushServerNode scenario IDs (HV-DAT-SRV-001…0NN) with
 * typed expected outcomes, the public v1 restore conformance runner shape,
 * the controlled external qualification harness guard (refuses CI/cloud/
 * shared/production networks and recording-enabled runs; aggregate-only
 * evidence), the immutable release ledger, and the versioned FEAT-010/011
 * downstream handoff. External execution of server TwinTests and the
 * controlled corpus remains separately owned release evidence
 * (EXT-009-001/003); absence is NOT_SUPPLIED, never fabricated.
 *
 * SECRET BOUNDARY: no source identifier, password, plaintext, mnemonic,
 * private key, full address, or external digest is representable.
 *
 * Normative source: FEAT-009 FeatureDescription "Controlled Legacy
 * Interoperability Evidence", "Network isolation", "Testing Strategy",
 * "Definition of Done"; FeatureTasks.md External release admission.
 */
import type { ExternalReleaseFinding, ReleaseFindingState, ServerScenarioAlignment } from '../contracts/evidence';

/** Stable server scenario catalog (client-side contract; server executes them). */
export const SERVER_SCENARIOS: readonly ServerScenarioAlignment[] = [
  { scenarioId: 'HV-DAT-SRV-001', clientTestRef: 'lookup-existing-exact-pair', twinTestRef: null, expectedOutcome: 'existing-exact-both-key', evidenceState: 'NOT_SUPPLIED' },
  { scenarioId: 'HV-DAT-SRV-002', clientTestRef: 'lookup-signing-only-mismatch', twinTestRef: null, expectedOutcome: 'signing-only-fails-closed', evidenceState: 'NOT_SUPPLIED' },
  { scenarioId: 'HV-DAT-SRV-003', clientTestRef: 'lookup-encryption-mismatch', twinTestRef: null, expectedOutcome: 'encryption-mismatch-fails-closed', evidenceState: 'NOT_SUPPLIED' },
  { scenarioId: 'HV-DAT-SRV-004', clientTestRef: 'lookup-authoritative-not-found', twinTestRef: null, expectedOutcome: 'authoritative-not-found', evidenceState: 'NOT_SUPPLIED' },
  { scenarioId: 'HV-DAT-SRV-005', clientTestRef: 'lookup-transport-vs-not-found', twinTestRef: null, expectedOutcome: 'transport-never-not-found', evidenceState: 'NOT_SUPPLIED' },
  { scenarioId: 'HV-DAT-SRV-006', clientTestRef: 'create-exact-key-accepted', twinTestRef: null, expectedOutcome: 'fullidentity-accepted', evidenceState: 'NOT_SUPPLIED' },
  { scenarioId: 'HV-DAT-SRV-007', clientTestRef: 'create-wrong-key-rejected', twinTestRef: null, expectedOutcome: 'invalid-proof-rejected-before-mempool', evidenceState: 'NOT_SUPPLIED' },
  { scenarioId: 'HV-DAT-SRV-008', clientTestRef: 'create-altered-signature-rejected', twinTestRef: null, expectedOutcome: 'signatory-mismatch-rejected', evidenceState: 'NOT_SUPPLIED' },
  { scenarioId: 'HV-DAT-SRV-009', clientTestRef: 'create-atomic-same-key-pending', twinTestRef: null, expectedOutcome: 'atomic-pending', evidenceState: 'NOT_SUPPLIED' },
  { scenarioId: 'HV-DAT-SRV-010', clientTestRef: 'create-exact-confirmation', twinTestRef: null, expectedOutcome: 'exact-block-confirmation', evidenceState: 'NOT_SUPPLIED' },
  { scenarioId: 'HV-DAT-SRV-011', clientTestRef: 'reset-recreation', twinTestRef: null, expectedOutcome: 'blockchain-reset-recreation', evidenceState: 'NOT_SUPPLIED' },
];

/** External release findings ledger (initial NOT_EVALUATED states). */
export const RELEASE_FINDINGS: readonly ExternalReleaseFinding[] = [
  { id: 'EXT-009-001', state: 'NOT_SUPPLIED', evidencePin: null, note: 'Controlled legacy corpus qualification runs only on an isolated approved non-production network with aggregate-only evidence.' },
  { id: 'EXT-009-002', state: 'NOT_SUPPLIED', evidencePin: null, note: 'Physical Ubuntu/Android and real-device picker/protection qualification consumes the deterministic scenario package.' },
  { id: 'EXT-009-003', state: 'NOT_SUPPLIED', evidencePin: null, note: 'HushServerNode hardening and TwinTests (HV-DAT-SRV-001…011) are separately owned release evidence.' },
  { id: 'EXT-009-004', state: 'NOT_SUPPLIED', evidencePin: null, note: 'FEAT-008 no-mnemonic/optional-protection replacement contracts and migrations must be green before release.' },
  { id: 'EXT-009-005', state: 'NOT_SUPPLIED', evidencePin: null, note: 'Independent security review must have no unresolved High/Critical finding affecting file custody, decryption, key proof, protection, registration, or cleanup.' },
];

/** Update a finding state only from immutable external evidence (never fabricated). */
export function admitReleaseFinding(
  findings: readonly ExternalReleaseFinding[],
  id: string,
  state: ReleaseFindingState,
  evidencePin: string | null,
): { readonly ok: true; readonly updated: ExternalReleaseFinding[] } | { readonly ok: false; readonly reason: string } {
  if (state === 'PASS' && (evidencePin === null || !/^[a-f0-9]{40,64}$/i.test(evidencePin))) {
    return { ok: false, reason: 'PASS requires an immutable evidence pin' };
  }
  if (!findings.some((f) => f.id === id)) {
    return { ok: false, reason: `unknown finding: ${id}` };
  }
  return {
    ok: true,
    updated: findings.map((f) => (f.id === id ? { ...f, state, evidencePin } : f)),
  };
}

/** Controlled external harness preflight: refuse unsafe execution before opening any file. */
export function controlledCorpusPreflight(opts: {
  readonly ciMarker: boolean;
  readonly cloudMarker: boolean;
  readonly sharedNetworkMarker: boolean;
  readonly productionNetworkMarker: boolean;
  readonly recordingEnabled: boolean;
  readonly echoCapablePasswordSource: boolean;
  readonly outputPathAllowed: boolean;
}): { readonly ok: true } | { readonly ok: false; readonly code: 'CI_OR_CLOUD' | 'SHARED_OR_PRODUCTION_NETWORK' | 'RECORDING_ENABLED' | 'ECHO_CAPABLE_PASSWORD' | 'OUTPUT_PATH_DENIED' } {
  if (opts.ciMarker || opts.cloudMarker) {
    return { ok: false, code: 'CI_OR_CLOUD' };
  }
  if (opts.sharedNetworkMarker || opts.productionNetworkMarker) {
    return { ok: false, code: 'SHARED_OR_PRODUCTION_NETWORK' };
  }
  if (opts.recordingEnabled) {
    return { ok: false, code: 'RECORDING_ENABLED' };
  }
  if (opts.echoCapablePasswordSource) {
    return { ok: false, code: 'ECHO_CAPABLE_PASSWORD' };
  }
  if (!opts.outputPathAllowed) {
    return { ok: false, code: 'OUTPUT_PATH_DENIED' };
  }
  return { ok: true };
}

/** Aggregate controlled-corpus evidence writer (never per-file detail). */
export function aggregateCorpusEvidence(input: {
  readonly totalFiles: number;
  readonly passed: number;
  readonly failed: number;
  readonly sourceUnchangedAggregate: boolean;
  readonly producerShapeClasses: number;
  readonly isolatedNetworkDigest: string;
}): { readonly ok: true; readonly evidence: ControlledCorpusEvidenceLike } | { readonly ok: false; readonly reason: string } {
  if (input.totalFiles !== input.passed + input.failed) {
    return { ok: false, reason: 'aggregate counts inconsistent' };
  }
  return {
    ok: true,
    evidence: { ...input, captureDisabled: true },
  };
}

interface ControlledCorpusEvidenceLike {
  readonly totalFiles: number;
  readonly passed: number;
  readonly failed: number;
  readonly sourceUnchangedAggregate: boolean;
  readonly producerShapeClasses: number;
  readonly isolatedNetworkDigest: string;
  readonly captureDisabled: true;
}
