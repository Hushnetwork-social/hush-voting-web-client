/**
 * FEAT-008 recovery-words integration — immutable downstream handoff and
 * release-finding composition (Task 6.9).
 *
 * Publishes the no-mnemonic selected-key staging, protection-mode, resume,
 * cleanup, and concrete-key-only consumer contracts for FEAT-009/010/011,
 * plus the machine-readable external release findings (EXT-008-001…004).
 * The handoff is versioned, immutable, and secret-free; consumers can never
 * obtain recovery words, private-key returns, generic signers/decryptors, or
 * full-address persistence.
 *
 * Normative source: FEAT-008 FeatureDescription "Cross-Feature Contract and
 * Release Dependencies", "Definition of Done"; Phase 1 implementation
 * sequence; Phase 2 evidence schemas.
 */
import type { DownstreamHandoffManifest, ExternalFinding } from '../contracts/evidence';

/** Immutable downstream recovery handoff (v1). */
export const RECOVERY_DOWNSTREAM_HANDOFF_V1: DownstreamHandoffManifest = {
  handoffVersion: 1,
  feature: 'FEAT-008',
  exposes: [
    'versioned-selected-key-staging',
    'protection-mode-metadata',
    'staged-resume',
    'verified-cleanup',
    'no-mnemonic-vault-contract',
    'concrete-key-only-export-eligibility',
  ],
  forbidden: ['recovery-words', 'private-key-return', 'generic-signer', 'generic-decryptor', 'full-address-persistence'],
  pinDigests: {
    // Pinned at Phase 0/1; re-pinned at Phase 7 with the immutable release evidence.
    'identity-corpus': 'f1bec7741de20efc3e488d0736ab61e745f3739032daaf50d955a83878d4f124',
    'vault-corpus': 'e8dfdfa49b9e33cfc8a47b1266c5a14cb978c4be28f21d87cc2f034d435582e5',
  },
};

/** External release findings ledger (never implementation blockers). */
export const RECOVERY_RELEASE_FINDINGS: readonly ExternalFinding[] = [
  {
    findingId: 'EXT-008-001',
    title: 'Cross-feature no-mnemonic/optional-protection migration',
    owningScope: 'Targeted versioned updates for FEAT-003/004/005/006/007/009/010/011',
    releaseImpact: 'BLOCKS_RELEASE of the no-mnemonic contract; new FEAT-008 vaults remain versioned and fail-closed',
    implementationBlocking: false,
    evidenceObserved: 'Sealed v1 handoffs record mnemonic/password-only behavior; FEAT-008 uses additive versions',
    followUp: 'Separately owned EPIC/FEAT work; capability gates stay fail-closed',
  },
  {
    findingId: 'EXT-008-002',
    title: 'HushServerNode signature/authenticity, atomic reservation, stable-code, focused FEAT-008 TwinTests',
    owningScope: 'HushServerNode hardening EPIC/FEAT',
    releaseImpact: 'BLOCKS_RELEASE of missing-profile recreation',
    implementationBlocking: false,
    evidenceObserved: 'Focused TwinTests and hardening artifacts unavailable in the client repository',
    followUp: 'HushServerNode workstream; server scenario contract HV-RW-SRV-001…008 published for linkage',
  },
  {
    findingId: 'EXT-008-003',
    title: 'Physical Ubuntu/Android and real-device WebAuthn PRF qualification',
    owningScope: 'Platform qualification workstream',
    releaseImpact: 'BLOCKS_RELEASE of passwordless modes',
    implementationBlocking: false,
    evidenceObserved: 'No physical devices/real-browser majors available in this environment; virtual authenticators only',
    followUp: 'Qualified physical harness per FEAT-005/006 procedures',
  },
  {
    findingId: 'EXT-008-004',
    title: 'Independent security review with no unresolved High/Critical',
    owningScope: 'Governance/release review',
    releaseImpact: 'BLOCKS_RELEASE',
    implementationBlocking: false,
    evidenceObserved: 'Organizational review not yet performed',
    followUp: 'Independent security review workstream',
  },
];

/** Machine-readable findings manifest (validated by evidence schema). */
export function releaseFindingsManifest(): { readonly manifestVersion: 1; readonly feature: 'FEAT-008'; readonly findings: readonly ExternalFinding[] } {
  return { manifestVersion: 1, feature: 'FEAT-008', findings: RECOVERY_RELEASE_FINDINGS };
}
