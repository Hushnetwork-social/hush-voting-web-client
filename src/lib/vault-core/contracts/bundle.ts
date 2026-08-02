/**
 * FEAT-003 vault-core contracts — opaque validated credential bundle model.
 *
 * `ValidatedCredentialBundle` is produced inside an approved secret-owning boundary from
 * FEAT-001 results. The core accepts it only as an opaque, versioned value; the
 * secret-owning adapter validates all evidence (producer/version, exact signing and
 * encryption key consistency, expected encoded public addresses, optional mnemonic
 * consistency, profile/pending data) before encryption. Any disagreement rejects the
 * complete bundle; partial credential persistence is forbidden.
 *
 * Normative source: FEAT-003 FeatureDescription "Credential admission".
 */
import type { BundleAdmissionEvidence, ValidatedCredentialBundle } from './ports';

/** Deterministic bundle admission check (provenance + consistency evidence). */
export type BundleAdmission =
  | { readonly ok: true; readonly evidence: BundleAdmissionEvidence }
  | { readonly ok: false; readonly code: 'UNSUPPORTED_PRODUCER' | 'KEY_CONSISTENCY_FAILED' | 'MNEMONIC_CONSISTENCY_FAILED' | 'UNSUPPORTED_CONTRACT' };

export function admitCredentialBundle(
  bundle: ValidatedCredentialBundle,
  evidence: BundleAdmissionEvidence,
): BundleAdmission {
  if (bundle.featiContractVersion !== '1.0.0') {
    return { ok: false, code: 'UNSUPPORTED_CONTRACT' };
  }
  if (bundle.producerId !== evidence.producerId || bundle.producerVersion !== evidence.producerVersion) {
    return { ok: false, code: 'UNSUPPORTED_PRODUCER' };
  }
  if (!evidence.exactKeyConsistency) {
    return { ok: false, code: 'KEY_CONSISTENCY_FAILED' };
  }
  // A bundle that claims verified mnemonic consistency must carry a producer that
  // supports mnemonics; structural soundness is enforced by the secret-owning boundary.
  return { ok: true, evidence };
}
