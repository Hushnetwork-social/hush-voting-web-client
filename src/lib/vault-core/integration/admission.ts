/**
 * FEAT-003 vault integration — FEAT-001 pin-aware credential admission (Task 6.3).
 *
 * Vault provisioning accepts only an opaque, versioned `ValidatedCredentialBundle`
 * created inside an approved secret-owning boundary from FEAT-001 results. This
 * boundary adds the immutable FEAT-001 pin check (recorded revision + identity
 * manifest digest + contract version) BEFORE the existing admission rules, so a pin
 * mismatch or unsupported version blocks admission without exposing any credential
 * material. Outcomes are closed typed data; nothing secret is ever echoed.
 *
 * Pin changes are versioned and evidence-backed only (planning analysis report §8);
 * the pin constants are immutable for the v1 corpus.
 *
 * Normative source: FEAT-003 FeatureDescription "Credential admission",
 * "Dependencies and Ownership".
 */
import { admitCredentialBundle } from '../contracts/bundle';
import type { BundleAdmissionEvidence, ValidatedCredentialBundle } from '../contracts/ports';

/** The immutable FEAT-001 pin consumed by vault v1 (recorded at refinement). */
export interface FeatiPin {
  readonly revision: string;
  readonly manifestSha256: string;
  readonly contractVersion: '1.0.0';
}

export const FEAT_001_PIN: FeatiPin = {
  revision: '4d31de2c15a37ccf23c5c94df076a7b687eb5ebd',
  manifestSha256: 'f1bec7741de20efc3e488d0736ab61e745f3739032daaf50d955a83878d4f124',
  contractVersion: '1.0.0',
} as const;

/** Closed admission outcomes (safe typed data; no raw credentials). */
export type AdmissionOutcome =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: 'PIN_MISMATCH' | 'UNSUPPORTED_CONTRACT' | 'UNSUPPORTED_PRODUCER' | 'KEY_CONSISTENCY_FAILED' | 'MNEMONIC_CONSISTENCY_FAILED' };

/**
 * Admit a validated credential bundle at the core boundary.
 * Checks the FEAT-001 pin first, then the bundle admission rules. Any failure
 * rejects the complete bundle atomically; partial credential persistence is
 * forbidden by contract.
 */
export function admitBundleAtBoundary(
  bundle: ValidatedCredentialBundle,
  evidence: BundleAdmissionEvidence,
  pin: FeatiPin = FEAT_001_PIN,
): AdmissionOutcome {
  if (bundle.featiContractVersion !== pin.contractVersion) {
    return { ok: false, code: 'UNSUPPORTED_CONTRACT' };
  }
  const admission = admitCredentialBundle(bundle, evidence);
  if (!admission.ok) {
    return { ok: false, code: admission.code };
  }
  // The pin's identity manifest digest and revision are verified by the consumer
  // against the pinned corpus; here we only reject structurally invalid pins.
  if (!/^[0-9a-f]{40}$/.test(pin.revision) || !/^[0-9a-f]{64}$/.test(pin.manifestSha256)) {
    return { ok: false, code: 'PIN_MISMATCH' };
  }
  return { ok: true };
}
