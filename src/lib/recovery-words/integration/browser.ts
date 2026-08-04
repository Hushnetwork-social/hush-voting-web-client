/**
 * FEAT-008 recovery-words integration — browser composition.
 *
 * Wires the platform-neutral recovery authority ports to real browser
 * capabilities: same-origin BFF public lookup with `Cache-Control: no-store`,
 * WebAuthn platform-authenticator PRF capability gating (fail-closed), the
 * sealed `recoverWordsProvision` browser operation for selected-key staging,
 * and the one-owner coordination surface. The concrete WebAuthn PRF crypto
 * and worker custody are consumed through the sealed browser-vault seam;
 * physical/real-device qualification remains an external release finding.
 *
 * SECRET BOUNDARY: phrases, keys, passwords, PRF output, and wrapping keys
 * never cross this composition — only public candidate descriptors, opaque
 * refs, ciphertext, and typed outcomes.
 *
 * Normative source: FEAT-008 FeatureDescription "Complete lookup
 * requirement", "No client caching", "Passwordless Web", "Browser
 * concurrency"; FEAT-007 transport contract; FEAT-004 browser-vault handoff.
 */
import type { PublicCandidateDescriptor } from '../../identity-compatibility/types';
import type { CandidateLookupOutcome, SelectedKeyProofEvidence } from '../contracts/candidates';
import type { NetworkIdentifier, RecoveryEpoch, RecoveryResult } from '../contracts/lifecycle';
import { LOOKUP_REQUEST_TIMEOUT_MS, type RecoveryLookupPort } from '../authority/lookup';
import type { SelectedKeyProofPort } from '../authority/proof';

/** Same-origin BFF lookup endpoint (server-only; never NEXT_PUBLIC). */
export const BFF_IDENTITY_LOOKUP_PATH = '/api/identity' as const;

/**
 * Real browser lookup port: bounded same-origin POST with an explicit
 * `no-store` expectation. A timeout/transport failure records `unresolved`
 * (never absence); full addresses are excluded from ordinary diagnostics.
 */
export function createBffRecoveryLookupPort(fetchImpl: typeof fetch = fetch): RecoveryLookupPort {
  return {
    async lookupCandidate(candidate: PublicCandidateDescriptor, networkIdentifier: NetworkIdentifier): Promise<CandidateLookupOutcome> {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), LOOKUP_REQUEST_TIMEOUT_MS);
      try {
        const response = await fetchImpl(BFF_IDENTITY_LOOKUP_PATH, {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-recovery-network': networkIdentifier },
          body: JSON.stringify({ publicSigningAddress: candidate.signingAddress }),
          cache: 'no-store',
          signal: controller.signal,
        });
        if (!response.ok) {
          return { kind: 'unresolved', reason: 'transport' };
        }
        const payload = (await response.json()) as { reply?: { identity?: { alias?: unknown; visibility?: unknown } | null } };
        const profile = payload.reply?.identity;
        if (profile === null || profile === undefined) {
          return { kind: 'authoritativeNotFound' };
        }
        // Blockchain visibility is authoritative; never hardcoded.
        const visibility = profile.visibility === 'public' ? 'public' : 'private';
        return { kind: 'exactProfile', profileAlias: String(profile.alias ?? ''), visibility };
      } catch {
        return { kind: 'unresolved', reason: 'timeout' };
      } finally {
        clearTimeout(timer);
      }
    },
  };
}

/** WebAuthn platform-authenticator PRF capability report (fail-closed). */
export interface WebAuthnPrfCapabilities {
  readonly webauthnPlatform: boolean;
  readonly discoverableCredential: boolean;
  readonly userVerification: boolean;
  readonly prf: boolean;
  readonly allowedProductionRpId: string | null;
}

/** Production RP ID allowlist (versioned; physical qualification required). */
export const ALLOWED_PRODUCTION_RP_IDS: ReadonlyArray<string> = [] as const;

/**
 * Capability detection — NEVER enables passwordless Web without all
 * mandatory properties and an allowlisted RP ID. Physical/real-device
 * qualification remains an external release finding.
 */
export function detectWebAuthnPrfCapabilities(
  environment: Pick<typeof globalThis, 'PublicKeyCredential'> = globalThis as unknown as Pick<typeof globalThis, 'PublicKeyCredential'>,
  rpId: string | null,
): WebAuthnPrfCapabilities {
  const hasPlatform = typeof environment.PublicKeyCredential !== 'undefined';
  if (!hasPlatform) {
    return { webauthnPlatform: false, discoverableCredential: false, userVerification: false, prf: false, allowedProductionRpId: null };
  }
  return {
    webauthnPlatform: true,
    discoverableCredential: true, // resolved at runtime by the seam; detection is conservative
    userVerification: true,
    prf: false, // PRF availability requires a live credential assertion; never assumed
    allowedProductionRpId: rpId !== null && ALLOWED_PRODUCTION_RP_IDS.includes(rpId) ? rpId : null,
  };
}

/**
 * Sealed browser proof seam consumption: the worker authority performs the
 * selected-key derivation/proof through the FEAT-004 `recoverWordsProvision`
 * operation contract. This composition provides the typed outcome mapping;
 * the actual worker protocol is the sealed seam.
 */
export function createBrowserProofPort(seam: { proveSelected(index: number, epoch: RecoveryEpoch): Promise<RecoveryResult<SelectedKeyProofEvidence>> }): SelectedKeyProofPort {
  return {
    async proveSelected(selectedCandidateIndex: number, epoch: RecoveryEpoch): Promise<RecoveryResult<SelectedKeyProofEvidence>> {
      return seam.proveSelected(selectedCandidateIndex, epoch);
    },
  };
}
