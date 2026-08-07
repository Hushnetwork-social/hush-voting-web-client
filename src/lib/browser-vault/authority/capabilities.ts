/**
 * FEAT-004 worker authority — capability phases and fresh-password capabilities.
 *
 * Fresh-password capabilities remain bound to the requesting channel, one
 * purpose, first use, and no more than 60 seconds. Another tab cannot consume
 * them. Capability phases gate which operations may run inside the authority.
 *
 * Normative source: FEAT-004 FeatureDescription "Shared tabs", "Mnemonic
 * Reveal", "Worker protocol"; FEAT-003 session kernel.
 */

import type { BrowserOperationKind } from '../contracts/protocol';

/** Authority capability phases (safe projection vocabulary). */
export type AuthorityPhase = 'noLocalUser' | 'locked' | 'verificationOnly' | 'authenticated' | 'removalInProgress';

/** Fresh-password capability purposes. */
export type FreshCapabilityPurpose = 'provision' | 'changePassword' | 'removeLocalUser' | 'revealMnemonic' | 'exportEncryptedFile';

export const FRESH_CAPABILITY_MAX_AGE_MS = 60_000 as const;

export interface FreshPasswordCapability {
  readonly id: string;
  readonly purpose: FreshCapabilityPurpose;
  readonly clientChannel: string;
  readonly authorityEpoch: number;
  readonly issuedAtMs: number;
  readonly expiresAtMs: number;
  /** One-use by contract; consumed on first successful use. */
  readonly used: boolean;
}

export type CapabilityConsumption =
  | { readonly ok: true; readonly capability: FreshPasswordCapability }
  | { readonly ok: false; readonly reason: 'expired' | 'wrong-channel' | 'wrong-epoch' | 'used' | 'purpose-mismatch' | 'malformed' };

/** Issue a fresh one-use capability bound to channel/epoch/purpose (≤60 s). */
export function issueFreshCapability(params: {
  readonly id: string;
  readonly purpose: FreshCapabilityPurpose;
  readonly clientChannel: string;
  readonly authorityEpoch: number;
  readonly nowMs: number;
}): FreshPasswordCapability {
  return {
    id: params.id,
    purpose: params.purpose,
    clientChannel: params.clientChannel,
    authorityEpoch: params.authorityEpoch,
    issuedAtMs: params.nowMs,
    expiresAtMs: params.nowMs + FRESH_CAPABILITY_MAX_AGE_MS,
    used: false,
  };
}

/** Consume a fresh capability with full channel/epoch/purpose/age/one-use checks. */
export function consumeFreshCapability(
  capability: FreshPasswordCapability | null,
  params: { readonly purpose: FreshCapabilityPurpose; readonly clientChannel: string; readonly authorityEpoch: number; readonly nowMs: number },
): CapabilityConsumption {
  if (capability === null) {
    return { ok: false, reason: 'malformed' };
  }
  if (capability.used) {
    return { ok: false, reason: 'used' };
  }
  if (capability.clientChannel !== params.clientChannel) {
    return { ok: false, reason: 'wrong-channel' };
  }
  if (capability.authorityEpoch !== params.authorityEpoch) {
    return { ok: false, reason: 'wrong-epoch' };
  }
  if (capability.purpose !== params.purpose) {
    return { ok: false, reason: 'purpose-mismatch' };
  }
  if (params.nowMs > capability.expiresAtMs) {
    return { ok: false, reason: 'expired' };
  }
  return { ok: true, capability: { ...capability, used: true } };
}

/** Fresh capabilities required per closed operation kind. */
export const FRESH_CAPABILITY_REQUIRED_BY_OPERATION: Readonly<Record<BrowserOperationKind, FreshCapabilityPurpose | null>> = {
  provisionFromValidatedBundle: 'provision',
  changeDevicePassword: 'changePassword',
  removeLocalUser: 'removeLocalUser',
  revealMnemonic: 'revealMnemonic',
  exportEncryptedFile: 'exportEncryptedFile',
  unlockPassword: null,
  verifyOnlineIdentity: null,
  lockAll: null,
  // FEAT-010 v2 additive: sealed candidate lifecycle + startup inspection.
  createCandidate: null,
  revealCandidateWords: null,
  concealCandidate: null,
  destroyCandidate: null,
  deriveWordsCandidate: null,
  importFileCandidate: null,
  retainTransactionDigest: null,
  submitIdentityTransaction: null,
  promoteLifecycle: null,
  inspectStartup: null,
} as const;

/** Safe session projection vocabulary for clients (never secrets). */
export type SafeSessionState = AuthorityPhase;
