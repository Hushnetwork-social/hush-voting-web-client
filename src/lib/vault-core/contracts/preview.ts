/**
 * FEAT-003 vault-core contracts — cleartext locked preview (identity-only).
 *
 * Before password verification, expose only: normalized alias, abbreviated signing
 * address (first 8 / last 6 characters), lifecycle status, and format versions.
 * The exact preview is included in record/key-package AAD; before successful decryption
 * it is display-only and cannot drive authorization, identity matching, migration, or
 * mutation. After unlock it must match the encrypted record.
 *
 * Deep-Dive decision: identity-only preview. No full addresses, no mnemonic availability
 * details, no avatars, no network identity.
 *
 * Normative source: FEAT-003 FeatureDescription "Cleartext preview allowlist".
 */
import type { VaultLifecycleStatus } from './records';

/** Abbreviated signing-address preview (8 + 6 characters). */
export interface SigningAddressPreview {
  readonly prefix: string;
  readonly suffix: string;
}

export const PREVIEW_ALIAS_MAX_LENGTH = 64 as const;
export const PREVIEW_SIGNING_ADDRESS_PREFIX_LENGTH = 8 as const;
export const PREVIEW_SIGNING_ADDRESS_SUFFIX_LENGTH = 6 as const;

/** Cleartext preview v1 — the exact allowlisted locked-screen metadata. */
export interface VaultPreviewV1 {
  readonly alias: string;
  readonly signingAddressPrefix: string;
  readonly signingAddressSuffix: string;
  readonly lifecycleStatus: VaultLifecycleStatus;
  readonly envelopeFormatVersion: 1;
  readonly parameterSuiteVersion: 1;
  readonly recordSchemaVersion: 1;
}

/** Deterministic validation of the identity-only preview allowlist. */
export type PreviewValidation =
  | { readonly ok: true; readonly preview: VaultPreviewV1 }
  | { readonly ok: false; readonly code: 'INVALID_PREVIEW'; readonly message: string };

export function validatePreviewV1(input: unknown): PreviewValidation {
  if (typeof input !== 'object' || input === null) {
    return { ok: false, code: 'INVALID_PREVIEW', message: 'preview must be an object' };
  }
  const p = input as Record<string, unknown>;
  const alias = p.alias;
  const prefix = p.signingAddressPrefix;
  const suffix = p.signingAddressSuffix;
  const lifecycle = p.lifecycleStatus;
  const env = p.envelopeFormatVersion;
  const suite = p.parameterSuiteVersion;
  const rec = p.recordSchemaVersion;
  if (typeof alias !== 'string' || alias.length < 1 || alias.length > PREVIEW_ALIAS_MAX_LENGTH) {
    return { ok: false, code: 'INVALID_PREVIEW', message: 'alias must be 1-64 characters' };
  }
  if (
    typeof prefix !== 'string' ||
    prefix.length !== PREVIEW_SIGNING_ADDRESS_PREFIX_LENGTH ||
    !/^[A-Za-z0-9]{8}$/.test(prefix)
  ) {
    return { ok: false, code: 'INVALID_PREVIEW', message: 'signingAddressPrefix must be 8 alphanumeric characters' };
  }
  if (
    typeof suffix !== 'string' ||
    suffix.length !== PREVIEW_SIGNING_ADDRESS_SUFFIX_LENGTH ||
    !/^[A-Za-z0-9]{6}$/.test(suffix)
  ) {
    return { ok: false, code: 'INVALID_PREVIEW', message: 'signingAddressSuffix must be 6 alphanumeric characters' };
  }
  if (lifecycle !== 'PendingRegistration' && lifecycle !== 'Active') {
    return { ok: false, code: 'INVALID_PREVIEW', message: 'lifecycleStatus must be PendingRegistration or Active' };
  }
  if (env !== 1 || suite !== 1 || rec !== 1) {
    return { ok: false, code: 'INVALID_PREVIEW', message: 'preview format versions must match v1' };
  }
  return { ok: true, preview: input as unknown as VaultPreviewV1 };
}
