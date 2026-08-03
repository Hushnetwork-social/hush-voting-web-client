/**
 * FEAT-006 Android wrapper v1 — canonical authenticated metadata (Phase 2,
 * Task 2.3), TypeScript mirror of `src-tauri/src/android_vault/wrapper.rs`.
 *
 * The Android Keystore wraps only FEAT-003's password-protected package. The
 * outer wrapper's authenticated metadata binds wrapper version, adapter ID
 * `android-keystore`, application ID and release channel, opaque local
 * vault/key reference, FEAT-003 envelope/suite/schema versions, slot, expected
 * vault/package generation, record purpose, and bounded critical extensions.
 * It never binds Android username/account, device model, hostname, server URL,
 * current time, biometric identity, or Hush alias/address into authorization.
 *
 * Canonical bytes are RFC 8785 JCS (`src/lib/vault-core/canonical/jcs.ts`) and
 * must be byte-identical to the Rust side. Bounds: inner envelope 1 MiB,
 * complete wrapper 1.5 MiB, bounded string fields.
 */

import { canonicalizeJsonBytes } from '../vault-core/canonical/jcs';
import { sha256Hex } from '../identity-compatibility/crypto';

/** Release-channel namespace separating production/debug/test/internal. */
export type ReleaseChannel = 'production' | 'debug' | 'test' | 'internal';

export const RELEASE_CHANNELS: readonly ReleaseChannel[] = [
  'production',
  'debug',
  'test',
  'internal',
] as const;

export type Slot = 'a' | 'b';

export const SLOTS: readonly Slot[] = ['a', 'b'] as const;

/** One bounded critical-extension entry (identity-free key/value pair). */
export interface CriticalExtension {
  readonly key: string;
  readonly value: string;
}

/** Authenticated Android wrapper metadata (v1). */
export interface AndroidWrapperMetadataV1 {
  readonly wrapperVersion: number;
  readonly adapterId: string;
  readonly applicationId: string;
  readonly releaseChannel: ReleaseChannel;
  readonly vaultKeyReference: string;
  readonly envelopeFormatVersion: number;
  readonly parameterSuiteVersion: number;
  readonly recordSchemaVersion: number;
  readonly slot: Slot;
  readonly vaultGeneration: number;
  readonly recordPurpose: string;
  readonly criticalExtensions: readonly CriticalExtension[];
}

export const ADAPTER_ID = 'android-keystore';
export const APPLICATION_ID = 'com.hushvoting.client';
export const WRAPPER_FORMAT_VERSION = 1;
export const RECORD_PURPOSE = 'vault-package';
export const INNER_ENVELOPE_MAX_BYTES = 1024 * 1024; // 1 MiB
export const WRAPPER_MAX_BYTES = 1536 * 1024; // 1.5 MiB
export const MAX_FIELD_LEN = 64;
export const MAX_CRITICAL_EXTENSIONS = 8;

/** Tokens that must never appear in authenticated string fields. */
const FORBIDDEN_IDENTITY_TOKENS: readonly string[] = [
  'alias',
  'address',
  'user',
  'account',
  'host',
  'url',
  'time',
  'biometric',
  'identity',
  'model',
  'endpoint',
  'serial',
  'androidid',
  'attestation',
];

/** Identity-free check: no alias/address/user/account/host/URL/time/biometric/
 * identity/model/endpoint/serial/Android ID/attestation token in any field. */
export function isIdentityFree(meta: AndroidWrapperMetadataV1): boolean {
  const values = [
    meta.adapterId,
    meta.applicationId,
    meta.vaultKeyReference,
    meta.recordPurpose,
    ...meta.criticalExtensions.flatMap((e) => [e.key, e.value]),
  ];
  const lower = values.map((v) => v.toLowerCase());
  return !FORBIDDEN_IDENTITY_TOKENS.some((token) => lower.some((v) => v.includes(token)));
}

/** Fixed production vocabulary match. */
export function matchesFixedVocabulary(meta: AndroidWrapperMetadataV1): boolean {
  return (
    meta.wrapperVersion === WRAPPER_FORMAT_VERSION &&
    meta.adapterId === ADAPTER_ID &&
    meta.applicationId === APPLICATION_ID &&
    meta.recordPurpose === RECORD_PURPOSE
  );
}

/** Bounded string fields and critical-extension cardinality. */
export function isBounded(meta: AndroidWrapperMetadataV1): boolean {
  return (
    meta.adapterId.length <= MAX_FIELD_LEN &&
    meta.applicationId.length <= MAX_FIELD_LEN &&
    meta.vaultKeyReference.length <= MAX_FIELD_LEN &&
    meta.recordPurpose.length <= MAX_FIELD_LEN &&
    meta.criticalExtensions.length <= MAX_CRITICAL_EXTENSIONS &&
    meta.criticalExtensions.every((e) => e.key.length <= MAX_FIELD_LEN && e.value.length <= MAX_FIELD_LEN)
  );
}

/** Canonical metadata object (field names/nesting fixed; JCS sorts keys). */
export function metadataObject(meta: AndroidWrapperMetadataV1): Record<string, unknown> {
  return {
    wrapperVersion: meta.wrapperVersion,
    adapterId: meta.adapterId,
    applicationId: meta.applicationId,
    releaseChannel: meta.releaseChannel,
    vaultKeyReference: meta.vaultKeyReference,
    envelopeFormatVersion: meta.envelopeFormatVersion,
    parameterSuiteVersion: meta.parameterSuiteVersion,
    recordSchemaVersion: meta.recordSchemaVersion,
    slot: meta.slot,
    vaultGeneration: meta.vaultGeneration,
    recordPurpose: meta.recordPurpose,
    criticalExtensions: meta.criticalExtensions.map((e) => ({ key: e.key, value: e.value })),
  };
}

/** Canonical AAD bytes (RFC 8785; deterministic across TS and Rust). */
export function canonicalBytes(meta: AndroidWrapperMetadataV1): Uint8Array {
  return canonicalizeJsonBytes(metadataObject(meta));
}

/** SHA-256 hex of the canonical AAD bytes (vector replay identity). */
export function canonicalSha256(meta: AndroidWrapperMetadataV1): string {
  return sha256Hex(canonicalBytes(meta));
}
