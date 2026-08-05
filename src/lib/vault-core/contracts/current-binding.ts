/**
 * FEAT-010 additive vault contracts — current concrete-key-only network-bound
 * record binding (Task 2.3).
 *
 * Additive on top of the sealed FEAT-003 record model:
 * - a current record carries an explicit canonical network/configuration
 *   binding (authenticated metadata; never inferred from hostname, profile,
 *   server reply, or user input);
 * - a current record is concrete-key-only: NO mnemonic/seed/phrase/recovery
 *   field or extension exists; any mnemonic-shaped content injected into a
 *   current record fails parsing before authentication or migration;
 * - network mismatch fails before unlock/lookup/recreation (AC-010-021,
 *   AC-010-043).
 *
 * This module defines the SHAPE and VALIDATION only; the encrypted record
 * writer/reader lives in Phase 3 with the sealed journal/CAS machinery.
 *
 * Framework-neutral, secret-free (only safe public binding fields).
 */
import type { DeploymentManifest } from '../../runtime/deployment';

/** Current-record schema version (additive axis; sealed v1 meanings untouched). */
export const CURRENT_RECORD_SCHEMA_VERSION = 1 as const;

/** Protection-mode classes valid on current records (closed registry). */
export type CurrentProtectionModeClass =
  | 'device-password'
  | 'webauthn-prf'
  | 'ubuntu-secret-service'
  | 'android-keystore';

export const CURRENT_PROTECTION_MODE_CLASSES: readonly CurrentProtectionModeClass[] = [
  'device-password',
  'webauthn-prf',
  'ubuntu-secret-service',
  'android-keystore',
] as const;

/**
 * Authenticated network binding of a current vault record. Stored INSIDE the
 * encrypted record (generation-CAS authenticated), never in the untrusted
 * sidecar. A mismatch with the active deployment manifest fails closed.
 */
export interface CurrentNetworkBinding {
  /** Canonical network identifier (matches DeploymentManifest.canonicalNetworkId). */
  readonly canonicalNetworkId: string;
  /** Network magic (matches DeploymentManifest.networkMagic). */
  readonly networkMagic: number;
  /** Deployment configuration the record was provisioned under. */
  readonly configurationId: string;
}

/** Safe public identity bindings carried by a current record (no secrets). */
export interface CurrentKeyBinding {
  /** Concrete signing public address (no mnemonic/seed material). */
  readonly signingAddress: string;
  /** Concrete encryption public address. */
  readonly encryptionAddress: string;
}

/** The additive current record contract (schema v1). */
export interface CurrentVaultRecordV1 {
  readonly schemaVersion: 1;
  readonly networkBinding: CurrentNetworkBinding;
  readonly keyBinding: CurrentKeyBinding;
  readonly protectionModeClass: CurrentProtectionModeClass;
  /** Monotonic generation of this encrypted record slot. */
  readonly generation: number;
}

/** Closed shape-validation diagnostics. */
export type CurrentRecordDiagnostic =
  | { readonly code: 'UNSUPPORTED_SCHEMA_VERSION' }
  | { readonly code: 'MNEMONIC_SHAPE_PRESENT' }
  | { readonly code: 'INVALID_NETWORK_BINDING' }
  | { readonly code: 'INVALID_KEY_BINDING' }
  | { readonly code: 'INVALID_PROTECTION_MODE' }
  | { readonly code: 'INVALID_GENERATION' };

export interface CurrentRecordValidation {
  readonly ok: boolean;
  readonly diagnostics: readonly CurrentRecordDiagnostic[];
}

/** Mnemonic-shaped content markers that current records must never contain. */
const MNEMONIC_MARKERS = ['mnemonic', 'seedPhrase', 'recoveryWords', 'seed', 'bip39', 'phrase'] as const;

const ADDRESS_PATTERN = /^[A-Za-z0-9]{40,64}$/;

function hasMnemonicShape(value: unknown): boolean {
  if (value === null || typeof value !== 'object') return false;
  const record = value as Record<string, unknown>;
  if (MNEMONIC_MARKERS.some((marker) => Object.prototype.hasOwnProperty.call(record, marker))) {
    return true;
  }
  // Nested extensions must also be mnemonic-free (no recovery extension).
  if (record.extensions !== null && typeof record.extensions === 'object') {
    const extensions = record.extensions as Record<string, unknown>;
    return MNEMONIC_MARKERS.some((marker) => Object.prototype.hasOwnProperty.call(extensions, marker));
  }
  return false;
}

function isValidBinding(value: unknown): value is CurrentNetworkBinding {
  if (value === null || typeof value !== 'object') return false;
  const binding = value as Record<string, unknown>;
  return (
    typeof binding.canonicalNetworkId === 'string' &&
    binding.canonicalNetworkId.length > 0 &&
    typeof binding.networkMagic === 'number' &&
    Number.isSafeInteger(binding.networkMagic) &&
    binding.networkMagic > 0 &&
    typeof binding.configurationId === 'string' &&
    binding.configurationId.length > 0
  );
}

function isValidKeyBinding(value: unknown): value is CurrentKeyBinding {
  if (value === null || typeof value !== 'object') return false;
  const binding = value as Record<string, unknown>;
  return (
    typeof binding.signingAddress === 'string' &&
    ADDRESS_PATTERN.test(binding.signingAddress) &&
    typeof binding.encryptionAddress === 'string' &&
    ADDRESS_PATTERN.test(binding.encryptionAddress)
  );
}

/**
 * Validate an untrusted current-record payload. Rules:
 * - exact schema version 1 (newer/unknown versions fail closed);
 * - NO mnemonic/seed/phrase/recovery-shaped field may exist (AC-010-080);
 * - network binding, key binding, protection mode, and generation must be
 *   structurally valid;
 * - a mnemonic-shaped payload is rejected BEFORE any migration or
 *   authentication capability is issued.
 */
export function validateCurrentRecord(payload: unknown): CurrentRecordValidation {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    return { ok: false, diagnostics: [{ code: 'INVALID_KEY_BINDING' }] };
  }
  const record = payload as Record<string, unknown>;
  const diagnostics: CurrentRecordDiagnostic[] = [];

  if (record.schemaVersion !== CURRENT_RECORD_SCHEMA_VERSION) {
    diagnostics.push({ code: 'UNSUPPORTED_SCHEMA_VERSION' });
  }
  if (hasMnemonicShape(record)) {
    diagnostics.push({ code: 'MNEMONIC_SHAPE_PRESENT' });
  }
  if (!isValidBinding(record.networkBinding)) {
    diagnostics.push({ code: 'INVALID_NETWORK_BINDING' });
  }
  if (!isValidKeyBinding(record.keyBinding)) {
    diagnostics.push({ code: 'INVALID_KEY_BINDING' });
  }
  if (!CURRENT_PROTECTION_MODE_CLASSES.includes(record.protectionModeClass as CurrentProtectionModeClass)) {
    diagnostics.push({ code: 'INVALID_PROTECTION_MODE' });
  }
  if (typeof record.generation !== 'number' || !Number.isSafeInteger(record.generation) || record.generation < 0) {
    diagnostics.push({ code: 'INVALID_GENERATION' });
  }

  if (diagnostics.length > 0) {
    return { ok: false, diagnostics };
  }
  return { ok: true, diagnostics: [] };
}

/** Network-mismatch verdict between a validated current record and the active manifest. */
export type NetworkBindingVerdict =
  | { readonly kind: 'bound' }
  | { readonly kind: 'mismatch' };

/**
 * Authenticate the record's network binding against the active deployment
 * manifest. Any difference in canonical network id, magic, or configuration
 * fails before unlock/lookup/recreation (AC-010-021/043). Never treat absence
 * on a different network as a blockchain reset.
 */
export function checkNetworkBinding(record: CurrentVaultRecordV1, manifest: DeploymentManifest): NetworkBindingVerdict {
  if (
    record.networkBinding.canonicalNetworkId === manifest.canonicalNetworkId &&
    record.networkBinding.networkMagic === manifest.networkMagic &&
    record.networkBinding.configurationId === manifest.configurationId
  ) {
    return { kind: 'bound' };
  }
  return { kind: 'mismatch' };
}
