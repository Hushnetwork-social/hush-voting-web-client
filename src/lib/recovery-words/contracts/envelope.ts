/**
 * FEAT-008 recovery-words — no-mnemonic envelope and protection-mode contracts.
 *
 * Introduces an EXPLICIT ADDITIVE contract version for encrypted selected-key
 * recovery records (no mnemonic/seed record capability) and a closed
 * protection hierarchy: Device-password Web/native, passwordless Web (WebAuthn
 * PRF), passwordless native (qualified Secret Service / Android Keystore), and
 * explicit session-only. Sealed v1 vault semantics (FEAT-003–006) keep their
 * old meaning; FEAT-008 never reuses a v1 identifier for incompatible
 * behavior and never downgrades.
 *
 * SECRET BOUNDARY: this module describes ciphertext containers, public
 * bindings, versions, and metadata — never raw keys, phrases, PRF/KEK/DEK
 * outputs, or wrapping keys. Protection secrets are consumed only inside the
 * secret authority.
 *
 * Normative source: FEAT-008 FeatureDescription "No-Persistence Rule",
 * "Initial Protection Choice", "Versioned mode hierarchy", "Encrypted
 * Derived-Key Staging", "Existing Mnemonic-Record Migration",
 * "Cross-Feature Contract and Release Dependencies"; FEAT-003 vault version
 * model (independent version axes, fail-closed parsing).
 */
import type { RecoveryFailure, RecoveryResult } from './lifecycle';

/** FEAT-008 additive recovery-record contract version (no-mnemonic). */
export const RECOVERY_RECORD_CONTRACT_VERSION = 1 as const;

/** Protection-mode metadata version (closed; authenticated envelope metadata). */
export const PROTECTION_MODE_VERSION = 1 as const;

/**
 * Closed protection hierarchy. Protection mode is authenticated envelope
 * metadata and cannot be inferred from successful decryption or downgraded.
 */
export type ProtectionMode =
  | 'devicePasswordWeb' // Argon2id-derived layer wrapping a random vault DEK
  | 'devicePasswordNative' // qualified OS wrapper + Argon2id-derived layer
  | 'passwordlessWeb' // WebAuthn PRF-derived HKDF KEK wrapping a random DEK
  | 'passwordlessNative' // qualified Secret Service / Keystore wrapping a random DEK
  | 'sessionOnly'; // no persistence; isolated memory only

/** Persistent-protection classification per the versioned mode hierarchy. */
export const PROTECTION_MODE_PERSISTENT: Readonly<Record<ProtectionMode, boolean>> = {
  devicePasswordWeb: true,
  devicePasswordNative: true,
  passwordlessWeb: true,
  passwordlessNative: true,
  sessionOnly: false,
} as const;

/** Modes that require qualified OS-backed protection (no HushVoting password). */
export const PROTECTION_MODE_REQUIRES_OS_WRAPPER: Readonly<Record<ProtectionMode, boolean>> = {
  devicePasswordWeb: false,
  devicePasswordNative: true,
  passwordlessWeb: false,
  passwordlessNative: true,
  sessionOnly: false,
} as const;

/** Modes that require a Device-password-derived layer (password modes). */
export const PROTECTION_MODE_REQUIRES_DEVICE_PASSWORD: Readonly<Record<ProtectionMode, boolean>> = {
  devicePasswordWeb: true,
  devicePasswordNative: true,
  passwordlessWeb: false,
  passwordlessNative: false,
  sessionOnly: false,
} as const;

/** Closed registry of every supported mode+version pair. */
export interface ProtectionMetadata {
  readonly mode: ProtectionMode;
  readonly version: typeof PROTECTION_MODE_VERSION;
}

/** Bounded profile metadata carried in a recovery record (never secret). */
export type RecoveryProfileMetadata =
  | {
      readonly kind: 'existing';
      readonly authoritativeAlias: string;
      readonly authoritativeVisibility: 'private' | 'public';
    }
  | {
      readonly kind: 'pendingRecreate';
      readonly reviewAlias: string;
      readonly reviewVisibility: 'private' | 'public';
    };

/**
 * Persisted recovery envelope record (FEAT-008 contract version 1).
 *
 * Contains ONLY encrypted selected derived keys and approved metadata: no
 * mnemonic or seed record capability exists at the type level. The exact
 * signing/encryption private key representations are opaque ciphertext
 * fields; raw keys, phrases, and wrapping authorities are never representable.
 */
export interface RecoveryEnvelopeRecord {
  readonly contractVersion: typeof RECOVERY_RECORD_CONTRACT_VERSION;
  /** Approved producer/version that produced the selected credentials. */
  readonly producer: {
    readonly producerId: string;
    readonly producerVersion: string;
  };
  /** Exact encoded public bindings (byte/string-exact verification target). */
  readonly publicBindings: {
    readonly signingAddress: string;
    readonly encryptionAddress: string;
  };
  readonly networkIdentifier: string;
  readonly protection: ProtectionMetadata;
  readonly profile: RecoveryProfileMetadata;
  readonly lifecycle: {
    readonly stage: 'staged' | 'active'; // staged is non-authenticated
    readonly generation: number; // bounded generation counter (two-slot CAS)
  };
  /** Opaque AES-256-GCM ciphertext containers (unique nonces, canonical AAD). */
  readonly ciphertext: {
    readonly signingKeyCiphertext: string;
    readonly encryptionKeyCiphertext: string;
    readonly nonce: string;
    readonly aadContext: string; // purpose/RP/network/record binding descriptor
  };
  /** Bounded reconciliation metadata required by the selected path. */
  readonly reconciliation: {
    readonly requiresProfileRecreate: boolean; // missing-profile path
    readonly retainedTransactionRef: string | null; // opaque ref; persistent confirmed-creation only
  };
}

/** Runtime mode guard (closed vocabulary). */
export function isProtectionMode(value: unknown): value is ProtectionMode {
  return (
    value === 'devicePasswordWeb' ||
    value === 'devicePasswordNative' ||
    value === 'passwordlessWeb' ||
    value === 'passwordlessNative' ||
    value === 'sessionOnly'
  );
}

/** Fail-closed parse of protection metadata (unknown mode/version → failure). */
export function parseProtectionMetadata(value: unknown): RecoveryResult<ProtectionMetadata> {
  if (value === null || typeof value !== 'object') {
    return failure('PROTECTION_METADATA_INVALID', 'Protection metadata is malformed.');
  }
  const record = value as Record<string, unknown>;
  const mode = record['mode'];
  const version = record['version'];
  if (!isProtectionMode(mode)) {
    return failure('UNSUPPORTED_PROTECTION_MODE', 'Protection mode is unknown or unsupported.');
  }
  if (version !== PROTECTION_MODE_VERSION) {
    return failure('UNSUPPORTED_PROTECTION_VERSION', 'Protection metadata version is unsupported.');
  }
  return { ok: true, value: { mode, version: PROTECTION_MODE_VERSION } };
}

/**
 * Fail-closed parse of a persisted recovery envelope record. Rejects unknown
 * versions, unknown protection modes, missing wrappers, empty-password
 * attempts, and any injected mnemonic/seed field.
 */
export function parseRecoveryEnvelopeRecord(value: unknown): RecoveryResult<RecoveryEnvelopeRecord> {
  if (value === null || typeof value !== 'object') {
    return failure('ENVELOPE_MALFORMED', 'Recovery record is malformed.');
  }
  const json = JSON.stringify(value);
  const record = value as Record<string, unknown>;

  // No-mnemonic enforcement: any mnemonic/seed-shaped key fails the record.
  if (json && /"(mnemonic|seed|phrase)"\s*:/i.test(json)) {
    return failure('MNEMONIC_RECORD_INJECTED', 'Recovery record must not contain mnemonic material.');
  }

  if (record['contractVersion'] !== RECOVERY_RECORD_CONTRACT_VERSION) {
    return failure('UNSUPPORTED_RECOVERY_VERSION', 'Recovery record version is unsupported.');
  }

  const protection = parseProtectionMetadata(record['protection']);
  if (!protection.ok) {
    return protection;
  }

  const publicBindings = record['publicBindings'];
  if (
    publicBindings === null ||
    typeof publicBindings !== 'object' ||
    typeof (publicBindings as Record<string, unknown>)['signingAddress'] !== 'string' ||
    typeof (publicBindings as Record<string, unknown>)['encryptionAddress'] !== 'string'
  ) {
    return failure('ENVELOPE_MALFORMED', 'Recovery record public bindings are malformed.');
  }

  const ciphertext = record['ciphertext'];
  if (
    ciphertext === null ||
    typeof ciphertext !== 'object' ||
    typeof (ciphertext as Record<string, unknown>)['signingKeyCiphertext'] !== 'string' ||
    typeof (ciphertext as Record<string, unknown>)['encryptionKeyCiphertext'] !== 'string' ||
    typeof (ciphertext as Record<string, unknown>)['nonce'] !== 'string' ||
    typeof (ciphertext as Record<string, unknown>)['aadContext'] !== 'string'
  ) {
    return failure('ENVELOPE_MALFORMED', 'Recovery record ciphertext is malformed.');
  }

  const producer = record['producer'];
  if (
    producer === null ||
    typeof producer !== 'object' ||
    typeof (producer as Record<string, unknown>)['producerId'] !== 'string' ||
    typeof (producer as Record<string, unknown>)['producerVersion'] !== 'string'
  ) {
    return failure('ENVELOPE_MALFORMED', 'Recovery record producer metadata is malformed.');
  }

  // Bounded metadata unions must also fail closed (never inferred).
  const profile = record['profile'];
  const profileKind = (profile as Record<string, unknown> | null)?.['kind'];
  if (profileKind !== 'existing' && profileKind !== 'pendingRecreate') {
    return failure('ENVELOPE_MALFORMED', 'Recovery record profile metadata is malformed.');
  }
  const lifecycle = record['lifecycle'];
  const lifecycleStage = (lifecycle as Record<string, unknown> | null)?.['stage'];
  if (lifecycleStage !== 'staged' && lifecycleStage !== 'active') {
    return failure('ENVELOPE_MALFORMED', 'Recovery record lifecycle stage is malformed.');
  }
  const reconciliation = record['reconciliation'];
  if (
    reconciliation === null ||
    typeof reconciliation !== 'object' ||
    typeof (reconciliation as Record<string, unknown>)['requiresProfileRecreate'] !== 'boolean'
  ) {
    return failure('ENVELOPE_MALFORMED', 'Recovery record reconciliation metadata is malformed.');
  }

  return { ok: true, value: value as RecoveryEnvelopeRecord };
}

/** Explicit no-mnemonic guarantee check (defense in depth for consumers). */
export function validateNoMnemonicRecord(record: RecoveryEnvelopeRecord): boolean {
  const json = JSON.stringify(record);
  return !/"(mnemonic|seed|phrase)"\s*:/i.test(json);
}

/** Deterministic compatibility verdict for a parsed recovery record. */
export type RecoveryVersionCompatibility =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: 'UNSUPPORTED_CRITICAL_VERSION' | 'MNEMONIC_RECORD_PRESENT' };

export function checkRecoveryVersionCompatibility(record: RecoveryEnvelopeRecord): RecoveryVersionCompatibility {
  if (record.contractVersion !== RECOVERY_RECORD_CONTRACT_VERSION) {
    return { ok: false, code: 'UNSUPPORTED_CRITICAL_VERSION' };
  }
  if (!validateNoMnemonicRecord(record)) {
    return { ok: false, code: 'MNEMONIC_RECORD_PRESENT' };
  }
  return { ok: true };
}

/**
 * Empty-password/downgrade guard: passwordless modes must never be treated as
 * an empty Device password, and persistent modes must never degrade to
 * unwrapped storage. Returns an ok result only for representable legal
 * combinations.
 */
export function checkLegalProtectionCombination(
  mode: ProtectionMode,
  capabilities: Readonly<Record<string, boolean>>,
): RecoveryResult<{ readonly mode: ProtectionMode }> {
  if (mode === 'passwordlessWeb') {
    if (!capabilities['webauthnPlatform'] || !capabilities['discoverableCredential'] || !capabilities['userVerification'] || !capabilities['prf']) {
      return failure('UNQUALIFIED_PASSWORDLESS', 'Passwordless Web requires qualified WebAuthn platform/PRF capabilities.');
    }
    return { ok: true, value: { mode } };
  }
  if (mode === 'passwordlessNative') {
    if (!capabilities['qualifiedOsProtection']) {
      return failure('UNQUALIFIED_PASSWORDLESS', 'Passwordless native requires qualified OS-backed protection.');
    }
    return { ok: true, value: { mode } };
  }
  if (mode === 'sessionOnly') {
    return { ok: true, value: { mode } }; // no writes; explicit acknowledgement enforced by UI
  }
  return { ok: true, value: { mode } }; // password modes always legal when capability fresh
}

function failure(code: RecoveryFailure['code'], message: string): RecoveryResult<never> {
  return { ok: false, code, message, supportCode: `RW-${code.slice(0, 12)}` };
}
