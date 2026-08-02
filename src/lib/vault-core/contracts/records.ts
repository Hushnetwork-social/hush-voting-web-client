/**
 * FEAT-003 vault-core contracts — four bounded record classes.
 *
 * | Class | Protection | Purpose |
 * |-------|-----------|---------|
 * | Cleartext preview | AAD-authenticated, not authoritative | minimal locked-screen metadata |
 * | Ordinary identity record | encrypted | credential/profile/lifecycle/lock-policy |
 * | Optional mnemonic record | separately keyed, encrypted | recovery material (never opened on ordinary unlock) |
 * | Operational sidecar | non-secret, mutable/untrusted | active-pointer, journal, removal-tombstone, cooldown |
 *
 * No adapter may add unrestricted secret record classes. Root and record schemas are closed;
 * future data lives only in the bounded namespaced `extensions` mechanism.
 *
 * Normative source: FEAT-003 FeatureDescription "Logical Vault Model".
 */

/** Closed record-purpose registry (v1). */
export type RecordPurpose = 'ordinary' | 'mnemonic';

export const RECORD_PURPOSES: readonly RecordPurpose[] = ['ordinary', 'mnemonic'] as const;

/** Lifecycle status stored in the ordinary record and surfaced in the locked preview. */
export type VaultLifecycleStatus = 'PendingRegistration' | 'Active';

export const VAULT_LIFECYCLE_STATUSES: readonly VaultLifecycleStatus[] = [
  'PendingRegistration',
  'Active',
] as const;

/** Unpadded base64url byte string (bounded). */
export type Base64Url = string;

/**
 * One encrypted record slot.
 * The random AES-256-GCM data-encryption key encrypts `ciphertext` with `encryptionNonce`;
 * the purpose-bound KEK wraps that DEK in `keyPackage` with `wrappingNonce`.
 */
export interface EncryptedRecordV1 {
  readonly purpose: RecordPurpose;
  readonly generation: number;
  readonly producerId: string;
  readonly producerVersion: string;
  readonly schemaVersion: number;
  readonly keyPackage: {
    readonly wrappedDataKey: Base64Url;
    readonly wrappingNonce: Base64Url;
  };
  readonly ciphertext: Base64Url;
  readonly encryptionNonce: Base64Url;
}

/** Optional mnemonic slot: present only when the identity retains recovery material. */
export type MnemonicRecordV1 = EncryptedRecordV1 | null;

/** Record schema size/length bounds enforced by schemas and parse-time checks. */
export const RECORD_BOUNDS = {
  /** 512 KiB record bound. */
  maxRecordBytes: 524_288,
  /** 12-byte nonce → 16 base64url chars, unpadded. */
  nonceBase64UrlLength: 16,
  /** 32-byte wrapped DEK → 43 base64url chars minimum (with AES-GCM tag 60 chars total). */
  wrappedDataKeyMinLength: 43,
  wrappedDataKeyMaxLength: 64,
  producerIdMaxLength: 128,
  producerVersionMaxLength: 128,
} as const;

/** Structural invariant: an ordinary record is always required; mnemonic is optional. */
export interface RecordSlotsV1 {
  readonly ordinary: EncryptedRecordV1;
  readonly mnemonic: MnemonicRecordV1;
}
