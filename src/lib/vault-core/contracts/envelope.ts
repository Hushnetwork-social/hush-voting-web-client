/**
 * FEAT-003 vault-core contracts — logical inner envelope v1.
 *
 * One canonical logical inner envelope shared across browser, Ubuntu, and Android.
 * Browser stores the password-protected package directly; native adapters add an OS-backed
 * wrapper around it. Logical schema consistency does not make the resulting device vault
 * portable. A HUSH `.dat` file remains a separate portable encrypted backup contract and is
 * never treated as a device vault.
 *
 * v1 has NO canonical network identity field and NO network authorization semantics
 * (Deep-Dive override). Endpoint/server context is external application display config.
 *
 * Normative source: FEAT-003 FeatureDescription "Logical Vault Model", "Serialization".
 */
import type { ParameterSuiteV1 } from './suite';
import type { VaultPreviewV1 } from './preview';
import type { EncryptedRecordV1, MnemonicRecordV1 } from './records';
import type { ExtensionContainerV1 } from './extensions';
import type { VaultVersionSet } from './versions';

/** Authenticated generation pair: the active slot plus at most one rollback slot. */
export interface VaultGenerationV1 {
  readonly active: number;
  readonly rollback?: number;
}

/** Record slots carried by the envelope (ordinary always; mnemonic optional). */
export interface VaultRecordsV1 {
  readonly generation: VaultGenerationV1;
  readonly ordinary: EncryptedRecordV1;
  readonly mnemonic: MnemonicRecordV1;
}

/** The canonical logical inner envelope v1. */
export interface VaultEnvelopeV1 {
  readonly envelopeFormatVersion: 1;
  readonly parameterSuiteVersion: 1;
  readonly recordSchemaVersion: 1;
  readonly platformWrapperVersion: 0;
  readonly suite: ParameterSuiteV1;
  readonly preview: VaultPreviewV1;
  readonly records: VaultRecordsV1;
  readonly extensions: ExtensionContainerV1;
  readonly criticalExtensions: readonly string[];
}

/** Version axes in serialized order (canonical key order for AAD). */
export const ENVELOPE_VERSION_FIELDS = [
  'envelopeFormatVersion',
  'parameterSuiteVersion',
  'recordSchemaVersion',
  'platformWrapperVersion',
] as const;

/** Extract the four version axes from an envelope (for compatibility checks). */
export function envelopeVersionSet(envelope: VaultEnvelopeV1): VaultVersionSet {
  return {
    envelopeFormatVersion: envelope.envelopeFormatVersion,
    parameterSuiteVersion: envelope.parameterSuiteVersion,
    recordSchemaVersion: envelope.recordSchemaVersion,
    platformWrapperVersion: envelope.platformWrapperVersion,
  };
}
