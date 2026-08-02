/**
 * FEAT-003 vault-core canonical — purpose-bound AAD assembly.
 *
 * AAD binds at least (v1):
 * - all four version axes;
 * - suite identifier and exact KDF parameters;
 * - adapter/platform binding;
 * - cleartext preview (exact allowlisted fields);
 * - vault generation and record generation;
 * - record purpose;
 * - producer/version and public identity binding where applicable;
 * - critical extension list.
 *
 * Deep-Dive override: vault v1 has NO canonical network identity and NO network-bound AAD.
 * Moving ciphertext between record purposes, vault generations, adapters, or identities
 * must fail authentication.
 *
 * Normative source: FEAT-003 FeatureDescription "AAD binding".
 */
import { canonicalizeJsonBytes } from './jcs';
import type { ParameterSuiteV1 } from '../contracts/suite';
import type { VaultPreviewV1 } from '../contracts/preview';
import type { AdapterBinding } from '../contracts/versions';

/** AAD binding inputs — every field is authenticated. */
export interface AadInputs {
  readonly envelopeFormatVersion: number;
  readonly parameterSuiteVersion: number;
  readonly recordSchemaVersion: number;
  readonly platformWrapperVersion: number;
  readonly suiteId: string;
  readonly kdfParameters: {
    readonly algorithm: string;
    readonly memoryKiB: number;
    readonly iterations: number;
    readonly parallelism: number;
  };
  /** Adapter/platform binding ('logical' for corpus fixtures). */
  readonly adapterBinding: AdapterBinding;
  readonly preview: VaultPreviewV1;
  readonly vaultGeneration: number;
  readonly recordGeneration: number;
  readonly recordPurpose: 'ordinary' | 'mnemonic';
  readonly producerId: string;
  readonly producerVersion: string;
  /** Public signing-address binding (identity binding; no private material). */
  readonly signingAddress: string;
  readonly criticalExtensions: readonly string[];
}

/**
 * Build the canonical AAD metadata object for one record wrap/encryption.
 * No network identity in v1. Key order is canonicalized by JCS, so insertion order
 * never matters for the resulting bytes.
 */
export function buildAadMetadata(inputs: AadInputs): Record<string, unknown> {
  return {
    envelopeFormatVersion: inputs.envelopeFormatVersion,
    parameterSuiteVersion: inputs.parameterSuiteVersion,
    recordSchemaVersion: inputs.recordSchemaVersion,
    platformWrapperVersion: inputs.platformWrapperVersion,
    suiteId: inputs.suiteId,
    kdf: {
      algorithm: inputs.kdfParameters.algorithm,
      memoryKiB: inputs.kdfParameters.memoryKiB,
      iterations: inputs.kdfParameters.iterations,
      parallelism: inputs.kdfParameters.parallelism,
    },
    adapterBinding: inputs.adapterBinding,
    preview: {
      alias: inputs.preview.alias,
      signingAddressPrefix: inputs.preview.signingAddressPrefix,
      signingAddressSuffix: inputs.preview.signingAddressSuffix,
      lifecycleStatus: inputs.preview.lifecycleStatus,
      envelopeFormatVersion: inputs.preview.envelopeFormatVersion,
      parameterSuiteVersion: inputs.preview.parameterSuiteVersion,
      recordSchemaVersion: inputs.preview.recordSchemaVersion,
    },
    vaultGeneration: inputs.vaultGeneration,
    recordGeneration: inputs.recordGeneration,
    recordPurpose: inputs.recordPurpose,
    producer: {
      id: inputs.producerId,
      version: inputs.producerVersion,
    },
    signingAddress: inputs.signingAddress,
    criticalExtensions: [...inputs.criticalExtensions].sort(),
  };
}

/** Canonical AAD bytes (deterministic across TypeScript and Rust). */
export function buildAadBytes(inputs: AadInputs): Uint8Array {
  return canonicalizeJsonBytes(buildAadMetadata(inputs));
}

/** Build AAD inputs for a suite-selected wrap from minimal caller data. */
export function aadInputsFor(
  suite: ParameterSuiteV1,
  params: {
    readonly adapterBinding: AdapterBinding;
    readonly preview: VaultPreviewV1;
    readonly vaultGeneration: number;
    readonly recordGeneration: number;
    readonly recordPurpose: 'ordinary' | 'mnemonic';
    readonly producerId: string;
    readonly producerVersion: string;
    readonly signingAddress: string;
    readonly criticalExtensions: readonly string[];
  },
): AadInputs {
  return {
    envelopeFormatVersion: 1,
    parameterSuiteVersion: suite.kdf.algorithm === 'Argon2id' ? 1 : -1,
    recordSchemaVersion: 1,
    platformWrapperVersion: 0,
    suiteId: suite.id,
    kdfParameters: {
      algorithm: suite.kdf.algorithm,
      memoryKiB: suite.kdf.minMemoryKiB,
      iterations: suite.kdf.iterations,
      parallelism: suite.kdf.parallelism,
    },
    adapterBinding: params.adapterBinding,
    preview: params.preview,
    vaultGeneration: params.vaultGeneration,
    recordGeneration: params.recordGeneration,
    recordPurpose: params.recordPurpose,
    producerId: params.producerId,
    producerVersion: params.producerVersion,
    signingAddress: params.signingAddress,
    criticalExtensions: params.criticalExtensions,
  };
}
