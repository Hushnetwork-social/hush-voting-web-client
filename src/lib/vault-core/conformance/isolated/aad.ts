/**
 * FEAT-003 isolated conformance — independent AAD assembly.
 *
 * Reconstructs the purpose-bound AAD metadata object from a corpus AAD vector input
 * and canonicalizes it with the isolated JCS. This module is written independently
 * from `../canonical/aad.ts` and must never import it. The corpus pins the exact
 * canonical bytes; the isolated replay proves the bytes independently.
 *
 * Deep-Dive override: vault v1 has NO canonical network identity and NO network-bound
 * AAD. Moving ciphertext between record purposes, vault generations, adapters, or
 * identities must fail authentication.
 */
import { canonicalizeBytes } from './jcs';

/** The serialized AAD vector input shape stored in aad-vectors.json. */
export interface AadVectorInput {
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
  readonly adapterBinding: string;
  readonly preview: {
    readonly alias: string;
    readonly signingAddressPrefix: string;
    readonly signingAddressSuffix: string;
    readonly lifecycleStatus: string;
    readonly envelopeFormatVersion: number;
    readonly parameterSuiteVersion: number;
    readonly recordSchemaVersion: number;
  };
  readonly vaultGeneration: number;
  readonly recordGeneration: number;
  readonly recordPurpose: 'ordinary' | 'mnemonic';
  readonly producerId: string;
  readonly producerVersion: string;
  readonly signingAddress: string;
  readonly criticalExtensions: readonly string[];
}

/**
 * Build the canonical AAD metadata object from vector input. Key order is
 * canonicalized by JCS so insertion order never affects the bytes.
 */
export function buildAadMetadata(input: AadVectorInput): Record<string, unknown> {
  return {
    envelopeFormatVersion: input.envelopeFormatVersion,
    parameterSuiteVersion: input.parameterSuiteVersion,
    recordSchemaVersion: input.recordSchemaVersion,
    platformWrapperVersion: input.platformWrapperVersion,
    suiteId: input.suiteId,
    kdf: {
      algorithm: input.kdfParameters.algorithm,
      memoryKiB: input.kdfParameters.memoryKiB,
      iterations: input.kdfParameters.iterations,
      parallelism: input.kdfParameters.parallelism,
    },
    adapterBinding: input.adapterBinding,
    preview: {
      alias: input.preview.alias,
      signingAddressPrefix: input.preview.signingAddressPrefix,
      signingAddressSuffix: input.preview.signingAddressSuffix,
      lifecycleStatus: input.preview.lifecycleStatus,
      envelopeFormatVersion: input.preview.envelopeFormatVersion,
      parameterSuiteVersion: input.preview.parameterSuiteVersion,
      recordSchemaVersion: input.preview.recordSchemaVersion,
    },
    vaultGeneration: input.vaultGeneration,
    recordGeneration: input.recordGeneration,
    recordPurpose: input.recordPurpose,
    producer: { id: input.producerId, version: input.producerVersion },
    signingAddress: input.signingAddress,
    criticalExtensions: [...input.criticalExtensions].sort(),
  };
}

/** Canonical AAD bytes for one record wrap/encryption. */
export function buildAadBytes(input: AadVectorInput): Uint8Array {
  return canonicalizeBytes(buildAadMetadata(input));
}
