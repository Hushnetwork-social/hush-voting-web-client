/**
 * FEAT-003 vault-core contracts — closed parameter suite v1.
 *
 * Suite policy is closed: callers and envelopes cannot select arbitrary algorithm names.
 * A new KDF, cipher, label scheme, or parameter policy requires a new parameter-suite
 * version, security review, migration path, and conformance vectors.
 *
 * Normative source: FEAT-003 FeatureDescription "Cryptographic Suite".
 */

/** Exact v1 suite construction (mirrors conformance/vault/v1/schemas/suite.schema.json). */
export interface ParameterSuiteV1 {
  readonly id: 'hush/vault/suite/v1';
  readonly kdf: {
    readonly algorithm: 'Argon2id';
    /** 19 MiB. */
    readonly minMemoryKiB: 19456;
    readonly iterations: 2;
    readonly parallelism: 1;
    readonly saltBytesMin: 16;
    readonly outputBytes: 32;
    readonly calibrationTargetMs: 750;
    readonly calibrationWindowMsMin: 500;
    readonly calibrationWindowMsMax: 1000;
    readonly hardTimeoutMs: 1500;
    /** Provisional 64 MiB browser/Android cap. */
    readonly browserMemoryCapKiB: 65536;
    /** Provisional 256 MiB Ubuntu cap. */
    readonly ubuntuMemoryCapKiB: 262144;
  };
  readonly hkdf: {
    readonly algorithm: 'HKDF-SHA-256';
    readonly hash: 'SHA-256';
    readonly outputBytes: 32;
    /** Exact versioned ASCII labels — never reinterpreted or localized. */
    readonly labels: ['hush/vault/v1/credential-kek', 'hush/vault/v1/mnemonic-kek'];
  };
  readonly cipher: {
    readonly algorithm: 'AES-256-GCM';
    readonly keyBytes: 32;
    readonly nonceBytes: 12;
  };
  readonly limits: {
    readonly maxEnvelopeBytes: 1048576;
    readonly maxMetadataBytes: 65536;
    readonly maxRecordBytes: 524288;
    readonly maxExtensionDepth: 4;
    readonly maxCollections: 64;
    readonly maxNestingDepth: 16;
  };
}

/** The immutable v1 parameter suite. */
export const PARAMETER_SUITE_V1: ParameterSuiteV1 = {
  id: 'hush/vault/suite/v1',
  kdf: {
    algorithm: 'Argon2id',
    minMemoryKiB: 19456,
    iterations: 2,
    parallelism: 1,
    saltBytesMin: 16,
    outputBytes: 32,
    calibrationTargetMs: 750,
    calibrationWindowMsMin: 500,
    calibrationWindowMsMax: 1000,
    hardTimeoutMs: 1500,
    browserMemoryCapKiB: 65536,
    ubuntuMemoryCapKiB: 262144,
  },
  hkdf: {
    algorithm: 'HKDF-SHA-256',
    hash: 'SHA-256',
    outputBytes: 32,
    labels: ['hush/vault/v1/credential-kek', 'hush/vault/v1/mnemonic-kek'],
  },
  cipher: { algorithm: 'AES-256-GCM', keyBytes: 32, nonceBytes: 12 },
  limits: {
    maxEnvelopeBytes: 1048576,
    maxMetadataBytes: 65536,
    maxRecordBytes: 524288,
    maxExtensionDepth: 4,
    maxCollections: 64,
    maxNestingDepth: 16,
  },
} as const;

/** Closed registry keyed by parameter-suite version. */
export const PARAMETER_SUITE_REGISTRY: Readonly<Record<1, ParameterSuiteV1>> = {
  1: PARAMETER_SUITE_V1,
} as const;

/** HKDF purpose labels (exact ASCII, versioned). */
export const HKDF_LABEL_CREDENTIAL_KEK = 'hush/vault/v1/credential-kek' as const;
export const HKDF_LABEL_MNEMONIC_KEK = 'hush/vault/v1/mnemonic-kek' as const;
