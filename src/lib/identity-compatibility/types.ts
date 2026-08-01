/**
 * FEAT-001 identity compatibility API — public types.
 *
 * Framework-neutral: no React, Next.js, DOM, storage, transport, or state-store
 * dependencies. Expected input failures are typed data with stable
 * machine-readable codes; they never throw and never echo secrets.
 */

/** Stable machine-readable failure codes (match the corpus error-code set). */
export type CompatibilityErrorCode =
  | 'INVALID_WORD_COUNT'
  | 'UNKNOWN_WORD'
  | 'INVALID_CHECKSUM'
  | 'INVALID_MNEMONIC'
  | 'UNSUPPORTED_PRODUCER'
  | 'UNSUPPORTED_VERSION'
  | 'UNSUPPORTED_PASSPHRASE'
  | 'INVALID_KEY_ENCODING'
  | 'INVALID_PRIVATE_SCALAR'
  | 'DAT_INVALID_MAGIC'
  | 'DAT_UNSUPPORTED_VERSION'
  | 'DAT_MALFORMED'
  | 'DAT_WRONG_PASSWORD'
  | 'DAT_MISSING_FIELD'
  | 'DAT_UNKNOWN_FIELD'
  | 'DAT_DUPLICATE_FIELD'
  | 'DAT_INVALID_FIELD'
  | 'DAT_MNEMONIC_KEY_MISMATCH'
  | 'DAT_KEY_MISMATCH'
  | 'SIGNATURE_MALFORMED'
  | 'DERIVATION_FAILURE'
  | 'CANONICAL_MISMATCH';

/** Typed failure. `message` is safe for diagnostics and never contains credentials. */
export interface CompatibilityFailure {
  readonly ok: false;
  readonly code: CompatibilityErrorCode;
  readonly message: string;
}

export type CompatibilityResult<T> = { readonly ok: true; readonly value: T } | CompatibilityFailure;

export type PublicKeyEncoding = 'COMPRESSED' | 'UNCOMPRESSED';

/** Immutable producer identity (from the attested inventory). */
export interface ProducerInfo {
  readonly producerId: string;
  readonly name: string;
  readonly precedence: number;
  readonly mnemonicSupport: '12_AND_24' | '24';
  readonly publicKeyEncoding: PublicKeyEncoding;
}

/**
 * Public candidate descriptor — the ONLY thing derived before selection.
 * Carries no private material. `producerIds` lists every contributing producer
 * ID when identical exact address pairs were deduplicated.
 */
export interface PublicCandidateDescriptor {
  readonly producerId: string;
  readonly producerName: string;
  readonly precedence: number;
  /** All contributing producer IDs (mutable during dedup merge; immutable once returned). */
  producerIds: string[];
  readonly signingAddress: string;
  readonly encryptionAddress: string;
  readonly publicKeyEncoding: PublicKeyEncoding;
}

/** Ordered, deduplicated candidate set produced from one compatibility input. */
export interface DerivedCandidates {
  readonly candidates: PublicCandidateDescriptor[];
  /** Producer IDs whose contract rejected the input (deterministic, not errors). */
  readonly rejectedProducers: ReadonlyArray<{ readonly producerId: string; readonly code: CompatibilityErrorCode }>;
}

/** Caller-supplied controlled registry entry (offline lookup evidence). */
export interface RegistryEntry {
  readonly signingAddress: string;
  readonly encryptionAddress: string;
  readonly profileAlias: string;
}

/** Deterministic lookup outcome; never silently chooses among distinct matches. */
export interface LookupResult {
  readonly matchCount: number;
  readonly ambiguous: boolean;
  readonly matches: ReadonlyArray<{
    readonly registryId: string;
    readonly profileAlias: string;
    readonly producerIds: ReadonlyArray<string>;
  }>;
}

/** Private credential material for ONE selected producer only. */
export interface SelectedCredentials {
  readonly producerId: string;
  readonly producerName: string;
  readonly signingPrivateKey: string;
  readonly encryptionPrivateKey: string;
  readonly signingAddress: string;
  readonly encryptionAddress: string;
  readonly publicKeyEncoding: PublicKeyEncoding;
}

/** Strictly parsed .dat v1 portable credential record. */
export interface PortableCredentialsRecord {
  readonly ProfileName: string;
  readonly PublicSigningAddress: string;
  readonly PrivateSigningKey: string;
  readonly PublicEncryptAddress: string;
  readonly PrivateEncryptKey: string;
  readonly IsPublic: boolean;
  readonly Mnemonic: string | null;
}

/** Result of pure .dat v1 compatibility decoding. */
export interface DatDecodeResult {
  readonly record: PortableCredentialsRecord;
  readonly mnemonicKeyConsistent: boolean;
  readonly privatePublicConsistent: boolean;
}
