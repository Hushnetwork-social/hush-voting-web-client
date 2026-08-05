/**
 * FEAT-001 identity compatibility API — producer registry and adapters.
 *
 * Producer IDs, classifications, precedence, and contracts are frozen by the
 * attested inventory (`conformance/identity/v1/inventory.json` and
 * `producers/*.json`). Adapters wrap the historical algorithms exactly; legacy
 * producer defaults are never rewritten.
 */
import { mnemonicToSeed, hkdfSha256, derivePublicKey, isUsableScalar, bytesToHexLower } from './crypto';
import type { ProducerInfo, PublicKeyEncoding, CompatibilityResult, CompatibilityFailure } from './types';

export interface DerivedProducerKeys {
  readonly signingPrivateKey: string;
  readonly encryptionPrivateKey: string;
  readonly signingAddress: string;
  readonly encryptionAddress: string;
  readonly publicKeyEncoding: PublicKeyEncoding;
}

const failure = (code: CompatibilityFailure['code'], message: string): CompatibilityFailure => ({ ok: false, code, message });

/** Approved derivation producers in frozen precedence order (attestation record §7). */
export const APPROVED_DERIVATION_PRODUCERS: readonly ProducerInfo[] = [
  {
    producerId: 'P-01',
    name: 'Hush Feeds Web Client (TypeScript)',
    precedence: 1,
    mnemonicSupport: '12_AND_24',
    publicKeyEncoding: 'COMPRESSED',
  },
  {
    producerId: 'P-02',
    name: 'Olimpo.KeyDerivation (.NET)',
    precedence: 2,
    mnemonicSupport: '24',
    publicKeyEncoding: 'UNCOMPRESSED',
  },
  {
    producerId: 'P-03',
    name: 'Hush Desktop Client (Avalonia, historical HushClient)',
    precedence: 5,
    mnemonicSupport: '24',
    publicKeyEncoding: 'UNCOMPRESSED',
  },
];

export function getProducer(producerId: string): ProducerInfo | undefined {
  return APPROVED_DERIVATION_PRODUCERS.find((p) => p.producerId === producerId);
}

/** Normalize per the .NET contract: lowercase; split on space/tab/newline/CR; single spaces. */
export function normalizeMnemonicOlimpo(mnemonic: string): string {
  return mnemonic
    .toLowerCase()
    .split(/[ \t\n\r]+/)
    .filter((w) => w.length > 0)
    .join(' ');
}

/** How the .NET producer's BIP-39 validation behaves (24 words, wordlist, checksum). */
export function countWords(mnemonic: string): number {
  if (mnemonic.trim().length === 0) return 0;
  return mnemonic.trim().split(/[ \t\n\r]+/).length;
}

/**
 * Contract C-A (P-01): BIP-39 seed; HKDF-SHA256 info "signing"/"encryption";
 * 32-byte output used directly as the private scalar; compressed public keys.
 * No retry on invalid scalar (documented producer behavior).
 */
export function deriveP01Keys(mnemonic: string): CompatibilityResult<DerivedProducerKeys> {
  const seed = mnemonicToSeed(mnemonic);
  const signingPrivateKey = bytesToHexString(hkdfSha256(seed, 'signing'));
  const encryptionPrivateKey = bytesToHexString(hkdfSha256(seed, 'encryption'));
  if (!isUsableScalar(signingPrivateKey) || !isUsableScalar(encryptionPrivateKey)) {
    return failure('DERIVATION_FAILURE', 'P-01 derived an unusable scalar');
  }
  return {
    ok: true,
    value: {
      signingPrivateKey,
      encryptionPrivateKey,
      signingAddress: derivePublicKey(signingPrivateKey, 'COMPRESSED'),
      encryptionAddress: derivePublicKey(encryptionPrivateKey, 'COMPRESSED'),
      publicKeyEncoding: 'COMPRESSED',
    },
  };
}

/**
 * Contract C-B (P-02): same BIP-39 seed; HKDF-SHA256 info
 * "hush/signing/secp256k1/v1" / "hush/encrypt/secp256k1/v1"; invalid-scalar
 * retry with "{info}/{attempt}"; uncompressed public keys.
 */
export function deriveP02Keys(mnemonic: string): CompatibilityResult<DerivedProducerKeys> {
  const normalized = normalizeMnemonicOlimpo(mnemonic);
  const seed = mnemonicToSeed(normalized);
  const deriveWithRetry = (info: string): string => {
    let attempt = 0;
    let keyMaterial = hkdfSha256(seed, info);
    while (!isUsableScalar(bytesToHexString(keyMaterial))) {
      attempt += 1;
      keyMaterial = hkdfSha256(seed, `${info}/${attempt}`);
    }
    return bytesToHexString(keyMaterial);
  };
  const signingPrivateKey = deriveWithRetry('hush/signing/secp256k1/v1');
  const encryptionPrivateKey = deriveWithRetry('hush/encrypt/secp256k1/v1');
  return {
    ok: true,
    value: {
      signingPrivateKey,
      encryptionPrivateKey,
      signingAddress: derivePublicKey(signingPrivateKey, 'UNCOMPRESSED'),
      encryptionAddress: derivePublicKey(encryptionPrivateKey, 'UNCOMPRESSED'),
      publicKeyEncoding: 'UNCOMPRESSED',
    },
  };
}

/**
 * Derive keys for a producer. P-03 wraps the Olimpo path (identical contract
 * to P-02; candidates deduplicate while retaining both producer IDs).
 */
export function deriveProducerKeys(producerId: string, mnemonic: string): CompatibilityResult<DerivedProducerKeys> {
  if (producerId === 'P-01') return deriveP01Keys(mnemonic);
  if (producerId === 'P-02' || producerId === 'P-03') return deriveP02Keys(mnemonic);
  return failure('UNSUPPORTED_PRODUCER', `producer ${producerId} has no derivation adapter`);
}

function bytesToHexString(bytes: Uint8Array): string {
  return bytesToHexLower(bytes);
}
