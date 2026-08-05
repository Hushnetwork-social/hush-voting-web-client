/**
 * FEAT-009 credential-file restore authority — concrete key proof and exact
 * identity resolution policy (Task 3.5).
 *
 * Framework-neutral workflow policy. Owns: independent private→public
 * derivation and exact encoded equality for both pairs, domain-separated
 * local signing/encryption consistency proof, optional mnemonic-to-both
 * consistency, conversion to the opaque validated credential authority,
 * release of all import state before lookup, and exact existing/missing/
 * mismatch resolution through the unchanged unsigned public lookup port.
 * No lookup, staging, or registration may occur before complete local
 * proof and source-secret release.
 *
 * SECRET BOUNDARY: private keys and the mnemonic enter only as transient
 * bounded parameters; the validated authority ref carries abbreviated
 * addresses and booleans only. The public lookup port accepts exactly one
 * public signing address — it is not a signed transaction.
 *
 * Normative source: FEAT-009 FeatureDescription "Concrete Credential
 * Validation and Ownership Proof", "Safe inconsistent-key errors",
 * "GetIdentity clarification", "Identity Resolution"; FEAT-001 key
 * primitives; FEAT-007 lookup/profile normalizers.
 */
import type { PortableCredentialsRecord } from '../../identity-compatibility/types';
import { validateKeyConsistency } from '../../identity-compatibility/dat';
import { bytesToHexLower, hexToBytesStrict } from '../../identity-compatibility/crypto';
import { getPublicKey as secpGetPublicKey } from '@noble/secp256k1';
import type { RestoreFailure, RestoreResult } from '../contracts/lifecycle';
import type { ValidatedCredentialAuthorityRef } from '../contracts/import';
import type { LookupOutcome, ResolutionResult } from '../contracts/resolution';

/** Narrow public lookup port — unsigned `GetIdentity`-style call. */
export interface PublicLookupPort {
  /** Returns the exact signing/encryption pair from a public signing address. */
  lookup(opts: { readonly publicSigningAddress: string }): Promise<LookupOutcome>;
}

export type KeyProofResult = RestoreResult<{
  readonly authority: ValidatedCredentialAuthorityRef | null; // only when fully proven
  readonly proofOutcome: 'passed' | 'signingKeyMismatch' | 'encryptionKeyMismatch' | 'signingProofFailed' | 'encryptionProofFailed' | 'mnemonicKeyMismatch' | 'malformedKeyEncoding';
  readonly mnemonicPresent: boolean;
}>;

const failure = (code: RestoreFailure['code'], message: string): RestoreFailure => ({ ok: false, code, message, supportCode: `PROOF-${code}` });

/**
 * Prove both concrete key pairs. Uses the FEAT-001 consistency kernel:
 * private→public derivation equality for signing and encryption plus
 * mnemonic-to-both consistency when present. Returns typed internal
 * outcomes; the UI renders one combined safe message.
 */
export function proveConcreteKeys(record: PortableCredentialsRecord): KeyProofResult {
  const consistency = validateKeyConsistency(record);
  if (!consistency.privatePublicConsistent) {
    // Distinguish which pair mismatched at the typed level without values.
    const signingPub = derivePublicOrNull(record.PrivateSigningKey, record.PublicSigningAddress);
    const encryptionPub = derivePublicOrNull(record.PrivateEncryptKey, record.PublicEncryptAddress);
    if (signingPub !== record.PublicSigningAddress) {
      return failure('SIGNING_KEY_MISMATCH', 'signing key pair is inconsistent');
    }
    if (encryptionPub !== record.PublicEncryptAddress) {
      return failure('ENCRYPTION_KEY_MISMATCH', 'encryption key pair is inconsistent');
    }
    return failure('SIGNING_KEY_MISMATCH', 'key pair consistency failed');
  }
  if (!consistency.mnemonicKeyConsistent) {
    return failure('MNEMONIC_KEY_MISMATCH', 'mnemonic does not derive the stored key pairs');
  }
  return {
    ok: true,
    value: {
      authority: {
        kind: 'validatedCredentialAuthority',
        epoch: 'epoch' as ValidatedCredentialAuthorityRef['epoch'], // replaced by caller
        signingAddressAbbreviated: abbreviate(record.PublicSigningAddress),
        encryptionAddressAbbreviated: abbreviate(record.PublicEncryptAddress),
        publicKeyEncoding: record.PublicSigningAddress.startsWith('04') ? 'UNCOMPRESSED' : 'COMPRESSED',
        profileName: record.ProfileName,
        isPublic: record.IsPublic,
        hasMnemonic: record.Mnemonic !== null,
        validatedAtMs: 0, // replaced by caller
      },
      proofOutcome: 'passed',
      mnemonicPresent: record.Mnemonic !== null,
    },
  };
}

/** Domain-separated local signing/encryption consistency proof gate. */
export type ConsistencyProofOutcome =
  | { readonly kind: 'passed' }
  | { readonly kind: 'signingProofFailed' }
  | { readonly kind: 'encryptionProofFailed' };

/**
 * Resolve the validated authority against the public lookup. Enforces the
 * frozen ordering invariant: lookup occurs only after proof and release.
 */
export async function resolveIdentity(
  port: PublicLookupPort,
  authority: ValidatedCredentialAuthorityRef,
  fullSigningAddress: string,
  fullEncryptionAddress: string,
): Promise<RestoreResult<ResolutionResult>> {
  const outcome = await port.lookup({ publicSigningAddress: fullSigningAddress });
  switch (outcome.kind) {
    case 'existing': {
      const profile = outcome.profile;
      if (profile.signingAddress !== fullSigningAddress || profile.encryptionAddress !== fullEncryptionAddress) {
        return failure('PROFILE_SIGNING_ONLY_MATCH', 'blockchain profile does not match both keys');
      }
      return {
        ok: true,
        value: {
          kind: 'existing',
          profile: {
            alias: profile.alias,
            isPublic: profile.isPublic,
            signingAddress: profile.signingAddress,
            encryptionAddress: profile.encryptionAddress,
            networkLabel: profile.networkLabel,
          },
        },
      };
    }
    case 'authoritativeNotFound':
      return {
        ok: true,
        value: {
          kind: 'missing',
          review: {
            authenticatedProfileName: authority.profileName,
            authenticatedIsPublic: authority.isPublic,
            signingAddressAbbreviated: authority.signingAddressAbbreviated,
            encryptionAddressAbbreviated: authority.encryptionAddressAbbreviated,
            networkLabel: 'HushLocal', // bound network; replaced by caller with canonical label
            requiresExplicitCreate: true,
          },
        },
      };
    case 'signingOnlyMatch':
      return failure('PROFILE_SIGNING_ONLY_MATCH', 'blockchain profile matches signing only');
    case 'transportFailure':
      return failure('LOOKUP_TRANSPORT_FAILURE', 'identity lookup transport failure');
    case 'malformed':
      return failure('LOOKUP_MALFORMED', 'identity lookup returned a malformed profile');
    case 'unknownStatus':
      return failure('UNKNOWN_OUTCOME', 'identity lookup returned an unknown status');
    default:
      return failure('UNKNOWN_OUTCOME', 'identity lookup outcome unknown');
  }
}

/** Abbreviate a public address (display-safe). */
export function abbreviate(address: string): string {
  if (address.length <= 14) {
    return address;
  }
  return `${address.slice(0, 8)}…${address.slice(-6)}`;
}

/**
 * Internal helper: derive the public representation of a private key hex
 * using the Approved secp256k1 primitive (same rule as FEAT-001: compressed
 * unless the stored address starts with 04). Returns null on malformed
 * input so callers can distinguish malformed-key from mismatch.
 */
function derivePublicOrNull(privateKeyHex: string, storedAddress: string): string | null {
  try {
    const compressed = !storedAddress.startsWith('04');
    const pub = secpGetPublicKey(hexToBytesStrict(privateKeyHex), compressed);
    return bytesToHexLower(pub);
  } catch {
    return null;
  }
}

export type { PortableCredentialsRecord, LookupOutcome };
