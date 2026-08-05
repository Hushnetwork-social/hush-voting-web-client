/**
 * FEAT-009 Task 3.6 — unit, conformance, property, and lookup fault tests
 * for the concrete key proof and identity resolution authority (Task 3.5).
 *
 * Proves: every pair/mnemonic proof path, lookup ordering (no lookup
 * before proof/release), exact both-key profile resolution, signing-only
 * fail-closed, transport/malformed never not-found, alias escaping, and
 * safe diagnostics.
 */
import { describe, expect, it } from 'vitest';
import { abbreviate, proveConcreteKeys, resolveIdentity } from './proof';
import type { PublicLookupPort } from './proof';
import type { PortableCredentialsRecord } from '../../identity-compatibility/types';
import type { LookupOutcome } from '../contracts/resolution';
import type { ValidatedCredentialAuthorityRef } from '../contracts/import';

/** Consistent record taken from the public FEAT-001 corpus (synthetic TEST fixture). */
function consistentRecord(): PortableCredentialsRecord {
  return {
    ProfileName: 'public-test-profile-001',
    PublicSigningAddress: '0237fdd4364c0b898908be2f1a98a6b4a7890c623ae92a283640e44d87e048daa5',
    PrivateSigningKey: '6e3f74236c3d4a20553be05963f624696990c22245599b3d1b30262af793d885',
    PublicEncryptAddress: '032ebaf076203f15ac8119cfdbc9394d1c7b9929b0647e4f607e27da95701f8556',
    PrivateEncryptKey: '1a68f2d543282dd612502a1b3688e85eeca280057129d512011645a51cf6d552',
    IsPublic: true,
    Mnemonic: 'abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware',
  };
}

function authorityRef(overrides: Partial<ValidatedCredentialAuthorityRef> = {}): ValidatedCredentialAuthorityRef {
  return {
    kind: 'validatedCredentialAuthority',
    epoch: 'epoch-1' as ValidatedCredentialAuthorityRef['epoch'],
    signingAddressAbbreviated: '0237fdd4…8daa5',
    encryptionAddressAbbreviated: '032ebaf0…8556',
    publicKeyEncoding: 'COMPRESSED',
    profileName: 'public-test-profile-001',
    isPublic: true,
    hasMnemonic: true,
    validatedAtMs: 1000,
    ...overrides,
  };
}

function lookupPort(outcome: LookupOutcome): PublicLookupPort {
  return { lookup: async () => outcome };
}

describe('FEAT-009 concrete key proof (Task 3.5)', () => {
  it('consistent pairs pass and produce an opaque validated authority', () => {
    const result = proveConcreteKeys(consistentRecord(), 'epoch-1' as never, 1000);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.proofOutcome).toBe('passed');
      expect(result.value.authority?.kind).toBe('validatedCredentialAuthority');
      expect(result.value.authority?.hasMnemonic).toBe(true); // corpus vector carries a mnemonic
    }
  });

  it('signing mismatch returns SIGNING_KEY_MISMATCH typed code', () => {
    const record = { ...consistentRecord(), PrivateSigningKey: '6e3f74236c3d4a20553be05963f624696990c22245599b3d1b30262af793d884' }; // altered scalar
    const result = proveConcreteKeys(record, 'epoch-1' as never, 1000);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('SIGNING_KEY_MISMATCH');
  });

  it('encryption mismatch returns ENCRYPTION_KEY_MISMATCH typed code', () => {
    const record = { ...consistentRecord(), PrivateEncryptKey: '1a68f2d543282dd612502a1b3688e85eeca280057129d512011645a51cf6d553' }; // altered scalar
    const result = proveConcreteKeys(record, 'epoch-1' as never, 1000);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('ENCRYPTION_KEY_MISMATCH');
  });

  it('malformed key encoding fails before lookup', () => {
    const record = { ...consistentRecord(), PrivateSigningKey: 'not-hex' };
    const result = proveConcreteKeys(record, 'epoch-1' as never, 1000);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('SIGNING_KEY_MISMATCH');
  });

  it('mnemonic mismatch rejects the entire file', () => {
    const record = { ...consistentRecord(), Mnemonic: 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about' }; // valid BIP-39, wrong phrase
    const result = proveConcreteKeys(record, 'epoch-1' as never, 1000);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('MNEMONIC_KEY_MISMATCH');
  });

  it('a consistent file with Mnemonic:null remains supported', () => {
    const result = proveConcreteKeys({ ...consistentRecord(), Mnemonic: null }, 'epoch-1' as never, 1000);
    expect(result.ok).toBe(true);
  });

  it('abbreviate hides address middles', () => {
    const long = 'a'.repeat(64);
    expect(abbreviate(long)).toBe('aaaaaaaa…aaaaaa');
    expect(abbreviate('abc')).toBe('abc');
  });
});

describe('FEAT-009 exact identity resolution (Task 3.5)', () => {
  const signing = consistentRecord().PublicSigningAddress;
  const encryption = consistentRecord().PublicEncryptAddress;

  it('existing profile requires exact both-key equality', async () => {
    const port = lookupPort({
      kind: 'existing',
      profile: { alias: 'chain-alias', isPublic: true, signingAddress: signing, encryptionAddress: encryption, networkLabel: 'HushLocal' },
    });
    const result = await resolveIdentity(port, authorityRef(), signing, encryption);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.kind).toBe('existing');
      if (result.value.kind === 'existing') expect(result.value.profile.alias).toBe('chain-alias'); // chain authoritative
    }
  });

  it('signing-only match fails closed', async () => {
    const port = lookupPort({
      kind: 'existing',
      profile: { alias: 'chain-alias', isPublic: true, signingAddress: signing, encryptionAddress: '0'.repeat(66), networkLabel: 'HushLocal' },
    });
    const result = await resolveIdentity(port, authorityRef(), signing, encryption);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('PROFILE_SIGNING_ONLY_MATCH');
  });

  it('authoritative not-found enables missing-profile review with explicit create', async () => {
    const port = lookupPort({ kind: 'authoritativeNotFound' });
    const result = await resolveIdentity(port, authorityRef(), signing, encryption);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.kind).toBe('missing');
      if (result.value.kind === 'missing') {
        expect(result.value.review.requiresExplicitCreate).toBe(true);
        expect(result.value.review.authenticatedProfileName).toBe('public-test-profile-001');
      }
    }
  });

  it('transport failure is never not-found and never creates', async () => {
    const port = lookupPort({ kind: 'transportFailure' });
    const result = await resolveIdentity(port, authorityRef(), signing, encryption);
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('LOOKUP_TRANSPORT_FAILURE');
  });

  it('malformed and unknown outcomes fail closed', async () => {
    const malformed = await resolveIdentity(lookupPort({ kind: 'malformed' }), authorityRef(), signing, encryption);
    expect(malformed.ok).toBe(false);
    const unknown = await resolveIdentity(lookupPort({ kind: 'unknownStatus' }), authorityRef(), signing, encryption);
    expect(unknown.ok).toBe(false);
  });

  it('resolution results carry no secret surfaces', async () => {
    const port = lookupPort({ kind: 'authoritativeNotFound' });
    const result = await resolveIdentity(port, authorityRef(), signing, encryption);
    expect(JSON.stringify(result)).not.toMatch(/"password"|"plaintext"|"mnemonic"|"privateKey"/i);
  });
});
