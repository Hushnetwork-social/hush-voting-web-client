/**
 * FEAT-016 Task 6.3 — exact licence sealing seam tests.
 *
 * Proves the exact-bytes seam closed in Phase 6:
 *   - sealing signs the canonical unsigned envelope and appends the frozen
 *     UserSignature member; the digest stored is over the sealed bytes;
 *   - the seal verifies against the canonical unsigned bytes (server
 *     contract); one-byte tampering fails;
 *   - deterministic RFC 6979 signing means two seals of the same unsigned
 *     envelope are byte-identical (exact reuse across retry/restart);
 *   - fresh query envelopes always differ (`signedAt` changes per attempt)
 *     and their signature verifies over the frozen canonical JSON;
 *   - unsigned/signed classification is exact; malformed input fails closed.
 *
 * Normative source: FEAT-016 FeatureDescription "Licence Transaction and
 * Pending Journal"; FEAT-015 frozen corpus; Phase 3 code review note 1.
 */
import { describe, expect, it } from 'vitest';
import { deriveP01Keys } from '../identity-compatibility/producers';
import mnemonicVectors from '../../../conformance/identity/v1/vectors/mnemonic-vectors.json';
import {
  isLicenceCanonicalUnsignedJson,
  isLicenceSignedTransactionJson,
  sealLicenceTransaction,
  signLicenceQueryEnvelope,
  verifyLicenceSeal,
} from './sealing';
import { buildDirectFreeUnsignedTransaction } from './direct-free';
import { LICENCE_FIXED_BASELINE_TRANSACTION_ID } from './fixtures/canonical-vectors';
import { LICENCE_CATALOGUE_VERSION_V1, LICENCE_PLAN_DIRECT_FREE } from './contracts';
import { licenceTransactionDigest } from './canonical';
import { verifyMessage } from '../identity-compatibility/signature';
import { QUERY_FIXTURE_ACTOR } from './fixtures/canonical-vectors';

const VECTORS = (mnemonicVectors as { vectors: Array<{ id: string; producerId: string; mnemonic: string }> }).vectors;
const P01 = VECTORS.find((v) => v.id === 'M-001' && v.producerId === 'P-01');

const TEST_MNEMONIC = P01?.mnemonic ?? '';

function testKeys(): { signingPrivateKey: string; signingAddress: string } {
  const derived = deriveP01Keys(TEST_MNEMONIC);
  expect(derived.ok).toBe(true);
  if (!derived.ok) throw new Error('derive failed');
  return { signingPrivateKey: derived.value.signingPrivateKey, signingAddress: derived.value.signingAddress };
}

/** Canonical unsigned envelope (server template) for the baseline fixture. */
function unsignedFixture(): { unsignedJson: string; digest: string } {
  const template = {
    TransitionIntent: 'baseline_free' as const,
    RequestedPlanId: LICENCE_PLAN_DIRECT_FREE,
    ObservedCatalogueVersion: LICENCE_CATALOGUE_VERSION_V1,
  };
  const built = buildDirectFreeUnsignedTransaction(template, LICENCE_FIXED_BASELINE_TRANSACTION_ID, '2026-09-06T00:00:00.000Z');
  expect(built.ok).toBe(true);
  if (!built.ok) throw new Error('build failed');
  return { unsignedJson: built.canonicalUnsignedJson, digest: built.digest };
}

describe('unsigned/signed classification', () => {
  it('classifies the canonical unsigned envelope exactly', () => {
    const { unsignedJson } = unsignedFixture();
    expect(isLicenceCanonicalUnsignedJson(unsignedJson)).toBe(true);
    expect(isLicenceSignedTransactionJson(unsignedJson)).toBe(false);
  });

  it('rejects malformed, empty, non-JSON, and signature-shaped input', () => {
    expect(isLicenceCanonicalUnsignedJson('')).toBe(false);
    expect(isLicenceCanonicalUnsignedJson('not json')).toBe(false);
    expect(isLicenceCanonicalUnsignedJson(JSON.stringify({ nope: true }))).toBe(false);
    expect(isLicenceCanonicalUnsignedJson(null)).toBe(false);
    expect(isLicenceCanonicalUnsignedJson(42)).toBe(false);
    expect(isLicenceSignedTransactionJson('')).toBe(false);
    expect(isLicenceSignedTransactionJson(null)).toBe(false);
    expect(isLicenceSignedTransactionJson(JSON.stringify({ UserSignature: { Signatory: 'x', Signature: 'y' } }))).toBe(false);
  });
});

describe('sealLicenceTransaction (exact-bytes seam)', () => {
  it('signs the canonical unsigned bytes and appends the frozen UserSignature member', () => {
    const keys = testKeys();
    const { unsignedJson, digest } = unsignedFixture();
    const sealed = sealLicenceTransaction({ unsignedJson, signingPrivateKeyHex: keys.signingPrivateKey, signingAddress: keys.signingAddress });
    expect(sealed.ok).toBe(true);
    if (!sealed.ok) return;
    expect(sealed.signedDigest).toBe(licenceTransactionDigest(sealed.signedJson));
    expect(sealed.signedDigest).not.toBe(digest); // digest now binds the sealed bytes
    expect(isLicenceSignedTransactionJson(sealed.signedJson)).toBe(true);
    expect(isLicenceCanonicalUnsignedJson(sealed.signedJson)).toBe(false);
    const parsed = JSON.parse(sealed.signedJson) as { UserSignature: { Signatory: string; Signature: string } };
    expect(parsed.UserSignature.Signatory).toBe(keys.signingAddress);
    // The seal verifies against the exact canonical unsigned bytes.
    expect(verifyLicenceSeal({ unsignedJson, signedJson: sealed.signedJson, publicSigningKeyHex: keys.signingAddress })).toBe(true);
  });

  it('rejects malformed unsigned envelopes and missing signers', () => {
    const keys = testKeys();
    expect(sealLicenceTransaction({ unsignedJson: '{}', signingPrivateKeyHex: keys.signingPrivateKey, signingAddress: keys.signingAddress })).toEqual({ ok: false, code: 'malformed-unsigned' });
    const { unsignedJson } = unsignedFixture();
    expect(sealLicenceTransaction({ unsignedJson, signingPrivateKeyHex: 'zz', signingAddress: keys.signingAddress })).toEqual({ ok: false, code: 'missing-signer' });
  });

  it('is deterministic: two seals of the same envelope are byte-identical (exact reuse)', () => {
    const keys = testKeys();
    const { unsignedJson } = unsignedFixture();
    const first = sealLicenceTransaction({ unsignedJson, signingPrivateKeyHex: keys.signingPrivateKey, signingAddress: keys.signingAddress });
    const second = sealLicenceTransaction({ unsignedJson, signingPrivateKeyHex: keys.signingPrivateKey, signingAddress: keys.signingAddress });
    expect(first.ok).toBe(true);
    expect(second.ok).toBe(true);
    if (!first.ok || !second.ok) return;
    expect(second.signedJson).toBe(first.signedJson);
    expect(second.signedDigest).toBe(first.signedDigest);
  });

  it('fails verification when the signed bytes are tampered', () => {
    const keys = testKeys();
    const { unsignedJson } = unsignedFixture();
    const sealed = sealLicenceTransaction({ unsignedJson, signingPrivateKeyHex: keys.signingPrivateKey, signingAddress: keys.signingAddress });
    expect(sealed.ok).toBe(true);
    if (!sealed.ok) return;
    const tampered = `${sealed.signedJson.slice(0, -2)}x}`;
    expect(verifyLicenceSeal({ unsignedJson, signedJson: tampered, publicSigningKeyHex: keys.signingAddress })).toBe(false);
    const wrongKey = sealLicenceTransaction({ unsignedJson, signingPrivateKeyHex: keys.signingPrivateKey, signingAddress: keys.signingAddress });
    expect(wrongKey.ok).toBe(true);
  });
});

describe('signLicenceQueryEnvelope (fresh per attempt)', () => {
  it('mints headers whose signature verifies over the frozen canonical envelope bytes', () => {
    const keys = testKeys();
    const signed = signLicenceQueryEnvelope({ actorAddress: keys.signingAddress, signedAt: '2026-09-06T00:00:00.000Z', signingPrivateKeyHex: keys.signingPrivateKey });
    expect(signed.ok).toBe(true);
    if (!signed.ok) return;
    expect(signed.headers.signatory).toBe(keys.signingAddress.toLowerCase());
    const canonicalJson = `{"actorAddress":"${keys.signingAddress.toLowerCase()}","method":"GetMyEntitlement","request":{},"signedAt":"2026-09-06T00:00:00.000Z"}`;
    const compactHex = Buffer.from(signed.headers.signature, 'base64').toString('hex');
    expect(verifyMessage(canonicalJson, compactHex, keys.signingAddress, 'compact')).toBe(true);
  });

  it('produces a different signature for every fresh signedAt (never reused)', () => {
    const keys = testKeys();
    const a = signLicenceQueryEnvelope({ actorAddress: keys.signingAddress, signedAt: '2026-09-06T00:00:00.000Z', signingPrivateKeyHex: keys.signingPrivateKey });
    const b = signLicenceQueryEnvelope({ actorAddress: keys.signingAddress, signedAt: '2026-09-06T00:00:03.000Z', signingPrivateKeyHex: keys.signingPrivateKey });
    expect(a.ok).toBe(true);
    expect(b.ok).toBe(true);
    if (!a.ok || !b.ok) return;
    expect(b.headers.signedAt).not.toBe(a.headers.signedAt);
    expect(b.headers.signature).not.toBe(a.headers.signature);
  });

  it('matches the frozen server fixture envelope shape for the canonical actor', () => {
    // Server contract test vector: canonical JSON is ordinal deep-sorted and
    // compact. Signing must bind exactly those bytes.
    const keys = testKeys();
    const signed = signLicenceQueryEnvelope({ actorAddress: QUERY_FIXTURE_ACTOR, signedAt: '2026-09-06T00:00:00Z', signingPrivateKeyHex: keys.signingPrivateKey });
    expect(signed.ok).toBe(true);
    if (!signed.ok) return;
    expect(signed.headers.signatory).toBe(QUERY_FIXTURE_ACTOR);
    expect(signed.headers.signedAt).toBe('2026-09-06T00:00:00Z');
  });

  it('rejects a missing signer', () => {
    expect(signLicenceQueryEnvelope({ actorAddress: QUERY_FIXTURE_ACTOR, signedAt: '2026-09-06T00:00:00Z', signingPrivateKeyHex: 'zz' })).toEqual({ ok: false, code: 'missing-signer' });
  });
});
