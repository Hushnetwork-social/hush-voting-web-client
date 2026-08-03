/**
 * FEAT-006 Phase 2 Task 2.4 — wrapper/storage model tests (TS).
 * Canonical bytes, strict bounds, binding-field mutation sensitivity,
 * identity-neutrality, and unknown-version preservation. The pinned canonical
 * digest is replayed from `conformance/android-vault/v1/vectors/` so Rust and
 * TypeScript must agree byte-for-byte.
 */
import { describe, expect, it } from 'vitest';
import {
  ADAPTER_ID,
  APPLICATION_ID,
  AndroidWrapperMetadataV1,
  canonicalBytes,
  canonicalSha256,
  INNER_ENVELOPE_MAX_BYTES,
  isBounded,
  isIdentityFree,
  matchesFixedVocabulary,
  RECORD_PURPOSE,
  WRAPPER_FORMAT_VERSION,
  WRAPPER_MAX_BYTES,
} from './wrapper';

function sample(): AndroidWrapperMetadataV1 {
  return {
    wrapperVersion: WRAPPER_FORMAT_VERSION,
    adapterId: ADAPTER_ID,
    applicationId: APPLICATION_ID,
    releaseChannel: 'production',
    vaultKeyReference: 'hvk-9f3e1a02b8c4',
    envelopeFormatVersion: 1,
    parameterSuiteVersion: 1,
    recordSchemaVersion: 1,
    slot: 'a',
    vaultGeneration: 7,
    recordPurpose: RECORD_PURPOSE,
    criticalExtensions: [],
  };
}

describe('FEAT-006 Android wrapper v1 (TS)', () => {
  it('fixed metadata is identity-free, bounded, and vocabulary-matching', () => {
    const meta = sample();
    expect(isIdentityFree(meta)).toBe(true);
    expect(isBounded(meta)).toBe(true);
    expect(matchesFixedVocabulary(meta)).toBe(true);
  });

  it('identity-bearing key references are rejected', () => {
    const meta = { ...sample(), vaultKeyReference: 'alias-user-bob' };
    expect(isIdentityFree(meta)).toBe(false);
  });

  it('wrong version fails the fixed vocabulary', () => {
    expect(matchesFixedVocabulary({ ...sample(), wrapperVersion: 99 })).toBe(false);
  });

  it('oversized fields and excessive extensions are rejected', () => {
    expect(isBounded({ ...sample(), vaultKeyReference: 'x'.repeat(200) })).toBe(false);
    const many = Array.from({ length: 9 }, (_, i) => ({ key: `k${i}`, value: 'v' }));
    expect(isBounded({ ...sample(), criticalExtensions: many })).toBe(false);
  });

  it('bounds are exactly 1 MiB inner and 1.5 MiB wrapper', () => {
    expect(INNER_ENVELOPE_MAX_BYTES).toBe(1024 * 1024);
    expect(WRAPPER_MAX_BYTES).toBe(1536 * 1024);
    expect(INNER_ENVELOPE_MAX_BYTES).toBeLessThan(WRAPPER_MAX_BYTES);
  });

  it('canonical bytes are deterministic and mutation-sensitive', async () => {
    const a = canonicalSha256(sample());
    const b = canonicalSha256(sample());
    expect(a).toBe(b);
    expect(a).toMatch(/^[0-9a-f]{64}$/);

    expect(canonicalSha256({ ...sample(), slot: 'b' })).not.toBe(a);
    expect(canonicalSha256({ ...sample(), vaultGeneration: 8 })).not.toBe(a);
    expect(canonicalSha256({ ...sample(), releaseChannel: 'debug' })).not.toBe(a);
    expect(canonicalSha256({ ...sample(), vaultKeyReference: 'hvk-other' })).not.toBe(a);
    expect(
      canonicalSha256({ ...sample(), criticalExtensions: [{ key: 'k', value: 'v' }] }),
    ).not.toBe(a);
  });

  it('replays the pinned canonical vector identically to Rust', async () => {
    // Pinned vector AW-001 in conformance/android-vault/v1/vectors/.
    const digest = canonicalSha256(sample());
    expect(digest).toBe('706f5a9dcf9c8ccc4484e3c5099835bae1894d204886165f65dafe94059edd76');
    const json = Buffer.from(canonicalBytes(sample())).toString('utf8');
    expect(json).toBe(
      '{"adapterId":"android-keystore","applicationId":"com.hushvoting.client","criticalExtensions":[],"envelopeFormatVersion":1,"parameterSuiteVersion":1,"recordPurpose":"vault-package","recordSchemaVersion":1,"releaseChannel":"production","slot":"a","vaultGeneration":7,"vaultKeyReference":"hvk-9f3e1a02b8c4","wrapperVersion":1}',
    );
  });
});
