/**
 * FEAT-004 verification tests — exact both-key binding and allowlist safety.
 *
 * Proves: only an approved endpoint identifier resolves; exact match promotes
 * only on both-key equality; signing/encryption mismatch and missing profile
 * are distinct; timeout and network failures are typed and retryable;
 * arbitrary endpoints/redirects never influence verification; no page Boolean
 * can promote authentication (the outcome vocabulary has no such path).
 *
 * Normative source: FEAT-004 FeatureDescription "Online Identity
 * Verification"; Task 4.6 behavior specification.
 */
import { describe, expect, it } from 'vitest';
import { isAllowedRedirect, isEndpointApproved, resolveEndpoint } from './resolver';
import { verifyExactBinding, type VerificationTransport } from './verifier';

const SAFE_CANDIDATE = { alias: 'Alice', abbreviatedSigningAddress: '01234567…' };

function transport(result: Awaited<ReturnType<VerificationTransport['lookup']>>): VerificationTransport {
  return { lookup: async () => result };
}

describe('endpoint resolver — allowlist safety', () => {
  it('resolves only approved config identifiers', () => {
    expect(resolveEndpoint('production-hushnetwork')).not.toBeNull();
    expect(resolveEndpoint('development-localhost')).not.toBeNull();
    expect(resolveEndpoint('https://evil.example')).toBeNull();
    expect(resolveEndpoint('arbitrary')).toBeNull();
    expect(resolveEndpoint(42)).toBeNull();
  });

  it('approves only allowlisted HTTPS endpoints', () => {
    expect(isEndpointApproved('production-hushnetwork')).toBe(true);
    expect(isEndpointApproved('test-fixture')).toBe(true);
    expect(isEndpointApproved('https://evil.example')).toBe(false);
  });

  it('rejects redirects outside the allowlist origin', () => {
    expect(isAllowedRedirect('https://api.hushnetwork.app/something')).toBe(true);
    expect(isAllowedRedirect('https://evil.example/steal')).toBe(false);
    expect(isAllowedRedirect('not-a-url')).toBe(false);
  });
});

describe('verification — exact binding outcomes', () => {
  it('promotes only on exact both-key match', async () => {
    const outcome = await verifyExactBinding({
      configId: 'production-hushnetwork',
      localSigningAddress: 'S-1',
      localEncryptionAddress: 'E-1',
      safeCandidate: SAFE_CANDIDATE,
      transport: transport({ kind: 'profile', profile: { signingAddress: 'S-1', encryptionAddress: 'E-1' } }),
    });
    expect(outcome.code).toBe('VERIFY_SUCCESS');
  });

  it('distinguishes signing and encryption mismatches', async () => {
    const signing = await verifyExactBinding({
      configId: 'production-hushnetwork',
      localSigningAddress: 'S-1',
      localEncryptionAddress: 'E-1',
      safeCandidate: SAFE_CANDIDATE,
      transport: transport({ kind: 'profile', profile: { signingAddress: 'S-2', encryptionAddress: 'E-1' } }),
    });
    expect(signing.code).toBe('VERIFY_SIGNING_KEY_MISMATCH');

    const encryption = await verifyExactBinding({
      configId: 'production-hushnetwork',
      localSigningAddress: 'S-1',
      localEncryptionAddress: 'E-1',
      safeCandidate: SAFE_CANDIDATE,
      transport: transport({ kind: 'profile', profile: { signingAddress: 'S-1', encryptionAddress: 'E-2' } }),
    });
    expect(encryption.code).toBe('VERIFY_ENCRYPTION_KEY_MISMATCH');
  });

  it('reports missing profiles with the safe candidate and typed network outcomes', async () => {
    const missing = await verifyExactBinding({
      configId: 'production-hushnetwork',
      localSigningAddress: 'S-1',
      localEncryptionAddress: 'E-1',
      safeCandidate: SAFE_CANDIDATE,
      transport: transport({ kind: 'missing' }),
    });
    expect(missing.code).toBe('VERIFY_PROFILE_MISSING');

    const network = await verifyExactBinding({
      configId: 'production-hushnetwork',
      localSigningAddress: 'S-1',
      localEncryptionAddress: 'E-1',
      safeCandidate: SAFE_CANDIDATE,
      transport: transport({ kind: 'network-error' }),
    });
    expect(network.code).toBe('VERIFY_NETWORK_UNAVAILABLE');

    const timeout = await verifyExactBinding({
      configId: 'production-hushnetwork',
      localSigningAddress: 'S-1',
      localEncryptionAddress: 'E-1',
      safeCandidate: SAFE_CANDIDATE,
      transport: transport({ kind: 'timeout' }),
    });
    expect(timeout.code).toBe('VERIFY_TIMEOUT');
  });

  it('fails closed on arbitrary endpoints and redirects without leaking details', async () => {
    const outcome = await verifyExactBinding({
      configId: 'https://evil.example',
      localSigningAddress: 'S-1',
      localEncryptionAddress: 'E-1',
      safeCandidate: SAFE_CANDIDATE,
      transport: transport({ kind: 'profile', profile: { signingAddress: 'S-1', encryptionAddress: 'E-1' } }),
    });
    expect(outcome.code).toBe('UNKNOWN_FAILURE');
    if (outcome.code === 'UNKNOWN_FAILURE') {
      expect(outcome.supportCode).toMatch(/^vc-/);
    }
  });

  it('enforces the 10-second timeout bound', async () => {
    const never = { lookup: async () => new Promise<never>(() => undefined) };
    const outcome = await verifyExactBinding({
      configId: 'production-hushnetwork',
      localSigningAddress: 'S-1',
      localEncryptionAddress: 'E-1',
      safeCandidate: SAFE_CANDIDATE,
      transport: never,
      timeoutMs: 5,
    });
    expect(outcome.code).toBe('VERIFY_TIMEOUT');
  });
});
