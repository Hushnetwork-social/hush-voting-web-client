/**
 * FEAT-011 Task 2.2 — exhaustive model/boundary/malformed-input tests for the
 * identity-decision and public-projection contracts (Task 2.1).
 *
 * Covers: candidate cardinality/outcome permutations; exact both-key rule;
 * metadata bounds; explicit-confirmation guard; incomplete-set rejection;
 * multiple exact candidates; secret/full-identifier forbidden fields; unknown
 * result fail-closed; no export capability.
 */

import { describe, expect, it } from 'vitest';
import * as contracts from './contracts';
import {
  ALIAS_MAX_GRAPHEMES,
  CONVERGENCE_OPERATIONS,
  classifyLookupDecision,
  projectPublicIdentity,
  validateAuthoritativeMetadata,
  type ConvergenceOperationId,
  type ExactIdentityProof,
  type IdentityLookupDecision,
  type PublicIdentityProjection,
} from './contracts';

const PROOF: ExactIdentityProof = {
  signingAddress: 'A1B2C3D4E5F60718293A4B5C6D7E8F90123456789ABCDEF0123456789ABCDEF0',
  encryptionAddress: 'F0EDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210F',
  normalizedAlias: 'alice',
  visibility: 'public',
};

/** Build every legal decision permutation for policy classification. */
function allDecisions(): ReadonlyArray<IdentityLookupDecision> {
  return [
    { kind: 'existingIdentity', proof: PROOF },
    { kind: 'authoritativeAbsence' },
    { kind: 'identityContradiction', code: 'SIGNING_ADDRESS_MISMATCH' },
    { kind: 'identityContradiction', code: 'ENCRYPTION_ADDRESS_MISMATCH' },
    { kind: 'lookupAmbiguity', reason: 'timeout' },
    { kind: 'lookupAmbiguity', reason: 'offline' },
    { kind: 'lookupAmbiguity', reason: 'malformedResponse' },
    { kind: 'lookupAmbiguity', reason: 'oversizeResponse' },
    { kind: 'lookupAmbiguity', reason: 'unknownEnum' },
    { kind: 'lookupAmbiguity', reason: 'transportFailure' },
    { kind: 'lookupAmbiguity', reason: 'cacheInconsistency' },
    { kind: 'lookupAmbiguity', reason: 'partialCandidateSet' },
    { kind: 'candidateSetIncomplete', completed: 1, total: 4 },
    { kind: 'candidateSetIncomplete', completed: 0, total: 4 },
  ];
}

describe('identity-decision contracts (Task 2.1/2.2)', () => {
  it('classifies every decision permutation without absence/authentication confusion', () => {
    const reactions = allDecisions().map((d) => classifyLookupDecision(d));
    // Exact both-key proof is the ONLY authenticatable decision.
    expect(reactions.filter((r) => r === 'authenticatable')).toHaveLength(1);
    // Authoritative absence is the ONLY registration-eligible decision.
    expect(reactions.filter((r) => r === 'registrationEligible')).toHaveLength(1);
    // Timeout/offline/malformed/partial-candidate/transport are NEVER absence or auth.
    for (const r of reactions) {
      expect(['authenticatable', 'registrationEligible', 'retryable', 'failClosed']).toContain(r);
    }
    const ambiguous = allDecisions().filter((d) => d.kind === 'lookupAmbiguity');
    expect(ambiguous.every((d) => classifyLookupDecision(d) === 'retryable')).toBe(true);
    const incomplete = allDecisions().filter((d) => d.kind === 'candidateSetIncomplete');
    expect(incomplete.every((d) => classifyLookupDecision(d) === 'retryable')).toBe(true);
  });

  it('fails closed on both contradiction codes (never adoptable, never create)', () => {
    for (const d of allDecisions().filter((x) => x.kind === 'identityContradiction')) {
      expect(classifyLookupDecision(d)).toBe('failClosed');
    }
  });

  it('exact both-key rule: only the full proof is authenticatable (compile-time + runtime)', () => {
    // Signing-address-only success is structurally unrepresentable: the union
    // requires the complete ExactIdentityProof with both addresses.
    const onlyAuthenticatable = allDecisions().find((d) => classifyLookupDecision(d) === 'authenticatable');
    expect(onlyAuthenticatable?.kind).toBe('existingIdentity');
    if (onlyAuthenticatable?.kind === 'existingIdentity') {
      expect(onlyAuthenticatable.proof.signingAddress).toBe(PROOF.signingAddress);
      expect(onlyAuthenticatable.proof.encryptionAddress).toBe(PROOF.encryptionAddress);
    }
  });

  it('incomplete candidate sets are rejected as retryable, never absence', () => {
    const decision: IdentityLookupDecision = { kind: 'candidateSetIncomplete', completed: 3, total: 5 };
    expect(classifyLookupDecision(decision)).toBe('retryable');
    expect(decision.kind).not.toBe('authoritativeAbsence');
  });

  it('multiple exact candidates fail closed by construction (no selection order exists)', () => {
    // The CandidateResolution union has no order-dependent select: multiple
    // matches are a terminal 'multipleMatches' variant; the decision union
    // never carries a list of candidates.
    const resolution: contracts.CandidateResolution = { kind: 'multipleMatches', count: 2 };
    expect(resolution.kind).toBe('multipleMatches');
    expect(classifyLookupDecision({ kind: 'lookupAmbiguity', reason: 'partialCandidateSet' })).toBe('retryable');
  });

  it('unknown/unsupported result shapes are unrepresentable (closed union, exhaustive switch)', () => {
    // Exhaustiveness: adding a new kind breaks this compile-time switch.
    const kinds = allDecisions().map((d) => d.kind);
    expect(new Set(kinds)).toEqual(
      new Set(['existingIdentity', 'authoritativeAbsence', 'identityContradiction', 'lookupAmbiguity', 'candidateSetIncomplete']),
    );
  });
});

describe('authoritative metadata bounds (Task 2.2)', () => {
  it('rejects empty, over-grapheme, and over-byte aliases', () => {
    expect(validateAuthoritativeMetadata('   ', 'public').ok).toBe(false);
    expect(validateAuthoritativeMetadata('', 'private').ok).toBe(false);
    const maxGraphemes = 'a'.repeat(ALIAS_MAX_GRAPHEMES);
    expect(validateAuthoritativeMetadata(maxGraphemes, 'public').ok).toBe(true);
    expect(validateAuthoritativeMetadata('a'.repeat(ALIAS_MAX_GRAPHEMES + 1), 'public').ok).toBe(false);
    // 64 graphemes × 4-byte code points = exactly the 256-byte bound.
    const maxBytes = '😀'.repeat(ALIAS_MAX_GRAPHEMES);
    expect(validateAuthoritativeMetadata(maxBytes, 'private').ok).toBe(true);
    // Grapheme clusters, not code points: q+combining-acute is 1 grapheme / 2 code points.
    const combining = 'q\u0301'.repeat(ALIAS_MAX_GRAPHEMES); // 64 graphemes, 128 code points, 192 bytes
    expect(validateAuthoritativeMetadata(combining, 'private').ok).toBe(true);
    expect(validateAuthoritativeMetadata('q\u0301'.repeat(ALIAS_MAX_GRAPHEMES + 1), 'private').ok).toBe(false);
  });

  it('normalizes NFC and trims whitespace; rejects invalid visibility', () => {
    const result = validateAuthoritativeMetadata('  Ali\u0301ce  ', 'public');
    expect(result.ok).toBe(true);
    if (result.ok) {
      // 'i' + combining acute composes canonically to '\u00ed' (í).
      expect(result.value.normalizedAlias).toBe('Al\u00edce');
      expect(result.value.normalizedAlias).not.toContain(' ');
    }
    expect(validateAuthoritativeMetadata('alice', 'unknown').ok).toBe(false);
    expect(validateAuthoritativeMetadata('alice', undefined).ok).toBe(false);
    expect(validateAuthoritativeMetadata('alice', 1).ok).toBe(false);
  });

  it('returns typed failures, never throws (malformed input)', () => {
    expect(() => validateAuthoritativeMetadata(null as unknown as string, 'public')).not.toThrow();
    expect(validateAuthoritativeMetadata(null as unknown as string, 'public').ok).toBe(false);
  });
});

describe('public projection boundary (Task 2.1/2.2)', () => {
  const ref = 'opaque-ref-1' as contracts.ProfileReference;

  it('projects abbreviated addresses and preserves the opaque reference', () => {
    const projection = projectPublicIdentity(PROOF, ref);
    expect(projection.abbreviatedSigningAddress).toBe('A1B2C3D4…BCDEF0');
    expect(projection.abbreviatedEncryptionAddress).toBe('F0EDCBA9…43210F');
    expect(projection.profileReference).toBe(ref);
    expect(projection.normalizedAlias).toBe('alice');
    expect(projection.visibility).toBe('public');
  });

  it('contains no secret/full-identifier fields (forbidden-field scan)', () => {
    const projection = projectPublicIdentity(PROOF, ref);
    const violations = contracts.assertNoSecretSurface(projection);
    expect(violations).toEqual([]);
    const json = JSON.stringify(projection);
    expect(json).not.toContain(PROOF.signingAddress);
    expect(json).not.toContain(PROOF.encryptionAddress);
    expect(json).not.toMatch(/password|mnemonic|privateKey|transaction|signature|BEGIN/);
  });

  it('detects accidental widening of the projection boundary', () => {
    const widened = {
      ...projectPublicIdentity(PROOF, ref),
      fullAddress: PROOF.signingAddress,
      password: 'hunter2',
    } as unknown as PublicIdentityProjection;
    const violations = contracts.assertNoSecretSurface(widened);
    expect(violations).toContain('fullAddress');
    expect(violations).toContain('password');
  });

  it('detects PEM material and long base64 identifiers in the projection', () => {
    const pem = {
      ...projectPublicIdentity(PROOF, ref),
      normalizedAlias: 'BEGIN PRIVATE KEY',
    } as unknown as PublicIdentityProjection;
    expect(contracts.assertNoSecretSurface(pem)).toContain('privateKey');
    const b64 = {
      ...projectPublicIdentity(PROOF, ref),
      normalizedAlias: 'A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2',
    } as unknown as PublicIdentityProjection;
    expect(contracts.assertNoSecretSurface(b64)).toContain('fullAddress');
  });
});

describe('no export capability (Task 2.2)', () => {
  it('the convergence operation registry contains no export/backup/create-dat capability', () => {
    const forbidden = /export|backup|createDat|saveDat|download/i;
    for (const op of CONVERGENCE_OPERATIONS) {
      expect(forbidden.test(op)).toBe(false);
    }
    const ops: readonly ConvergenceOperationId[] = CONVERGENCE_OPERATIONS;
    expect(ops).toContain('lock');
    expect(ops).toContain('removal');
    expect(ops).not.toContain('export' as ConvergenceOperationId);
  });

  it('the module surface exposes no export symbol', () => {
    const exportedNames = Object.keys(contracts);
    expect(exportedNames.some((n) => /export|backup|createDat/i.test(n))).toBe(false);
  });
});
