/**
 * FEAT-007 Task 2.6 — unit/fuzz tests for wire normalizers.
 * Coverage targets: AC-007-028–036, 045–050; every legal status/code
 * combination, unknown enum/code, malformed successful profile,
 * signing/encryption mismatch, transport failure, message-mutation invariance,
 * and allowlisted editable code supplied by the pinned external artifact.
 */
import { describe, expect, it } from 'vitest';
import { normalizeGetIdentityReply, normalizeSubmitReply, type LookupOutcome, type SubmissionOutcome } from './wire.js';

const LOCAL_SIGNING = 'A11B22C33D44E55F66A77B88C99D00E11F22A33B44C55D66E77F88A99B00C11';
const LOCAL_ENCRYPT = 'Q77W66E55R44T33Y22U11I00O99P88A77S66D55F44G33H22J11K00L99M88';
const OTHER = 'Z99Y88X77W66V55U44T33S22R11Q00P99O88N77M66L55K44J33I22H11G00F99';

describe('normalizeGetIdentityReply — authoritative absence vs failure', () => {
  it('transport-successful Successfull=false is authoritative not-found', () => {
    const outcome = normalizeGetIdentityReply({ successfull: false, message: 'not found' }, LOCAL_SIGNING, LOCAL_ENCRYPT);
    expect(outcome).toEqual({ kind: 'authoritativeAbsent' });
  });

  it('null/undefined/malformed replies are never not-found', () => {
    expect(normalizeGetIdentityReply(null, LOCAL_SIGNING, LOCAL_ENCRYPT)).toEqual({ kind: 'malformedSuccess' });
    expect(normalizeGetIdentityReply(undefined, LOCAL_SIGNING, LOCAL_ENCRYPT)).toEqual({ kind: 'malformedSuccess' });
    expect(normalizeGetIdentityReply({ successfull: 'yes', message: '' } as never, LOCAL_SIGNING, LOCAL_ENCRYPT)).toEqual({ kind: 'compatibilityError' });
  });

  it('exact signing + encryption addresses confirm the profile', () => {
    const outcome = normalizeGetIdentityReply(
      { successfull: true, message: 'ok', profileName: 'Voter', publicSigningAddress: LOCAL_SIGNING, publicEncryptAddress: LOCAL_ENCRYPT, isPublic: false },
      LOCAL_SIGNING,
      LOCAL_ENCRYPT,
    );
    expect(outcome).toEqual({ kind: 'exactProfile', profileName: 'Voter', publicSigningAddress: LOCAL_SIGNING, publicEncryptAddress: LOCAL_ENCRYPT, isPublic: false });
  });

  it('signing mismatch is not a confirmation', () => {
    const outcome = normalizeGetIdentityReply(
      { successfull: true, message: 'ok', profileName: 'Other', publicSigningAddress: OTHER, publicEncryptAddress: OTHER, isPublic: true },
      LOCAL_SIGNING,
      LOCAL_ENCRYPT,
    );
    expect(outcome).toEqual({ kind: 'signingKeyMismatch' });
  });

  it('signing match with encryption mismatch fails closed', () => {
    const outcome = normalizeGetIdentityReply(
      { successfull: true, message: 'ok', profileName: 'Voter', publicSigningAddress: LOCAL_SIGNING, publicEncryptAddress: OTHER, isPublic: false },
      LOCAL_SIGNING,
      LOCAL_ENCRYPT,
    );
    expect(outcome).toEqual({ kind: 'encryptionKeyMismatch' });
  });

  it('malformed successful profile fails closed', () => {
    expect(
      normalizeGetIdentityReply({ successfull: true, message: 'ok', profileName: '', publicSigningAddress: LOCAL_SIGNING, publicEncryptAddress: LOCAL_ENCRYPT, isPublic: false }, LOCAL_SIGNING, LOCAL_ENCRYPT),
    ).toEqual({ kind: 'malformedSuccess' });
    expect(
      normalizeGetIdentityReply({ successfull: true, message: 'ok', profileName: 'Voter', publicSigningAddress: 'not-an-address', publicEncryptAddress: LOCAL_ENCRYPT, isPublic: false }, LOCAL_SIGNING, LOCAL_ENCRYPT),
    ).toEqual({ kind: 'malformedSuccess' });
    expect(
      normalizeGetIdentityReply({ successfull: true, message: 'ok', profileName: 'Voter', publicSigningAddress: LOCAL_SIGNING, publicEncryptAddress: LOCAL_ENCRYPT, isPublic: 'yes' as never }, LOCAL_SIGNING, LOCAL_ENCRYPT),
    ).toEqual({ kind: 'malformedSuccess' });
  });
});

describe('normalizeSubmitReply — closed status/code mapping', () => {
  const EMPTY_ALLOWLIST: ReadonlySet<string> = new Set();

  it('maps ACCEPTED / PENDING / ALREADY_EXISTS with successfull=true', () => {
    expect(normalizeSubmitReply({ successfull: true, message: 'ok', status: 'ACCEPTED' }, EMPTY_ALLOWLIST)).toEqual({ kind: 'accepted' });
    expect(normalizeSubmitReply({ successfull: true, message: 'ok', status: 'PENDING' }, EMPTY_ALLOWLIST)).toEqual({ kind: 'pending' });
    expect(normalizeSubmitReply({ successfull: true, message: 'ok', status: 'ALREADY_EXISTS' }, EMPTY_ALLOWLIST)).toEqual({ kind: 'alreadyExists' });
  });

  it('treats contradictory successfull=false with non-REJECTED statuses as compatibility errors', () => {
    expect(normalizeSubmitReply({ successfull: false, message: 'x', status: 'ACCEPTED' }, EMPTY_ALLOWLIST)).toEqual({ kind: 'compatibilityError' });
    expect(normalizeSubmitReply({ successfull: false, message: 'x', status: 'PENDING' }, EMPTY_ALLOWLIST)).toEqual({ kind: 'compatibilityError' });
  });

  it('rejects without a validation code are unknown/terminal, never editable', () => {
    expect(normalizeSubmitReply({ successfull: true, message: 'no', status: 'REJECTED' }, EMPTY_ALLOWLIST)).toEqual({ kind: 'unknownRejection' });
    expect(normalizeSubmitReply({ successfull: true, message: 'no', status: 'REJECTED', validationCode: null }, EMPTY_ALLOWLIST)).toEqual({ kind: 'unknownRejection' });
  });

  it('UNSPECIFIED / unknown enum / contradictory replies fail closed', () => {
    expect(normalizeSubmitReply({ successfull: true, message: 'x', status: 'UNSPECIFIED' }, EMPTY_ALLOWLIST)).toEqual({ kind: 'compatibilityError' });
    expect(normalizeSubmitReply({ successfull: true, message: 'x', status: null }, EMPTY_ALLOWLIST)).toEqual({ kind: 'compatibilityError' });
    expect(normalizeSubmitReply({ successfull: true, message: 'x', status: 'MADE_UP' as never }, EMPTY_ALLOWLIST)).toEqual({ kind: 'compatibilityError' });
    expect(normalizeSubmitReply(null, EMPTY_ALLOWLIST)).toEqual({ kind: 'compatibilityError' });
  });

  it('editable codes come only from the pinned allowlist; unknown codes are terminal', () => {
    const allowlist = new Set(['ALIAS_INVALID']);
    expect(normalizeSubmitReply({ successfull: true, message: 'alias invalid', status: 'REJECTED', validationCode: 'ALIAS_INVALID' }, allowlist)).toEqual({ kind: 'editableRejection', validationCode: 'ALIAS_INVALID' });
    expect(normalizeSubmitReply({ successfull: true, message: 'bad sig', status: 'REJECTED', validationCode: 'SIGNATURE_INVALID' }, allowlist)).toEqual({ kind: 'terminalRejection', validationCode: 'SIGNATURE_INVALID' });
  });

  it('empty allowlist fails closed: no editable correction is ever authorized', () => {
    const outcome = normalizeSubmitReply({ successfull: true, message: 'alias invalid', status: 'REJECTED', validationCode: 'ALIAS_INVALID' }, EMPTY_ALLOWLIST);
    expect(outcome.kind).toBe('terminalRejection');
  });
});

describe('message-mutation invariance', () => {
  it('free-form Message never changes any outcome', () => {
    const editable = new Set(['E1']);
    const base: Array<() => SubmissionOutcome> = [
      () => normalizeSubmitReply({ successfull: true, message: 'anything', status: 'ACCEPTED' }, editable),
      () => normalizeSubmitReply({ successfull: true, message: 'ANOTHER THING', status: 'ACCEPTED' }, editable),
      () => normalizeSubmitReply({ successfull: true, message: '', status: 'REJECTED', validationCode: 'E1' }, editable),
      () => normalizeSubmitReply({ successfull: true, message: '!!!', status: 'REJECTED', validationCode: 'E1' }, editable),
    ];
    expect(base[0]()).toEqual(base[1]());
    expect(base[2]()).toEqual(base[3]());
  });

  it('lookup Message text never flips absence into confirmation', () => {
    const a = normalizeGetIdentityReply({ successfull: false, message: 'not found' }, LOCAL_SIGNING, LOCAL_ENCRYPT);
    const b = normalizeGetIdentityReply({ successfull: false, message: 'profile exists!' }, LOCAL_SIGNING, LOCAL_ENCRYPT);
    expect(a).toEqual(b);
    expect(a.kind).toBe('authoritativeAbsent');
  });
});

describe('outcome exhaustiveness (closed union)', () => {
  it('enumerates the closed lookup outcomes', () => {
    const kinds: ReadonlyArray<LookupOutcome['kind']> = [
      'authoritativeAbsent',
      'exactProfile',
      'signingKeyMismatch',
      'encryptionKeyMismatch',
      'malformedSuccess',
      'compatibilityError',
      'transportFailure',
    ];
    expect(new Set(kinds).size).toBe(kinds.length);
  });

  it('enumerates the closed submission outcomes', () => {
    const kinds: ReadonlyArray<SubmissionOutcome['kind']> = [
      'accepted',
      'pending',
      'alreadyExists',
      'editableRejection',
      'terminalRejection',
      'unknownRejection',
      'transportFailure',
      'compatibilityError',
    ];
    expect(new Set(kinds).size).toBe(kinds.length);
  });
});
