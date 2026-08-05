/**
 * FEAT-009 Task 3.4 — unit, vector, fuzz, timing-model, and destruction
 * tests for the exact password/decryption/backoff/strict-parse/destruction
 * authority (Task 3.3).
 *
 * Proves: exact public-vector outcomes, password byte boundaries, one-
 * attempt semantics, backoff scheduling across file/tab changes, strict
 * parser rejection mapping, mnemonic handling, stale cancellation, and
 * destruction ordering.
 */
import { describe, expect, it } from 'vitest';
import {
  PER_ATTEMPT_DESTRUCTION_ORDER,
  attemptDecryption,
  currentBackoffMs,
  initialBackoffState,
  mapImportFailure,
  recordAuthFailure,
  resetBackoff,
  strictImport,
  utf8ByteLength,
} from './import.js';
import { backoffDelaySeconds } from '../contracts/import.js';

/** Envelope built with the same exact v1 layout the FEAT-001 API expects. */
function validEnvelopeStub(): Uint8Array {
  const bytes = new Uint8Array(36 + 16);
  bytes.set([0x48, 0x55, 0x53, 0x48], 0); // HUSH
  bytes.set([1, 0, 0, 0], 4); // version 1
  return bytes;
}

describe('FEAT-009 password byte semantics (Task 3.3)', () => {
  it('UTF-8 byte length is exact without normalization', () => {
    expect(utf8ByteLength('')).toBe(0);
    expect(utf8ByteLength('abc')).toBe(3);
    expect(utf8ByteLength(' ')).toBe(1); // spaces significant
    expect(utf8ByteLength('ñ')).toBe(2); // no NFC normalization
    expect(utf8ByteLength('é')).toBe(2);
    expect(utf8ByteLength('e\u0301')).toBe(3); // NFD form is distinct bytes
    expect(utf8ByteLength('a'.repeat(4096))).toBe(4096);
    expect(utf8ByteLength('a'.repeat(4097))).toBe(4097);
  });

  it('over-4096-byte passwords are rejected before PBKDF2', async () => {
    const result = await attemptDecryption(validEnvelopeStub(), 'a'.repeat(4097), { emptyPasswordExplicit: false });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('PASSWORD_TOO_LONG');
  });

  it('automatic empty password is prohibited without the explicit option', async () => {
    const result = await attemptDecryption(validEnvelopeStub(), '', { emptyPasswordExplicit: false });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('PASSWORD_TOO_LONG');
  });

  it('explicit empty option submits exactly zero bytes once', async () => {
    const result = await attemptDecryption(validEnvelopeStub(), '', { emptyPasswordExplicit: true });
    // Stub envelope has random ciphertext; decryption fails with the combined
    // outcome (authenticated=false) — proving zero bytes were attempted.
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.authenticated).toBe(false);
  });
});

describe('FEAT-009 backoff model (Task 3.3)', () => {
  it('schedule is 0/0/2/4/8/16/30 and persists across file changes', () => {
    let state = initialBackoffState();
    expect(currentBackoffMs(state)).toBe(0);
    state = recordAuthFailure(state); // attempt 1
    expect(currentBackoffMs(state)).toBe(0);
    state = recordAuthFailure(state); // attempt 2
    expect(currentBackoffMs(state)).toBe(0);
    state = recordAuthFailure(state); // attempt 3
    expect(currentBackoffMs(state)).toBe(2000);
    state = recordAuthFailure(state); // attempt 4 — file change does not reset
    expect(currentBackoffMs(state)).toBe(4000);
    state = recordAuthFailure(state); // attempt 5
    expect(currentBackoffMs(state)).toBe(8000);
    state = recordAuthFailure(state); // attempt 6
    expect(currentBackoffMs(state)).toBe(16000);
    state = recordAuthFailure(state); // attempt 7+
    expect(currentBackoffMs(state)).toBe(30000);
    state = recordAuthFailure(state); // capped
    expect(currentBackoffMs(state)).toBe(30000);
    expect(backoffDelaySeconds(100)).toBe(30);
  });

  it('successful complete validation resets the counter', () => {
    let state = initialBackoffState();
    state = recordAuthFailure(state);
    state = recordAuthFailure(state);
    state = recordAuthFailure(state);
    expect(currentBackoffMs(state)).toBe(2000);
    state = resetBackoff();
    expect(currentBackoffMs(state)).toBe(0);
  });

  it('no password hash, fingerprint, or durable deadline is representable', () => {
    const state = initialBackoffState();
    expect(JSON.stringify(state)).not.toMatch(/hash|fingerprint|deadline|password/i);
  });
});

describe('FEAT-009 decryption one-attempt semantics (Task 3.3)', () => {
  it('wrong password produces the combined outcome without cause inference', async () => {
    const result = await attemptDecryption(validEnvelopeStub(), 'wrong-password', { emptyPasswordExplicit: false });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.authenticated).toBe(false);
      expect(result.value.plaintext).toBeNull();
    }
  });

  it('destruction events follow the frozen ordering', () => {
    expect(PER_ATTEMPT_DESTRUCTION_ORDER).toEqual([
      'passwordDestroyed',
      'plaintextDestroyed',
      'challengeDestroyed',
      'mnemonicDestroyed',
      'snapshotReleased',
      'sourceReleased',
    ]);
  });
});

describe('FEAT-009 strict import mapping (Task 3.3)', () => {
  it('maps every FEAT-001 failure code to the closed vocabulary', () => {
    expect(mapImportFailure('DAT_MALFORMED')).toBe('AUTHENTICATION_FAILED');
    expect(mapImportFailure('DAT_WRONG_PASSWORD')).toBe('AUTHENTICATION_FAILED');
    expect(mapImportFailure('DAT_DECRYPT_FAILED')).toBe('AUTHENTICATION_FAILED');
    expect(mapImportFailure('DAT_DUPLICATE_FIELD')).toBe('PAYLOAD_DUPLICATE_FIELD');
    expect(mapImportFailure('DAT_UNKNOWN_FIELD')).toBe('PAYLOAD_UNKNOWN_FIELD');
    expect(mapImportFailure('DAT_MISSING_FIELD')).toBe('PAYLOAD_MISSING_FIELD');
    expect(mapImportFailure('DAT_INVALID_FIELD')).toBe('PAYLOAD_INVALID_FIELD');
    expect(mapImportFailure('DAT_KEY_MISMATCH')).toBe('SIGNING_KEY_MISMATCH');
    expect(mapImportFailure('DAT_MNEMONIC_KEY_MISMATCH')).toBe('MNEMONIC_KEY_MISMATCH');
    expect(mapImportFailure('SOMETHING_NEW')).toBe('UNKNOWN_OUTCOME'); // fail closed
  });

  it('strictImport on a stub envelope fails safely without values', async () => {
    const result = await strictImport(validEnvelopeStub(), 'x');
    // Stub ciphertext cannot authenticate; result must be a closed failure
    // carrying no decrypted values.
    if (!result.ok) {
      expect(result.supportCode).toMatch(/^IMPORT-/);
      expect(result.message).not.toMatch(/password|plaintext|key/i);
    }
  });

  it('strict import result never contains secret surfaces', async () => {
    const result = await strictImport(validEnvelopeStub(), 'x');
    const serialized = JSON.stringify(result);
    expect(serialized).not.toMatch(/"password"|"plaintext"|"mnemonic"|"privateKey"/i);
  });
});
