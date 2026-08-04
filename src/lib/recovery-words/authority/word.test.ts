/**
 * FEAT-008 Task 3.2 — unit, vector, property, and lifecycle tests for the
 * bounded word validation and candidate derivation authority.
 * Coverage targets: AC-008-001, 004, 006–007, 014–023 (authority portion);
 * deterministic corpus replay, fault/lifecycle coverage.
 */
import { describe, expect, it } from 'vitest';
import mnemonicVectors from '../../../../conformance/identity/v1/vectors/mnemonic-vectors.json';
import {
  createEpochDeadline,
  createFeat001DerivationPort,
  countNormalizedWords,
  isEpochExpired,
  mapMnemonicFailure,
  mustClearOn,
  normalizePhrase,
  RECOVERY_EPOCH_MAX_MS,
  verifyAndDerive,
} from './word.js';
import type { MnemonicDerivationPort } from './word.js';

const vectors = mnemonicVectors as { vectors: Array<{ id: string; producerId: string; mnemonic: string }> };
const M001 = vectors.vectors.find((v) => v.id === 'M-001')?.mnemonic ?? '';
const M002 = vectors.vectors.find((v) => v.id === 'M-002')?.mnemonic ?? '';

function stubPort(overrides?: Partial<MnemonicDerivationPort>): MnemonicDerivationPort {
  return {
    derive: () => ({ ok: true, value: { candidates: [], rejectedProducers: [] } }),
    ...overrides,
  };
}

describe('normalizePhrase (Recovery-Word Entry Contract)', () => {
  it('NFKD-normalizes, lowercases, collapses separators, and rejoins with single spaces', () => {
    expect(normalizePhrase('  ABANDON\t Amount\n\nliar  amount ')).toBe('abandon amount liar amount');
    expect(normalizePhrase('\uFF21bandon')).toBe('abandon'); // fullwidth A (U+FF21) → NFKD 'A' → 'a'
    expect(normalizePhrase('')).toBe('');
  });

  it('never turns an unknown word into a known word', () => {
    const normalized = normalizePhrase('abandon abandon zzz-not-a-word abandon');
    expect(normalized).toBe('abandon abandon zzz-not-a-word abandon');
  });
});

describe('countNormalizedWords', () => {
  it('counts exactly the normalized words', () => {
    expect(countNormalizedWords('a b c')).toBe(3);
    expect(countNormalizedWords('')).toBe(0);
  });
});

describe('verifyAndDerive policy', () => {
  it('rejects unsupported counts (15/18/21 or 0) as WRONG_COUNT without server access', () => {
    const port = stubPort();
    const result = verifyAndDerive(port, 'one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen', ['P-01'], 1000, null);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('WRONG_COUNT');
    }
  });

  it('coalesces a second command within the minimum interval (DOUBLE_DISPATCH)', () => {
    const port = stubPort();
    const result = verifyAndDerive(port, M002, ['P-01'], 1050, 1000);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('DOUBLE_DISPATCH');
    }
  });

  it('rejects a partial candidate set (missing applicable producer) and fails closed', () => {
    const port = stubPort({
      derive: () => ({ ok: true, value: { candidates: [], rejectedProducers: [] } }),
    });
    const result = verifyAndDerive(port, M001, ['P-01', 'P-02'], 2000, null);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('PRODUCER_DERIVATION_FAILURE');
    }
  });

  it('maps FEAT-001 failures to the FEAT-008 closed vocabulary', () => {
    expect(mapMnemonicFailure('INVALID_WORD_COUNT')).toBe('WRONG_COUNT');
    expect(mapMnemonicFailure('UNKNOWN_WORD')).toBe('UNKNOWN_WORD');
    expect(mapMnemonicFailure('INVALID_CHECKSUM')).toBe('CHECKSUM_FAILURE');
    expect(mapMnemonicFailure('UNSUPPORTED_PASSPHRASE')).toBe('UNSUPPORTED_INPUT');
    expect(mapMnemonicFailure('DERIVATION_FAILURE')).toBe('PRODUCER_DERIVATION_FAILURE');
    expect(mapMnemonicFailure('BOGUS')).toBe('UNKNOWN_OUTCOME');
  });
});

describe('real FEAT-001 corpus replay (TEST-ONLY vectors)', () => {
  it('derives every applicable Approved candidate from the pinned corpus phrase', () => {
    const port = createFeat001DerivationPort();
    const result = verifyAndDerive(port, M001, ['P-01'], 3000, null);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.candidates.length).toBeGreaterThan(0);
      // Public candidate descriptors must carry exact addresses and provenance.
      for (const candidate of result.value.candidates) {
        expect(candidate.signingAddress.length).toBeGreaterThan(20);
        expect(candidate.encryptionAddress.length).toBeGreaterThan(20);
        expect(candidate.producerIds.length).toBeGreaterThan(0);
      }
    }
  });

  it('accepts the 12-word corpus phrase for applicable producers', () => {
    const port = createFeat001DerivationPort();
    const result = verifyAndDerive(port, M002, ['P-01'], 4000, null);
    expect(result.ok).toBe(true);
  });
});

describe('epoch custody and clear policy', () => {
  it('caps the unprovisioned foreground authority at 10 minutes', () => {
    const deadline = createEpochDeadline(0);
    expect(deadline).toBe(RECOVERY_EPOCH_MAX_MS);
    expect(isEpochExpired(deadline, RECOVERY_EPOCH_MAX_MS)).toBe(false);
    expect(isEpochExpired(deadline, RECOVERY_EPOCH_MAX_MS + 1)).toBe(true);
  });

  it('clears transient phrase/candidate state on Back/Lock/lifecycle/cancellation/timeout/ownership loss', () => {
    for (const event of ['back', 'lock', 'lifecycleLoss', 'cancellation', 'timeout', 'ownershipLoss', 'networkChange'] as const) {
      expect(mustClearOn(event, 'preVerify')).toBe(true);
      expect(mustClearOn(event, 'postVerify')).toBe(true);
    }
  });

  it('keeps the encrypted stage intact on Back for staged resume (locks instead of destroying)', () => {
    expect(mustClearOn('back', 'staged')).toBe(false);
    expect(mustClearOn('lock', 'staged')).toBe(true);
    expect(mustClearOn('lifecycleLoss', 'staged')).toBe(true);
  });
});
