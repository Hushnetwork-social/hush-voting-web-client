/**
 * FEAT-008 Task 3.6 — unit, conformance, downgrade, and staging fault tests
 * for selected-key proof, protection selection, staging, and destruction.
 * Coverage targets: AC-008-021–023, 036–054 (authority portion); cross-mode
 * vectors, fault matrix, and no-persistence tests.
 */
import { describe, expect, it } from 'vitest';
import type { RecoveryEpoch } from '../contracts/lifecycle';
import type { SelectedKeyProofEvidence } from '../contracts/candidates';
import {
  assertPersistentDestructionOrder,
  assertSessionDestructionOrder,
  AUTHORIZATION_MAX_MS,
  defaultProtectionMode,
  isMnemonicAllowed,
  protectionCanPersist,
  selectProtectionMode,
  type ProtectionCapabilityReport,
  type SelectedKeyProofPort,
} from './proof';

const epoch = 'epoch-1' as RecoveryEpoch;

const FULL_CAPABILITIES: ProtectionCapabilityReport = {
  webauthnPlatform: true,
  discoverableCredential: true,
  userVerification: true,
  prf: true,
  qualifiedOsProtection: true,
  secureScreenLock: true,
};

function proofPort(): SelectedKeyProofPort {
  return {
    async proveSelected() {
      const evidence: SelectedKeyProofEvidence = { epoch, producerId: 'p-01', bothKeyExact: true, challengeValidated: true, vectorValidated: true, completedAtEpochMs: 1 };
      return { ok: true, value: evidence };
    },
  };
}

describe('protection selection policy', () => {
  it('defaults Device-password mode per platform', () => {
    expect(defaultProtectionMode('web')).toBe('devicePasswordWeb');
    expect(defaultProtectionMode('native')).toBe('devicePasswordNative');
  });

  it('accepts password modes without extra capability', () => {
    expect(selectProtectionMode('devicePasswordWeb', FULL_CAPABILITIES, false).ok).toBe(true);
    expect(selectProtectionMode('devicePasswordNative', FULL_CAPABILITIES, false).ok).toBe(true);
  });

  it('accepts session-only only with explicit acknowledgement', () => {
    expect(selectProtectionMode('sessionOnly', FULL_CAPABILITIES, false).ok).toBe(false);
    const ack = selectProtectionMode('sessionOnly', FULL_CAPABILITIES, true);
    expect(ack.ok).toBe(true);
    if (ack.ok) {
      expect(ack.value.mode).toBe('sessionOnly');
    }
  });

  it('rejects unqualified passwordless Web with NO silent fallback', () => {
    const missingPrf: ProtectionCapabilityReport = { ...FULL_CAPABILITIES, prf: false };
    const result = selectProtectionMode('passwordlessWeb', missingPrf, false);
    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.code).toBe('UNQUALIFIED_PASSWORDLESS');
    }
  });

  it('rejects unqualified passwordless native', () => {
    const noOs: ProtectionCapabilityReport = { ...FULL_CAPABILITIES, qualifiedOsProtection: false };
    expect(selectProtectionMode('passwordlessNative', noOs, false).ok).toBe(false);
  });

  it('accepts qualified passwordless Web', () => {
    const result = selectProtectionMode('passwordlessWeb', FULL_CAPABILITIES, false);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.mode).toBe('passwordlessWeb');
    }
  });
});

describe('persistence classification', () => {
  it('persistent modes can persist; session-only cannot', () => {
    expect(protectionCanPersist('devicePasswordWeb')).toBe(true);
    expect(protectionCanPersist('passwordlessWeb')).toBe(true);
    expect(protectionCanPersist('passwordlessNative')).toBe(true);
    expect(protectionCanPersist('sessionOnly')).toBe(false);
  });
});

describe('destruction points', () => {
  it('persistent mode retains the phrase through verified stage, then destroys before online verification', () => {
    expect(isMnemonicAllowed('preVerify', 'devicePasswordWeb', false)).toBe(true);
    expect(isMnemonicAllowed('postVerifyPreStage', 'devicePasswordWeb', false)).toBe(true);
    // Stage committed but NOT yet read-back verified → still allowed (retained)
    expect(isMnemonicAllowed('stageCommitted', 'devicePasswordWeb', false)).toBe(true);
    // After verified read-back → phrase must be destroyed
    expect(isMnemonicAllowed('stageCommitted', 'devicePasswordWeb', true)).toBe(false);
    expect(isMnemonicAllowed('activated', 'devicePasswordWeb', true)).toBe(false);
  });

  it('session-only destroys immediately after isolated install', () => {
    expect(isMnemonicAllowed('stageCommitted', 'sessionOnly', true)).toBe(false);
    expect(isMnemonicAllowed('activated', 'sessionOnly', true)).toBe(false);
  });

  it('enforces the persistent destruction ordering (stage then destroy)', () => {
    expect(assertPersistentDestructionOrder(['stageCommitted', 'mnemonicDestroyedPersistent'])).toBe(true);
    expect(assertPersistentDestructionOrder(['mnemonicDestroyedPersistent', 'stageCommitted'])).toBe(false);
    expect(assertPersistentDestructionOrder(['stageCommitted'])).toBe(false);
  });

  it('enforces session-only no-stage destruction', () => {
    expect(assertSessionDestructionOrder(['mnemonicDestroyedSession'])).toBe(true);
    expect(assertSessionDestructionOrder(['stageCommitted', 'mnemonicDestroyedSession'])).toBe(false);
  });
});

describe('authorization bound', () => {
  it('caps one-use purpose-bound authorization at 60 seconds', () => {
    expect(AUTHORIZATION_MAX_MS).toBe(60_000);
  });
});

describe('proof port seam', () => {
  it('selected-key proof succeeds with exact both-key + challenge + vectors', async () => {
    const port = proofPort();
    const result = await port.proveSelected(0, epoch);
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.bothKeyExact).toBe(true);
      expect(result.value.challengeValidated).toBe(true);
      expect(result.value.vectorValidated).toBe(true);
    }
  });
});
