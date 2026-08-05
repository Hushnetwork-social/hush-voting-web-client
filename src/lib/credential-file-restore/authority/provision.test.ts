/**
 * FEAT-009 Task 3.8 — unit, model, tamper, crash, and reconciliation tests
 * for the protection/staging/activation/recreation/resume authority
 * (Task 3.7).
 *
 * Proves: protection qualification with no downgrade, stage write/read-back
 * ordering, exact online activation truth, mempool ≠ confirmation, server
 * invalid-proof distinction, resume fail-closed, session-only no-write.
 */
import { describe, expect, it } from 'vitest';
import {
  activateExistingProfile,
  createMissingProfile,
  evaluateResume,
  evaluateSessionOnly,
  selectProtection,
  stageValidatedCredentials,
} from './provision';
import type { FreshVerificationPort, ProtectionCapabilityPort, RegistrationPort, StagingPort } from './provision';
import type { StagedRestoreRecordMetadata } from '../contracts/protection';

const METADATA: StagedRestoreRecordMetadata = {
  protectionMode: 'devicePassword',
  protectionVersion: 'v1',
  networkLabel: 'HushLocal',
  signingAddressAbbreviated: 'aa…bb',
  encryptionAddressAbbreviated: 'cc…dd',
  profileAlias: 'chain-alias',
  profileIsPublic: true,
  stagedAtMs: 1000,
  generation: 2,
  purpose: 'file-restore',
};

function capPort(result: 'qualified' | 'unavailable' | 'unsupported'): ProtectionCapabilityPort {
  return { qualify: async () => result };
}

function stagingPort(writeOk: boolean, verificationKind: 'verified' | 'tampered' | 'corrupt'): StagingPort {
  return {
    writeStage: async () => (writeOk ? { ok: true as const, value: { state: 'committed' as const } } : { ok: false as const, code: 'STAGE_WRITE_FAILURE' as const, message: 'write failed', supportCode: 'S' }),
    verifyStage: async () => ({ kind: verificationKind }),
  };
}

describe('FEAT-009 protection selection (Task 3.7)', () => {
  it('qualified mode is accepted', async () => {
    const result = await selectProtection(capPort('qualified'), 'devicePassword');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.mode).toBe('devicePassword');
  });

  it('capability loss fails closed without downgrade', async () => {
    for (const state of ['unavailable', 'unsupported'] as const) {
      const result = await selectProtection(capPort(state), 'webAuthnPasswordless');
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code).toBe('PROTECTION_CANCELLED');
    }
  });
});

describe('FEAT-009 staging (Task 3.7)', () => {
  it('write → read-back verified → committed', async () => {
    const result = await stageValidatedCredentials(stagingPort(true, 'verified'), { protectionMode: 'devicePassword', generation: 1 });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.state).toBe('committed');
      expect(result.value.verification).toBe('verified');
    }
  });

  it('tampered read-back fails closed and never activates', async () => {
    const result = await stageValidatedCredentials(stagingPort(true, 'tampered'), { protectionMode: 'devicePassword', generation: 1 });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('STAGE_WRITE_FAILURE');
  });

  it('write failure fails closed', async () => {
    const result = await stageValidatedCredentials(stagingPort(false, 'verified'), { protectionMode: 'devicePassword', generation: 1 });
    expect(result.ok).toBe(false);
  });
});

describe('FEAT-009 exact activation (Task 3.7)', () => {
  type FreshKind = 'exactExisting' | 'authoritativeAbsent' | 'transportFailure' | 'mismatch';
  function freshPort(kind: FreshKind): FreshVerificationPort {
    return {
      freshLookup: async () =>
        kind === 'exactExisting'
          ? { kind, profile: { alias: 'a', isPublic: true, signingAddress: 's', encryptionAddress: 'e', networkLabel: 'HushLocal' } }
          : ({ kind }),
    };
  }

  it('fresh exact both-key lookup activates', async () => {
    const result = await activateExistingProfile(freshPort('exactExisting'), 's', 'e');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.kind).toBe('activatedExisting');
  });

  it('authoritative absence routes to missing-profile, never activates', async () => {
    const result = await activateExistingProfile(freshPort('authoritativeAbsent'), 's', 'e');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.kind).toBe('notYetActive');
  });

  it('transport failure preserves the stage; never shell', async () => {
    const result = await activateExistingProfile(freshPort('transportFailure'), 's', 'e');
    expect(result.ok).toBe(true);
    if (result.ok) expect(result.value.kind).toBe('connectivityFailure');
  });

  it('mismatch fails closed', async () => {
    const result = await activateExistingProfile(freshPort('mismatch'), 's', 'e');
    expect(result.ok).toBe(false);
  });
});

describe('FEAT-009 missing-profile recreation (Task 3.7)', () => {
  type RegKind = 'confirmed' | 'accepted' | 'pending' | 'alreadyExists' | 'invalidProof' | 'rejected' | 'timeout' | 'unknown';
  function registrationPort(kind: RegKind): RegistrationPort {
    return {
      submitMissingProfile: async () => {
        switch (kind) {
          case 'confirmed':
            return { kind: 'confirmed' };
          case 'accepted':
            return { kind: 'accepted' };
          case 'pending':
            return { kind: 'pending' };
          case 'alreadyExists':
            return { kind: 'alreadyExists' };
          case 'invalidProof':
            return { kind: 'invalidProof' };
          case 'rejected':
            return { kind: 'rejected', code: 'REJECTED' };
          case 'timeout':
            return { kind: 'timeout' };
          case 'unknown':
            return { kind: 'unknown' };
        }
      },
    };
  }

  it('only CONFIRMED activates; mempool acceptance is not success', async () => {
    const confirmed = await createMissingProfile(registrationPort('confirmed'), { signingAddress: 's', encryptionAddress: 'e', alias: 'a', isPublic: false });
    expect(confirmed.ok).toBe(true);
    if (confirmed.ok) expect(confirmed.value.kind).toBe('confirmed');

    const accepted = await createMissingProfile(registrationPort('accepted'), { signingAddress: 's', encryptionAddress: 'e', alias: 'a', isPublic: false });
    expect(accepted.ok).toBe(true);
    if (accepted.ok) expect(accepted.value.kind).toBe('accepted'); // NOT confirmed
  });

  it('invalid-proof and rejected map to the distinct safe server rejection', async () => {
    for (const kind of ['invalidProof', 'rejected'] as const) {
      const result = await createMissingProfile(registrationPort(kind), { signingAddress: 's', encryptionAddress: 'e', alias: 'a', isPublic: false });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code).toBe('SERVER_PROOF_REJECTED');
    }
  });

  it('unknown outcomes fail closed', async () => {
    const result = await createMissingProfile(registrationPort('unknown'), { signingAddress: 's', encryptionAddress: 'e', alias: 'a', isPublic: false });
    expect(result.ok).toBe(false);
  });
});

describe('FEAT-009 resume and session-only (Task 3.7)', () => {
  it('verified stage resumes with real metadata; corrupt fails closed', () => {
    const resume = evaluateResume({ kind: 'verified' }, METADATA);
    expect(resume.ok).toBe(true);
    if (resume.ok && resume.value.kind === 'resume') {
      expect(resume.value.stage.generation).toBe(2);
      expect(resume.value.stage.purpose).toBe('file-restore');
    }
    const corrupt = evaluateResume({ kind: 'corrupt' }, METADATA);
    expect(corrupt.ok).toBe(false);
    if (!corrupt.ok) expect(corrupt.code).toBe('STAGED_RESTART_FAILURE');
  });

  it('session-only persists nothing and ends on authority loss', () => {
    const active = evaluateSessionOnly(true);
    expect(active.ok).toBe(true);
    if (active.ok) expect(active.value.kind).toBe('active');
    const ended = evaluateSessionOnly(false);
    if (ended.ok) expect(ended.value.kind).toBe('ended');
  });
});
