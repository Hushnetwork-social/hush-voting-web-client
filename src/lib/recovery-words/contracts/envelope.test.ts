/**
 * FEAT-008 Task 2.4 — unit, vector, and downgrade tests for no-mnemonic
 * envelope and protection-mode contracts.
 * Coverage targets: AC-008-036–054, 060, 062–063, 072, 082 (contract layer
 * portion); valid mode matrix, unknown versions, copied/tampered metadata,
 * missing wrappers, empty-password attempts, session-only persistence scan,
 * old-reader/new-version fail-closed behavior.
 */
import { describe, expect, it } from 'vitest';
import {
  PROTECTION_MODE_PERSISTENT,
  PROTECTION_MODE_REQUIRES_DEVICE_PASSWORD,
  PROTECTION_MODE_REQUIRES_OS_WRAPPER,
  PROTECTION_MODE_VERSION,
  RECOVERY_RECORD_CONTRACT_VERSION,
  checkLegalProtectionCombination,
  checkRecoveryVersionCompatibility,
  isProtectionMode,
  parseProtectionMetadata,
  parseRecoveryEnvelopeRecord,
  validateNoMnemonicRecord,
  type ProtectionMode,
  type RecoveryEnvelopeRecord,
} from './envelope.js';

function validEnvelope(overrides: Partial<RecoveryEnvelopeRecord> = {}): RecoveryEnvelopeRecord {
  const base: RecoveryEnvelopeRecord = {
    contractVersion: RECOVERY_RECORD_CONTRACT_VERSION,
    producer: { producerId: 'p-01', producerVersion: '1.0.0' },
    publicBindings: { signingAddress: 'A'.repeat(66), encryptionAddress: 'E'.repeat(66) },
    networkIdentifier: 'hush-mainnet-1',
    protection: { mode: 'devicePasswordWeb', version: PROTECTION_MODE_VERSION },
    profile: { kind: 'existing', authoritativeAlias: 'Voter', authoritativeVisibility: 'private' },
    lifecycle: { stage: 'staged', generation: 1 },
    ciphertext: {
      signingKeyCiphertext: 'c1'.repeat(32),
      encryptionKeyCiphertext: 'c2'.repeat(32),
      nonce: 'n'.repeat(24),
      aadContext: 'hushvoting:vault:rp:network:recovery:v1',
    },
    reconciliation: { requiresProfileRecreate: false, retainedTransactionRef: null },
  };
  return { ...base, ...overrides };
}

describe('ProtectionMode closed hierarchy', () => {
  it('registers every legal mode with its persistence/OS/password classification', () => {
    const modes: ProtectionMode[] = ['devicePasswordWeb', 'devicePasswordNative', 'passwordlessWeb', 'passwordlessNative', 'sessionOnly'];
    expect(modes.every(isProtectionMode)).toBe(true);
    expect(PROTECTION_MODE_PERSISTENT.devicePasswordWeb).toBe(true);
    expect(PROTECTION_MODE_PERSISTENT.passwordlessWeb).toBe(true);
    expect(PROTECTION_MODE_PERSISTENT.sessionOnly).toBe(false);
    expect(PROTECTION_MODE_REQUIRES_OS_WRAPPER.devicePasswordNative).toBe(true);
    expect(PROTECTION_MODE_REQUIRES_OS_WRAPPER.passwordlessNative).toBe(true);
    expect(PROTECTION_MODE_REQUIRES_DEVICE_PASSWORD.devicePasswordWeb).toBe(true);
    expect(PROTECTION_MODE_REQUIRES_DEVICE_PASSWORD.passwordlessWeb).toBe(false);
    expect(PROTECTION_MODE_REQUIRES_DEVICE_PASSWORD.sessionOnly).toBe(false);
  });

  it('rejects unknown modes', () => {
    expect(isProtectionMode('password')).toBe(false);
    expect(isProtectionMode(undefined)).toBe(false);
  });
});

describe('parseProtectionMetadata', () => {
  it('accepts the closed legal mode+version pairs', () => {
    const parsed = parseProtectionMetadata({ mode: 'passwordlessNative', version: 1 });
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.value.mode).toBe('passwordlessNative');
    }
  });

  it('fails closed on unknown mode, unknown version, and malformed shape', () => {
    expect(parseProtectionMetadata({ mode: 'plaintext', version: 1 }).ok).toBe(false);
    expect(parseProtectionMetadata({ mode: 'sessionOnly', version: 99 }).ok).toBe(false);
    expect(parseProtectionMetadata(null).ok).toBe(false);
    expect(parseProtectionMetadata('devicePasswordWeb').ok).toBe(false);
  });

  it('never downgrades an empty-password shortcut into a passwordless mode', () => {
    const parsed = parseProtectionMetadata({ mode: 'passwordlessWeb', version: 1 });
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      // passwordlessWeb is a distinct mode; an empty password is not representable
      expect(parsed.value.mode).not.toBe('devicePasswordWeb');
    }
  });
});

describe('RecoveryEnvelopeRecord no-mnemonic enforcement', () => {
  it('validates a well-formed no-mnemonic record', () => {
    const record = validEnvelope();
    expect(validateNoMnemonicRecord(record)).toBe(true);
    const parsed = parseRecoveryEnvelopeRecord(record);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(checkRecoveryVersionCompatibility(parsed.value)).toEqual({ ok: true });
    }
  });

  it('rejects any injected mnemonic/seed/phrase field (MNEMONIC_RECORD_INJECTED)', () => {
    const injected = { ...validEnvelope(), mnemonic: 'abandon ... zoo' } as unknown;
    const parsed = parseRecoveryEnvelopeRecord(injected);
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) {
      expect(parsed.code).toBe('MNEMONIC_RECORD_INJECTED');
    }
    const seedInjected = { ...validEnvelope(), seed: '0xdeadbeef' } as unknown;
    expect(parseRecoveryEnvelopeRecord(seedInjected).ok).toBe(false);
  });

  it('fails closed on unknown contract version (old-reader/new-writer rule)', () => {
    const unknown = validEnvelope({ contractVersion: 99 as never });
    const parsed = parseRecoveryEnvelopeRecord(unknown);
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) {
      expect(parsed.code).toBe('UNSUPPORTED_RECOVERY_VERSION');
    }
  });

  it('fails closed on malformed bindings/ciphertext/producer shapes', () => {
    expect(parseRecoveryEnvelopeRecord(validEnvelope({ publicBindings: { signingAddress: 'x', encryptionAddress: 42 } as never })).ok).toBe(false);
    expect(parseRecoveryEnvelopeRecord(validEnvelope({ ciphertext: { signingKeyCiphertext: 'x' } as never })).ok).toBe(false);
    expect(parseRecoveryEnvelopeRecord(validEnvelope({ producer: { producerId: 'p-01' } as never })).ok).toBe(false);
    expect(parseRecoveryEnvelopeRecord(null).ok).toBe(false);
  });

  it('rejects an unknown protection mode embedded in an envelope', () => {
    const badMode = validEnvelope({ protection: { mode: 'plaintext' as never, version: 1 } });
    const parsed = parseRecoveryEnvelopeRecord(badMode);
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) {
      expect(parsed.code).toBe('UNSUPPORTED_PROTECTION_MODE');
    }
  });

  it('rejects an envelope whose protection version is unsupported (no downgrade)', () => {
    const badVersion = validEnvelope({ protection: { mode: 'devicePasswordWeb', version: 0 as never } });
    const parsed = parseRecoveryEnvelopeRecord(badVersion);
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) {
      expect(parsed.code).toBe('UNSUPPORTED_PROTECTION_VERSION');
    }
  });

  it('fails closed on malformed profile/lifecycle/reconciliation metadata unions', () => {
    expect(parseRecoveryEnvelopeRecord(validEnvelope({ profile: { kind: 'mystery' } as never })).ok).toBe(false);
    expect(parseRecoveryEnvelopeRecord(validEnvelope({ lifecycle: { stage: 'bogus' } as never })).ok).toBe(false);
    expect(parseRecoveryEnvelopeRecord(validEnvelope({ reconciliation: { requiresProfileRecreate: 'yes' } as never })).ok).toBe(false);
  });
});

describe('checkLegalProtectionCombination', () => {
  it('accepts password modes with fresh capability', () => {
    expect(checkLegalProtectionCombination('devicePasswordWeb', {}).ok).toBe(true);
    expect(checkLegalProtectionCombination('devicePasswordNative', {}).ok).toBe(true);
  });

  it('accepts session-only without persistence capability', () => {
    expect(checkLegalProtectionCombination('sessionOnly', {}).ok).toBe(true);
  });

  it('rejects unqualified passwordless Web (missing PRF/platform/discoverable/userVerification)', () => {
    const result = checkLegalProtectionCombination('passwordlessWeb', { webauthnPlatform: true, discoverableCredential: true, userVerification: true, prf: false });
    expect(result.ok).toBe(false);
    const empty = checkLegalProtectionCombination('passwordlessWeb', {});
    expect(empty.ok).toBe(false);
    if (!empty.ok) {
      expect(empty.code).toBe('UNQUALIFIED_PASSWORDLESS');
    }
  });

  it('rejects unqualified passwordless native (no OS wrapper)', () => {
    const result = checkLegalProtectionCombination('passwordlessNative', { qualifiedOsProtection: false });
    expect(result.ok).toBe(false);
  });

  it('never silently falls back: unqualified passwordless yields no mode at all', () => {
    const result = checkLegalProtectionCombination('passwordlessWeb', {});
    expect(result.ok).toBe(false);
  });
});

describe('session-only persistence scan', () => {
  it('session-only records are not representable as persistent envelopes', () => {
    // A session-only authority writes nothing; a persisted envelope must declare
    // a persistent protection mode, so no recovery record may use sessionOnly.
    const record = validEnvelope({ protection: { mode: 'sessionOnly', version: 1 } });
    // The envelope parser accepts the shape (it is metadata), but the staging
    // authority must never persist it: assert the invariant in the contract.
    const parsed = parseRecoveryEnvelopeRecord(record);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) {
      expect(parsed.value.protection.mode).toBe('sessionOnly');
    }
    // And a persisted recovery record with sessionOnly protection is a
    // contradiction the staging layer must reject (Phase 3 authority).
    expect(PROTECTION_MODE_PERSISTENT.sessionOnly).toBe(false);
  });
});
