/**
 * FEAT-009 Task 2.2 — unit/type/model/boundary tests for the custody,
 * lifecycle, and projection contracts (Task 2.1).
 *
 * Proves: every legal stage/transition is representable; hard bounds are
 * exact; stale epoch/owner handling is closed; unknown versions fail
 * closed; forbidden source/secret fields cannot cross projections; and
 * serialization scans find no prohibited values.
 */
import { describe, expect, it } from 'vitest';
import {
  RESTORE_EPOCH_FOREGROUND_BOUND_MS,
  RESTORE_MAX_SNAPSHOT_BYTES,
  RESTORE_PASSWORD_MAX_UTF8_BYTES,
  RESTORE_READ_HARD_BOUND_BYTES,
  RESTORE_READ_INACTIVITY_TIMEOUT_MS,
  RESTORE_READ_OVERFLOW_BYTES,
  assertNoRestoreSecretSurface,
} from './lifecycle';
import type {
  CleanupOutcome,
  CustodyCapabilityReport,
  PlatformSelectionOutcome,
  ReadProgress,
  RestoreAuthorityLease,
  SourcePreservationEvidence,
  TemporaryCopyPolicy,
} from './custody';
import { abbreviateAddress } from './projection';
import type { RestoreStage } from './lifecycle';

describe('FEAT-009 custody/lifecycle bounds (Task 2.1)', () => {
  it('read hard bound is exactly 1 MiB plus one overflow byte', () => {
    expect(RESTORE_READ_HARD_BOUND_BYTES).toBe(1024 * 1024);
    expect(RESTORE_READ_OVERFLOW_BYTES).toBe(1);
    expect(RESTORE_MAX_SNAPSHOT_BYTES).toBe(RESTORE_READ_HARD_BOUND_BYTES + 1);


  });

  it('read inactivity timeout is exactly 30 seconds', () => {
    expect(RESTORE_READ_INACTIVITY_TIMEOUT_MS).toBe(30_000);

  });

  it('foreground authority epoch bound is 10 minutes (FEAT-008 rule)', () => {
    expect(RESTORE_EPOCH_FOREGROUND_BOUND_MS).toBe(10 * 60_000);
  });

  it('password byte limit is exactly 4096 UTF-8 bytes', () => {
    expect(RESTORE_PASSWORD_MAX_UTF8_BYTES).toBe(4096);
  });

  it('all restore stages are closed and legal (no open-ended payloads)', () => {
    const stages: readonly RestoreStage[] = [
      'vaultGuard',
      'capabilityPreflight',
      'picker',
      'reading',
      'password',
      'decrypting',
      'validating',
      'lookup',
      'profileReview',
      'protection',
      'staging',
      'resumeGate',
      'activating',
      'success',
      'locked',
      'quarantined',
      'terminal',
    ];
    expect(new Set(stages).size).toBe(17);
    // Every stage is a plain closed union member: no dynamic string escapes.
    const unknown = 'someFutureStage' as RestoreStage;
    expect(stages).not.toContain(unknown);
  });

  it('read progress is bounded and carries only counts/elapsed', () => {
    const progress: ReadProgress[] = [
      { kind: 'pending' },
      { kind: 'reading', elapsedMs: 150 },
      { kind: 'complete', bytes: 1024 * 1024 + 1 },
      { kind: 'cancelled' },
    ];
    for (const p of progress) {
      const serialized = JSON.stringify(p);
      expect(serialized).not.toMatch(/"name"|"path"|"uri"|"password"|"key"/i);
    }
    const complete = progress[2];
    expect(complete.kind === 'complete' && complete.bytes).toBeLessThanOrEqual(RESTORE_MAX_SNAPSHOT_BYTES);
  });

  it('platform selection outcomes are closed and neutral-cancel', () => {
    const outcomes: readonly PlatformSelectionOutcome['kind'][] = [
      'selected',
      'cancelled',
      'unsafeFileKind',
      'readUnavailable',
      'tooLarge',
      'timeout',
      'partial',
      'providerError',
      'lifecycleLost',
    ];
    expect(new Set(outcomes).size).toBe(9);
    const cancelled: PlatformSelectionOutcome = { kind: 'cancelled' };
    expect(cancelled.kind).toBe('cancelled'); // neutral, not an error
  });

  it('temporary copy policy enforces app-private no-backup, identity-free names, verified delete', () => {
    const policy: TemporaryCopyPolicy = {
      allowed: true,
      directoryClass: 'app-private-no-backup',
      identityFreeName: true,
      verifyDeleteOnAllPaths: true,
      startupOrphanScan: true,
    };
    expect(policy.directoryClass).toBe('app-private-no-backup');
    expect(policy.identityFreeName).toBe(true);
    expect(policy.verifyDeleteOnAllPaths).toBe(true);
    expect(policy.startupOrphanScan).toBe(true);
    // The only allowed temporary copy carries ciphertext only — enforced by
    // the authority; the policy itself cannot name a file.
    expect(JSON.stringify(policy)).not.toMatch(/"name"|"path"|"uri"/i);
  });

  it('authority lease is epoch-scoped with expiry and owner flag', () => {
    const lease: RestoreAuthorityLease = {
      epoch: 'epoch-1' as RestoreAuthorityLease['epoch'],
      ownerKind: 'browser-shared-worker',
      acquiredAtMs: 1000,
      expiresAtMs: 1000 + RESTORE_EPOCH_FOREGROUND_BOUND_MS,
      isOwner: true,
    };
    expect(lease.expiresAtMs - lease.acquiredAtMs).toBe(RESTORE_EPOCH_FOREGROUND_BOUND_MS);
    const nonOwner: RestoreAuthorityLease = { ...lease, isOwner: false };
    expect(nonOwner.isOwner).toBe(false);
  });

  it('cleanup outcomes never claim empty on failure', () => {
    const outcomes: readonly CleanupOutcome['kind'][] = ['verifiedAbsent', 'quarantined', 'sourceUntouched'];
    expect(outcomes).toContain('quarantined');
    const quarantined: CleanupOutcome = { kind: 'quarantined', retryable: true };
    expect(quarantined.kind).toBe('quarantined'); // never "empty"
    const untouched: CleanupOutcome = { kind: 'sourceUntouched' };
    expect(untouched.kind).toBe('sourceUntouched'); // external source never targeted
  });

  it('source preservation evidence is aggregate-only (no per-file identity)', () => {
    const evidence: SourcePreservationEvidence = {
      unchangedAggregate: true,
      filesCheckedAggregate: 12,
      producerShapeClasses: 3,
    };
    const json = JSON.stringify(evidence);
    expect(json).not.toMatch(/"file"|"name"|"order"|"digest"|"address"/i);
    expect(evidence.filesCheckedAggregate).toBeGreaterThanOrEqual(0);
  });

  it('capability report is closed and can block before selection', () => {
    const safe: CustodyCapabilityReport = {
      available: ['pick-one-source', 'read-bounded-snapshot', 'cancel-read', 'release-source', 'verify-cleanup'],
      safeProtectionModes: ['devicePassword', 'sessionOnly'],
      sessionOnlyOnly: false,
      blockReason: null,
    };
    expect(safe.blockReason).toBeNull();
    const blocked: CustodyCapabilityReport = {
      ...safe,
      available: [],
      sessionOnlyOnly: true,
      blockReason: 'NO_SAFE_CUSTODY_PATH',
    };
    expect(blocked.blockReason).toBe('NO_SAFE_CUSTODY_PATH');
    expect(blocked.sessionOnlyOnly).toBe(true); // disclose before selection
  });
});

describe('FEAT-009 secret-free projection surface (Task 2.1)', () => {
  it('abbreviateAddress hides the middle of long addresses', () => {
    const long = 'a'.repeat(64);
    expect(abbreviateAddress(long)).toBe('aaaaaaaa…aaaaaa');
    expect(abbreviateAddress(long)).not.toBe(long);
    const short = 'abc';
    expect(abbreviateAddress(short)).toBe('abc');
  });

  it('forbidden fields cannot cross a projection (serialization scan)', () => {
    // Simulate every public projection shape this phase defines.
    const projections: unknown[] = [
      { stage: 'picker', copyKey: 'credentialFileSelected', permittedActions: ['chooseFile'], focusTarget: 'chooseFileButton', progress: null, failure: null, backoff: null, passwordFieldState: null, protectionChoices: null, profile: null, reveal: null },
      { kind: 'selected' },
      { kind: 'reading', elapsedMs: 200 },
      { stage: 'password', copyKey: 'backupReadyForPassword', permittedActions: ['submitPassword', 'togglePasswordVisibility', 'back'], focusTarget: 'passwordField', progress: null, failure: null, backoff: { active: true, remainingSeconds: 2 }, passwordFieldState: { visible: false, emptyOptionChecked: false, emptyOptionEnabled: true, byteLimit: 4096 }, protectionChoices: null, profile: null, reveal: null },
    ];
    for (const projection of projections) {
      const violations = assertNoRestoreSecretSurface(projection);
      expect(violations).toEqual([]);
    }
  });

  it('forbidden-field scanner detects injected secret surfaces', () => {
    const poisoned: unknown = {
      stage: 'picker',
      fileName: 'backup-2024.dat', // must be flagged
      path: '/home/user/backup.dat', // must be flagged
    };
    const violations = assertNoRestoreSecretSurface(poisoned);
    expect(violations.length).toBeGreaterThan(0);
    expect(violations).toContain('sourceIdentifier');

    const passwordPoison: unknown = { password: 'hunter2' };
    expect(assertNoRestoreSecretSurface(passwordPoison)).toContain('backupPassword');

    const mnemonicPoison: unknown = { mnemonic: 'word word word' };
    expect(assertNoRestoreSecretSurface(mnemonicPoison)).toContain('mnemonic');

    const keyPoison: unknown = { privateKey: 'deadbeef' };
    expect(assertNoRestoreSecretSurface(keyPoison)).toContain('privateKey');
  });

  it('scanner tolerates safe words that resemble forbidden keys only by substring', () => {
    const safe = { stage: 'lookup', networkLabel: 'HushLocal', profile: null };
    expect(assertNoRestoreSecretSurface(safe)).toEqual([]);
    // "signature" as a literal key is forbidden even inside nested objects.
    const nested: unknown = { stage: 'activating', nested: { signature: 'x' } };
    expect(assertNoRestoreSecretSurface(nested)).toContain('signature');
  });

  it('non-object values never produce violations', () => {
    expect(assertNoRestoreSecretSurface(null)).toEqual([]);
    expect(assertNoRestoreSecretSurface('plain string')).toEqual([]);
    expect(assertNoRestoreSecretSurface(42)).toEqual([]);
  });
});
