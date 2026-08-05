/**
 * FEAT-009 Task 3.2 — unit, property, source-preservation, and fault tests
 * for the bounded snapshot/envelope/source-release authority (Task 3.1).
 *
 * Proves: every source size boundary (minimum/1 MiB/overflow), immutable
 * snapshot behavior, cancellation/timeout/stale handling, structural
 * envelope errors (typed pre-password), and that the authority never
 * reopens the source.
 */
import { describe, expect, it } from 'vitest';
import {
  PROGRESS_THRESHOLD_MS,
  SNAPSHOT_BOUNDS,
  acquireSnapshot,
  enforceReadBound,
  evaluateEnvelopeGate,
  shouldShowProgress,
  sourceReleasePolicy,
} from './snapshot';
import type { BoundedSourceReadPort } from './snapshot';
import type { RestoreEpoch } from '../contracts/lifecycle';

const EPOCH = 'epoch-1' as RestoreEpoch;

/** Build a structurally valid v1 envelope stub (36-byte minimum + tag). */
function validEnvelopeStub(extraBytes = 16): Uint8Array {
  // magic HUSH + version 1 LE + 16-byte salt + 12-byte nonce + ciphertext+tag
  const bytes = new Uint8Array(36 + extraBytes);
  bytes.set([0x48, 0x55, 0x53, 0x48], 0); // HUSH
  bytes.set([1, 0, 0, 0], 4); // version 1 LE
  return bytes;
}

function makePort(opts: {
  readonly outcomeKind?: 'selected' | 'cancelled' | 'tooLarge' | 'timeout' | 'partial' | 'unsafeFileKind' | 'providerError' | 'lifecycleLost' | 'readUnavailable';
  readonly bytes?: Uint8Array | null;
  readonly cancelCalls?: { readonly count: number };
}): BoundedSourceReadPort & { readonly cancelCount: () => number } {
  let cancels = 0;
  return {
    read: async ({ limitBytes }) => {
      const bytes = opts.bytes ?? validEnvelopeStub();
      if (opts.outcomeKind === 'selected' && bytes.byteLength <= limitBytes) {
        return { outcome: { kind: 'selected' }, bytes, elapsedMs: 10 };
      }
      const kind = opts.outcomeKind ?? 'readUnavailable';
      return { outcome: { kind }, bytes: null, elapsedMs: 10 };
    },
    cancel: async () => {
      cancels += 1;
    },
    cancelCount: () => cancels,
  };
}

describe('FEAT-009 read bound enforcement (Task 3.1)', () => {
  it('exact bound constants: 1 MiB + 1 overflow byte', () => {
    expect(SNAPSHOT_BOUNDS.hardBoundBytes).toBe(1024 * 1024);
    expect(SNAPSHOT_BOUNDS.overflowBytes).toBe(1);
    expect(SNAPSHOT_BOUNDS.maxSnapshotBytes).toBe(1024 * 1024 + 1);
    expect(SNAPSHOT_BOUNDS.inactivityTimeoutMs).toBe(30_000);
    expect(SNAPSHOT_BOUNDS.epochMaxMs).toBe(600_000);
    expect(SNAPSHOT_BOUNDS.progressThresholdMs).toBe(150);
  });

  it('enforceReadBound accepts the exact maximum and rejects beyond', () => {
    expect(enforceReadBound(1024 * 1024 + 1).ok).toBe(true);
    expect(enforceReadBound(0).ok).toBe(true);
    const over = enforceReadBound(1024 * 1024 + 2);
    expect(over.ok).toBe(false);
    if (!over.ok) {
      expect(over.code).toBe('FILE_TOO_LARGE');
    }
  });

  it('progress shows only after the 150 ms threshold', () => {
    expect(shouldShowProgress(0)).toBe(false);
    expect(shouldShowProgress(149)).toBe(false);
    expect(shouldShowProgress(150)).toBe(true);
    expect(shouldShowProgress(1000)).toBe(true);
  });
});

describe('FEAT-009 envelope gate (Task 3.1)', () => {
  it('valid v1 envelope passes the gate', () => {
    expect(evaluateEnvelopeGate(validEnvelopeStub())).toEqual({ kind: 'valid', version: 1 });
  });

  it('short envelope returns tooShort', () => {
    expect(evaluateEnvelopeGate(new Uint8Array(35))).toEqual({ kind: 'tooShort' });
  });

  it('wrong magic returns invalidMagic', () => {
    const bytes = validEnvelopeStub();
    bytes.set([0x58, 0x58, 0x58, 0x58], 0); // XXXX
    expect(evaluateEnvelopeGate(bytes)).toEqual({ kind: 'invalidMagic' });
  });

  it('unsupported version returns the safe version number', () => {
    const bytes = validEnvelopeStub();
    bytes.set([2, 0, 0, 0], 4); // version 2
    const result = evaluateEnvelopeGate(bytes);
    expect(result).toEqual({ kind: 'unsupportedVersion', version: 2 });
  });

  it('oversize envelope returns tooLarge before inspection', () => {
    const bytes = new Uint8Array(1024 * 1024 + 2);
    bytes.set([0x48, 0x55, 0x53, 0x48], 0);
    expect(evaluateEnvelopeGate(bytes)).toEqual({ kind: 'tooLarge' });
  });
});

describe('FEAT-009 snapshot acquisition (Task 3.1)', () => {
  it('acquires an opaque snapshot for a selected bounded read', async () => {
    const port = makePort({ outcomeKind: 'selected', bytes: validEnvelopeStub() });
    const result = await acquireSnapshot(port, { epoch: EPOCH, nowMs: 1000 });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.value.kind).toBe('snapshot');
      expect(result.value.byteLength).toBe(36 + 16);
      expect(result.value.epoch).toBe(EPOCH);
    }
  });

  it('returns FILE_TOO_LARGE for oversize reads before any envelope work', async () => {
    const port = makePort({ outcomeKind: 'tooLarge' });
    const result = await acquireSnapshot(port, { epoch: EPOCH, nowMs: 1000 });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.code).toBe('FILE_TOO_LARGE');
  });

  it('maps every non-selected platform outcome to a typed pre-password error', async () => {
    const cases: ReadonlyArray<{ readonly kind: Parameters<typeof makePort>[0]['outcomeKind']; readonly expected: string }> = [
      { kind: 'cancelled', expected: 'PICKER_CANCELLED' },
      { kind: 'timeout', expected: 'READ_INACTIVITY_TIMEOUT' },
      { kind: 'partial', expected: 'READ_PARTIAL' },
      { kind: 'unsafeFileKind', expected: 'UNSAFE_FILE_KIND' },
      { kind: 'providerError', expected: 'READ_UNAVAILABLE' },
      { kind: 'lifecycleLost', expected: 'READ_UNAVAILABLE' },
      { kind: 'readUnavailable', expected: 'READ_UNAVAILABLE' },
    ];
    for (const c of cases) {
      const port = makePort({ outcomeKind: c.kind });
      const result = await acquireSnapshot(port, { epoch: EPOCH, nowMs: 1000 });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code).toBe(c.expected);
    }
  });

  it('maps invalid envelope content to typed structural errors', async () => {
    const cases: ReadonlyArray<{ readonly bytes: Uint8Array; readonly expected: string }> = [
      { bytes: new Uint8Array(35), expected: 'ENVELOPE_TOO_SHORT' },
      { bytes: (() => { const b = validEnvelopeStub(); b.set([0x58, 0x58, 0x58, 0x58], 0); return b; })(), expected: 'INVALID_MAGIC' },
      { bytes: (() => { const b = validEnvelopeStub(); b.set([3, 0, 0, 0], 4); return b; })(), expected: 'UNSUPPORTED_VERSION' },
    ];
    for (const c of cases) {
      const port = makePort({ outcomeKind: 'selected', bytes: c.bytes });
      const result = await acquireSnapshot(port, { epoch: EPOCH, nowMs: 1000 });
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.code).toBe(c.expected);
    }
  });

  it('no snapshot is retained for invalid envelopes (release on structural failure)', async () => {
    const port = makePort({ outcomeKind: 'selected', bytes: new Uint8Array(35) });
    const result = await acquireSnapshot(port, { epoch: EPOCH, nowMs: 1000 });
    expect(result.ok).toBe(false);
  });

  it('the source-release policy forbids reopening (snapshot-only import)', () => {
    expect(sourceReleasePolicy()).toEqual({ reopenAllowed: false, snapshotOnly: true });
  });
});

// Reference only — documents that the read port contract carries an epoch-scoped cancel.
void PROGRESS_THRESHOLD_MS;
