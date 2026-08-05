/**
 * FEAT-009 credential-file restore authority — bounded snapshot, envelope
 * gate, and source-release policy (Task 3.1).
 *
 * Framework-neutral workflow policy. Owns the rules for one epoch-scoped
 * authority operation: verified-empty custody preflight, one platform
 * source, a capped immutable snapshot (1 MiB + one overflow byte), the
 * pre-password envelope gate, progress/cancel/timeout handling, and
 * deterministic release of every source capability. Platform adapters
 * supply the bounded byte stream through a narrow port; this module never
 * holds source identifiers, paths, URIs, or descriptors.
 *
 * SECRET BOUNDARY: source bytes enter only as one bounded Uint8Array
 * parameter; the snapshot reference returned is opaque (byte count + epoch
 * only). No name/path/URI/provider/digest is representable.
 *
 * Normative source: FEAT-009 FeatureDescription "Entry and Capability
 * Preflight", "Bounded Read Lifecycle", "Temporary Copies", "Structural
 * bounds", "Source Preservation and Cleanup"; FEAT-001 envelope contract.
 */
import { inspectDatEnvelope } from '../../identity-compatibility/dat';
import {
  RESTORE_MAX_SNAPSHOT_BYTES,
  RESTORE_READ_HARD_BOUND_BYTES,
  RESTORE_READ_INACTIVITY_TIMEOUT_MS,
} from '../contracts/lifecycle';
import type { RestoreEpoch, RestoreFailure, RestoreResult } from '../contracts/lifecycle';
import type { PlatformSelectionOutcome, ReadProgress } from '../contracts/custody';

/** Unprovisioned foreground authority epoch (10 minutes; FEAT-008 rule). */
export const RESTORE_EPOCH_MAX_MS = 600_000 as const;
/** Show read/decrypt/validate progress after this threshold. */
export const PROGRESS_THRESHOLD_MS = 150 as const;

/** Narrow platform read port — supplies exactly one bounded stream attempt. */
export interface BoundedSourceReadPort {
  /** Opens and reads at most `limit` bytes; resolves when done/cancelled/failed. */
  read(opts: { readonly epoch: RestoreEpoch; readonly limitBytes: number; readonly inactivityTimeoutMs: number }): Promise<{
    readonly outcome: PlatformSelectionOutcome;
    readonly bytes: Uint8Array | null; // null on every non-selected outcome
    readonly elapsedMs: number;
  }>;
  /** Cancels an in-flight read; resolves after handles/grants are released. */
  cancel(opts: { readonly epoch: RestoreEpoch }): Promise<void>;
}

/** One accepted immutable snapshot (opaque reference; byte count only). */
export interface AcceptedSnapshot {
  readonly kind: 'snapshot';
  readonly epoch: RestoreEpoch;
  readonly byteLength: number;
  readonly acceptedAtMs: number;
}

export type SnapshotResult = RestoreResult<AcceptedSnapshot>;

const failure = (code: RestoreFailure['code'], message: string): RestoreFailure => ({ ok: false, code, message, supportCode: `SNAP-${code}` });

/** Cap a read to 1 MiB + one overflow byte; reject anything larger. */
export function enforceReadBound(byteLength: number): { readonly ok: true } | { readonly ok: false; readonly code: 'FILE_TOO_LARGE' } {
  if (byteLength > RESTORE_MAX_SNAPSHOT_BYTES) {
    return { ok: false, code: 'FILE_TOO_LARGE' };
  }
  return { ok: true };
}

/** Pre-password envelope gate over the immutable snapshot (Task 3.1). */
export type EnvelopeGateOutcome =
  | { readonly kind: 'valid'; readonly version: 1 }
  | { readonly kind: 'tooShort' }
  | { readonly kind: 'tooLarge' }
  | { readonly kind: 'invalidMagic' }
  | { readonly kind: 'unsupportedVersion'; readonly version: number };

/** Map the FEAT-001 envelope inspection result to the closed FEAT-009 gate. */
export function evaluateEnvelopeGate(envelope: Uint8Array): EnvelopeGateOutcome {
  if (envelope.byteLength > RESTORE_MAX_SNAPSHOT_BYTES) {
    return { kind: 'tooLarge' };
  }
  const inspection = inspectDatEnvelope(envelope);
  if (!inspection.ok) {
    switch (inspection.code) {
      case 'DAT_MALFORMED':
        return envelope.byteLength < 36 ? { kind: 'tooShort' } : { kind: 'tooLarge' };
      case 'DAT_INVALID_MAGIC':
        return { kind: 'invalidMagic' };
      case 'DAT_UNSUPPORTED_VERSION': {
        // Safe structural number only (int32 LE at offset 4); never content.
        const view = new DataView(envelope.buffer, envelope.byteOffset + 4, 4);
        return { kind: 'unsupportedVersion', version: view.getInt32(0, true) };
      }
      default:
        return { kind: 'invalidMagic' };
    }
  }
  return { kind: 'valid', version: 1 };
}

/** Envelope gate result type for the authority. */
export type EnvelopeGateResult = RestoreResult<{ readonly outcome: EnvelopeGateOutcome; readonly snapshot: AcceptedSnapshot }>;

/**
 * Accept one bounded platform read into an immutable snapshot, apply the
 * read bound, run the pre-password envelope gate, and return the opaque
 * snapshot reference. On every non-selected/oversize/partial outcome the
 * caller must treat the source as released (no handles survive the port's
 * promise resolution). Envelope failures are typed pre-password errors;
 * no password work occurs and no snapshot is retained for invalid
 * envelopes.
 */
export async function acquireSnapshot(
  port: BoundedSourceReadPort,
  opts: { readonly epoch: RestoreEpoch; readonly nowMs: number },
): Promise<SnapshotResult> {
  const read = await port.read({
    epoch: opts.epoch,
    limitBytes: RESTORE_MAX_SNAPSHOT_BYTES,
    inactivityTimeoutMs: RESTORE_READ_INACTIVITY_TIMEOUT_MS,
  });
  if (read.outcome.kind !== 'selected') {
    switch (read.outcome.kind) {
      case 'tooLarge':
        return failure('FILE_TOO_LARGE', 'source exceeds the 1 MiB read bound');
      case 'timeout':
        return failure('READ_INACTIVITY_TIMEOUT', 'source read exceeded the inactivity budget');
      case 'partial':
        return failure('READ_PARTIAL', 'source read ended with partial bytes');
      case 'cancelled':
        return failure('PICKER_CANCELLED', 'source selection was cancelled');
      case 'unsafeFileKind':
        return failure('UNSAFE_FILE_KIND', 'source is not a safe regular file');
      case 'providerError':
        return failure('READ_UNAVAILABLE', 'source provider reported an error');
      case 'lifecycleLost':
        return failure('READ_UNAVAILABLE', 'source custody was lost');
      default:
        return failure('READ_UNAVAILABLE', 'source read did not complete');
    }
  }
  if (read.bytes === null) {
    return failure('READ_PARTIAL', 'source read returned no bytes');
  }
  const bound = enforceReadBound(read.bytes.byteLength);
  if (!bound.ok) {
    return failure('FILE_TOO_LARGE', 'source exceeds the 1 MiB read bound');
  }
  const gate = evaluateEnvelopeGate(read.bytes);
  if (gate.kind === 'tooShort') {
    return failure('ENVELOPE_TOO_SHORT', 'source envelope is shorter than the structural minimum');
  }
  if (gate.kind === 'tooLarge') {
    return failure('ENVELOPE_OVERSIZE', 'source envelope exceeds the size bound');
  }
  if (gate.kind === 'invalidMagic') {
    return failure('INVALID_MAGIC', 'source envelope has invalid magic');
  }
  if (gate.kind === 'unsupportedVersion') {
    return failure('UNSUPPORTED_VERSION', 'source envelope version is not supported');
  }
  return {
    ok: true,
    value: {
      kind: 'snapshot',
      epoch: opts.epoch,
      byteLength: read.bytes.byteLength,
      acceptedAtMs: opts.nowMs,
    },
  };
}

/** Release contract: the authority never reopens the source; snapshot-only. */
export function sourceReleasePolicy(): { readonly reopenAllowed: false; readonly snapshotOnly: true } {
  return { reopenAllowed: false, snapshotOnly: true };
}

/** Bound/epoch constants for tests and callers. */
export const SNAPSHOT_BOUNDS = {
  hardBoundBytes: RESTORE_READ_HARD_BOUND_BYTES,
  overflowBytes: 1,
  maxSnapshotBytes: RESTORE_MAX_SNAPSHOT_BYTES,
  inactivityTimeoutMs: RESTORE_READ_INACTIVITY_TIMEOUT_MS,
  epochMaxMs: RESTORE_EPOCH_MAX_MS,
  progressThresholdMs: PROGRESS_THRESHOLD_MS,
} as const;

/** Coarse progress helper: show after the 150 ms threshold. */
export function shouldShowProgress(elapsedMs: number): boolean {
  return elapsedMs >= PROGRESS_THRESHOLD_MS;
}

export type { ReadProgress };
