/**
 * FEAT-009 credential-file restore — source custody contracts.
 *
 * Framework-neutral. Defines the closed vocabulary for platform source
 * acquisition: one source per attempt, bounded read lifecycle, immutable
 * snapshot, cancellation, safe platform outcomes, temporary ciphertext
 * policy, source release, and ownership/epoch metadata. Platform adapters
 * (browser File, Ubuntu native, Android SAF) map their native results into
 * these closed types; native identifiers never cross the boundary.
 *
 * SECRET BOUNDARY: no custody type can carry a source name, path, URI,
 * provider, descriptor, digest, stable identifier, source byte, or generic
 * capability. The platform authority owns all such values.
 *
 * Normative source: FEAT-009 FeatureDescription "File Picker UX",
 * "Bounded Read Lifecycle", "Temporary Copies", "Concurrency and
 * Ownership", "Source Preservation and Cleanup".
 */

import type { RestoreEpoch, RestoreFailure, RestoreOperationId, RestoreResult } from './lifecycle.js';

/** Coarse bounded read progress (never exposes byte content or identifiers). */
export type ReadProgress =
  | { readonly kind: 'pending' } // not started
  | { readonly kind: 'reading'; readonly elapsedMs: number } // bounded elapsed; may reset on progress
  | { readonly kind: 'complete'; readonly bytes: number } // bytes read (≤ bound+1); count only
  | { readonly kind: 'cancelled' };

/** Closed platform custody outcome — the ONLY payloads that cross to the UI. */
export type PlatformSelectionOutcome =
  | { readonly kind: 'selected' } // exactly one source accepted; UI shows "Credential file selected"
  | { readonly kind: 'cancelled' } // neutral; clears every handle/secret/status reference
  | { readonly kind: 'unsafeFileKind' } // directory/device/FIFO/socket (native)
  | { readonly kind: 'readUnavailable' } // unreadable/cancelled read
  | { readonly kind: 'tooLarge' } // overflow byte observed
  | { readonly kind: 'timeout' } // 30s inactivity
  | { readonly kind: 'partial' } // truncated stream; never parsed/decrypted/cached
  | { readonly kind: 'providerError' } // Android remote-provider error
  | { readonly kind: 'lifecycleLost' }; // background/process/lifecycle loss; state released

/** Immutable snapshot reference owned by the authority (opaque; no bytes in state). */
export interface ImportSnapshotReference {
  readonly kind: 'importSnapshot';
  readonly epoch: RestoreEpoch;
  readonly operationId: RestoreOperationId;
  /** Ciphertext byte length as read (count only; content stays inside the authority). */
  readonly byteLength: number;
  readonly acceptedAtMs: number;
}

/** Temporary ciphertext copy policy (only when a bridge unavoidably requires one). */
export interface TemporaryCopyPolicy {
  readonly allowed: boolean; // false = prefer no temporary copy at all
  readonly directoryClass: 'app-private-no-backup';
  readonly identityFreeName: boolean; // never includes original name/path/URI/identity
  readonly verifyDeleteOnAllPaths: boolean; // success/failure/cancel/lifecycle/startup
  readonly startupOrphanScan: boolean;
}

/** Authority epoch/ownership metadata (no secret, no identity data). */
export interface RestoreAuthorityLease {
  readonly epoch: RestoreEpoch;
  readonly ownerKind: 'browser-shared-worker' | 'ubuntu-process' | 'android-process';
  readonly acquiredAtMs: number;
  readonly expiresAtMs: number; // epoch foreground bound (10 minutes unprovisioned)
  readonly isOwner: boolean; // false ⇒ non-owner blocked state
}

/** Closed cleanup result (never "empty" on failure). */
export type CleanupOutcome =
  | { readonly kind: 'verifiedAbsent' } // verified local absence; first-run paths allowed
  | { readonly kind: 'quarantined'; readonly retryable: boolean } // cleanup failure blocks Create/Restore
  | { readonly kind: 'sourceUntouched' }; // external source never targeted by any cleanup

/** Source preservation evidence: aggregate-only, in-process comparison. */
export interface SourcePreservationEvidence {
  readonly unchangedAggregate: boolean; // before/after comparison inside the test process
  readonly filesCheckedAggregate: number; // count only; no per-file identity/order/digest
  readonly producerShapeClasses: number; // count of covered producer/shape classes
}

/** Custody capability registry — the closed set of legal FEAT-009 custody operations. */
export type RestoreCustodyCapability =
  | 'pick-one-source'
  | 'read-bounded-snapshot'
  | 'cancel-read'
  | 'release-source'
  | 'verify-cleanup';

export interface CustodyCapabilityReport {
  readonly available: readonly RestoreCustodyCapability[];
  readonly safeProtectionModes: readonly string[]; // closed protection mode ids (FEAT-008 vocabulary)
  readonly sessionOnlyOnly: boolean; // disclose before selection when only session-only is safe
  readonly blockReason: RestoreFailure['code'] | null; // null ⇒ safe to proceed
}

export type CustodyResult = RestoreResult<ImportSnapshotReference>;

export interface CustodyContract {
  readonly epoch: RestoreEpoch;
  readonly capabilityReport: CustodyCapabilityReport;
  readonly temporaryCopyPolicy: TemporaryCopyPolicy;
  readonly readBoundBytes: number; // 1 MiB + 1 overflow byte
  readonly readInactivityTimeoutMs: number; // 30,000
}
