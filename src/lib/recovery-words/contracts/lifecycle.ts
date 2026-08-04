/**
 * FEAT-008 recovery-words — recovery lifecycle and operation contracts.
 *
 * Framework-neutral (no React, Next.js, DOM, storage, transport, or
 * state-store dependencies). Defines the closed vocabulary for the Recovery
 * Words workflow: typed stages, opaque epoch/operation ownership, typed
 * failures, retention/destruction events, and completion states.
 *
 * SECRET BOUNDARY: nothing in this module can represent recovery words, a
 * seed, a private key, a Device password, WebAuthn PRF output, a full
 * candidate set with linkage, a credential reference, or a transaction.
 * The secret authority (browser worker / Ubuntu / Android) owns all
 * credential material; the machine receives only opaque references and
 * safe typed outcomes.
 *
 * Normative source: FEAT-008 FeatureDescription "Recovery-Word Entry
 * Contract", "Transient Mnemonic Custody and No-Persistence Rule",
 * "Candidate Outcome UX", "Error Model", "Restart and Resume", "Concurrency
 * and Ownership", "Cleanup and Logout"; FEAT-002 secret-free ports;
 * FEAT-003 lifecycle vocabulary; FEAT-007 creation lifecycle vocabulary.
 */

/** Opaque recovery operation identifier issued by the authority (never a secret). */
export type RecoveryOperationId = string & { readonly __recoveryOperationId: unique symbol };

/** Opaque recovery epoch; results with a stale epoch are ignored. */
export type RecoveryEpoch = string & { readonly __recoveryEpoch: unique symbol };

/**
 * Canonical network identifier to which lookup, protection context, staged
 * data, and registration are bound. It is a stable chain/network identity,
 * not merely a server URL. Network change invalidates the complete
 * lookup/selection/stage and requires fresh word entry.
 */
export type NetworkIdentifier = string & { readonly __networkIdentifier: unique symbol };

/**
 * Typed recovery workflow stage. Visible URL stays `/`; stages are typed
 * in-memory application state. A stage may expose only actions permitted by
 * the current authority epoch.
 */
export type RecoveryStage =
  // Entry guard — FEAT-008 may start only from verified-empty local state.
  | 'vaultGuard' // authoritative platform inspection: no active/staged/rollback/quarantine/competing authority
  | 'networkLabel' // canonical target network confirmation
  // Word entry — dedicated uncontrolled component owns the phrase buffer.
  | 'wordEntry' // 12/24 selection, indexed grid, paste, validation, concealment
  | 'verifying' // one bounded phrase handoff to the authority; page buffers clear
  | 'deriving' // every applicable Approved public candidate derived (progress after 150 ms)
  | 'lookup' // complete sequential public lookup (safe counted progress)
  | 'resolving' // zero/one/multiple outcome assembly; never partial
  | 'candidateSelection' // source-guided no-default selection (zero-match multiple)
  | 'profileSelection' // explicit no-default blockchain-profile selection (multiple existing)
  | 'proof' // selected-key local signing/encryption consistency proof
  | 'protection' // non-retention acknowledgement + protection-mode choice
  | 'staging' // encrypted selected-key stage write + read-back verification
  | 'existingProfileVerify' // fresh exact GetIdentity before activation
  | 'recreateReview' // explicit missing-profile review (alias empty, visibility Private, Public ack)
  | 'registration' // FEAT-007 unchanged registration/polling/confirmation lifecycle
  | 'activating' // atomic activation after exact online verification
  | 'success' // Identity restored; announced once; dashboard transition automatic
  // Restart and resume — staged keys exist; words are gone and unrecoverable.
  | 'finishRestoring' // non-authenticated staged gate; blocks Create/Restore
  // Lifecycle and failure surfaces.
  | 'locked' // lifecycle lock; Lock retains the local identity
  | 'quarantined' // cleanup failure; first-run recovery blocked until verified absence
  | 'terminal'; // fail-closed terminal state (corruption/unknown outcome)

/** Closed typed recovery failures (safe; never echo words/keys/addresses). */
export type RecoveryFailureCode =
  // Entry and input
  | 'VAULT_NOT_VERIFIED_EMPTY' // competing/local authority exists; FEAT-008 not startable
  | 'WRONG_COUNT' // expected vs actual count; no partial paste
  | 'UNKNOWN_WORD' // numbered positions; no echo/autocorrection
  | 'CHECKSUM_FAILURE' // phrase-wide; never suggests replacement words
  | 'UNSUPPORTED_INPUT' // unsupported count/language/optional passphrase
  // Mnemonic custody and candidate derivation
  | 'PRODUCER_DERIVATION_FAILURE' // applicable-producer derivation/encoding failed; complete set rejected
  | 'PARTIAL_CANDIDATE_LOOKUP' // timeout/transport/malformed/contradictory; never absence
  | 'SIGNING_ENCRYPTION_MISMATCH' // exact both-key equality failed; signing-only fails closed
  | 'EPOCH_EXPIRED' // unprovisioned authority exceeded the 10-minute foreground epoch
  | 'STALE_EPOCH' // result from a stale epoch/operation; rejected without state mutation
  | 'DOUBLE_DISPATCH' // a second validation/derivation command while one is in flight
  | 'OWNERSHIP_LOST' // another tab/window/process owns the recovery epoch
  // Lookup and resolution
  | 'NETWORK_UNAVAILABLE' // transport failure; never profile absence; remain gated
  | 'MALFORMED_PROFILE' // grossly malformed/oversized server profile; fail closed
  // Protection and staging
  | 'PROTECTION_CANCELLED' // password/WebAuthn/OS cancellation; preserve pre-stage flow within epoch
  | 'ENCRYPTED_STAGE_FAILURE' // stage write/read-back failed; destroy keying state; never activate
  | 'STAGED_RESTART_FAILURE' // staged data corrupt/unsupported version; fail closed
  // Profile verification and registration
  | 'PROFILE_DISAPPEARED' // earlier match absent at final verification; explicit recreate review
  | 'REGISTRATION_REJECTED' // FEAT-007 closed status/code mapping
  | 'REGISTRATION_PENDING' // FEAT-007 wait-only behavior
  // Cleanup and unknown outcomes
  | 'CLEANUP_FAILURE' // verified absence impossible; quarantine
  | 'QUARANTINED' // quarantine blocks first-run until verified absence
  | 'UNKNOWN_OUTCOME' // unknown/contradictory outcome; fail closed; no free-form parsing
  // Envelope/protection parsing (additive no-mnemonic contract)
  | 'ENVELOPE_MALFORMED' // recovery record shape invalid
  | 'MNEMONIC_RECORD_INJECTED' // mnemonic/seed/phrase field present; record rejected
  | 'UNSUPPORTED_RECOVERY_VERSION' // recovery record contract version unknown
  | 'PROTECTION_METADATA_INVALID' // protection metadata malformed
  | 'UNSUPPORTED_PROTECTION_MODE' // protection mode unknown; fail closed without downgrade
  | 'UNSUPPORTED_PROTECTION_VERSION' // protection metadata version unknown
  | 'UNQUALIFIED_PASSWORDLESS' // passwordless capability missing; persistence unavailable; no silent fallback;

export interface RecoveryFailure {
  readonly ok: false;
  readonly code: RecoveryFailureCode;
  /** Safe diagnostic text; never contains words, keys, addresses, credentials, or transaction material. */
  readonly message: string;
  /** Sanitized support code (opaque, safe). */
  readonly supportCode: string;
}

export type RecoveryResult<T> = { readonly ok: true; readonly value: T } | RecoveryFailure;

/**
 * Retention/destruction events — the authoritative audit vocabulary for the
 * no-persistence rule. The authority emits these; the machine records counts
 * and coarse timing classes only (never the phrase or derived material).
 */
export type RecoveryRetentionEvent =
  | 'phraseTransferred' // one bounded phrase handed to the authority
  | 'pageInputsCleared' // page buffers cleared; history cannot restore them
  | 'candidatesResolved' // complete public candidate set assembled
  | 'selectedKeysDerived' // private credentials derived for the selected producer only
  | 'proofPassed' // local signing/encryption consistency proof succeeded
  | 'stageCommitted' // encrypted selected-key stage written and read-back verified
  | 'mnemonicDestroyedPersistent' // mnemonic/seed/intermediates destroyed before online verification
  | 'mnemonicDestroyedSession' // mnemonic/seed/intermediates destroyed after isolated install
  | 'epochCleared' // candidate outcomes/protection state cleared at epoch end
  | 'cleanupVerified' // verified local absence after removal/cancellation
  | 'quarantineRaised'; // cleanup could not verify absence; FEAT-008 blocked

/** Completion states — the only terminal outcomes of the recovery workflow. */
export type RecoveryCompletionState =
  | 'restoredExistingProfile' // exact both-key online verification, existing profile
  | 'createdMissingProfile' // exact-key FEAT-007 registration confirmed (or in flight persistent)
  | 'sessionOnlyRestored' // explicit session-only authority; nothing persisted
  | 'cancelled' // verified cancellation; no local user created
  | 'quarantined'; // terminal quarantine; requires verified cleanup before first-run

/** Safe operational evidence category (privacy-safe; no secrets, no full addresses). */
export type RecoveryEvidenceCategory =
  | 'vault-guard-passed'
  | 'phrase-transferred'
  | 'page-inputs-cleared'
  | 'candidates-derived'
  | 'lookup-complete'
  | 'lookup-incomplete'
  | 'candidate-selected'
  | 'proof-passed'
  | 'protection-chosen'
  | 'stage-committed'
  | 'mnemonic-destroyed'
  | 'existing-profile-activated'
  | 'missing-profile-created'
  | 'session-only-activated'
  | 'restart-resumed'
  | 'back-destroyed'
  | 'owner-blocked'
  | 'cleanup-verified'
  | 'quarantined'
  | 'compatibility-error';

/** Compile-time + runtime proof that no generic secret surface is representable. */
export type ForbiddenRecoverySecretSurface =
  | 'mnemonic'
  | 'seed'
  | 'privateKey'
  | 'devicePassword'
  | 'prfOutput'
  | 'wrappingKey'
  | 'fullAddress'
  | 'credentialId'
  | 'transaction'
  | 'signature'
  | 'genericCapability';

export function assertNoSecretSurface(value: unknown): ForbiddenRecoverySecretSurface[] {
  const violations: ForbiddenRecoverySecretSurface[] = [];
  if (value === null || typeof value !== 'object') {
    return violations;
  }
  const json = JSON.stringify(value);
  if (!json) {
    return violations;
  }
  const keyHits = [
    'mnemonic',
    'seed',
    'privateKey',
    'devicePassword',
    'prfOutput',
    'wrappingKey',
    'fullAddress',
    'credentialId',
    'transaction',
    'signature',
  ] as const;
  for (const key of keyHits) {
    if (json.toLowerCase().includes(`"${key}"`)) {
      violations.push(key as ForbiddenRecoverySecretSurface);
    }
  }
  // Heuristic guards against accidental embedding of encoded secret material.
  if (json.includes('PRIVATE KEY') || json.includes('BEGIN')) {
    violations.push('privateKey');
  }
  if (json.includes('recovery words') && json.includes('paste')) {
    violations.push('mnemonic');
  }
  return violations;
}
