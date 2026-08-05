/**
 * FEAT-009 credential-file restore — source custody and lifecycle contracts.
 *
 * Framework-neutral (no React, Next.js, DOM, storage, transport, or
 * state-store dependencies). Defines the closed vocabulary for the
 * Restore Credential File workflow: typed custody stages, one active
 * authority epoch, opaque operation ownership, bounded read outcomes,
 * cancellation, source release, ownership, navigation, cleanup, and
 * quarantine.
 *
 * SECRET BOUNDARY: nothing in this module can represent a source name,
 * path, URI, provider, descriptor, digest, stable identifier, source byte,
 * Backup-file password, derived AES key, plaintext, mnemonic, private key,
 * full address, exact transaction, or generic capability. The secret
 * authority owns all source and credential material; the machine receives
 * only opaque references and safe typed outcomes.
 *
 * Normative source: FEAT-009 FeatureDescription "Entry and Capability
 * Preflight", "File Picker UX", "Bounded Read Lifecycle", "Source Release
 * Boundary", "Navigation and Back", "Concurrency and Ownership", "Source
 * Preservation and Cleanup"; FEAT-002 secret-free auth ports; FEAT-003
 * lifecycle/epoch vocabulary; FEAT-004 browser authority coordination.
 */

/** Opaque file-restore operation identifier issued by the authority (never a secret). */
export type RestoreOperationId = string & { readonly __restoreOperationId: unique symbol };

/** Opaque restore epoch; results with a stale epoch are ignored. */
export type RestoreEpoch = string & { readonly __restoreEpoch: unique symbol };

/**
 * Bounded snapshot size contract. The authority reads at most 1 MiB plus one
 * overflow byte; any observation of the overflow byte stops the read with a
 * typed oversize outcome before decryption or full parse.
 */
export const RESTORE_READ_HARD_BOUND_BYTES = 1024 * 1024; // 1 MiB
export const RESTORE_READ_OVERFLOW_BYTES = 1;
export const RESTORE_MAX_SNAPSHOT_BYTES = RESTORE_READ_HARD_BOUND_BYTES + RESTORE_READ_OVERFLOW_BYTES;

/** Open/read inactivity timeout for platform source streams (30 seconds). */
export const RESTORE_READ_INACTIVITY_TIMEOUT_MS = 30_000;

/** Foreground authority epoch bound for unprovisioned restore (FEAT-008 10-minute rule). */
export const RESTORE_EPOCH_FOREGROUND_BOUND_MS = 10 * 60_000;

/** Maximum Backup-file password bytes before PBKDF2 (4,096 UTF-8 bytes). */
export const RESTORE_PASSWORD_MAX_UTF8_BYTES = 4096;

/**
 * Typed restore workflow stage. Visible URL stays `/`; stages are typed
 * in-memory application state. A stage may expose only actions permitted by
 * the current authority epoch.
 */
export type RestoreStage =
  // Entry guard — FEAT-009 may start only from verified-empty local state.
  | 'vaultGuard' // authoritative inspection: no active/staged/rollback/removal/quarantined/competing authority
  | 'capabilityPreflight' // safe protection/custody capability proof before picker
  | 'picker' // one-source platform selection (cancel is neutral)
  | 'reading' // bounded read with progress/Cancel; never parses partial input
  | 'password' // "Backup ready for password"; purpose-specific uncontrolled field
  | 'decrypting' // exactly one PBKDF2/AES-GCM attempt inside the authority
  | 'validating' // strict payload parse + concrete both-pair proof (+ optional mnemonic consistency)
  | 'lookup' // unchanged unsigned public GetIdentity after local proof and source release
  | 'profileReview' // missing-profile explicit review (same-key explanation, current alias/Public rules)
  | 'protection' // separate FEAT-008 protection-mode selection (backup password state destroyed)
  | 'staging' // encrypted verified-concrete-key stage write + read-back verification
  | 'resumeGate' // "Finish restoring your identity" (non-authenticated staged gate)
  | 'activating' // fresh exact online verification or exact FEAT-007 block confirmation
  | 'success' // Identity restored; announced once; dashboard transition automatic
  // Lifecycle and failure surfaces.
  | 'locked' // lifecycle lock; Lock retains the configured local identity
  | 'quarantined' // cleanup failure; Create/Restore blocked until verified absence
  | 'terminal'; // fail-closed terminal state (unknown/contradictory outcome)

/** Closed typed restore failures (safe; never echo source/credential values). */
export type RestoreFailureCode =
  // Entry and preflight
  | 'VAULT_NOT_VERIFIED_EMPTY' // competing/local authority exists; FEAT-009 not startable
  | 'NO_SAFE_CUSTODY_PATH' // capability preflight found no safe authority/protection mode
  | 'SESSION_ONLY_ONLY' // disclosure: only session-only is safe; requires explicit acknowledgement
  // Picker and read
  | 'PICKER_CANCELLED' // neutral; cleared every handle/secret/status reference
  | 'UNSAFE_FILE_KIND' // directory/device/FIFO/socket (native); safe regular files only
  | 'FILE_TOO_LARGE' // overflow byte observed; oversize before decryption
  | 'READ_UNAVAILABLE' // unreadable/cancelled source read
  | 'READ_INACTIVITY_TIMEOUT' // 30s open/read inactivity; partial cleared
  | 'READ_PARTIAL' // partial stream; never parsed/decrypted/cached
  | 'TEMP_CLEANUP_FAILED' // temporary ciphertext delete/verify failed; quarantine
  // Envelope and password
  | 'ENVELOPE_TOO_SHORT' // below structural minimum (36 bytes)
  | 'ENVELOPE_OVERSIZE' // exceeds 1 MiB+overflow bound
  | 'INVALID_MAGIC' // wrong magic (safe pre-password error)
  | 'UNSUPPORTED_VERSION' // not v1 (safe pre-password error)
  | 'PASSWORD_TOO_LONG' // over 4,096 UTF-8 bytes; rejected before PBKDF2
  | 'AUTHENTICATION_FAILED' // combined wrong-password-or-damaged outcome; never claims cause
  | 'BACKOFF_ACTIVE' // authority-wide delay in effect for this attempt
  // Strict payload and proof
  | 'PAYLOAD_NOT_JSON' // authenticated text is not well-formed JSON
  | 'PAYLOAD_DUPLICATE_FIELD' // duplicate property rejected before object construction
  | 'PAYLOAD_UNKNOWN_FIELD' // unknown property
  | 'PAYLOAD_MISSING_FIELD' // missing required property
  | 'PAYLOAD_INVALID_FIELD' // wrong-type/null-disallowed/oversized/bound violation
  | 'UNSUPPORTED_KEY_ENCODING' // malformed/unsupported key encoding or algorithm
  | 'SIGNING_KEY_MISMATCH' // private→public derivation mismatch (typed internal code)
  | 'ENCRYPTION_KEY_MISMATCH' // encryption pair mismatch (typed internal code)
  | 'KEY_PROOF_FAILED' // domain-separated signing/encryption consistency proof failed
  | 'MNEMONIC_KEY_MISMATCH' // optional mnemonic does not derive both pairs
  // Lookup and resolution
  | 'LOOKUP_TRANSPORT_FAILURE' // transport failure; never profile absence; remain gated
  | 'LOOKUP_MALFORMED' // grossly malformed/oversized server profile; fail closed
  | 'PROFILE_SIGNING_ONLY_MATCH' // signing match with different encryption address; fail closed
  | 'SERVER_PROOF_REJECTED' // HushServerNode invalid-signature/identity-proof rejection (distinct from lookup)
  // Protection and staging
  | 'PROTECTION_CANCELLED' // password/WebAuthn/OS cancellation
  | 'STAGE_WRITE_FAILURE' // stage write/read-back failed; destroy keying state; never activate
  | 'STAGED_RESTART_FAILURE' // staged data corrupt/unsupported version; fail closed
  // Ownership and cleanup
  | 'OWNERSHIP_LOST' // another tab/window/process owns the restore epoch
  | 'EPOCH_EXPIRED' // foreground authority bound exceeded
  | 'STALE_EPOCH' // result from a stale epoch/operation; dropped without state mutation
  | 'DOUBLE_DISPATCH' // second sensitive operation while one is in flight
  | 'CLEANUP_FAILURE' // verified absence impossible; quarantine
  | 'QUARANTINED' // quarantine blocks first-run paths until verified absence
  // Unknown outcomes
  | 'UNKNOWN_OUTCOME'; // unknown/contradictory outcome; fail closed; no free-form parsing

export interface RestoreFailure {
  readonly ok: false;
  readonly code: RestoreFailureCode;
  /** Safe diagnostic text; never contains source, password, key, address, or transaction material. */
  readonly message: string;
  /** Sanitized support code (opaque, safe). */
  readonly supportCode: string;
}

export type RestoreResult<T> = { readonly ok: true; readonly value: T } | RestoreFailure;

/**
 * Retention/destruction events — authoritative audit vocabulary for source
 * custody and secret disposal. The authority emits these; the machine
 * records counts and coarse timing classes only.
 */
export type RestoreCustodyEvent =
  | 'sourceSelected' // exactly one platform source accepted for the current epoch
  | 'snapshotAccepted' // one immutable bounded ciphertext snapshot captured
  | 'snapshotReleased' // ciphertext snapshot cleared after validated-authority conversion
  | 'sourceHandleReleased' // handle/descriptor/URI grant closed/revoked
  | 'temporaryCopyCreated' // unavoidable ciphertext-only temp copy (app-private no-backup)
  | 'temporaryCopyVerifiedDeleted' // temp copy deleted and verified on the current path
  | 'startupOrphanScan' // startup temp/orphan reconciliation ran
  | 'passwordDestroyed' // password/KDF/AES/plaintext/parser state destroyed after attempt
  | 'plaintextDestroyed' // decrypted buffers/parser objects/partial credentials destroyed
  | 'mnemonicDestroyed' // optional mnemonic/seed/intermediates destroyed after consistency
  | 'validatedAuthorityConverted' // opaque validated concrete-key authority created
  | 'epochCleared' // selection/snapshot/password/profile state cleared at epoch end
  | 'backDestroyed' // pre-stage Back destroyed validated authority and returned to empty selection
  | 'stageLocked' // post-stage Back locked the workflow; Finish restoring your identity only
  | 'cleanupVerified' // verified local absence after removal/cancellation
  | 'quarantineRaised'; // cleanup could not verify absence; FEAT-009 blocked

/** Completion states — the only terminal outcomes of the restore workflow. */
export type RestoreCompletionState =
  | 'restoredExistingProfile' // fresh exact both-key online verification, existing profile
  | 'createdMissingProfile' // exact-key FEAT-007 registration confirmed (or in flight persistent)
  | 'sessionOnlyRestored' // explicit session-only authority; nothing persisted
  | 'cancelled' // verified cancellation; no local user created
  | 'quarantined'; // terminal quarantine; requires verified cleanup before first-run

/** Safe operational evidence category (privacy-safe; no secrets, no identifiers). */
export type RestoreEvidenceCategory =
  | 'vault-guard-passed'
  | 'preflight-passed'
  | 'source-selected'
  | 'snapshot-accepted'
  | 'read-complete'
  | 'read-incomplete'
  | 'envelope-passed'
  | 'password-attempted'
  | 'authentication-failed'
  | 'payload-parsed'
  | 'key-proof-passed'
  | 'key-proof-failed'
  | 'mnemonic-consistency-passed'
  | 'source-released'
  | 'lookup-complete'
  | 'lookup-incomplete'
  | 'profile-resolved-existing'
  | 'profile-resolved-missing'
  | 'protection-chosen'
  | 'stage-committed'
  | 'resume-gate-shown'
  | 'activated-existing'
  | 'activated-created'
  | 'session-only-activated'
  | 'back-destroyed'
  | 'owner-blocked'
  | 'cleanup-verified'
  | 'quarantined'
  | 'compatibility-error';

/** Compile-time + runtime proof that no generic secret surface is representable. */
export type ForbiddenRestoreSecretSurface =
  | 'sourceIdentifier'
  | 'sourceBytes'
  | 'backupPassword'
  | 'aesKey'
  | 'plaintext'
  | 'mnemonic'
  | 'seed'
  | 'privateKey'
  | 'fullAddress'
  | 'credentialId'
  | 'transaction'
  | 'signature'
  | 'externalDigest'
  | 'genericCapability';

/** Runtime scan: any forbidden secret surface key present ⇒ violations listed. */
export function assertNoRestoreSecretSurface(value: unknown): ForbiddenRestoreSecretSurface[] {
  const violations: ForbiddenRestoreSecretSurface[] = [];
  if (value === null || typeof value !== 'object') {
    return violations;
  }
  let json: string;
  try {
    json = JSON.stringify(value);
  } catch {
    return violations;
  }
  if (!json) return violations;
  const lower = json.toLowerCase();
  // Keys only ("key": pattern) — safe values such as a stage named
  // 'password' or a copy key named 'backupPasswordIncorrectOrDamaged' are
  // legitimate and must not trip the scanner.
  const hasKey = (key: string): boolean => lower.includes(`"${key.toLowerCase()}":`);
  if (hasKey('fileName') || hasKey('filePath') || hasKey('fileUri') || hasKey('uri') || hasKey('provider') || hasKey('descriptor') || hasKey('sourceIdentifier')) {
    violations.push('sourceIdentifier');
  }
  if (hasKey('sourceDigest') || hasKey('digest') || hasKey('externalDigest')) {
    violations.push('externalDigest');
  }
  if (hasKey('password') || hasKey('backupPassword')) {
    violations.push('backupPassword');
  }
  if (hasKey('aesKey') || hasKey('kdfKey')) {
    violations.push('aesKey');
  }
  if (hasKey('plaintext') || hasKey('decryptedJson')) {
    violations.push('plaintext');
  }
  if (hasKey('mnemonic')) violations.push('mnemonic');
  if (hasKey('seed')) violations.push('seed');
  if (hasKey('privateKey') || hasKey('privateSigningKey') || hasKey('privateEncryptKey')) {
    violations.push('privateKey');
  }
  if (hasKey('fullAddress') || hasKey('publicSigningAddress') || hasKey('publicEncryptAddress')) {
    violations.push('fullAddress');
  }
  if (hasKey('credentialId')) violations.push('credentialId');
  if (hasKey('transaction') || hasKey('transactionId')) violations.push('transaction');
  if (hasKey('signature')) violations.push('signature');
  if (hasKey('capability')) violations.push('genericCapability');
  // Heuristic guards against accidental embedding of encoded secret material.
  if (json.includes('PRIVATE KEY') || json.includes('BEGIN')) violations.push('privateKey');
  return violations;
}
