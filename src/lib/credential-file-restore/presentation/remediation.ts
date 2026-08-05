/**
 * FEAT-009 credential-file restore — error, progress, accessibility, and
 * remediation projections.
 *
 * Framework-neutral. Maps every typed structural, authentication, semantic,
 * lookup, server-proof, cleanup, and success outcome to bounded copy,
 * allowed restore actions, status semantics, and predictable focus. Unknown
 * codes fail closed with a generic safe message — never free-form parsing,
 * never echoed source identifiers, passwords, keys, addresses, or platform
 * internals.
 *
 * Normative source: FEAT-009 FeatureDescription "Decryption and Error
 * Privacy", "Safe inconsistent-key errors", "Success and User Feedback",
 * "Accessibility and Responsive UX", "Failure backoff".
 */
import type { RestoreFailureCode } from '../contracts/lifecycle';
import type { RestoreAction } from '../contracts/projection';

/** Bounded remediation surface for one typed failure. */
export interface RestoreRemediation {
  readonly code: RestoreFailureCode;
  /** Safe, bounded copy; never echoes source/password/keys/addresses. */
  readonly message: string;
  /** Allowed restore actions for this error (closed). */
  readonly actions: readonly RestoreAction[];
  /** Focus destination. */
  readonly focusTarget: 'input' | 'summary' | 'primaryAction';
  /** True when the current screen is retained for correction. */
  readonly retainsScreen: boolean;
}

/** Closed remediation table (single source for the renderer). */
const REMEDIATION_TABLE: Readonly<Partial<Record<RestoreFailureCode, Omit<RestoreRemediation, 'code'>>>> = {
  VAULT_NOT_VERIFIED_EMPTY: { message: 'A local identity already exists on this device.', actions: ['back'], focusTarget: 'primaryAction', retainsScreen: false },
  NO_SAFE_CUSTODY_PATH: { message: 'No safe way to read a credential file is available on this device.', actions: ['back'], focusTarget: 'summary', retainsScreen: false },
  SESSION_ONLY_ONLY: { message: 'Only session-only restore is safe here; nothing will be saved on this device.', actions: ['acknowledgeSessionOnly', 'back'], focusTarget: 'primaryAction', retainsScreen: true },
  PICKER_CANCELLED: { message: 'File selection was cancelled.', actions: ['chooseFile', 'back'], focusTarget: 'primaryAction', retainsScreen: true },
  UNSAFE_FILE_KIND: { message: 'The selected item is not a readable file.', actions: ['chooseDifferentFile', 'back'], focusTarget: 'primaryAction', retainsScreen: true },
  FILE_TOO_LARGE: { message: 'The credential file is too large to read.', actions: ['chooseDifferentFile', 'back'], focusTarget: 'primaryAction', retainsScreen: true },
  READ_UNAVAILABLE: { message: 'The credential file could not be read.', actions: ['retryRead', 'chooseDifferentFile', 'back'], focusTarget: 'primaryAction', retainsScreen: true },
  READ_INACTIVITY_TIMEOUT: { message: 'Reading the credential file took too long.', actions: ['retryRead', 'chooseDifferentFile', 'back'], focusTarget: 'primaryAction', retainsScreen: true },
  READ_PARTIAL: { message: 'The credential file ended unexpectedly.', actions: ['retryRead', 'chooseDifferentFile', 'back'], focusTarget: 'primaryAction', retainsScreen: true },
  TEMP_CLEANUP_FAILED: { message: 'Temporary restore data could not be removed.', actions: ['retryCleanup'], focusTarget: 'summary', retainsScreen: false },
  ENVELOPE_TOO_SHORT: { message: 'This file is not a valid HUSH credential backup.', actions: ['chooseDifferentFile', 'back'], focusTarget: 'primaryAction', retainsScreen: true },
  ENVELOPE_OVERSIZE: { message: 'This file is not a valid HUSH credential backup.', actions: ['chooseDifferentFile', 'back'], focusTarget: 'primaryAction', retainsScreen: true },
  INVALID_MAGIC: { message: 'This file is not a valid HUSH credential backup.', actions: ['chooseDifferentFile', 'back'], focusTarget: 'primaryAction', retainsScreen: true },
  UNSUPPORTED_VERSION: { message: 'This credential backup uses an unsupported format version.', actions: ['chooseDifferentFile', 'back'], focusTarget: 'primaryAction', retainsScreen: true },
  PASSWORD_TOO_LONG: { message: 'The backup password is too long.', actions: ['submitPassword'], focusTarget: 'input', retainsScreen: true },
  AUTHENTICATION_FAILED: { message: 'The backup password is incorrect or the credential file is damaged.', actions: ['submitPassword', 'chooseDifferentFile'], focusTarget: 'input', retainsScreen: true },
  BACKOFF_ACTIVE: { message: 'Please wait before trying again.', actions: [], focusTarget: 'summary', retainsScreen: true },
  PAYLOAD_NOT_JSON: { message: 'This credential backup contains invalid data.', actions: ['chooseDifferentFile', 'back'], focusTarget: 'summary', retainsScreen: false },
  PAYLOAD_DUPLICATE_FIELD: { message: 'This credential backup contains invalid data.', actions: ['chooseDifferentFile', 'back'], focusTarget: 'summary', retainsScreen: false },
  PAYLOAD_UNKNOWN_FIELD: { message: 'This credential backup contains invalid data.', actions: ['chooseDifferentFile', 'back'], focusTarget: 'summary', retainsScreen: false },
  PAYLOAD_MISSING_FIELD: { message: 'This credential backup contains invalid data.', actions: ['chooseDifferentFile', 'back'], focusTarget: 'summary', retainsScreen: false },
  PAYLOAD_INVALID_FIELD: { message: 'This credential backup contains invalid data.', actions: ['chooseDifferentFile', 'back'], focusTarget: 'summary', retainsScreen: false },
  UNSUPPORTED_KEY_ENCODING: { message: 'This credential file contains invalid or inconsistent identity keys and cannot be restored.', actions: ['chooseDifferentFile', 'back'], focusTarget: 'summary', retainsScreen: false },
  SIGNING_KEY_MISMATCH: { message: 'This credential file contains invalid or inconsistent identity keys and cannot be restored.', actions: ['chooseDifferentFile', 'back'], focusTarget: 'summary', retainsScreen: false },
  ENCRYPTION_KEY_MISMATCH: { message: 'This credential file contains invalid or inconsistent identity keys and cannot be restored.', actions: ['chooseDifferentFile', 'back'], focusTarget: 'summary', retainsScreen: false },
  KEY_PROOF_FAILED: { message: 'This credential file contains invalid or inconsistent identity keys and cannot be restored.', actions: ['chooseDifferentFile', 'back'], focusTarget: 'summary', retainsScreen: false },
  MNEMONIC_KEY_MISMATCH: { message: 'This credential file contains invalid or inconsistent identity keys and cannot be restored.', actions: ['chooseDifferentFile', 'back'], focusTarget: 'summary', retainsScreen: false },
  LOOKUP_TRANSPORT_FAILURE: { message: 'The identity check could not be completed; please retry.', actions: ['back'], focusTarget: 'primaryAction', retainsScreen: false },
  LOOKUP_MALFORMED: { message: 'The identity check returned an invalid response.', actions: ['back'], focusTarget: 'summary', retainsScreen: false },
  PROFILE_SIGNING_ONLY_MATCH: { message: 'The credential file does not match the blockchain identity exactly.', actions: ['back'], focusTarget: 'summary', retainsScreen: false },
  SERVER_PROOF_REJECTED: { message: 'HushServerNode rejected the identity proof.', actions: ['back'], focusTarget: 'summary', retainsScreen: false },
  PROTECTION_CANCELLED: { message: 'Protection setup was cancelled.', actions: ['selectProtectionMode', 'back'], focusTarget: 'primaryAction', retainsScreen: true },
  STAGE_WRITE_FAILURE: { message: 'Your encrypted identity could not be saved.', actions: ['back'], focusTarget: 'summary', retainsScreen: false },
  STAGED_RESTART_FAILURE: { message: 'The saved restore could not be verified.', actions: ['cancelStagedRestore'], focusTarget: 'summary', retainsScreen: false },
  OWNERSHIP_LOST: { message: 'File restore is already in progress in another window.', actions: ['retryRead'], focusTarget: 'primaryAction', retainsScreen: false },
  EPOCH_EXPIRED: { message: 'This restore session expired; please start again.', actions: ['chooseFile', 'back'], focusTarget: 'summary', retainsScreen: false },
  STALE_EPOCH: { message: 'This action is no longer valid; please try again.', actions: ['back'], focusTarget: 'summary', retainsScreen: false },
  DOUBLE_DISPATCH: { message: 'Please wait for the current operation to finish.', actions: [], focusTarget: 'summary', retainsScreen: true },
  CLEANUP_FAILURE: { message: 'Local restore data could not be fully removed.', actions: ['retryCleanup'], focusTarget: 'summary', retainsScreen: false },
  QUARANTINED: { message: 'Restore is blocked until local cleanup is verified.', actions: ['retryCleanup'], focusTarget: 'summary', retainsScreen: false },
};

/** Map any typed failure to a bounded remediation surface (unknown → fail closed). */
export function mapErrorToRemediation(code: RestoreFailureCode): RestoreRemediation {
  const entry = REMEDIATION_TABLE[code];
  if (entry !== undefined) {
    return { code, ...entry };
  }
  return {
    code: 'UNKNOWN_OUTCOME',
    message: 'Something went wrong; please try again.',
    actions: ['back'],
    focusTarget: 'summary',
    retainsScreen: false,
  };
}

/** Exact required copy keys (centralized; never composed from raw messages). */
export const EXACT_COPY: Readonly<Record<string, string>> = {
  readingCredentialFile: 'Reading credential file…',
  backupReadyForPassword: 'Backup ready for password',
  decryptingBackup: 'Decrypting backup…',
  validatingIdentityKeys: 'Validating identity keys…',
  checkingBlockchainIdentity: 'Checking blockchain identity…',
  protectThisDevice: 'Protect this device',
  savingEncryptedIdentity: 'Saving encrypted identity…',
  waitingForBlockchainFinalApproval: 'Waiting for blockchain final approval',
  identityRestored: 'Identity restored',
  finishRestoringYourIdentity: 'Finish restoring your identity',
  credentialFileSelected: 'Credential file selected',
  backupPasswordIncorrectOrDamaged: 'The backup password is incorrect or the credential file is damaged.',
  invalidOrInconsistentIdentityKeys: 'This credential file contains invalid or inconsistent identity keys and cannot be restored.',
  noProfileExistsOnBlockchain: 'Your credential file restored control of this identity, but no profile currently exists on this blockchain.',
  serverRejectedIdentityProof: 'HushServerNode rejected the identity proof.',
  thisBackupCreatedWithoutPassword: 'This backup was created without a password',
  passwordDecryptsSelectedBackupOnly: 'This password decrypts the selected backup only. It is not your HushVoting vault password.',
  mnemonicSourceNotice: 'Your unchanged backup still contains encrypted recovery words; HushVoting did not copy them.',
  recoveryInProgress: 'Recovery is already in progress in another window.',
  quarantinedCleanup: 'Restore is blocked until local cleanup is verified.',
};
