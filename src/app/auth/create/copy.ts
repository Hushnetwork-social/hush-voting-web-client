/**
 * FEAT-007 create-user UI — copy and terminology (normative, EPIC-001
 * design baseline "Copy and Terminology Contract").
 *
 * Exact labels: Create User, Device password, Backup-file password, Restore
 * Recovery Words, Restore Credential File, Unlock HushVoting!. No "Account
 * password", "Import Keys", "Reset password", or "Cloud recovery" wording.
 */

export const PRODUCT = 'HushVoting!';
export const NO_PASSWORD_WORDING = 'No HushVoting account password exists on a server.';

export const ENTRY = {
  title: 'Secure your voting identity',
  subtitle: 'Create a HushNetwork identity or restore one you own.',
  privacy: 'Your passwords and private credentials stay on this device.',
  createUser: 'Create User',
  createUserDetail: 'Generate a new identity and 24 recovery words.',
  restoreWords: 'Restore Recovery Words',
  restoreWordsDetail: 'Use an existing valid 12- or 24-word phrase.',
  restoreFile: 'Restore Credential File',
  restoreFileDetail: 'Use an encrypted HUSH .dat backup and its password.',
  footnote: NO_PASSWORD_WORDING,
};

export const PREF_LIGHT = {
  title: 'Security check',
  detail: 'Checking that this device can store your identity safely.',
  unsupportedTitle: 'This device cannot create an identity safely',
  unsupportedDetail: 'Required storage or security protection is unavailable. No alias or secret has been collected.',
  temporaryTitle: 'Storage is temporarily unavailable',
  temporaryDetail: 'The secure store could not be reached. You can retry.',
  retry: 'Retry',
};

export const PROFILE = {
  title: 'Create user · Profile',
  detail: 'Choose the public profile details for this HushNetwork identity. Your signing address remains the identity authority.',
  aliasLabel: 'Profile name / alias',
  visibilityLabel: 'Profile visibility',
  private: 'Private — recommended',
  public: 'Public',
  publicWarningTitle: 'Public visibility cannot be changed later',
  publicWarningDetail:
    'Your profile visibility is recorded on the blockchain when your identity is created. The current interface cannot change it afterwards.',
  publicAcknowledge: 'I understand that visibility is permanent and public.',
  continue: 'Continue',
  aliasRequired: 'Enter a profile name to continue.',
  aliasInvalid: 'This profile name contains characters that are not allowed.',
  aliasTooLong: 'This profile name is too long (64 characters or 256 bytes maximum).',
  publicAckRequired: 'Acknowledge the visibility notice to continue.',
};

export const GENERATE = {
  title: 'Create user · Recovery',
  detail: 'HushVoting! will create 24 words and the signing/encryption keys for your HushNetwork identity.',
  noPassword: 'No password is used to generate these words or keys.',
  warning: 'Anyone with the words can control the identity.',
  action: 'Generate recovery words',
  progress: 'Generating your identity securely…',
};

export const RECOVERY = {
  title: 'Create user · Save recovery words',
  detail: 'These 24 words are the only portable way to recover this identity.',
  copy: 'Copy words',
  copyWarning: 'Clipboard contents may remain visible to other applications. Browser screenshots cannot be prevented.',
  copyDone: 'Words copied. Clipboard will be cleared shortly.',
  regenerate: 'Regenerate',
  regenerateConfirmTitle: 'Regenerate recovery words?',
  regenerateConfirmDetail: 'The previous words will become invalid for this pending identity.',
  regenerateConfirmAction: 'Regenerate and destroy previous words',
  understood: 'I understand HushVoting cannot reset or recover these words.',
  reveal: 'Show words',
  conceal: 'Hide words',
  concealed: 'Recovery words are hidden.',
  timedOut: 'Recovery words were hidden after the time limit.',
};

export const CONFIRM = {
  title: 'Create user · Confirm recovery',
  detail: 'Enter the requested words from your saved copy.',
  verify: 'Verify words',
  reviewAll: 'Review all words',
  mismatch: (position: number) => `Word ${position} does not match. Please check your saved words.`,
  attempts: (remaining: number) => `You have ${remaining} ${remaining === 1 ? 'attempt' : 'attempts'} remaining before this challenge closes.`,
  challengeClosed: 'This challenge is closed. Review your saved words to start a new one.',
};

export const PROTECT = {
  title: 'Protect this device',
  detail:
    'Create a password for the encrypted HushVoting! vault on this device. This password does not generate your HushNetwork identity, change your recovery words, or become a backup-file password.',
  cannotReset: 'HushVoting cannot reset it remotely.',
  label: 'Device password',
  confirmLabel: 'Confirm device password',
  show: 'Show device password',
  hide: 'Hide device password',
  action: 'Protect this device and continue',
  mismatch: 'The two entries do not match.',
  policy: (clusters: number) => `Use at least ${clusters} characters (6–64 characters allowed).`,
};

export const REVIEW = {
  title: 'Review HushNetwork identity',
  detail: 'Creating submits a signed identity transaction. Confirmation may take one or two blocks.',
  alias: 'Alias',
  visibility: 'Visibility',
  signingAddress: 'Signing address',
  recovery: 'Recovery',
  recoveryConfirmed: '24 words confirmed',
  deviceProtection: 'Device protection',
  deviceProtectionReady: 'Ready',
  action: 'Create HushNetwork identity',
  submitting: 'Submitting…',
};

export const STATUS = {
  finishCreating: {
    title: 'Finish creating your identity',
    detail: 'You were in the middle of creating your HushNetwork identity. Unlock this device to continue safely.',
    action: 'Unlock this device',
  },
  waiting: {
    title: 'Waiting for blockchain final approval',
    detail:
      'Your identity transaction is in the mempool. HushVoting! is waiting for HushServerNode to include it in the blockchain. This usually takes a few seconds.',
    safeExit: 'You can lock or close HushVoting! safely. We will check again after your next unlock.',
    checkAgain: 'Check again',
    lock: 'Lock',
    live: 'Waiting for blockchain confirmation…',
  },
  delay: {
    title: 'Blockchain confirmation delayed',
    detail:
      'Your identity transaction has not been included in a block yet. Your local identity remains safely stored. You can check again or lock.',
    checkAgain: 'Check again',
    lock: 'Lock',
  },
  connection: {
    title: 'Waiting for connection',
    detail: 'HushVoting! could not reach the network. Your exact transaction remains encrypted on this device.',
    retry: 'Try again',
    lock: 'Lock',
  },
  correcting: {
    title: 'Fix your profile to continue',
    detail: 'The identity service could not accept one profile detail. Only the profile step is reopened; your recovery words and keys stay the same.',
    action: 'Continue to Profile',
  },
  cancelling: {
    title: 'Cancel local identity setup?',
    detail: 'If your identity transaction was already submitted, it may still confirm on the blockchain. Your saved recovery words are required to restore it later.',
    cancelAction: 'Cancel local identity',
    keepAction: 'Keep setting up',
  },
  terminal: {
    title: 'This device is locked out',
    detail: 'A safety check failed. HushVoting! cannot create or authenticate identities until the issue is resolved. Contact support with this code:',
  },
};
