/**
 * FEAT-008 recovery-words UI — copy.
 *
 * Secret-safe user-facing copy for the Recovery Words journey. None of these
 * strings ever contains or echoes word values, keys, addresses, or
 * credentials. Copy follows the EPIC-001 IdentityOnboardingDesignBaseline
 * terminology (Restore Recovery Words, Device password, Protect this device).
 */
export const PRODUCT = 'HushVoting!';

export const ENTRY = {
  title: 'Restore your identity',
  subtitle: 'Use your recovery words to restore control of your HushNetwork identity on this device.',
  restoreWords: 'Restore Recovery Words',
  restoreWordsDetail: 'Enter a 12- or 24-word recovery phrase',
  noServerPassword: 'No HushVoting account password exists on a server.',
  privacy: 'Your recovery words stay on this device and are never sent to any server.',
} as const;

export const WORD_ENTRY = {
  title: 'Enter your recovery words',
  intro: 'Choose a 12- or 24-word phrase. You can also paste a complete phrase from your own secure copy.',
  twelve: '12 words',
  twentyFour: '24 words',
  wordLabel: (index: number, total: number) => `Recovery word ${index} of ${total}`,
  pasteHint: 'Paste a complete phrase into any word box.',
  showAll: 'Show all words',
  hideAll: 'Hide all words',
  shoulderSurfing: 'Words are hidden to protect against shoulder surfing. The focused word stays visible for correction.',
  clearAll: 'Clear all',
  verify: 'Verify',
  busyVerifying: 'Checking…',
  wrongCountStatic: 'Recovery phrases must contain exactly 12 or 24 words.',
  unsupportedInput: 'Only 12- or 24-word English phrases without a passphrase are supported.',
  unknownWords: 'Some words are not in the supported word list.',
  checksumNote: 'The checksum is checked securely on this device.',
  replacePrompt: 'Replace all entered recovery words with the pasted phrase?',
  replaceConfirm: 'Replace all',
  replaceCancel: 'Cancel',
  noRetention: `${PRODUCT} will not save these recovery words. Keep your own secure copy.`,
  noRetentionDetail: 'Reinstall, vault reset, device loss, or ending this session requires your external recovery words or a backup file.',
  inactivityConceal: 'Words were hidden automatically.',
} as const;

export const LOOKUP = {
  title: 'Checking your identity',
  progress: (done: number, total: number) => `Checking identity formats ${done} of ${total}`,
  retry: 'Retry unresolved checks',
} as const;

export const CANDIDATE_REVIEW = {
  existingTitle: 'Confirm this identity',
  existingDetail: 'This recovery phrase matches the following identity on the current network. Alias and visibility come from the blockchain.',
  continue: 'Continue to protect this device',
  multipleTitle: 'Choose your identity',
  multipleDetail: 'This phrase matches more than one identity. Select the one you want to restore.',
  zeroTitle: 'Your recovery words restored control of this identity',
  zeroDetail: 'No profile currently exists on this blockchain. This can happen after a blockchain reset or if the identity was never registered.',
  zeroHint: 'Your recovery words are valid — HushVoting is not generating new keys.',
  sourceLabel: 'Source',
  signing: 'Signing address',
  encryption: 'Encryption address',
  alias: 'Alias',
  visibility: 'Visibility',
  network: 'Network',
  revealFull: 'Reveal full addresses',
  concealFull: 'Hide full addresses',
  copyAddress: 'Copy address',
  notSure: 'I\u2019m not sure',
  notSureGuidance: 'Your trusted public address may appear in prior notifications, receipts, or block explorers.',
  selected: 'Selected',
  select: 'Select this identity',
} as const;

export const PROTECTION = {
  title: 'Protect this device',
  acknowledgement: `${PRODUCT} will not save these recovery words.`,
  defaultPasswordLabel: 'Create a HushVoting vault password',
  defaultPasswordDetail: 'An extra local layer protecting your restored identity on this device.',
  passwordlessWebLabel: 'Use this device\u2019s passkey (platform authenticator)',
  passwordlessNativeLabel: 'Use the operating system\u2019s secure storage',
  sessionOnlyLabel: 'Use this browser session only',
  sessionOnlyDetail: 'Nothing is saved on this device; you will need your recovery words again after this session ends.',
  sessionOnlyAck: 'I understand that nothing will be saved on this device.',
  syncedPasskeyNote: 'Your platform provider may synchronize the passkey under its own policy; the encrypted HushVoting vault stays on this device.',
  unlockedDeviceWarning: 'Anyone with access to this unlocked device/session may access HushVoting.',
  passwordLabel: 'HushVoting vault password',
  passwordConfirm: 'Confirm the password',
  continue: 'Continue',
} as const;

export const STAGING = {
  title: 'Saving your restored identity',
  detail: 'Encrypted keys are being saved and verified on this device.',
  failTitle: 'Saving failed',
  failDetail: 'Nothing was saved. Enter your recovery words again to retry.',
} as const;

export const RECREATE = {
  title: 'Create HushNetwork identity',
  detail: 'No profile exists for these keys on this network. Review the details below; your recovered keys are used exactly as restored.',
  aliasLabel: 'Alias (public name)',
  aliasPlaceholder: 'Enter a public alias',
  visibilityPrivate: 'Private',
  visibilityPublic: 'Public',
  publicAcknowledgement: 'I understand this identity and its activity will be publicly visible.',
  create: 'Create HushNetwork identity',
  networkNote: (network: string) => `Target network: ${network}`,
} as const;

export const RESUME = {
  title: 'Finish restoring your identity',
  detail: 'A saved restore is waiting. Unlock it to verify and finish restoring.',
  unlock: 'Unlock and finish',
  lockedDetail: 'You are locked out while a restore is in progress on this device.',
} as const;

export const SUCCESS = {
  title: 'Identity restored',
  detail: 'Your identity is restored and this device is protected.',
} as const;

export const GUARDS = {
  alreadyInProgress: 'Recovery is already in progress in another HushVoting! tab.',
  alreadyInProgressDetail: 'Close the other tab, or retry here once it finishes.',
  removeLocalUser: 'Log out and remove local user',
  removeDetail: 'Removes this local identity from the device. Your blockchain identity is not deleted.',
  forgotPassword: 'Forgot device password?',
  forgotDetail: `${PRODUCT} cannot recover or reset your device password.`,
  quarantine: 'Recovery is blocked until local cleanup completes.',
  quarantineRetry: 'Retry cleanup',
  screenshotNote: 'Web screenshot prevention cannot be guaranteed; keep your words away from screen capture.',
} as const;

export const BACK = {
  label: 'Back',
  beforeVerify: 'Back',
  afterVerify: 'Back',
  staged: 'Lock',
} as const;
