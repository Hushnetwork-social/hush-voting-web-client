/**
 * FEAT-005 Ubuntu auth UI copy — canonical, honest, secret-free.
 *
 * Every string uses the design-summary canonical terms. Protection language
 * never claims hardware isolation, provider-name proof, or equivalence to
 * Secret Service for password-only mode. Copy carries no raw provider/path/
 * identity/secret detail and no secret values ever live in React state.
 */

import type { ProviderAvailability, ProtectionMode } from '../../../lib/ubuntu-vault';

/** Canonical protection-class summary for Security settings. */
export function protectionModeLabel(mode: ProtectionMode): string {
  return mode === 'osBacked'
    ? 'Ubuntu keyring + device password'
    : 'Device password protection only';
}

/** Honest description for each mode (no overclaims). */
export function protectionModeDescription(mode: ProtectionMode): string {
  return mode === 'osBacked'
    ? 'The Ubuntu keyring stores a device wrapping key, and your HushVoting device password protects the vault package. Both are required.'
    : 'Only your HushVoting device password protects the vault package. This was enabled because no supported Ubuntu keyring was available; copied files can be subjected to offline password guessing without first obtaining an Ubuntu keyring secret.';
}

/** Provider-status title (safe, closed, no raw detail). */
export function providerStatusTitle(state: ProviderAvailability): string {
  switch (state) {
    case 'availableUnlocked':
      return 'Ubuntu keyring protection is ready';
    case 'availableLocked':
      return 'Ubuntu keyring is locked';
    case 'promptCancelled':
      return 'Keyring unlock was cancelled';
    case 'temporarilyUnavailable':
      return 'Ubuntu keyring is temporarily unavailable';
    case 'unqualifiedProvider':
      return 'Ubuntu keyring protection is not available on this system';
    case 'protectionInvalidated':
      return 'Ubuntu keyring protection cannot be verified';
    case 'unavailable':
      return 'No Ubuntu keyring protection was found';
  }
}

/** Provider-status detail (safe, closed). */
export function providerStatusDetail(state: ProviderAvailability): string {
  switch (state) {
    case 'availableUnlocked':
      return 'Your HushVoting device password is still required to unlock your vault.';
    case 'availableLocked':
      return 'Unlock the Ubuntu keyring from an explicit action below; this never counts as a wrong HushVoting password.';
    case 'promptCancelled':
    case 'temporarilyUnavailable':
      return 'Nothing was changed. You can retry; a locked or temporarily unavailable keyring never enables weaker protection.';
    case 'unqualifiedProvider':
      return 'Persistent protection cannot be provisioned until the keyring passes qualification. Password-only protection is not offered in this state.';
    case 'protectionInvalidated':
      return 'Your encrypted vault files were preserved. Portable recovery is required; no replacement key is guessed.';
    case 'unavailable':
      return 'Follow the keyring setup guidance and retry. After confirmed absence you may choose acknowledged password-only protection.';
  }
}

/** Fallback explanation (reduced copied-file resistance, honest). */
export const FALLBACK_EXPLANATION =
  'Your HushVoting device password still encrypts your private keys. Without the Ubuntu keyring, a copied file can be subjected to offline password guessing. Ubuntu keyring protection is recommended when available.';

/** Fallback warning (never labeled OS-backed/hardware-backed). */
export const FALLBACK_ACKNOWLEDGEMENT_LABEL =
  'I understand that password-only protection is weaker than Ubuntu keyring protection and that copied files could be guessed offline.';

/** Upgrade offer copy. */
export const UPGRADE_OFFER_TITLE = 'Ubuntu keyring protection is now available';
export const UPGRADE_OFFER_DETAIL =
  'Your vault will be protected by a fresh Ubuntu keyring wrapping key and your device password. The change is atomic: the password-only copy is removed only after the new protection unlocks successfully once.';

/** Reveal concealment bound (seconds). */
export const REVEAL_CONCEAL_SECONDS = 60;

/** Clipboard cleanup delay (seconds). */
export const CLIPBOARD_CLEANUP_SECONDS = 60;

/** Honest capture limitation note (no universal screenshot claim). */
export const REVEAL_LIMITATIONS =
  'On-screen content can still be captured by compositors, recorders, accessibility history, clipboard managers, or a compromised system.';

/** Removal copy. */
export const REMOVAL_PROGRESS_LABEL = 'Removing local user…';
export const REMOVAL_INCOMPLETE_TITLE = 'Removal is not finished';
export const REMOVAL_INCOMPLETE_DETAIL =
  'Protected content remains blocked. Cleanup will resume from where it stopped; success is only reported after verified absence.';
