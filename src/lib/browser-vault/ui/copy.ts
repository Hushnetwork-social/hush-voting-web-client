/**
 * FEAT-004 browser-vault UI copy — pure, deterministic, accessibility-safe.
 *
 * Maps every browser-vault state/outcome to the exact user-facing copy. No
 * secret content ever appears in titles, labels, live regions, or status. UI
 * copy states browser residual risks honestly and never describes IndexedDB
 * as OS-backed/hardware-backed protection. Persistence risk, rollback
 * recovery, clipboard limits, and removal behavior are understandable and
 * accurate (acceptance criterion 45).
 *
 * Normative source: FEAT-004 FeatureDescription "Error Handling and User
 * Feedback", "Accessibility", "Storage persistence", "Rollback Recovery".
 */

import type { VaultResultCode } from '../../vault-core/contracts/results';
import { COMBINED_CREDENTIAL_ERROR } from '../../auth/types';

/** Closed mapping: every FEAT-003/browser result code -> one actionable surface. */
export const VAULT_ERROR_COPY: Readonly<Record<VaultResultCode, { readonly message: string; readonly action: string }>> = {
  NoVault: { message: 'No local identity was found on this device.', action: 'Create or restore an identity.' },
  UnsupportedVaultVersion: { message: 'This local vault version is not supported by this app.', action: 'Update HushVoting or contact support.' },
  MalformedEnvelope: { message: 'The protected data could not be read.', action: 'Retry or create a fresh identity.' },
  WrongPasswordOrDamagedData: { message: COMBINED_CREDENTIAL_ERROR, action: 'Retry with your device password.' },
  Throttled: { message: 'Too many attempts. Wait before trying again.', action: 'Retry after the wait time.' },
  KdfResourceLimit: { message: 'This browser cannot meet the protection requirements on this device.', action: 'Use a supported Chrome/Edge browser or a native device.' },
  PlatformProtectionUnavailable: { message: 'Device protection is not available here.', action: 'Use a supported browser or native app.' },
  PlatformProtectionInvalidated: { message: 'Device protection changed and can no longer be used.', action: 'Create or restore an identity.' },
  IdentityBindingMismatch: { message: 'The recovered identity does not match the expected profile.', action: 'Verify the recovery material.' },
  MigrationFailedRollbackAvailable: { message: 'A previous local generation can be recovered.', action: 'Review the recovery option.' },
  GenerationConflict: { message: 'Another change happened first. Reloading current state.', action: 'Retry.' },
  StorageUnavailable: { message: 'Browser storage is temporarily unavailable.', action: 'Retry.' },
  StorageQuotaExceeded: { message: 'Browser storage is full. Protected data is preserved.', action: 'Free storage or back up first.' },
  PersistenceDenied: { message: 'Browser data may be removed automatically.', action: 'Acknowledge and continue, or cancel.' },
  StaleSession: { message: 'This session is no longer active.', action: 'Unlock again.' },
  OperationForbidden: { message: 'This action is not permitted in the current state.', action: 'Return to the previous screen.' },
  CleanupFailed: { message: 'Cleanup could not finish. The vault stays locked.', action: 'Retry.' },
  ExtensionUnsupported: { message: 'This capability is not supported here.', action: 'Use a supported browser.' },
};

/** Preflight guidance for capability reports (non-secret, actionable). */
export const PREFLIGHT_COPY = {
  unsupported:
    'This browser cannot safely store your identity. Use a current or previous major version of Chrome or Edge on a supported device.',
  retryable: 'Browser storage is temporarily busy. You can retry.',
  secureOrigin: 'Protected features require a secure connection.',
} as const;

/** Persistence durability warning (explicit acknowledgement required). */
export const PERSISTENCE_WARNING =
  'This browser may remove site data automatically, which would remove your local vault. Acknowledge to continue, or back up with an encrypted file when available.';

/** Mnemonic reveal copy (browser residual risks, no overclaims). */
export const REVEAL_COPY = {
  heading: 'Recovery words',
  intro:
    'Browsers cannot prevent screenshots, privileged extensions, assistive/speech history, or compromise of the active page. Keep this screen private.',
  concealAfter: 'Words will hide automatically after 60 seconds.',
  copyWarning:
    'Copying places the words on your clipboard for up to 30 seconds. We attempt to clear it, but newer clipboard content may be overwritten only by our own empty write. We never read your clipboard.',
  copy: 'Copy words',
  copied: 'Copied. We will attempt to clear the clipboard after 30 seconds.',
  copyDenied: 'The browser refused the clipboard write.',
} as const;

/** Removal copy (logical removal, never on-chain/physical claims). */
export const REMOVAL_COPY = {
  confirm: 'Remove the local identity from this browser? This removes the local vault.',
  note: 'Removal is best-effort logical removal; it does not change your on-chain identity and cannot guarantee physical erasure of browser data.',
} as const;
