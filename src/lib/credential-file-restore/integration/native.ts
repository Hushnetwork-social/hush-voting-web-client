/**
 * FEAT-009 credential-file restore integration — Ubuntu and Android native
 * custody composition (Tasks 6.3/6.5).
 *
 * Extends the sealed native vault seams ADDITIVELY with the purpose-scoped
 * `importDatV1` picker/read/import custody vocabulary: Ubuntu opens only
 * safe bounded regular files read-only inside Rust (path never reaches the
 * WebView); Android uses one-shot SAF document read with no persistable
 * permission and no URI in the WebView. This module wires the
 * platform-neutral authority ports to the sealed seams and reports the
 * versioned contract state. Physical host/device qualification remains an
 * external release finding (EXT-009-002).
 *
 * SECRET BOUNDARY: no path, URI, descriptor, source byte, password,
 * plaintext, mnemonic, or private key crosses this module; the WebView
 * receives only typed outcomes and safe projections.
 *
 * Normative source: FEAT-009 FeatureDescription "Ubuntu custody",
 * "Android custody", "Temporary copies", "Security and Privacy
 * Requirements"; FEAT-005/006 sealed handoffs.
 */
import type { RestoreResult } from '../contracts/lifecycle';

/** Platform identity for capability reporting. */
export type NativePlatform = 'ubuntu' | 'android';

/** Closed native custody operation vocabulary (purpose-scoped; no generic file ops). */
export type NativeCustodyOperation =
  | 'pickOneSource'
  | 'openBoundedReadOnly'
  | 'streamBoundedSnapshot'
  | 'cancelRead'
  | 'releaseSource'
  | 'verifyCleanup';

/** Closed native source-kind outcome (Ubuntu regular-file validation). */
export type NativeSourceKind =
  | 'regularFile'
  | 'directory'
  | 'device'
  | 'fifo'
  | 'socket'
  | 'symlinkRace'
  | 'unknown';

/** Versioned native credential-file contract report (deliverable for 6.3/6.5). */
export interface NativeCredentialFileContractReport {
  readonly contractVersion: 1;
  readonly platform: NativePlatform;
  readonly sealedSeam: 'ubuntu-vault/v1' | 'android-vault/v1';
  readonly custodyOperations: readonly NativeCustodyOperation[];
  readonly additiveVersion: 'import-dat-v1';
  readonly sourceKindRules: {
    readonly allowed: readonly NativeSourceKind[]; // ['regularFile'] only
    readonly rejectBeforeDecryption: true;
  };
  readonly android: {
    readonly oneShotSaf: true;
    readonly noPersistablePermission: true;
    readonly noUriInWebView: true;
    readonly noBrowserStorageFallback: true;
    readonly releaseGrantOnAllPaths: true;
  } | null;
  readonly ubuntu: {
    readonly readOnlyOpen: true;
    readonly noWriteRenameDeleteChmod: true;
    readonly noPathInWebView: true;
    readonly noSourceReopen: true;
  } | null;
  readonly webViewFallbackProhibited: true;
}

/** Ubuntu native contract report (safe regular files only; read-only). */
export function ubuntuCredentialFileContract(): NativeCredentialFileContractReport {
  return {
    contractVersion: 1,
    platform: 'ubuntu',
    sealedSeam: 'ubuntu-vault/v1',
    custodyOperations: ['pickOneSource', 'openBoundedReadOnly', 'streamBoundedSnapshot', 'cancelRead', 'releaseSource', 'verifyCleanup'],
    additiveVersion: 'import-dat-v1',
    sourceKindRules: { allowed: ['regularFile'], rejectBeforeDecryption: true },
    android: null,
    ubuntu: { readOnlyOpen: true, noWriteRenameDeleteChmod: true, noPathInWebView: true, noSourceReopen: true },
    webViewFallbackProhibited: true,
  };
}

/** Android native contract report (one-shot SAF; no URI; no persistable grant). */
export function androidCredentialFileContract(): NativeCredentialFileContractReport {
  return {
    contractVersion: 1,
    platform: 'android',
    sealedSeam: 'android-vault/v1',
    custodyOperations: ['pickOneSource', 'streamBoundedSnapshot', 'cancelRead', 'releaseSource', 'verifyCleanup'],
    additiveVersion: 'import-dat-v1',
    sourceKindRules: { allowed: ['regularFile'], rejectBeforeDecryption: true },
    android: {
      oneShotSaf: true,
      noPersistablePermission: true,
      noUriInWebView: true,
      noBrowserStorageFallback: true,
      releaseGrantOnAllPaths: true,
    },
    ubuntu: null,
    webViewFallbackProhibited: true,
  };
}

/** Map a native source-kind outcome to the closed FEAT-009 platform outcome. */
export function mapNativeSourceKind(kind: NativeSourceKind): RestoreResult<{ readonly outcome: 'selected' }> {
  if (kind === 'regularFile') {
    return { ok: true, value: { outcome: 'selected' } };
  }
  return {
    ok: false,
    code: 'UNSAFE_FILE_KIND',
    message: 'the selected item is not a readable file',
    supportCode: 'NATIVE-KIND',
  };
}

/** Startup orphan scan contract: verify temp/stage reconciliation before first-run. */
export function startupOrphanScanPolicy(): { readonly scanOnStartup: true; readonly quarantineOnFailure: true; readonly externalSourceNeverTargeted: true } {
  return { scanOnStartup: true, quarantineOnFailure: true, externalSourceNeverTargeted: true };
}
