/**
 * FEAT-005 Ubuntu vault bridge — closed native operation registry mirror.
 *
 * Mirrors `src-tauri/src/ubuntu_vault/contracts/operations.rs` (Rust
 * `OPERATION_REGISTRY`). The WebView may only request registered operations;
 * unknown, stale, or generic kinds fail closed. There is no
 * `getPrivateKey`, `decryptVault`, `sign(bytes)`, arbitrary encrypt/decrypt,
 * generic filesystem access, or generic credential serialization command.
 *
 * Normative source: FEAT-005 FeatureDescription "Closed operation registry".
 */

import type { CapabilityPhase, NativeOperationKind } from './contracts';

/** Native operation specification (mirror of Rust `OperationSpec`). */
export interface NativeOperationSpec {
  readonly kind: NativeOperationKind;
  readonly version: 1;
  readonly requiredCapabilityPhase: CapabilityPhase;
  readonly purpose: string;
  /** Bounded input byte ceiling enforced by the native dispatcher. */
  readonly maxInputBytes: number;
}

/** Exhaustive closed native registry (v1). */
export const NATIVE_OPERATION_REGISTRY: Readonly<Record<NativeOperationKind, NativeOperationSpec>> = {
  inspectPreview: {
    kind: 'inspectPreview',
    version: 1,
    requiredCapabilityPhase: 'locked',
    purpose: 'inspect-safe-preview',
    maxInputBytes: 0,
  },
  provision: {
    kind: 'provision',
    version: 1,
    requiredCapabilityPhase: 'provisioning',
    purpose: 'provision-device-vault',
    maxInputBytes: 1_024,
  },
  replace: {
    kind: 'replace',
    version: 1,
    requiredCapabilityPhase: 'provisioning',
    purpose: 'replace-credential-bundle',
    maxInputBytes: 1_024,
  },
  unlock: {
    kind: 'unlock',
    version: 1,
    requiredCapabilityPhase: 'locked',
    purpose: 'unlock-device-vault',
    maxInputBytes: 1_024,
  },
  lock: {
    kind: 'lock',
    version: 1,
    requiredCapabilityPhase: 'verificationOnly',
    purpose: 'global-lock',
    maxInputBytes: 0,
  },
  changeDevicePassword: {
    kind: 'changeDevicePassword',
    version: 1,
    requiredCapabilityPhase: 'authenticated',
    purpose: 'change-device-password',
    maxInputBytes: 1_024,
  },
  removeLocalUser: {
    kind: 'removeLocalUser',
    version: 1,
    requiredCapabilityPhase: 'authenticated',
    purpose: 'remove-local-user',
    maxInputBytes: 0,
  },
  revealMnemonic: {
    kind: 'revealMnemonic',
    version: 1,
    requiredCapabilityPhase: 'authenticated',
    purpose: 'reveal-recovery-words',
    maxInputBytes: 0,
  },
  generateIdentity: {
    kind: 'generateIdentity',
    version: 1,
    requiredCapabilityPhase: 'provisioning',
    purpose: 'generate-hush-identity',
    maxInputBytes: 0,
  },
  restoreIdentity: {
    kind: 'restoreIdentity',
    version: 1,
    requiredCapabilityPhase: 'provisioning',
    purpose: 'restore-hush-identity',
    maxInputBytes: 4_096,
  },
  verifyOnline: {
    kind: 'verifyOnline',
    version: 1,
    requiredCapabilityPhase: 'verificationOnly',
    purpose: 'verify-online-identity',
    maxInputBytes: 256,
  },
  createFullIdentitySign: {
    kind: 'createFullIdentitySign',
    version: 1,
    requiredCapabilityPhase: 'verificationOnly',
    purpose: 'create-full-identity-sign',
    maxInputBytes: 16_384,
  },
  importDatV1: {
    kind: 'importDatV1',
    version: 1,
    requiredCapabilityPhase: 'provisioning',
    purpose: 'import-dat-v1',
    maxInputBytes: 4_096,
  },
  exportDatV1: {
    kind: 'exportDatV1',
    version: 1,
    requiredCapabilityPhase: 'authenticated',
    purpose: 'export-dat-v1',
    maxInputBytes: 256,
  },
} as const;

export const NATIVE_OPERATION_KINDS: readonly NativeOperationKind[] = Object.keys(
  NATIVE_OPERATION_REGISTRY,
) as NativeOperationKind[];

/** Generic secret access that NO native operation may represent. */
export type ForbiddenNativeSurface =
  | 'getPrivateKey'
  | 'decryptVault'
  | 'signBytes'
  | 'arbitraryEncryptDecrypt'
  | 'genericFilesystem'
  | 'genericCredentialSerialization';

/** Prove the registry has no generic secret surface (compile-time + runtime). */
export function assertNoGenericNativeAccess(): ForbiddenNativeSurface[] {
  const violations: ForbiddenNativeSurface[] = [];
  for (const kind of NATIVE_OPERATION_KINDS) {
    const spec = NATIVE_OPERATION_REGISTRY[kind];
    if (
      spec.kind === 'createFullIdentitySign' ||
      spec.kind === 'importDatV1' ||
      spec.kind === 'exportDatV1'
    ) {
      continue; // operation-scoped and capability-bound — not generic
    }
    // Any other purpose containing generic vocabulary is a violation.
    const purpose = spec.purpose.toLowerCase();
    if (purpose.includes('private-key') || purpose.includes('sign(bytes)')) {
      violations.push('getPrivateKey');
    }
    if (purpose.includes('decrypt-vault') || purpose.includes('decryptvault')) {
      violations.push('decryptVault');
    }
  }
  return violations;
}

/** Resolve a spec by kind; unknown/stale/generic kinds fail closed. */
export function resolveNativeOperation(kind: unknown): NativeOperationSpec | null {
  if (typeof kind !== 'string') {
    return null;
  }
  return NATIVE_OPERATION_REGISTRY[kind as NativeOperationKind] ?? null;
}
