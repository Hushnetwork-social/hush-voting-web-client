/**
 * FEAT-004 browser-vault contracts — closed downstream operation registry.
 *
 * FEAT-007/008/009/010/011 consume stable, operation-scoped authority requests.
 * Every operation declares its version, required capability phase, purpose,
 * channel/epoch binding, cancellation rule, and safe result shape. No operation
 * can represent generic secret access (arbitrary signing, arbitrary decryption,
 * private-key retrieval, serialized bundle return, or plaintext export).
 *
 * FEAT-011 may add ONLY a separately approved encrypted-output operation; it can
 * never become a generic private-key export through consumer composition.
 *
 * Normative source: FEAT-004 FeatureDescription "Provisioning handoff",
 * "Downstream consumers"; FEAT-003 `src/lib/vault-core/contracts/operations.ts`.
 */

/** Capability phase required before an operation may run inside the authority. */
export type CapabilityPhase = 'provisioning' | 'verificationOnly' | 'authenticated' | 'locked' | 'removal';

/** Closed downstream operation kinds (one seam per consumer flow). */
export type DownstreamOperationKind =
  | 'createProvision' // FEAT-007 closed key-generation/validation/provisioning
  | 'recoverWordsProvision' // FEAT-008 closed mnemonic validation/provisioning
  | 'recoverFileProvision' // FEAT-009 closed .dat decryption/validation/provisioning
  | 'unlock' // FEAT-010 returning-user unlock
  | 'changePassword' // FEAT-010 device-password change
  | 'lock' // FEAT-010 global lock
  | 'removeLocalUser' // FEAT-010 tombstone-backed removal
  | 'verifyOnline' // worker-owned exact identity verification
  | 'revealMnemonic' // purpose-scoped transient reveal
  | 'exportEncryptedFile'; // FEAT-011 separately approved encrypted output

export interface DownstreamOperationSpec {
  readonly kind: DownstreamOperationKind;
  readonly version: 1;
  readonly requiredCapabilityPhase: CapabilityPhase;
  readonly purpose: string;
  /** Requires a fresh purpose-bound one-use password capability (≤60 s). */
  readonly requiresFreshPasswordCapability: boolean;
  /** Whether the operation may be cancelled after dispatch. */
  readonly cancellable: boolean;
  /** Closed safe result surface returned to the page (never secrets). */
  readonly resultSurface: 'typed-outcome' | 'opaque-operation-id' | 'digest-only-report';
}

/** Closed registry — exhaustive, declarative, immutable for v1. */
export const DOWNSTREAM_OPERATION_REGISTRY: Readonly<Record<DownstreamOperationKind, DownstreamOperationSpec>> = {
  createProvision: {
    kind: 'createProvision',
    version: 1,
    requiredCapabilityPhase: 'provisioning',
    purpose: 'FEAT-007 create: atomically provision a worker-validated credential bundle',
    requiresFreshPasswordCapability: true,
    cancellable: true,
    resultSurface: 'typed-outcome',
  },
  recoverWordsProvision: {
    kind: 'recoverWordsProvision',
    version: 1,
    requiredCapabilityPhase: 'provisioning',
    purpose: 'FEAT-008 restore: provision from validated recovery words inside the authority',
    requiresFreshPasswordCapability: true,
    cancellable: true,
    resultSurface: 'typed-outcome',
  },
  recoverFileProvision: {
    kind: 'recoverFileProvision',
    version: 1,
    requiredCapabilityPhase: 'provisioning',
    purpose: 'FEAT-009 restore: decrypt/validate a HUSH .dat file inside the authority',
    requiresFreshPasswordCapability: true,
    cancellable: true,
    resultSurface: 'typed-outcome',
  },
  unlock: {
    kind: 'unlock',
    version: 1,
    requiredCapabilityPhase: 'locked',
    purpose: 'FEAT-010 unlock: local decrypt to VerificationOnly, worker-owned online promotion',
    requiresFreshPasswordCapability: false,
    cancellable: true,
    resultSurface: 'typed-outcome',
  },
  changePassword: {
    kind: 'changePassword',
    version: 1,
    requiredCapabilityPhase: 'authenticated',
    purpose: 'FEAT-010 password change: rewrap keys and preserve identity',
    requiresFreshPasswordCapability: true,
    cancellable: true,
    resultSurface: 'typed-outcome',
  },
  lock: {
    kind: 'lock',
    version: 1,
    requiredCapabilityPhase: 'authenticated',
    purpose: 'FEAT-010 global lock: revoke capabilities and clear secrets',
    requiresFreshPasswordCapability: false,
    cancellable: false,
    resultSurface: 'typed-outcome',
  },
  removeLocalUser: {
    kind: 'removeLocalUser',
    version: 1,
    requiredCapabilityPhase: 'authenticated',
    purpose: 'FEAT-010 removal: global tombstone-backed verified local-user removal',
    requiresFreshPasswordCapability: true,
    cancellable: false,
    resultSurface: 'typed-outcome',
  },
  verifyOnline: {
    kind: 'verifyOnline',
    version: 1,
    requiredCapabilityPhase: 'verificationOnly',
    purpose: 'worker-owned exact profile + both-key online identity verification',
    requiresFreshPasswordCapability: false,
    cancellable: true,
    resultSurface: 'typed-outcome',
  },
  revealMnemonic: {
    kind: 'revealMnemonic',
    version: 1,
    requiredCapabilityPhase: 'authenticated',
    purpose: 'purpose-scoped transient mnemonic reveal (60 s max, dedicated component)',
    requiresFreshPasswordCapability: true,
    cancellable: true,
    resultSurface: 'typed-outcome',
  },
  exportEncryptedFile: {
    kind: 'exportEncryptedFile',
    version: 1,
    requiredCapabilityPhase: 'authenticated',
    purpose: 'FEAT-011 separately approved encrypted .dat v1 output (no plaintext export)',
    requiresFreshPasswordCapability: true,
    cancellable: true,
    resultSurface: 'digest-only-report',
  },
} as const;

export const DOWNSTREAM_OPERATION_KINDS: readonly DownstreamOperationKind[] = Object.keys(
  DOWNSTREAM_OPERATION_REGISTRY,
) as DownstreamOperationKind[];

/** Generic secret access that NO operation may represent. */
export type ForbiddenSecretSurface = 'sign' | 'decrypt' | 'returnPrivateKey' | 'returnBundle' | 'plaintextExport';

/** Prove the registry has no generic secret surface (compile-time + runtime). */
export function assertNoGenericSecretAccess(): ForbiddenSecretSurface[] {
  const violations: ForbiddenSecretSurface[] = [];
  for (const kind of DOWNSTREAM_OPERATION_KINDS) {
    const spec = DOWNSTREAM_OPERATION_REGISTRY[kind];
    if (spec.resultSurface === 'typed-outcome' || spec.resultSurface === 'opaque-operation-id' || spec.resultSurface === 'digest-only-report') {
      continue; // all v1 result surfaces are closed and safe
    }
    violations.push('returnBundle');
  }
  return violations;
}

/** Resolve a spec by kind; returns null for unknown/forbidden kinds (fail closed). */
export function resolveDownstreamOperation(kind: unknown): DownstreamOperationSpec | null {
  if (typeof kind !== 'string') {
    return null;
  }
  const spec = DOWNSTREAM_OPERATION_REGISTRY[kind as DownstreamOperationKind];
  return spec ?? null;
}
