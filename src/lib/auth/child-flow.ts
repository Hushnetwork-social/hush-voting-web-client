/**
 * FEAT-010 auth contracts — closed child-flow handoff (Task 2.5).
 *
 * The three onboarding child flows (FEAT-007 Create User, FEAT-008 Recovery
 * Words, FEAT-009 Credential File) emit ONLY:
 * - a safe secret-free render projection (typed, opaque view reference);
 * - typed action callbacks;
 * - on success: an OPAQUE non-persisted `VerificationOnly` capability, a safe
 *   public binding projection, and a typed completion outcome.
 *
 * A child flow can never grant protected access: the root must perform a
 * fresh exact both-key online verification after completion (AC-010-013).
 * The completion payload boundary validation rejects any attempt to smuggle
 * secrets, authority references, endpoints, transactions, or generic
 * capabilities (AC-010-089).
 *
 * Framework-neutral, secret-free.
 */

declare const opaque: unique symbol;

/** The three closed child-flow kinds (mirrors OnboardingKind). */
export type ChildFlowKind = 'createUser' | 'recoveryWords' | 'credentialFile';

export const CHILD_FLOW_KINDS: readonly ChildFlowKind[] = ['createUser', 'recoveryWords', 'credentialFile'] as const;

/** Opaque reference to the child's own secret-free view state. React adapters
 * (Phase 5) map this to the completed FEAT-007/008/009 component. */
export type OpaqueChildView = unknown & { readonly [opaque]: 'OpaqueChildView' };

/** Typed child actions the host may forward (closed vocabulary). */
export type ChildAction =
  | { readonly type: 'CHILD.BACK' }
  | { readonly type: 'CHILD.SUBMIT' }
  | { readonly type: 'CHILD.SELECT_PROTECTION'; readonly mode: string }
  | { readonly type: 'CHILD.RETRY' };

/** Closed typed child outcomes (never raw exceptions). */
export type ChildOutcomeCode =
  | 'CHILD_COMPLETED'
  | 'CHILD_CANCELLED'
  | 'CHILD_CLEANUP_COMPLETE'
  | 'CHILD_FAILED';

/** Safe public binding shown after child completion (public keys only). */
export interface ChildCompletionBinding {
  /** Full signing public address (safe public metadata; UI abbreviates). */
  readonly signingAddress: string;
  /** Full encryption public address. */
  readonly encryptionAddress: string;
}

/** Opaque, non-persisted verification-only capability. */
export type VerificationOnlyCapability = string & { readonly [opaque]: 'VerificationOnlyCapability' };

/**
 * The ONLY completion payload a child flow may hand to root orchestration.
 * Carries no password, mnemonic, private key, decrypted file, source
 * identifier, transaction, endpoint, native handle, or authority reference.
 */
export interface VerificationOnlyCompletion {
  readonly capability: VerificationOnlyCapability;
  readonly binding: ChildCompletionBinding;
  readonly outcome: 'provisioned' | 'resumed';
}

/** Safe child render projection emitted by the selected child authority. */
export interface ChildRenderProjection {
  readonly childKind: ChildFlowKind;
  /** Opaque view reference (never an authority reference or secret). */
  readonly view: OpaqueChildView;
  /** Typed callbacks the host may forward. */
  readonly allowedActions: readonly ChildAction['type'][];
}

/** Closed projection diagnostics. */
export type ChildProjectionDiagnostic =
  | { readonly code: 'UNKNOWN_CHILD_KIND' }
  | { readonly code: 'MISSING_VIEW' }
  | { readonly code: 'FORBIDDEN_FIELD' }
  | { readonly code: 'FORBIDDEN_ACTION' };

/** Secret/authority-shaped field names that can never appear in child VIEWS. */
const FORBIDDEN_VIEW_MARKERS = [
  'password',
  'mnemonic',
  'seed',
  'seedPhrase',
  'phrase',
  'privateKey',
  'secret',
  'decrypted',
  'decryptedFile',
  'transaction',
  'signedBytes',
  'endpoint',
  'uri',
  'path',
  'nativeHandle',
  'authority',
  'capability',
] as const;

/**
 * Secret/authority-shaped markers for COMPLETION payloads. `capability` is
 * intentionally NOT listed: the payload's `capability` field is the sanctioned
 * opaque verification-only token (still never authenticating by itself).
 */
const FORBIDDEN_COMPLETION_MARKERS = [
  'password',
  'mnemonic',
  'seed',
  'seedPhrase',
  'phrase',
  'privateKey',
  'secret',
  'decrypted',
  'decryptedFile',
  'transaction',
  'signedBytes',
  'endpoint',
  'uri',
  'path',
  'nativeHandle',
  'authority',
] as const;

/** Closed action vocabulary the host ever forwards. */
const ALLOWED_ACTIONS: readonly ChildAction['type'][] = ['CHILD.BACK', 'CHILD.SUBMIT', 'CHILD.SELECT_PROTECTION', 'CHILD.RETRY'];

/**
 * Recursively scan an object tree for forbidden markers (never descends into
 * cycles — parsed JSON payloads are acyclic).
 */
function hasForbiddenFieldRecursive(value: unknown, markers: readonly string[]): boolean {
  if (value === null || typeof value !== 'object') return false;
  const record = value as Record<string, unknown>;
  for (const key of Object.keys(record)) {
    if (markers.includes(key)) return true;
    const child = record[key];
    if (child !== null && typeof child === 'object') {
      if (hasForbiddenFieldRecursive(child, markers)) return true;
    }
  }
  return false;
}

function hasForbiddenField(value: unknown, markers: readonly string[]): boolean {
  return hasForbiddenFieldRecursive(value, markers);
}

/**
 * Validate a child render projection. Unknown kinds, missing views,
 * forbidden fields (secrets/authority references), and forbidden actions fail
 * closed — `Setting up…` and default-child fallbacks are never allowed
 * (AC-010-012).
 */
export function validateChildRenderProjection(
  childKind: unknown,
  view: unknown,
  allowedActions: unknown,
): { readonly ok: boolean; readonly diagnostics: readonly ChildProjectionDiagnostic[] } {
  const diagnostics: ChildProjectionDiagnostic[] = [];
  if (!CHILD_FLOW_KINDS.includes(childKind as ChildFlowKind)) {
    diagnostics.push({ code: 'UNKNOWN_CHILD_KIND' });
  }
  if (view === null || view === undefined) {
    diagnostics.push({ code: 'MISSING_VIEW' });
  } else if (hasForbiddenField(view, FORBIDDEN_VIEW_MARKERS)) {
    diagnostics.push({ code: 'FORBIDDEN_FIELD' });
  }
  if (!Array.isArray(allowedActions) || allowedActions.length === 0) {
    diagnostics.push({ code: 'FORBIDDEN_ACTION' });
  } else {
    for (const action of allowedActions) {
      if (!ALLOWED_ACTIONS.includes(action as ChildAction['type'])) {
        diagnostics.push({ code: 'FORBIDDEN_ACTION' });
      }
    }
  }
  return { ok: diagnostics.length === 0, diagnostics };
}

/**
 * Validate a completion payload. Rejects any secret-shaped, authority-shaped,
 * or capability-shaped field so no child flow can grant protected access
 * (AC-010-013/089). Binding addresses must be structurally valid public keys.
 */
export function validateVerificationOnlyCompletion(
  payload: unknown,
): { readonly ok: boolean; readonly diagnostics: readonly ChildProjectionDiagnostic[]; readonly completion?: VerificationOnlyCompletion } {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    return { ok: false, diagnostics: [{ code: 'FORBIDDEN_FIELD' }] };
  }
  const record = payload as Record<string, unknown>;
  const diagnostics: ChildProjectionDiagnostic[] = [];
  if (hasForbiddenField(record, FORBIDDEN_COMPLETION_MARKERS) || hasForbiddenField(record.binding, FORBIDDEN_COMPLETION_MARKERS)) {
    diagnostics.push({ code: 'FORBIDDEN_FIELD' });
  }
  if (typeof record.capability !== 'string' || record.capability.length === 0) {
    diagnostics.push({ code: 'FORBIDDEN_FIELD' });
  }
  const binding = record.binding as Record<string, unknown> | null | undefined;
  if (
    binding === null ||
    typeof binding !== 'object' ||
    typeof binding.signingAddress !== 'string' ||
    !/^[A-Za-z0-9]{40,64}$/.test(binding.signingAddress) ||
    typeof binding.encryptionAddress !== 'string' ||
    !/^[A-Za-z0-9]{40,64}$/.test(binding.encryptionAddress)
  ) {
    diagnostics.push({ code: 'FORBIDDEN_FIELD' });
  }
  if (record.outcome !== 'provisioned' && record.outcome !== 'resumed') {
    diagnostics.push({ code: 'FORBIDDEN_FIELD' });
  }
  if (diagnostics.length > 0) {
    return { ok: false, diagnostics };
  }
  const validatedBinding = binding as { signingAddress: string; encryptionAddress: string };
  return {
    ok: true,
    diagnostics: [],
    completion: {
      capability: record.capability as VerificationOnlyCapability,
      binding: { signingAddress: validatedBinding.signingAddress, encryptionAddress: validatedBinding.encryptionAddress },
      outcome: record.outcome as VerificationOnlyCompletion['outcome'],
    },
  };
}

/** The child-flow completion handoff port (framework-neutral). */
export interface OnboardingChildHandoffPort {
  /** Await the child's completion; emits verification-only at most. */
  awaitCompletion(): Promise<VerificationOnlyCompletion>;
  /** Request child cleanup before Back (must acknowledge before first-run). */
  cleanup(): Promise<{ readonly kind: 'CHILD_CLEANUP_COMPLETE' }>;
}
