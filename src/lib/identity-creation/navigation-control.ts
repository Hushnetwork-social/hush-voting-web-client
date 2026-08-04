/**
 * FEAT-007 identity-creation — navigation, history, lifecycle, and ownership
 * presentation control.
 *
 * Implements the root-only navigation rules for the Create User journey: one
 * opaque same-URL history entry per navigation-relevant step; unified browser/
 * Android/in-app Back; history invalidation after the provisional boundary;
 * vault-inspection rejection of forged/stale/restored onboarding tokens; and
 * the non-secret `local user now exists` cross-tab event. The visible URL
 * never changes from `/`.
 *
 * Normative source: FEAT-007 FeatureDescription "Navigation and History",
 * "Connectivity and Offline Behavior"; EPIC-001 design baseline shared header;
 * FEAT-002 root-only navigation authority.
 */

/** Navigation-relevant creation destinations (typed, never serialized). */
export type CreationDestinationKind =
  | 'createEntry'
  | 'createPreflight'
  | 'createProfile'
  | 'createGenerate'
  | 'createRecovery'
  | 'createConfirmRecovery'
  | 'createProtect'
  | 'createReview'
  | 'createWaiting'
  | 'createDelay'
  | 'createConnection'
  | 'createCorrecting'
  | 'createCancelling';

/** Steps that push one opaque history entry (minor edits/reveals do not). */
export const NAVIGATION_RELEVANT_STEPS: ReadonlySet<CreationDestinationKind> = new Set<CreationDestinationKind>([
  'createEntry',
  'createPreflight',
  'createProfile',
  'createGenerate',
  'createRecovery',
  'createConfirmRecovery',
  'createProtect',
  'createReview',
  'createWaiting',
  'createDelay',
  'createConnection',
  'createCorrecting',
  'createCancelling',
]);

/** Minor, non-history steps (validation, input, reveal controls, accordion). */
export type CreationMinorChange = 'fieldEdit' | 'validationMessage' | 'revealToggle' | 'acknowledgementToggle';

/** One opaque history entry decision. */
export function decideHistoryEntry(destination: CreationDestinationKind, minor: CreationMinorChange | null): { readonly push: boolean; readonly destination: CreationDestinationKind | null } {
  if (minor !== null) {
    // Minor changes never create history entries.
    return { push: false, destination: null };
  }
  if (!NAVIGATION_RELEVANT_STEPS.has(destination)) {
    return { push: false, destination: null };
  }
  return { push: true, destination };
}

/** Unified Back transition across browser/Android/in-app Back. */
export function unifiedBack(current: CreationDestinationKind, historyDepth: number): CreationDestinationKind | 'root' | 'locked' {
  if (historyDepth <= 1) {
    // Safe first-run root: no Back at the root.
    return 'root';
  }
  switch (current) {
    case 'createWaiting':
    case 'createDelay':
    case 'createConnection':
      // After provisional persistence, Back locks the saved local identity
      // and shows returning-user unlock — never reopens creation history.
      return 'locked';
    case 'createReview':
      return 'createProtect';
    case 'createProtect':
      return 'createConfirmRecovery';
    case 'createConfirmRecovery':
      return 'createRecovery';
    case 'createRecovery':
      return 'createGenerate';
    case 'createGenerate':
      return 'createProfile';
    case 'createProfile':
      return 'createPreflight';
    case 'createPreflight':
      return 'createEntry';
    default:
      return 'root';
  }
}

/**
 * History invalidation after the provisional boundary: pre-creation entries
 * can never render as a fresh creation flow; Back resolves to Lock/unlock.
 */
export function invalidatePreCreationHistory(preCreationDepth: number, localBoundaryCrossed: boolean): { readonly invalidated: boolean; readonly safeBackTarget: 'locked' | null } {
  if (!localBoundaryCrossed) {
    return { invalidated: false, safeBackTarget: null };
  }
  return { invalidated: preCreationDepth > 0, safeBackTarget: 'locked' };
}

/** Vault-inspection guard: stale/forged/restored/manual tokens are rejected. */
export function inspectOnboardingToken(tokenIsValid: boolean, vaultShowsProvisionalOrUser: boolean): { readonly allowed: boolean; readonly reason: 'ok' | 'forgedToken' | 'localUserExists' } {
  if (!tokenIsValid) {
    return { allowed: false, reason: 'forgedToken' };
  }
  if (vaultShowsProvisionalOrUser) {
    // A local/provisional user always blocks the three first-run actions.
    return { allowed: false, reason: 'localUserExists' };
  }
  return { allowed: true, reason: 'ok' };
}

/** Non-secret cross-tab event vocabulary (never broadcasts identity data). */
export type CrossTabEventKind = 'localUserNowExists';

export interface CrossTabEvent {
  readonly kind: CrossTabEventKind;
}

/** Build the non-secret local-user event (no alias/address/transaction data). */
export function localUserExistsEvent(): CrossTabEvent {
  return { kind: 'localUserNowExists' };
}

/** Single-owner authority: one vault authority per process/tab for creation. */
export function canProvisionConcurrently(owners: number): { readonly allowed: boolean; readonly reason: 'singleOwner' | 'multipleOwners' } {
  return owners <= 1 ? { allowed: true, reason: 'singleOwner' } : { allowed: false, reason: 'multipleOwners' };
}
