/**
 * FEAT-002 authentication authority — XState v5 machine (framework-neutral).
 *
 * The machine is the SOLE authentication authority exposed to React. It has
 * parallel regions so connectivity cannot erase authentication context:
 *
 *   auth          — initializing, noLocalUser, onboarding, locked, unlocking,
 *                   verifyingIdentityOnline, missingProfileConfirmation,
 *                   authenticated, recoverableError, blockedError,
 *                   removingLocalUser
 *   connectivity  — unknown, online, offline, reconnecting
 *
 * Design rules enforced here:
 * - `authenticated` requires BOTH a live opaque capability and a current
 *   online confirmation (profile + both keys). Offline entry is impossible.
 * - Actor operations are epoch + operation scoped; OPERATION.STARTED assigns
 *   the active operation id and stale results (wrong epoch or operation id)
 *   are ignored by guards. State exit cancels the invoked actor.
 * - One operation per state; duplicate submission is rejected by the
 *   noActiveOperation guard and by the absence of transition handlers for
 *   repeated intents while an operation is pending.
 * - Secrets never appear in events or context; the UI hands them to the
 *   secret authority directly (SecretSubmissionSink) and the machine sees
 *   only an opaque operation id and a typed safe result.
 * - Missing mandatory actors and missing onboarding capabilities fail closed.
 *
 * The machine is pure with respect to actor side effects: callback actors
 * call the injected ports, await the typed result, and send scoped events
 * back. Tests drive the same event stream deterministically.
 */

import { assign, fromCallback, setup } from 'xstate';
import { INITIAL_EPOCH, isStaleEpoch, nextEpoch } from './policies.js';
import type {
  AuthIntent,
  AuthMachineContext,
  CapabilityId,
  ConnectivityStateCode,
  InvalidationReason,
  LocalUserRef,
  OperationId,
  OnboardingKind,
  SessionEpoch,
  SupportCode,
} from '../types.js';
import type { AuthActors } from '../ports.js';
import type {
  InitializationResult,
  OnboardingResult,
  RemovalResult,
  UnlockResult,
  VerificationResult,
} from '../results.js';

/** Actor kinds the machine can start. */
export type OperationKind =
  | 'initialize'
  | 'unlock'
  | 'verify'
  | 'onboarding'
  | 'confirmMissingProfile'
  | 'removal';

/** Events accepted by the machine (intents + scoped actor/system events). */
export type AuthMachineEvent =
  | AuthIntent
  | { readonly type: 'OPERATION.STARTED'; readonly kind: OperationKind; readonly operationId: OperationId; readonly epoch: SessionEpoch }
  | { readonly type: 'ACTOR.INITIALIZE_RESULT'; readonly operationId: OperationId; readonly epoch: SessionEpoch; readonly result: InitializationResult }
  | { readonly type: 'ACTOR.UNLOCK_RESULT'; readonly operationId: OperationId; readonly epoch: SessionEpoch; readonly result: UnlockResult }
  | { readonly type: 'ACTOR.VERIFY_RESULT'; readonly operationId: OperationId; readonly epoch: SessionEpoch; readonly result: VerificationResult }
  | { readonly type: 'ACTOR.ONBOARDING_RESULT'; readonly operationId: OperationId; readonly epoch: SessionEpoch; readonly result: OnboardingResult }
  | { readonly type: 'ACTOR.REMOVAL_RESULT'; readonly operationId: OperationId; readonly epoch: SessionEpoch; readonly result: RemovalResult }
  | { readonly type: 'CONNECTIVITY.CHANGE'; readonly state: ConnectivityStateCode }
  | { readonly type: 'SESSION.AUTHORITY_LOST' }
  | { readonly type: 'SESSION.INVALIDATED'; readonly reason: InvalidationReason }
  | { readonly type: 'TIMER.IDLE_TIMEOUT' }
  | { readonly type: 'TIMER.BACKGROUND_TIMEOUT' };

/** Machine context = allowlisted auth context + injected actor ports. */
export type AuthMachineContextWithActors = AuthMachineContext & {
  readonly actors: AuthActors;
  /** Active onboarding child flow kind, when in onboarding. */
  readonly onboardingKind: OnboardingKind | null;
  /** Opaque local-user reference held while provisioned (never a secret). */
  readonly localUserRef: LocalUserRef | null;
  /** Parallel connectivity region state (mirrors the region for guards). */
  readonly connectivity: ConnectivityStateCode;
};

/** Input: validated production actors + registered capability flags. */
export interface AuthMachineInput {
  readonly actors: AuthActors;
  readonly registeredCapabilities: ReadonlySet<CapabilityId>;
  readonly safeCoordination: boolean;
}

/** Map an onboarding intent to its child-flow kind (or null). */
export function onboardingKindForIntent(type: string): OnboardingKind | null {
  switch (type) {
    case 'INTENT.CREATE_USER':
      return 'createUser';
    case 'INTENT.RESTORE_CREDENTIAL_FILE':
      return 'restoreCredentialFile';
    case 'INTENT.RESTORE_RECOVERY_WORDS':
      return 'restoreRecoveryWords';
    default:
      return null;
  }
}

/** Shared guard helpers (exported for tests). */
export const machineGuards = {
  isCurrentOperation: (
    context: AuthMachineContextWithActors,
    event: { operationId?: OperationId; epoch?: SessionEpoch },
  ): boolean =>
    event.operationId !== undefined &&
    event.operationId === context.activeOperationId &&
    (event.epoch === undefined || !isStaleEpoch(event.epoch, context.sessionEpoch)),
};

export const authMachine = setup({
  types: {
    context: {} as AuthMachineContextWithActors,
    events: {} as AuthMachineEvent,
    input: {} as AuthMachineInput,
  },
  actors: {
    initializeActor: fromCallback<AuthMachineEvent, { actor: AuthActors['localUserAuthority']; epoch: SessionEpoch }>(
      ({ input, sendBack }) => {
        if (input.actor === null) {
          sendBack({ type: 'SESSION.AUTHORITY_LOST' });
          return () => undefined;
        }
        const op = input.actor.initialize(input.epoch);
        sendBack({ type: 'OPERATION.STARTED', kind: 'initialize', operationId: op.operationId, epoch: input.epoch });
        void op.result.then((result) => {
          sendBack({ type: 'ACTOR.INITIALIZE_RESULT', operationId: op.operationId, epoch: input.epoch, result });
        });
        return () => {
          input.actor?.cancel(op.operationId);
        };
      },
    ),
    unlockActor: fromCallback<AuthMachineEvent, { actor: AuthActors['secretAuthority']; epoch: SessionEpoch }>(
      ({ input, sendBack }) => {
        if (input.actor === null) {
          sendBack({ type: 'SESSION.AUTHORITY_LOST' });
          return () => undefined;
        }
        const op = input.actor.beginUnlock(input.epoch);
        sendBack({ type: 'OPERATION.STARTED', kind: 'unlock', operationId: op.operationId, epoch: input.epoch });
        void op.result.then((result) => {
          sendBack({ type: 'ACTOR.UNLOCK_RESULT', operationId: op.operationId, epoch: input.epoch, result });
        });
        return () => {
          input.actor?.cancel(op.operationId);
        };
      },
    ),
    verifyActor: fromCallback<
      AuthMachineEvent,
      { actor: AuthActors['identityVerification']; epoch: SessionEpoch; localUserRef: LocalUserRef | null }
    >(({ input, sendBack }) => {
      if (input.actor === null) {
        sendBack({ type: 'SESSION.AUTHORITY_LOST' });
        return () => undefined;
      }
      const op = input.actor.verifyOnline(input.epoch, input.localUserRef ?? ('' as LocalUserRef));
      sendBack({ type: 'OPERATION.STARTED', kind: 'verify', operationId: op.operationId, epoch: input.epoch });
      void op.result.then((result) => {
        sendBack({ type: 'ACTOR.VERIFY_RESULT', operationId: op.operationId, epoch: input.epoch, result });
      });
      return () => {
        input.actor?.cancel(op.operationId);
      };
    }),
    onboardingActor: fromCallback<
      AuthMachineEvent,
      { actor: AuthActors['onboarding'][OnboardingKind]; kind: OnboardingKind; epoch: SessionEpoch }
    >(({ input, sendBack }) => {
      if (input.actor === null) {
        sendBack({ type: 'SESSION.AUTHORITY_LOST' });
        return () => undefined;
      }
      const op = input.actor.start(input.kind, input.epoch);
      sendBack({ type: 'OPERATION.STARTED', kind: 'onboarding', operationId: op.operationId, epoch: input.epoch });
      void op.result.then((result) => {
        sendBack({ type: 'ACTOR.ONBOARDING_RESULT', operationId: op.operationId, epoch: input.epoch, result });
      });
      return () => {
        input.actor?.cancel(op.operationId);
      };
    }),
    onboardingCleanupActor: fromCallback<
      AuthMachineEvent,
      { actor: AuthActors['onboarding'][OnboardingKind]; epoch: SessionEpoch }
    >(({ input, sendBack }) => {
      if (input.actor === null) {
        sendBack({ type: 'SESSION.AUTHORITY_LOST' });
        return () => undefined;
      }
      const op = input.actor.cleanup(input.epoch);
      sendBack({ type: 'OPERATION.STARTED', kind: 'onboarding', operationId: op.operationId, epoch: input.epoch });
      void op.result.then((result) => {
        sendBack({ type: 'ACTOR.ONBOARDING_RESULT', operationId: op.operationId, epoch: input.epoch, result });
      });
      return () => {
        input.actor?.cancel(op.operationId);
      };
    }),
    confirmMissingProfileActor: fromCallback<AuthMachineEvent, { actor: AuthActors['onboarding'][OnboardingKind]; epoch: SessionEpoch }>(
      ({ input, sendBack }) => {
        if (input.actor === null) {
          sendBack({ type: 'SESSION.AUTHORITY_LOST' });
          return () => undefined;
        }
        const op = input.actor.confirmMissingProfile(input.epoch);
        sendBack({ type: 'OPERATION.STARTED', kind: 'confirmMissingProfile', operationId: op.operationId, epoch: input.epoch });
        void op.result.then((result) => {
          sendBack({ type: 'ACTOR.VERIFY_RESULT', operationId: op.operationId, epoch: input.epoch, result });
        });
        return () => {
          input.actor?.cancel(op.operationId);
        };
      },
    ),
    removalActor: fromCallback<AuthMachineEvent, { actor: AuthActors['removal']; epoch: SessionEpoch }>(
      ({ input, sendBack }) => {
        if (input.actor === null) {
          sendBack({ type: 'SESSION.AUTHORITY_LOST' });
          return () => undefined;
        }
        const op = input.actor.removeLocalUser(input.epoch);
        sendBack({ type: 'OPERATION.STARTED', kind: 'removal', operationId: op.operationId, epoch: input.epoch });
        void op.result.then((result) => {
          sendBack({ type: 'ACTOR.REMOVAL_RESULT', operationId: op.operationId, epoch: input.epoch, result });
        });
        return () => {
          input.actor?.cancel(op.operationId);
        };
      },
    ),
  },
  actions: {
    assignActiveOperation: assign({
      activeOperationId: (args) => (args.event as { operationId: OperationId }).operationId,
    }),
    clearActiveOperation: assign({ activeOperationId: () => null as OperationId | null }),
    incrementEpoch: assign({
      sessionEpoch: ({ context }) => nextEpoch(context.sessionEpoch),
      activeOperationId: () => null as OperationId | null,
    }),
    assignOnboardingKind: assign({
      onboardingKind: (args) => onboardingKindForIntent(args.event.type) as OnboardingKind | null,
    }),
    clearOnboardingKind: assign({ onboardingKind: () => null as OnboardingKind | null }),
    assignSafeIdentity: assign({
      safeIdentity: (args) =>
        (args.event as { result?: { safeIdentity?: AuthMachineContext['safeIdentity'] } }).result?.safeIdentity ?? null,
    }),
    clearSafeIdentity: assign({ safeIdentity: () => null }),
    assignLocalUserRef: assign({
      localUserRef: (args) =>
        (args.event as { result?: { localUserRef?: LocalUserRef } }).result?.localUserRef ?? null,
    }),
    clearLocalUserRef: assign({ localUserRef: () => null as LocalUserRef | null }),
    assignOutcome: assign({
      outcomeCode: (args) =>
        (args.event as { result?: { code: AuthMachineContext['outcomeCode'] } }).result?.code ?? null,
    }),
    clearOutcome: assign({ outcomeCode: () => null }),
    assignSupportCode: assign({
      supportCode: (args) =>
        (args.event as { result?: { supportCode?: string } }).result?.supportCode as SupportCode | null,
    }),
    clearSupportCode: assign({ supportCode: () => null }),
  },
  guards: {
    hasSecretAuthority: ({ context }) => context.actors.secretAuthority !== null,
    hasIdentityVerification: ({ context }) => context.actors.identityVerification !== null,
    hasCreateCapability: ({ context }) => context.actors.onboarding.createUser !== null,
    hasRestoreFileCapability: ({ context }) => context.actors.onboarding.restoreCredentialFile !== null,
    hasRestoreWordsCapability: ({ context }) => context.actors.onboarding.restoreRecoveryWords !== null,
  },
}).createMachine({
  id: 'authAuthority',
  context: ({ input }) => ({
    sessionEpoch: INITIAL_EPOCH,
    activeOperationId: null as OperationId | null,
    registeredCapabilities: input.registeredCapabilities,
    safeCoordination: input.safeCoordination,
    safeIdentity: null,
    environment: null,
    cooldownDeadlineMs: null,
    navigationToken: null,
    supportCode: null,
    outcomeCode: null,
    coarseStageStartedAtMs: null,
    actors: input.actors,
    onboardingKind: null as OnboardingKind | null,
    localUserRef: null as LocalUserRef | null,
    connectivity: 'unknown' as ConnectivityStateCode,
  }),
  type: 'parallel',
  states: {
    auth: {
      id: 'auth',
      initial: 'initializing',
      states: {
        initializing: {
          invoke: {
            id: 'initialize',
            src: 'initializeActor',
            input: ({ context }) => ({ actor: context.actors.localUserAuthority, epoch: context.sessionEpoch }),
          },
          on: {
            'OPERATION.STARTED': {
              guard: ({ context, event }) =>
                context.activeOperationId === null && !isStaleEpoch(event.epoch, context.sessionEpoch),
              actions: 'assignActiveOperation',
            },
            'SESSION.AUTHORITY_LOST': {
              target: 'blockedError',
            },
            'ACTOR.INITIALIZE_RESULT': [
              {
                target: 'noLocalUser',
                guard: ({ context, event }) =>
                  machineGuards.isCurrentOperation(context, event) &&
                  (event.result.code === 'INIT_NO_LOCAL_USER' || event.result.code === 'INIT_MEMORY_ONLY'),
                actions: ['clearActiveOperation', 'clearSafeIdentity', 'clearLocalUserRef', 'assignOutcome'],
              },
              {
                target: 'locked',
                guard: ({ context, event }) =>
                  machineGuards.isCurrentOperation(context, event) && event.result.code === 'INIT_LOCKED_USER',
                actions: ['clearActiveOperation', 'assignSafeIdentity', 'assignLocalUserRef', 'assignOutcome'],
              },
              {
                target: 'recoverableError',
                guard: ({ context, event }) =>
                  machineGuards.isCurrentOperation(context, event) && event.result.code === 'INIT_STORAGE_UNAVAILABLE',
                actions: ['clearActiveOperation', 'assignOutcome'],
              },
              {
                target: 'blockedError',
                guard: ({ context, event }) =>
                  machineGuards.isCurrentOperation(context, event) &&
                  (event.result.code === 'INIT_UNSUPPORTED_VAULT_VERSION' ||
                    event.result.code === 'INIT_CORRUPT_VAULT' ||
                    event.result.code === 'INIT_UNSAFE_COORDINATION'),
                actions: ['clearActiveOperation', 'assignOutcome'],
              },
            ],
          },
        },
        noLocalUser: {
          entry: ['clearOutcome', 'clearActiveOperation', 'clearSafeIdentity', 'clearLocalUserRef', 'clearOnboardingKind'],
          on: {
            'INTENT.CREATE_USER': [
              { target: 'onboarding', guard: 'hasCreateCapability', actions: 'assignOnboardingKind' },
              { target: 'blockedError' },
            ],
            'INTENT.RESTORE_CREDENTIAL_FILE': [
              { target: 'onboarding', guard: 'hasRestoreFileCapability', actions: 'assignOnboardingKind' },
              { target: 'blockedError' },
            ],
            'INTENT.RESTORE_RECOVERY_WORDS': [
              { target: 'onboarding', guard: 'hasRestoreWordsCapability', actions: 'assignOnboardingKind' },
              { target: 'blockedError' },
            ],
          },
        },
        onboarding: {
          initial: 'running',
          states: {
            running: {
              invoke: {
                id: 'onboarding',
                src: 'onboardingActor',
                input: ({ context }) => ({
                  actor: context.actors.onboarding[context.onboardingKind ?? 'createUser'],
                  kind: context.onboardingKind ?? 'createUser',
                  epoch: context.sessionEpoch,
                }),
              },
              on: {
                'INTENT.BACK_FROM_ONBOARDING': {
                  target: '../cleanup',
                },
                'OPERATION.STARTED': {
                  guard: ({ context, event }) =>
                    context.activeOperationId === null && !isStaleEpoch(event.epoch, context.sessionEpoch),
                  actions: 'assignActiveOperation',
                },
                'ACTOR.ONBOARDING_RESULT': [
                  {
                    target: '#auth.verifyingIdentityOnline',
                    guard: ({ context, event }) =>
                      machineGuards.isCurrentOperation(context, event) && event.result.code === 'ONBOARDING_COMPLETED',
                    actions: ['clearActiveOperation', 'assignOutcome', 'assignLocalUserRef'],
                  },
                  {
                    target: '#auth.recoverableError',
                    guard: ({ context, event }) =>
                      machineGuards.isCurrentOperation(context, event) && event.result.code === 'UNKNOWN_FAILURE',
                    actions: ['clearActiveOperation', 'assignOutcome', 'assignSupportCode'],
                  },
                  {
                    target: '../cleanup',
                    guard: ({ context, event }) =>
                      machineGuards.isCurrentOperation(context, event) && event.result.code === 'ONBOARDING_BACK',
                    actions: 'clearActiveOperation',
                  },
                ],
              },
            },
            cleanup: {
              invoke: {
                id: 'onboardingCleanup',
                src: 'onboardingCleanupActor',
                input: ({ context }) => ({
                  actor: context.actors.onboarding[context.onboardingKind ?? 'createUser'],
                  epoch: context.sessionEpoch,
                }),
              },
              on: {
                'OPERATION.STARTED': {
                  guard: ({ context, event }) =>
                    context.activeOperationId === null && !isStaleEpoch(event.epoch, context.sessionEpoch),
                  actions: 'assignActiveOperation',
                },
                'ACTOR.ONBOARDING_RESULT': {
                  target: '#auth.noLocalUser',
                  guard: ({ context, event }) =>
                    machineGuards.isCurrentOperation(context, event) && event.result.code === 'ONBOARDING_CLEANUP_COMPLETE',
                  actions: ['clearActiveOperation', 'clearOutcome', 'clearOnboardingKind'],
                },
              },
            },
          },
        },
        locked: {
          entry: ['clearActiveOperation', 'clearOutcome', 'clearSupportCode'],
          on: {
            'INTENT.UNLOCK': [
              { target: 'unlocking', guard: 'hasSecretAuthority', actions: 'clearOutcome' },
              { target: 'blockedError' },
            ],
            'INTENT.REMOVE_LOCAL_USER': { target: 'removingLocalUser' },
          },
        },
        unlocking: {
          invoke: {
            id: 'unlock',
            src: 'unlockActor',
            input: ({ context }) => ({ actor: context.actors.secretAuthority, epoch: context.sessionEpoch }),
          },
          on: {
            'OPERATION.STARTED': {
              guard: ({ context, event }) =>
                context.activeOperationId === null && !isStaleEpoch(event.epoch, context.sessionEpoch),
              actions: 'assignActiveOperation',
            },
            'ACTOR.UNLOCK_RESULT': [
              {
                target: 'verifyingIdentityOnline',
                guard: ({ context, event }) =>
                  machineGuards.isCurrentOperation(context, event) && event.result.code === 'UNLOCK_SUCCESS',
                actions: ['clearActiveOperation', 'assignOutcome'],
              },
              {
                target: 'locked',
                guard: ({ context, event }) =>
                  machineGuards.isCurrentOperation(context, event) && event.result.code === 'UNLOCK_WRONG_PASSWORD_OR_DAMAGED',
                actions: ['clearActiveOperation', 'assignOutcome'],
              },
              {
                target: 'recoverableError',
                guard: ({ context, event }) =>
                  machineGuards.isCurrentOperation(context, event) &&
                  (event.result.code === 'UNLOCK_THROTTLED' || event.result.code === 'UNKNOWN_FAILURE'),
                actions: ['clearActiveOperation', 'assignOutcome', 'assignSupportCode'],
              },
            ],
          },
        },
        verifyingIdentityOnline: {
          invoke: {
            id: 'verify',
            src: 'verifyActor',
            input: ({ context }) => ({
              actor: context.actors.identityVerification,
              epoch: context.sessionEpoch,
              localUserRef: context.localUserRef,
            }),
          },
          on: {
            'OPERATION.STARTED': {
              guard: ({ context, event }) =>
                context.activeOperationId === null && !isStaleEpoch(event.epoch, context.sessionEpoch),
              actions: 'assignActiveOperation',
            },
            'ACTOR.VERIFY_RESULT': [
              {
                target: 'authenticated',
                guard: ({ context, event }) =>
                  machineGuards.isCurrentOperation(context, event) && event.result.code === 'VERIFY_SUCCESS',
                actions: ['clearActiveOperation', 'assignOutcome'],
              },
              {
                target: 'missingProfileConfirmation',
                guard: ({ context, event }) =>
                  machineGuards.isCurrentOperation(context, event) && event.result.code === 'VERIFY_PROFILE_MISSING',
                actions: ['clearActiveOperation', 'assignOutcome'],
              },
              {
                target: 'blockedError',
                guard: ({ context, event }) =>
                  machineGuards.isCurrentOperation(context, event) &&
                  (event.result.code === 'VERIFY_SIGNING_KEY_MISMATCH' || event.result.code === 'VERIFY_ENCRYPTION_KEY_MISMATCH'),
                actions: ['clearActiveOperation', 'assignOutcome'],
              },
              {
                target: 'recoverableError',
                guard: ({ context, event }) =>
                  machineGuards.isCurrentOperation(context, event) && event.result.code === 'UNKNOWN_FAILURE',
                actions: ['clearActiveOperation', 'assignOutcome', 'assignSupportCode'],
              },
              // VERIFY_TIMEOUT / VERIFY_NETWORK_UNAVAILABLE: stay behind the
              // locked verification gate; the connectivity region handles retry.
              {
                target: '.',
                guard: ({ context, event }) =>
                  machineGuards.isCurrentOperation(context, event) &&
                  (event.result.code === 'VERIFY_TIMEOUT' || event.result.code === 'VERIFY_NETWORK_UNAVAILABLE'),
                actions: ['clearActiveOperation', 'assignOutcome'],
              },
            ],
            'INTENT.RETRY': [
              { target: 'verifyingIdentityOnline', guard: 'hasIdentityVerification' },
            ],
          },
        },
        missingProfileConfirmation: {
          entry: 'clearOutcome',
          invoke: {
            id: 'confirmMissingProfile',
            src: 'confirmMissingProfileActor',
            input: ({ context }) => ({
              actor: context.actors.onboarding[context.onboardingKind ?? 'createUser'],
              epoch: context.sessionEpoch,
            }),
          },
          on: {
            'OPERATION.STARTED': {
              guard: ({ context, event }) =>
                context.activeOperationId === null && !isStaleEpoch(event.epoch, context.sessionEpoch),
              actions: 'assignActiveOperation',
            },
            'ACTOR.VERIFY_RESULT': [
              {
                target: 'authenticated',
                guard: ({ context, event }) =>
                  machineGuards.isCurrentOperation(context, event) && event.result.code === 'VERIFY_SUCCESS',
                actions: ['clearActiveOperation', 'assignOutcome', 'assignLocalUserRef'],
              },
              {
                target: 'blockedError',
                guard: ({ context, event }) =>
                  machineGuards.isCurrentOperation(context, event) &&
                  (event.result.code === 'VERIFY_SIGNING_KEY_MISMATCH' || event.result.code === 'VERIFY_ENCRYPTION_KEY_MISMATCH'),
                actions: ['clearActiveOperation', 'assignOutcome'],
              },
              {
                target: 'recoverableError',
                guard: ({ context, event }) =>
                  machineGuards.isCurrentOperation(context, event) && event.result.code === 'UNKNOWN_FAILURE',
                actions: ['clearActiveOperation', 'assignOutcome', 'assignSupportCode'],
              },
              {
                // Still missing after confirmation attempt — stay for another explicit action.
                target: '.',
                guard: ({ context, event }) =>
                  machineGuards.isCurrentOperation(context, event) && event.result.code === 'VERIFY_PROFILE_MISSING',
                actions: ['clearActiveOperation', 'assignOutcome'],
              },
            ],
            'INTENT.BACK_FROM_ONBOARDING': { target: 'noLocalUser' },
          },
        },
        authenticated: {
          entry: ['clearActiveOperation', 'clearOutcome', 'clearSupportCode'],
          on: {
            'INTENT.LOCK': { target: 'locked', actions: 'incrementEpoch' },
            'TIMER.IDLE_TIMEOUT': { target: 'locked', actions: 'incrementEpoch' },
            'TIMER.BACKGROUND_TIMEOUT': { target: 'locked', actions: 'incrementEpoch' },
            'SESSION.INVALIDATED': { target: 'locked', actions: 'incrementEpoch' },
            'SESSION.AUTHORITY_LOST': { target: 'locked', actions: 'incrementEpoch' },
            'INTENT.REMOVE_LOCAL_USER': { target: 'removingLocalUser', actions: 'incrementEpoch' },
            'INTENT.REAUTHENTICATION_REQUIRED': { target: 'locked', actions: 'incrementEpoch' },
          },
        },
        recoverableError: {
          entry: ['clearActiveOperation'],
          on: {
            'INTENT.RETRY': [
              {
                target: 'initializing',
                guard: ({ context }) =>
                  context.outcomeCode === 'INIT_STORAGE_UNAVAILABLE' ||
                  context.outcomeCode === 'UNKNOWN_FAILURE',
              },
              {
                target: 'unlocking',
                guard: ({ context }) => context.outcomeCode === 'UNLOCK_THROTTLED',
              },
              {
                target: 'verifyingIdentityOnline',
                guard: ({ context }) =>
                  context.outcomeCode === 'VERIFY_TIMEOUT' ||
                  context.outcomeCode === 'VERIFY_NETWORK_UNAVAILABLE' ||
                  context.outcomeCode === null,
              },
            ],
            'INTENT.LOCK': { target: 'locked', actions: 'incrementEpoch' },
            'INTENT.REMOVE_LOCAL_USER': { target: 'removingLocalUser', actions: 'incrementEpoch' },
          },
        },
        blockedError: {
          entry: ['clearActiveOperation'],
          on: {
            'INTENT.RETRY': { target: 'initializing' },
            'INTENT.REMOVE_LOCAL_USER': { target: 'removingLocalUser', actions: 'incrementEpoch' },
          },
        },
        removingLocalUser: {
          invoke: {
            id: 'removal',
            src: 'removalActor',
            input: ({ context }) => ({ actor: context.actors.removal, epoch: context.sessionEpoch }),
          },
          on: {
            'OPERATION.STARTED': {
              guard: ({ context, event }) =>
                context.activeOperationId === null && !isStaleEpoch(event.epoch, context.sessionEpoch),
              actions: 'assignActiveOperation',
            },
            'ACTOR.REMOVAL_RESULT': [
              {
                target: 'noLocalUser',
                guard: ({ context, event }) =>
                  machineGuards.isCurrentOperation(context, event) && event.result.code === 'REMOVAL_COMPLETE',
                actions: ['clearActiveOperation', 'clearSafeIdentity', 'clearLocalUserRef', 'clearOutcome', 'clearOnboardingKind'],
              },
              {
                target: 'blockedError',
                guard: ({ context, event }) =>
                  machineGuards.isCurrentOperation(context, event) && event.result.code === 'REMOVAL_BLOCKED_REMEDIATION',
                actions: ['clearActiveOperation', 'assignOutcome'],
              },
              {
                target: 'recoverableError',
                guard: ({ context, event }) =>
                  machineGuards.isCurrentOperation(context, event) && event.result.code === 'UNKNOWN_FAILURE',
                actions: ['clearActiveOperation', 'assignOutcome', 'assignSupportCode'],
              },
            ],
          },
        },
      },
    },
    connectivity: {
      initial: 'unknown',
      states: {
        unknown: {
          on: {
            'CONNECTIVITY.CHANGE': [
              { target: 'online', guard: ({ event }) => event.state === 'online' },
              { target: 'offline', guard: ({ event }) => event.state === 'offline' },
              { target: 'reconnecting', guard: ({ event }) => event.state === 'reconnecting' },
            ],
          },
        },
        online: {
          on: {
            'CONNECTIVITY.CHANGE': [
              { target: 'offline', guard: ({ event }) => event.state === 'offline' },
              { target: 'reconnecting', guard: ({ event }) => event.state === 'reconnecting' },
            ],
          },
        },
        offline: {
          on: {
            'CONNECTIVITY.CHANGE': [
              { target: 'online', guard: ({ event }) => event.state === 'online' },
              { target: 'reconnecting', guard: ({ event }) => event.state === 'reconnecting' },
            ],
          },
        },
        reconnecting: {
          on: {
            'CONNECTIVITY.CHANGE': [
              { target: 'online', guard: ({ event }) => event.state === 'online' },
              { target: 'offline', guard: ({ event }) => event.state === 'offline' },
            ],
          },
        },
      },
    },
  },
});
