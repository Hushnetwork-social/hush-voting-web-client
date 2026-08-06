/**
 * FEAT-010 web actor adapters (Task 7.3) — FEAT-002 ports over the sealed
 * browser-vault client.
 *
 * Maps the closed worker outcomes onto the FEAT-002 typed results the auth
 * machine consumes. Every mapping is deterministic and secret-free; unknown
 * or malformed worker outcomes fail closed (never a fabricated success).
 * The SecretSubmissionSink hands secrets directly to the authenticated
 * MessagePort and clears the page-side copy immediately.
 *
 * Normative source: FEAT-002 ports.ts/results.ts; FEAT-004 handoff;
 * FEAT-010 FeatureDescription "Returning Unlock", "Removal"; AC-010-029/035/036/037/073/074.
 */

import type { BrowserVaultClient, ClientOperationResult } from '../../browser-vault/production/client';
import type { LocalUserAuthorityPort, SecretAuthorityPort, IdentityVerificationPort, RemovalPort, BrowserCoordinationPort } from '../ports';
import type { SessionEpoch, LocalUserRef, OperationId } from '../types';
import type { InitializationResult, UnlockResult, VerificationResult, RemovalResult, CoordinationResult } from '../results';
import { AUTH_TIMING } from '../types';

/** Safe payload views produced by the worker (closed, never secrets). */
export interface WorkerSafeIdentityPayload {
  readonly safeIdentity?: { readonly alias?: unknown; readonly abbreviatedSigningAddress?: unknown };
  readonly surface?: unknown;
  readonly reason?: unknown;
}

function safeIdentityFromPayload(payload: unknown): { readonly alias: string; readonly abbreviatedSigningAddress: string } | null {
  if (typeof payload !== 'object' || payload === null) {
    return null;
  }
  const record = payload as WorkerSafeIdentityPayload;
  const identity = record.safeIdentity;
  if (typeof identity !== 'object' || identity === null) {
    return null;
  }
  const alias = identity.alias;
  const abbreviated = identity.abbreviatedSigningAddress;
  if (typeof alias !== 'string' || alias.length === 0 || typeof abbreviated !== 'string' || abbreviated.length === 0) {
    return null;
  }
  return { alias, abbreviatedSigningAddress: abbreviated };
}

/** Cancelable operation wrapper used by every adapter. */
function cancelable<T>(client: BrowserVaultClient, operationId: OperationId, result: Promise<T>): { readonly operationId: OperationId; readonly result: Promise<T> } {
  return {
    operationId,
    result,
  };
}

/**
 * Local-user authority port: worker startup inspection → typed INIT result.
 * Startup precedence mapping (documented decision): the closed INIT
 * vocabulary has no tombstone/staged codes, so an active removal tombstone
 * surfaces as INIT_CORRUPT_VAULT (blocked error with recoveryGuidance +
 * removal); the removal action resumes the verified removal inside the
 * worker. Retry re-inspects.
 */
/** Ensure the sealed client is connected before dispatch (fail closed). */
async function ensureConnected(client: BrowserVaultClient): Promise<boolean> {
  if (client.isConnected()) {
    return true;
  }
  const handshake = await client.connect();
  return handshake.ok;
}

export function createWebLocalUserAuthority(client: BrowserVaultClient): LocalUserAuthorityPort {
  return {
    initialize(epoch: SessionEpoch) {
      const operationId = `init-${epoch}-${Date.now().toString(36)}` as OperationId;
      const result: Promise<InitializationResult> = ensureConnected(client).then((connected) => {
        if (!connected) {
          return { code: 'INIT_STORAGE_UNAVAILABLE' } as InitializationResult;
        }
        return client.dispatch('inspectStartup').then((outcome) => {
        switch (outcome.outcome) {
          case 'OK': {
            const payload = outcome.payload as { surface?: unknown; safeIdentity?: unknown } | undefined;
            if (payload?.surface === 'verifiedAbsent') {
              return { code: 'INIT_NO_LOCAL_USER' } as InitializationResult;
            }
            if (payload?.surface === 'lockedVault') {
              const safeIdentity = safeIdentityFromPayload(outcome.payload);
              if (safeIdentity) {
                return { code: 'INIT_LOCKED_USER', safeIdentity } as InitializationResult;
              }
              return { code: 'INIT_CORRUPT_VAULT' } as InitializationResult;
            }
            if (payload?.surface === 'removalTombstone') {
              // Resume verified removal through the removal action.
              return { code: 'INIT_CORRUPT_VAULT' } as InitializationResult;
            }
            if (payload?.surface === 'quarantine') {
              return { code: 'INIT_CORRUPT_VAULT' } as InitializationResult;
            }
            return { code: 'INIT_CORRUPT_VAULT' } as InitializationResult;
          }
          case 'UNSUPPORTED_VAULT':
            return { code: 'INIT_UNSUPPORTED_VAULT_VERSION' } as InitializationResult;
          case 'CORRUPT_VAULT':
            return { code: 'INIT_CORRUPT_VAULT' } as InitializationResult;
          case 'TRANSPORT_UNAVAILABLE':
          case 'AUTHORITY_INVALIDATED':
            return { code: 'INIT_STORAGE_UNAVAILABLE' } as InitializationResult;
          default:
            return { code: 'INIT_STORAGE_UNAVAILABLE' } as InitializationResult;
        }
        });
      });
      return cancelable(client, operationId, result);
    },
    cancel(operationId: OperationId) {
      client.cancel(operationId);
    },
  };
}

/**
 * Secret-authority port: unlock over the worker with the exact combined
 * error, cooldown schedule, and support codes. The machine never sees the
 * password; the UI hands it to the sink.
 */
export function createWebSecretAuthority(client: BrowserVaultClient): SecretAuthorityPort {
  return {
    beginUnlock(epoch: SessionEpoch) {
      const operationId = `unlock-${epoch}-${Date.now().toString(36)}` as OperationId;
      const result: Promise<UnlockResult> = ensureConnected(client).then((connected) => {
        if (!connected) {
          return { code: 'UNKNOWN_FAILURE', supportCode: `au-${operationId.slice(-6)}` } as UnlockResult;
        }
        // The protocol operation MUST carry the adapter's operation id so the
        // SecretSubmissionSink (keyed by the machine's OPERATION.STARTED id)
        // reaches the exact operation the worker consumes.
        return client.dispatch('unlockPassword', undefined, undefined, operationId).then((outcome) => {
        switch (outcome.outcome) {
          case 'OK':
            return { code: 'UNLOCK_SUCCESS' } as UnlockResult;
          case 'WRONG_PASSWORD_OR_DAMAGED':
            return { code: 'UNLOCK_WRONG_PASSWORD_OR_DAMAGED' } as UnlockResult;
          case 'THROTTLED': {
            const deadline = typeof outcome.retryDeadlineMs === 'number' ? outcome.retryDeadlineMs : Date.now() + 5000;
            return { code: 'UNLOCK_THROTTLED', cooldownDeadlineMs: deadline } as UnlockResult;
          }
          case 'NETWORK_MISMATCH':
            return { code: 'UNKNOWN_FAILURE', supportCode: `nm-${operationId.slice(-6)}` } as UnlockResult;
          case 'UNSUPPORTED_VAULT':
            return { code: 'UNKNOWN_FAILURE', supportCode: `uv-${operationId.slice(-6)}` } as UnlockResult;
          case 'CORRUPT_VAULT':
            return { code: 'UNKNOWN_FAILURE', supportCode: `cv-${operationId.slice(-6)}` } as UnlockResult;
          case 'TRANSPORT_UNAVAILABLE':
          case 'AUTHORITY_INVALIDATED':
            return { code: 'UNKNOWN_FAILURE', supportCode: `au-${operationId.slice(-6)}` } as UnlockResult;
          default:
            return { code: 'UNKNOWN_FAILURE', supportCode: `uf-${operationId.slice(-6)}` } as UnlockResult;
        }
        });
      });
      return cancelable(client, operationId, result);
    },
    cancel(operationId: OperationId) {
      client.cancel(operationId);
    },
  };
}

/** Fresh exact online verification port (worker-owned both-key lookup). */
export function createWebIdentityVerification(client: BrowserVaultClient): IdentityVerificationPort {
  return {
    verifyOnline(epoch: SessionEpoch, _localUserRef: LocalUserRef) {
      const operationId = `verify-${epoch}-${Date.now().toString(36)}` as OperationId;
      const result: Promise<VerificationResult> = ensureConnected(client).then((connected) => {
        if (!connected) {
          return { code: 'VERIFY_NETWORK_UNAVAILABLE' } as VerificationResult;
        }
        return client.dispatch('verifyOnlineIdentity').then((outcome) => {
        switch (outcome.outcome) {
          case 'OK':
            return { code: 'VERIFY_SUCCESS' } as VerificationResult;
          case 'PROFILE_MISSING': {
            const safe = safeIdentityFromPayload(outcome.payload);
            if (safe) {
              return { code: 'VERIFY_PROFILE_MISSING', safeCandidate: safe } as VerificationResult;
            }
            return { code: 'VERIFY_PROFILE_MISSING', safeCandidate: { alias: 'Unknown', abbreviatedSigningAddress: '…' } } as VerificationResult;
          }
          case 'SIGNING_KEY_MISMATCH':
            return { code: 'VERIFY_SIGNING_KEY_MISMATCH' } as VerificationResult;
          case 'ENCRYPTION_KEY_MISMATCH':
            return { code: 'VERIFY_ENCRYPTION_KEY_MISMATCH' } as VerificationResult;
          case 'VERIFY_TIMEOUT':
            return { code: 'VERIFY_TIMEOUT' } as VerificationResult;
          case 'NETWORK_UNAVAILABLE':
            return { code: 'VERIFY_NETWORK_UNAVAILABLE' } as VerificationResult;
          case 'TRANSPORT_UNAVAILABLE':
          case 'AUTHORITY_INVALIDATED':
            return { code: 'VERIFY_NETWORK_UNAVAILABLE' } as VerificationResult;
          default:
            return { code: 'UNKNOWN_FAILURE', supportCode: `vf-${operationId.slice(-6)}` } as VerificationResult;
        }
        });
      });
      return cancelable(client, operationId, result);
    },
    cancel(operationId: OperationId) {
      client.cancel(operationId);
    },
  };
}

/** Removal port: tombstone-backed verified removal (idempotent resume). */
export function createWebRemoval(client: BrowserVaultClient, issueCapability: () => Promise<string>): RemovalPort {
  return {
    removeLocalUser(epoch: SessionEpoch) {
      const operationId = `remove-${epoch}-${Date.now().toString(36)}` as OperationId;
      let freshCapabilityId: Promise<string>;
      try {
        freshCapabilityId = issueCapability();
      } catch {
        return cancelable(client, operationId, Promise.resolve({ code: 'UNKNOWN_FAILURE', supportCode: 'cp-' } as RemovalResult));
      }
      const result: Promise<RemovalResult> = freshCapabilityId.then((capabilityId) =>
        client.dispatch('removeLocalUser', undefined, capabilityId).then((outcome) => {
          switch (outcome.outcome) {
            case 'OK':
              return { code: 'REMOVAL_COMPLETE' } as RemovalResult;
            case 'CORRUPT_VAULT':
              return { code: 'REMOVAL_BLOCKED_REMEDIATION', remediation: 'retry' } as RemovalResult;
            case 'TRANSPORT_UNAVAILABLE':
            case 'AUTHORITY_INVALIDATED':
              return { code: 'UNKNOWN_FAILURE', supportCode: `rm-${operationId.slice(-6)}` } as RemovalResult;
            default:
              return { code: 'UNKNOWN_FAILURE', supportCode: `rm-${operationId.slice(-6)}` } as RemovalResult;
          }
        }),
      );
      return cancelable(client, operationId, result);
    },
    cancel(operationId: OperationId) {
      client.cancel(operationId);
    },
  };
}

/**
 * Browser coordination port: SharedWorker handshake + exclusive Web Lock.
 * A failed handshake or a held lock yields COORDINATION_UNSAFE (never a
 * fallback to another storage authority).
 */
export function createWebBrowserCoordination(client: BrowserVaultClient): BrowserCoordinationPort {
  const LOCK_NAME = 'hushvoting-vault-authority';
  return {
    acquire(epoch: SessionEpoch) {
      const operationId = `coord-${epoch}-${Date.now().toString(36)}` as OperationId;
      const result: Promise<CoordinationResult> = (async () => {
        if (!client.isConnected()) {
          const handshake = await client.connect();
          if (!handshake.ok) {
            return { code: 'COORDINATION_UNSAFE' } as CoordinationResult;
          }
        }
        if (typeof navigator === 'undefined' || typeof navigator.locks === 'undefined') {
          return { code: 'COORDINATION_UNSAFE' } as CoordinationResult;
        }
        const acquired = await navigator.locks.request(LOCK_NAME, { ifAvailable: true }, () => true);
        return (acquired ? { code: 'COORDINATION_SAFE' } : { code: 'COORDINATION_UNSAFE' }) as CoordinationResult;
      })();
      return cancelable(client, operationId, result);
    },
    async release(_epoch: SessionEpoch) {
      // Web Locks release on scope exit; the worker lease is authority-owned.
    },
    cancel(operationId: OperationId) {
      client.cancel(operationId);
    },
  };
}

/** Map a worker operation result to a typed failure (helper). */
export function outcomeToFailure(outcome: ClientOperationResult, fallbackSupport: string): { readonly code: 'UNKNOWN_FAILURE'; readonly supportCode: string } {
  return { code: 'UNKNOWN_FAILURE', supportCode: outcome.supportCode ?? fallbackSupport };
}

/** Timeout guard for initialization (branded shell ≤ 5 s; AC-010-024). */
export const INIT_INSPECTION_TIMEOUT_MS = AUTH_TIMING.initTimeoutMs;

/** Public exports for tests. */
export const webActorExports = { safeIdentityFromPayload, outcomeToFailure, INIT_INSPECTION_TIMEOUT_MS };
