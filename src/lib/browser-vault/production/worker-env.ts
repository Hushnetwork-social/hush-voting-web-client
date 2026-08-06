/**
 * FEAT-010 production browser worker environment (Task 7.3).
 *
 * Wires the FEAT-004 `WorkerAuthority` to the real sealed vault engine:
 * real IndexedDB storage, real suite crypto, the pinned deployment manifest,
 * same-origin BFF identity lookup, BroadcastChannel advisory, and the
 * out-of-band secret transfer channel. This module runs ONLY inside the
 * SharedWorker (imported by the worker entry; never by page code).
 *
 * The handshake's runtime configuration identifier resolves through the
 * CLOSED manifest catalog: only the pinned isolated devnet configuration is
 * admissible for local/development operation; production without an approved
 * manifest fails closed (no fabricated environment, no fallback).
 *
 * Normative source: FEAT-004 FeatureDescription "Worker delivery",
 * "Capability Preflight"; FEAT-010 FeatureDescription "Current Network
 * Binding", "Real Composition"; AC-010-019/020.
 */

import type { AuthorityEnvironment } from '../authority/authority';
import { resolveManifest, ISOLATED_DEVNET_MANIFEST } from '../../runtime/manifests';
import type { DeploymentManifest } from '../../runtime/deployment';
import { SealedVaultEngine, type SealedOutcome } from './sealed-vault';
import type { VaultStorageSession } from '../storage/wrapper';
import type { SuiteCryptoOperations } from '../../vault-core/contracts/ports';
import type { RuntimeConfigId } from '../contracts/protocol';

/** Same-origin BFF identity lookup path (server-only route; no NEXT_PUBLIC). */
const BFF_IDENTITY_LOOKUP_PATH = '/api/identity' as const;

/** Same-origin BFF signed-transaction submission path. */
const BFF_BLOCKCHAIN_SUBMIT_PATH = '/api/blockchain' as const;

/** Identity lookup deadline (bounded; matches the transport contract). */
const LOOKUP_TIMEOUT_MS = 10_000 as const;

/** Closed outcome vocabulary emitted to the authority (typed, secret-free). */
export type WorkerOperationOutcome =
  | { readonly outcome: 'OK'; readonly payload?: unknown }
  | { readonly outcome: 'WRONG_PASSWORD_OR_DAMAGED' }
  | { readonly outcome: 'THROTTLED'; readonly retryDeadlineMs?: number }
  | { readonly outcome: 'NETWORK_MISMATCH' }
  | { readonly outcome: 'UNSUPPORTED_VAULT' }
  | { readonly outcome: 'CORRUPT_VAULT' }
  | { readonly outcome: 'PROFILE_MISSING'; readonly payload?: unknown }
  | { readonly outcome: 'SIGNING_KEY_MISMATCH' }
  | { readonly outcome: 'ENCRYPTION_KEY_MISMATCH' }
  | { readonly outcome: 'VERIFY_TIMEOUT' }
  | { readonly outcome: 'NETWORK_UNAVAILABLE' }
  | { readonly outcome: 'INVALID_INPUT'; readonly payload?: unknown }
  | { readonly outcome: 'UNKNOWN_FAILURE'; readonly payload?: unknown };

function outcomeFromSealed(result: SealedOutcome): WorkerOperationOutcome {
  switch (result.code) {
    case 'OK':
      return { outcome: 'OK', payload: result.detail };
    case 'WRONG_PASSWORD_OR_DAMAGED':
      return { outcome: 'WRONG_PASSWORD_OR_DAMAGED' };
    case 'THROTTLED':
      return { outcome: 'THROTTLED', retryDeadlineMs: result.cooldownDeadlineMs };
    case 'NETWORK_MISMATCH':
      return { outcome: 'NETWORK_MISMATCH' };
    case 'UNSUPPORTED_VAULT':
      return { outcome: 'UNSUPPORTED_VAULT' };
    case 'CORRUPT_VAULT':
      return { outcome: 'CORRUPT_VAULT' };
    case 'PROFILE_MISSING':
      return { outcome: 'PROFILE_MISSING', payload: result.safeCandidate };
    case 'SIGNING_KEY_MISMATCH':
      return { outcome: 'SIGNING_KEY_MISMATCH' };
    case 'ENCRYPTION_KEY_MISMATCH':
      return { outcome: 'ENCRYPTION_KEY_MISMATCH' };
    case 'VERIFY_TIMEOUT':
      return { outcome: 'VERIFY_TIMEOUT' };
    case 'NETWORK_UNAVAILABLE':
      return { outcome: 'NETWORK_UNAVAILABLE' };
    case 'INVALID_INPUT':
      return { outcome: 'INVALID_INPUT', payload: { reason: result.reason } };
    case 'UNKNOWN_FAILURE':
      return { outcome: 'UNKNOWN_FAILURE', payload: { supportCode: result.supportCode } };
  }
}

/** Resolve the deployment manifest for a protocol runtime configuration id. */
export function resolveManifestForRuntimeConfig(configId: unknown): { readonly ok: true; readonly manifest: DeploymentManifest } | { readonly ok: false } {
  if (configId === 'development-localhost') {
    const resolution = resolveManifest(ISOLATED_DEVNET_MANIFEST.configurationId);
    if (resolution.ok) {
      return { ok: true, manifest: resolution.manifest };
    }
  }
  // 'production-hushnetwork' and 'test-fixture' are not approved for this
  // isolated build; production fails closed until an approved manifest exists.
  return { ok: false };
}

/** Real same-origin BFF signed-transaction submission (sealed mapping). */
export function createWorkerBffTransactionSubmit(fetchImpl: typeof fetch = fetch): (signedTransaction: string) => Promise<{ readonly ok: true; readonly reply: { readonly status?: string; readonly validationCode?: string | null; readonly successfull?: boolean } } | { readonly ok: false; readonly failure: string }> {
  return async (signedTransaction) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), LOOKUP_TIMEOUT_MS);
    try {
      const response = await fetchImpl(BFF_BLOCKCHAIN_SUBMIT_PATH, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ signedTransaction }),
        cache: 'no-store',
        signal: controller.signal,
      });
      if (!response.ok) {
        return { ok: false, failure: 'unavailable' };
      }
      const body = (await response.json()) as { reply?: { status?: unknown; validationCode?: unknown; successfull?: unknown } } | null;
      const reply = body?.reply;
      if (reply === null || reply === undefined) {
        return { ok: false, failure: 'malformed' };
      }
      return {
        ok: true,
        reply: {
          status: typeof reply.status === 'string' ? reply.status : undefined,
          validationCode: typeof reply.validationCode === 'string' ? reply.validationCode : null,
          successfull: typeof reply.successfull === 'boolean' ? reply.successfull : undefined,
        },
      };
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        return { ok: false, failure: 'timeout' };
      }
      return { ok: false, failure: 'unavailable' };
    } finally {
      clearTimeout(timer);
    }
  };
}

/** Real same-origin BFF identity lookup (sealed mapping; no free-form text). */
export function createWorkerBffIdentityLookup(fetchImpl: typeof fetch = fetch): (signingAddress: string) => Promise<{ readonly kind: 'exact' | 'missing' | 'timeout' | 'unavailable'; readonly profileName?: string; readonly signingAddress?: string; readonly encryptionAddress?: string; readonly visibility?: 'private' | 'public' }> {
  return async (signingAddress) => {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), LOOKUP_TIMEOUT_MS);
    try {
      const response = await fetchImpl(BFF_IDENTITY_LOOKUP_PATH, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ publicSigningAddress: signingAddress }),
        cache: 'no-store',
        signal: controller.signal,
      });
      if (!response.ok) {
        return { kind: 'unavailable' };
      }
      const payload = (await response.json()) as {
        reply?: { successfull?: unknown; profileName?: unknown; publicSigningAddress?: unknown; publicEncryptAddress?: unknown; isPublic?: unknown } | null;
      };
      const reply = payload.reply;
      if (reply === null || reply === undefined) {
        return { kind: 'missing' };
      }
      const signing = reply.publicSigningAddress;
      const encryption = reply.publicEncryptAddress;
      if (typeof signing !== 'string' || typeof encryption !== 'string') {
        return { kind: 'missing' };
      }
      return {
        kind: 'exact',
        profileName: typeof reply.profileName === 'string' ? reply.profileName : undefined,
        signingAddress: signing,
        encryptionAddress: encryption,
        visibility: reply.isPublic === true ? 'public' : 'private',
      };
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        return { kind: 'timeout' };
      }
      return { kind: 'unavailable' };
    } finally {
      clearTimeout(timer);
    }
  };
}

/** Out-of-band secret transfer book (worker-held; never logged). */
export interface SecretTransfer {
  readonly operationId: string;
  readonly kind: 'devicePassword' | 'mnemonic' | 'filePassword' | 'fileBytes';
  readonly value: string | Uint8Array;
  consumed: boolean;
}

/** Production authority environment over the sealed engine. */
export function createProductionWorkerEnvironment(params: {
  readonly storage: VaultStorageSession;
  readonly suite: SuiteCryptoOperations & { readonly randomBytes: (length: number) => Uint8Array; readonly suiteId: string };
  readonly appIdentity: { readonly appVersion: string; readonly buildDigest: string };
  readonly runtimeConfigId: RuntimeConfigId;
  readonly deliver: AuthorityEnvironment['deliver'];
  readonly broadcast: AuthorityEnvironment['broadcast'];
  readonly onForceCleanup: () => void;
  readonly fetchImpl?: typeof fetch;
}): { readonly env: AuthorityEnvironment; readonly engine: SealedVaultEngine; readonly secrets: { store: (transfer: SecretTransfer) => void; take: (operationId: string, kind: SecretTransfer['kind']) => string | Uint8Array | null } } {
  const manifestResolution = resolveManifestForRuntimeConfig(params.runtimeConfigId);
  const secrets = new Map<string, SecretTransfer>();
  const store = (transfer: SecretTransfer): void => {
    secrets.set(transfer.operationId, transfer);
  };
  const take = (operationId: string, kind: SecretTransfer['kind']): string | Uint8Array | null => {
    const transfer = secrets.get(operationId);
    if (!transfer || transfer.kind !== kind || transfer.consumed) {
      return null;
    }
    transfer.consumed = true;
    secrets.delete(operationId);
    return transfer.value;
  };
  /** Bounded wait for a secret the UI submits after the operation started. */
  const waitForSecret = (operationId: string, kind: SecretTransfer['kind'], timeoutMs = 60_000): Promise<string | Uint8Array | null> =>
    new Promise((resolve) => {
      const deadline = Date.now() + timeoutMs;
      const poll = (): void => {
        const value = take(operationId, kind);
        if (value !== null) {
          resolve(value);
          return;
        }
        if (Date.now() >= deadline) {
          resolve(null);
          return;
        }
        setTimeout(poll, 50);
      };
      poll();
    });

  if (!manifestResolution.ok) {
    // Fail closed: no approved manifest → every operation returns a typed
    // invalid outcome; the authority never fabricates an environment.
    const failClosedOutcome = (): Promise<{ readonly outcome: string; readonly retryable: boolean; readonly allowedActions: readonly string[] }> =>
      Promise.resolve({ outcome: 'NETWORK_MISMATCH', retryable: false, allowedActions: [] });
    return {
      env: {
        nowMs: () => Date.now(),
        randomId: (prefix) => `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`,
        appIdentity: params.appIdentity,
        executeOperation: failClosedOutcome as unknown as AuthorityEnvironment['executeOperation'],
        deliver: params.deliver,
        broadcast: params.broadcast,
        cleanupBoundMs: 1000,
        onForceCleanup: params.onForceCleanup,
      },
      engine: null as unknown as SealedVaultEngine,
      secrets: { store, take },
    };
  }

  const manifest = manifestResolution.manifest;
  const engine = new SealedVaultEngine({
    storage: params.storage,
    suite: params.suite,
    manifest,
    nowMs: () => Date.now(),
    randomId: (prefix) => `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`,
    lookupIdentity: createWorkerBffIdentityLookup(params.fetchImpl),
    // The engine no longer broadcasts advisories; the authority owns epoch
    // invalidation and cross-tab broadcast with the REAL epoch.
    broadcast: (payload) => {
      void payload;
    },
    onForceCleanup: params.onForceCleanup,
  });

  const executeOperation: AuthorityEnvironment['executeOperation'] = async (request) => {
    const operation = request.operation;
    const payload = request.payload ?? {};
    try {
      emitDiagnosticBeacon({ kind: 'operation-start', operation });
      const result = await dispatchOperation(request, payload);
      emitDiagnosticBeacon({ kind: 'operation-done', operation, outcome: result.outcome });
      return result;
    } catch (error) {
      emitDiagnosticBeacon({ kind: 'operation-error', operation, outcome: `error: ${String(error)}` });
      return { outcome: 'UNKNOWN_FAILURE', retryable: false, allowedActions: [], supportCode: undefined };
    }
  };

  async function dispatchOperation(request: Parameters<AuthorityEnvironment['executeOperation']>[0], payload: Record<string, unknown>): Promise<Awaited<ReturnType<AuthorityEnvironment['executeOperation']>>> {
      const operation = request.operation;
      switch (operation) {
        case 'createCandidate': {
          const outcome = engine.createCandidate({ wordCount: 24 });
          return toAuthorityResult(outcomeFromSealed(outcome));
        }
        case 'revealCandidateWords': {
          const candidateRef = typeof payload.candidateRef === 'string' ? payload.candidateRef : '';
          if (candidateRef.length === 0) {
            return toAuthorityResult({ outcome: 'INVALID_INPUT', payload: { reason: 'missing-candidate-ref' } });
          }
          const outcome = engine.revealWords(candidateRef);
          return toAuthorityResult(outcomeFromSealed(outcome));
        }
        case 'concealCandidate': {
          const candidateRef = typeof payload.candidateRef === 'string' ? payload.candidateRef : '';
          const outcome = engine.concealCandidate(candidateRef);
          return toAuthorityResult(outcomeFromSealed(outcome));
        }
        case 'destroyCandidate': {
          const candidateRef = typeof payload.candidateRef === 'string' ? payload.candidateRef : '';
          const outcome = engine.destroyCandidate(candidateRef);
          return toAuthorityResult(outcomeFromSealed(outcome));
        }
        case 'deriveWordsCandidate': {
          const mnemonic = take(request.operationId, 'mnemonic');
          if (typeof mnemonic !== 'string') {
            return toAuthorityResult({ outcome: 'INVALID_INPUT', payload: { reason: 'missing-mnemonic' } });
          }
          const producerId = typeof payload.producerId === 'string' ? payload.producerId : 'P-01';
          const wordCount = payload.wordCount === 12 || payload.wordCount === 24 ? payload.wordCount : 24;
          const outcome = engine.deriveWordsCandidate({ mnemonic, producerId, wordCount });
          return toAuthorityResult(outcomeFromSealed(outcome));
        }
        case 'importFileCandidate': {
          const filePassword = take(request.operationId, 'filePassword');
          const fileBytesValue = take(request.operationId, 'fileBytes');
          if (typeof filePassword !== 'string' || typeof fileBytesValue !== 'string') {
            return toAuthorityResult({ outcome: 'INVALID_INPUT', payload: { reason: 'missing-file-material' } });
          }
          const fileBytes = decodeBase64Url(fileBytesValue);
          if (fileBytes === null) {
            return toAuthorityResult({ outcome: 'INVALID_INPUT', payload: { reason: 'file-encoding' } });
          }
          const outcome = await engine.importFileCandidate({ fileBytes, filePassword });
          return toAuthorityResult(outcomeFromSealed(outcome));
        }
        case 'provisionFromValidatedBundle': {
          const devicePassword = take(request.operationId, 'devicePassword');
          const candidateRef = typeof payload.candidateRef === 'string' ? payload.candidateRef : '';
          emitDiagnosticBeacon({ kind: 'provision-inputs', operation: request.operationId, outcome: `pw=${typeof devicePassword === 'string'} ref=${candidateRef.length > 0}` });
          if (typeof devicePassword !== 'string' || candidateRef.length === 0) {
            return toAuthorityResult({ outcome: 'INVALID_INPUT', payload: { reason: 'missing-provision-input' } });
          }
          const alias = typeof payload.alias === 'string' ? payload.alias : '';
          const visibility = payload.visibility === 'public' ? 'public' : payload.visibility === 'private' ? 'private' : null;
          if (alias.length === 0 || visibility === null) {
            return toAuthorityResult({ outcome: 'INVALID_INPUT', payload: { reason: 'profile-input' } });
          }
          const outcome = await engine.provision({
            candidateRef,
            devicePassword,
            alias,
            visibility,
            configurationId: manifest.configurationId,
            networkBinding: { canonicalNetworkId: manifest.canonicalNetworkId, networkMagic: manifest.networkMagic, configurationId: manifest.configurationId },
            producerId: 'P-01',
          });
          return toAuthorityResult(outcomeFromSealed(outcome));
        }
        case 'unlockPassword': {
          // The secret arrives AFTER the operation starts (the machine's
          // OPERATION.STARTED triggers the UI's SecretSubmissionSink); wait
          // for it under a bounded deadline.
          const devicePasswordValue = await waitForSecret(request.operationId, 'devicePassword');
          const devicePassword = typeof devicePasswordValue === 'string' ? devicePasswordValue : null;
          if (devicePassword === null) {
            return toAuthorityResult({ outcome: 'INVALID_INPUT', payload: { reason: 'missing-password' } });
          }
          emitDiagnosticBeacon({ kind: 'unlock-step', operation: 'before-engine-unlock' });
          const outcome = await engine.unlock({ devicePassword, configurationId: manifest.configurationId });
          emitDiagnosticBeacon({ kind: 'unlock-step', operation: 'after-engine-unlock', outcome: outcome.code });
          return toAuthorityResult(outcomeFromSealed(outcome));
        }
        case 'verifyOnlineIdentity': {
          const outcome = await engine.verifyOnline();
          return toAuthorityResult(outcomeFromSealed(outcome));
        }
        case 'changeDevicePassword': {
          const currentPassword = take(request.operationId, 'devicePassword');
          const newPassword = take(`${request.operationId}:new`, 'devicePassword');
          if (typeof currentPassword !== 'string' || typeof newPassword !== 'string') {
            return toAuthorityResult({ outcome: 'INVALID_INPUT', payload: { reason: 'missing-passwords' } });
          }
          const outcome = await engine.changeDevicePassword({ currentPassword, newPassword });
          return toAuthorityResult(outcomeFromSealed(outcome));
        }
        case 'lockAll': {
          const outcome = engine.lock();
          return toAuthorityResult(outcomeFromSealed(outcome));
        }
        case 'removeLocalUser': {
          emitDiagnosticBeacon({ kind: 'removal-step', operation: 'before-engine-removal' });
          const outcome = await engine.removeLocalUser();
          emitDiagnosticBeacon({ kind: 'removal-step', operation: 'after-engine-removal', outcome: outcome.code });
          return toAuthorityResult(outcomeFromSealed(outcome));
        }
        case 'retainTransactionDigest': {
          const digest = typeof payload.digest === 'string' ? payload.digest : '';
          if (digest.length === 0) {
            return toAuthorityResult({ outcome: 'INVALID_INPUT', payload: { reason: 'missing-digest' } });
          }
          const outcome = await engine.retainTransactionDigest(digest);
          return toAuthorityResult(outcomeFromSealed(outcome));
        }
        case 'submitIdentityTransaction': {
          const alias = typeof payload.alias === 'string' ? payload.alias : '';
          const visibility = payload.visibility === 'public' ? 'public' : payload.visibility === 'private' ? 'private' : null;
          if (alias.length === 0 || visibility === null) {
            return toAuthorityResult({ outcome: 'INVALID_INPUT', payload: { reason: 'profile-input' } });
          }
          const outcome = await engine.submitIdentityTransaction({
            alias,
            visibility,
            submit: createWorkerBffTransactionSubmit(params.fetchImpl),
          });
          return toAuthorityResult(outcomeFromSealed(outcome));
        }
        case 'promoteLifecycle': {
          const status = payload.status === 'Active' || payload.status === 'PendingRegistration' ? payload.status : null;
          if (status === null) {
            return toAuthorityResult({ outcome: 'INVALID_INPUT', payload: { reason: 'status-input' } });
          }
          const outcome = await engine.promoteLifecycle(status);
          return toAuthorityResult(outcomeFromSealed(outcome));
        }
        case 'inspectStartup': {
          const outcome = await engine.inspectStartup();
          return toAuthorityResult(outcomeFromSealed(outcome));
        }
        default:
          return { outcome: 'INVALID_INPUT', retryable: false, allowedActions: [], supportCode: undefined };
      }
  }

  /** Diagnostic beacon (BroadcastChannel; never affects operations). */
  function emitDiagnosticBeacon(status: { readonly kind: string; readonly operation?: string; readonly outcome?: string }): void {
    try {
      if (typeof BroadcastChannel !== 'undefined') {
        const channel = new BroadcastChannel('hushvoting-vault-advisory');
        channel.postMessage({ kind: 'vault-worker-op', event: status } as Record<string, unknown>);
        channel.close();
      }
    } catch {
      // diagnostic only
    }
  }

  return {
    env: {
      nowMs: () => Date.now(),
      randomId: (prefix) => `${prefix}-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`,
      appIdentity: params.appIdentity,
      executeOperation,
      deliver: params.deliver,
      broadcast: params.broadcast,
      cleanupBoundMs: 1000,
      onForceCleanup: params.onForceCleanup,
    },
    engine,
    secrets: { store, take },
  };
}

function toAuthorityResult(outcome: WorkerOperationOutcome): { readonly outcome: string; readonly retryable: boolean; readonly allowedActions: readonly string[]; readonly retryDeadlineMs?: number; readonly supportCode?: string; readonly payload?: unknown } {
  switch (outcome.outcome) {
    case 'OK':
      return { outcome: 'OK', retryable: false, allowedActions: [], supportCode: undefined, payload: outcome.payload };
    case 'WRONG_PASSWORD_OR_DAMAGED':
      return { outcome: 'WRONG_PASSWORD_OR_DAMAGED', retryable: true, allowedActions: ['retry'], supportCode: undefined };
    case 'THROTTLED':
      return { outcome: 'THROTTLED', retryable: false, allowedActions: ['retry'], retryDeadlineMs: outcome.retryDeadlineMs, supportCode: undefined };
    case 'NETWORK_MISMATCH':
      return { outcome: 'NETWORK_MISMATCH', retryable: false, allowedActions: [], supportCode: undefined };
    case 'UNSUPPORTED_VAULT':
      return { outcome: 'UNSUPPORTED_VAULT', retryable: false, allowedActions: ['removal'], supportCode: undefined };
    case 'CORRUPT_VAULT':
      return { outcome: 'CORRUPT_VAULT', retryable: false, allowedActions: ['removal'], supportCode: undefined };
    case 'PROFILE_MISSING':
      return { outcome: 'PROFILE_MISSING', retryable: false, allowedActions: ['createOrRestore'], supportCode: undefined, payload: outcome.payload };
    case 'SIGNING_KEY_MISMATCH':
    case 'ENCRYPTION_KEY_MISMATCH':
      return { outcome: outcome.outcome, retryable: false, allowedActions: ['lock', 'removal'], supportCode: undefined };
    case 'VERIFY_TIMEOUT':
    case 'NETWORK_UNAVAILABLE':
      return { outcome: outcome.outcome, retryable: true, allowedActions: ['retry'], supportCode: undefined };
    case 'INVALID_INPUT':
      return { outcome: 'INVALID_INPUT', retryable: false, allowedActions: [], supportCode: undefined, payload: outcome.payload };
    case 'UNKNOWN_FAILURE':
      return { outcome: 'UNKNOWN_FAILURE', retryable: true, allowedActions: ['retry'], supportCode: undefined, payload: outcome.payload };
  }
}

/** Public exports for the worker entry and tests. */
export const productionWorkerExports = { resolveManifestForRuntimeConfig, createWorkerBffIdentityLookup, createWorkerBffTransactionSubmit, BFF_IDENTITY_LOOKUP_PATH, BFF_BLOCKCHAIN_SUBMIT_PATH, LOOKUP_TIMEOUT_MS };

/** Decode a base64url string to bytes (strict; null on malformed input). */
function decodeBase64Url(value: string): Uint8Array | null {
  try {
    const normalized = value.replace(/-/g, '+').replace(/_/g, '/');
    const binary = atob(normalized);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch {
    return null;
  }
}
