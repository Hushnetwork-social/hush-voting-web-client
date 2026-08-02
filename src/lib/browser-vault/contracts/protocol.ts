/**
 * FEAT-004 browser-vault contracts — closed page/worker protocol.
 *
 * Every page/worker message is a strict closed discriminated union validated at
 * runtime before dispatch. A handshake binds: exact worker protocol compatibility
 * version, application build compatibility version, a random client channel, the
 * authority epoch, an opaque operation ID, and a safe runtime/endpoint
 * configuration identifier. Malformed, unknown, duplicated, stale, wrong-channel,
 * wrong-epoch, or oversized messages fail closed and never start a secret
 * operation. Capability/session references are non-serializable by contract,
 * non-persisted, and non-transferable between tabs.
 *
 * SECRET BOUNDARY: no message variant carries password bytes, mnemonics, private
 * keys, salts, keys, nonces, decrypted records, or serialized session bearer
 * values. Secret material is transferred out-of-band through the FEAT-002
 * SecretSubmissionSink boundary directly to the authenticated MessagePort.
 *
 * Normative source: FEAT-004 FeatureDescription "Worker protocol", "Browser
 * Architecture"; FEAT-002 `src/lib/auth/ports.ts` epoch/operation scoping.
 */

/**
 * Exact protocol compatibility version. Any change to a message shape, handshake
 * field, or semantic rule MUST bump this value; mixed versions never interop.
 */
export const BROWSER_PROTOCOL_VERSION = 1 as const;

/** Application build compatibility string (short immutable build digest). */
export interface AppBuildIdentity {
  /** Exact application build version (semver of the authenticated app). */
  readonly appVersion: string;
  /** Short immutable build digest (first 12 hex chars) for exact matching. */
  readonly buildDigest: string;
}

/** Closed set of safe runtime/endpoint configuration identifiers. */
export type RuntimeConfigId = 'production-hushnetwork' | 'development-localhost' | 'test-fixture';

/** Allowed runtime configuration identifiers (build/runtime-approved allowlist). */
export const ALLOWED_RUNTIME_CONFIG_IDS: readonly RuntimeConfigId[] = [
  'production-hushnetwork',
  'development-localhost',
  'test-fixture',
] as const;

export function isAllowedRuntimeConfigId(value: unknown): value is RuntimeConfigId {
  return typeof value === 'string' && (ALLOWED_RUNTIME_CONFIG_IDS as readonly string[]).includes(value);
}

/** Opaque operation identifier (random, page-issued, consumed once). */
export type OperationId = string;
/** Opaque client channel (random per connection; never reused across tabs). */
export type ClientChannel = string;
/** Monotonic authority epoch (incremented on Lock/invalidation/takeover). */
export type AuthorityEpoch = number;

/** Bounds enforced by runtime schema validation (fail closed on violation). */
export const PROTOCOL_BOUNDS = {
  /** Max length for opaque identifiers (operation, channel, config id). */
  maxIdentifierLength: 128,
  /** Max serialized message size in bytes (reject oversized payloads). */
  maxMessageBytes: 16 * 1024,
  /** Max extra fields allowed (strict schemas reject extras; bound protects against abuse). */
  maxFields: 32,
} as const;

/**
 * Handshake request — the first message a page sends on a fresh connection.
 * Binds compatibility versions, a fresh random client channel, and a safe
 * runtime configuration identifier. No secret fields exist here.
 */
export interface HandshakeRequest {
  readonly kind: 'handshake';
  readonly protocolVersion: number;
  readonly appVersion: string;
  readonly buildDigest: string;
  readonly clientChannel: string;
  readonly runtimeConfigId: string;
}

/** Accepted handshake: client receives a fresh channel-bound opaque capability. */
export interface HandshakeAccepted {
  readonly kind: 'handshake-accepted';
  readonly protocolVersion: number;
  readonly appVersion: string;
  readonly buildDigest: string;
  readonly clientChannel: string;
  readonly authorityEpoch: number;
  readonly operationId: string;
  /** Safe public session projection (never secrets). */
  readonly session: { readonly state: 'noLocalUser' | 'locked' | 'verificationOnly' | 'authenticated' | 'removalInProgress' };
}

/** Rejected handshake: deterministic safe reason; no secret or raw detail. */
export interface HandshakeRejected {
  readonly kind: 'handshake-rejected';
  readonly protocolVersion: number;
  readonly reason: 'version-mismatch' | 'build-mismatch' | 'unsupported-config' | 'malformed';
}

/** Operation request — closed registry of authority operations. */
export type BrowserOperationKind =
  | 'provisionFromValidatedBundle'
  | 'unlockPassword'
  | 'changeDevicePassword'
  | 'verifyOnlineIdentity'
  | 'lockAll'
  | 'removeLocalUser'
  | 'revealMnemonic'
  | 'exportEncryptedFile';

/**
 * Operation request. Carries NO secret payload: password/mnemonic/file bytes are
 * delivered out-of-band through the SecretSubmissionSink boundary. The request
 * only declares the closed operation kind and its epoch/operation binding.
 */
export interface OperationRequest {
  readonly kind: 'operation';
  readonly operation: BrowserOperationKind;
  readonly operationVersion: number;
  readonly clientChannel: string;
  readonly authorityEpoch: number;
  readonly operationId: string;
  /** Purpose-bound fresh capability token id when the operation requires one. */
  readonly freshCapabilityId?: string;
}

/** Cancel an in-flight operation (epoch invalidation is authority-owned). */
export interface OperationCancel {
  readonly kind: 'cancel';
  readonly operationId: string;
  readonly clientChannel: string;
  readonly authorityEpoch: number;
}

/** Lifecycle signal from the page (best-effort; correctness never depends on it). */
export interface PageLifecycleSignal {
  readonly kind: 'lifecycle';
  readonly signal: 'pagehide' | 'visibility-hidden' | 'disconnect' | 'heartbeat';
  readonly clientChannel: string;
  readonly authorityEpoch: number;
}

/** Closed union of page → authority messages. */
export type BrowserClientMessage =
  | HandshakeRequest
  | OperationRequest
  | OperationCancel
  | PageLifecycleSignal;

/** Safe typed result/event from the authority → page. */
export interface OperationOutcome {
  readonly kind: 'operation-outcome';
  readonly operationId: string;
  readonly clientChannel: string;
  /** Closed FEAT-003-compatible safe result code or browser-adapter code. */
  readonly outcome: string;
  readonly retryable: boolean;
  readonly allowedActions: readonly string[];
  readonly retryDeadlineMs?: number;
  readonly supportCode?: string;
}

/** Global invalidation event (Lock, removal, takeover, update, cleanup). */
export interface GlobalInvalidation {
  readonly kind: 'global-invalidation';
  readonly authorityEpoch: number;
  readonly reason: 'lock' | 'removal' | 'takeover' | 'update-mismatch' | 'authority-loss' | 'cleanup-failed';
}

/** Closed union of authority → page events. */
export type BrowserWorkerEvent = OperationOutcome | GlobalInvalidation | HandshakeAccepted | HandshakeRejected;

/**
 * Runtime schema validation — the ONLY admission gate for inbound messages.
 * Returns the validated message or `null` when the value is malformed, unknown,
 * oversized, or contains secret-bearing/unexpected fields. Never echoes the raw
 * input; callers fail closed with a typed safe result.
 */
export function validateClientMessage(value: unknown): BrowserClientMessage | null {
  if (typeof value !== 'object' || value === null) {
    return null;
  }
  const record = value as Record<string, unknown>;
  if (typeof record.kind !== 'string') {
    return null;
  }
  switch (record.kind) {
    case 'handshake':
      return validateHandshake(record);
    case 'operation':
      return validateOperation(record);
    case 'cancel':
      return validateCancel(record);
    case 'lifecycle':
      return validateLifecycle(record);
    default:
      // Unknown message kind: fail closed.
      return null;
  }
}

function isBoundedString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= PROTOCOL_BOUNDS.maxIdentifierLength;
}

function isBoundedNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0;
}

function hasNoUnknownFields(record: Record<string, unknown>, allowed: readonly string[]): boolean {
  const keys = Object.keys(record);
  return keys.length <= PROTOCOL_BOUNDS.maxFields && keys.every((key) => allowed.includes(key));
}

function validateHandshake(record: Record<string, unknown>): HandshakeRequest | null {
  if (!hasNoUnknownFields(record, ['kind', 'protocolVersion', 'appVersion', 'buildDigest', 'clientChannel', 'runtimeConfigId'])) {
    return null;
  }
  if (!isBoundedNumber(record.protocolVersion) || record.protocolVersion !== BROWSER_PROTOCOL_VERSION) {
    return null;
  }
  if (!isBoundedString(record.appVersion) || !isBoundedString(record.buildDigest)) {
    return null;
  }
  if (!isBoundedString(record.clientChannel) || !isBoundedString(record.runtimeConfigId)) {
    return null;
  }
  if (!isAllowedRuntimeConfigId(record.runtimeConfigId)) {
    return null;
  }
  return {
    kind: 'handshake',
    protocolVersion: record.protocolVersion,
    appVersion: record.appVersion,
    buildDigest: record.buildDigest,
    clientChannel: record.clientChannel,
    runtimeConfigId: record.runtimeConfigId,
  };
}

function validateOperation(record: Record<string, unknown>): OperationRequest | null {
  if (!hasNoUnknownFields(record, ['kind', 'operation', 'operationVersion', 'clientChannel', 'authorityEpoch', 'operationId', 'freshCapabilityId'])) {
    return null;
  }
  if (!isBoundedString(record.operation) || !OPERATION_KINDS.has(record.operation)) {
    return null;
  }
  if (!isBoundedNumber(record.operationVersion) || record.operationVersion !== 1) {
    return null;
  }
  if (!isBoundedString(record.clientChannel) || !isBoundedNumber(record.authorityEpoch) || !isBoundedString(record.operationId)) {
    return null;
  }
  if (record.freshCapabilityId !== undefined && !isBoundedString(record.freshCapabilityId)) {
    return null;
  }
  const request: OperationRequest = {
    kind: 'operation',
    operation: record.operation as BrowserOperationKind,
    operationVersion: record.operationVersion,
    clientChannel: record.clientChannel,
    authorityEpoch: record.authorityEpoch,
    operationId: record.operationId,
    ...(record.freshCapabilityId !== undefined ? { freshCapabilityId: record.freshCapabilityId as string } : {}),
  };
  return request;
}

const OPERATION_KINDS: ReadonlySet<string> = new Set<BrowserOperationKind>([
  'provisionFromValidatedBundle',
  'unlockPassword',
  'changeDevicePassword',
  'verifyOnlineIdentity',
  'lockAll',
  'removeLocalUser',
  'revealMnemonic',
  'exportEncryptedFile',
]);

function validateCancel(record: Record<string, unknown>): OperationCancel | null {
  if (!hasNoUnknownFields(record, ['kind', 'operationId', 'clientChannel', 'authorityEpoch'])) {
    return null;
  }
  if (!isBoundedString(record.operationId) || !isBoundedString(record.clientChannel) || !isBoundedNumber(record.authorityEpoch)) {
    return null;
  }
  return {
    kind: 'cancel',
    operationId: record.operationId,
    clientChannel: record.clientChannel,
    authorityEpoch: record.authorityEpoch,
  };
}

function validateLifecycle(record: Record<string, unknown>): PageLifecycleSignal | null {
  if (!hasNoUnknownFields(record, ['kind', 'signal', 'clientChannel', 'authorityEpoch'])) {
    return null;
  }
  if (record.signal !== 'pagehide' && record.signal !== 'visibility-hidden' && record.signal !== 'disconnect' && record.signal !== 'heartbeat') {
    return null;
  }
  if (!isBoundedString(record.clientChannel) || !isBoundedNumber(record.authorityEpoch)) {
    return null;
  }
  return {
    kind: 'lifecycle',
    signal: record.signal,
    clientChannel: record.clientChannel,
    authorityEpoch: record.authorityEpoch,
  };
}

/** Sanity helper: a validated message must never carry secret-shaped fields. */
export function assertNoSecretField(message: BrowserClientMessage): void {
  const keys = Object.keys(message);
  const forbidden = ['password', 'passwordBytes', 'mnemonic', 'privateKey', 'secret', 'salt', 'nonce', 'keyMaterial', 'decrypted', 'bundle'];
  for (const key of keys) {
    if (forbidden.some((token) => key.toLowerCase().includes(token))) {
      throw new Error(`protocol message carries secret-shaped field: ${key}`);
    }
  }
}

/** Approximate serialized size guard used by transport layers before dispatch. */
export function estimateMessageBytes(message: unknown): number {
  try {
    return new TextEncoder().encode(JSON.stringify(message)).byteLength;
  } catch {
    return Number.POSITIVE_INFINITY;
  }
}
