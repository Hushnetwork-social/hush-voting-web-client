/**
 * FEAT-004 browser-vault contracts — non-secret capability preflight.
 *
 * Preflight runs BEFORE the application displays or accepts a password, mnemonic,
 * credential file, or generated credential material. It verifies secure-context
 * status, native IndexedDB open/transaction/write/read/delete behavior using
 * non-secret bounded data, WebCrypto HKDF-SHA-256/AES-GCM availability, CSPRNG
 * availability, module-worker support, SharedWorker (or an approved exclusive
 * fallback path), storage persistence and estimate APIs when available, and
 * required text/structured-clone/transfer behavior.
 *
 * Unsupported capability and temporary storage denial are DISTINCT outcomes.
 * Temporary failures offer bounded Retry; unsupported environments explain the
 * certified Chrome/Edge and native-app alternatives. The application never
 * collects a secret it has already established cannot be processed safely.
 *
 * Browser primitives are injected (FEAT-002 CoordinationEnvironment pattern) so
 * preflight logic is deterministic and unit-testable without real globals.
 *
 * Normative source: FEAT-004 FeatureDescription "Capability Preflight",
 * "Supported Browser and Deployment Baseline".
 */

/** Closed set of capability checks performed by preflight. */
export type CapabilityCheck =
  | 'secureContext'
  | 'indexedDb'
  | 'webCryptoHkdf'
  | 'webCryptoAesGcm'
  | 'cryptoRandom'
  | 'moduleWorker'
  | 'sharedWorker'
  | 'webLock'
  | 'storageEstimate'
  | 'storagePersisted';

export const ALL_CAPABILITY_CHECKS: readonly CapabilityCheck[] = [
  'secureContext',
  'indexedDb',
  'webCryptoHkdf',
  'webCryptoAesGcm',
  'cryptoRandom',
  'moduleWorker',
  'sharedWorker',
  'webLock',
  'storageEstimate',
  'storagePersisted',
] as const;

/**
 * Result of one capability check. `unavailable` is a hard unsupported condition;
 * `temporary` is a transient denial (e.g., storage busy) that allows bounded
 * Retry. `unknown` means the capability cannot be probed deterministically.
 */
export type CapabilityStatus = 'available' | 'unavailable' | 'temporary' | 'unknown';

export interface CapabilityReport {
  readonly check: CapabilityCheck;
  readonly status: CapabilityStatus;
  /** Short deterministic code for safe diagnostics; never a raw platform message. */
  readonly detail: string;
}

/** Preflight verdict over all checks. */
export interface PreflightReport {
  readonly ok: boolean;
  /** True when at least one check is `temporary` (bounded Retry is offered). */
  readonly retryable: boolean;
  readonly secureOrigin: boolean;
  readonly checks: readonly CapabilityReport[];
}

/** Deterministic preflight result codes for safe typed diagnostics. */
export type PreflightCode =
  | 'PREFLIGHT_OK'
  | 'INSECURE_ORIGIN'
  | 'STORAGE_UNAVAILABLE'
  | 'CRYPTO_UNAVAILABLE'
  | 'RANDOM_UNAVAILABLE'
  | 'WORKER_UNAVAILABLE'
  | 'COORDINATION_UNAVAILABLE'
  | 'TEMPORARY_STORAGE_DENIED'
  | 'PREFLIGHT_UNKNOWN';

/** Mandatory checks that must be `available` for any secret workflow. */
export const MANDATORY_CAPABILITY_CHECKS: readonly CapabilityCheck[] = [
  'secureContext',
  'indexedDb',
  'webCryptoHkdf',
  'webCryptoAesGcm',
  'cryptoRandom',
  'moduleWorker',
];

/**
 * Browser primitives injected into preflight. Every probe uses non-secret
 * bounded data only and never collects or retains credential material.
 */
export interface BrowserPreflightEnvironment {
  readonly isSecureContext: boolean;
  readonly indexedDBAvailable: () => boolean;
  /** Bounded non-secret probe: open, write, read, delete a temp record. */
  readonly probeIndexedDb: () => Promise<'ok' | 'temporary' | 'unavailable'>;
  readonly webCryptoAvailable: () => boolean;
  readonly hkdfAvailable: () => Promise<boolean>;
  readonly aesGcmAvailable: () => Promise<boolean>;
  readonly cryptoRandomAvailable: () => boolean;
  readonly moduleWorkerAvailable: () => boolean;
  readonly sharedWorkerAvailable: () => boolean;
  readonly webLockAvailable: () => boolean;
  readonly storageEstimateAvailable: () => boolean;
  readonly storagePersistedAvailable: () => boolean;
}

/**
 * Run the complete non-secret preflight. Returns a typed report; the caller maps
 * to the closed FEAT-003 result vocabulary (`StorageUnavailable`, typed failures)
 * and never surfaces raw DOM/platform exceptions.
 */
export async function runCapabilityPreflight(env: BrowserPreflightEnvironment): Promise<PreflightReport> {
  const checks: CapabilityReport[] = [];
  let retryable = false;
  let ok = true;

  const record = (check: CapabilityCheck, status: CapabilityStatus, detail: string): void => {
    checks.push({ check, status, detail });
    if (status === 'unavailable') {
      ok = false;
    }
    if (status === 'temporary') {
      retryable = true;
    }
    if (status === 'unknown') {
      ok = false; // unknown capability cannot prove safety; fail closed
    }
  };

  record('secureContext', env.isSecureContext ? 'available' : 'unavailable', env.isSecureContext ? 'SECURE_CONTEXT_OK' : 'INSECURE_ORIGIN');

  if (env.indexedDBAvailable()) {
    const probe = await env.probeIndexedDb();
    const status: CapabilityStatus = probe === 'ok' ? 'available' : probe === 'temporary' ? 'temporary' : 'unavailable';
    const detail = probe === 'ok' ? 'IDB_PROBE_OK' : probe === 'temporary' ? 'IDB_TEMPORARY_DENIED' : 'IDB_UNAVAILABLE';
    record('indexedDb', status, detail);
  } else {
    record('indexedDb', 'unavailable', 'IDB_MISSING');
  }

  if (env.webCryptoAvailable()) {
    const hkdf = await env.hkdfAvailable();
    const aes = await env.aesGcmAvailable();
    record('webCryptoHkdf', hkdf ? 'available' : 'unavailable', hkdf ? 'HKDF_OK' : 'HKDF_UNAVAILABLE');
    record('webCryptoAesGcm', aes ? 'available' : 'unavailable', aes ? 'AESGCM_OK' : 'AESGCM_UNAVAILABLE');
  } else {
    record('webCryptoHkdf', 'unavailable', 'WEBCRYPTO_MISSING');
    record('webCryptoAesGcm', 'unavailable', 'WEBCRYPTO_MISSING');
  }

  record('cryptoRandom', env.cryptoRandomAvailable() ? 'available' : 'unavailable', env.cryptoRandomAvailable() ? 'CSPRNG_OK' : 'CSPRNG_UNAVAILABLE');
  record('moduleWorker', env.moduleWorkerAvailable() ? 'available' : 'unavailable', env.moduleWorkerAvailable() ? 'WORKER_MODULE_OK' : 'WORKER_MODULE_UNAVAILABLE');
  record('sharedWorker', env.sharedWorkerAvailable() ? 'available' : 'unavailable', env.sharedWorkerAvailable() ? 'SHARED_WORKER_OK' : 'SHARED_WORKER_UNAVAILABLE');
  record('webLock', env.webLockAvailable() ? 'available' : 'unavailable', env.webLockAvailable() ? 'WEB_LOCK_OK' : 'WEB_LOCK_UNAVAILABLE');
  record('storageEstimate', env.storageEstimateAvailable() ? 'available' : 'unknown', env.storageEstimateAvailable() ? 'ESTIMATE_OK' : 'ESTIMATE_MISSING');
  record('storagePersisted', env.storagePersistedAvailable() ? 'available' : 'unknown', env.storagePersistedAvailable() ? 'PERSISTED_OK' : 'PERSISTED_MISSING');

  return {
    ok,
    retryable,
    secureOrigin: env.isSecureContext,
    checks,
  };
}

/** Derive the deterministic preflight code from a report (safe diagnostics only). */
export function preflightCode(report: PreflightReport): PreflightCode {
  if (!report.secureOrigin) {
    return 'INSECURE_ORIGIN';
  }
  const byCheck = new Map(report.checks.map((c) => [c.check, c.status]));
  // Temporary storage denial is distinct from unavailable storage and allows bounded Retry.
  if (byCheck.get('indexedDb') === 'temporary') {
    return 'TEMPORARY_STORAGE_DENIED';
  }
  if (report.ok) {
    return 'PREFLIGHT_OK';
  }
  if (byCheck.get('indexedDb') === 'unavailable') {
    return 'STORAGE_UNAVAILABLE';
  }
  if (byCheck.get('webCryptoHkdf') === 'unavailable' || byCheck.get('webCryptoAesGcm') === 'unavailable') {
    return 'CRYPTO_UNAVAILABLE';
  }
  if (byCheck.get('cryptoRandom') === 'unavailable') {
    return 'RANDOM_UNAVAILABLE';
  }
  if (byCheck.get('moduleWorker') === 'unavailable') {
    return 'WORKER_UNAVAILABLE';
  }
  if (byCheck.get('sharedWorker') === 'unavailable' && byCheck.get('webLock') === 'unavailable') {
    return 'COORDINATION_UNAVAILABLE';
  }
  return 'PREFLIGHT_UNKNOWN';
}
