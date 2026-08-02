/**
 * FEAT-004 browser-vault verification — worker-owned exact online verification.
 *
 * After local unlock the authority remains `VerificationOnly`. The worker
 * owns online verification: it resolves only an approved endpoint identifier,
 * performs a PUBLIC-only lookup, independently validates profile existence and
 * exact signing/encryption key binding, and promotes to `Authenticated` only
 * on an epoch/operation-current exact match. The page can never promote
 * authentication with a Boolean or a cached preview.
 *
 * A 10-second timeout and connectivity errors remain typed and retryable.
 * Endpoint changes require renewed exact verification. Correct local unlock
 * may remain inside the authority under session policy while online
 * verification is retried; the authenticated shell never opens offline.
 *
 * Normative source: FEAT-004 FeatureDescription "Online Identity
 * Verification"; FEAT-002 `src/lib/auth/results.ts` verification codes.
 */
import { isEndpointApproved, resolveEndpoint } from './resolver';

/** Public-only identity lookup result (never secrets). */
export interface PublicProfile {
  readonly signingAddress: string;
  readonly encryptionAddress: string;
}

/** Worker-compatible transport (injected; public lookup only). */
export interface VerificationTransport {
  readonly lookup: (params: { readonly baseUrl: string; readonly path: string; readonly signingAddress: string }) => Promise<
    | { readonly kind: 'profile'; readonly profile: PublicProfile }
    | { readonly kind: 'missing' }
    | { readonly kind: 'network-error' }
    | { readonly kind: 'timeout' }
    | { readonly kind: 'redirect-denied' }
    | { readonly kind: 'bad-request' }
  >;
}

/** Closed verification outcome in the FEAT-002 vocabulary. */
export type VerificationOutcome =
  | { readonly code: 'VERIFY_SUCCESS' }
  | { readonly code: 'VERIFY_PROFILE_MISSING'; readonly safeCandidate: { readonly alias: string; readonly abbreviatedSigningAddress: string } }
  | { readonly code: 'VERIFY_SIGNING_KEY_MISMATCH' }
  | { readonly code: 'VERIFY_ENCRYPTION_KEY_MISMATCH' }
  | { readonly code: 'VERIFY_TIMEOUT' }
  | { readonly code: 'VERIFY_NETWORK_UNAVAILABLE' }
  | { readonly code: 'UNKNOWN_FAILURE'; readonly supportCode: string };

export interface VerificationParams {
  readonly configId: unknown;
  readonly localSigningAddress: string;
  readonly localEncryptionAddress: string;
  readonly safeCandidate: { readonly alias: string; readonly abbreviatedSigningAddress: string };
  readonly transport: VerificationTransport;
  readonly timeoutMs?: number;
}

/**
 * Verify exact online identity binding. Returns `VERIFY_SUCCESS` only when the
 * remote profile exists and BOTH public keys match exactly. No page-supplied
 * Boolean can promote authentication.
 */
export async function verifyExactBinding(params: VerificationParams): Promise<VerificationOutcome> {
  if (!isEndpointApproved(params.configId)) {
    return { code: 'UNKNOWN_FAILURE', supportCode: randomSupportCode() }; // arbitrary endpoint rejected
  }
  const endpoint = resolveEndpoint(params.configId)!;
  const timeoutMs = params.timeoutMs ?? 10_000;
  const lookup = withTimeout(params.transport.lookup, timeoutMs);
  const result = await lookup({
    baseUrl: endpoint.baseUrl,
    path: endpoint.path,
    signingAddress: params.localSigningAddress,
  });
  switch (result.kind) {
    case 'timeout':
      return { code: 'VERIFY_TIMEOUT' };
    case 'network-error':
      return { code: 'VERIFY_NETWORK_UNAVAILABLE' };
    case 'redirect-denied':
    case 'bad-request':
      return { code: 'VERIFY_NETWORK_UNAVAILABLE' };
    case 'missing':
      return { code: 'VERIFY_PROFILE_MISSING', safeCandidate: params.safeCandidate };
    case 'profile': {
      const { profile } = result;
      if (profile.signingAddress !== params.localSigningAddress) {
        return { code: 'VERIFY_SIGNING_KEY_MISMATCH' };
      }
      if (profile.encryptionAddress !== params.localEncryptionAddress) {
        return { code: 'VERIFY_ENCRYPTION_KEY_MISMATCH' };
      }
      return { code: 'VERIFY_SUCCESS' };
    }
  }
}

function withTimeout<T extends (params: never) => Promise<unknown>>(fn: T, timeoutMs: number): T {
  return (async (params: never) => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<{ readonly kind: 'timeout' }>((resolve) => {
      timer = setTimeout(() => resolve({ kind: 'timeout' }), timeoutMs);
    });
    try {
      const outcome = (await Promise.race([fn(params), timeout])) as Awaited<ReturnType<T>>;
      return outcome;
    } finally {
      if (timer !== undefined) {
        clearTimeout(timer);
      }
    }
  }) as T;
}

/** Random bounded per-occurrence support code (safe diagnostics only). */
export function randomSupportCode(): string {
  return `vc-${Math.random().toString(36).slice(2, 8)}${Math.random().toString(36).slice(2, 6)}`;
}
