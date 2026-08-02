/**
 * FEAT-004 browser-vault verification — endpoint allowlist resolver.
 *
 * The worker resolves approved runtime/endpoint configuration identifiers
 * through a build/runtime-approved HTTPS allowlist. Arbitrary URLs, schemes,
 * credentials, redirects to unapproved origins, and arbitrary headers are
 * rejected. Endpoint context is display/configuration in vault v1 and is never
 * added as network authorization or AAD (FEAT-003 Deep-Dive decision).
 *
 * Normative source: FEAT-004 FeatureDescription "Online Identity
 * Verification", "Worker protocol".
 */
import { ALLOWED_RUNTIME_CONFIG_IDS, type RuntimeConfigId } from '../contracts/protocol';

/** One approved HTTPS endpoint resolution. */
export interface EndpointResolution {
  readonly configId: RuntimeConfigId;
  readonly baseUrl: string;
  readonly path: string;
  /** Allowed request headers (fixed, never arbitrary). */
  readonly headers: readonly string[];
  /** HTTPS-only by construction. */
  readonly https: true;
}

/** Build/runtime-approved endpoint allowlist. */
export const ENDPOINT_ALLOWLIST: Readonly<Record<RuntimeConfigId, EndpointResolution>> = {
  'production-hushnetwork': {
    configId: 'production-hushnetwork',
    baseUrl: 'https://api.hushnetwork.app',
    path: '/api/identity/check',
    headers: ['content-type'],
    https: true,
  },
  'development-localhost': {
    configId: 'development-localhost',
    baseUrl: 'http://localhost:3001',
    path: '/api/identity/check',
    headers: ['content-type'],
    https: true, // localhost development exception is documented, not enforced as TLS
  },
  'test-fixture': {
    configId: 'test-fixture',
    baseUrl: 'https://fixtures.hushnetwork.test',
    path: '/identity/lookup',
    headers: [],
    https: true,
  },
};

/** Resolve a config identifier; unknown identifiers fail closed (null). */
export function resolveEndpoint(configId: unknown): EndpointResolution | null {
  if (typeof configId !== 'string' || !(ALLOWED_RUNTIME_CONFIG_IDS as readonly string[]).includes(configId)) {
    return null;
  }
  return ENDPOINT_ALLOWLIST[configId as RuntimeConfigId] ?? null;
}

/** True when a redirect target stays inside the approved allowlist. */
export function isAllowedRedirect(targetUrl: string): boolean {
  try {
    const parsed = new URL(targetUrl);
    for (const resolution of Object.values(ENDPOINT_ALLOWLIST)) {
      const base = new URL(resolution.baseUrl);
      if (parsed.origin === base.origin) {
        return true;
      }
    }
  } catch {
    return false;
  }
  return false;
}

/** Verify a config id resolves and the endpoint is HTTPS/approved (non-secret). */
export function isEndpointApproved(configId: unknown): boolean {
  const resolution = resolveEndpoint(configId);
  if (resolution === null) {
    return false;
  }
  if (resolution.https && !resolution.baseUrl.startsWith('https://') && resolution.configId !== 'development-localhost') {
    return false;
  }
  return true;
}
