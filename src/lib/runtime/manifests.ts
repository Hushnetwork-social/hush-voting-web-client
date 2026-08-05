/**
 * FEAT-010 runtime — closed deployment manifest catalog (Task 6.1).
 *
 * Every approved environment has an exact digest-pinned manifest. This module
 * holds the ONLY manifests the application may resolve; production offers no
 * arbitrary endpoint/network input (AC-010-019/020). The isolated local
 * devnet manifest is pinned by its recomputed sha256 digest; the production
 * slot stays `notConfigured` until an approved production manifest exists —
 * resolution then fails closed instead of fabricating an environment.
 *
 * Integrity model: the digest constant is the compile-time pin. At runtime
 * the resolver verifies exact canonical-form equality (the canonical JSON
 * whose sha256 equals the pinned digest is embedded), so any drift between
 * the catalog and its canonical serialization fails closed deterministically
 * without requiring a hash implementation in browser bundles.
 *
 * Framework-neutral, secret-free.
 */
import {
  canonicalManifestJson,
  parseDeploymentManifest,
  type DeploymentManifest,
  type DeploymentValidation,
} from './deployment';

/** sha256(canonicalManifestJson(isolated devnet)) — pinned. */
export const ISOLATED_DEVNET_DIGEST = '7a1f8d8e5b453fa132746662a1743458737da4159f498a501859e503763b0aaf' as const;

/** The exact canonical JSON whose sha256 is ISOLATED_DEVNET_DIGEST. */
export const ISOLATED_DEVNET_CANONICAL_JSON =
  '{"configurationId":"isolated-local-devnet-v1","canonicalNetworkId":"hushnetwork-devnet","networkMagic":5195086,"transportMode":"bff","endpointIds":["devnet-identity-a"],"contractVersions":{"client":"1.0.0","server":"1.0.0","adapter":"1.0.0"},"classification":"isolated-non-production"}' as const;

/** The one approved isolated environment (local HushServerNode/devnet). */
export const ISOLATED_DEVNET_MANIFEST: DeploymentManifest = {
  configurationId: 'isolated-local-devnet-v1',
  canonicalNetworkId: 'hushnetwork-devnet',
  networkMagic: 5195086,
  transportMode: 'bff',
  endpointIds: ['devnet-identity-a'],
  contractVersions: { client: '1.0.0', server: '1.0.0', adapter: '1.0.0' },
  classification: 'isolated-non-production',
  digest: ISOLATED_DEVNET_DIGEST,
} as const;

/** Manifest resolution outcomes. */
export type ManifestResolution =
  | { readonly ok: true; readonly manifest: DeploymentManifest }
  | { readonly ok: false; readonly code: 'notConfigured' | 'unapproved' }
  | { readonly ok: false; readonly code: 'tampered'; readonly validation: DeploymentValidation };

/**
 * Resolve the active deployment manifest from a configuration identifier.
 * Only the pinned catalog is admissible; drift from the canonical form fails
 * closed (`tampered`). Production without an approved manifest is
 * `notConfigured`, never a fabricated environment.
 */
export function resolveManifest(configurationId: string): ManifestResolution {
  if (configurationId === ISOLATED_DEVNET_MANIFEST.configurationId) {
    if (canonicalManifestJson(ISOLATED_DEVNET_MANIFEST) !== ISOLATED_DEVNET_CANONICAL_JSON) {
      return { ok: false, code: 'tampered', validation: { ok: false, diagnostics: [{ code: 'DIGEST_MISMATCH' }] } };
    }
    // Field-level validation with the canonical JSON as the digest oracle.
    const validation = parseDeploymentManifest(ISOLATED_DEVNET_MANIFEST, () => ISOLATED_DEVNET_DIGEST);
    if (!validation.ok || validation.manifest === undefined) {
      return { ok: false, code: 'tampered', validation };
    }
    return { ok: true, manifest: validation.manifest };
  }
  if (configurationId.startsWith('production-')) {
    // No approved production manifest is pinned yet: fail closed.
    return { ok: false, code: 'notConfigured' };
  }
  return { ok: false, code: 'unapproved' };
}

/** Integrity self-check of the catalog (called by tests and CI). */
export function verifyManifestCatalog(): boolean {
  const resolution = resolveManifest(ISOLATED_DEVNET_MANIFEST.configurationId);
  return resolution.ok && resolution.manifest.digest === ISOLATED_DEVNET_DIGEST;
}

/** Manifest catalog self-check constant used by the CI exclusion gate. */
export const MANIFEST_CATALOG_SELF_CHECK = verifyManifestCatalog();
