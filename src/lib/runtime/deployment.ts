/**
 * FEAT-010 runtime contracts — closed deployment/network manifest.
 *
 * Every approved HushVoting environment is described by one exact
 * versioned/digest-pinned manifest:
 * - configuration ID (stable identifier for the environment);
 * - canonical network identifier + magic (network truth — never inferred from
 *   hostnames, profiles, server replies, or user input);
 * - approved transport mode and allowlisted endpoint IDs;
 * - compatible client/server/adapter contract versions;
 * - production or isolated-non-production classification.
 *
 * Rules enforced here (normative: FeatureDescription "Deployment and Network
 * Binding", AC-010-019…022):
 * - user-controlled strings never establish network/target truth;
 * - endpoint rotation is allowed only between manifest entries bound to the
 *   SAME canonical network;
 * - production offers no arbitrary endpoint/network input;
 * - unknown/malformed/mismatched manifests fail closed with typed diagnostics.
 *
 * Framework-neutral: no Next.js, fetch, or storage dependency.
 */

/** Deployment classification: production vs explicitly isolated local/devnet. */
export type DeploymentClass = 'production' | 'isolated-non-production';

/** Approved transport modes. Native targets never use the BFF mode. */
export type DeploymentTransportMode = 'bff' | 'native';

/** Exact compatible contract versions (semver strings, pinned). */
export interface ContractVersionPin {
  /** Client (web/native application) contract version. */
  readonly client: string;
  /** HushServerNode contract version. */
  readonly server: string;
  /** Platform vault adapter contract version. */
  readonly adapter: string;
}

/** One digest-pinned approved environment manifest. */
export interface DeploymentManifest {
  /** Stable environment identifier (bounded, e.g. `isolated-local-devnet-v1`). */
  readonly configurationId: string;
  /** Canonical HushNetwork identifier (never user-supplied). */
  readonly canonicalNetworkId: string;
  /** Network magic number (must equal the HushServerNode devnet/mainnet magic). */
  readonly networkMagic: number;
  /** Approved transport mode for this environment. */
  readonly transportMode: DeploymentTransportMode;
  /** Allowlisted endpoint IDs (resolved server-side / natively, never by page code). */
  readonly endpointIds: readonly string[];
  readonly contractVersions: ContractVersionPin;
  readonly classification: DeploymentClass;
  /** sha256 digest of the canonical manifest serialization (pin). */
  readonly digest: string;
}

/** Closed manifest-validation diagnostics (never exceptions, never secrets). */
export type DeploymentDiagnostic =
  | { readonly code: 'INVALID_CONFIGURATION_ID' }
  | { readonly code: 'INVALID_NETWORK_ID' }
  | { readonly code: 'INVALID_NETWORK_MAGIC' }
  | { readonly code: 'INVALID_TRANSPORT_MODE' }
  | { readonly code: 'NO_ENDPOINTS' }
  | { readonly code: 'DUPLICATE_ENDPOINT' }
  | { readonly code: 'INVALID_ENDPOINT_ID' }
  | { readonly code: 'INVALID_CONTRACT_VERSION' }
  | { readonly code: 'INVALID_CLASSIFICATION' }
  | { readonly code: 'DIGEST_MISMATCH' }
  | { readonly code: 'UNKNOWN_FIELD' }
  | { readonly code: 'NOT_AN_OBJECT' };

export interface DeploymentValidation {
  readonly ok: boolean;
  readonly diagnostics: readonly DeploymentDiagnostic[];
}

/** Bounded identifier pattern (no spaces, no URL-ish or path-ish characters). */
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
/** Bounded endpoint ID pattern (never a URL; resolved through the manifest). */
const ENDPOINT_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/;
/** Semantic-version-ish pin (exact-pinned, no ranges). */
const VERSION_PATTERN = /^\d+\.\d+\.\d+$/;

const KNOWN_FIELDS = new Set([
  'configurationId',
  'canonicalNetworkId',
  'networkMagic',
  'transportMode',
  'endpointIds',
  'contractVersions',
  'classification',
  'digest',
]);

/** Canonical serialization used for the digest pin (stable field order). */
export function canonicalManifestJson(manifest: Omit<DeploymentManifest, 'digest'>): string {
  return JSON.stringify({
    configurationId: manifest.configurationId,
    canonicalNetworkId: manifest.canonicalNetworkId,
    networkMagic: manifest.networkMagic,
    transportMode: manifest.transportMode,
    endpointIds: manifest.endpointIds,
    contractVersions: {
      client: manifest.contractVersions.client,
      server: manifest.contractVersions.server,
      adapter: manifest.contractVersions.adapter,
    },
    classification: manifest.classification,
  });
}

/** Injected digest function (node:crypto sha256 in the BFF; test doubles elsewhere). */
export type DigestFunction = (canonicalJson: string) => string;

function isContractVersionPin(value: unknown): value is ContractVersionPin {
  if (value === null || typeof value !== 'object') return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v.client === 'string' && VERSION_PATTERN.test(v.client) &&
    typeof v.server === 'string' && VERSION_PATTERN.test(v.server) &&
    typeof v.adapter === 'string' && VERSION_PATTERN.test(v.adapter)
  );
}

/**
 * Parse and validate an untrusted manifest payload. Returns a typed result;
 * unknown fields, malformed shapes, invalid values, and digest mismatches
 * fail closed with exact diagnostics. Free-form text never controls behavior.
 *
 * The digest field must equal `hashFn(canonicalManifestJson(payload without
 * digest))` — the parser recomputes it, so any content tampering without a
 * matching digest update fails integrity. Deployment pipelines additionally
 * pin the digest value itself against the approved manifest digest.
 */
export function parseDeploymentManifest(payload: unknown, hashFn: DigestFunction): DeploymentValidation & { readonly manifest?: DeploymentManifest } {
  if (payload === null || typeof payload !== 'object' || Array.isArray(payload)) {
    return { ok: false, diagnostics: [{ code: 'NOT_AN_OBJECT' }] };
  }
  const record = payload as Record<string, unknown>;
  const diagnostics: DeploymentDiagnostic[] = [];

  for (const key of Object.keys(record)) {
    if (!KNOWN_FIELDS.has(key)) {
      diagnostics.push({ code: 'UNKNOWN_FIELD' });
    }
  }

  const configurationId = record.configurationId;
  if (typeof configurationId !== 'string' || !ID_PATTERN.test(configurationId)) {
    diagnostics.push({ code: 'INVALID_CONFIGURATION_ID' });
  }
  const canonicalNetworkId = record.canonicalNetworkId;
  if (typeof canonicalNetworkId !== 'string' || !ID_PATTERN.test(canonicalNetworkId)) {
    diagnostics.push({ code: 'INVALID_NETWORK_ID' });
  }
  const networkMagic = record.networkMagic;
  if (typeof networkMagic !== 'number' || !Number.isSafeInteger(networkMagic) || networkMagic <= 0) {
    diagnostics.push({ code: 'INVALID_NETWORK_MAGIC' });
  }
  const transportMode = record.transportMode;
  if (transportMode !== 'bff' && transportMode !== 'native') {
    diagnostics.push({ code: 'INVALID_TRANSPORT_MODE' });
  }
  const endpointIds = record.endpointIds;
  if (!Array.isArray(endpointIds) || endpointIds.length === 0) {
    diagnostics.push({ code: 'NO_ENDPOINTS' });
  } else {
    const seen = new Set<string>();
    for (const endpoint of endpointIds) {
      if (typeof endpoint !== 'string' || !ENDPOINT_PATTERN.test(endpoint)) {
        diagnostics.push({ code: 'INVALID_ENDPOINT_ID' });
        continue;
      }
      if (seen.has(endpoint)) {
        diagnostics.push({ code: 'DUPLICATE_ENDPOINT' });
        continue;
      }
      seen.add(endpoint);
    }
  }
  const contractVersions = record.contractVersions;
  if (!isContractVersionPin(contractVersions)) {
    diagnostics.push({ code: 'INVALID_CONTRACT_VERSION' });
  }
  const classification = record.classification;
  if (classification !== 'production' && classification !== 'isolated-non-production') {
    diagnostics.push({ code: 'INVALID_CLASSIFICATION' });
  }

  // Integrity: recompute the digest over the canonical payload (without the
  // digest field) and require an exact match. Unknown-field violations are
  // already recorded above; the digest check still runs over known fields.
  const digest = record.digest;
  const recomputed = hashFn(
    canonicalManifestJson({
      configurationId: configurationId as string,
      canonicalNetworkId: canonicalNetworkId as string,
      networkMagic: networkMagic as number,
      transportMode: transportMode as DeploymentTransportMode,
      endpointIds: (Array.isArray(endpointIds) ? endpointIds : []) as readonly string[],
      contractVersions: isContractVersionPin(contractVersions) ? contractVersions : { client: '', server: '', adapter: '' },
      classification: classification as DeploymentClass,
    }),
  );
  if (typeof digest !== 'string' || digest !== recomputed) {
    diagnostics.push({ code: 'DIGEST_MISMATCH' });
  }

  if (diagnostics.length > 0) {
    return { ok: false, diagnostics };
  }

  const manifest: DeploymentManifest = {
    configurationId: configurationId as string,
    canonicalNetworkId: canonicalNetworkId as string,
    networkMagic: networkMagic as number,
    transportMode: transportMode as DeploymentTransportMode,
    endpointIds: endpointIds as readonly string[],
    contractVersions: contractVersions as ContractVersionPin,
    classification: classification as DeploymentClass,
    digest: digest as string,
  };
  return { ok: true, diagnostics: [], manifest };
}

/**
 * Same-network endpoint rotation rule (AC-010-022): rotation is permitted only
 * between manifests whose canonical network identifier AND magic match exactly.
 * Cross-network rotation fails closed before any lookup or migration.
 */
export function canRotateEndpoint(from: DeploymentManifest, to: DeploymentManifest): boolean {
  return (
    from.canonicalNetworkId === to.canonicalNetworkId &&
    from.networkMagic === to.networkMagic &&
    from.contractVersions.client === to.contractVersions.client &&
    from.contractVersions.server === to.contractVersions.server
  );
}

/** Whether this manifest is production-class (drives endpoint/override policy). */
export function isProductionManifest(manifest: DeploymentManifest): boolean {
  return manifest.classification === 'production';
}
