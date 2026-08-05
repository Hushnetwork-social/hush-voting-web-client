/**
 * FEAT-010 auth contracts — immutable secret-safe evidence schema (Task 2.7).
 *
 * Evidence records carry ONLY allowlisted aggregate/digest fields. The
 * validator rejects any alias, full address, endpoint, transaction, file
 * identifier, key ID, exact secret timestamp, or secret-like content
 * (normative: FeatureDescription "Observability", "Secret-safe evidence";
 * AC-010-089/097/099).
 *
 * Framework-neutral, secret-free.
 */

/** Target classes for platform evidence. */
export type EvidenceTarget = 'web' | 'ubuntu' | 'android-physical';

/** Aggregate outcome of a real-platform procedure (no named-human attestation). */
export type AggregatePlatformResult = 'PASS' | 'FAIL' | 'NOT_EXECUTED';

/** External EPIC blocker state (never fabricated, never inferred). */
export type ExternalBlockerState = 'PASS' | 'FAIL' | 'NOT_SUPPLIED';

/** One immutable evidence record (secret-safe by construction + validation). */
export interface EvidenceRecord {
  readonly recordId: string;
  readonly featureId: 'FEAT-010';
  readonly criterionId: string;
  readonly target: EvidenceTarget;
  /** Exact tested artifact/build/config/server/fixture digests. */
  readonly digests: readonly { readonly label: string; readonly digest: string }[];
  readonly result: AggregatePlatformResult;
  readonly coarseTimingBucketMs: number;
  /** Random ephemeral support code (non-correlating) for failures. */
  readonly supportCode?: string;
}

/** One external-blocker ledger entry. */
export interface ExternalBlockerEntry {
  readonly id: string;
  readonly owner: string;
  readonly state: ExternalBlockerState;
  readonly releaseImpact: string;
}

/** Evidence validation diagnostics. */
export type EvidenceDiagnostic =
  | { readonly code: 'FORBIDDEN_IDENTIFIER'; readonly detail: string }
  | { readonly code: 'INVALID_RESULT' }
  | { readonly code: 'INVALID_TARGET' }
  | { readonly code: 'INVALID_DIGEST' }
  | { readonly code: 'INVALID_BUCKET' }
  | { readonly code: 'UNKNOWN_RECORD_ID' };

/** Prohibited content markers (secrets/identifiers/endpoints/transactions). */
const FORBIDDEN_PATTERNS: readonly { readonly label: string; readonly re: RegExp }[] = [
  { label: 'alias', re: /alias|displayName|username/i },
  { label: 'address', re: /signingAddress|encryptionAddress|fullAddress|publicAddress/i },
  { label: 'endpoint', re: /https?:\/\/|grpc:|endpointUrl|rpcUrl/i },
  { label: 'transaction material', re: /txId|transactionId|signedJson|signature/i },
  { label: 'file identifier', re: /\.dat|filePath|sourceUri/i },
  { label: 'key id', re: /keyId|credentialId|nativeHandle/i },
  { label: 'secret timestamp', re: /issuedAt|expiresAt|lastAuthAt|timestamp/i },
  { label: 'secret content', re: /password|mnemonic|seedPhrase|privateKey/i },
  { label: 'device identifier', re: /deviceId|serial|udid/i },
];

const DIGEST_PATTERN = /^[a-f0-9]{16,128}$/;

function scan(value: string): string | null {
  for (const { label, re } of FORBIDDEN_PATTERNS) {
    if (re.test(value)) return label;
  }
  return null;
}

/** Validate an evidence record; any prohibited identifier rejects it. */
export function validateEvidenceRecord(
  record: unknown,
): { readonly ok: boolean; readonly diagnostics: readonly EvidenceDiagnostic[] } {
  if (record === null || typeof record !== 'object' || Array.isArray(record)) {
    return { ok: false, diagnostics: [{ code: 'INVALID_RESULT' }] };
  }
  const r = record as Record<string, unknown>;
  const diagnostics: EvidenceDiagnostic[] = [];

  if (r.featureId !== 'FEAT-010') {
    diagnostics.push({ code: 'UNKNOWN_RECORD_ID' });
  }
  if (typeof r.recordId !== 'string' || r.recordId.length === 0 || /[\s/\\]/.test(r.recordId)) {
    diagnostics.push({ code: 'UNKNOWN_RECORD_ID' });
  }
  if (typeof r.criterionId !== 'string' || !/^AC-010-\d{3}$/.test(r.criterionId)) {
    diagnostics.push({ code: 'UNKNOWN_RECORD_ID' });
  }
  if (r.target !== 'web' && r.target !== 'ubuntu' && r.target !== 'android-physical') {
    diagnostics.push({ code: 'INVALID_TARGET' });
  }
  if (r.result !== 'PASS' && r.result !== 'FAIL' && r.result !== 'NOT_EXECUTED') {
    diagnostics.push({ code: 'INVALID_RESULT' });
  }
  if (typeof r.coarseTimingBucketMs !== 'number' || r.coarseTimingBucketMs < 0) {
    diagnostics.push({ code: 'INVALID_BUCKET' });
  }
  if (!Array.isArray(r.digests) || r.digests.length === 0) {
    diagnostics.push({ code: 'INVALID_DIGEST' });
  } else {
    for (const entry of r.digests) {
      const e = entry as Record<string, unknown> | null;
      if (
        e === null ||
        typeof e.label !== 'string' ||
        typeof e.digest !== 'string' ||
        !DIGEST_PATTERN.test(e.digest)
      ) {
        diagnostics.push({ code: 'INVALID_DIGEST' });
      }
    }
  }

  // Scan only free-text fields for prohibited content (digest values are
  // sanctioned hex content and must never be scanned as identifiers).
  const scanFields: string[] = [];
  if (typeof r.recordId === 'string') scanFields.push(r.recordId);
  if (typeof r.criterionId === 'string') scanFields.push(r.criterionId);
  if (typeof r.supportCode === 'string') scanFields.push(r.supportCode);
  if (Array.isArray(r.digests)) {
    for (const entry of r.digests) {
      const e = entry as Record<string, unknown> | null;
      if (e !== null && typeof e.label === 'string') scanFields.push(e.label);
    }
  }
  const hit = scan(scanFields.join('\n'));
  if (hit !== null) {
    diagnostics.push({ code: 'FORBIDDEN_IDENTIFIER', detail: hit });
  }

  return { ok: diagnostics.length === 0, diagnostics };
}

/** Validate an external-blocker entry (truthful states only). */
export function validateExternalBlockerEntry(
  entry: unknown,
): { readonly ok: boolean; readonly diagnostics: readonly EvidenceDiagnostic[] } {
  if (entry === null || typeof entry !== 'object') {
    return { ok: false, diagnostics: [{ code: 'INVALID_RESULT' }] };
  }
  const e = entry as Record<string, unknown>;
  const diagnostics: EvidenceDiagnostic[] = [];
  if (typeof e.id !== 'string' || !/^EXT-\d{3}-\d{3}$/.test(e.id)) {
    diagnostics.push({ code: 'UNKNOWN_RECORD_ID' });
  }
  if (typeof e.owner !== 'string' || e.owner.length === 0) {
    diagnostics.push({ code: 'UNKNOWN_RECORD_ID' });
  }
  if (e.state !== 'PASS' && e.state !== 'FAIL' && e.state !== 'NOT_SUPPLIED') {
    diagnostics.push({ code: 'INVALID_RESULT' });
  }
  if (typeof e.releaseImpact !== 'string' || e.releaseImpact.length === 0) {
    diagnostics.push({ code: 'UNKNOWN_RECORD_ID' });
  }
  const scanFields = [e.id, e.owner, e.releaseImpact].filter((v): v is string => typeof v === 'string');
  const hit = scan(scanFields.join('\n'));
  if (hit !== null) {
    diagnostics.push({ code: 'FORBIDDEN_IDENTIFIER', detail: hit });
  }
  return { ok: diagnostics.length === 0, diagnostics };
}
