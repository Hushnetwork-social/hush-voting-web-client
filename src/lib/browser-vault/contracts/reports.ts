/**
 * FEAT-004 browser-vault contracts — safe digest-only evidence reports.
 *
 * Platform reports identify exact versions, corpus pins, and outcomes only.
 * No stable identity, device, session, vault, DB key, endpoint, ciphertext
 * excerpt, exact timestamp, raw browser error, or credential-derived value may
 * appear. Reports are the additive evidence surface FEAT-004 publishes for
 * corpus replay and browser qualification.
 *
 * Normative source: FEAT-004 FeatureDescription "Browser-Version
 * Infrastructure", "Privacy, Diagnostics, and Telemetry".
 */

/** Coarse outcome vocabulary for deterministic reports. */
export type ReportOutcome = 'pass' | 'mismatch' | 'error' | 'skip';

/** Digest-only adapter evidence report (schema v1). */
export interface BrowserAdapterReport {
  readonly reportVersion: 1;
  readonly outcome: ReportOutcome;
  /** Exact app build identity (never the source tree state). */
  readonly appVersion: string;
  readonly buildDigest: string;
  readonly protocolVersion: number;
  /** Exact corpus pin the adapter replayed against. */
  readonly corpusVersion: string;
  readonly corpusManifestSha256: string;
  /** Certified browser family + major version category (release-freeze relative). */
  readonly browserFamily: string;
  readonly browserMajorVersion: string;
  /** Coarse performance/resource bucket only (never exact timing). */
  readonly coarseDurationBucketMs?: number;
  /** Platform adapter digest (immutable build output). */
  readonly adapterDigestSha256?: string;
}

/** Field deny-list enforced by the report validator: nothing identity/secret-shaped. */
const FORBIDDEN_REPORT_FIELDS = [
  'identity',
  'alias',
  'address',
  'key',
  'secret',
  'password',
  'mnemonic',
  'ciphertext',
  'token',
  'session',
  'deviceId',
  'url',
  'endpoint',
  'db',
  'timestamp',
] as const;

/** Validate a report object rejects identity/secret/stable-identifier fields. */
export function validateReportSafety(report: unknown): boolean {
  if (typeof report !== 'object' || report === null) {
    return false;
  }
  const scan = (value: unknown, path: string): boolean => {
    if (typeof value === 'string') {
      const lower = value.toLowerCase();
      if (FORBIDDEN_REPORT_FIELDS.some((token) => lower.includes(token))) {
        return false;
      }
    } else if (Array.isArray(value)) {
      return value.every((item, index) => scan(item, `${path}[${index}]`));
    } else if (typeof value === 'object' && value !== null) {
      return Object.entries(value).every(([k, v]) => {
        // Field names are scanned as well as values: an identity/secret-shaped
        // key is a contract violation even with a generic value.
        const keyLower = k.toLowerCase();
        if (FORBIDDEN_REPORT_FIELDS.some((token) => keyLower.includes(token))) {
          return false;
        }
        return scan(v, `${path}.${k}`);
      });
    }
    return true;
  };
  return scan(report, '$');
}

/** Create a report with only the fields actually provided (no undefined noise). */
export function createAdapterReport(input: Omit<BrowserAdapterReport, 'reportVersion'>): BrowserAdapterReport {
  return { reportVersion: 1, ...input };
}
