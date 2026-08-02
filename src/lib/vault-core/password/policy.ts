/**
 * FEAT-003 vault-core password — local strength and policy model.
 *
 * Hard reject:
 * - grapheme/byte policy violations (Unicode contract);
 * - matches from the pinned bundled common/compromised-password set;
 * - deterministic obvious identity-derived values.
 *
 * Score 0–1 values not already hard-rejected require explicit weakness acknowledgement
 * but remain permitted; score 2–4 proceed normally. A pinned fully local
 * zxcvbn-compatible engine with bundled dictionaries performs no network request.
 * Password values and strength results are never sent to telemetry.
 *
 * The bundled common list is a pinned, digest-versioned subset (see
 * COMMON_LIST_DIGEST). Full zxcvbn dictionaries land with the Phase 7 corpus; this
 * module owns the deterministic policy shape.
 *
 * Normative source: FEAT-003 FeatureDescription "Strength policy", "Identity-derived
 * rejection".
 */
import { comparisonRepresentation } from './unicode';

/** Pinned bundled common/compromised password set (sample; full set arrives with corpus). */
const COMMON_PASSWORDS: readonly string[] = [
  'password', 'password1', 'password123', '123456', '12345678', '123456789',
  '1234567890', 'qwerty', 'qwerty123', 'abc123', 'letmein', 'admin', 'welcome',
  'monkey', 'dragon', 'iloveyou', 'sunshine', 'princess', 'football', 'baseball',
] as const;

/** Digest-pinned policy inputs (placeholder digest; pinned full set lands in Phase 7). */
export const COMMON_LIST_DIGEST = '0000000000000000000000000000000000000000000000000000000000000000' as const;

/** Score 0–4 (zxcvbn-compatible). */
export type StrengthScore = 0 | 1 | 2 | 3 | 4;

export interface StrengthResult {
  readonly score: StrengthScore;
  readonly hardRejected: boolean;
  readonly requiresAcknowledgement: boolean;
}

/**
 * Deterministic local strength heuristic (zxcvbn-compatible shape, offline).
 * Uses length/entropy proxies; the full engine is corpus-pinned in Phase 7.
 */
export function localStrengthScore(comparisonValue: string): StrengthScore {
  const length = comparisonValue.length;
  const unique = new Set(comparisonValue).size;
  if (length === 0) return 0;
  const variety = unique / length;
  if (length <= 6) return 0;
  if (length <= 8 && variety < 0.5) return 1;
  if (length <= 10) return 2;
  if (length <= 14) return 3;
  return 4;
}

/** Hard rejection: exact match against the pinned common list (comparison form). */
export function matchesCommonList(comparisonValue: string): boolean {
  return COMMON_PASSWORDS.some((c) => comparisonRepresentation(c) === comparisonValue);
}

/** Identity-derived rejection: alias equality, alias token ≥4 graphemes, year/numeric affixes. */
export function isIdentityDerived(comparisonValue: string, aliasTerms: readonly string[]): boolean {
  for (const term of aliasTerms) {
    const alias = comparisonRepresentation(term);
    if (alias.length >= 4 && comparisonValue === alias) return true;
    if (alias.length >= 4) {
      // Recognized common numeric or four-digit-year prefix/suffix.
      const year = /^(19|20)\d{2}$/.test(alias) ? alias : null;
      const numeric = /^\d{1,4}$/.test(alias) ? alias : null;
      const affix = year ?? numeric;
      if (affix) {
        if (comparisonValue === `${affix}${alias}` || comparisonValue === `${alias}${affix}`) return true;
        continue;
      }
      const prefix = comparisonValue.startsWith(alias) ? comparisonValue.slice(alias.length) : '';
      const suffix = comparisonValue.endsWith(alias) ? comparisonValue.slice(0, -alias.length) : '';
      if ((prefix !== '' && /^\d{1,4}$/.test(prefix)) || (suffix !== '' && /^\d{1,4}$/.test(suffix))) return true;
    }
  }
  return false;
}

export interface PasswordPolicyInput {
  readonly password: string;
  readonly aliasTerms: readonly string[];
}

export type PasswordPolicyResult =
  | { readonly ok: true; readonly score: StrengthScore; readonly requiresAcknowledgement: boolean }
  | { readonly ok: false; readonly code: 'POLICY_VIOLATION' | 'COMMON_PASSWORD' | 'IDENTITY_DERIVED'; readonly message: string };

/** Deterministic full policy evaluation (Unicode contract assumed already validated). */
export function evaluatePasswordPolicy(input: PasswordPolicyInput): PasswordPolicyResult {
  const comparison = comparisonRepresentation(input.password);
  if (matchesCommonList(comparison)) {
    return { ok: false, code: 'COMMON_PASSWORD', message: 'password matches a common/compromised value' };
  }
  if (isIdentityDerived(comparison, input.aliasTerms)) {
    return { ok: false, code: 'IDENTITY_DERIVED', message: 'password is derived from identity metadata' };
  }
  const score = localStrengthScore(comparison);
  const requiresAcknowledgement = score <= 1;
  return { ok: true, score, requiresAcknowledgement };
}
