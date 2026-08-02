/**
 * FEAT-003 isolated conformance — independent password policy hard-rejection.
 *
 * Recomputes the deterministic hard-rejection rules from the FEAT-003 Device-Password
 * Contract without importing the primary `../password/policy.ts` implementation:
 * - exact match against the pinned bundled common/compromised set;
 * - deterministic identity-derived rejection (alias equality, alias token ≥4
 *   graphemes, recognized numeric or four-digit-year prefix/suffix).
 *
 * Strength scoring (0–4) is a heuristic whose full zxcvbn-compatible engine is
 * corpus-pinned in Phase 7; the isolated path verifies pinned score outcomes are
 * internally consistent (0–4 range, acknowledgement rule) rather than re-deriving a
 * subjective heuristic.
 */
import { isolatedComparison } from './unicode';

/** Pinned bundled common/compromised password set (sample; full set lands with Phase 7). */
const COMMON_PASSWORDS: readonly string[] = [
  'password', 'password1', 'password123', '123456', '12345678', '123456789',
  '1234567890', 'qwerty', 'qwerty123', 'abc123', 'letmein', 'admin', 'welcome',
  'monkey', 'dragon', 'iloveyou', 'sunshine', 'princess', 'football', 'baseball',
] as const;

/** Exact match against the pinned common list (comparison form). */
export function isolatedMatchesCommonList(comparisonValue: string): boolean {
  return COMMON_PASSWORDS.some((candidate) => isolatedComparison(candidate) === comparisonValue);
}

/** Identity-derived rejection per the Device-Password Contract. */
export function isolatedIsIdentityDerived(comparisonValue: string, aliasTerms: readonly string[]): boolean {
  for (const term of aliasTerms) {
    const alias = isolatedComparison(term);
    if (alias.length < 4) continue;
    if (comparisonValue === alias) return true;
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
  return false;
}

/** Independent hard-rejection verdict for a password input. */
export function isolatedHardRejection(input: string, aliasTerms: readonly string[]): 'none' | 'COMMON_PASSWORD' | 'IDENTITY_DERIVED' {
  const comparison = isolatedComparison(input);
  if (isolatedMatchesCommonList(comparison)) return 'COMMON_PASSWORD';
  if (isolatedIsIdentityDerived(comparison, aliasTerms)) return 'IDENTITY_DERIVED';
  return 'none';
}
