/**
 * FEAT-004 browser-vault crypto — nonce uniqueness and cleanup boundaries.
 *
 * The adapter rejects observable nonce reuse across active/rollback records.
 * Bounded per-session tracking: record keys are bounded opaque identifiers and
 * the tracker never retains plaintext. Cleanup overwrites application-owned
 * mutable byte arrays and drops references as soon as practical; it does NOT
 * claim deterministic physical erasure of JavaScript engine copies, WebCrypto
 * internals, GC'd strings, crash dumps, extensions, or OS memory.
 *
 * Normative source: FEAT-004 FeatureDescription "Production Cryptography",
 * "Memory cleanup".
 */

/** Hex view of a nonce for reuse comparison (never stored alongside plaintext). */
export function nonceToHex(nonce: Uint8Array): string {
  let out = '';
  for (const byte of nonce) {
    out += byte.toString(16).padStart(2, '0');
  }
  return out;
}

/**
 * Bounded per-session nonce tracker (active + rollback record scopes).
 *
 * Scope contract: record scopes MUST include the record generation
 * (e.g. `active:gen-3`, `rollback:gen-2`) so a re-encrypted record is a fresh
 * scope and rotation is never mistaken for reuse. The tracker rejects:
 *  - the same nonce under two different scopes (coexisting records reuse);
 *  - a same-scope nonce change (a scope may only ever hold one nonce);
 *  - growth beyond `maxEntries` (bounded, fail closed).
 */
export interface NonceTracker {
  /** Record a nonce under a record scope; false when the nonce is already used. */
  readonly observe: (recordScope: string, nonce: Uint8Array) => boolean;
  /** Drop all tracking (called on Lock/cleanup). */
  readonly clear: () => void;
  readonly size: () => number;
}

/** Bounded tracker that rejects reuse within a scope and across scopes. */
export function createNonceTracker(maxEntries = 64): NonceTracker {
  const seen = new Map<string, string>();
  return {
    observe(recordScope, nonce) {
      const hex = nonceToHex(nonce);
      const existing = seen.get(recordScope);
      if (existing === hex) {
        return true; // same scope, same nonce: unchanged record; not a new use
      }
      if (existing !== undefined) {
        return false; // same scope reused with a different nonce is allowed only via rotation; reject stale reuse
      }
      if (seen.size >= maxEntries) {
        return false; // bounded tracker; fail closed rather than unbounded growth
      }
      for (const value of seen.values()) {
        if (value === hex) {
          return false; // cross-scope nonce reuse
        }
      }
      seen.set(recordScope, hex);
      return true;
    },
    clear() {
      seen.clear();
    },
    size() {
      return seen.size;
    },
  };
}

/** Best-effort overwrite of an application-owned mutable byte array. */
export function wipeBytes(bytes: Uint8Array | null | undefined): void {
  if (bytes) {
    bytes.fill(0);
  }
}

/** Drop references to a set of mutable buffers (best effort, no physical-erasure claim). */
export function dropBuffers(...buffers: Array<Uint8Array | null | undefined>): void {
  for (const buffer of buffers) {
    wipeBytes(buffer);
  }
}
