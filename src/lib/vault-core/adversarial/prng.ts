/**
 * FEAT-003 adversarial harness — deterministic seeded PRNG (Task 7.1).
 *
 * mulberry32: a small, deterministic, seed-reproducible 32-bit PRNG. Every property
 * and fuzz case derives from an explicit seed so any discovered failure can be
 * replayed byte-for-byte and recorded as a permanent regression vector. No wall-clock,
 * entropy, or real credential input participates in case generation.
 */

/** Deterministic 32-bit PRNG; returns a float in [0, 1). */
export function mulberry32(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

/** Random integer in [min, max] inclusive. */
export function intInRange(rand: () => number, min: number, max: number): number {
  return min + Math.floor(rand() * (max - min + 1));
}

/** Random pick from an array. */
export function pick<T>(rand: () => number, items: readonly T[]): T {
  return items[Math.floor(rand() * items.length)];
}

/** Random ASCII/Unicode-ish string (bounded length). */
export function randomString(rand: () => number, maxLen: number): string {
  const len = intInRange(rand, 0, maxLen);
  let out = '';
  for (let i = 0; i < len; i++) {
    const mode = rand();
    if (mode < 0.5) {
      out += String.fromCharCode(intInRange(rand, 0x20, 0x7e));
    } else if (mode < 0.75) {
      out += String.fromCharCode(intInRange(rand, 0x80, 0x2fff));
    } else if (mode < 0.9) {
      // Unicode combining marks exercise NFC normalization paths.
      out += String.fromCharCode(intInRange(rand, 0x300, 0x36f));
    } else {
      out += String.fromCodePoint(intInRange(rand, 0x1f000, 0x1f9ff));
    }
  }
  return out;
}

/** Random base64url-ish token. */
export function randomBase64Url(rand: () => number, maxLen: number): string {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
  const len = intInRange(rand, 0, maxLen);
  let out = '';
  for (let i = 0; i < len; i++) out += alphabet[Math.floor(rand() * alphabet.length)];
  return out;
}

/** Random nested JSON-ish value with bounded depth/size. */
export function randomJsonValue(rand: () => number, depth: number, budget: { nodes: number }): unknown {
  if (depth <= 0 || budget.nodes <= 0) {
    return pick(rand, [null, true, false, intInRange(rand, -1000, 1000), randomString(rand, 12)]);
  }
  const kind = rand();
  if (kind < 0.3) {
    const n = intInRange(rand, 0, Math.min(4, budget.nodes));
    budget.nodes -= n;
    const arr: unknown[] = [];
    for (let i = 0; i < n; i++) arr.push(randomJsonValue(rand, depth - 1, budget));
    return arr;
  }
  if (kind < 0.6) {
    const n = intInRange(rand, 0, Math.min(4, budget.nodes));
    budget.nodes -= n;
    const obj: Record<string, unknown> = {};
    for (let i = 0; i < n; i++) {
      obj[`k${i}_${intInRange(rand, 0, 999)}`] = randomJsonValue(rand, depth - 1, budget);
    }
    return obj;
  }
  return pick(rand, [null, true, false, intInRange(rand, -1000, 1000), randomString(rand, 12)]);
}
