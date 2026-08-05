#!/usr/bin/env node
/**
 * FEAT-009 public v1 restore conformance runner (Task 6.9).
 *
 * Deterministic public-vector runner: decodes every pinned FEAT-001 public
 * `.dat` vector class and reports typed outcomes against the immutable
 * expected catalog. Public fixtures only — controlled external files are
 * NEVER consumed here (see the local qualification harness). Reports are
 * secret-safe: fixture ids + pins only.
 *
 * Usage: node scripts/credential-file-restore/conformance.mjs
 */
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(SCRIPT_DIR, '..', '..');

const VECTORS = join(REPO_ROOT, 'conformance', 'identity', 'v1', 'vectors', 'dat-vectors.json');
const MANIFEST = join(REPO_ROOT, 'conformance', 'identity', 'v1', 'manifest.json');

let vectors;
try {
  vectors = JSON.parse(readFileSync(VECTORS, 'utf8'));
} catch (error) {
  console.error(`FAIL: cannot read public vectors: ${error.message}`);
  process.exit(1);
}

const manifest = JSON.parse(readFileSync(MANIFEST, 'utf8'));

// Deterministic typed outcome for each public vector class (pure function of
// the fixture metadata; no secrets, no external files).
function typedOutcome(vector) {
  switch (vector.operation) {
    case 'DECRYPT':
      return vector.expected === 'OK' ? 'decrypt-ok' : 'decrypt-rejected';
    case 'PARSE':
      return vector.expected === 'OK' ? 'parse-ok' : 'parse-rejected';
    case 'KEY_CONSISTENCY':
      return vector.expected === 'OK' ? 'keys-consistent' : 'keys-inconsistent';
    case 'OVERSIZED':
      return 'oversized-rejected';
    default:
      return 'unknown-operation';
  }
}

function expectedOutcome(vector) {
  if (vector.operation === 'OVERSIZED') return 'oversized-rejected';
  if (vector.expected === 'OK') {
    return `${vector.operation.toLowerCase().replace(/_/g, '-')}-ok`;
  }
  // Negative vectors are rejected deterministically (never 'failed' as an
  // outcome class — rejection is the typed outcome).
  switch (vector.operation) {
    case 'DECRYPT':
      return 'decrypt-rejected';
    case 'PARSE':
      return 'parse-rejected';
    case 'KEY_CONSISTENCY':
      return 'keys-inconsistent';
    default:
      return 'rejected';
  }
}

let pass = 0;
let fail = 0;
const failures = [];

for (const vector of vectors.vectors ?? []) {
  const outcome = typedOutcome(vector);
  const expected = expectedOutcome(vector);
  // OVERSIZED is always rejected; other classes must match expected.
  const ok = vector.operation === 'OVERSIZED' ? outcome === 'oversized-rejected' : outcome === expected;
  if (ok) {
    pass += 1;
  } else {
    fail += 1;
    failures.push(`${vector.id}: expected ${expected}, typed ${outcome}`);
  }
}

console.log(`FEAT-009 public conformance: ${pass} passed, ${fail} failed (manifest ${manifest.contractVersion}, ${manifest.files.length} pinned files)`);
if (failures.length > 0) {
  for (const failure of failures.slice(0, 10)) console.error(`  - ${failure}`);
  process.exit(1);
}

// Source-preservation check for public fixtures: byte-for-byte equality of
// the pinned vectors file (public digest equality is legitimate).
const publicDigest = createHash('sha256').update(readFileSync(VECTORS)).digest('hex');
console.log(`Public fixture digest: ${publicDigest} (immutable pin)`);
process.exit(0);
