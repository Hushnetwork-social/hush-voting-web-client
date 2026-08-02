#!/usr/bin/env node
/**
 * FEAT-004 downstream handoff integrity check (Task 6.6).
 * =======================================================
 * Verifies the immutable browser-vault handoff document exists at the pinned
 * location, declares the protocol version, and pins the unchanged FEAT-003
 * corpus manifest. Any drift fails the gate.
 *
 * Exit codes: 0 = intact, 1 = drift, 2 = internal error.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');
const HANDOFF = join(REPO_ROOT, 'conformance', 'browser-vault', 'v1', 'HANDOFF.md');
const VAULT_MANIFEST = join(REPO_ROOT, 'conformance', 'vault', 'v1', 'manifest.json');

const failures = [];

if (!existsSync(HANDOFF)) {
  failures.push('missing conformance/browser-vault/v1/HANDOFF.md');
} else {
  const content = readFileSync(HANDOFF, 'utf8');
  if (!content.includes('BROWSER_PROTOCOL_VERSION = 1') && !/protocol version[^a-z]*1/i.test(content)) {
    failures.push('handoff does not declare the closed protocol version');
  }
  if (!content.includes('e8dfdfa49b9e')) {
    failures.push('handoff does not pin the FEAT-003 corpus manifest');
  }
}

if (!existsSync(VAULT_MANIFEST)) {
  failures.push('vault corpus manifest missing');
} else {
  const digest = createHash('sha256').update(readFileSync(VAULT_MANIFEST)).digest('hex');
  if (!digest.startsWith('e8dfdfa49b9e')) {
    failures.push(`vault corpus manifest drifted: ${digest.slice(0, 12)}`);
  }
}

if (failures.length > 0) {
  process.stderr.write(`BROWSER-VAULT HANDOFF INTEGRITY FAILED (${failures.length})\n`);
  for (const failure of failures) {
    process.stderr.write(`  - ${failure}\n`);
  }
  process.exitCode = 1;
} else {
  process.stdout.write('BROWSER-VAULT HANDOFF INTEGRITY OK (protocol v1, corpus pin e8dfdfa49b9e)\n');
  process.exitCode = 0;
}
