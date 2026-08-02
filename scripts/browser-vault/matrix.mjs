#!/usr/bin/env node
/**
 * FEAT-004 browser matrix qualification (Task 7.5/7.6).
 * =======================================================
 * Declares the required release targets (current/previous desktop Chrome and
 * Edge, current physical Android Chrome/Edge + managed previous-major) and
 * executes the unchanged production-adapter suite for every target that is
 * locally executable. Sanitized evidence (browser family/major category,
 * outcomes, coarse timing buckets, digests) is emitted — never stable
 * identity/device/session identifiers or exact timestamps.
 *
 * Missing REQUIRED targets FAIL release (no silent skip): a release cannot
 * claim certification without executing every declared target. Local runs
 * execute desktop Chromium and record the other targets as
 * required-but-blocked, so CI with the approved managed browser/device
 * service completes the matrix.
 *
 * Exit codes: 0 = all declared targets executed, 1 = blocked/unsupported
 * targets or gate failure, 2 = internal error.
 */
import { execFileSync } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');
const EVIDENCE = join(REPO_ROOT, 'conformance', 'reports', 'browser-matrix-evidence.json');

/** Required release targets (release-freeze relative major categories). */
const REQUIRED_TARGETS = [
  { id: 'desktop-chrome-current', browser: 'chrome', major: 'current', device: 'desktop', localExecutable: true },
  { id: 'desktop-chrome-previous', browser: 'chrome', major: 'previous', device: 'desktop', localExecutable: false },
  { id: 'desktop-edge-current', browser: 'edge', major: 'current', device: 'desktop', localExecutable: false },
  { id: 'desktop-edge-previous', browser: 'edge', major: 'previous', device: 'desktop', localExecutable: false },
  { id: 'android-chrome-current', browser: 'chrome', major: 'current', device: 'android-physical', localExecutable: false },
  { id: 'android-edge-current', browser: 'edge', major: 'current', device: 'android-physical', localExecutable: false },
  { id: 'android-chrome-previous-managed', browser: 'chrome', major: 'previous', device: 'android-managed', localExecutable: false },
  { id: 'android-edge-previous-managed', browser: 'edge', major: 'previous', device: 'android-managed', localExecutable: false },
];

function runLocalChromiumSuite() {
  execFileSync('npx', ['playwright', 'test', 'browser/vault-qualification.spec.ts', 'browser/vault-storage.spec.ts', 'browser/vault-coordination.spec.ts', 'browser/vault-performance.spec.ts', '--project=desktop-chromium', '--reporter=json', '--output', join(REPO_ROOT, 'test-results', 'matrix')], {
    cwd: REPO_ROOT,
    stdio: 'pipe',
    timeout: 900_000,
  });
}

/** Coarse timing bucket (never exact timing in evidence). */
function bucketMs(ms) {
  if (ms < 50) return 'lt50';
  if (ms < 250) return '50-250';
  if (ms < 1000) return '250-1000';
  return 'gt1000';
}

function main() {
  const results = [];
  let blocked = 0;
  for (const target of REQUIRED_TARGETS) {
    if (!target.localExecutable) {
      results.push({
        target: target.id,
        browser: target.browser,
        major: target.major,
        device: target.device,
        outcome: 'required-blocked',
        detail: 'approved managed browser/device job must execute this target before release',
      });
      blocked += 1;
      continue;
    }
    try {
      const start = Date.now();
      runLocalChromiumSuite();
      results.push({
        target: target.id,
        browser: target.browser,
        major: target.major,
        device: target.device,
        outcome: 'pass',
        durationBucketMs: bucketMs(Date.now() - start),
        suite: 'production-adapter-qualification',
      });
    } catch {
      results.push({ target: target.id, browser: target.browser, major: target.major, device: target.device, outcome: 'fail' });
      blocked += 1;
    }
  }

  mkdirSync(join(REPO_ROOT, 'conformance', 'reports'), { recursive: true });
  writeFileSync(EVIDENCE, JSON.stringify({ schema: 'browser-matrix-evidence-v1', generated: new Date().toISOString().slice(0, 10), results }, null, 2));

  const executed = results.filter((r) => r.outcome === 'pass').length;
  if (blocked > 0) {
    process.stderr.write(`BROWSER MATRIX BLOCKED: ${blocked} required target(s) not executed (${executed}/${REQUIRED_TARGETS.length} executed). Release cannot be certified until all targets run.\n`);
    process.exitCode = 1;
  } else {
    process.stdout.write(`BROWSER MATRIX OK (${executed}/${REQUIRED_TARGETS.length} targets executed, evidence written)\n`);
    process.exitCode = 0;
  }
}

main();
