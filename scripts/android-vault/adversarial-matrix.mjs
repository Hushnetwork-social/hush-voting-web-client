#!/usr/bin/env node
/**
 * FEAT-006 Phase 7 Task 7.1 — cross-runtime conformance and adversarial matrix.
 *
 * Replays the pinned corpora and AW-001 canonical AAD through both runtimes,
 * then sweeps every authenticated wrapper field through a mutation matrix and
 * asserts each mutation changes the canonical digest (tamper sensitivity).
 * Runs the configured android_vault Rust tests and android-vault TS tests as
 * the deterministic cross-runtime replay. No editable fixture copy exists;
 * the vector file is the single source of truth.
 *
 * Usage:
 *   node scripts/android-vault/adversarial-matrix.mjs
 */

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { createHash } from 'node:crypto';

const SCRIPT_DIR = dirname(new URL(import.meta.url).pathname);
const REPO_ROOT = join(SCRIPT_DIR, '..', '..');

/** RFC 8785-style canonical JSON for the vector metadata (deterministic). */
function canonicalJson(value) {
  if (Array.isArray(value)) {
    return `[${value.map(canonicalJson).join(',')}]`;
  }
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return `{${keys.map((k) => `${canonicalJson(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  if (typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  throw new Error('cannot canonicalize');
}

function sha256Hex(text) {
  return createHash('sha256').update(text, 'utf8').digest('hex');
}

/** Mutation matrix: every authenticated binding field, one at a time. */
function mutations(meta) {
  return [
    ['wrapperVersion', { ...meta, wrapperVersion: 2 }],
    ['adapterId', { ...meta, adapterId: 'other-adapter' }],
    ['applicationId', { ...meta, applicationId: 'com.hushvoting.client.debug' }],
    ['releaseChannel', { ...meta, releaseChannel: 'debug' }],
    ['vaultKeyReference', { ...meta, vaultKeyReference: 'hvk-mutated' }],
    ['envelopeFormatVersion', { ...meta, envelopeFormatVersion: 2 }],
    ['parameterSuiteVersion', { ...meta, parameterSuiteVersion: 2 }],
    ['recordSchemaVersion', { ...meta, recordSchemaVersion: 2 }],
    ['slot', { ...meta, slot: 'b' }],
    ['vaultGeneration', { ...meta, vaultGeneration: 8 }],
    ['recordPurpose', { ...meta, recordPurpose: 'other' }],
    ['criticalExtensions', { ...meta, criticalExtensions: [{ key: 'k', value: 'v' }] }],
  ];
}

function main() {
  const matrix = [
    { name: 'rust-android-vault-tests', cmd: 'cargo', args: ['test', '--manifest-path', 'src-tauri/Cargo.toml', '--lib', 'android_vault', '--locked'] },
    { name: 'ts-android-vault-tests', cmd: 'npm', args: ['run', 'test:unit', '--silent', '--', 'src/lib/android-vault', 'src/app/auth/android'] },
    { name: 'identity-conformance', cmd: 'npm', args: ['run', 'identity:conformance', '--silent'] },
    { name: 'vault-ci', cmd: 'npm', args: ['run', 'vault:ci', '--silent'] },
  ];

  let red = 0;
  for (const gate of matrix) {
    try {
      execFileSync(gate.cmd, gate.args, { cwd: REPO_ROOT, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      console.log(`[PASS] ${gate.name}`);
    } catch (err) {
      red += 1;
      console.error(`[FAIL] ${gate.name}: ${err?.stdout?.toString?.() ?? err?.message ?? err}`);
    }
  }

  // AW-001 vector mutation sweep.
  const vectors = JSON.parse(
    readFileSync(join(REPO_ROOT, 'conformance', 'android-vault', 'v1', 'vectors', 'android-wrapper-vectors.json'), 'utf8'),
  );
  const aw001 = vectors.vectors[0];
  const base = canonicalJson(aw001.metadata);
  const baseSha = sha256Hex(base);
  if (baseSha !== aw001.canonicalSha256) {
    red += 1;
    console.error(`[FAIL] AW-001 canonical digest mismatch: expected ${aw001.canonicalSha256} got ${baseSha}`);
  } else {
    console.log(`[PASS] AW-001 canonical digest replay (${baseSha.slice(0, 12)}...)`);
  }
  let mutated = 0;
  for (const [field, m] of mutations(aw001.metadata)) {
    const sha = sha256Hex(canonicalJson(m));
    if (sha === baseSha) {
      red += 1;
      console.error(`[FAIL] mutation of ${field} did not change the canonical digest`);
    } else {
      mutated += 1;
    }
  }
  console.log(`[INFO] mutation sweep: ${mutated}/${mutations(aw001.metadata).length} fields tamper-sensitive`);

  if (red > 0) {
    console.error(`ANDROID ADVERSARIAL MATRIX FAILED (${red} red)`);
    process.exit(1);
  }
  console.log('ANDROID ADVERSARIAL MATRIX OK (corpora + AW-001 replay, mutation sweep)');
}

if (process.argv[1] && process.argv[1].endsWith('adversarial-matrix.mjs')) {
  main();
}
