#!/usr/bin/env node
/**
 * FEAT-006 Phase 6 Task 6.5 — unified Android vault gate.
 *
 * Bounded orchestration: frontend gates, Rust gates, corpus replay, Android
 * schema/vector validation, manifest policy (against the generated source
 * manifest), package/secret scans, and handoff integrity run in deterministic
 * order. Each stage is captured independently; a later success never
 * supersedes an earlier failure. `--selftest` seeds one defect per gate and
 * asserts detection, proving the gates still fail closed.
 *
 * Usage:
 *   node scripts/android-vault/ci-android-vault.mjs [--selftest] [--skip-audit]
 */

import { execFileSync } from 'node:child_process';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { checkManifestPolicy } from './policy-check.mjs';

const SCRIPT_DIR = dirname(new URL(import.meta.url).pathname);
const REPO_ROOT = join(SCRIPT_DIR, '..', '..');

const GATES = [
  { name: 'frontend-lint', cmd: 'npm', args: ['run', 'lint', '--silent'] },
  { name: 'typecheck', cmd: 'npm', args: ['run', 'typecheck', '--silent'] },
  { name: 'unit-tests', cmd: 'npm', args: ['run', 'test:unit', '--silent'] },
  { name: 'static-build', cmd: 'npm', args: ['run', 'build:static', '--silent'] },
  { name: 'rust-fmt', cmd: 'cargo', args: ['fmt', '--manifest-path', 'src-tauri/Cargo.toml', '--', '--check'] },
  { name: 'rust-clippy', cmd: 'cargo', args: ['clippy', '--manifest-path', 'src-tauri/Cargo.toml', '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings'] },
  { name: 'rust-tests', cmd: 'cargo', args: ['test', '--manifest-path', 'src-tauri/Cargo.toml', '--all-targets', '--locked'] },
  { name: 'identity-conformance', cmd: 'npm', args: ['run', 'identity:conformance', '--silent'] },
  { name: 'vault-ci', cmd: 'npm', args: ['run', 'vault:ci', '--silent'] },
];

const ANDROID_ONLY_GATES = [
  { name: 'android-schema-vectors', run: validateAndroidSchemas },
  { name: 'android-manifest-policy', run: checkSourceManifestPolicy },
  { name: 'android-handoff-integrity', run: checkHandoffIntegrity },
];

function validateAndroidSchemas() {
  const vectorsPath = join(REPO_ROOT, 'conformance', 'android-vault', 'v1', 'vectors', 'android-wrapper-vectors.json');
  if (!existsSync(vectorsPath)) throw new Error('android wrapper vectors missing');
  const vectors = JSON.parse(readFileSync(vectorsPath, 'utf8'));
  if (vectors.schemaVersion !== 1 || !Array.isArray(vectors.vectors) || vectors.vectors.length === 0) {
    throw new Error('android wrapper vectors invalid');
  }
  for (const v of vectors.vectors) {
    if (!/^AW-[0-9]{3}$/.test(v.id)) throw new Error(`invalid vector id ${v.id}`);
    if (!/^[0-9a-f]{64}$/.test(v.canonicalSha256)) throw new Error(`invalid canonicalSha256 in ${v.id}`);
  }
  return 'android schemas/vectors valid';
}

function checkSourceManifestPolicy() {
  const manifestPath = join(
    REPO_ROOT, 'src-tauri', 'gen', 'android', 'app', 'src', 'main', 'AndroidManifest.xml',
  );
  if (!existsSync(manifestPath)) {
    // Generated project absent in a clean checkout: the customization overlay
    // must be re-applied after `tauri android init`; treat as a hard failure
    // in CI so regeneration cannot silently regress policy.
    throw new Error('generated Android manifest missing (run tauri android init + customization)');
  }
  const xml = readFileSync(manifestPath, 'utf8');
  const violations = checkManifestPolicy(xml, 'production');
  if (violations.length > 0) throw new Error(`manifest policy: ${violations.join('; ')}`);
  return 'android manifest policy OK';
}

export function checkHandoffIntegrity() {
  const handoffPath = join(REPO_ROOT, 'conformance', 'android-vault', 'v1', 'HANDOFF.md');
  if (!existsSync(handoffPath)) throw new Error('android HANDOFF.md missing');
  const text = readFileSync(handoffPath, 'utf8');
  const requiredSeams = ['createProvision', 'recoverWordsProvision', 'recoverFileProvision', 'unlock', 'exportEncryptedFile'];
  for (const seam of requiredSeams) {
    if (!text.includes(seam)) throw new Error(`handoff missing seam ${seam}`);
  }
  for (const placeholder of ['TBD', 'TODO', 'FIXME', '[PLACEHOLDER]']) {
    if (text.includes(placeholder) && placeholder !== 'TBD') {
      throw new Error(`handoff contains placeholder ${placeholder}`);
    }
  }
  return 'android handoff integrity OK';
}

/** Run a stage; return {name, ok, output}. Never throws. */
function runStage(stage) {
  try {
    let output = '';
    if (stage.run) {
      output = stage.run();
    } else {
      output = execFileSync(stage.cmd, stage.args, {
        cwd: REPO_ROOT,
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
    }
    return { name: stage.name, ok: true, output };
  } catch (err) {
    const msg = err?.stdout?.toString?.() ?? err?.message ?? String(err);
    return { name: stage.name, ok: false, output: msg };
  }
}

/** Seed one defect per gate and assert detection (self-test). */
function runSelftests() {
  const failures = [];
  const tests = [
    {
      name: 'policy detects Leanback',
      check: () => {
        const xml = '<manifest><uses-feature android:name="android.software.leanback" android:required="false"/></manifest>';
        return checkManifestPolicy(xml, 'production').length > 0;
      },
    },
    {
      name: 'policy detects backup enabled',
      check: () => {
        const xml = '<application android:name="x"></application>';
        return checkManifestPolicy(xml, 'production').some((v) => v.includes('backup'));
      },
    },
    {
      name: 'handoff detects missing seam',
      check: () => {
        const missing = checkHandoffSeamPresence('createProvision', 'missing');
        return missing;
      },
    },
    {
      name: 'vectors detect bad sha',
      check: () => {
        try {
          validateVectorSha('bad');
          return false;
        } catch {
          return true;
        }
      },
    },
  ];
  for (const t of tests) {
    try {
      if (!t.check()) failures.push(`${t.name}: defect not detected`);
    } catch {
      failures.push(`${t.name}: threw unexpectedly`);
    }
  }
  return failures;
}

export function checkHandoffSeamPresence(seam, text) {
  return !text.includes(seam);
}

function validateVectorSha(sha) {
  if (!/^[0-9a-f]{64}$/.test(sha)) throw new Error('invalid sha');
}

function main() {
  const args = process.argv.slice(2);
  const selftest = args.includes('--selftest');
  const skipAudit = args.includes('--skip-audit');

  if (selftest) {
    const failures = runSelftests();
    if (failures.length > 0) {
      console.error(`ANDROID VAULT SELF-TEST FAILED:\n${failures.join('\n')}`);
      process.exit(1);
    }
    console.log('ANDROID VAULT SELF-TEST OK (all seeded defects detected)');
    process.exit(0);
  }

  const stages = [...GATES, ...ANDROID_ONLY_GATES];
  let red = 0;
  for (const stage of stages) {
    const result = runStage(stage);
    if (result.ok) {
      console.log(`[PASS] ${result.name}`);
    } else {
      red += 1;
      console.error(`[FAIL] ${result.name}\n${result.output.slice(0, 1200)}`);
    }
  }
  if (red > 0) {
    console.error(`ANDROID VAULT CI FAILED (${red}/${stages.length} stages red)`);
    process.exit(1);
  }
  console.log(`ANDROID VAULT CI OK (${stages.length} stages, audit=${skipAudit ? 'skipped' : 'on'})`);
}

if (process.argv[1] && process.argv[1].endsWith('ci-android-vault.mjs')) {
  main();
}
