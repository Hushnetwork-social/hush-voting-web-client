#!/usr/bin/env node
/** Prove the Rust runner and deterministic corpus controls cannot enter production. */
import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = process.cwd();
const SOURCE_FORBIDDEN = [
  'DETERMINISTIC_TEST_PROVIDER',
  'vault-reference-runner',
  'tools/vault-reference-runner',
  'vault-core/canonical/suite-reference',
  'vault-core/conformance',
];
const ARTIFACT_FORBIDDEN = [
  'DETERMINISTIC_TEST_PROVIDER',
  'vault-reference-runner',
  'correct horse battery staple',
  'password-bytes',
  'public-test-channel',
];

export function scanText(text, tokens) {
  return tokens.filter((token) => text.includes(token));
}

function walk(dir, visit) {
  if (!existsSync(dir)) return;
  for (const entry of readdirSync(dir).sort()) {
    const path = join(dir, entry);
    const metadata = statSync(path);
    if (metadata.isDirectory()) {
      if (['node_modules', 'target', 'coverage', '.git'].includes(entry)) continue;
      walk(path, visit);
    } else {
      visit(path, metadata);
    }
  }
}

function productionSourceFindings() {
  const findings = [];
  walk(join(ROOT, 'src'), (path) => {
    const rel = relative(ROOT, path).split('\\').join('/');
    if (!/\.(ts|tsx|js|mjs)$/.test(path)) return;
    if (rel.endsWith('.test.ts') || rel.endsWith('.test.tsx')) return;
    if (rel === 'src/lib/vault-core/canonical/suite-reference.ts' || rel.startsWith('src/lib/vault-core/conformance/')) return;
    for (const token of scanText(readFileSync(path, 'utf8'), SOURCE_FORBIDDEN)) findings.push(`${rel}:${token}`);
  });
  const tauriFiles = [join(ROOT, 'src-tauri/Cargo.toml'), join(ROOT, 'src-tauri/Cargo.lock')];
  walk(join(ROOT, 'src-tauri/src'), (path) => tauriFiles.push(path));
  for (const path of tauriFiles) {
    if (!existsSync(path) || statSync(path).isDirectory()) continue;
    const rel = relative(ROOT, path).split('\\').join('/');
    for (const token of scanText(readFileSync(path, 'utf8'), SOURCE_FORBIDDEN)) findings.push(`${rel}:${token}`);
  }
  return findings;
}

function productionArtifactFindings() {
  const findings = [];
  for (const output of ['.next', '.next-web', '.next-static', '.next-tauri', 'out']) {
    walk(join(ROOT, output), (path, metadata) => {
      if (metadata.size > 20 * 1024 * 1024 || !/\.(js|mjs|cjs|json|html|rsc|txt)$/.test(path)) return;
      const rel = relative(ROOT, path).split('\\').join('/');
      const text = readFileSync(path, 'utf8');
      for (const token of scanText(text, ARTIFACT_FORBIDDEN)) findings.push(`${rel}:${token}`);
    });
  }
  return findings;
}

function boundaryFindings() {
  const findings = [];
  const gitignore = readFileSync(join(ROOT, '.gitignore'), 'utf8');
  if (!gitignore.includes('tools/**/target/')) findings.push('.gitignore:runner-target-not-ignored');
  const runnerManifest = join(ROOT, 'tools/vault-reference-runner/Cargo.toml');
  const runnerLock = join(ROOT, 'tools/vault-reference-runner/Cargo.lock');
  if (!existsSync(runnerManifest) || !existsSync(runnerLock)) findings.push('runner:missing-locked-manifest');
  const tauriManifest = readFileSync(join(ROOT, 'src-tauri/Cargo.toml'), 'utf8');
  if (tauriManifest.includes('vault-reference-runner')) findings.push('src-tauri/Cargo.toml:runner-dependency');
  return findings;
}

export function runProductionExclusion() {
  return [...productionSourceFindings(), ...productionArtifactFindings(), ...boundaryFindings()].sort();
}

function main() {
  const findings = runProductionExclusion();
  if (findings.length) throw new Error(`production boundary violations: ${findings.join(', ')}`);
  process.stdout.write('VAULT PRODUCTION EXCLUSION PASS (source, Tauri graph, web/static artifacts, locked runner boundary)\n');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    main();
  } catch (error) {
    process.stderr.write(`VAULT PRODUCTION EXCLUSION FAILED: ${error.message}\n`);
    process.exitCode = 1;
  }
}
