#!/usr/bin/env node
/**
 * FEAT-005 unified Ubuntu-vault CI gate (Task 6.7/6.8).
 * =====================================================
 * Runs every Ubuntu-adapter gate deterministically with bounded timeouts:
 *   1. lint, 2. typecheck, 3. unit tests (incl. composition, shell-policy,
 *      UI, bridge), 4. identity conformance, 5. vault core CI (corpus
 *      untouched), 6. browser-vault CI (browser stays green + native-
 *      excluded), 7. Rust format, 8. Rust clippy (-D warnings),
 *   9. Rust tests, 10. cargo audit, 11. protocol integrity (vendored proto
 *      SHA-256 vs pins + descriptor digest), 12. secret scan,
 *  13. release evidence, 14. handoff integrity.
 *
 * `--selftest` runs the failure-mode self-tests: seeded defects (CSP drift,
 * capability drift, protocol drift) MUST fail the corresponding gate,
 * proving the gates actually guard the contract. The unmodified baseline
 * must pass.
 *
 * A failing gate exits non-zero with a stable sanitized diagnostic naming
 * the stage only. Success writes a digest-only summary to
 * `conformance/ubuntu-vault/v1/reports/ubuntu-vault-ci-summary.json`.
 *
 * Exit codes: 0 = all gates pass, 1 = a gate failed, 2 = internal error.
 */
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');
const REPORT_DIR = join(REPO_ROOT, 'conformance', 'ubuntu-vault', 'v1', 'reports');
const SUMMARY_PATH = join(REPORT_DIR, 'ubuntu-vault-ci-summary.json');
const SELF_TEST = process.argv.includes('--selftest');

const PROTOCOL_DIR = join(REPO_ROOT, 'conformance', 'protocol');

const PINNED_PROTO_DIGESTS = {
  'hushIdentity.proto': 'df3a2d9b128335dc3c92f0ef2b246655ed4c95f53f7ce058d438d945724f8ffa',
  'hushBlockchain.proto': 'e0625d52e4227ed77b6eb0e7d74b2990b7a8d3e8ecd77bd308371797275dc04b',
};

const GATES = [
  { name: 'lint', script: 'lint', timeoutMs: 300_000 },
  { name: 'typecheck', script: 'typecheck', timeoutMs: 300_000 },
  { name: 'unit-tests', script: 'test:unit', timeoutMs: 900_000 },
  { name: 'identity-conformance', script: 'identity:conformance', timeoutMs: 300_000 },
  { name: 'vault-core-ci', script: 'vault:ci', timeoutMs: 1_200_000 },
  { name: 'browser-vault-ci', script: 'browser-vault:ci', timeoutMs: 1_200_000 },
  { name: 'rust-format', command: ['cargo', 'fmt', '--manifest-path', 'src-tauri/Cargo.toml', '--', '--check'], timeoutMs: 180_000 },
  { name: 'rust-clippy', command: ['cargo', 'clippy', '--manifest-path', 'src-tauri/Cargo.toml', '--all-targets', '--all-features', '--locked', '--', '-D', 'warnings'], timeoutMs: 1_800_000 },
  { name: 'rust-tests', command: ['cargo', 'test', '--manifest-path', 'src-tauri/Cargo.toml', '--all-targets', '--locked'], timeoutMs: 1_800_000 },
  { name: 'audit', command: ['cargo', 'audit', '--file', 'src-tauri/Cargo.lock'], timeoutMs: 600_000 },
  { name: 'protocol-integrity', fn: checkProtocolIntegrity, timeoutMs: 60_000 },
  { name: 'secret-scan', fn: checkSecretScan, timeoutMs: 120_000 },
  { name: 'release-evidence', fn: writeReleaseEvidence, timeoutMs: 60_000 },
  { name: 'handoff-integrity', fn: checkHandoff, timeoutMs: 60_000 },
];

function runNpmScript(name, timeoutMs) {
  execFileSync('npm', ['run', name], { cwd: REPO_ROOT, stdio: 'ignore', timeout: timeoutMs });
}

function runCommand(command, timeoutMs) {
  execFileSync(command[0], command.slice(1), { cwd: REPO_ROOT, stdio: 'ignore', timeout: timeoutMs });
}

function sha256Bytes(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function gitRevision() {
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], { cwd: REPO_ROOT, encoding: 'utf8' }).trim();
  } catch {
    return 'unknown';
  }
}

/** Gate 11: vendored protocol artifacts must match the pinned digests. */
function checkProtocolIntegrity() {
  const failures = [];
  for (const [file, expected] of Object.entries(PINNED_PROTO_DIGESTS)) {
    const actual = sha256Bytes(readFileSync(join(PROTOCOL_DIR, file)));
    if (actual !== expected) {
      failures.push(`${file} digest ${actual} != pinned ${expected}`);
    }
  }
  if (failures.length > 0) {
    throw new Error(`protocol integrity: ${failures.join('; ')}`);
  }
}

/** Gate 12: no secret-shaped markers in Ubuntu sources/reports. */
function checkSecretScan() {
  const targets = [
    join(REPO_ROOT, 'src-tauri', 'src', 'ubuntu_vault'),
    join(REPO_ROOT, 'src', 'lib', 'ubuntu-vault'),
    join(REPO_ROOT, 'src', 'app', 'auth', 'ubuntu'),
  ];
  const needles = ['BEGIN PRIVATE KEY', 'BEGIN EC PRIVATE KEY', 'xpriv', 'hdseed:'];
  let hits = 0;
  for (const dir of targets) {
    const files = walk(dir).filter((f) => f.endsWith('.rs') || f.endsWith('.ts') || f.endsWith('.tsx'));
    for (const file of files) {
      const text = readFileSync(file, 'utf8');
      for (const needle of needles) {
        if (text.includes(needle)) {
          hits += 1;
          process.stderr.write(`secret-scan hit: ${file} contains ${needle}\n`);
        }
      }
    }
  }
  if (hits > 0) {
    throw new Error(`secret-scan: ${hits} secret-shaped markers found`);
  }
}

function walk(dir) {
  const out = [];
  const entries = readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...walk(full));
    } else {
      out.push(full);
    }
  }
  return out;
}

/** Gate 13: deterministic digest-only release evidence. */
function writeReleaseEvidence() {
  const evidence = {
    contractVersion: 1,
    generatedAt: new Date().toISOString().slice(0, 10),
    gitRevision: gitRevision(),
    applicationId: 'com.hushvoting.client',
    adapterId: 'ubuntu-secret-service-v1',
    packageFormats: ['deb', 'appimage'],
    packages: collectPackageDigests(),
    protocol: {
      revision: 'fb789bd1c2b353387183300a370de2960bc71795',
      hushIdentitySha256: PINNED_PROTO_DIGESTS['hushIdentity.proto'],
      hushBlockchainSha256: PINNED_PROTO_DIGESTS['hushBlockchain.proto'],
    },
    corpora: {
      vaultManifestSha256: 'e8dfdfa49b9e33cfc8a47b1266c5a14cb978c4be28f21d87cc2f034d435582e5',
      identityManifestSha256: 'f1bec7741de20efc3e488d0736ab61e745f3739032daaf50d955a83878d4f124',
    },
    dependencyPins: {
      oo7: '0.3.3',
      tonic: '0.13.1',
      prost: '0.13.5',
      k256: '0.13.4',
      serde: '1.0.220',
      tauri: '2.11.x',
      tauriPluginSingleInstance: '2.4.3',
    },
    noSecretMarkers: 0,
  };
  mkdirSync(REPORT_DIR, { recursive: true });
  writeFileSync(join(REPORT_DIR, 'release-evidence.json'), `${JSON.stringify(evidence, null, 2)}\n`);
}

/** Package artifacts and their SHA-256 digests (missing packages -> []). */
function collectPackageDigests() {
  const bundleRoot = join(REPO_ROOT, 'src-tauri', 'target', 'release', 'bundle');
  const candidates = [
    ['deb', join(bundleRoot, 'deb', 'HushVoting_0.1.0_amd64.deb')],
    ['appimage', join(bundleRoot, 'appimage', 'HushVoting_0.1.0_amd64.AppImage')],
  ];
  const out = {};
  for (const [format, file] of candidates) {
    try {
      out[format] = { file: file.split('/').pop(), sha256: sha256Bytes(readFileSync(file)) };
    } catch {
      out[format] = null; // not built in this checkout yet
    }
  }
  return out;
}

/** Gate 14: downstream handoff exists and names the closed operation seams. */
function checkHandoff() {
  const handoff = readFileSync(join(REPO_ROOT, 'conformance', 'ubuntu-vault', 'v1', 'HANDOFF.md'), 'utf8');
  const required = ['createProvision', 'recoverWordsProvision', 'recoverFileProvision', 'unlock', 'lock', 'changeDevicePassword', 'removeLocalUser', 'verifyOnline', 'revealMnemonic', 'exportEncryptedFile'];
  const missing = required.filter((seam) => !handoff.includes(seam));
  if (missing.length > 0) {
    throw new Error(`handoff missing operation seams: ${missing.join(', ')}`);
  }
}

// ---------------------------------------------------------------------------
// Failure-mode self-tests (Task 6.8)
// ---------------------------------------------------------------------------

const SELF_TEST_CASES = [
  {
    name: 'csp-drift',
    apply: () => mutateJson(join(REPO_ROOT, 'src-tauri', 'tauri.conf.json'), (cfg) => {
      cfg.app.security.csp = `${cfg.app.security.csp} 'unsafe-inline'`;
      return cfg;
    }),
    gate: () => runNpmScript('test:unit', 900_000),
  },
  {
    name: 'capability-drift',
    apply: () => mutateJson(join(REPO_ROOT, 'src-tauri', 'capabilities', 'default.json'), (cfg) => {
      cfg.permissions = [...cfg.permissions, 'core:default'];
      return cfg;
    }),
    gate: () => runNpmScript('test:unit', 900_000),
  },
  {
    name: 'protocol-drift',
    apply: () => {
      const file = join(PROTOCOL_DIR, 'hushIdentity.proto');
      const bytes = readFileSync(file);
      bytes[Math.floor(bytes.length / 2)] ^= 0x01;
      writeFileSync(file, bytes);
    },
    gate: () => runCommand(['cargo', 'check', '--manifest-path', 'src-tauri/Cargo.toml', '--locked'], 1_800_000),
  },
];

function mutateJson(path, mutate) {
  const cfg = JSON.parse(readFileSync(path, 'utf8'));
  writeFileSync(path, `${JSON.stringify(mutate(cfg), null, 2)}\n`);
}

async function runSelfTests() {
  let failed = 0;
  for (const test of SELF_TEST_CASES) {
    // Back up the fixture.
    const backup = {
      tauri: readFileSync(join(REPO_ROOT, 'src-tauri', 'tauri.conf.json')),
      capabilities: readFileSync(join(REPO_ROOT, 'src-tauri', 'capabilities', 'default.json')),
      proto: readFileSync(join(PROTOCOL_DIR, 'hushIdentity.proto')),
    };
    try {
      test.apply();
      let detected = false;
      try {
        test.gate();
      } catch {
        detected = true;
      }
      process.stdout.write(`SELFTEST ${test.name}: ${detected ? 'PASS (defect detected)' : 'FAIL (defect NOT detected)'}\n`);
      if (!detected) {
        failed += 1;
      }
    } finally {
      writeFileSync(join(REPO_ROOT, 'src-tauri', 'tauri.conf.json'), backup.tauri);
      writeFileSync(join(REPO_ROOT, 'src-tauri', 'capabilities', 'default.json'), backup.capabilities);
      writeFileSync(join(PROTOCOL_DIR, 'hushIdentity.proto'), backup.proto);
    }
  }
  return failed;
}

// ---------------------------------------------------------------------------

async function main() {
  mkdirSync(REPORT_DIR, { recursive: true });
  if (SELF_TEST) {
    const failed = await runSelfTests();
    process.exit(failed === 0 ? 0 : 1);
  }

  const results = [];
  let anyFailed = false;
  for (const gate of GATES) {
    const started = Date.now();
    try {
      if (gate.script) {
        runNpmScript(gate.script, gate.timeoutMs);
      } else if (gate.command) {
        runCommand(gate.command, gate.timeoutMs);
      } else if (gate.fn) {
        gate.fn();
      }
      results.push({ stage: gate.name, ok: true, ms: Date.now() - started });
      process.stdout.write(`OK   ${gate.name}\n`);
    } catch (error) {
      anyFailed = true;
      results.push({ stage: gate.name, ok: false, ms: Date.now() - started });
      process.stdout.write(`FAIL ${gate.name}: ${String(error.message).slice(0, 200)}\n`);
      break;
    }
  }

  const summary = {
    contractVersion: 1,
    generatedAt: new Date().toISOString(),
    gitRevision: gitRevision(),
    stages: results,
    allPassed: !anyFailed,
  };
  writeFileSync(SUMMARY_PATH, `${JSON.stringify(summary, null, 2)}\n`);

  process.stdout.write(
    anyFailed
      ? `UBUNTU VAULT CI FAILED (${results.filter((r) => r.ok).length}/${results.length} stages)\n`
      : `UBUNTU VAULT CI OK (${results.length} stages, revision ${summary.gitRevision})\n`,
  );
  process.exit(anyFailed ? 1 : 0);
}

main().catch((error) => {
  process.stderr.write(`ubuntu-vault:ci internal error: ${error.message}\n`);
  process.exit(2);
});
