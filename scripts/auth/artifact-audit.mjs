#!/usr/bin/env node
/**
 * FEAT-002 auth artifact audit.
 *
 * Scans generated artifacts (browser storage, history, build output, test
 * output, screenshots, traces, logs, telemetry shapes) for prohibited secret
 * patterns, identifiers, raw errors, test bypasses, and production inspection
 * hooks. NEVER prints matched values — only location + category.
 *
 * Scope: first-party generated output. Vendored framework code
 * (node_modules, standalone/node_modules) is excluded because its prose and
 * API strings are not app artifacts.
 *
 * Usage:
 *   node scripts/auth/artifact-audit.mjs [--dir .next-web] [--dir .next-static] [--dir out]
 * Exit code 0 = zero findings; 1 = findings; 2 = usage error.
 */

import { existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';

const PROHIBITED_PATTERNS = [
  // A real password VALUE (excluding the literal `type="password"` attribute
  // and self-describing UI label copy such as "Show device password", which
  // the real FEAT-007/008/009 onboarding flows legitimately render).
  {
    category: 'password',
    pattern: /(?:password|passphrase|devicePassword)\s*[:=]\s*["']([^"']{8,})["']/i,
  },
  // A mnemonic as a quoted string literal (12+ English words in quotes).
  {
    category: 'mnemonic',
    pattern: /["'](?:[a-z]{3,12}\s){11,23}[a-z]{3,12}["']/i,
  },
  { category: 'private-key', pattern: /BEGIN (?:RSA |EC |)?PRIVATE KEY/i },
  { category: 'raw-error', pattern: /at\s+[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*:\d+:\d+/ },
  { category: 'election-id', pattern: /\bELEC-[A-Z0-9]+\b/i },
  { category: 'test-bypass', pattern: /createDevelopmentComposition|completeAllPendingOperations|Demo User|test-op-/i },
  { category: 'inspection-hook', pattern: /xstate\.inspect|from\s+['"]@xstate\/inspect|devtools:\s*true/i },
];

/** Directories that are framework/vendored output, not first-party artifacts. */
function isVendored(path) {
  return path.includes('node_modules') || path.includes('standalone');
}

function walk(dir, acc) {
  if (!existsSync(dir)) {
    return acc;
  }
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    let isDir = false;
    try {
      isDir = statSync(full).isDirectory();
    } catch {
      continue;
    }
    if (isDir) {
      walk(full, acc);
    } else if (/\.(js|mjs|cjs|json|html|txt)$/i.test(entry)) {
      // .map files embed full source text (doc comments, allowlist literals)
      // and are build metadata, not shipped artifacts — excluded to avoid
      // false positives; executable chunks are the meaningful output.
      acc.push(full);
    }
  }
  return acc;
}

function scanFile(file, findings) {
  let content;
  try {
    content = readFileSync(file, 'utf8');
  } catch {
    return;
  }
  for (const { category, pattern } of PROHIBITED_PATTERNS) {
    const matches = content.matchAll(new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : pattern.flags + 'g'));
    let flagged = false;
    for (const match of matches) {
      const value = match[1] ?? '';
      if (category === 'password' && /password|passphrase|device|show|confirm|enter|your|the|vault|label/i.test(value)) {
        // Self-describing UI copy, not a credential value.
        continue;
      }
      flagged = true;
      break;
    }
    if (flagged) {
      // Report location + category only; never echo the matched value.
      findings.push({ file, category });
    }
  }
}

function main() {
  const args = process.argv.slice(2);
  const dirs = [];
  for (let i = 0; i < args.length; i += 1) {
    if (args[i] === '--dir' && args[i + 1]) {
      dirs.push(resolve(args[i + 1]));
      i += 1;
    }
  }
  const targets = dirs.length > 0 ? dirs : ['.next-web', '.next-static', 'out'];
  const findings = [];
  for (const dir of targets) {
    for (const file of walk(dir, [])) {
      if (isVendored(file)) {
        continue;
      }
      scanFile(file, findings);
    }
  }
  if (findings.length > 0) {
    console.error('AUTH ARTIFACT AUDIT FAILED');
    for (const { file, category } of findings) {
      console.error(`  [${category}] ${file}`);
    }
    process.exit(1);
  }
  console.log('AUTH ARTIFACT AUDIT PASSED (zero prohibited findings)');
  process.exit(0);
}

// Self-test: seeded leak fixtures must be detected without echoing values.
function selfTest() {
  const tmp = join(tmpdir(), 'auth-audit-seed');
  mkdirSync(tmp, { recursive: true });
  const mnemonicWords = [
    'abandon', 'ability', 'able', 'about', 'above', 'absent', 'absorb', 'abstract', 'absurd', 'abuse', 'access', 'accident',
    'account', 'accuse', 'achieve', 'acid', 'acoustic', 'acquire', 'across', 'act', 'action', 'actor', 'actress', 'actual',
  ];
  writeFileSync(join(tmp, 'leak.js'), `const password = "hunter2-very-secret-value";\nconst m = "${mnemonicWords.join(' ')}";\n`);
  writeFileSync(join(tmp, 'type-password.js'), 'const inputType = "password";\n<input type="password" />\n');
  writeFileSync(join(tmp, 'clean.js'), 'export const ok = "type";\n');
  const findings = [];
  scanFile(join(tmp, 'leak.js'), findings);
  scanFile(join(tmp, 'type-password.js'), findings);
  scanFile(join(tmp, 'clean.js'), findings);
  const leakCategories = findings.filter((f) => f.file.endsWith('leak.js')).map((f) => f.category).sort();
  const typeFindings = findings.filter((f) => f.file.endsWith('type-password.js')).length;
  const cleanFindings = findings.filter((f) => f.file.endsWith('clean.js')).length;
  rmSync(tmp, { recursive: true, force: true });
  return { ok: leakCategories.includes('password') && typeFindings === 0 && cleanFindings === 0, leakCategories };
}

if (process.argv.includes('--selftest')) {
  const result = selfTest();
  if (!result.ok) {
    console.error('SELFTEST FAILED:', JSON.stringify(result));
    process.exit(1);
  }
  console.log('SELFTEST PASSED');
  process.exit(0);
}

main();
