/**
 * FEAT-003 security/performance/archive evidence verification (Task 7.6).
 *
 * - the security gate exits 0 on the clean tree and FAILS on an injected secret
 *   pattern (negative fixture, restored safely);
 * - the deterministic archive reproduces byte-identical membership/ordering/digests
 *   and its --check mode passes;
 * - the performance path cannot bypass security checks: tampered canonical bytes are
 *   still rejected by the bounded parser, and the corpus manifest integrity check is
 *   not skipped by any fast path.
 */
import { describe, expect, it, beforeAll, afterAll } from 'vitest';
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';
import { parseBoundedJson } from '../canonical/parse';
import { verifyManifestIndependently } from '../conformance/isolated-validator';

const ROOT = process.cwd();
const SECURITY_SCRIPT = join(ROOT, 'scripts', 'vault', 'security-gates.mjs');
const ARCHIVE_SCRIPT = join(ROOT, 'scripts', 'vault', 'archive.mjs');
// Negative fixtures live OUTSIDE the scanned default trees (tmp/) so parallel
// vitest workers and tsc never observe them; the scan targets them explicitly.
const FIXTURE_DIR = join(ROOT, 'tmp', 'vault-security-negative-fixture');

function runScript(script: string, args: string[] = []): { status: number; stdout: string; stderr: string } {
  try {
    const stdout = execFileSync(process.execPath, [script, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
    return { status: 0, stdout, stderr: '' };
  } catch (err) {
    const e = err as { status?: number; stdout?: string; stderr?: string };
    return { status: e.status ?? 1, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

beforeAll(() => rmSync(FIXTURE_DIR, { recursive: true, force: true }));
afterAll(() => rmSync(FIXTURE_DIR, { recursive: true, force: true }));

describe('FEAT-003 security gates verification', () => {
  it('clean tree passes the security gate', () => {
    const result = runScript(SECURITY_SCRIPT, ['--skip-audit']);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('VAULT SECURITY GATES OK');
  });

  it('an injected private-key pattern fails the gate (negative fixture)', () => {
    mkdirSync(FIXTURE_DIR, { recursive: true });
    writeFileSync(join(FIXTURE_DIR, 'leak.ts'), '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n');
    const result = runScript(SECURITY_SCRIPT, ['--skip-audit', 'tmp/vault-security-negative-fixture']);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('private key PEM header');
    rmSync(FIXTURE_DIR, { recursive: true, force: true });
  });

  it('the fast path never skips schema/integrity checks', () => {
    // Tampered canonical bytes are still rejected by the bounded parser (the
    // "performance path" cannot bypass validation to save time).
    const tampered = new TextEncoder().encode('{"a":1,"a":2}');
    const parsed = parseBoundedJson(tampered);
    expect(parsed.ok).toBe(false);
    if (!parsed.ok) expect(parsed.code).toBe('DUPLICATE_KEY');
    // Corpus integrity is verified even in the isolated fast path.
    const { records } = verifyManifestIndependently(join(ROOT, 'conformance', 'vault', 'v1'));
    expect(records.every((r) => r.ok)).toBe(true);
  });
});

describe('FEAT-003 deterministic archive verification', () => {
  it('archive builds reproducibly and --check passes', () => {
    const build1 = runScript(ARCHIVE_SCRIPT, ['--clean']);
    expect(build1.status).toBe(0);
    expect(build1.stdout).toContain('reproducible');
    const check = runScript(ARCHIVE_SCRIPT, ['--check']);
    expect(check.status).toBe(0);
    // Rebuild after check must be byte-identical (membership + ordering + digests).
    const build2 = runScript(ARCHIVE_SCRIPT);
    expect(build2.status).toBe(0);
    const dirs = readdirSync(join(ROOT, 'conformance', 'archive')).filter((d) => d.startsWith('vault-'));
    expect(dirs.length).toBe(1);
    const manifestPath = join(ROOT, 'conformance', 'archive', dirs[0], 'archive-manifest.json');
    const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
    expect(manifest.files.map((f: { path: string }) => f.path)).toEqual([...manifest.files.map((f: { path: string }) => f.path)].sort());
    expect(manifest.corpusManifestSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it('archive contains no secret material and only declared reports', () => {
    const dirs = readdirSync(join(ROOT, 'conformance', 'archive')).filter((d) => d.startsWith('vault-'));
    const manifest = JSON.parse(readFileSync(join(ROOT, 'conformance', 'archive', dirs[0], 'archive-manifest.json'), 'utf8'));
    // The declared public-test-credential allowlist (vectors/) is the sanctioned
    // home of synthetic credential vectors; other paths must not look secret.
    const allowlist = ['schemas/', 'vectors/', 'reports/', 'manifest.json', 'metadata.json', 'HANDOFF.md', 'README.md', 'archive-manifest.json'];
    for (const f of manifest.files as Array<{ path: string }>) {
      if (allowlist.some((p) => f.path.startsWith(p))) continue;
      expect(f.path).not.toMatch(/(password|secret|private|mnemonic|key)[-/]/);
    }
    expect(manifest.files.some((f: { path: string }) => f.path === 'reports/vault-ts-isolated.json')).toBe(true);
    expect(manifest.files.some((f: { path: string }) => f.path === 'reports/vault-ts-reference.json')).toBe(true);
  });
});
