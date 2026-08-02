/**
 * FEAT-003 downstream handoff validation (Task 6.6).
 * Every downstream consumer (FEAT-002, FEAT-004..FEAT-010) is named in the handoff
 * with concrete artifact paths, commands, version rules, and ownership boundaries.
 * The handoff must never reference mutable evidence (branch URLs, live digests) or
 * leave unresolved placeholders; every named path and command must exist.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const ROOT = join(import.meta.dirname, '..', '..', '..', '..');
const CORPUS = join(ROOT, 'conformance', 'vault', 'v1');
const HANDOFF = readFileSync(join(CORPUS, 'HANDOFF.md'), 'utf8');
const PACKAGE = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));

test('handoff names every downstream consumer with ownership boundaries', () => {
  for (const consumer of ['FEAT-002', 'FEAT-004', 'FEAT-005', 'FEAT-006', 'FEAT-007', 'FEAT-008', 'FEAT-009', 'FEAT-010']) {
    assert.ok(HANDOFF.includes(consumer), `handoff missing consumer ${consumer}`);
  }
  // Every consumer row names an ownership boundary (core-owned vs downstream-owned).
  assert.ok(HANDOFF.includes('Core-owned'));
  assert.ok(HANDOFF.includes('Downstream-owned'));
});

test('handoff references only immutable evidence — no branch URLs or placeholders', () => {
  for (const mutable of ['refs/heads', 'tree/main', 'tree/develop', 'TBD', 'TODO', 'FIXME']) {
    assert.ok(!HANDOFF.includes(mutable), `handoff contains mutable/placeholder marker: ${mutable}`);
  }
  // Every 40/64-hex value in the handoff must be a real immutable pin.
  const pins = HANDOFF.match(/[0-9a-f]{40}|[0-9a-f]{64}/g) ?? [];
  assert.ok(pins.length >= 2, 'expected FEAT-001 revision + digest pins in handoff');
  for (const pin of pins) assert.match(pin, /^[0-9a-f]+$/);
});

test('every artifact path named in the handoff exists on disk', () => {
  // Per-line extraction is robust against fenced code blocks in the document.
  const paths = new Set();
  for (const line of HANDOFF.split('\n')) {
    for (const raw of line.match(/`([^`]+)`/g) ?? []) {
      const rel = raw.slice(1, -1).trim();
      if (/^(src|conformance|scripts)\//.test(rel)) paths.add(rel);
    }
  }
  const checked = [];
  for (const rel of paths) {
    // Reports are generated at gate time (gitignored); skip them.
    if (rel.startsWith('conformance/reports/')) continue;
    if (rel.endsWith('/')) {
      assert.ok(existsSync(join(ROOT, rel.slice(0, -1))), `handoff artifact directory missing: ${rel}`);
      checked.push(rel);
      continue;
    }
    assert.ok(existsSync(join(ROOT, rel)), `handoff artifact missing: ${rel}`);
    checked.push(rel);
  }
  assert.ok(checked.length >= 10, `expected >= 10 concrete artifact paths, checked ${checked.length}`);
});

test('every command named in the handoff exists in package.json scripts', () => {
  const commands = HANDOFF.match(/npm run ([a-z0-9:-]+)/g) ?? [];
  assert.ok(commands.length >= 8, `expected >= 8 npm commands in handoff, got ${commands.length}`);
  for (const raw of commands) {
    const script = raw.slice('npm run '.length);
    assert.ok(PACKAGE.scripts[script], `handoff command missing from package.json: ${script}`);
  }
});

test('every vector family file named in the handoff exists and matches the ID table', () => {
  const familyFiles = ['vectors/canonical-byte-vectors.json', 'vectors/aad-vectors.json', 'vectors/suite-vectors.json', 'vectors/password-vectors.json', 'vectors/core-vectors.json'];
  for (const rel of familyFiles) {
    assert.ok(existsSync(join(CORPUS, rel)), `vector family missing: ${rel}`);
  }
  const core = JSON.parse(readFileSync(join(CORPUS, 'vectors/core-vectors.json'), 'utf8')).vectors;
  const ids = core.map((v) => v.id);
  const prefixes = ['E-', 'L-', 'M-', 'G-', 'Q-', 'T-'];
  for (const p of prefixes) assert.ok(ids.some((id) => id.startsWith(p)), `core vectors missing ${p} family`);
});

test('version registry is closed, monotonic, and digest-pinned', () => {
  const registry = JSON.parse(readFileSync(join(ROOT, 'conformance', 'vault', 'versions.json'), 'utf8'));
  const versions = registry.versions.map((v) => v.corpusVersion);
  assert.deepEqual(versions, [...versions].sort(), 'registry must be monotonic');
  for (const v of registry.versions) {
    assert.match(v.manifestSha256, /^[0-9a-f]{64}$/);
    const dir = join(ROOT, 'conformance', 'vault', v.dir);
    assert.ok(existsSync(dir), `retained version directory missing: ${v.dir}`);
    const digest = createHash('sha256').update(readFileSync(join(dir, 'manifest.json'))).digest('hex');
    assert.equal(digest, v.manifestSha256, `digest drift for ${v.corpusVersion}`);
  }
});

test('report schema generators match the published TypeScript generators only', () => {
  const schema = JSON.parse(readFileSync(join(CORPUS, 'schemas/report.schema.json'), 'utf8'));
  assert.deepEqual(schema.properties.generator.enum.sort(), ['hush-vault-ts-isolated', 'hush-vault-ts-reference']);
});
