// FEAT-008 Phase 7 Task 7.1; seeded catalogue defects must fail the mapping gate.
import { mkdtempSync, cpSync, readFileSync, writeFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import { strict as assert } from 'node:assert';
import { test } from 'node:test';

const client = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const source = join(client, '../hush-server-node/Node/HushNode.IntegrationTests/HushVoting/Features/recovery-words');
const manifest = join(client, '../hush-voting-memory-bank/Features/04_COMPLETED/FEAT-008-recovery-words-identity-restore/acceptance-coverage-manifest.json');
const validator = join(client, 'scripts/recovery-words/validate-coverage-manifest.mjs');

for (const seed of ['valid', 'missing scenario', 'duplicate scenario', 'wrong AC association', 'missing criterion']) {
  test(`recovery .NET coverage: ${seed}`, () => {
    const temporary = mkdtempSync(join(tmpdir(), 'hv-recovery-coverage-'));
    try {
      const features = join(temporary, 'features'), input = join(temporary, 'manifest.json');
      cpSync(source, features, { recursive: true });
      cpSync(manifest, input);
      const first = join(features, readdirSync(features).find(name => name.endsWith('.feature')));
      let text = readFileSync(first, 'utf8');
      const block = text.match(/^  @FEAT-008 @AC-008-\d{3}[^\n]*\n  Scenario:[\s\S]*?(?=\n  @FEAT-008|$)/m)?.[0];
      assert.ok(block, 'controlled catalogue has a tagged scenario');
      if (seed === 'missing scenario') text = text.replace(block, '');
      if (seed === 'duplicate scenario') text += `\n${block}\n`;
      if (seed === 'wrong AC association') {
        const tag = block.match(/@AC-008-\d{3}/)[0];
        const replacement = tag === '@AC-008-001' ? '@AC-008-002' : '@AC-008-001';
        text = text.replace(block, block.replace(tag, replacement));
      }
      if (seed === 'missing criterion') {
        const data = JSON.parse(readFileSync(input, 'utf8'));
        delete data.criteria['AC-008-001'];
        writeFileSync(input, JSON.stringify(data));
      }
      writeFileSync(first, text);
      const result = spawnSync(process.execPath, [validator, input], {
        env: { ...process.env, FEAT008_COVERAGE_FEATURES: features }, encoding: 'utf8', timeout: 10_000,
      });
      assert.equal(result.error, undefined);
      assert.equal(result.status, seed === 'valid' ? 0 : 1, result.stdout + result.stderr);
      if (seed === 'valid') assert.match(result.stdout, /85\/85 criteria, 85 \.NET scenarios/);
    } finally { rmSync(temporary, { recursive: true, force: true }); }
  });
}
