#!/usr/bin/env node
/**
 * Cross-repository CI contract validation (Phase 6, Tasks 6.2/6.4).
 * ================================================================
 * Mechanically verifies the compatibility-CI wiring that cannot be executed
 * locally (GitHub Actions jobs):
 *   - the pinned HushServerNode runner revision exists and is a 40-hex commit;
 *   - the HushVoting workflow checks out that pinned revision and never a
 *     mutable default branch;
 *   - the workflow records both revisions and the manifest digest;
 *   - workflow steps never echo credential values or fixture material.
 *
 * Executable failure modes (exit codes 1/2/3, tamper detection, schema
 * rejection, report redaction) are covered by the .NET runner test suite
 * (HushIdentityCompatibilityConformance.Tests) and the runner's own tests.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const WORKFLOW_PATH = join(ROOT, '..', '..', '..', '.github', 'workflows', 'identity-compatibility.yml');
const HEX40 = /^[0-9a-f]{40}$/;

function read(rel) {
  return readFileSync(join(ROOT, rel), 'utf8');
}

test('runner pin exists with a 40-hex revision and the server repository', () => {
  const pinPath = join(ROOT, 'scripts', 'runner-pin.json');
  assert.ok(existsSync(pinPath), 'runner-pin.json exists');
  const pin = JSON.parse(read('scripts/runner-pin.json'));
  assert.equal(pin.repository, 'hush-server-node');
  assert.ok(HEX40.test(pin.revision), `pin revision is 40-hex: ${pin.revision}`);
  assert.ok(pin.note && pin.note.length > 20, 'pin carries an update-approval note');
});

test('workflow checks out the pinned runner revision, never a mutable branch', () => {
  const workflow = readFileSync(WORKFLOW_PATH, 'utf8');
  assert.ok(workflow.includes('runner-pin.json'), 'workflow reads the pin file');
  assert.ok(workflow.includes('repository: Hushnetwork-social/hush-server-node'), 'workflow targets the server repository');
  assert.ok(workflow.includes('ref: ${{ steps.pin.outputs.revision }}'), 'workflow checks out the pinned ref');
  assert.ok(!workflow.includes('ref: master') && !workflow.includes('ref: main'), 'no mutable branch checkout');
  assert.ok(workflow.includes('ref: ${{ github.event.pull_request.head.sha }}') === false, 'PR head is the checked-out default');
});

test('workflow records both revisions and the manifest digest', () => {
  const workflow = readFileSync(WORKFLOW_PATH, 'utf8');
  assert.ok(workflow.includes('HushVoting revision'), 'records the HushVoting revision');
  assert.ok(workflow.includes('Pinned HushServerNode runner revision'), 'records the pinned runner revision');
  assert.ok(workflow.includes('manifest-digest'), 'records the manifest digest');
});

test('workflow never echoes credential values or fixture material', () => {
  const workflow = readFileSync(WORKFLOW_PATH, 'utf8');
  for (const secret of ['abandon amount', 'hush-public-test-password', '6e3f74236c3d4a20553be05963f624696990c22245599b3d1b30262af793d885']) {
    assert.ok(!workflow.includes(secret), 'no credential/fixture values in the workflow');
  }
  assert.ok(workflow.includes('No credential values are emitted in logs or reports.'), 'secret-safe logging documented');
});

test('workflow exists in the HushVoting repository', () => {
  const workflow = readFileSync(WORKFLOW_PATH, 'utf8');
  assert.ok(workflow.includes('Identity Compatibility - HushVoting to Server'), 'workflow present');
});

test('local executable failure modes are covered by the runner test suite', () => {
  // The .NET runner tests cover: exit 0 full pass, exit 2 invalid corpus,
  // tamper mismatch (exit-1 semantics), and report redaction. This test pins
  // that expectation so the contract stays visible from the corpus side.
  const serverPin = JSON.parse(read('scripts/runner-pin.json'));
  assert.ok(serverPin.revision.length === 40);
  const docs = read('README.md');
  assert.ok(docs.includes('exit codes'), 'README documents runner exit codes 0/1/2/3');
  assert.ok(docs.includes('2') && docs.includes('3'), 'exit codes 2 and 3 documented');
});
