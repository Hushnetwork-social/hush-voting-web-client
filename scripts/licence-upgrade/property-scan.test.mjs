// FEAT-017 property-scan regression: the page-owned polling property must
// still fail a 3-second poll in the licence page/UI (positive) without
// failing the EPIC-001 identity create/recovery authority poll that runs in
// the same tree (negative). Run with:
//   node --test scripts/licence-upgrade/property-scan.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { findForbiddenProperties } from './property-scan.mjs';

const IDENTITY_BRIDGE = '/repo/src/lib/auth/web/child-bridge.ts';
const LICENCE_UI = '/repo/src/app/auth/licence/licence-workspace.tsx';

test('the identity bridge 3-second reconciliation poll is not a page-owned licence loop', () => {
  const source = 'this.confirmationPoll = setInterval(() => { void this.reconcileWaiting(); }, 3000);\n';
  assert.deepEqual(findForbiddenProperties(IDENTITY_BRIDGE, source), []);
});

test('a 3-second poll in the licence UI remains a finding', () => {
  const source = 'setInterval(() => { void refreshLicence(); }, 3000);\n';
  assert.equal(findForbiddenProperties(LICENCE_UI, source).length, 1);
});
