// FEAT-016 property-scan regression: the entitlement-specific properties must
// still fail the real entitlement anti-patterns (positive) without failing the
// unrelated EPIC-001/FEAT-009 lifecycle code that uses browser connectivity and
// a 30-second clipboard timer for their own, non-entitlement purpose
// (negative). Run with: node --test scripts/entitlement-bootstrap/property-scan.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { findForbiddenProperties } from './property-scan.mjs';

const AUTH_BRIDGE = '/repo/src/lib/auth/web/child-bridge.ts';
const RECOVERY_UI = '/repo/src/app/auth/create/recovery.tsx';
const ENTITLEMENT_BRIDGE = '/repo/src/lib/auth/web/entitlement-bridge.ts';
const LICENCE_COORDINATOR = '/repo/src/lib/licensing/coordinator.ts';

test('navigator.onLine gating an authentication submission is not an entitlement finding', () => {
  const source = 'if (!navigator.onLine || document.visibilityState !== "visible") { return; }\n';
  assert.deepEqual(findForbiddenProperties(AUTH_BRIDGE, source), []);
});

test('navigator.onLine inside the entitlement authority remains a finding', () => {
  const source = 'if (!navigator.onLine) { return entitlementState; }\n';
  assert.equal(findForbiddenProperties(ENTITLEMENT_BRIDGE, source).length, 1);
});

test('a 30-second timer that clears recovery-word clipboard custody is not a delayed-confirmation finding', () => {
  const source = 'cleanupTimer.current = setTimeout(() => { void cleanupAfter(0); }, 30_000);\n';
  assert.deepEqual(findForbiddenProperties(RECOVERY_UI, source), []);
});

test('a 30-second timer inside the licence confirmation authority remains a finding', () => {
  const source = 'setTimeout(() => setConfirmationDelayed(true), 30_000);\n';
  assert.equal(findForbiddenProperties(LICENCE_COORDINATOR, source).length, 1);
});
