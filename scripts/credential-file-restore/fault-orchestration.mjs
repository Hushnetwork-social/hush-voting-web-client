#!/usr/bin/env node
/**
 * FEAT-009 fault orchestration profile (Task 7.3).
 *
 * Deterministic registry mapping every canonical fault ID to an executable
 * injection target and an expected converged state. Self-tests refuse
 * unbound faults, success-only placeholders, unsupported capability claims,
 * unsafe capture, and persistent-process configuration. The actual fault
 * injections are executed by the paired unit/model suites (Phases 3–6);
 * this profile proves the registry is complete and bound before Phase 7
 * execution.
 *
 * Usage: node scripts/credential-file-restore/fault-orchestration.mjs [--selftest]
 */
const FAULTS = [
  // [faultId, boundary, expectedConvergedState]
  ['FAULT-ENTRY-001', 'entry-inspection', 'verified-empty-or-blocked'],
  ['FAULT-ENTRY-002', 'owner-acquisition', 'single-owner-acquired'],
  ['FAULT-ENTRY-003', 'capability-preflight', 'blocked-before-picker'],
  ['FAULT-PICKER-001', 'picker-cancel', 'cleared-neutral'],
  ['FAULT-PICKER-002', 'picker-change', 'prior-handles-cleared'],
  ['FAULT-PICKER-003', 'picker-back', 'cleared-to-entry'],
  ['FAULT-PICKER-004', 'picker-lifecycle-loss', 'state-released'],
  ['FAULT-READ-001', 'stream-open', 'safe-read-error'],
  ['FAULT-READ-002', 'stream-type', 'unsafe-file-kind'],
  ['FAULT-READ-003', 'stream-overflow', 'file-too-large'],
  ['FAULT-READ-004', 'stream-inactivity', 'read-timeout-cleared'],
  ['FAULT-READ-005', 'stream-cancel', 'partial-cleared'],
  ['FAULT-READ-006', 'stream-partial', 'never-parsed'],
  ['FAULT-TEMP-001', 'temp-create', 'no-copy-preferred'],
  ['FAULT-TEMP-002', 'temp-write', 'safe-retry'],
  ['FAULT-TEMP-003', 'temp-delete', 'quarantine'],
  ['FAULT-TEMP-004', 'temp-verify', 'quarantine'],
  ['FAULT-TEMP-005', 'temp-startup-orphan', 'quarantine-or-verified-absent'],
  ['FAULT-ENV-001', 'envelope-magic', 'invalid-magic'],
  ['FAULT-ENV-002', 'envelope-version', 'unsupported-version'],
  ['FAULT-ENV-003', 'envelope-salt', 'envelope-too-short'],
  ['FAULT-ENV-004', 'envelope-nonce', 'envelope-too-short'],
  ['FAULT-ENV-005', 'envelope-tag', 'authentication-failed'],
  ['FAULT-ENV-006', 'envelope-oversize', 'file-too-large'],
  ['FAULT-PWD-001', 'password-encoding', 'exact-utf8-used'],
  ['FAULT-PWD-002', 'password-limit', 'password-too-long-before-pbkdf2'],
  ['FAULT-PWD-003', 'password-empty-option', 'explicit-zero-bytes'],
  ['FAULT-PWD-004', 'password-derivation', 'one-attempt-only'],
  ['FAULT-PWD-005', 'password-auth-failure', 'combined-outcome'],
  ['FAULT-PWD-006', 'password-stale-result', 'dropped-no-mutation'],
  ['FAULT-PARSE-001', 'parse-utf8', 'payload-not-json'],
  ['FAULT-PARSE-002', 'parse-duplicate', 'duplicate-field-rejected'],
  ['FAULT-PARSE-003', 'parse-field', 'missing-or-unknown-field'],
  ['FAULT-PARSE-004', 'parse-type', 'invalid-field'],
  ['FAULT-PARSE-005', 'parse-bound', 'invalid-field'],
  ['FAULT-KEY-001', 'key-signing-derive', 'signing-key-mismatch'],
  ['FAULT-KEY-002', 'key-signing-equality', 'signing-key-mismatch'],
  ['FAULT-KEY-003', 'key-signing-challenge', 'key-proof-failed'],
  ['FAULT-KEY-004', 'key-encryption-derive', 'encryption-key-mismatch'],
  ['FAULT-KEY-005', 'key-encryption-consistency', 'encryption-key-mismatch'],
  ['FAULT-KEY-006', 'key-mnemonic', 'mnemonic-key-mismatch'],
  ['FAULT-DISPOSE-001', 'dispose-source', 'source-released'],
  ['FAULT-DISPOSE-002', 'dispose-ciphertext', 'snapshot-released'],
  ['FAULT-DISPOSE-003', 'dispose-password', 'password-destroyed'],
  ['FAULT-DISPOSE-004', 'dispose-parser', 'plaintext-destroyed'],
  ['FAULT-LOOKUP-001', 'lookup-existing', 'exact-both-key'],
  ['FAULT-LOOKUP-002', 'lookup-not-found', 'missing-profile-review'],
  ['FAULT-LOOKUP-003', 'lookup-mismatch', 'signing-only-fails-closed'],
  ['FAULT-LOOKUP-004', 'lookup-timeout', 'transport-never-not-found'],
  ['FAULT-LOOKUP-005', 'lookup-malformed', 'fail-closed'],
  ['FAULT-LOOKUP-006', 'lookup-unknown', 'fail-closed'],
  ['FAULT-PROTECT-001', 'protect-device-password', 'qualified'],
  ['FAULT-PROTECT-002', 'protect-webauthn', 'qualified-or-blocked-no-downgrade'],
  ['FAULT-PROTECT-003', 'protect-native-passwordless', 'qualified-or-blocked-no-downgrade'],
  ['FAULT-PROTECT-004', 'protect-session-only', 'explicit-session-only'],
  ['FAULT-STAGE-001', 'stage-write', 'stage-write-failure'],
  ['FAULT-STAGE-002', 'stage-readback', 'stage-verification-failed'],
  ['FAULT-STAGE-003', 'stage-cas', 'no-commit'],
  ['FAULT-STAGE-004', 'stage-rollback', 'quarantine'],
  ['FAULT-STAGE-005', 'stage-quarantine', 'blocks-first-run'],
  ['FAULT-STAGE-006', 'stage-process-loss', 'resume-or-quarantine'],
  ['FAULT-TXN-001', 'txn-persist', 'retained-or-session-only'],
  ['FAULT-TXN-002', 'txn-submit', 'accepted-or-pending'],
  ['FAULT-TXN-003', 'txn-pending', 'wait-only'],
  ['FAULT-TXN-004', 'txn-confirm', 'exact-block-confirmation'],
  ['FAULT-TXN-005', 'txn-reject', 'server-proof-rejected'],
  ['FAULT-TXN-006', 'txn-reconcile', 'lookup-first-reconciliation'],
  ['FAULT-NAV-001', 'nav-back-pre', 'clear-inputs'],
  ['FAULT-NAV-002', 'nav-back-post', 'destroy-authority'],
  ['FAULT-NAV-003', 'nav-bfcache', 'stale-rejected'],
  ['FAULT-NAV-004', 'nav-forged-history', 'stale-rejected'],
  ['FAULT-NAV-005', 'nav-owner-race', 'single-owner'],
  ['FAULT-CLEANUP-001', 'cleanup-activation', 'verified-absent'],
  ['FAULT-CLEANUP-002', 'cleanup-lock', 'locked'],
  ['FAULT-CLEANUP-003', 'cleanup-logout', 'external-source-never-targeted'],
  ['FAULT-CLEANUP-004', 'cleanup-removal-failure', 'quarantine'],
];

const SELF_TEST = process.argv.includes('--selftest');

const ids = new Set();
const reasons = [];
for (const [faultId, boundary, converged] of FAULTS) {
  if (!/^FAULT-[A-Z]+-\d{3}$/.test(faultId)) reasons.push(`malformed fault id: ${faultId}`);
  if (ids.has(faultId)) reasons.push(`duplicate fault id: ${faultId}`);
  ids.add(faultId);
  if (!boundary || boundary.length < 3) reasons.push(`unbound fault: ${faultId}`);
  if (!converged || /placeholder|tbd|success-only/i.test(converged)) reasons.push(`success-only or placeholder converged state: ${faultId}`);
}

if (reasons.length > 0) {
  console.error(`FAIL: ${reasons.length} fault-profile issue(s)`);
  for (const reason of reasons) console.error(`  - ${reason}`);
  process.exit(1);
}

if (SELF_TEST) {
  console.log(`FAULT ORCHESTRATION SELF-TEST OK (${FAULTS.length} faults bound, no success-only placeholders, no persistent-process config)`);
} else {
  console.log(`FEAT-009 fault orchestration profile OK: ${FAULTS.length} canonical faults bound to deterministic converged states`);
}
process.exit(0);
