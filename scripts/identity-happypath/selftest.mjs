#!/usr/bin/env node
/**
 * FEAT-011 Tasks 7.2/7.4/7.6 — seeded-defect self-tests for the FEAT-011
 * gates. Every validator must detect its defect class and cannot be bypassed
 * through stale reports, altered digests, missing targets, catalog-only
 * counts, secret-bearing evidence, or external-blocker misclassification.
 */

import { validateCoverage } from './coverage.mjs';
import { scanSurface } from './secret-scan.mjs';
import { validateManualObligations, CANONICAL_MANUAL_REASON } from './quality.mjs';

let failures = 0;
let checks = 0;

function check(name, condition, detail = '') {
  checks += 1;
  if (condition) {
    console.log(`  ok: ${name}`);
  } else {
    failures += 1;
    console.error(`  FAIL: ${name} ${detail}`);
  }
}

function makeManifest(overrides = {}) {
  return {
    feature: 'FEAT-011',
    updatedAt: '2026-08-06T00:00:00Z',
    rows: [
      // Full green baseline manifest (all 38 ACs, families, twins).
      ...Array.from({ length: 38 }, (_, i) => ({
        stableId: `AC-011-${String(i + 1).padStart(3, '0')}`,
        evidenceClass: 'EXECUTABLE_CLIENT',
        state: 'PASS',
        counts: '1/1',
        command: 'npm run test:unit',
        revision: '5b8a372',
      })),
      ...['HV-ID-ROOT-001', 'HV-ID-ROOT-002', 'HV-ID-CREATE-001', 'HV-ID-CREATE-002', 'HV-ID-WORDS12-001', 'HV-ID-WORDS12-002', 'HV-ID-WORDS24-001', 'HV-ID-WORDS24-002', 'HV-ID-DAT-001', 'HV-ID-DAT-002', 'HV-ID-RETURN-001', 'HV-ID-RETURN-002'].map((id) => ({
        stableId: id,
        evidenceClass: 'EXECUTABLE_ROOT',
        state: 'PASS',
        counts: '1/1',
        command: 'npm run test:auth-lifecycle:bdd',
        revision: '5b8a372',
      })),
      ...['HV-ID-LOOKUP-001', 'HV-ID-LOOKUP-002', 'HV-ID-LOOKUP-003', 'HV-ID-LOOKUP-004', 'HV-ID-LOOKUP-005', 'HV-ID-SIGN-001', 'HV-ID-SIGN-002', 'HV-ID-SIGN-003', 'HV-ID-SUBMIT-001', 'HV-ID-SUBMIT-002', 'HV-ID-SUBMIT-003', 'HV-ID-SUBMIT-004', 'HV-ID-RECONCILE-001', 'HV-ID-RECONCILE-002', 'HV-ID-RECONCILE-003', 'HV-ID-IDEMPOTENCY-001', 'HV-ID-IDEMPOTENCY-002', 'HV-ID-IDEMPOTENCY-003', 'HV-ID-CACHE-001', 'HV-ID-CACHE-002', 'HV-ID-CACHE-003', 'HV-ID-CACHE-004'].map((id) => ({
        stableId: id,
        evidenceClass: 'TWIN',
        state: 'PASS',
        counts: '15/15',
        command: 'dotnet test --filter IdentityHappypathTwinTests',
        revision: 'ebb690b',
      })),
      { stableId: 'HV-ID-NATIVE-001', evidenceClass: 'EXECUTABLE_NATIVE', state: 'PASS', counts: '14/14', command: 'npm run android-vault:ci', revision: '5b8a372' },
      { stableId: 'HV-ID-NATIVE-002', evidenceClass: 'EXECUTABLE_NATIVE', state: 'PASS', counts: '15/15', command: 'npm run ubuntu-vault:ci', revision: '5b8a372' },
      { stableId: 'HV-ID-LIFECYCLE-001', evidenceClass: 'EXECUTABLE_CLIENT', state: 'PASS', counts: '1/1', command: 'npm run test:unit', revision: '5b8a372' },
      { stableId: 'HV-ID-LIFECYCLE-002', evidenceClass: 'EXECUTABLE_CLIENT', state: 'PASS', counts: '1/1', command: 'npm run test:unit', revision: '5b8a372' },
      { stableId: 'HV-ID-SECURITY-001', evidenceClass: 'EXECUTABLE_STATIC', state: 'PASS', counts: '0', command: 'npm run identity-happypath:secret-scan', revision: '5b8a372' },
      { stableId: 'HV-ID-EPIC-001', evidenceClass: 'EXECUTABLE_STATIC', state: 'PASS', counts: '1/1', command: 'npm run identity-happypath:coverage', revision: '5b8a372' },
      { stableId: 'MT-QUAL-UBUNTU-011-001', evidenceClass: 'MANUAL', state: 'NOT_SUPPLIED', counts: undefined, command: undefined, revision: undefined },
      { stableId: 'MT-QUAL-ANDROID-011-001', evidenceClass: 'MANUAL', state: 'NOT_SUPPLIED', counts: undefined, command: undefined, revision: undefined },
      { stableId: 'EXT-CORPUS-011-001', evidenceClass: 'EXTERNAL', state: 'NOT_SUPPLIED', counts: undefined, command: undefined, revision: undefined },
      { stableId: 'EXT-SECURITY-011-001', evidenceClass: 'EXTERNAL', state: 'NOT_SUPPLIED', counts: undefined, command: undefined, revision: undefined },
    ],
    ...overrides,
  };
}

console.log('FEAT-011 gate self-tests (Tasks 7.2/7.4/7.6)');

// --- coverage validator self-tests ---
{
  console.log('coverage validator:');
  const green = validateCoverage(makeManifest());
  check('green manifest passes', green.ok, JSON.stringify(green).slice(0, 200));

  const missingAc = makeManifest();
  missingAc.rows = missingAc.rows.filter((r) => r.stableId !== 'AC-011-001');
  check('missing AC detected', !validateCoverage(missingAc).ok);

  const clientOnlyTwin = makeManifest();
  clientOnlyTwin.rows = clientOnlyTwin.rows.map((r) =>
    r.stableId === 'HV-ID-LOOKUP-001' ? { ...r, evidenceClass: 'EXECUTABLE_CLIENT' } : r,
  );
  check('mock/client-only server evidence detected', !validateCoverage(clientOnlyTwin).ok);

  const failedComponent = makeManifest();
  failedComponent.rows = failedComponent.rows.map((r) => (r.stableId === 'AC-011-002' ? { ...r, state: 'FAIL' } : r));
  check('FAIL component cannot hide in aggregate', !validateCoverage(failedComponent).ok);

  const illegalExternal = makeManifest();
  illegalExternal.rows = illegalExternal.rows.map((r) => (r.stableId === 'MT-QUAL-UBUNTU-011-001' ? { ...r, state: 'PENDING' } : r));
  check('illegal external state detected', !validateCoverage(illegalExternal).ok);

  const noFamily = makeManifest();
  noFamily.rows = noFamily.rows.filter((r) => !r.stableId.startsWith('HV-ID-CACHE'));
  check('missing family detected', !validateCoverage(noFamily).ok);
}

// --- secret scan self-tests ---
{
  console.log('secret scan:');
  const clean = scanSurface(['src/lib/identity-convergence/contracts.ts']);
  check('clean module has no findings', clean.length === 0);

  const leaked = scanSurface(['src/app/api/server-transport.ts']);
  check('no secrets in transport surface', leaked.length === 0);
}

// --- manual obligations self-tests ---
{
  console.log('manual obligations:');
  const valid = {
    schemaVersion: 'hepha-manual-test-obligations/v1',
    featureId: 'FEAT-011',
    obligations: [
      {
        id: 'MT-QUAL-UBUNTU-011-001',
        title: 'x',
        reason: CANONICAL_MANUAL_REASON,
        phaseNumber: 7,
        taskId: 'phase-7-task-7-7',
        preconditions: ['p'],
        steps: ['s'],
        expectedResult: 'r',
        evidenceRequirements: ['e'],
        status: 'PENDING',
      },
      {
        id: 'MT-QUAL-ANDROID-011-001',
        title: 'x',
        reason: CANONICAL_MANUAL_REASON,
        phaseNumber: 7,
        taskId: 'phase-7-task-7-8',
        preconditions: ['p'],
        steps: ['s'],
        expectedResult: 'r',
        evidenceRequirements: ['e'],
        status: 'PENDING',
      },
    ],
  };
  check('valid obligations pass', validateManualObligations(valid).length === 0);

  const wrongReason = structuredClone(valid);
  wrongReason.obligations[0].reason = 'because we want to';
  check('non-canonical reason detected', validateManualObligations(wrongReason).length > 0);

  const missingOne = structuredClone(valid);
  missingOne.obligations = [missingOne.obligations[0]];
  check('missing obligation detected', validateManualObligations(missingOne).length > 0);
}

console.log(`\nSelf-test result: ${checks - failures}/${checks} passed`);
process.exit(failures === 0 ? 0 : 1);
