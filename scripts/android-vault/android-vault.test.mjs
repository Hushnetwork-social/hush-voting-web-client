/**
 * FEAT-006 Phase 6 Tasks 6.2/6.4/6.6/6.8 — deterministic script tests.
 *
 * Covers: Android project customization (idempotency + drift failure +
 * variant isolation), manifest/backup/component policy (seeded negatives),
 * unified gate self-tests (seeded defects detected), and handoff integrity.
 * Run with: node --test scripts/android-vault/android-vault.test.mjs
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, writeFileSync, readFileSync, rmSync, mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';

import { customizeProject, CustomizationError, MIN_SDK, PRODUCTION_APP_ID, VARIANTS } from './customize-project.mjs';
import { checkManifestPolicy } from './policy-check.mjs';
import { checkHandoffIntegrity, checkHandoffSeamPresence } from './ci-android-vault.mjs';

const ROOT = join(new URL('..', import.meta.url).pathname, '..');

/** Build a minimal fixture of the generated Tauri Android project. */
function fixtureProject() {
  const dir = mkdtempSync(join(tmpdir(), 'feat006-proj-'));
  mkdirSync(join(dir, 'app', 'src', 'main', 'java', 'com', 'hushvoting', 'client'), { recursive: true });
  writeFileSync(join(dir, 'build.gradle.kts'), '');
  writeFileSync(join(dir, 'settings.gradle'), '');
  writeFileSync(join(dir, 'gradle.properties'), '');
  writeFileSync(
    join(dir, 'app', 'build.gradle.kts'),
    [
      'android {',
      '  compileSdk = 36',
      '  namespace = "com.hushvoting.client"',
      '  defaultConfig {',
      '    applicationId = "com.hushvoting.client"',
      '    minSdk = 24',
      '    targetSdk = 36',
      '  }',
      '}',
    ].join('\n'),
  );
  writeFileSync(
    join(dir, 'app', 'src', 'main', 'AndroidManifest.xml'),
    [
      '<?xml version="1.0" encoding="utf-8"?>',
      '<manifest xmlns:android="http://schemas.android.com/apk/res/android">',
      '    <uses-feature android:name="android.software.leanback" android:required="false" />',
      '    <application android:usesCleartextTraffic="${usesCleartextTraffic}">',
      '        <activity android:name=".MainActivity" android:exported="true">',
      '            <category android:name="android.intent.category.LEANBACK_LAUNCHER" />',
      '            <category android:name="android.intent.category.LAUNCHER" />',
      '        </activity>',
      '    </application>',
      '</manifest>',
    ].join('\n'),
  );
  return dir;
}

test('customization is idempotent and applies the SDK baseline', () => {
  const dir = fixtureProject();
  const first = customizeProject(dir);
  assert.ok(first.length > 0, 'first run must apply changes');
  const second = customizeProject(dir);
  assert.equal(second.length, 0, 'second run must be idempotent');
  const gradle = readFileSync(join(dir, 'app', 'build.gradle.kts'), 'utf8');
  assert.match(gradle, /minSdk\s*=\s*28/);
  assert.match(gradle, /targetSdk\s*=\s*36/);
  assert.match(gradle, /compileSdk\s*=\s*36/);
  assert.match(gradle, new RegExp(`applicationId\\s*=\\s*"${PRODUCTION_APP_ID}"`));
  const manifest = readFileSync(join(dir, 'app', 'src', 'main', 'AndroidManifest.xml'), 'utf8');
  assert.ok(!manifest.includes('leanback'));
  assert.ok(!manifest.includes('LEANBACK_LAUNCHER'));
  assert.ok(manifest.includes('android:allowBackup="false"'));
  rmSync(dir, { recursive: true, force: true });
});

test('customization refuses drifted generated structure', () => {
  const dir = fixtureProject();
  rmSync(join(dir, 'app', 'build.gradle.kts'));
  assert.throws(() => customizeProject(dir), CustomizationError);
  rmSync(dir, { recursive: true, force: true });
});

test('customization rejects a non-production identity', () => {
  const dir = fixtureProject();
  const gradlePath = join(dir, 'app', 'build.gradle.kts');
  const gradle = readFileSync(gradlePath, 'utf8').replace(
    'applicationId = "com.hushvoting.client"',
    'applicationId = "com.hushvoting.client.debug"',
  );
  writeFileSync(gradlePath, gradle);
  assert.throws(() => customizeProject(dir), CustomizationError);
  rmSync(dir, { recursive: true, force: true });
});

test('variant identities are isolated namespaces', () => {
  assert.equal(VARIANTS.production, 'com.hushvoting.client');
  assert.equal(VARIANTS.debug, 'com.hushvoting.client.debug');
  assert.equal(VARIANTS.test, 'com.hushvoting.client.test');
  assert.equal(VARIANTS.internal, 'com.hushvoting.client.internal');
  const values = Object.values(VARIANTS);
  assert.equal(new Set(values).size, values.length);
  assert.equal(MIN_SDK, 28);
});

test('manifest policy passes the hardened fixture', () => {
  const dir = fixtureProject();
  customizeProject(dir);
  const xml = readFileSync(join(dir, 'app', 'src', 'main', 'AndroidManifest.xml'), 'utf8');
  assert.deepEqual(checkManifestPolicy(xml, 'production'), []);
  rmSync(dir, { recursive: true, force: true });
});

test('manifest policy detects every seeded forbidden declaration', () => {
  const cases = [
    ['<uses-feature android:name="android.software.leanback"/>', 'leanback'],
    ['<uses-permission android:name="android.permission.CAMERA"/>', 'permission'],
    ['<application android:allowBackup="true"></application>', 'backup'],
    ['android:usesCleartextTraffic="true"', 'cleartext'],
    ['<activity android:exported="true"/><activity android:exported="true"/>', 'exported'],
    ['<action android:name="android.intent.action.SEND"/>', 'intent'],
  ];
  for (const [xml, expected] of cases) {
    const violations = checkManifestPolicy(xml, 'production');
    assert.ok(violations.length > 0, `no violation for ${expected}`);
    assert.ok(violations.some((v) => v.includes(expected) || v.includes('exported')), `wrong violation for ${expected}: ${violations}`);
  }
});

test('unified gate self-test detects seeded defects', () => {
  const out = execFileSync(process.execPath, [
    join(ROOT, 'scripts', 'android-vault', 'ci-android-vault.mjs'),
    '--selftest',
  ], { encoding: 'utf8' });
  assert.match(out, /ANDROID VAULT SELF-TEST OK/);
});

test('handoff integrity gate passes on the sealed handoff', () => {
  const result = checkHandoffIntegrity();
  assert.match(result, /handoff integrity OK/);
});

test('handoff integrity gate detects a missing seam', () => {
  assert.ok(checkHandoffSeamPresence('createProvision', 'no seam here'));
  assert.ok(!checkHandoffSeamPresence('createProvision', 'createProvision present'));
});
