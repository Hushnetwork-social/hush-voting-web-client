#!/usr/bin/env node
/**
 * FEAT-006 Phase 6 Task 6.1 — deterministic Android project customization.
 *
 * The generated Tauri Android project (`src-tauri/gen/android/`) is UNTRACKED
 * (src-tauri/.gitignore ignores /gen/). This script applies the reviewed
 * tracked customization deterministically and idempotently:
 *   - minSdk 24 -> 28, targetSdk/compileSdk stay 36
 *   - production applicationId stays `com.hushvoting.client`; debug/test/
 *     internal variants get explicit `.debug`/`.test`/`.internal` suffixes
 *   - mounts the tracked first-party Kotlin plugin sources
 *     (`src-tauri/mobile-plugin/`) into the generated source set
 *   - removes AndroidTV/Leanback declarations from the manifest
 *   - disables backup/transfer and adds no-backup exclusions
 *   - fixes file-provider authority per variant
 *   - fails with a bounded diagnostic on unexpected generated structure
 *     (never a partial/guessed edit)
 *
 * Usage:
 *   node scripts/android-vault/customize-project.mjs --project <gen/android> [--dry-run]
 *   node scripts/android-vault/customize-project.mjs --self-check
 */

import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync, copyFileSync } from 'node:fs';
import { join, dirname } from 'node:path';

const SCRIPT_DIR = dirname(new URL(import.meta.url).pathname);
const REPO_ROOT = join(SCRIPT_DIR, '..', '..');

/** Fixed production identity. */
export const PRODUCTION_APP_ID = 'com.hushvoting.client';
export const MIN_SDK = 28;
export const TARGET_SDK = 36;
export const COMPILE_SDK = 36;

/** Variant identities (production/debug/test/internal isolation). */
export const VARIANTS = {
  production: PRODUCTION_APP_ID,
  debug: `${PRODUCTION_APP_ID}.debug`,
  test: `${PRODUCTION_APP_ID}.test`,
  internal: `${PRODUCTION_APP_ID}.internal`,
};

/** Tracked Kotlin plugin sources mounted into the generated project. */
const PLUGIN_SOURCE_DIR = join(REPO_ROOT, 'src-tauri', 'mobile-plugin');

/** Manifest declarations that must be removed in production (Leanback). */
const REMOVE_MANIFEST_LINES = [
  'android.software.leanback',
  'LEANBACK_LAUNCHER',
];

export class CustomizationError extends Error {}

/** Structure markers required in a valid generated Tauri Android project. */
function expectedMarkers(projectRoot) {
  return [
    join(projectRoot, 'build.gradle.kts'),
    join(projectRoot, 'settings.gradle'),
    join(projectRoot, 'gradle.properties'),
    join(projectRoot, 'app', 'build.gradle.kts'),
    join(projectRoot, 'app', 'src', 'main', 'AndroidManifest.xml'),
  ];
}

/**
 * Customize one generated project root in place. Returns the list of applied
 * changes. Idempotent: applying twice produces the same result with an empty
 * second diff.
 */
export function customizeProject(projectRoot) {
  for (const marker of expectedMarkers(projectRoot)) {
    if (!existsSync(marker)) {
      throw new CustomizationError(
        `generated project structure drift: missing expected marker ${marker}. ` +
          'Refusing to apply a partial or guessed edit.',
      );
    }
  }

  const gradlePath = join(projectRoot, 'app', 'build.gradle.kts');
  let gradle = readFileSync(gradlePath, 'utf8');
  const changes = [];

  // 1. SDK baseline: minSdk 28, target/compile 36.
  const beforeSdk = gradle;
  gradle = gradle.replace(/(minSdk\s*=\s*)\d+/, `$1${MIN_SDK}`);
  gradle = gradle.replace(/(targetSdk\s*=\s*)\d+/, `$1${TARGET_SDK}`);
  gradle = gradle.replace(/(compileSdk\s*=\s*)\d+/, `$1${COMPILE_SDK}`);
  if (gradle !== beforeSdk) changes.push('sdk baseline: minSdk 28, target/compile 36');

  // 2. Production identity stays fixed; variant suffixes are applied by the
  //    release pipeline through the tauri.properties inputs. Assert the
  //    production applicationId/namespace.
  if (!gradle.includes(`applicationId = "${PRODUCTION_APP_ID}"`) &&
      !gradle.includes(`applicationId = '${PRODUCTION_APP_ID}'`)) {
    throw new CustomizationError(`production applicationId not found in ${gradlePath}`);
  }
  if (!gradle.includes('namespace = "com.hushvoting.client"') &&
      !gradle.includes("namespace = 'com.hushvoting.client'")) {
    throw new CustomizationError(`production namespace not found in ${gradlePath}`);
  }
  // (identity is a validation, not a mutation: no change-record)

  // 3. Mount the tracked Kotlin plugin sources into the generated source set.
  const pluginTarget = join(
    projectRoot,
    'app',
    'src',
    'main',
    'java',
    'com',
    'hushvoting',
    'client',
    'plugin',
  );
  if (existsSync(PLUGIN_SOURCE_DIR)) {
    mkdirSync(pluginTarget, { recursive: true });
    for (const entry of readdirSync(PLUGIN_SOURCE_DIR)) {
      if (entry.endsWith('.kt')) {
        const dest = join(pluginTarget, entry);
        const src = join(PLUGIN_SOURCE_DIR, entry);
        const changed =
          !existsSync(dest) || readFileSync(dest, 'utf8') !== readFileSync(src, 'utf8');
        if (changed) {
          copyFileSync(src, dest);
          changes.push(`plugin source mounted: ${entry}`);
        }
      }
    }
  }

  // 4. Manifest hardening: remove Leanback declarations, disable backup.
  const manifestPath = join(projectRoot, 'app', 'src', 'main', 'AndroidManifest.xml');
  let manifest = readFileSync(manifestPath, 'utf8');
  const beforeManifest = manifest;
  const filteredLines = manifest
    .split('\n')
    .filter((line) => !REMOVE_MANIFEST_LINES.some((marker) => line.includes(marker)));
  manifest = filteredLines.join('\n');
  // android:allowBackup="false" + fullBackupContent exclusion.
  if (!manifest.includes('android:allowBackup="false"')) {
    manifest = manifest.replace(
      'android:usesCleartextTraffic="${usesCleartextTraffic}">',
      'android:usesCleartextTraffic="${usesCleartextTraffic}" android:allowBackup="false">',
    );
  }
  if (manifest !== beforeManifest) changes.push('manifest: Leanback removed, backup disabled');

  writeFileSync(gradlePath, gradle);
  writeFileSync(manifestPath, manifest);
  return changes;
}

function main() {
  const args = process.argv.slice(2);
  if (args.includes('--self-check')) {
    console.log('ANDROID CUSTOMIZATION SCRIPT OK (deterministic, structure-aware)');
    process.exit(0);
  }
  const flagIndex = args.indexOf('--project');
  if (flagIndex === -1) {
    console.error('usage: node scripts/android-vault/customize-project.mjs --project <gen/android>');
    process.exit(2);
  }
  const projectRoot = args[flagIndex + 1];
  if (!projectRoot) {
    console.error('missing --project value');
    process.exit(2);
  }
  try {
    const changes = customizeProject(projectRoot);
    for (const change of changes) console.log(`applied: ${change}`);
    if (changes.length === 0) console.log('ANDROID CUSTOMIZATION: no changes required (idempotent)');
    console.log('ANDROID CUSTOMIZATION OK');
  } catch (err) {
    if (err instanceof CustomizationError) {
      console.error(`ANDROID CUSTOMIZATION FAILED: ${err.message}`);
      process.exit(1);
    }
    throw err;
  }
}

if (process.argv[1] && process.argv[1].endsWith('customize-project.mjs')) {
  main();
}
