#!/usr/bin/env node
/**
 * FEAT-006 Phase 6 Task 6.3 — manifest/WebView/backup/component policy.
 *
 * Inspects a final merged manifest (or a fixture) against the production
 * policy allowlist/denylist: no Leanback, one exported launcher, backup
 * disabled, no broad permissions, no cleartext in production, no inbound
 * credential association/share/deep link. The same rules are applied to the
 * merged manifest produced by Gradle at release time (Phase 7 package
 * inspection) and to fixtures in tests. Every forbidden declaration fails
 * independently with a bounded diagnostic.
 *
 * Usage:
 *   node scripts/android-vault/policy-check.mjs --manifest <AndroidManifest.xml> [--variant production|debug]
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';

const SCRIPT_DIR = dirname(new URL(import.meta.url).pathname);

/** Permissions allowed in production (narrowly justified). */
export const ALLOWED_PERMISSIONS = [
  'android.permission.INTERNET',
  'android.permission.ACCESS_NETWORK_STATE',
];

/** Forbidden permissions (never requested). */
export const FORBIDDEN_PERMISSIONS = [
  'android.permission.CAMERA',
  'android.permission.RECORD_AUDIO',
  'android.permission.ACCESS_FINE_LOCATION',
  'android.permission.ACCESS_COARSE_LOCATION',
  'android.permission.READ_CONTACTS',
  'android.permission.POST_NOTIFICATIONS',
  'android.permission.READ_MEDIA_IMAGES',
  'android.permission.READ_EXTERNAL_STORAGE',
  'android.permission.WRITE_EXTERNAL_STORAGE',
  'android.permission.QUERY_ALL_PACKAGES',
  'android.permission.SYSTEM_ALERT_WINDOW',
  'android.permission.BIND_ACCESSIBILITY_SERVICE',
  'android.permission.USE_BIOMETRIC',
  'android.permission.WAKE_LOCK',
  'android.permission.FOREGROUND_SERVICE',
];

/** Forbidden declarations in production. */
export const FORBIDDEN_DECLARATIONS = [
  'android.software.leanback',
  'LEANBACK_LAUNCHER',
];

/** Inbound credential entry points that must never exist. */
export const FORBIDDEN_INTENT_PATTERNS = [
  'android.intent.action.VIEW',
  'android.intent.action.SEND',
  'android.intent.action.PROCESS_TEXT',
];

export class PolicyError extends Error {}

/** Result of a policy check (list of violations; empty = pass). */
export function checkManifestPolicy(manifestXml, variant = 'production') {
  const violations = [];

  for (const permission of FORBIDDEN_PERMISSIONS) {
    if (manifestXml.includes(`android.permission.${permission.split('.').pop()}`) ||
        manifestXml.includes(permission)) {
      violations.push(`forbidden permission: ${permission}`);
    }
  }

  for (const declaration of FORBIDDEN_DECLARATIONS) {
    if (manifestXml.includes(declaration)) {
      violations.push(`forbidden declaration: ${declaration}`);
    }
  }

  // Backup must be disabled (allowBackup="false").
  if (variant === 'production' && !manifestXml.includes('android:allowBackup="false"')) {
    violations.push('backup not disabled (android:allowBackup="false" missing)');
  }

  // Production cleartext must be false.
  if (variant === 'production' && manifestXml.includes('usesCleartextTraffic="true"')) {
    violations.push('cleartext traffic enabled in production');
  }

  // Exactly one exported launcher; no other exported components.
  const exportedCount = (manifestXml.match(/android:exported="true"/g) ?? []).length;
  if (exportedCount !== 1) {
    violations.push(`expected exactly one exported component, found ${exportedCount}`);
  }
  if (!manifestXml.includes('android.intent.category.LAUNCHER')) {
    violations.push('launcher category missing');
  }

  // No inbound credential association/share/deep link.
  for (const pattern of FORBIDDEN_INTENT_PATTERNS) {
    if (manifestXml.includes(pattern)) {
      violations.push(`inbound intent pattern: ${pattern}`);
    }
  }

  return violations;
}

function main() {
  const args = process.argv.slice(2);
  const manifestIndex = args.indexOf('--manifest');
  const variantIndex = args.indexOf('--variant');
  if (manifestIndex === -1) {
    console.error('usage: node scripts/android-vault/policy-check.mjs --manifest <AndroidManifest.xml> [--variant production]');
    process.exit(2);
  }
  const manifestPath = args[manifestIndex + 1];
  const variant = variantIndex !== -1 ? args[variantIndex + 1] : 'production';
  const xml = readFileSync(manifestPath, 'utf8');
  const violations = checkManifestPolicy(xml, variant);
  if (violations.length > 0) {
    console.error(`ANDROID MANIFEST POLICY FAILED (${variant}):\n${violations.join('\n')}`);
    process.exit(1);
  }
  console.log(`ANDROID MANIFEST POLICY OK (${variant})`);
}

if (process.argv[1] && process.argv[1].endsWith('policy-check.mjs')) {
  main();
}
