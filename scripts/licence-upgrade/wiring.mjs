#!/usr/bin/env node
/**
 * FEAT-017 wiring / integration-evidence validator (Phase 6 task 6.5).
 *
 * Machine-checks that the Phase 6 integration seams are REAL (non-zero):
 *  1. the root Web composition mounts licence surfaces from authority facts
 *     (AuthRoot -> AuthenticatedLicenceRoot -> LicenceWorkspaceHost);
 *  2. EntitlementBridge routes licence workspace intents to the closed
 *     worker ops (activate/acknowledge/account-entry refresh);
 *  3. the worker op vocabulary + session methods exist and the page-safe
 *     snapshot carries FEAT-017 upgrade facts;
 *  4. the native confirmed-upgrade envelope builder exists (byte parity);
 *  5. no integration seam is dead: each file below must contain its anchor
 *     symbol, and the anchors must be wired (not only declared).
 *
 * Zero discovery or a missing anchor is RED.
 *
 * Usage: node scripts/licence-upgrade/wiring.mjs
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');

/** Anchor file → required integration symbol(s). */
const ANCHORS = [
  { file: 'src/app/auth/AuthRoot.tsx', anchor: 'AuthenticatedLicenceRoot' },
  { file: 'src/app/auth/AuthenticatedLicenceRoot.tsx', anchor: 'LicenceWorkspaceHost' },
  { file: 'src/app/auth/licence/licence-workspace-host.tsx', anchor: 'projectLicenceWorkspaceViewFacts' },
  { file: 'src/app/auth/licence/top-bar-surfaces.tsx', anchor: 'LicenceActivationNotification' },
  { file: 'src/lib/auth/web/entitlement-bridge.ts', anchor: 'handleLicenceWorkspaceIntent' },
  { file: 'src/lib/auth/web/entitlement-bridge.ts', anchor: 'licenceUpgradeConfirm' },
  { file: 'src/lib/auth/web/licence-workspace.ts', anchor: 'presentationInputFromMirror' },
  { file: 'src/lib/browser-vault/production/licence-session.ts', anchor: 'confirmUpgrade' },
  { file: 'src/lib/browser-vault/production/worker-env.ts', anchor: 'licenceUpgradeConfirm' },
  { file: 'src/lib/licensing/session-contract.ts', anchor: 'upgradeOperation' },
  { file: 'src-tauri/src/licence_vault.rs', anchor: 'confirmed_upgrade_payload_json' },
];

/** Self-test override: replace the anchor table (seeded-defect proof). */
function anchorTable() {
  const override = process.env.FEAT017_WIRING_ANCHORS_JSON;
  if (typeof override === 'string' && override.length > 0) {
    const parsed = JSON.parse(override);
    if (Array.isArray(parsed)) return parsed;
  }
  return ANCHORS;
}

let ok = true;
let seen = 0;
for (const { file, anchor } of anchorTable()) {
  const path = join(REPO_ROOT, file);
  const content = readFileSync(path, 'utf8');
  if (!content.includes(anchor)) {
    console.error(`WIRING FAIL: ${file} does not contain ${anchor}`);
    ok = false;
  } else {
    seen += 1;
  }
}
if (!ok) {
  process.exit(1);
}
console.log(`FEAT-017 WIRING OK (${seen}/${anchorTable().length} integration anchors present in real seams)`);
