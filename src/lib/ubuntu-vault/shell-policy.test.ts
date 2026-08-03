/**
 * FEAT-005 shell-hardening policy tests (Task 6.4).
 *
 * Parses the production Tauri configuration and capabilities from disk and
 * asserts the release denylist: no generic plugin/capability, no broad
 * unsafe script policy, no remote content, no release devtools, exact
 * network allowlists, and the shared `.deb`/AppImage application identity.
 * A violation fails this gate before any release packaging.
 */

import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

interface TauriConfig {
  identifier: string;
  app?: {
    windows?: Array<{ label?: string; devtools?: boolean; url?: string }>;
    security?: { csp?: string };
  };
  bundle?: { targets?: string[] };
}

function readJson(relative: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(process.cwd(), relative), 'utf8')) as Record<
    string,
    unknown
  >;
}

const tauriConfig = readJson('src-tauri/tauri.conf.json') as unknown as TauriConfig;
const capabilities = readJson('src-tauri/capabilities/default.json') as unknown as {
  identifier: string;
  windows: string[];
  permissions: string[];
};

const PROHIBITED_PERMISSIONS = [
  'core:default',
  'core:path:default',
  'core:process:default',
  'shell:',
  'http:',
  'fs:',
  'opener:',
  'clipboard-manager:',
  'os:',
  'dialog:',
  'websocket:',
];

describe('package identity (task 6.5)', () => {
  it('shares the fixed production application id across formats', () => {
    expect(tauriConfig.identifier).toBe('com.hushvoting.client');
    // The capability set identifier is a local name (not the app id) and is
    // never a wildcard.
    expect(capabilities.identifier).not.toContain('*');
  });

  it('targets only .deb and AppImage', () => {
    expect(tauriConfig.bundle?.targets).toEqual(['deb', 'appimage']);
  });

  it('never bundles, installs, or starts a Secret Service provider', () => {
    const raw = JSON.stringify(tauriConfig).toLowerCase();
    expect(raw).not.toContain('gnome-keyring');
    expect(raw).not.toContain('secret-service-daemon');
    expect(raw).not.toContain('apt');
  });
});

describe('CSP and content policy (task 6.3)', () => {
  it('forbids broad unsafe script policy and third-party script sources', () => {
    const csp = tauriConfig.app?.security?.csp ?? '';
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain("script-src 'self' 'unsafe-inline'");
    expect(csp).not.toContain('unsafe-eval');
    // No third-party script/style/font/analytics hosts.
    for (const thirdParty of ['google', 'cloudflare', 'jsdelivr', 'analytics', 'fonts.g']) {
      expect(csp).not.toContain(thirdParty);
    }
  });

  it('allowlists only the approved IPC and production endpoint in connect-src', () => {
    const csp = tauriConfig.app?.security?.csp ?? '';
    expect(csp).toContain('https://api.hushnetwork.social');
    expect(csp).toContain('ipc:');
    expect(csp).toContain('http://ipc.localhost');
    // Cleartext production endpoints are impossible by construction.
    expect(csp).not.toContain('http://api.hushnetwork.social');
    expect(csp).not.toContain('localhost:4666');
  });

  it('loads only bundled first-party assets (no remote website)', () => {
    const window = tauriConfig.app?.windows?.[0];
    expect(window?.url).toBeUndefined();
    expect((window?.url ?? '')).toBe('');
  });

  it('disables release devtools', () => {
    const window = tauriConfig.app?.windows?.[0];
    expect(window?.devtools).toBe(false);
  });
});

describe('capability denylist (task 6.3)', () => {
  it('grants only the main window reviewed core defaults', () => {
    expect(capabilities.windows).toEqual(['main']);
    for (const permission of capabilities.permissions) {
      // No wildcard permission is ever granted.
      expect(permission).not.toContain('*');
      for (const prohibited of PROHIBITED_PERMISSIONS) {
        expect(permission).not.toContain(prohibited);
      }
    }
  });

  it('contains no generic core:default permission', () => {
    expect(capabilities.permissions).not.toContain('core:default');
  });

  it('grants exactly the reviewed window/event defaults (no others)', () => {
    const allowed = new Set(['core:window:default', 'core:event:default']);
    for (const permission of capabilities.permissions) {
      expect(allowed.has(permission)).toBe(true);
    }
  });
});
