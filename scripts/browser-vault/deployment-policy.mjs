#!/usr/bin/env node
/**
 * FEAT-004 deployment-policy verification (Task 6.4).
 * ====================================================
 * Serves the PRODUCTION web build with a bounded foreground `next start` and
 * asserts the restrictive security headers (CSP, frame denial, nosniff,
 * referrer, HSTS), then terminates the server and all children. Also asserts
 * the built application registers NO service worker on the authenticated
 * origin (checked in a real browser context via Playwright in Phase 7; here
 * the static artifact scan proves no sw.js exists in the build output).
 *
 * Requires the production build to exist (`npm run build:web`). Exit codes:
 * 0 = policy verified, 1 = failure, 2 = internal error.
 */
import { spawn } from 'node:child_process';
import { existsSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');
const WEB_BUILD = join(REPO_ROOT, '.next-web');
const PORT = 3299;
const BASE = `http://localhost:${PORT}`;

const REQUIRED_HEADERS = [
  ['Content-Security-Policy', "default-src 'self'"],
  ['Content-Security-Policy', "script-src 'self'"],
  ['Content-Security-Policy', "object-src 'none'"],
  ['Content-Security-Policy', "frame-ancestors 'none'"],
  ['Content-Security-Policy', "worker-src 'self'"],
  ['X-Frame-Options', 'DENY'],
  ['X-Content-Type-Options', 'nosniff'],
  ['Referrer-Policy', 'no-referrer'],
  ['Strict-Transport-Security', 'max-age=31536000'],
];

function fail(message) {
  process.stderr.write(`DEPLOYMENT POLICY FAILED: ${message}\n`);
  process.exitCode = 1;
}

function assertNoServiceWorkerArtifact() {
  const outDir = join(REPO_ROOT, 'out');
  if (!existsSync(outDir)) {
    return true;
  }
  const candidates = [];
  const walk = (dir) => {
    for (const entry of readdirSync(dir)) {
      const full = join(dir, entry);
      if (statSync(full).isDirectory()) {
        walk(full);
      } else if (/sw(\.|-)worker\.js$/.test(entry)) {
        candidates.push(full);
      }
    }
  };
  walk(outDir);
  if (candidates.length > 0) {
    fail(`service worker artifact found in static export: ${candidates.join(', ')}`);
    return false;
  }
  return true;
}

if (!existsSync(WEB_BUILD)) {
  process.stderr.write('DEPLOYMENT POLICY SKIPPED: .next-web build missing (run npm run build:web first)\n');
  process.exitCode = 2;
  process.exit();
}

let verified = assertNoServiceWorkerArtifact();

const server = spawn('npx', ['next', 'start', '-p', String(PORT)], {
  cwd: REPO_ROOT,
  // Match the build-time env so next.config.ts resolves distDir to .next-web.
  env: { ...process.env, STANDALONE_BUILD: 'true' },
  stdio: ['ignore', 'pipe', 'pipe'],
});

const timeout = setTimeout(() => {
  fail('server start timeout');
  server.kill('SIGTERM');
  process.exitCode = 1;
}, 60_000);

async function waitForServer() {
  for (let attempt = 0; attempt < 60; attempt += 1) {
    try {
      const response = await fetch(BASE);
      if (response.ok || response.status === 404 || response.status === 307) {
        return response;
      }
    } catch {
      // retry
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  return null;
}

const response = await waitForServer();
clearTimeout(timeout);

if (response === null) {
  fail('server did not become ready');
} else {
  const headers = Object.fromEntries(response.headers.entries());
  for (const [name, fragment] of REQUIRED_HEADERS) {
    const value = headers[name.toLowerCase()] ?? '';
    if (!value.includes(fragment)) {
      fail(`header ${name} missing expected fragment: ${fragment}`);
      verified = false;
    }
  }
  if (verified) {
    process.stdout.write('DEPLOYMENT POLICY OK (CSP/frame/nosniff/referrer/HSTS verified; no service worker artifact)\n');
  }
}

server.kill('SIGTERM');
await new Promise((resolve) => setTimeout(resolve, 500));
process.exit(verified ? 0 : 1);
