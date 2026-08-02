#!/usr/bin/env node
/**
 * FEAT-003 prior-version corpus replay (Task 6.1).
 * =================================================
 * Every RETAINED corpus version replays permanently. A retained version is a
 * `conformance/vault/v{N}/` directory pinned by `conformance/vault/versions.json`:
 *
 *   1. the version registry is loaded and asserted closed + monotonic;
 *   2. each retained version directory must exist;
 *   3. each retained version's CURRENT manifest digest must equal its PINNED digest
 *      (recorded when the version was published). Any change to a retained version's
 *      files — even unintentional — fails the gate, so a new contract version can
 *      never silently alter a prior version's expected outcomes;
 *   4. a deterministic digest-only replay record is emitted.
 *
 * The isolated validator replays the CURRENT version's vectors via
 * `npm run vault:conformance`; retained prior versions are guarded by their
 * immutable digest pins (a prior version's vectors cannot be re-derived differently
 * without failing this gate).
 *
 * Exit codes: 0 = all retained versions replay, 1 = replay or registry failure.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const REPO_ROOT = join(import.meta.dirname, '..', '..');
const REGISTRY_PATH = join(REPO_ROOT, 'conformance', 'vault', 'versions.json');

function loadRegistry() {
  if (!existsSync(REGISTRY_PATH)) {
    return { contract: 'FEAT-003 vault corpus version registry v1', versions: [], error: 'registry missing' };
  }
  return JSON.parse(readFileSync(REGISTRY_PATH, 'utf8'));
}

function manifestDigest(versionDir) {
  const bytes = readFileSync(join(versionDir, 'manifest.json'));
  return createHash('sha256').update(bytes).digest('hex');
}

function main() {
  const registry = loadRegistry();
  if (registry.error) {
    process.stderr.write(`VAULT PRIOR-VERSION REPLAY FAILED: ${registry.error}\n`);
    process.exit(1);
  }
  if (!Array.isArray(registry.versions) || registry.versions.length === 0) {
    process.stderr.write('VAULT PRIOR-VERSION REPLAY FAILED: version registry has no versions\n');
    process.exit(1);
  }
  const versions = registry.versions.filter((v) => v.retained !== false);
  const versionNumbers = versions.map((v) => v.corpusVersion);
  const sorted = [...versionNumbers].sort();
  if (JSON.stringify(versionNumbers) !== JSON.stringify(sorted)) {
    process.stderr.write('VAULT PRIOR-VERSION REPLAY FAILED: version registry is not monotonic\n');
    process.exit(1);
  }
  const results = [];
  let failed = false;
  for (const version of versions) {
    const dir = join(REPO_ROOT, 'conformance', 'vault', version.dir ?? `v${version.corpusVersion}`);
    if (!existsSync(dir)) {
      results.push({ corpusVersion: version.corpusVersion, ok: false, reason: 'version directory missing' });
      failed = true;
      continue;
    }
    const digest = manifestDigest(dir);
    if (version.manifestSha256 !== digest) {
      results.push({ corpusVersion: version.corpusVersion, ok: false, reason: `manifest digest drift (pinned ${version.manifestSha256.slice(0, 12)}, got ${digest.slice(0, 12)})` });
      failed = true;
      continue;
    }
    results.push({ corpusVersion: version.corpusVersion, ok: true, manifestSha256: digest });
  }
  process.stdout.write(
    failed
      ? `VAULT PRIOR-VERSION REPLAY FAILED: ${JSON.stringify(results.filter((r) => !r.ok))}\n`
      : `VAULT PRIOR-VERSION REPLAY OK (${results.length} retained version(s): ${versionNumbers.join(', ')})\n`,
  );
  process.exit(failed ? 1 : 0);
}

try {
  main();
} catch (err) {
  process.stderr.write(`VAULT PRIOR-VERSION REPLAY INTERNAL ERROR: ${err.message}\n`);
  process.exit(2);
}
