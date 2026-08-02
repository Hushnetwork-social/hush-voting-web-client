#!/usr/bin/env node
/**
 * Vault corpus validator + production-exclusion scan.
 * ====================================================
 * 1. Validates metadata.json against metadata.schema.json (structural + pinned values).
 * 2. Confirms every schema file is well-formed JSON and a draft 2020-12 object.
 * 3. Verifies manifest integrity via generate-manifest --check semantics.
 * 4. Production-exclusion scan: public test credentials / deterministic selectors must
 *    never appear outside allowlisted corpus paths or inside production source/bundles.
 *
 * Exit codes: 0 = ok, 1 = validation failure, 2 = internal error.
 */
import { readFileSync, readdirSync, existsSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { verifyManifestAgainstDisk, ROOT } from './generate-manifest.mjs';

const SCHEMAS_DIR = join(ROOT, 'schemas');
// Unambiguous test-only/reference selectors that must never appear in production source.
// HKDF labels and suite constants are NORMATIVE and allowed; these markers identify
// deterministic test providers, the independent Rust reference runner, and corpus
// public-test-credential plumbing only.
const PROHIBITED_IN_PRODUCTION = [
  'DETERMINISTIC_TEST_PROVIDER',
  'vault-reference-runner',
  'PUBLIC_TEST_CREDENTIAL',
];
const ALLOWLIST_PREFIXES = ['conformance/vault/', 'conformance/identity/'];

/** Structural validation of metadata.json against its schema. */
function validateMetadata() {
  const metadata = JSON.parse(readFileSync(join(ROOT, 'metadata.json'), 'utf8'));
  const schema = JSON.parse(readFileSync(join(SCHEMAS_DIR, 'metadata.schema.json'), 'utf8'));
  const errors = [];
  if (metadata.corpusVersion !== schema.properties.corpusVersion.const) errors.push('corpusVersion mismatch');
  if (metadata.feature !== schema.properties.feature.const) errors.push('feature mismatch');
  if (metadata.featiPin.revision !== schema.properties.featiPin.properties.revision.const) errors.push('FEAT-001 revision mismatch');
  if (metadata.featiPin.manifestSha256 !== schema.properties.featiPin.properties.manifestSha256.const) errors.push('FEAT-001 manifest digest mismatch');
  if (metadata.publicTestCredentials.declaredPublicOnly !== true) errors.push('public test credentials must be declared public-only');
  if (errors.length) throw new Error(`metadata invalid: ${errors.join('; ')}`);
  return metadata;
}

/** Every schema file is a well-formed draft 2020-12 object. */
function validateSchemas() {
  const schemas = readdirSync(SCHEMAS_DIR).filter((f) => f.endsWith('.json')).sort();
  for (const f of schemas) {
    const doc = JSON.parse(readFileSync(join(SCHEMAS_DIR, f), 'utf8'));
    if (doc.$schema !== 'https://json-schema.org/draft/2020-12/schema') {
      throw new Error(`schema ${f} is not draft 2020-12`);
    }
    if (typeof doc.title !== 'string' || typeof doc.$id !== 'string') {
      throw new Error(`schema ${f} missing $id/title`);
    }
  }
  return schemas.length;
}

/** Deterministic selector scan across production source (src/, scripts/). */
function productionExclusionScan() {
  const findings = [];
  const walk = (dir) => {
    if (!existsSync(dir)) return;
    for (const entry of readdirSync(dir)) {
      const p = join(dir, entry);
      if (statSync(p).isDirectory()) {
        if (entry === 'node_modules' || entry === '.next' || entry === '.next-web' || entry === '.next-static' || entry === '.next-tauri' || entry === 'out' || entry === 'target') continue;
        walk(p);
      } else if (/\.(ts|tsx|mjs|js|json)$/.test(entry)) {
        const abs = join(ROOT, relative(ROOT, p));
        const isAllowlisted = ALLOWLIST_PREFIXES.some((prefix) => abs.startsWith(prefix));
        if (isAllowlisted) continue;
        const content = readFileSync(p, 'utf8');
        for (const token of PROHIBITED_IN_PRODUCTION) {
          if (content.includes(token)) {
            findings.push(`${relative(process.cwd(), p)} contains selector '${token}' outside allowlist`);
          }
        }
      }
    }
  };
  walk(join(ROOT, '../../../src'));
  walk(join(ROOT, '../../../scripts'));
  if (findings.length) throw new Error(`production-exclusion scan failed:\n${findings.join('\n')}`);
  return findings.length;
}

function main() {
  const args = process.argv.slice(2);
  const skipExclusion = args.includes('--skip-exclusion');
  const metadata = validateMetadata();
  const schemaCount = validateSchemas();
  verifyManifestAgainstDisk();
  const findings = skipExclusion ? 0 : productionExclusionScan();
  process.stdout.write(
    `VAULT CORPUS OK (metadata v${metadata.corpusVersion}, ${schemaCount} schemas, manifest verified, ${findings} exclusion findings)\n`
  );
  process.exit(0);
}

try {
  main();
} catch (err) {
  process.stderr.write(`VAULT CORPUS FAILED: ${err.message}\n`);
  process.exit(1);
}
