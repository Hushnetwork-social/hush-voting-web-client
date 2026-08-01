#!/usr/bin/env node
/**
 * Corpus validation (schema + integrity + completeness)
 * ======================================================
 * Validates every corpus document against its local JSON Schema 2020-12
 * document (no remote references), verifies canonical formatting and manifest
 * integrity, and enforces vector completeness rules:
 *
 *   - every APPROVED producer has positive mnemonic/key vectors and, where
 *     applicable, .dat/canonical/signature vectors;
 *   - lookup outcomes cover zero, one, and multiple matches plus dedup;
 *   - negative coverage spans every required category;
 *   - no secret-scanner exception applies outside exact corpus paths (checked
 *     by the repository secret-scan allowlist, not here).
 *
 * Usage: node scripts/validate.mjs
 * Exit codes: 0 = valid, 1 = validation failure.
 */
import { createHash } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validate as ajvValidate } from './vendor/ajv-bundle.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
let failures = 0;

function fail(msg) {
  failures += 1;
  console.error('FAIL:', msg);
}

function readJson(p) {
  const raw = readFileSync(p, 'utf8');
  if (raw.charCodeAt(0) === 0xfeff) fail(`BOM in ${p}`);
  if (raw.includes('\r')) fail(`CRLF in ${p}`);
  if (!raw.endsWith('\n')) fail(`missing final newline in ${p}`);
  return { raw, obj: JSON.parse(raw) };
}

function canonicalForm(obj) {
  const sort = (o) => {
    if (Array.isArray(o)) return o.map(sort);
    if (o && typeof o === 'object') {
      return Object.fromEntries(Object.keys(o).sort().map((k) => [k, sort(o[k])]));
    }
    return o;
  };
  return JSON.stringify(sort(obj), null, 2) + '\n';
}

// ---- load schemas ----------------------------------------------------------
const schemaDir = join(ROOT, 'schemas');
const schemas = {};
for (const f of readdirSync(schemaDir).filter((x) => x.endsWith('.schema.json'))) {
  const { obj } = readJson(join(schemaDir, f));
  schemas[obj.$id] = obj;
}
function validateAgainst(schemaId, doc, label) {
  const res = ajvValidate(schemas[schemaId], doc);
  if (!res.valid) {
    fail(`${label} failed schema ${schemaId}: ${res.errors.map((e) => e.instancePath + ' ' + e.message).join('; ')}`);
  }
}

// ---- corpus documents ------------------------------------------------------
function docName(p) {
  return relative(ROOT, p).split(sep).join('/');
}
const docs = {};
const dataFiles = [];
for (const dir of ['schemas', 'producers', 'vectors', 'lookup']) {
  for (const f of readdirSync(join(ROOT, dir)).filter((x) => x.endsWith('.json'))) {
    dataFiles.push(`${dir}/${f}`);
  }
}
dataFiles.push('inventory.json');
for (const rel of dataFiles.sort()) {
  const full = join(ROOT, rel);
  const { raw, obj } = readJson(full);
  docs[rel] = { raw, obj };
  if (canonicalForm(obj) !== raw) fail(`non-canonical formatting in ${rel}`);
}

// schema validation by kind
for (const rel of dataFiles) {
  if (rel.endsWith('.schema.json')) continue;
  const kind = docs[rel].obj.kind;
  const map = {
    'producer-inventory': 'urn:hushvoting:conformance:identity:v1:schemas:inventory',
    'mnemonic-vectors': 'urn:hushvoting:conformance:identity:v1:schemas:mnemonic-vectors',
    'key-vectors': 'urn:hushvoting:conformance:identity:v1:schemas:key-vectors',
    'dat-vectors': 'urn:hushvoting:conformance:identity:v1:schemas:dat-vectors',
    'canonical-byte-vectors': 'urn:hushvoting:conformance:identity:v1:schemas:canonical-byte-vectors',
    'signature-vectors': 'urn:hushvoting:conformance:identity:v1:schemas:signature-vectors',
    'negative-vectors': 'urn:hushvoting:conformance:identity:v1:schemas:negative-vectors',
    'lookup-outcomes': 'urn:hushvoting:conformance:identity:v1:schemas:lookup-outcomes',
  };
  if (rel.startsWith('producers/')) {
    validateAgainst('urn:hushvoting:conformance:identity:v1:schemas:producer', docs[rel].obj, docName(rel));
    continue;
  }
  const schemaId = map[kind];
  if (!schemaId) {
    fail(`${docName(rel)}: unknown kind ${kind}`);
    continue;
  }
  validateAgainst(schemaId, docs[rel].obj, docName(rel));
}

// producer records vs inventory consistency
const inventory = docs['inventory.json'].obj;
const producerIds = new Set(inventory.producers.map((p) => p.producerId));
for (const rel of dataFiles) {
  if (!rel.startsWith('producers/')) continue;
  const pid = docs[rel].obj.producerId;
  if (!producerIds.has(pid)) fail(`producer record ${rel} not listed in inventory`);
}
for (const p of inventory.producers) {
  if (p.recordFile && !existsSync(join(ROOT, p.recordFile))) {
    fail(`inventory record ${p.producerId} references missing file ${p.recordFile}`);
  }
}

// ---- completeness: every APPROVED producer has positive vectors ------------
const approved = inventory.producers.filter((p) => p.classification === 'APPROVED');
const mnemonic = docs['vectors/mnemonic-vectors.json'].obj.vectors;
const key = docs['vectors/key-vectors.json'].obj.vectors;
const dat = docs['vectors/dat-vectors.json'].obj.vectors;
const canonical = docs['vectors/canonical-byte-vectors.json'].obj.vectors;
const signature = docs['vectors/signature-vectors.json'].obj.vectors;
const negative = docs['vectors/negative-vectors.json'].obj.vectors;
const lookup = docs['lookup/outcomes.json'].obj;

// Wrapper producers inherit vector coverage from the contract they wrap:
//   P-03 (desktop) wraps the Olimpo path (P-02 derivation, P-04 .dat, P-07 signing)
//   P-05 (.dat .NET writer) is mutually compatible with P-04
const coverageAlias = {
  mnemonic: { 'P-03': 'P-02' },
  key: { 'P-03': 'P-02' },
  dat: { 'P-03': 'P-04', 'P-05': 'P-04' },
  signature: { 'P-03': 'P-02' },
};
const kindByOperation = {
  MNEMONIC_DERIVE: 'mnemonic',
  KEY_ENCODE: 'key',
  DAT_V1: 'dat',
  DAT_V1_ENCRYPT: 'dat',
  DAT_V1_DECRYPT: 'dat',
  DAT_V1_PARSE: 'dat',
  SIGN: 'signature',
  VERIFY: 'signature',
};
const vectorSets = { mnemonic, key, dat, signature };

for (const p of approved) {
  const ops = new Set(p.recordFile ? docs[p.recordFile].obj.supportedOperations : []);
  const kinds = new Set();
  for (const [op, kind] of Object.entries(kindByOperation)) {
    if (ops.has(op)) kinds.add(kind);
  }
  if (kinds.size === 0) {
    // signature-only or no-operation producers require no vectors; P-07 covered below
    continue;
  }
  for (const kind of kinds) {
    const effective = (coverageAlias[kind] ?? {})[p.producerId] ?? p.producerId;
    if (!vectorSets[kind].some((v) => v.producerId === effective)) {
      fail(`APPROVED producer ${p.producerId} has no ${kind} vectors (effective ${effective})`);
    }
  }
}
if (!signature.some((v) => v.producerId === 'P-01')) fail('P-01 has no signature vector');
if (!signature.some((v) => v.producerId === 'P-02')) fail('P-02 has no signature vector');
if (!dat.some((v) => v.producerId === 'P-04')) fail('P-04 has no .dat vector');

// 12-word and 24-word coverage
if (!mnemonic.some((v) => v.wordCount === 12 && v.producerId === 'P-01')) fail('missing 12-word positive vector for P-01');
if (!mnemonic.some((v) => v.wordCount === 24 && v.producerId === 'P-01')) fail('missing 24-word positive vector for P-01');
if (!mnemonic.some((v) => v.wordCount === 24 && v.producerId === 'P-02')) fail('missing 24-word positive vector for P-02');
if (!negative.some((v) => v.errorCode === 'INVALID_WORD_COUNT' && v.producerId === 'P-02')) fail('missing 12-word rejection vector for P-02');

// ---- negative matrix categories -------------------------------------------
const codes = new Set(negative.map((v) => v.errorCode));
const requiredNegatives = [
  'INVALID_WORD_COUNT',
  'UNKNOWN_WORD',
  'INVALID_CHECKSUM',
  'INVALID_MNEMONIC',
  'UNSUPPORTED_PRODUCER',
  'UNSUPPORTED_VERSION',
  'UNSUPPORTED_PASSPHRASE',
];
for (const c of requiredNegatives) {
  if (!codes.has(c)) fail(`negative matrix missing error code ${c}`);
}
const datCodes = new Set(dat.map((v) => v.errorCode).filter(Boolean));
for (const c of ['DAT_INVALID_MAGIC', 'DAT_UNSUPPORTED_VERSION', 'DAT_MALFORMED', 'DAT_WRONG_PASSWORD', 'DAT_MISSING_FIELD', 'DAT_UNKNOWN_FIELD', 'DAT_DUPLICATE_FIELD', 'DAT_INVALID_FIELD', 'DAT_MNEMONIC_KEY_MISMATCH', 'DAT_KEY_MISMATCH']) {
  if (!datCodes.has(c)) fail(`dat vectors missing error code ${c}`);
}
const keyCodes = new Set(key.map((v) => v.errorCode).filter(Boolean));
for (const c of ['INVALID_KEY_ENCODING', 'INVALID_PRIVATE_SCALAR']) {
  if (!keyCodes.has(c)) fail(`key vectors missing error code ${c}`);
}
if (!signature.some((v) => v.expected === 'INVALID')) fail('signature vectors missing invalid fixtures');
if (!signature.some((v) => v.errorCode === 'SIGNATURE_MALFORMED')) fail('signature vectors missing malformed fixtures');

// ---- canonical byte coverage ----------------------------------------------
const mutations = new Set(canonical.filter((v) => v.operation === 'TAMPER').map((v) => v.mutation));
for (const m of ['REORDER_PAYLOAD_FIELDS', 'CHANGE_TIMESTAMP_MS', 'CHANGE_PAYLOAD_SIZE', 'CHANGE_TRANSACTION_ID', 'CHANGE_PAYLOAD_KIND', 'CHANGE_ALIAS_VALUE', 'NON_ASCII_UTF8_ALIAS']) {
  if (!mutations.has(m)) fail(`canonical vectors missing tamper ${m}`);
}

// ---- lookup cardinality ----------------------------------------------------
const counts = lookup.scenarios.map((s) => s.expected.matchCount);
if (!counts.includes(0)) fail('lookup outcomes missing zero-match scenario');
if (!counts.includes(1)) fail('lookup outcomes missing one-match scenario');
if (!counts.includes(2)) fail('lookup outcomes missing multiple-match scenario');
if (!lookup.scenarios.some((s) => s.expected.deduplicated)) fail('lookup outcomes missing dedup scenario');

// ---- manifest integrity ----------------------------------------------------
if (!existsSync(join(ROOT, 'manifest.json'))) {
  fail('manifest.json missing (run scripts/generate-manifest.mjs)');
} else {
  const { obj: manifest } = readJson(join(ROOT, 'manifest.json'));
  validateAgainst('urn:hushvoting:conformance:identity:v1:schemas:manifest', manifest, 'manifest.json');
  const listed = new Set(manifest.files.map((f) => f.path));
  const expectedFiles = new Set(dataFiles);
  for (const f of manifest.files) {
    const full = join(ROOT, f.path);
    if (!existsSync(full)) {
      fail(`manifest lists missing file ${f.path}`);
      continue;
    }
    const bytes = readFileSync(full);
    const sha = createHash('sha256').update(bytes).digest('hex');
    if (sha !== f.sha256) fail(`manifest digest mismatch for ${f.path}`);
    if (bytes.length !== f.bytes) fail(`manifest byte length mismatch for ${f.path}`);
  }
  for (const f of dataFiles) {
    if (!listed.has(f)) fail(`corpus file not listed in manifest: ${f}`);
  }
  for (const f of manifest.files) {
    if (!expectedFiles.has(f.path)) fail(`manifest lists non-corpus or unexpected file ${f.path}`);
  }
}

// ---- secret-safety spot checks ---------------------------------------------
const joined = Object.values(docs)
  .map((d) => d.raw)
  .join('\n');
if (joined.includes('BEGIN PRIVATE KEY') || joined.includes('BEGIN RSA PRIVATE KEY')) {
  fail('corpus contains PEM private key material');
}
if (joined.includes('PRIVATE_KEY_HEX')) {
  fail('placeholder private-key markers present');
}

console.log(failures === 0 ? `VALIDATION OK (${dataFiles.length} corpus files)` : `VALIDATION FAILED (${failures} failure(s))`);
process.exitCode = failures === 0 ? 0 : 1;
