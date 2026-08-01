/**
 * Schema boundary tests (Task 2.2)
 * ================================
 * Valid corpus documents validate against their local JSON Schema 2020-12
 * documents; unknown/missing/wrong-type fields and version mismatches fail;
 * no schema carries remote references; corpus formatting is deterministic.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { validate } from '../scripts/vendor/ajv-bundle.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');

function loadSchemas() {
  const schemas = {};
  for (const f of readdirSync(join(ROOT, 'schemas')).filter((x) => x.endsWith('.schema.json'))) {
    const obj = JSON.parse(readFileSync(join(ROOT, 'schemas', f), 'utf8'));
    schemas[obj.$id] = obj;
  }
  return schemas;
}
const schemas = loadSchemas();

function schemaFor(doc) {
  const byKind = {
    'producer-inventory': 'urn:hushvoting:conformance:identity:v1:schemas:inventory',
    'mnemonic-vectors': 'urn:hushvoting:conformance:identity:v1:schemas:mnemonic-vectors',
    'key-vectors': 'urn:hushvoting:conformance:identity:v1:schemas:key-vectors',
    'dat-vectors': 'urn:hushvoting:conformance:identity:v1:schemas:dat-vectors',
    'canonical-byte-vectors': 'urn:hushvoting:conformance:identity:v1:schemas:canonical-byte-vectors',
    'signature-vectors': 'urn:hushvoting:conformance:identity:v1:schemas:signature-vectors',
    'negative-vectors': 'urn:hushvoting:conformance:identity:v1:schemas:negative-vectors',
    'lookup-outcomes': 'urn:hushvoting:conformance:identity:v1:schemas:lookup-outcomes',
  };
  return byKind[doc.kind];
}

const dataFiles = [];
for (const dir of ['producers', 'vectors', 'lookup']) {
  for (const f of readdirSync(join(ROOT, dir)).filter((x) => x.endsWith('.json'))) {
    dataFiles.push(`${dir}/${f}`);
  }
}
dataFiles.push('inventory.json');

test('all corpus documents validate against their local schemas', () => {
  for (const rel of dataFiles) {
    const doc = JSON.parse(readFileSync(join(ROOT, rel), 'utf8'));
    const schemaId = rel.startsWith('producers/')
      ? 'urn:hushvoting:conformance:identity:v1:schemas:producer'
      : schemaFor(doc);
    assert.ok(schemaId, `${rel} has no mapped schema`);
    const result = validate(schemas[schemaId], doc);
    assert.ok(result.valid, `${rel}: ${result.errors.map((e) => e.instancePath + ' ' + e.message).join('; ')}`);
  }
});

test('unknown properties are rejected (additionalProperties: false)', () => {
  const producer = JSON.parse(readFileSync(join(ROOT, 'producers/p-01-hush-feeds-web-client.json'), 'utf8'));
  const result = validate(schemas['urn:hushvoting:conformance:identity:v1:schemas:producer'], {
    ...producer,
    StrayField: 1,
  });
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.message.includes('additional')));
});

test('missing required fields are rejected', () => {
  const producer = JSON.parse(readFileSync(join(ROOT, 'producers/p-01-hush-feeds-web-client.json'), 'utf8'));
  delete producer.producerId;
  const result = validate(schemas['urn:hushvoting:conformance:identity:v1:schemas:producer'], producer);
  assert.equal(result.valid, false);
  assert.ok(result.errors.some((e) => e.message.includes('producerId')));
});

test('wrong-type and wrong-enum values are rejected', () => {
  const producer = JSON.parse(readFileSync(join(ROOT, 'producers/p-01-hush-feeds-web-client.json'), 'utf8'));
  const wrongType = validate(schemas['urn:hushvoting:conformance:identity:v1:schemas:producer'], {
    ...producer,
    precedence: 'not-a-number',
  });
  assert.equal(wrongType.valid, false);
  const wrongEnum = validate(schemas['urn:hushvoting:conformance:identity:v1:schemas:producer'], {
    ...producer,
    classification: 'MAYBE',
  });
  assert.equal(wrongEnum.valid, false);
});

test('schema version mismatches are rejected', () => {
  const vectors = JSON.parse(readFileSync(join(ROOT, 'vectors/mnemonic-vectors.json'), 'utf8'));
  const result = validate(schemas['urn:hushvoting:conformance:identity:v1:schemas:mnemonic-vectors'], {
    ...vectors,
    schemaVersion: '2.0.0',
  });
  assert.equal(result.valid, false);
  const contract = validate(schemas['urn:hushvoting:conformance:identity:v1:schemas:mnemonic-vectors'], {
    ...vectors,
    contractVersion: 'not-semver',
  });
  assert.equal(contract.valid, false);
});

test('no schema carries remote references', () => {
  for (const schema of Object.values(schemas)) {
    const raw = JSON.stringify(schema);
    assert.ok(!raw.includes('"$ref"'), `schema ${schema.$id} uses $ref (remote references are forbidden)`);
    assert.equal(schema['$id'].startsWith('urn:'), true, `schema ${schema.$id} should use a local urn $id`);
  }
});

test('all JSON documents use canonical formatting (sorted keys, 2-space, LF, final newline)', () => {
  const sortKeys = (o) => {
    if (Array.isArray(o)) return o.map(sortKeys);
    if (o && typeof o === 'object') {
      return Object.fromEntries(Object.keys(o).sort().map((k) => [k, sortKeys(o[k])]));
    }
    return o;
  };
  const jsonFiles = [];
  for (const dir of ['schemas', 'producers', 'vectors', 'lookup']) {
    for (const f of readdirSync(join(ROOT, dir)).filter((x) => x.endsWith('.json'))) {
      jsonFiles.push(`${dir}/${f}`);
    }
  }
  jsonFiles.push('inventory.json', 'manifest.json');
  for (const rel of jsonFiles) {
    const raw = readFileSync(join(ROOT, rel), 'utf8');
    assert.ok(raw.charCodeAt(0) !== 0xfeff, `${rel} has BOM`);
    assert.ok(!raw.includes('\r'), `${rel} has CRLF`);
    assert.ok(raw.endsWith('\n'), `${rel} missing final newline`);
    assert.equal(raw, JSON.stringify(sortKeys(JSON.parse(raw)), null, 2) + '\n', `${rel} keys not canonically sorted`);
  }
});

test('dat duplicate-field vector really contains a duplicate key', () => {
  const dat = JSON.parse(readFileSync(join(ROOT, 'vectors/dat-vectors.json'), 'utf8'));
  const dup = dat.vectors.find((v) => v.id === 'D-011');
  assert.ok(dup, 'D-011 missing');
  const keys = [...dup.payloadJson.matchAll(/"([A-Za-z]+)":/g)].map((m) => m[1]);
  assert.equal(new Set(keys).size, keys.length - 1, 'D-011 must contain exactly one duplicated property');
});
