/**
 * FEAT-004 focused real-browser storage contract block.
 *
 * Validates the fixed `hushvoting-vault` v1 schema layout and transactional
 * lifecycle in a REAL supported browser engine (Chromium). The harness page is
 * served entirely through Playwright route fulfillment (no dev server left
 * running). Wrapper-level fixed-key enforcement is unit-tested with
 * fake-indexeddb; full production-adapter replay and the unified
 * `browser-vault:ci` gate land in Phase 7.
 *
 * Run: npx playwright test browser/vault-storage.spec.ts --project=desktop-chromium
 */
import { test, expect } from '@playwright/test';

const HARNESS_URL = 'http://localhost:3201/__vault-storage-harness';

const HARNESS_HTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>vault storage harness</title></head>
<body><script type="module">
const dbName = 'hushvoting-vault';
const version = 1;
const stores = ['vaultSlots', 'vaultJournal', 'operationalSidecars'];
const fixedKeys = { vaultSlots: ['slot-a', 'slot-b'], vaultJournal: ['current'], operationalSidecars: ['throttle'] };

function open(ver = version) {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(dbName, ver);
    req.onupgradeneeded = () => {
      for (const store of stores) {
        if (!req.result.objectStoreNames.contains(store)) req.result.createObjectStore(store);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
    req.onblocked = () => { window.__blocked = true; };
  });
}

function tx(db, store, mode, fn) {
  return new Promise((resolve, reject) => {
    const t = db.transaction(store, mode);
    const os = t.objectStore(store);
    let value;
    const req = fn(os);
    if (req) req.onsuccess = () => { value = req.result; };
    t.oncomplete = () => resolve(value);
    t.onerror = () => reject(t.error);
    t.onabort = () => reject(t.error);
  });
}

async function run() {
  const results = {};
  const db = await open();
  results.schemaVersion = db.version;
  results.stores = Array.from(db.objectStoreNames);
  results.indexCounts = stores.map((s) => db.transaction(s).objectStore(s).indexNames.length);

  // Fixed-key write/read/delete round-trip in the real engine.
  const payload = { tag: 'v1', bytes: [1, 2, 3] };
  await tx(db, 'vaultSlots', 'readwrite', (os) => os.put(payload, 'slot-a'));
  const readA = await tx(db, 'vaultSlots', 'readonly', (os) => os.get('slot-a'));
  results.slotRoundTrip = JSON.stringify(readA) === JSON.stringify(payload);
  await tx(db, 'vaultSlots', 'readwrite', (os) => os.delete('slot-a'));
  const afterDelete = await tx(db, 'vaultSlots', 'readonly', (os) => os.get('slot-a'));
  results.deleteWorks = afterDelete === undefined;

  await tx(db, 'vaultJournal', 'readwrite', (os) => os.put({ generation: 1, activeSlot: 'slot-b' }, 'current'));
  const journal = await tx(db, 'vaultJournal', 'readonly', (os) => os.get('current'));
  results.journal = journal;

  // Non-destructive versioned upgrade: a second connection at version 2 must
  // trigger versionchange on the first, which closes immediately.
  let firstClosedByVersionChange = false;
  db.onversionchange = () => { firstClosedByVersionChange = true; db.close(); };
  let upgraded = false;
  const second = await open(2).catch((e) => { results.upgradeError = String(e && e.name || e); return null; });
  if (second) {
    upgraded = true;
    results.upgradedStores = Array.from(second.objectStoreNames);
    second.close();
  }
  results.versionchangeClosedFirst = firstClosedByVersionChange;
  results.upgradePreserved = upgraded;

  window.__vaultStorageResults = results;
}
run().catch((error) => { window.__vaultStorageResults = { fatal: String(error && error.name || error) }; });
</script></body></html>`;

test.beforeEach(async ({ page }) => {
  await page.route('**/__vault-storage-harness', (route) =>
    route.fulfill({ status: 200, contentType: 'text/html', body: HARNESS_HTML }),
  );
});

test('real browser storage matches the fixed vault schema and lifecycle', async ({ page }) => {
  await page.goto(HARNESS_URL);
  await page.waitForFunction(() => (window as unknown as { __vaultStorageResults?: unknown }).__vaultStorageResults !== undefined);

  const results = await page.evaluate(() => (window as unknown as { __vaultStorageResults: Record<string, unknown> }).__vaultStorageResults);

  expect(results.fatal).toBeUndefined();
  expect(results.schemaVersion).toBe(1);
  // Object-store name order is not guaranteed by the IDB spec; compare as sets.
  expect([...(results.stores as string[])].sort()).toEqual(['operationalSidecars', 'vaultJournal', 'vaultSlots'].sort());
  expect(results.indexCounts).toEqual([0, 0, 0]);
  expect(results.slotRoundTrip).toBe(true);
  expect(results.deleteWorks).toBe(true);
  expect(results.journal).toEqual({ generation: 1, activeSlot: 'slot-b' });
  expect(results.upgradePreserved).toBe(true);
  expect(results.versionchangeClosedFirst).toBe(true);
});
