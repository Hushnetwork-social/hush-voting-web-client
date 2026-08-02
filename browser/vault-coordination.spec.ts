/**
 * FEAT-004 focused real-browser coordination block.
 *
 * Proves in a REAL supported browser engine (Chromium):
 * 1. a SharedWorker served from the same origin is a SINGLE shared authority
 *    instance across two tabs (counter shared);
 * 2. an exclusive Web Lock held by one tab blocks a second tab (never steal);
 * 3. after the owner closes, the second tab acquires the lock (takeover after
 *    proven release).
 *
 * Routes are context-scoped so every page and the worker script share the
 * fulfillment. The worker is test infrastructure only, never production
 * delivery (production workers are first-party module bundles wired in
 * Phase 6). No dev server is left running.
 */
import { test, expect } from '@playwright/test';

const ORIGIN = 'http://localhost:3201';
const WORKER_URL = `${ORIGIN}/__vault-test-worker.js`;

const WORKER_SCRIPT = `self.onconnect = (event) => {
  const port = event.ports[0];
  self.__connections = (self.__connections || 0) + 1;
  port.postMessage({ connections: self.__connections });
  port.onmessage = (msg) => { port.postMessage({ echo: msg.data }); };
  port.start();
};`;

const HARNESS = `<!doctype html>
<html><head><meta charset="utf-8"><title>coordination harness</title></head>
<body><script>
window.__connectShared = () => {
  return new Promise((resolve, reject) => {
    try {
      const worker = new SharedWorker('${WORKER_URL}', { name: 'vault-test-authority' });
      worker.port.onmessage = (e) => resolve(e.data);
      worker.port.start();
      worker.port.postMessage('hello');
    } catch (err) {
      reject(String(err));
    }
  });
};
window.__acquireLock = (name, ifAvailable) => {
  return new Promise((resolve) => {
    navigator.locks.request(name, { ifAvailable: ifAvailable === true }, (lock) => {
      if (lock === null) { resolve(false); return null; }
      window.__lockHeld = true;
      window.__releaseLock = () => { window.__lockHeld = false; };
      resolve(true);
      // Hold the lock for the tab lifetime; release hook above keeps state in sync.
      return new Promise((release) => {
        window.__releaseLock = () => { window.__lockHeld = false; release(null); };
      });
    });
  });
};
window.__lockHeldNow = () => window.__lockHeld === true;
</script></body></html>`;

test.beforeEach(async ({ context }) => {
  await context.route('**/__vault-test-worker.js', (route) =>
    route.fulfill({ status: 200, contentType: 'application/javascript', body: WORKER_SCRIPT }),
  );
  await context.route('**/__coordination-harness', (route) =>
    route.fulfill({ status: 200, contentType: 'text/html', body: HARNESS }),
  );
});

test('SharedWorker is a single shared authority across tabs', async ({ context }) => {
  const page1 = await context.newPage();
  await page1.goto(`${ORIGIN}/__coordination-harness`);
  const first = await page1.evaluate(() => (window as unknown as { __connectShared: () => Promise<{ connections: number }> }).__connectShared());

  const page2 = await context.newPage();
  await page2.goto(`${ORIGIN}/__coordination-harness`);
  const second = await page2.evaluate(() => (window as unknown as { __connectShared: () => Promise<{ connections: number }> }).__connectShared());

  // Both tabs reached the SAME shared authority instance: the connection counter
  // carried over from page 1 (1) into page 2's connect (2) on one worker.
  expect(first.connections).toBe(1);
  expect(second.connections).toBe(2);
  await page1.close();
  await page2.close();
});

test('exclusive Web Lock blocks a second tab and releases after owner close', async ({ context }) => {
  const owner = await context.newPage();
  await owner.goto(`${ORIGIN}/__coordination-harness`);
  const held = await owner.evaluate(() => (window as unknown as { __acquireLock: (n: string, i?: boolean) => Promise<boolean> }).__acquireLock('vault-test-lock', true));
  expect(held).toBe(true);

  const contender = await context.newPage();
  await contender.goto(`${ORIGIN}/__coordination-harness`);
  // Never steal: the contender fails to acquire while the owner holds the lock.
  const blocked = await contender.evaluate(() => (window as unknown as { __acquireLock: (n: string, i?: boolean) => Promise<boolean> }).__acquireLock('vault-test-lock', true));
  expect(blocked).toBe(false);

  // Owner closes → lock released → contender acquires (takeover after proven release).
  await owner.close();
  let acquired = false;
  for (let attempt = 0; attempt < 10 && !acquired; attempt += 1) {
    acquired = await contender.evaluate(() => (window as unknown as { __acquireLock: (n: string, i?: boolean) => Promise<boolean> }).__acquireLock('vault-test-lock', true));
    if (!acquired) {
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }
  expect(acquired).toBe(true);
  await contender.close();
});
