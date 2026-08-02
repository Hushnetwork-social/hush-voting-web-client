/**
 * FEAT-004 real-browser qualification block — WebCrypto vector replay.
 *
 * Replays the immutable FEAT-003 suite vectors through the REAL browser
 * WebCrypto primitives the production adapter uses (HKDF-SHA-256 and
 * AES-256-GCM + A-001 AAD binding), proving the browser engine produces the
 * corpus outcomes. Argon2id runs through the exact-pinned noble dependency
 * inside the worker (validated by the Phase 3 KAT replay in Node); this block
 * covers the WebCrypto half of the production path in the actual engine.
 *
 * The harness page is route-served (no dev server left running).
 */
import { test, expect } from '@playwright/test';

const ORIGIN = 'http://localhost:3201';

const HARNESS = `<!doctype html>
<html><head><meta charset="utf-8"><title>vault qualification harness</title></head>
<body><script type="module">
const subtle = crypto.subtle;
const b64url = (s) => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0));
const utf8 = (s) => new TextEncoder().encode(s);
const hex = (bytes) => Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
}
async function hkdf(ikm, salt, info, len) {
  const key = await subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, key, len * 8));
}
async function aesEncrypt(key, nonce, plaintext, aad) {
  const k = await subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
  const combined = new Uint8Array(await subtle.encrypt({ name: 'AES-GCM', iv: nonce, additionalData: aad, tagLength: 128 }, k, plaintext));
  return { ciphertext: combined.slice(0, combined.length - 16), tag: combined.slice(combined.length - 16) };
}
async function run() {
  const results = {};
  const ikm = b64url('cGFzc3dvcmQtYnl0ZXM');
  const salt = b64url('BwcHBwcHBwcHBwcHBwcHBw');

  const credentialKek = await hkdf(ikm, salt, utf8('hush/vault/v1/credential-kek'), 32);
  const mnemonicKek = await hkdf(ikm, salt, utf8('hush/vault/v1/mnemonic-kek'), 32);
  results.s001 = hex(await sha256(credentialKek));
  results.s002 = hex(await sha256(mnemonicKek));

  const aad = Uint8Array.from(atob('eyJhZGFwdGVyQmluZGluZyI6ImxvZ2ljYWwiLCJjcml0aWNhbEV4dGVuc2lvbnMiOltdLCJlbnZlbG9wZUZvcm1hdFZlcnNpb24iOjEsImtkZiI6eyJhbGdvcml0aG0iOiJBcmdvbjJpZCIsIml0ZXJhdGlvbnMiOjIsIm1lbW9yeUtpQiI6MTk0NTYsInBhcmFsbGVsaXNtIjoxfSwicGFyYW1ldGVyU3VpdGVWZXJzaW9uIjoxLCJwbGF0Zm9ybVdyYXBwZXJWZXJzaW9uIjowLCJwcmV2aWV3Ijp7ImFsaWFzIjoiQWxpY2UiLCJlbnZlbG9wZUZvcm1hdFZlcnNpb24iOjEsImxpZmVjeWNsZVN0YXR1cyI6IkFjdGl2ZSIsInBhcmFtZXRlclN1aXRlVmVyc2lvbiI6MSwicmVjb3JkU2NoZW1hVmVyc2lvbiI6MSwic2lnbmluZ0FkZHJlc3NQcmVmaXgiOiIwMTIzNDU2NyIsInNpZ25pbmdBZGRyZXNzU3VmZml4IjoiODlhYmNkIn0sInByb2R1Y2VyIjp7ImlkIjoiaHVzaC12b3RpbmctdHMiLCJ2ZXJzaW9uIjoiMS4wLjAifSwicmVjb3JkR2VuZXJhdGlvbiI6MSwicmVjb3JkUHVycG9zZSI6Im9yZGluYXJ5IiwicmVjb3JkU2NoZW1hVmVyc2lvbiI6MSwic2lnbmluZ0FkZHJlc3MiOiIwMTIzNDU2Nzg5YWJjZGVmIiwic3VpdGVJZCI6Imh1c2gvdmF1bHQvc3VpdGUvdjEiLCJ2YXVsdEdlbmVyYXRpb24iOjF9'), (c) => c.charCodeAt(0));
  const wrapped = await aesEncrypt(new Uint8Array(32).fill(3), new Uint8Array(12).fill(5), utf8('ordinary record payload'), aad);
  results.s003Cipher = hex(await sha256(wrapped.ciphertext));
  results.s003Tag = hex(await sha256(wrapped.tag));


  // RFC 5869 TC1 (S-006) in the real engine.
  const rfc5869 = await hkdf(new Uint8Array(22).fill(0x0b), Uint8Array.from([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]), Uint8Array.from([0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9]), 42);
  results.s006 = hex(rfc5869);

  // Tamper rejection in the real engine.
  const tampered = new Uint8Array(wrapped.ciphertext);
  tampered[0] ^= 0xff;
  let tamperRejected = false;
  try {
    const k = await subtle.importKey('raw', new Uint8Array(32).fill(3), { name: 'AES-GCM' }, false, ['decrypt']);
    const combined = new Uint8Array(tampered.length + 16);
    combined.set(tampered, 0);
    combined.set(wrapped.tag, tampered.length);
    await subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(12).fill(5), additionalData: aad, tagLength: 128 }, k, combined);
  } catch {
    tamperRejected = true;
  }
  results.tamperRejected = tamperRejected;

  // CSPRNG distinctness.
  const r1 = new Uint8Array(32); const r2 = new Uint8Array(32);
  crypto.getRandomValues(r1); crypto.getRandomValues(r2);
  results.cspRandom = hex(r1) !== hex(r2);

  window.__vaultQualResults = results;
}
run().catch((error) => { window.__vaultQualResults = { fatal: String(error) }; });
</script></body></html>`;

test.beforeEach(async ({ context }) => {
  await context.route('**/__vault-qual-harness', (route) =>
    route.fulfill({ status: 200, contentType: 'text/html', body: HARNESS }),
  );
});

test('real browser WebCrypto replays the suite vectors with exact outcomes', async ({ page }) => {
  await page.goto(`${ORIGIN}/__vault-qual-harness`);
  await page.waitForFunction(() => (window as unknown as { __vaultQualResults?: unknown }).__vaultQualResults !== undefined);
  const results = await page.evaluate(() => (window as unknown as { __vaultQualResults: Record<string, string | boolean> }).__vaultQualResults);

  expect(results.fatal).toBeUndefined();
  expect(results.s001).toBe('8222d5d542f8c968553cb0a768e8bd4a2dd2da568743db50f6b613e983c2f18a');
  expect(results.s002).toBe('6b21ea70a0bfc40f75ff242b407b6899e7b7418a1b86fec7fe94d3dc777670b9');
  expect(results.s003Cipher).toBe('2108a393bc4d933c90cb9ae5410946b67f24c96afac9ab9778ffabc3c1e01939');
  expect(results.s003Tag).toBe('cf6950d51982ea37b9f353d92e22274e692da837f19af091fbb7f478b3337539');
  expect(results.s006).toBe('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865');
  expect(results.tamperRejected).toBe(true);
  expect(results.cspRandom).toBe(true);
});
