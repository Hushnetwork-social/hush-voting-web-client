// FEAT-017 artifact-scan regression: a run of lowercase words in a test title
// is not secret material (negative); an actual quoted BIP39 mnemonic and a
// private-key PEM header still fail the privacy gate (positive). Run with:
//   node --test scripts/licence-upgrade/artifact-scan.test.mjs
import test from 'node:test';
import assert from 'node:assert/strict';
import { wordlists } from 'bip39';
import { findProhibitedArtifactContent, isMnemonicRun } from './artifact-scan.mjs';

test('an ordinary lowercase test title is not a mnemonic finding', () => {
  const title = '"removal confirmation retains the verified preview for fresh confirmed removal after live cleanup fails"';
  assert.equal(isMnemonicRun('removal confirmation retains the verified preview for fresh confirmed removal after live cleanup fails'), false);
  assert.deepEqual(findProhibitedArtifactContent(title), []);
});

test('a quoted 12-word BIP39 run remains a mnemonic finding', () => {
  const mnemonic = wordlists.english.slice(0, 12).join(' ');
  assert.equal(isMnemonicRun(mnemonic), true);
  assert.deepEqual(findProhibitedArtifactContent(`"${mnemonic}"`), ['mnemonic phrase']);
});

test('a private-key PEM header remains a finding beside ordinary prose', () => {
  const pem = '-----BEGIN ' + 'EC PRIVATE KEY' + '-----';
  const content = `"removal confirmation retains the verified preview after live cleanup fails"\n${pem}\n`;
  assert.ok(findProhibitedArtifactContent(content).includes('private key PEM header'));
});
