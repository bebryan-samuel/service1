'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { Vault, MemoryStore, FileStore } = require('../src/vault');
const { Masker } = require('../src/masker');

const fixture = fs.readFileSync(path.join(__dirname, '../fixtures/client_agreement.txt'), 'utf8');
const mk = () => new Masker({ vault: new Vault({ store: new MemoryStore() }) });

test('tokens are stable per document and distinct per entity', async () => {
  const m = mk();
  const a = await m.mask('d1', 'Jane Smith and Robert Johnson. Later Jane Smith again.');
  assert.equal(a.maskedText, '[CLIENT_1] and [CLIENT_2]. Later [CLIENT_1] again.');
  const b = await m.mask('d1', 'Robert Johnson');   // second call, same doc => same token
  assert.equal(b.maskedText, '[CLIENT_2]');
  const c = await m.mask('d2', 'Robert Johnson');   // different doc => independent numbering
  assert.equal(c.maskedText, '[CLIENT_1]');
});

test('round trip: unmask(mask(x)) === x', async () => {
  const m = mk();
  const x = 'Jane Smith paid $250,000 from #AC-99120. Call 555-201-3344. SSN 987-65-4321.';
  const { maskedText } = await m.mask('rt', x);
  assert.ok(!/Jane|250,000|AC-99120|555-201|987-65/.test(maskedText));
  assert.equal(await m.unmask('rt', maskedText), x);
});

test('entities returned by mask() never contain raw values; offsets line up', async () => {
  const m = mk();
  const { maskedText, entities } = await m.mask('e1', fixture);
  assert.ok(entities.length > 10);
  for (const e of entities) {
    assert.deepEqual(Object.keys(e).sort(), ['end', 'maskedEnd', 'maskedStart', 'start', 'token', 'type']);
    assert.equal(maskedText.slice(e.maskedStart, e.maskedEnd), e.token);
  }
});

test('concurrent masks for one document keep numbering consistent', async () => {
  const m = mk();
  const r = await Promise.all(['Jane Smith', 'Robert Johnson', 'Jane Smith', 'Priya Sharma'].map((t) => m.mask('c1', t)));
  assert.equal(r[0].maskedText, r[2].maskedText);
  assert.equal(new Set(r.map((x) => x.maskedText)).size, 3);
});

test('vault: mapping encrypted at rest, file perms 0600, tamper / wrong-document detected', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-'));
  const keyHex = crypto.randomBytes(32).toString('hex');
  const vault = new Vault({ store: new FileStore(dir), keyHex });
  const m = new Masker({ vault });
  await m.mask('enc1', 'Jane Smith, SSN 987-65-4321');
  const file = path.join(dir, 'enc1.map');
  const raw = fs.readFileSync(file, 'utf8');
  assert.ok(!/Jane|Smith|987-65-4321/.test(raw), 'plaintext found on disk');
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.equal((await new Vault({ store: new FileStore(dir), keyHex }).load('enc1')).tokens['[CLIENT_1]'], 'Jane Smith');
  fs.copyFileSync(file, path.join(dir, 'other.map'));           // replay under another id => AAD mismatch
  await assert.rejects(() => vault.load('other'));
});

test('vault rejects path-traversal document ids', async () => {
  const v = new Vault();
  await assert.rejects(() => v.load('../../etc/passwd'), /Invalid documentId/);
});
