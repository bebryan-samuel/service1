'use strict';
/**
 * ACCEPTANCE CRITERIA:
 *  1. Serialized request bytes to AI APIs contain zero raw PII.
 *  2. Application logs contain scrubbed/masked text only.
 *  3. Frontend rehydrates [CLIENT_1] -> real name at render time (see rehydrator.test.js + server test below).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const http = require('http');
const path = require('path');
const { createService, httpTransport, LeakBlockedError, createServer } = require('../src');
const R = require('../public/rehydrator.js');

const fixture = fs.readFileSync(path.join(__dirname, '../fixtures/client_agreement.txt'), 'utf8');
const PII = JSON.parse(fs.readFileSync(path.join(__dirname, '../fixtures/client_agreement.pii.json'), 'utf8'));
const leaks = (buf) => {
  const s = buf.toString('utf8').toLowerCase(), compact = s.replace(/[^a-z0-9]/g, '');
  return PII.filter((p) => s.includes(p.toLowerCase()) || (/\d{7,}/.test(p.replace(/\D/g, '')) && p.replace(/[^a-z0-9]/gi, '').length >= 7 && compact.includes(p.replace(/[^a-z0-9]/gi, '').toLowerCase())));
};
const listen = (srv) => new Promise((r) => srv.listen(0, '127.0.0.1', () => r(srv.address().port)));

async function captureServer() {
  const captured = [];
  const srv = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      captured.push(Buffer.concat([Buffer.from(`${req.method} ${req.url} HTTP/1.1\r\n${req.rawHeaders.join('\r\n')}\r\n\r\n`), ...chunks]));
      res.setHeader('content-type', 'application/json');
      res.end(JSON.stringify({ choices: [{ message: { content: 'Flag: "We guarantee an 18% return" - owner [CLIENT_1]' } }], data: [{ embedding: [0.1, 0.2] }] }));
    });
  });
  const port = await listen(srv);
  return { captured, url: `http://127.0.0.1:${port}/v1`, close: () => { srv.closeAllConnections(); srv.close(); } };
}

test('ACCEPTANCE 1: raw bytes sent to the AI vendor contain ZERO raw PII (completion + embedding)', async () => {
  const cap = await captureServer();
  const svc = createService({ transport: httpTransport({ url: cap.url, headers: { authorization: 'Bearer sk-test' } }), sink: { log() {}, info() {}, warn() {}, error() {} } });
  const docId = 'doc-int-1';
  const sections = fixture.split(/\n\n/);
  await svc.client.complete({ documentId: docId, model: 'gpt-x', messages: [{ role: 'system', content: 'Review for SEC/FINRA issues.' }, { role: 'user', content: fixture }] });
  for (const s of sections) await svc.client.embed({ documentId: docId, model: 'embed-x', input: [s] });
  await svc.client.complete({ documentId: docId, model: 'gpt-x', prompt: 'Is the claim by Jane Smith (SSN 987-65-4321) OK?' });
  cap.close(); 

  assert.ok(cap.captured.length >= 3);
  for (const bytes of cap.captured) assert.deepEqual(leaks(bytes), [], 'raw PII found in outbound bytes');
  const first = cap.captured[0].toString('utf8');
  assert.match(first, /\[CLIENT_1\]/);
  assert.match(first, /\[SSN_1\]/);
  assert.ok(first.includes('S&P 500'), 'non-PII terms must survive');
  assert.ok(first.includes('We guarantee an 18% return'), 'compliance-relevant text must survive');
  assert.ok(first.includes('Charles Schwab'));
});

test('EGRESS GUARD: blocks and never calls the vendor if masking is bypassed', async () => {
  let called = 0;
  const svc = createService({ transport: async () => { called++; return {}; }, sink: { log() {}, info() {}, warn() {}, error() {} } });
  await svc.masker.mask('doc-g', fixture);                       // populate the vault
  const bypass = Object.create(svc.masker); bypass.mask = async (id, t) => ({ maskedText: t });   // simulate a bug
  const { createMaskedLlmClient } = require('../src');
  const bad = createMaskedLlmClient({ masker: bypass, transport: async () => { called++; return {}; } });
  await assert.rejects(() => bad.complete({ documentId: 'doc-g', model: 'm', prompt: fixture }), (e) => {
    assert.ok(e instanceof LeakBlockedError);
    assert.deepEqual(leaks(Buffer.from(e.message)), [], 'error message itself must not leak PII');
    return true;
  });
  // variants: base64 / url-encoded / digits-only forms are caught too
  for (const sneaky of [Buffer.from('Jane Smith').toString('base64'), encodeURIComponent('Jane Smith'), '987654321', 'robert johnson']) {
    await assert.rejects(() => bad.embed({ documentId: 'doc-g', input: `x ${sneaky} y` }), LeakBlockedError);
  }
  assert.equal(called, 0);
});

test('ACCEPTANCE 2: application logs contain masked/scrubbed text only', async () => {
  const lines = [];
  const sink = { log: (l) => lines.push(l), info: (l) => lines.push(l), warn: (l) => lines.push(l), error: (l) => lines.push(l) };
  const svc = createService({ sink });
  await svc.client.complete({ documentId: 'doc-log', model: 'm', prompt: fixture });
  svc.logger.info('raw text accidentally logged:', fixture);                 // developer mistake
  svc.logger.error(new Error('failed for Jane Smith ssn 987-65-4321'));      // PII inside an error
  svc.logger.warn({ owner: 'Robert Johnson', phone: '555-201-3344' });       // PII inside an object
  svc.logger.info('unknown-to-detector secret', 'zzqx-internal');            // not matchable by regex...
  assert.ok(lines.length >= 4);
  for (const l of lines) assert.deepEqual(leaks(Buffer.from(l)), [], `PII in log line: ${l.slice(0, 80)}`);
});

test('ACCEPTANCE 3 (end-to-end): masked at rest, rehydrated for the officer', async () => {
  const svc = createService({});
  const srv = createServer({ ...svc, client: svc.client, apiToken: 'secret-token' });
  const port = await listen(srv);
  const base = `http://127.0.0.1:${port}`, auth = { authorization: 'Bearer secret-token', 'content-type': 'application/json' };
  try {
    assert.equal((await fetch(`${base}/documents`, { method: 'POST', body: '{}' })).status, 401);
    const created = await fetch(`${base}/documents`, { method: 'POST', headers: auth, body: JSON.stringify({ text: fixture }) });
    const raw = await created.text();
    assert.equal(created.status, 201);
    assert.deepEqual(leaks(Buffer.from(raw)), [], 'POST /documents response leaked PII');
    const { documentId, maskedText } = JSON.parse(raw);

    const cached = await (await fetch(`${base}/documents/${documentId}/masked`, { headers: auth })).text();
    assert.deepEqual(leaks(Buffer.from(cached)), [], 'cached analysis must be masked at rest');

    assert.equal((await fetch(`${base}/documents/${documentId}/mapping`)).status, 401);
    const { tokens } = await (await fetch(`${base}/documents/${documentId}/mapping`, { headers: auth })).json();
    assert.equal(tokens['[CLIENT_1]'], 'Jane Smith');
    const shown = R.rehydrate(maskedText, tokens);
    assert.ok(shown.includes('Client: Jane Smith') && shown.includes('987-65-4321'));
    assert.ok(!/\[(CLIENT|SSN)_\d+\]/.test(shown));

    await fetch(`${base}/dev/mock-llm`, { method: 'POST', headers: auth, body: JSON.stringify({ documentId, text: fixture }) });
    const payloads = await (await fetch(`${base}/dev/payloads`, { headers: auth })).text();
    assert.deepEqual(leaks(Buffer.from(payloads)), [], 'dev payload viewer leaked PII');
    assert.match(payloads, /\[CLIENT_1\]/);
    assert.equal((await fetch(`${base}/documents/..%2F..%2Fx/mapping`, { headers: auth })).status, 400);
  } finally { srv.closeAllConnections(); srv.close(); }
});
