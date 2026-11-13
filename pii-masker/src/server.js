'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { assertId } = require('./vault');

const STATIC = { '/': ['index.html', 'text/html; charset=utf-8'], '/index.html': ['index.html', 'text/html; charset=utf-8'],
  '/rehydrator.js': ['rehydrator.js', 'text/javascript; charset=utf-8'] };
const MAX_BODY = 2 * 1024 * 1024;

function createServer({ masker, vault, client, devLog, logger, apiToken, publicDir = path.join(__dirname, '..', 'public') }) {
  const digest = (s) => crypto.createHash('sha256').update(String(s)).digest();
  const authorized = (req) => {
    const m = /^Bearer (.+)$/.exec(req.headers.authorization || '');
    return !!m && !!apiToken && crypto.timingSafeEqual(digest(m[1]), digest(apiToken));
  };
  const send = (res, code, obj) => {
    const body = JSON.stringify(obj);
    res.writeHead(code, { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
    res.end(body);
  };
  const readJson = (req) => new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', (c) => { size += c.length; if (size > MAX_BODY) { reject(Object.assign(new Error('Payload too large'), { status: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}')); } catch { reject(Object.assign(new Error('Invalid JSON'), { status: 400 })); } });
    req.on('error', reject);
  });

  return http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://x');
      const p = url.pathname;
      logger.info(`${req.method} ${p}`);

      if (req.method === 'GET' && STATIC[p]) {
        const [file, type] = STATIC[p];
        res.writeHead(200, { 'content-type': type, 'x-content-type-options': 'nosniff' });
        return res.end(fs.readFileSync(path.join(publicDir, file)));
      }
      if (req.method === 'GET' && p === '/health') return send(res, 200, { ok: true, encryptedAtRest: vault.encrypted });

      // --- Mask a document (ingest). Response is PII-free. ---
      if (req.method === 'POST' && p === '/documents') {
        if (!authorized(req)) return send(res, 401, { error: 'Unauthorized' });
        const body = await readJson(req);
        if (typeof body.text !== 'string' || !body.text) return send(res, 400, { error: 'text (string) is required' });
        const documentId = body.documentId ? assertId(body.documentId) : crypto.randomUUID();
        const { maskedText, entities } = await masker.mask(documentId, body.text);
        await vault.saveMasked(documentId, maskedText);
        logger.info(`masked doc=${documentId} entities=${entities.length}`);
        return send(res, 201, { documentId, maskedText, entities });
      }
      let m;
      if (req.method === 'GET' && (m = /^\/documents\/([^/]+)\/masked$/.exec(p))) {
        if (!authorized(req)) return send(res, 401, { error: 'Unauthorized' });
        const t = await vault.loadMasked(assertId(m[1]));
        return t == null ? send(res, 404, { error: 'Not found' }) : send(res, 200, { documentId: m[1], maskedText: t });
      }
      // --- Mapping for client-side rehydration (officer-authenticated) ---
      if (req.method === 'GET' && (m = /^\/documents\/([^/]+)\/mapping$/.exec(p))) {
        if (!authorized(req)) return send(res, 401, { error: 'Unauthorized' });
        const { tokens } = await vault.load(assertId(m[1]));
        return Object.keys(tokens).length ? send(res, 200, { documentId: m[1], tokens }) : send(res, 404, { error: 'Not found' });
      }
      if (req.method === 'DELETE' && (m = /^\/documents\/([^/]+)$/.exec(p))) {
        if (!authorized(req)) return send(res, 401, { error: 'Unauthorized' });
        await vault.remove(assertId(m[1])); return send(res, 200, { deleted: true });
      }
      // --- Dev only: run text through the masked client against an echo vendor, then inspect payloads ---
      if (p.startsWith('/dev/')) {
        if (!devLog.enabled) return send(res, 404, { error: 'Not found' });
        if (!authorized(req)) return send(res, 401, { error: 'Unauthorized' });
        if (req.method === 'POST' && p === '/dev/mock-llm') {
          const { documentId, text } = await readJson(req);
          const out = await client.complete({ documentId: assertId(documentId), model: 'mock-llm',
            messages: [{ role: 'system', content: 'You are a compliance reviewer.' }, { role: 'user', content: String(text) }] });
          return send(res, 200, out);
        }
        if (req.method === 'GET' && p === '/dev/payloads') return send(res, 200, { payloads: devLog.list() });
        if (req.method === 'DELETE' && p === '/dev/payloads') { devLog.clear(); return send(res, 200, { cleared: true }); }
      }
      return send(res, 404, { error: 'Not found' });
    } catch (e) {
      logger.error(`request failed: ${e.name}: ${e.message}`);
      if (e.name === 'LeakBlockedError') return send(res, 500, { error: 'Blocked by PII egress guard' });
      return send(res, e.status || (/Invalid documentId/.test(e.message) ? 400 : 500), { error: e.status || /Invalid documentId/.test(e.message) ? e.message : 'Internal error' });
    }
  });
}
module.exports = { createServer };
