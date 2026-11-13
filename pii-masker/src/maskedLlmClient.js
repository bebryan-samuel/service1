'use strict';
/**
 * CENTRAL CHOKE POINT. All outbound completion / embedding traffic goes through here:
 *   payload -> deep-mask every string -> serialise -> EGRESS GUARD (fail closed) -> transport
 * No other code path should be able to reach an LLM vendor.
 */
const { detect } = require('./detector');
const { DENY } = require('./lexicon');
const { typeOfToken } = require('./entities');

class LeakBlockedError extends Error {
  constructor(reasons) { super(`Outbound request blocked by PII egress guard (${reasons.join('; ')})`); this.name = 'LeakBlockedError'; this.reasons = reasons; }
}
const SKIP_KEYS = new Set(['model', 'role', 'type', 'encoding_format']);
const HIGH_CONFIDENCE = new Set(['SSN', 'EMAIL', 'PHONE', 'CARD', 'ACCOUNT']);

async function maskDeep(masker, documentId, node, key) {
  if (typeof node === 'string') return SKIP_KEYS.has(key) ? node : (await masker.mask(documentId, node)).maskedText;
  if (Array.isArray(node)) { const o = []; for (const n of node) o.push(await maskDeep(masker, documentId, n, key)); return o; }
  if (node && typeof node === 'object') { const o = {}; for (const [k, v] of Object.entries(node)) o[k] = await maskDeep(masker, documentId, v, k); return o; }
  return node;
}

/** Independent second line of defence: look for any known raw value (and encodings of it) in the final bytes. */
async function egressGuard(vault, documentId, body) {
  const { tokens } = await vault.load(documentId);
  const lowerBody = body.toLowerCase();
  const compactBody = lowerBody.replace(/[^a-z0-9]/g, '');
  const reasons = [];
  for (const [token, value] of Object.entries(tokens)) {
    const type = typeOfToken(token);
    const v = value.toLowerCase();
    const variants = [v, JSON.stringify(value).slice(1, -1).toLowerCase(), encodeURIComponent(value).toLowerCase(), Buffer.from(value).toString('base64').toLowerCase()];
    let hit = variants.some((x) => x.length >= 3 && lowerBody.includes(x));
    if (!hit && ['SSN', 'PHONE', 'CARD', 'ACCOUNT'].includes(type)) {
      const c = v.replace(/[^a-z0-9]/g, '');
      hit = c.length >= 7 && compactBody.includes(c);
    }
    if (!hit && type === 'PERSON') {
      hit = v.split(/\s+/).some((w) => w.length >= 3 && !DENY.has(w) && new RegExp(`\\b${w.replace(/[^a-z'-]/g, '')}\\b`).test(lowerBody));
    }
    if (hit) reasons.push(`known ${type} value for ${token} present`);
  }
  for (const e of detect(body)) if (HIGH_CONFIDENCE.has(e.type)) reasons.push(`detector found unmasked ${e.type}`);
  if (reasons.length) throw new LeakBlockedError([...new Set(reasons)]);
}

function createMaskedLlmClient({ masker, transport, logger, devLog }) {
  if (!masker || typeof transport !== 'function') throw new Error('masker and transport are required');
  async function send(kind, documentId, payload) {
    if (!documentId) throw new Error('documentId is required (token mappings are per document)');
    const masked = await maskDeep(masker, documentId, payload);
    const body = JSON.stringify(masked);
    try { await egressGuard(masker.vault, documentId, body); }
    catch (e) { logger && logger.error(`egress blocked kind=${kind} doc=${documentId}: ${e.message}`); throw e; }
    devLog && devLog.record({ kind, documentId, body });
    logger && logger.info(`outbound ${kind} doc=${documentId} bytes=${Buffer.byteLength(body)}`);
    return transport({ kind, body });
  }
  return {
    /** complete({documentId, model, messages|prompt, ...}) -> vendor response (still masked) */
    complete: ({ documentId, ...payload }) => send('completion', documentId, payload),
    /** embed({documentId, model, input: string|string[]}) -> vendor response */
    embed: ({ documentId, ...payload }) => send('embedding', documentId, payload),
  };
}

/** Real HTTP transport: sends EXACTLY the guarded body string. */
function httpTransport({ url, headers = {} }) {
  return async ({ body }) => {
    const res = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body });
    const text = await res.text();
    if (!res.ok) throw new Error(`LLM vendor HTTP ${res.status}`);
    return JSON.parse(text);
  };
}
module.exports = { createMaskedLlmClient, httpTransport, LeakBlockedError, egressGuard };
