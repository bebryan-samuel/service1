'use strict';
/** Dev-only viewer buffer: stores exactly the bytes that left the choke point (already masked). Disabled in production. */
function createDevPayloadLog({ enabled = process.env.NODE_ENV !== 'production', max = 50 } = {}) {
  const entries = []; let seq = 0;
  return {
    enabled,
    record({ kind, documentId, body }) {
      if (!enabled) return;
      let parsed; try { parsed = JSON.parse(body); } catch { parsed = body; }
      const tokens = [...new Set(body.match(/\[(?:CLIENT|SSN|CARD|EMAIL|ACCOUNT|PHONE|ADDRESS|AMOUNT)_\d+\]/g) || [])];
      entries.push({ id: ++seq, at: new Date().toISOString(), kind, documentId, bytes: Buffer.byteLength(body), tokens, payload: parsed });
      if (entries.length > max) entries.shift();
    },
    list: () => entries.slice().reverse(),
    clear: () => { entries.length = 0; },
  };
}
module.exports = { createDevPayloadLog };
