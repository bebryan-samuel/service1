'use strict';
const { detect } = require('./detector');
const { TokenMapper } = require('./tokenMapper');
const { tokenRegex } = require('./entities');

/**
 * Masker: text -> masked text + entity list (NO raw values in the result), and back.
 * Every raw value ever seen is also added to `registry` so the logger can strip it even if detection misses it.
 */
class Masker {
  constructor({ vault, registry = new Set() }) {
    this.vault = vault; this.registry = registry; this._locks = new Map();
  }
  _lock(id, fn) {
    const prev = this._locks.get(id) || Promise.resolve();
    const next = prev.then(fn, fn);
    const tail = next.catch(() => {});
    this._locks.set(id, tail);
    tail.then(() => { if (this._locks.get(id) === tail) this._locks.delete(id); });
    return next;
  }

  /** @returns {{documentId, maskedText, entities: {type, token, start, end, maskedStart, maskedEnd}[]}} */
  mask(documentId, text) {
    if (typeof text !== 'string') throw new TypeError('text must be a string');
    return this._lock(documentId, async () => {
      const mapper = new TokenMapper(await this.vault.load(documentId));
      const knownPersons = Object.entries(mapper.state.tokens).filter(([t]) => t.startsWith('[CLIENT_')).map(([, v]) => v);
      const found = detect(text, { knownPersons });
      let out = '', cursor = 0;
      const entities = [];
      for (const e of found) {
        const token = mapper.tokenFor(e);
        out += text.slice(cursor, e.start);
        const maskedStart = out.length;
        out += token;
        entities.push({ type: e.type, token, start: e.start, end: e.end, maskedStart, maskedEnd: out.length });
        cursor = e.end;
        if (e.value.length >= 3) this.registry.add(e.value);
      }
      out += text.slice(cursor);
      for (const v of Object.values(mapper.state.tokens)) if (v.length >= 3) this.registry.add(v);
      await this.vault.save(documentId, mapper.state);
      return { documentId, maskedText: out, entities };
    });
  }

  /** Server-side rehydration (for trusted internal callers). The UI normally rehydrates client-side. */
  async unmask(documentId, text) {
    const { tokens } = await this.vault.load(documentId);
    return String(text).replace(tokenRegex(), (t) => (Object.prototype.hasOwnProperty.call(tokens, t) ? tokens[t] : t));
  }
}
module.exports = { Masker };
