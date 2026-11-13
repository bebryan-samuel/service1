'use strict';
const { TYPES } = require('./entities');

const emptyState = () => ({ version: 1, counters: {}, byKey: {}, tokens: {} });
const wordCount = (s) => String(s).trim().split(/\s+/).length;

/** Per-document mapper: same real value -> same token ([CLIENT_1]) every time, so the LLM keeps context. */
class TokenMapper {
  constructor(state) { this.state = state || emptyState(); }
  tokenFor({ type, key, value }) {
    const s = this.state;
    const k = `${type}|${key}`;
    let token = s.byKey[k];
    if (!token) {
      const p = TYPES[type].prefix;
      s.counters[p] = (s.counters[p] || 0) + 1;
      token = `[${p}_${s.counters[p]}]`;
      s.byKey[k] = token;
      s.tokens[token] = value;
    } else if (type === 'PERSON' && wordCount(value) > wordCount(s.tokens[token])) {
      s.tokens[token] = value; // prefer full name ("Jane Smith") over alias ("Jane")
    }
    return token;
  }
}
module.exports = { TokenMapper, emptyState };
