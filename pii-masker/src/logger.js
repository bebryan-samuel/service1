'use strict';
/**
 * PII-safe logger. Every line is (1) stripped of every raw value the masker has ever seen and
 * (2) re-scanned with the detector -> [REDACTED:TYPE]. Never throws.
 */
const { detect } = require('./detector');

function createLogger({ sink = console, registry = new Set(), level = 'info' } = {}) {
  const order = { debug: 0, info: 1, warn: 2, error: 3 };
  const scrub = (input) => {
    let s = String(input);
    for (const v of [...registry].sort((a, b) => b.length - a.length)) if (v && s.includes(v)) s = s.split(v).join('[REDACTED]');
    const ents = detect(s);
    for (let i = ents.length - 1; i >= 0; i--) s = s.slice(0, ents[i].start) + `[REDACTED:${ents[i].type}]` + s.slice(ents[i].end);
    return s;
  };
  const fmt = (a) => {
    if (a instanceof Error) return `${a.name}: ${a.message}`;
    if (typeof a === 'string') return a;
    try { return JSON.stringify(a); } catch { return '[unserialisable]'; }
  };
  const emit = (lvl) => (...args) => {
    try {
      if (order[lvl] < order[level]) return;
      sink[lvl === 'debug' ? 'log' : lvl](`[${lvl}] ${scrub(args.map(fmt).join(' '))}`);
    } catch { /* logging must never break the pipeline */ }
  };
  return { debug: emit('debug'), info: emit('info'), warn: emit('warn'), error: emit('error'), scrub };
}
module.exports = { createLogger };
