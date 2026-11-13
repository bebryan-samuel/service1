'use strict';
/**
 * Regex + heuristic PII detector (dependency-free alternative to Presidio).
 * Entity types: PERSON, EMAIL, PHONE, ADDRESS, SSN, ACCOUNT, CARD, MONEY (person-associated only).
 * detect(text) -> [{ type, start, end, value, key }]  (non-overlapping, sorted)
 */
const { TYPES } = require('./entities');
const { FIRST_NAMES, DENY, ORG_ALLOW } = require('./lexicon');

const WORD = "(?:O'|D')?[A-Z][a-z]+(?:-[A-Z][a-z]+)?";
const TITLE = '(?:Mr|Mrs|Ms|Mx|Dr|Miss)';
const SEQ_RE = new RegExp(`\\b${WORD}(?:[ \\t]+(?:[A-Z]\\.|${WORD}))*`, 'g');
const LABEL_RE = new RegExp(
  '\\b(?:Client|Co-investor|Co-client|Investor|Beneficiary|Trustee|Advisor|Adviser|Name|Account Holder|Account Owner|' +
  'Owner|Joint Holder|Spouse|Prepared for|Signed by|Signature|Attn|Attention|Dear|Hi|Hello)\\b[ \\t]*:?[ \\t]+' +
  `(?:${TITLE}\\.?[ \\t]+)?(${WORD}(?:[ \\t]+(?:[A-Z]\\.|${WORD})){0,3})`, 'gd');
const TITLED_RE = new RegExp(`\\b${TITLE}\\.?[ \\t]+(${WORD}(?:[ \\t]+${WORD})?)`, 'gd');

const EMAIL_RE = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/g;
const SSN_RES = [/(?<![\d-])\d{3}[- ]\d{2}[- ]\d{4}(?![\d-])/g,
  /\b(?:SSN|SS#|social security(?: number)?)[ \t]*[:#]?[ \t]*(\d{9})\b/gid];
const PHONE_RES = [
  /(?<![\d-])(?:\+?1[\s.-]?)?(?:\(\d{3}\)\s?|\d{3}[\s.-])\d{3}[\s.-]\d{4}(?![\d-])/g,
  /(?<![\d-])\+\d{1,3}[ -]?\d{2,4}[ -]\d{3,4}[ -]\d{3,4}(?![\d-])/g,
];
const ACCOUNT_RES = [
  /#?\b[A-Z]{2,4}-\d{4,12}\b/g,
  /\b(?:account|acct|a\/c|routing|iban|policy)\s*(?:number|no\.?|num|#)?\s*[:#]?\s*(#?(?=[A-Z0-9-]*\d{4})[A-Z0-9][A-Z0-9-]{4,})/gid,
];
const CARD_RE = /(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)/g;
const STREET = 'Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl|Terrace|Parkway|Pkwy|Highway|Hwy|Circle|Cir|Square|Trail|Plaza';
const ADDRESS_RES = [
  new RegExp(`\\b\\d{1,6}[ \\t]+(?:[A-Z][A-Za-z.'-]*[ \\t]+){1,4}?(?:${STREET})\\b` +
    `(?:,?[ \\t]+(?:Apt|Suite|Ste|Unit|Floor|Fl)\\.?[ \\t]*#?\\w+)?` +
    `(?:,[ \\t]*[A-Z][A-Za-z.' -]+,[ \\t]*[A-Z]{2}[ \\t]+\\d{5}(?:-\\d{4})?)?`, 'g'),
  /\bP\.?O\.? Box \d+\b/gi,
];
const MONEY_RE = /(?:US\$|USD\s?|\$)\s?\d[\d,]*(?:\.\d+)?(?:\s?(?:[Mm]illion|[Bb]illion|[Tt]housand|[MKB])\b)?/g;
const MONEY_CUE = /\b(?:balance|deposit(?:ed)?|net worth|portfolio|holdings|income|salary|invested|contribut(?:ion|ed)|withdr(?:awal|ew)|account value|assets|savings|owes|owed|loan|mortgage)\b/i;
const MONEY_NEAR = 80;

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const isInitial = (w) => /^[A-Z]\.$/.test(w);
const lower = (s) => s.toLowerCase();

function luhn(digits) {
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n; alt = !alt;
  }
  return sum % 10 === 0;
}

function canonPerson(v) { return lower(v).replace(/[^a-z\s'-]/g, ' ').replace(/\s+/g, ' ').trim(); }
function normalizeKey(type, value) {
  switch (type) {
    case 'SSN': case 'CARD': return value.replace(/\D/g, '');
    case 'PHONE': { const d = value.replace(/\D/g, ''); return d.length === 11 && d[0] === '1' ? d.slice(1) : d; }
    case 'ACCOUNT': return lower(value).replace(/[^a-z0-9]/g, '');
    case 'EMAIL': return lower(value.trim());
    case 'ADDRESS': return lower(value).replace(/[,.]/g, ' ').replace(/\s+/g, ' ').trim();
    case 'MONEY': return lower(value).replace(/\s+/g, '');
    default: return canonPerson(value);
  }
}

function collect(text, re, type, group, out, filter) {
  for (const m of text.matchAll(re)) {
    let s, e;
    if (group && m.indices && m.indices[group]) [s, e] = m.indices[group]; else { s = m.index; e = m.index + m[0].length; }
    if (filter && !filter(text.slice(s, e))) continue;
    out.push({ type, start: s, end: e });
  }
}

function wordsOf(text, base) {
  return [...text.matchAll(/\S+/g)].map((w) => ({ t: w[0], s: base + w.index, e: base + w.index + w[0].length }));
}

function findPersons(text, out) {
  // 1) First-name heuristic: <FirstName> [Initial] <Surname> [Surname]
  for (const m of text.matchAll(SEQ_RE)) {
    const words = wordsOf(m[0], m.index);
    for (let i = 0; i < words.length; i++) {
      const lw = lower(words[i].t);
      if (!FIRST_NAMES.has(lw) || DENY.has(lw)) continue;
      let last = i, surnames = 0, j = i + 1;
      while (j < words.length && surnames < 2) {
        if (isInitial(words[j].t)) { j++; continue; }
        if (DENY.has(lower(words[j].t))) break;
        last = j; surnames++; j++;
      }
      if (last === i) continue;
      const s = words[i].s, e = words[last].e;
      if (!ORG_ALLOW.has(lower(text.slice(s, e)))) out.push({ type: 'PERSON', start: s, end: e });
      i = last;
    }
  }
  // 2) Strong cues: "Client: X", "Dear X", "Ms. X" ...
  const cue = (re, mode) => {
    for (const m of text.matchAll(re)) {
      const [gs] = m.indices[1];
      const words = wordsOf(m[1], gs);
      let end = words.length;
      const bad = words.findIndex((w) => DENY.has(lower(w.t)));
      if (bad === 0) continue;
      if (bad > 0) { if (mode === 'strict') continue; end = bad; }
      const kept = words.slice(0, end);
      while (kept.length && isInitial(kept[kept.length - 1].t)) kept.pop();
      if (!kept.length) continue;
      const s = kept[0].s, e = kept[kept.length - 1].e;
      if (!ORG_ALLOW.has(lower(text.slice(s, e)))) out.push({ type: 'PERSON', start: s, end: e });
    }
  };
  cue(LABEL_RE, 'strict');
  cue(TITLED_RE, 'trim');
}

/** Same person, different surface forms ("Jane Smith", "Jane", "Ms. Smith") -> same key + extra spans. */
function propagatePersons(text, spans, known = []) {
  const persons = spans.filter((s) => s.type === 'PERSON').map((s) => text.slice(s.start, s.end)).concat(known);
  const parts = new Map(); // lower part -> Set(full keys)
  const cased = new Map(); // lower part -> Set(cased forms)
  for (const val of persons) {
    const key = canonPerson(val);
    if (key.split(' ').length < 2) continue;
    for (const w of val.split(/\s+/)) {
      const c = w.replace(/\.$/, '');
      if (c.length < 3 || DENY.has(lower(c)) || isInitial(w)) continue;
      const l = lower(c);
      if (!parts.has(l)) { parts.set(l, new Set()); cased.set(l, new Set()); }
      parts.get(l).add(key); cased.get(l).add(c);
    }
  }
  const unique = (l) => (parts.get(l) && parts.get(l).size === 1 ? [...parts.get(l)][0] : null);
  for (const [l, forms] of cased) {
    if (!unique(l)) continue;
    for (const f of forms) for (const m of text.matchAll(new RegExp(`\\b${esc(f)}\\b`, 'g'))) {
      spans.push({ type: 'PERSON', start: m.index, end: m.index + f.length });
    }
  }
  for (const s of spans) {
    if (s.type !== 'PERSON') continue;
    const key = canonPerson(text.slice(s.start, s.end));
    s.key = key.includes(' ') ? key : (unique(key) || key);
  }
}

/**
 * Overlap resolution (fail-closed). Overlapping spans form a cluster; the cluster becomes ONE span.
 * If the highest-priority member already covers the cluster it wins as-is (e.g. a name inside an address
 * -> ADDRESS). On partial overlap the union is masked under the highest-priority type so no fragment leaks.
 */
function resolveSpans(text, spans) {
  const sorted = [...spans].sort((a, b) => a.start - b.start || b.end - a.end);
  const clusters = [];
  let cur = null;
  for (const sp of sorted) {
    if (cur && sp.start < cur.end) { cur.members.push(sp); cur.end = Math.max(cur.end, sp.end); }
    else { cur = { start: sp.start, end: sp.end, members: [sp] }; clusters.push(cur); }
  }
  return clusters.map((c) => {
    const win = c.members.reduce((a, b) => {
      const pa = TYPES[a.type].priority, pb = TYPES[b.type].priority;
      return pb > pa || (pb === pa && b.end - b.start > a.end - a.start) ? b : a;
    });
    const covers = win.start === c.start && win.end === c.end;
    const value = text.slice(c.start, c.end);
    const key = covers && win.key ? win.key : normalizeKey(win.type, value);
    return { type: win.type, start: c.start, end: c.end, value, key };
  });
}

function findMoney(text, anchors) {
  const out = [];
  for (const m of text.matchAll(MONEY_RE)) {
    const start = m.index;
    let end = m.index + m[0].length;
    while (text[end - 1] === ',') end--;
    const before = text.slice(Math.max(0, start - 50), start);
    let linked = MONEY_CUE.test(before);
    if (!linked) {
      for (const a of anchors) {
        let between;
        if (a.end <= start) between = text.slice(a.end, start);
        else if (a.start >= end) between = text.slice(end, a.start);
        else continue;
        if (between.length > MONEY_NEAR) continue;
        const cleaned = between.replace(/\b(?:Mr|Mrs|Ms|Dr|Mx|St|No)\./g, '');
        if (!/\n|[.!?](?=\s+[A-Z])/.test(cleaned)) { linked = true; break; }
      }
    }
    if (linked) out.push({ type: 'MONEY', start, end });
  }
  return out;
}

/**
 * @param {string} text
 * @param {{knownPersons?: string[]}} opts  full names already mapped for this document (so a chunk that only says
 *        "Jane" or "Ms. Smith" still resolves to the same person as an earlier chunk that said "Jane Smith").
 */
function detect(text, { knownPersons = [] } = {}) {
  if (typeof text !== 'string' || !text) return [];
  const raw = [];
  const known = knownPersons.filter((n) => n.trim().split(/\s+/).length >= 2);
  for (const n of known) collect(text, new RegExp(`\\b${esc(n.trim()).replace(/\\? /g, '\\s+')}\\b`, 'g'), 'PERSON', 0, raw);
  for (const re of SSN_RES) collect(text, re, 'SSN', re.hasIndices ? 1 : 0, raw);
  collect(text, EMAIL_RE, 'EMAIL', 0, raw);
  for (const re of PHONE_RES) collect(text, re, 'PHONE', 0, raw);
  for (const re of ACCOUNT_RES) collect(text, re, 'ACCOUNT', re.hasIndices ? 1 : 0, raw);
  collect(text, CARD_RE, 'CARD', 0, raw, (v) => { const d = v.replace(/\D/g, ''); return d.length >= 13 && d.length <= 19 && luhn(d); });
  for (const re of ADDRESS_RES) collect(text, re, 'ADDRESS', 0, raw);
  findPersons(text, raw);
  propagatePersons(text, raw, known);
  const base = resolveSpans(text, raw);
  const money = findMoney(text, base);
  return resolveSpans(text, [...base, ...money]);
}

module.exports = { detect, resolveSpans, normalizeKey, luhn };
