/* Frontend rehydrator / unmasker. Cached analysis stays masked; real values are substituted only at render time. */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory(); else root.Rehydrator = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  var SRC = '\\[(?:CLIENT|SSN|CARD|EMAIL|ACCOUNT|PHONE|ADDRESS|AMOUNT)_\\d+\\]';
  var has = function (o, k) { return Object.prototype.hasOwnProperty.call(o, k); };
  function escapeHtml(s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }

  /** "[CLIENT_1] signed" -> "Jane Smith signed". Unknown tokens are left untouched. */
  function rehydrate(text, tokens) {
    return String(text).replace(new RegExp(SRC, 'g'), function (t) { return has(tokens, t) ? tokens[t] : t; });
  }
  /** Safe HTML (all text escaped) with each rehydrated value wrapped in <mark class="pii" data-token>. */
  function rehydrateHtml(text, tokens) {
    var re = new RegExp(SRC, 'g'), out = '', last = 0, m;
    text = String(text);
    while ((m = re.exec(text))) {
      out += escapeHtml(text.slice(last, m.index));
      out += has(tokens, m[0]) ? '<mark class="pii" data-token="' + m[0] + '">' + escapeHtml(tokens[m[0]]) + '</mark>' : escapeHtml(m[0]);
      last = m.index + m[0].length;
    }
    return out + escapeHtml(text.slice(last));
  }
  /** Translate an offset in MASKED text (e.g. a Service-2 highlight {start,end}) to the rehydrated text. */
  function mapOffset(maskedText, tokens, offset, side) {
    var re = new RegExp(SRC, 'g'), delta = 0, m;
    while ((m = re.exec(maskedText))) {
      var s = m.index, e = s + m[0].length, val = has(tokens, m[0]) ? tokens[m[0]] : m[0], d = val.length - m[0].length;
      if (e <= offset) { delta += d; continue; }
      if (s < offset) return side === 'end' ? e + delta + d : s + delta;
      break;
    }
    return offset + delta;
  }
  function mapRange(maskedText, tokens, start, end) {
    return { start: mapOffset(maskedText, tokens, start, 'start'), end: mapOffset(maskedText, tokens, end, 'end') };
  }
  return { rehydrate: rehydrate, rehydrateHtml: rehydrateHtml, mapOffset: mapOffset, mapRange: mapRange, escapeHtml: escapeHtml };
});
