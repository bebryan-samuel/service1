'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const R = require('../public/rehydrator.js');

const tokens = { '[CLIENT_1]': 'Jane Smith', '[SSN_1]': '987-65-4321' };

test('rehydrate substitutes known tokens, leaves unknown ones', () => {
  assert.equal(R.rehydrate('[CLIENT_1] has [SSN_1] and [CLIENT_9]', tokens), 'Jane Smith has 987-65-4321 and [CLIENT_9]');
});
test('rehydrateHtml escapes document text (no XSS) and marks values', () => {
  const html = R.rehydrateHtml('<img src=x onerror=1> [CLIENT_1]', { '[CLIENT_1]': '<b>Jane</b>' });
  assert.ok(!html.includes('<img') && !html.includes('<b>'));
  assert.ok(html.includes('<mark class="pii" data-token="[CLIENT_1]">&lt;b&gt;Jane&lt;/b&gt;</mark>'));
});
test('mapRange moves masked-text highlights onto rehydrated text', () => {
  const masked = 'Hello [CLIENT_1], we guarantee 18%.';
  const re = R.rehydrate(masked, tokens);
  const s = masked.indexOf('we guarantee'), e = s + 'we guarantee 18%'.length;
  const r = R.mapRange(masked, tokens, s, e);
  assert.equal(re.slice(r.start, r.end), 'we guarantee 18%');
  const t = masked.indexOf('[CLIENT_1]');
  const rt = R.mapRange(masked, tokens, t, t + 10);
  assert.equal(re.slice(rt.start, rt.end), 'Jane Smith');
});
