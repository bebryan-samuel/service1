'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { detect, resolveSpans } = require('../src/detector');

const has = (text, type, value) => detect(text).some((e) => e.type === type && e.value === value);

test('POSITIVE: each entity type is detected', () => {
  assert.ok(has('SSN: 987-65-4321', 'SSN', '987-65-4321'));
  assert.ok(has('Her social security number 987654321 is on file', 'SSN', '987654321'));
  assert.ok(has('mail jane.smith@example.com now', 'EMAIL', 'jane.smith@example.com'));
  assert.ok(has('Call (555) 867-5309 today', 'PHONE', '(555) 867-5309'));
  assert.ok(has('Call 555-201-3344 today', 'PHONE', '555-201-3344'));
  assert.ok(has('Call +1 555.201.3344 today', 'PHONE', '+1 555.201.3344'));
  assert.ok(has('Account Number: #AC-99120', 'ACCOUNT', '#AC-99120'));
  assert.ok(has('wire to acct 4402981177 please', 'ACCOUNT', '4402981177'));
  assert.ok(has('Card 4111 1111 1111 1111 expires', 'CARD', '4111 1111 1111 1111'));
  assert.ok(has('He lives at 4521 Maple Avenue, Springfield, IL 62704.', 'ADDRESS', '4521 Maple Avenue, Springfield, IL 62704'));
  assert.ok(has('Send to PO Box 9921', 'ADDRESS', 'PO Box 9921'));
  assert.ok(has('Jane Smith signed', 'PERSON', 'Jane Smith'));
  assert.ok(has('Client: Priya Sharma', 'PERSON', 'Priya Sharma'));
  assert.ok(has('Dear Ms. Alvarez, thank you', 'PERSON', 'Alvarez'));
  assert.ok(has('Dr. Robert Q. Johnson attended', 'PERSON', 'Robert Q. Johnson'));
});

test('POSITIVE: person-associated dollar amounts', () => {
  assert.ok(has('Jane Smith deposited $250,000 last week.', 'MONEY', '$250,000'));
  assert.ok(has('Her account balance is $1.2 million.', 'MONEY', '$1.2 million'));
  assert.ok(has('Robert Johnson, net worth $4,000,000, signed.', 'MONEY', '$4,000,000'));
});

test('NEGATIVE: non-PII financial vocabulary survives untouched', () => {
  const safe = [
    'The S&P 500 gained 4% last year.',
    'We follow FINRA Rule 2210 and SEC Rule 206(4)-1.',
    'Securities and Exchange Commission guidance applies.',
    'Dow Jones Industrial Average closed higher.',
    'Investment Agreement dated 2024-03-15 (Version 3.2.1), page 12 of 50.',
    'We guarantee an 18% return on all investments.',
    'The minimum investment is $10,000 for all clients.',
    'Charles Schwab and Wells Fargo custody assets; Morgan Stanley too.',
    'Section 401(k) plan with a 7.5% yield, ticker AAPL.',
    'The Federal Reserve held rates at 5.25%-5.50%.',
    'Important Disclosure: past performance is no guarantee of future results.',
    'Client Investment Agreement',
  ];
  for (const s of safe) assert.deepEqual(detect(s).map((e) => e.value), [], `false positive in: ${s}`);
});

test('SPAN RESOLUTION: a name inside an address collapses to one ADDRESS span', () => {
  const r = detect('Office: 100 Jane Austen Road, Bath');
  assert.equal(r.length, 1);
  assert.equal(r[0].type, 'ADDRESS');
});

test('SPAN RESOLUTION: partial overlap is merged fail-closed under the higher-priority type', () => {
  const text = 'abcdefghij';
  const r = resolveSpans(text, [{ type: 'PERSON', start: 0, end: 5 }, { type: 'PHONE', start: 3, end: 10 }]);
  assert.equal(r.length, 1);
  assert.deepEqual([r[0].type, r[0].start, r[0].end], ['PHONE', 0, 10]);
});

test('ALIASES: Jane Smith / Jane / Ms. Smith share one identity', () => {
  const r = detect('Jane Smith met us. Jane agreed. Ms. Smith signed.');
  const persons = r.filter((e) => e.type === 'PERSON');
  assert.equal(persons.length, 3);
  assert.equal(new Set(persons.map((p) => p.key)).size, 1);
});

test('Luhn: random 16-digit number is not a card', () => {
  assert.deepEqual(detect('ref 1234 5678 9012 3456 ok').filter((e) => e.type === 'CARD'), []);
});

test('CHUNKING: known names from earlier chunks resolve aliases in later chunks', () => {
  const r = detect("Jane's deposit was confirmed by Ms. Smith.", { knownPersons: ['Jane Smith'] });
  const p = r.filter((e) => e.type === 'PERSON');
  assert.deepEqual(p.map((e) => e.value), ['Jane', 'Smith']);
  assert.equal(new Set(p.map((e) => e.key)).size, 1);
});
