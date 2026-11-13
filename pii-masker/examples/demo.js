'use strict';
// CLI demo for reviewers:  node examples/demo.js fixtures/client_agreement.txt
const fs = require('fs');
const { createService } = require('../src');
const R = require('../public/rehydrator.js');

const file = process.argv[2] || 'fixtures/client_agreement.txt';
const text = fs.readFileSync(file, 'utf8');
const hr = (t) => console.log(`\n\x1b[1m=== ${t} ===\x1b[0m`);

(async () => {
  const outbound = [];
  const svc = createService({ transport: async ({ body }) => { outbound.push(body); return { choices: [{ message: { content: 'ok' } }] }; }, sink: console });
  const id = 'demo-doc';

  hr('1. RAW (server only)'); console.log(text);
  const { maskedText, entities } = await svc.masker.mask(id, text);
  hr('2. MASKED (what is stored / cached)'); console.log(maskedText);
  hr('3. ENTITY SUMMARY (no raw values)');
  const byType = {}; for (const e of entities) byType[e.type] = (byType[e.type] || 0) + 1; console.table(byType);

  await svc.client.complete({ documentId: id, model: 'demo-llm', messages: [{ role: 'user', content: text }] });
  hr('4. EXACT BYTES SENT TO THE AI VENDOR'); console.log(JSON.stringify(JSON.parse(outbound[0]), null, 2));

  const { tokens } = await svc.vault.load(id);
  hr('5. OFFICER VIEW (rehydrated at render time)'); console.log(R.rehydrate(maskedText, tokens));

  hr('6. EGRESS GUARD - simulated masking bypass');
  const { createMaskedLlmClient } = require('../src');
  const bypass = Object.create(svc.masker); bypass.mask = async (_i, t) => ({ maskedText: t });
  try { await createMaskedLlmClient({ masker: bypass, transport: async () => ({}), logger: svc.logger }).complete({ documentId: id, prompt: text }); }
  catch (e) { console.log('BLOCKED ->', e.name, ':', e.message); }
})();
