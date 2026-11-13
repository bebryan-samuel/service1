# Service 1 - PII Masking & Security Service (AI-1)

A zero-leak privacy wall: raw client identifiers are detected, replaced with stable tokens (`[CLIENT_1]`, `[SSN_1]`...), and the
mapping never leaves the server. External LLM / embedding vendors only ever receive masked text; the officer UI rehydrates real
values at render time.

* **Runtime:** Node.js >= 18, **zero npm dependencies** (regex + heuristics detector; `detect()` is a single interface so Microsoft
  Presidio can be dropped in - see `MASKER_LIMITATIONS.md` #1).
* **Run tests:** `npm test`  (21 tests) - **Demo:** `npm run demo` - **Dev console:** `npm start` -> http://localhost:3000 (token `dev-token`)

## Architecture

```
 raw text -> detector.js -> span resolution -> tokenMapper (per documentId) -> vault.js (AES-256-GCM, server-side)
                                   |
 payload -> maskedLlmClient.complete()/embed()
              1. deep-mask every string   2. serialise   3. EGRESS GUARD (fail closed)   4. transport
                                                              |-> blocks if ANY known raw value (or its base64 /
                                                                  URL-encoded / digits-only form) or high-confidence
                                                                  PII is still in the bytes
 masked at rest ---> GET /documents/:id/masked      mapping ---> GET /documents/:id/mapping (auth)
 public/rehydrator.js: tokens -> real values in the browser, XSS-safe, + mapRange() for Service-2 highlight offsets
```

| File | Task from brief |
|------|-----------------|
| `src/maskedLlmClient.js` | **Central API interceptor** - `complete()`, `embed()`, `httpTransport()`, egress guard |
| `src/detector.js`, `src/lexicon.js` | **Regex & heuristic detector** - Person, Email, Phone, Address, SSN, Account, Card (Luhn), person-associated $ amounts; **overlap/span resolution** (fail-closed clusters); alias propagation |
| `src/tokenMapper.js`, `src/vault.js`, `src/masker.js` | **Per-document token mapper**, server-side encrypted storage keyed by `documentId`, per-document locking |
| `public/rehydrator.js`, `public/index.html` | **Frontend rehydrator** (cached data stays masked; unmask at render) + **dev payload viewer** |
| `src/logger.js` | Logs scrubbed (known values + detector) - nothing raw can reach log sinks |
| `test/*.test.js`, `fixtures/` | **Adversarial verification suite** |
| `MASKER_LIMITATIONS.md` | Documented edge cases |

## Acceptance criteria -> proof

| Criterion | Test |
|-----------|------|
| Serialized request bytes to AI APIs contain zero raw PII | `integration.test.js` "ACCEPTANCE 1": a local mock vendor captures the **raw HTTP bytes** (request line + headers + body) for completion + embedding calls and asserts none of 24 PII strings (incl. digit-only/compact forms) appear, while `S&P 500`, `Charles Schwab` and the "guarantee 18%" text survive |
| Logs contain masked text only | "ACCEPTANCE 2": raw document, an `Error`, and an object are logged; every emitted line is re-checked |
| UI rehydrates `[CLIENT_1]` -> real name | "ACCEPTANCE 3" (HTTP end-to-end) + `rehydrator.test.js` |
| Positive/negative unit tests | `detector.test.js` (S&P 500, FINRA Rule 2210, "$10,000 minimum", Charles Schwab... all survive) |
| Defence in depth | "EGRESS GUARD" test simulates a masking bug and proves the vendor is never called |

## HTTP API (all except `/health`, static files require `Authorization: Bearer $MASKER_API_TOKEN`)

| Method & path | Purpose |
|---|---|
| `POST /documents` `{text, documentId?}` | Mask + store. Response: `{documentId, maskedText, entities:[{type, token, start, end, maskedStart, maskedEnd}]}` - never raw values |
| `GET /documents/:id/masked` | Cached masked text |
| `GET /documents/:id/mapping` | `{tokens}` for client-side rehydration (restrict to officers) |
| `DELETE /documents/:id` | Remove mapping + cache (retention) |
| `POST /dev/mock-llm`, `GET/DELETE /dev/payloads` | Dev only (404 when `NODE_ENV=production`): see exactly what would be sent to a vendor |

## Using it from Service 2 (AI Compliance Agent)

```js
const { createService, httpTransport } = require('./src');
const svc = createService({ transport: httpTransport({ url: 'https://api.openai.com/v1/chat/completions', headers: { authorization: `Bearer ${KEY}` } }),
                            store: new FileStore('./data'), keyHex: process.env.MASKER_VAULT_KEY });
const { maskedText, entities } = await svc.masker.mask(documentId, rawText);      // persist maskedText only
const res = await svc.client.complete({ documentId, model: '...', messages: [{ role: 'user', content: section }] });
// Service 2 validates quotes against maskedText; the UI maps highlight offsets with Rehydrator.mapRange(maskedText, tokens, start, end)
```

## Configuration

| Env | Meaning |
|---|---|
| `MASKER_VAULT_KEY` | 64 hex chars (32 bytes) - enables FileStore + AES-256-GCM. Generate: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"` |
| `MASKER_API_TOKEN` | bearer token (required in production; `dev-token` in dev) |
| `MASKER_STORE_DIR`, `PORT`, `NODE_ENV` | storage dir (default `./data`), port (3000), `production` disables dev routes and requires the two secrets |

## Design decisions worth calling out
* **Fail closed:** overlapping detections are merged into the union span; a blocked request raises `LeakBlockedError` (message lists types/tokens, never values).
* **Stable tokens:** same entity -> same token across sections and calls; "Jane Smith", "Jane", "Ms. Smith" share `[CLIENT_1]`; earlier chunks seed later chunks (`knownPersons`), a bug the egress guard caught during development.
* **Mapping isolation:** mappings live only in the vault; `mask()` results, logs, dev viewer and error messages contain none.
* **Path traversal / injection:** `documentId` is whitelisted (`[A-Za-z0-9_-]{1,64}`); rehydrator HTML-escapes all document text.
