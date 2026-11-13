# MASKER_LIMITATIONS.md - Known edge cases & residual risk

The masker is a **layered, fail-closed** control, not a guarantee. Layer 1 detects/masks, layer 2 (the egress guard) blocks any
request still containing a *known* raw value. Layer 2 can only catch PII that layer 1 already saw somewhere in the same document.
Items below are things layer 1 can miss; each has a mitigation.

| # | Edge case | Behaviour today | Mitigation / next step |
|---|-----------|-----------------|------------------------|
| 1 | **Names not in the lexicon and without a cue** (e.g. "Oluwaseun Adeyemi" with no "Client:", "Dear", "Mr.") | Missed on first sight | Swap/augment with Presidio `PERSON` NER (spaCy `en_core_web_lg`) behind the same `detect()` interface; extend `lexicon.js`. Names seen once with a cue are then masked everywhere via alias propagation + egress guard. |
| 2 | **ALL-CAPS names** (`JANE SMITH`) outside a cue | Missed | Case-insensitive pass or NER. |
| 3 | **Single first name only**, never seen in full form in the document ("Jane called.") | Missed unless cued (`Dear Jane`) | NER; or enrol known client names from CRM into `knownPersons`. |
| 4 | **Ambiguous surnames** (two people named Smith) | Alias propagation is disabled for ambiguous parts; bare "Smith" may leak | Always use full names / titled forms; CRM enrolment. |
| 5 | **Non-US formats**: addresses outside `<n> <Name> <Street-type>`, non-US IDs (Aadhaar, NINO, SIN, IBAN) | Phone intl format only partly covered; only labelled account/IBAN numbers; no national-ID patterns | Add recognisers (Presidio has many) - one regex each in `detector.js`. |
| 6 | **Person-associated dollar amounts** use a proximity heuristic (same sentence, <=80 chars, or a cue word like *balance/deposit*) | A fee like "minimum balance of $5,000" is masked (over-masking); an amount far from its owner is not | Tunable `MONEY_NEAR` / `MONEY_CUE`. Over-masking is the safe direction, but may blur rule checks about generic fees. |
| 7 | **Org names that look like people** ("Charles Schwab") | Suppressed via small `ORG_ALLOW` list; others (e.g. "Jordan Capital") rely on `DENY` words | Grow the allow-list from compliance feedback. |
| 8 | **Obfuscated PII** ("nine eight seven - six five...", `jane [at] example [dot] com`, digits split by newlines/page breaks, OCR noise) | Not detected by layer 1; the egress guard's *compact* comparison catches digit-only re-formatting of values layer 1 already saw | Pre-normalise OCR text; add obfuscation rules. |
| 9 | **Alias rehydration is lossy by design**: every surface form maps to one token, so "Ms. Smith" re-renders as "Ms. Jane Smith". | Cosmetic only; highlights stay correct because offsets are mapped through `mapRange()` | Optional: store per-occurrence surface forms. |
| 10 | **Token look-alikes in source text**: a document that literally contains `[CLIENT_1]` will be rehydrated | Possible mis-rehydration | Escape/reject input containing token syntax at upload time. |
| 11 | **Model output** may paraphrase or fabricate PII-like strings | Vendor responses are returned still masked and are never rehydrated server-side; frontend only substitutes *known* tokens | Service 2 must validate quotes against the *masked* text. |
| 12 | **Metadata**: file names, PDF properties, document titles | Only text passed to `masker.mask()` is covered | Run `mask()` on filename/metadata before they enter any payload (the deep-mask client already does this for every string in a payload). |
| 13 | **Images / scanned PDFs** | No OCR in this service | OCR upstream, then mask the extracted text. |
| 14 | **Logs registry** (`registry` Set) keeps raw values in process memory to scrub logs | Memory grows with document volume; values live in RAM | Bound/LRU the registry or key it by active documentId in production. |
| 15 | **Key management**: `MASKER_VAULT_KEY` comes from an env var | Fine for dev; weak for prod | Use KMS/HSM envelope encryption, key rotation, per-tenant keys, audit-log mapping reads. |
| 16 | **Authentication** is a single shared bearer token | Demo-grade | Replace with SSO/RBAC; mapping endpoint must be restricted to reviewing officers. |
| 17 | **Timing/size side-channels**: token numbering and payload length reveal the *count* of distinct entities | Accepted | n/a |
| 18 | **Embeddings**: input is masked, so vectors encode tokens (`[CLIENT_1]`) not identities | By design; retrieval by client name will not work against vendor embeddings | Keep name lookups in your own DB. |
