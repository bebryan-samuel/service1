'use strict';
const path = require('path');
const { createService, createServer, MemoryStore, FileStore } = require('./index');

const prod = process.env.NODE_ENV === 'production';
const keyHex = process.env.MASKER_VAULT_KEY;
const apiToken = process.env.MASKER_API_TOKEN || (prod ? null : 'dev-token');
if (prod && (!keyHex || !apiToken)) { console.error('FATAL: MASKER_VAULT_KEY and MASKER_API_TOKEN are required in production'); process.exit(1); }

const store = keyHex ? new FileStore(process.env.MASKER_STORE_DIR || path.join(__dirname, '..', 'data')) : new MemoryStore();
const svc = createService({ store, keyHex });
if (!keyHex) svc.logger.warn('No MASKER_VAULT_KEY set: using EPHEMERAL in-memory vault (dev only).');
const server = createServer({ ...svc, apiToken });
const port = Number(process.env.PORT || 3000);
server.listen(port, () => {
  svc.logger.info(`PII masker listening on http://localhost:${port}  (dev token: ${prod ? 'hidden' : apiToken})`);
});
