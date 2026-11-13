'use strict';
const { Vault, MemoryStore, FileStore } = require('./vault');
const { Masker } = require('./masker');
const { createLogger } = require('./logger');
const { createMaskedLlmClient, httpTransport, LeakBlockedError } = require('./maskedLlmClient');
const { createDevPayloadLog } = require('./devPayloadLog');
const { createServer } = require('./server');
const { detect } = require('./detector');

/** Wire up the whole service. `transport` = async ({kind, body}) => vendorResponse */
function createService({ store, keyHex, transport, sink, devEnabled } = {}) {
  const registry = new Set();
  const logger = createLogger({ sink, registry });
  const vault = new Vault({ store: store || new MemoryStore(), keyHex });
  const masker = new Masker({ vault, registry });
  const devLog = createDevPayloadLog(devEnabled === undefined ? {} : { enabled: devEnabled });
  const echo = async ({ body }) => ({ id: 'mock', note: 'echo vendor', received_bytes: Buffer.byteLength(body),
    choices: [{ message: { role: 'assistant', content: 'Mock review complete.' } }] });
  const client = createMaskedLlmClient({ masker, logger, devLog, transport: transport || echo });
  return { vault, masker, logger, devLog, client, registry };
}
module.exports = { createService, createServer, Vault, MemoryStore, FileStore, Masker, createLogger,
  createMaskedLlmClient, httpTransport, LeakBlockedError, createDevPayloadLog, detect };
