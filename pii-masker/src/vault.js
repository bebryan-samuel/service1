'use strict';
/**
 * Secure server-side storage for token mappings (keyed by documentId).
 *  - MemoryStore for tests / ephemeral dev, FileStore for persistence (dir 0700, files 0600, atomic writes)
 *  - Mappings are AES-256-GCM encrypted at rest when a 32-byte key is supplied (documentId bound as AAD)
 *  - The masked text cache is stored separately and is, by construction, PII-free
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { emptyState } = require('./tokenMapper');

const ID_RE = /^[A-Za-z0-9_-]{1,64}$/;
const assertId = (id) => { if (typeof id !== 'string' || !ID_RE.test(id)) throw new Error('Invalid documentId'); return id; };

class MemoryStore {
  constructor() { this.m = new Map(); }
  async get(k) { return this.m.has(k) ? this.m.get(k) : null; }
  async set(k, v) { this.m.set(k, v); }
  async delete(k) { this.m.delete(k); }
}

class FileStore {
  constructor(dir) { this.dir = path.resolve(dir); fs.mkdirSync(this.dir, { recursive: true, mode: 0o700 }); }
  _p(k) { return path.join(this.dir, k.replace(/[^A-Za-z0-9._-]/g, '_')); }
  async get(k) { try { return await fs.promises.readFile(this._p(k), 'utf8'); } catch (e) { if (e.code === 'ENOENT') return null; throw e; } }
  async set(k, v) {
    const p = this._p(k), tmp = `${p}.${process.pid}.tmp`;
    await fs.promises.writeFile(tmp, v, { mode: 0o600 });
    await fs.promises.rename(tmp, p);
  }
  async delete(k) { try { await fs.promises.unlink(this._p(k)); } catch (e) { if (e.code !== 'ENOENT') throw e; } }
}

class Vault {
  /** @param {{store?: object, keyHex?: string}} opts keyHex = 64 hex chars (32 bytes). */
  constructor({ store = new MemoryStore(), keyHex } = {}) {
    this.store = store;
    if (keyHex) {
      if (!/^[0-9a-fA-F]{64}$/.test(keyHex)) throw new Error('MASKER_VAULT_KEY must be 64 hex chars (32 bytes)');
      this.key = Buffer.from(keyHex, 'hex');
    }
    this.encrypted = !!this.key;
  }
  _enc(id, plain) {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', this.key, iv);
    c.setAAD(Buffer.from(id));
    const ct = Buffer.concat([c.update(plain, 'utf8'), c.final()]);
    return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64');
  }
  _dec(id, b64) {
    const buf = Buffer.from(b64, 'base64');
    const d = crypto.createDecipheriv('aes-256-gcm', this.key, buf.subarray(0, 12));
    d.setAAD(Buffer.from(id));
    d.setAuthTag(buf.subarray(12, 28));
    return Buffer.concat([d.update(buf.subarray(28)), d.final()]).toString('utf8');
  }
  async load(documentId) {
    assertId(documentId);
    const raw = await this.store.get(`${documentId}.map`);
    if (!raw) return emptyState();
    return JSON.parse(this.key ? this._dec(documentId, raw) : raw);
  }
  async save(documentId, state) {
    assertId(documentId);
    const json = JSON.stringify(state);
    await this.store.set(`${documentId}.map`, this.key ? this._enc(documentId, json) : json);
  }
  async saveMasked(documentId, maskedText) { assertId(documentId); await this.store.set(`${documentId}.masked`, maskedText); }
  async loadMasked(documentId) { assertId(documentId); return this.store.get(`${documentId}.masked`); }
  async remove(documentId) { assertId(documentId); await this.store.delete(`${documentId}.map`); await this.store.delete(`${documentId}.masked`); }
}

module.exports = { Vault, MemoryStore, FileStore, assertId };
