'use strict';
// Persistent session → producer-key bindings. The first producer to connect
// on a session binds its key; later producers must present the same key.
// Persisted (as sha256 hashes) so a relay restart or an idle session can't
// let a stranger who knows the session id claim it.
//
// File shape (data/state.json v2):
//   { "version": 2, "bindings": { "<session>": { "keyHash", "boundAt", "lastSeen" } } }

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const DAY = 24 * 60 * 60 * 1000;

class KeyBindings {
  constructor({ file, ttlMs = 90 * DAY, now = Date.now, saveDelayMs = 200, log = () => {} } = {}) {
    this.file = file;
    this.ttlMs = ttlMs;
    this.now = now;
    this.saveDelayMs = saveDelayMs;
    this.log = log;
    this.map = new Map();
    this.saveTimer = null;
  }

  get size() { return this.map.size; }

  static hash(key) { return crypto.createHash('sha256').update(String(key)).digest('hex'); }

  load() {
    if (!this.file) return;
    let j;
    try { j = JSON.parse(fs.readFileSync(this.file, 'utf8')); }
    catch (e) {
      if (e.code !== 'ENOENT') this.log(`could not load ${this.file}: ${e.message}`);
      return;
    }
    if (!j || j.version !== 2 || !j.bindings || typeof j.bindings !== 'object') {
      this.log(`ignoring ${this.file}: unsupported version ${j && j.version}`);
      return;
    }
    const now = this.now();
    let loaded = 0, pruned = 0;
    for (const [session, b] of Object.entries(j.bindings)) {
      if (!b || typeof b.keyHash !== 'string') { pruned++; continue; }
      if (now - (b.lastSeen || 0) > this.ttlMs) { pruned++; continue; }
      this.map.set(session, { keyHash: b.keyHash, boundAt: b.boundAt || now, lastSeen: b.lastSeen || now });
      loaded++;
    }
    this.log(`loaded ${loaded} bindings, pruned ${pruned}`);
  }

  // 'bound'    → no binding existed; this key now owns the session
  // 'ok'       → key matches the existing binding
  // 'mismatch' → a different key owns the session
  verify(session, key) {
    const now = this.now();
    const h = KeyBindings.hash(key);
    const b = this.map.get(session);
    if (!b) {
      this.map.set(session, { keyHash: h, boundAt: now, lastSeen: now });
      this.scheduleSave();
      return 'bound';
    }
    const a = Buffer.from(b.keyHash, 'hex'), c = Buffer.from(h, 'hex');
    if (a.length !== c.length || !crypto.timingSafeEqual(a, c)) return 'mismatch';
    b.lastSeen = now;
    this.scheduleSave();
    return 'ok';
  }

  // Read-only classification, no binding side effect:
  // 'free' → no binding; 'ok' → key matches; 'mismatch' → another key owns it.
  peek(session, key) {
    const b = this.map.get(session);
    if (!b) return 'free';
    const a = Buffer.from(b.keyHash, 'hex'), c = Buffer.from(KeyBindings.hash(key), 'hex');
    return (a.length === c.length && crypto.timingSafeEqual(a, c)) ? 'ok' : 'mismatch';
  }

  touch(session) {
    const b = this.map.get(session);
    if (!b) return;
    b.lastSeen = this.now();
    this.scheduleSave();
  }

  sweep() {
    const now = this.now();
    let mutated = false;
    for (const [s, b] of this.map) if (now - b.lastSeen > this.ttlMs) { this.map.delete(s); mutated = true; }
    if (mutated) this.scheduleSave();
    return mutated;
  }

  toJSON() {
    const bindings = {};
    for (const [s, b] of this.map) bindings[s] = { keyHash: b.keyHash, boundAt: b.boundAt, lastSeen: b.lastSeen };
    return { version: 2, bindings };
  }

  scheduleSave() {
    if (!this.file || this.saveTimer) return;
    this.saveTimer = setTimeout(() => { this.saveTimer = null; this.saveNow(); }, this.saveDelayMs);
    if (this.saveTimer.unref) this.saveTimer.unref();
  }

  saveNow() {
    if (!this.file) return;
    if (this.saveTimer) { clearTimeout(this.saveTimer); this.saveTimer = null; }
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      const tmp = this.file + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(this.toJSON()));
      fs.renameSync(tmp, this.file);
    } catch (e) {
      this.log(`save failed: ${e.message}`);
    }
  }
}

module.exports = { KeyBindings };
