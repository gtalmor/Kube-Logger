// Unit tests for the relay's pure-ish modules (server/lib/*). Run: npm test.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { BatchHistory } = require('../server/lib/history');
const { KeyBindings } = require('../server/lib/bindings');
const { sendOrKick, fanout, replayHistory, CLOSE_SLOW_CONSUMER } = require('../server/lib/fanout');

const frame = (from, n) => {
  const items = Array.from({ length: n }, (_, k) => ({ i: from + k, ns: 'ns', line: `l${from + k}` }));
  return { raw: JSON.stringify({ type: 'log-batch', items }), items };
};

// ── BatchHistory ────────────────────────────────────────────────────
test('history: tracks indices, evicts whole batches by lines and bytes', () => {
  const h = new BatchHistory({ maxLines: 5, maxBytes: 1e6 });
  assert.equal(h.firstIndex, -1); assert.equal(h.lastIndex, -1);
  let f = frame(0, 2); h.pushBatch(f.raw, f.items);
  f = frame(2, 2); h.pushBatch(f.raw, f.items);
  f = frame(4, 2); h.pushBatch(f.raw, f.items);     // 6 lines > 5 → drop first batch
  assert.equal(h.lines, 4);
  assert.equal(h.firstIndex, 2);
  assert.equal(h.lastIndex, 5);
  assert.equal(h.frames().length, 2);

  const hb = new BatchHistory({ maxLines: 1000, maxBytes: 150 });
  for (let k = 0; k < 10; k++) { const g = frame(k * 3, 3); hb.pushBatch(g.raw, g.items); }
  assert.ok(hb.bytes <= 150 || hb.batches.length === 1, 'byte cap honoured (or single batch)');
  assert.ok(hb.frames().length >= 1);
  hb.pushBatch('{}', []);            // empty batch ignored
  hb.reset('cap2');
  assert.equal(hb.lines, 0); assert.equal(hb.captureId, 'cap2'); assert.equal(hb.lastIndex, -1);
});

test('history: items without i get sequential indices', () => {
  const h = new BatchHistory();
  h.pushBatch('a', [{ line: 'x' }, { line: 'y' }]);
  h.pushBatch('b', [{ line: 'z' }]);
  assert.equal(h.firstIndex, 0);
  assert.equal(h.lastIndex, 2);
});

// ── KeyBindings ─────────────────────────────────────────────────────
test('bindings: bind, verify, mismatch, persistence, expiry', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kl-bind-'));
  const file = path.join(dir, 'state.json');
  let now = 1_000_000;
  const kb = new KeyBindings({ file, ttlMs: 1000, now: () => now });
  assert.equal(kb.verify('s1', 'key-a'), 'bound');
  assert.equal(kb.verify('s1', 'key-a'), 'ok');
  assert.equal(kb.verify('s1', 'key-b'), 'mismatch');
  assert.equal(kb.size, 1);
  assert.equal(kb.peek('s1', 'key-a'), 'ok');
  assert.equal(kb.peek('s1', 'key-b'), 'mismatch');
  assert.equal(kb.peek('s2', 'key-a'), 'free');
  assert.equal(kb.size, 1, 'peek never binds');
  kb.saveNow();
  const onDisk = JSON.parse(fs.readFileSync(file, 'utf8'));
  assert.equal(onDisk.version, 2);
  assert.equal(onDisk.bindings.s1.keyHash, KeyBindings.hash('key-a'));
  assert.ok(!JSON.stringify(onDisk).includes('key-a'), 'raw key never written');

  // Reload in a fresh instance → binding survives.
  const kb2 = new KeyBindings({ file, ttlMs: 1000, now: () => now });
  kb2.load();
  assert.equal(kb2.verify('s1', 'key-b'), 'mismatch');
  assert.equal(kb2.verify('s1', 'key-a'), 'ok');

  // Expiry: untouched for longer than ttl → swept / not loaded.
  now += 2000;
  assert.equal(kb2.sweep(), true);
  assert.equal(kb2.size, 0);
  assert.equal(kb2.verify('s1', 'key-c'), 'bound', 'expired session can be re-bound');

  fs.rmSync(dir, { recursive: true, force: true });
});

test('bindings: v1 state file is ignored', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kl-bind-'));
  const file = path.join(dir, 'state.json');
  fs.writeFileSync(file, JSON.stringify({ version: 1, invites: [['abc', { session: 'x' }]], roTokens: [] }));
  const logs = [];
  const kb = new KeyBindings({ file, log: m => logs.push(m) });
  kb.load();
  assert.equal(kb.size, 0);
  assert.ok(logs.some(l => /unsupported version 1/.test(l)));
  fs.rmSync(dir, { recursive: true, force: true });
});

// ── fanout / replay ─────────────────────────────────────────────────
function fakeWs({ bufferedAmount = 0 } = {}) {
  const ws = {
    readyState: 1, bufferedAmount, sent: [], closed: null,
    send(raw) { this.sent.push(raw); },
    close(code, reason) { this.closed = { code, reason }; this.readyState = 3; },
    terminate() { this.readyState = 3; },
  };
  return ws;
}

test('fanout: sendOrKick kicks a consumer whose buffer is too deep', () => {
  const ok = fakeWs();
  assert.equal(sendOrKick(ok, 'x', { maxBuffered: 10 }), true);
  const slow = fakeWs({ bufferedAmount: 100 });
  assert.equal(sendOrKick(slow, 'x', { maxBuffered: 10 }), false);
  assert.equal(slow.closed.code, CLOSE_SLOW_CONSUMER);
  assert.equal(sendOrKick(slow, 'y', { maxBuffered: 10 }), false, 'kicked sockets get nothing more');
});

test('fanout: frames are queued for a consumer mid-replay and flushed after history', async () => {
  const h = new BatchHistory();
  for (let k = 0; k < 120; k++) { const f = frame(k, 1); h.pushBatch(f.raw, f.items); }
  h.captureId = 'cap1';
  const ws = fakeWs();
  const p = replayHistory(ws, h, { chunk: 10 });
  // Live frame arrives while replay is in flight.
  const live = frame(120, 1);
  fanout([ws], live.raw);
  assert.ok(ws._replaying);
  assert.equal(await p, true);
  const types = ws.sent.map(r => JSON.parse(r));
  assert.equal(types[0].type, 'history-begin');
  assert.equal(types[0].lines, 120);
  assert.equal(types[0].captureId, 'cap1');
  assert.equal(types[types.length - 1].type, 'history-end');
  assert.equal(types[types.length - 1].lastIndex, 119);
  const idx = types.filter(t => t.type === 'log-batch').map(t => t.items[0].i);
  assert.deepEqual(idx, Array.from({ length: 121 }, (_, k) => k), 'history then live, in order');
  assert.ok(!ws._replaying);
  // After replay, fanout sends directly.
  fanout([ws], 'direct');
  assert.equal(ws.sent[ws.sent.length - 1], 'direct');
});

test('fanout: replay waits for a high buffer to drain and kicks on deadline', async () => {
  const h = new BatchHistory();
  for (let k = 0; k < 5; k++) { const f = frame(k, 1); h.pushBatch(f.raw, f.items); }
  // Drains after a few polls.
  const ws = fakeWs({ bufferedAmount: 100 });
  setTimeout(() => { ws.bufferedAmount = 0; }, 30);
  assert.equal(await replayHistory(ws, h, { chunk: 1, highWater: 10, pollMs: 5, maxBuffered: 1e9 }), true);
  // Never drains → kicked.
  const stuck = fakeWs({ bufferedAmount: 100 });
  assert.equal(await replayHistory(stuck, h, { chunk: 1, highWater: 10, pollMs: 5, deadlineMs: 30, maxBuffered: 1e9 }), false);
  assert.equal(stuck.closed.code, CLOSE_SLOW_CONSUMER);
});
