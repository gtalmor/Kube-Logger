// Boot the real server/index.js on an ephemeral port + temp data dir, drive
// it with ws + fetch, assert behavior. Run: `npm test`.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const WebSocket = require('ws');
const { startRelay, waitFor } = require('./helpers/relay');

const TIMEOUT = 8000;
const sid = () => crypto.randomBytes(16).toString('hex');
const key = () => crypto.randomBytes(16).toString('hex');

let relay, baseHttp, baseWs;

before(async () => {
  relay = await startRelay({ quiet: false, env: { CONSUMER_MAX_BUFFERED_BYTES: String(300 * 1024) } });
  ({ baseHttp, baseWs } = relay);
});

after(async () => { await relay.stop(); relay.cleanup(); });

// ── helpers ────────────────────────────────────────────────────────
// Every socket buffers parsed messages in `ws.queue`, so a frame that
// arrives before a test attaches a waiter (e.g. producer-hello right after
// open) is never lost. waitForMessage/collectUntil consume from the queue.
function openWs(url) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.queue = [];
    ws.on('message', raw => { try { ws.queue.push(JSON.parse(raw.toString())); } catch { return; } ws.emit('queued'); });
    ws.on('unexpected-response', (req, res) => { req.destroy(); reject(new Error(`HTTP ${res.statusCode}`)); });
    ws.on('error', reject);
    ws.on('open', () => resolve(ws));
  });
}
const openProducer = (session, k, base = baseWs) => openWs(`${base}/producer?session=${session}&key=${k}`);
const openConsumer = (session, base = baseWs) => openWs(`${base}/consumer?session=${session}`);

function waitForMessage(ws, pred, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const check = () => {
      const k = ws.queue.findIndex(pred);
      if (k < 0) return false;
      const [m] = ws.queue.splice(k, 1);
      clearTimeout(t); ws.off('queued', check); resolve(m);
      return true;
    };
    const t = setTimeout(() => { ws.off('queued', check); reject(new Error(`timeout waiting for message; queue: ${ws.queue.map(m => m.type || m.action).join(',')}`)); }, timeoutMs);
    if (!check()) ws.on('queued', check);
  });
}
// Take messages in arrival order until `stopPred` matches (inclusive).
function collectUntil(ws, stopPred, timeoutMs = 4000) {
  return new Promise((resolve, reject) => {
    const got = [];
    const check = () => {
      while (ws.queue.length) {
        const m = ws.queue.shift();
        got.push(m);
        if (stopPred(m)) { clearTimeout(t); ws.off('queued', check); resolve(got); return true; }
      }
      return false;
    };
    const t = setTimeout(() => { ws.off('queued', check); reject(new Error(`timeout; got ${got.map(m => m.type).join(',')}`)); }, timeoutMs);
    if (!check()) ws.on('queued', check);
  });
}
const waitForClose = ws => new Promise(resolve => ws.on('close', code => resolve(code)));
const drainSetup = ws => collectUntil(ws, m => m.type === 'history-end');   // relay-hello → history-begin → … → history-end
const batch = (from, n, ns = 'ns') => ({ type: 'log-batch', items: Array.from({ length: n }, (_, k) => ({ i: from + k, ns, line: `line-${from + k}` })) });
const linesOf = msgs => msgs.filter(m => m.type === 'log-batch').flatMap(m => m.items.map(it => it.i));
const closeAll = (...ws) => ws.forEach(w => { try { w.close(); } catch {} });

// ── upgrade validation + key binding ───────────────────────────────
test('same key replaces the old producer (4000); different key is 401', { timeout: TIMEOUT }, async () => {
  const session = sid(), k = key();
  const p1 = await openProducer(session, k);
  const p2 = await openProducer(session, k);
  assert.equal(await waitForClose(p1), 4000);
  await assert.rejects(openProducer(session, key()), /HTTP 401/);
  closeAll(p2);
});

test('malformed session or key is rejected with 400', { timeout: TIMEOUT }, async () => {
  await assert.rejects(openConsumer('too-short'), /HTTP 400/);
  await assert.rejects(openConsumer('bad chars!!bad chars!!'), /HTTP 400/);
  await assert.rejects(openProducer(sid(), 'short'), /HTTP 400/);
  await assert.rejects(openWs(`${baseWs}/producer?session=${sid()}`), /HTTP 400/);
});

test('binding survives the session being dropped (no producer, no consumers)', { timeout: TIMEOUT }, async () => {
  const session = sid(), k = key();
  const check = (s, kk) => fetch(`${baseHttp}/producer/check?session=${s}&key=${kk}`);
  assert.equal((await check(session, k)).status, 200);
  assert.equal(await (await check(session, k)).text(), 'free');
  const p = await openProducer(session, k);
  p.close();
  await waitForClose(p);
  await waitFor(async () => (await (await fetch(`${baseHttp}/stats`)).json()).bindings >= 1);
  await assert.rejects(openProducer(session, key()), /HTTP 401/);
  // Read-only check endpoint classifies without binding.
  assert.equal((await check(session, key())).status, 401);
  assert.equal(await (await check(session, k)).text(), 'ok');
  assert.equal((await check('short', k)).status, 400);
  const again = await openProducer(session, k);
  closeAll(again);
});

test('binding survives a relay restart (persisted, hashed)', { timeout: 15000 }, async () => {
  const own = await startRelay({ quiet: true });
  try {
    const session = sid(), k = key();
    const p = await openProducer(session, k, own.baseWs);
    p.close(); await waitForClose(p);
    await waitFor(() => fs.existsSync(path.join(own.dataDir, 'state.json')), 3000);
    const onDisk = JSON.parse(fs.readFileSync(path.join(own.dataDir, 'state.json'), 'utf8'));
    assert.equal(onDisk.version, 2);
    assert.ok(onDisk.bindings[session]);
    assert.ok(!JSON.stringify(onDisk).includes(k), 'raw key must not be persisted');
    await own.stop();
    const own2 = await startRelay({ quiet: true, dataDir: own.dataDir });
    try {
      await assert.rejects(openProducer(session, key(), own2.baseWs), /HTTP 401/);
      const ok = await openProducer(session, k, own2.baseWs);
      closeAll(ok);
    } finally { await own2.stop(); own2.cleanup(); }
  } finally { await own.stop(); own.cleanup(); }
});

test('a v1 state file is ignored at boot', { timeout: 15000 }, async () => {
  const own = await startRelay({ quiet: true });
  await own.stop();
  fs.mkdirSync(own.dataDir, { recursive: true });
  fs.writeFileSync(path.join(own.dataDir, 'state.json'), JSON.stringify({ version: 1, invites: [['code', { session: 'x', expiresAt: 9e15 }]], roTokens: [] }));
  const own2 = await startRelay({ quiet: true, dataDir: own.dataDir });
  try {
    const stats = await (await fetch(`${own2.baseHttp}/stats`)).json();
    assert.equal(stats.bindings, 0);
    assert.ok(/unsupported version 1/.test(own2.output()));
  } finally { await own2.stop(); own2.cleanup(); own.cleanup(); }
});

// ── fan-out + history ───────────────────────────────────────────────
test('log-batch frames reach all consumers; viewer actions reach the producer', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const prod = await openProducer(session, key());
  await waitForMessage(prod, m => m.type === 'producer-hello');
  const c1 = await openConsumer(session), c2 = await openConsumer(session);
  await drainSetup(c1); await drainSetup(c2);
  prod.send(JSON.stringify(batch(0, 3)));
  const m1 = await waitForMessage(c1, m => m.type === 'log-batch');
  const m2 = await waitForMessage(c2, m => m.type === 'log-batch');
  assert.deepEqual(m1.items.map(x => x.i), [0, 1, 2]);
  assert.deepEqual(m2.items.map(x => x.i), [0, 1, 2]);
  // Consumer → producer: forwarded verbatim; junk without `action` is dropped.
  c1.send(JSON.stringify({ action: 'pods', ns: 'default' }));
  c1.send('not json');
  c1.send(JSON.stringify({ type: 'presence', idle: true }));
  const act = await waitForMessage(prod, m => m.action === 'pods');
  assert.equal(act.ns, 'default');
  closeAll(prod, c1, c2);
});

test('a single legacy `log` frame is normalized into a 1-item log-batch', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const prod = await openProducer(session, key());
  const c = await openConsumer(session);
  await drainSetup(c);
  prod.send(JSON.stringify({ type: 'log', line: 'hello', ns: 'demo', i: 7 }));
  const m = await waitForMessage(c, m => m.type === 'log-batch');
  assert.deepEqual(m.items, [{ i: 7, ns: 'demo', line: 'hello' }]);
  const late = await openConsumer(session);
  const got = await drainSetup(late);
  assert.deepEqual(linesOf(got), [7]);
  closeAll(prod, c, late);
});

test('late joiner receives history-begin, batches in order, then history-end', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const prod = await openProducer(session, key());
  await waitForMessage(prod, m => m.type === 'producer-hello');
  prod.send(JSON.stringify({ type: 'capture-start', captureId: 'cap1', ns: ['ns'], start: 1 }));
  for (let b = 0; b < 30; b++) prod.send(JSON.stringify(batch(b * 10, 10)));
  prod.send(JSON.stringify({ type: 'auth-status', ok: true }));      // not replayed
  await new Promise(r => setTimeout(r, 100));
  const late = await openConsumer(session);
  const got = await drainSetup(late);
  assert.equal(got[0].type, 'relay-hello');
  assert.equal(got[0].producerConnected, true);
  assert.equal(got[1].type, 'history-begin');
  assert.equal(got[1].captureId, 'cap1');
  assert.equal(got[1].lines, 300);
  assert.equal(got[1].lastIndex, 299);
  assert.deepEqual(linesOf(got), Array.from({ length: 300 }, (_, k) => k));
  assert.ok(!got.some(m => m.type === 'auth-status'), 'non-log frames are not replayed');
  assert.equal(got[got.length - 1].type, 'history-end');
  closeAll(prod, late);
});

test('history survives a producer reconnect and producer-hello reports what the relay holds', { timeout: TIMEOUT }, async () => {
  const session = sid(), k = key();
  const p1 = await openProducer(session, k);
  await waitForMessage(p1, m => m.type === 'producer-hello');
  p1.send(JSON.stringify({ type: 'capture-start', captureId: 'capA', ns: ['ns'], start: 1 }));
  p1.send(JSON.stringify(batch(0, 5)));
  const c = await openConsumer(session);
  await drainSetup(c);
  p1.close(); await waitForClose(p1);
  await waitForMessage(c, m => m.type === 'producer-gone');
  const p2 = await openProducer(session, k);
  const hello = await waitForMessage(p2, m => m.type === 'producer-hello');
  assert.equal(hello.captureId, 'capA');
  assert.equal(hello.lastIndex, 4);
  assert.equal(hello.lines, 5);
  // Agent resyncs with the same captureId and only the tail.
  p2.send(JSON.stringify({ type: 'capture-state', captureId: 'capA', ns: ['ns'], start: 1, n: 8, first: 0, last: 7 }));
  p2.send(JSON.stringify(batch(5, 3)));
  const late = await openConsumer(session);
  const got = await drainSetup(late);
  assert.deepEqual(linesOf(got), [0, 1, 2, 3, 4, 5, 6, 7]);
  closeAll(p2, c, late);
});

test('capture-state is not fanned out; a different captureId clears history', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const prod = await openProducer(session, key());
  await waitForMessage(prod, m => m.type === 'producer-hello');
  prod.send(JSON.stringify({ type: 'capture-start', captureId: 'old', ns: ['ns'], start: 1 }));
  prod.send(JSON.stringify(batch(0, 4)));
  const c = await openConsumer(session);
  await drainSetup(c);
  let sawState = false;
  c.on('message', raw => { if (JSON.parse(raw.toString()).type === 'capture-state') sawState = true; });
  prod.send(JSON.stringify({ type: 'capture-state', captureId: 'new', ns: ['ns'], start: 2, n: 0, first: 0, last: -1 }));
  prod.send(JSON.stringify(batch(0, 2)));
  await waitForMessage(c, m => m.type === 'log-batch');
  assert.equal(sawState, false);
  const late = await openConsumer(session);
  const got = await drainSetup(late);
  assert.equal(got[1].captureId, 'new');
  assert.deepEqual(linesOf(got), [0, 1]);
  closeAll(prod, c, late);
});

test('capture-start and cleared reset history', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const prod = await openProducer(session, key());
  prod.send(JSON.stringify(batch(0, 3)));
  prod.send(JSON.stringify({ type: 'capture-start', captureId: 'c2', ns: ['ns'], start: 1 }));
  prod.send(JSON.stringify(batch(0, 1)));
  let got = await drainSetup(await openConsumer(session));
  assert.deepEqual(linesOf(got), [0]);
  prod.send(JSON.stringify({ type: 'cleared' }));
  got = await drainSetup(await openConsumer(session));
  assert.deepEqual(linesOf(got), []);
  closeAll(prod);
});

test('live frames arriving during replay land after the history, in order', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const prod = await openProducer(session, key());
  await waitForMessage(prod, m => m.type === 'producer-hello');
  // 600 batches → 12 replay chunks of 50, with event-loop yields between them.
  for (let b = 0; b < 600; b++) prod.send(JSON.stringify(batch(b, 1)));
  await new Promise(r => setTimeout(r, 150));
  const late = await openConsumer(session);
  const p = drainSetup(late);
  // Fire live frames while the replay is in flight.
  for (let b = 600; b < 605; b++) prod.send(JSON.stringify(batch(b, 1)));
  const got = await p;
  const idx = linesOf(got);
  assert.equal(idx.length, 605);
  assert.deepEqual(idx, Array.from({ length: 605 }, (_, k) => k));
  closeAll(prod, late);
});

test('a consumer that stops reading is closed with 4002 (slow consumer)', { timeout: 20000 }, async () => {
  // Own relay instance so the /stats consumer count is isolated from other tests.
  const own = await startRelay({ quiet: true, env: { CONSUMER_MAX_BUFFERED_BYTES: String(300 * 1024) } });
  try {
    const session = sid();
    const prod = await openProducer(session, key(), own.baseWs);
    const slow = await openConsumer(session, own.baseWs);
    await drainSetup(slow);
    slow._socket.pause();                                   // stop reading: relay buffer grows
    const closed = waitForClose(slow);
    const big = JSON.stringify({ type: 'log-batch', items: Array.from({ length: 200 }, (_, k) => ({ i: k, ns: 'ns', line: 'x'.repeat(500) })) }); // ~100 KB
    const pump = setInterval(() => { if (prod.readyState === 1) for (let k = 0; k < 10; k++) prod.send(big); }, 20);
    // The relay kicks once its buffer for `slow` passes 300 KB; the socket is torn down within ~5s.
    await waitFor(async () => (await (await fetch(`${own.baseHttp}/stats`)).json()).consumers === 0, 15000, 100);
    clearInterval(pump);
    slow._socket.resume();
    const code = await closed;
    assert.ok(code === 4002 || code === 1006, `expected 4002 (or 1006 after terminate), got ${code}`);
    closeAll(prod);
  } finally { await own.stop(); own.cleanup(); }
});

// ── HTTP surface ────────────────────────────────────────────────────
test('http: health, stats shape, invite route gone, static guard', { timeout: TIMEOUT }, async () => {
  assert.equal(await (await fetch(`${baseHttp}/health`)).text(), 'ok');
  const stats = await (await fetch(`${baseHttp}/stats`)).json();
  assert.deepEqual(Object.keys(stats).sort(), ['bindings', 'consumers', 'sessions', 'uptime']);
  assert.equal((await fetch(`${baseHttp}/i/anything-at-all`)).status, 404);
  const idx = await fetch(`${baseHttp}/`);
  assert.equal(idx.status, 200);
  assert.equal(idx.headers.get('cache-control'), 'no-store');
  assert.equal(idx.headers.get('referrer-policy'), 'no-referrer');
  assert.equal((await fetch(`${baseHttp}/..%2F..%2Fetc%2Fpasswd`)).status >= 400, true);
  assert.equal((await fetch(`${baseHttp}/next/`)).status, 404, 'no /next mount when the dir is missing');
});
