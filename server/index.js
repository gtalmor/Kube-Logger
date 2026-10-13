#!/usr/bin/env node
// Kube Logger Relay
//
//   local agent ── wss ──► /producer?session=S&key=K
//        ▲                      │ fan out (+ bounded history)
//        │                      ▼
//   viewer actions        /consumer?session=S   (owner's browser)
//
// - One producer per session. The first producer binds its key; later
//   producers must present the same key. Bindings persist across restarts
//   (data/state.json, hashed) so an idle session can't be claimed by a
//   stranger who only knows the session id.
// - The relay stores recent `log-batch` frames per session so a viewer that
//   opens later sees history. It tells a reconnecting producer what it has
//   (producer-hello) so the agent only replays the gap.
// - The relay never interprets viewer actions; it forwards them verbatim.

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const { WebSocketServer } = require('ws');

const { BatchHistory } = require('./lib/history');
const { KeyBindings } = require('./lib/bindings');
const { fanout, replayHistory, sendOrKick } = require('./lib/fanout');

const PORT = parseInt(process.env.PORT || '4040', 10);
const HOST = process.env.HOST || '127.0.0.1';
const ROOT = path.join(__dirname, '..');

// Static roots. PUBLIC_DIR is served at "/": the built viewer (web/dist)
// when it exists, else the legacy public/. LEGACY_DIR is served at "/legacy/"
// and NEXT_DIR at "/next/" when they exist and differ from PUBLIC_DIR.
const WEB_DIST = path.join(ROOT, 'web', 'dist');
const LEGACY = path.join(ROOT, 'public');
const PUBLIC_DIR = path.resolve(process.env.PUBLIC_DIR || (fs.existsSync(path.join(WEB_DIST, 'index.html')) ? WEB_DIST : LEGACY));
const MOUNTS = [
  ['/next/',   path.resolve(process.env.NEXT_DIR   || WEB_DIST)],
  ['/legacy/', path.resolve(process.env.LEGACY_DIR || LEGACY)],
].filter(([, dir]) => dir !== PUBLIC_DIR && fs.existsSync(path.join(dir, 'index.html')));

const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(ROOT, 'data'));
const STATE_FILE = path.join(DATA_DIR, 'state.json');

const HISTORY_MAX_LINES = parseInt(process.env.HISTORY_MAX_LINES || '20000', 10);
const HISTORY_MAX_BYTES = parseInt(process.env.HISTORY_MAX_BYTES || String(10 * 1024 * 1024), 10);
const CONSUMER_MAX_BUFFERED = parseInt(process.env.CONSUMER_MAX_BUFFERED_BYTES || String(16 * 1024 * 1024), 10);
const SEND_OPTS = { maxBuffered: CONSUMER_MAX_BUFFERED };

const SESSION_RE = /^[A-Za-z0-9_-]{16,64}$/;
const KEY_RE     = /^[A-Za-z0-9_-]{16,128}$/;

function log(session, msg) {
  const short = (session || '').slice(0, 8);
  console.log(`[${new Date().toISOString()}] [${short}…] ${msg}`);
}

// ── Sessions ────────────────────────────────────────────────────────
// id -> { producer, consumers: Set<ws>, history: BatchHistory, startedAt }
const sessions = new Map();

function getOrCreateSession(id) {
  let s = sessions.get(id);
  if (!s) {
    s = { producer: null, consumers: new Set(), history: new BatchHistory({ maxLines: HISTORY_MAX_LINES, maxBytes: HISTORY_MAX_BYTES }), startedAt: Date.now() };
    sessions.set(id, s);
  }
  return s;
}

function dropIfEmpty(id) {
  const s = sessions.get(id);
  if (s && !s.producer && s.consumers.size === 0) sessions.delete(id);
}

const bindings = new KeyBindings({ file: STATE_FILE, log: m => console.log(`[state] ${m}`) });
bindings.load();
setInterval(() => bindings.sweep(), 60 * 60 * 1000).unref();

// ── Static files ────────────────────────────────────────────────────
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.mjs':  'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map':  'application/json; charset=utf-8',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.ico':  'image/x-icon',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.txt':  'text/plain; charset=utf-8',
};

const SECURITY_HEADERS = {
  'Referrer-Policy': 'no-referrer',            // the session id lives in the URL
  'X-Content-Type-Options': 'nosniff',
};

function serveStatic(req, res) {
  let rel;
  try { rel = decodeURIComponent(url.parse(req.url).pathname || '/'); }
  catch { res.writeHead(400); return res.end('bad path'); }
  let root = PUBLIC_DIR;
  for (const [prefix, dir] of MOUNTS) {
    if (rel === prefix.slice(0, -1)) { res.writeHead(302, { Location: prefix }); return res.end(); }
    if (rel.startsWith(prefix)) { root = dir; rel = rel.slice(prefix.length - 1); break; }
  }
  if (rel === '/' || rel === '') rel = '/index.html';
  const full = path.normalize(path.join(root, rel));
  if (full !== root && !full.startsWith(root + path.sep)) { res.writeHead(400); return res.end('bad path'); }
  fs.stat(full, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404, SECURITY_HEADERS); return res.end('not found'); }
    const ext = path.extname(full).toLowerCase();
    const cache = ext === '.html' ? 'no-store'
      : /[\\/]assets[\\/]/.test(full) ? 'public, max-age=31536000, immutable'
      : 'public, max-age=300';
    res.writeHead(200, { ...SECURITY_HEADERS, 'Content-Type': MIME[ext] || 'application/octet-stream', 'Cache-Control': cache });
    fs.createReadStream(full).pipe(res);
  });
}

// ── HTTP ────────────────────────────────────────────────────────────
const httpServer = http.createServer((req, res) => {
  if (req.url === '/health') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('ok'); }
  // Lets an agent find out why a producer upgrade was refused (bun's ws has
  // no `unexpected-response` event). Read-only: never binds.
  if ((req.url || '').startsWith('/producer/check?')) {
    const q = url.parse(req.url, true).query;
    const session = String(q.session || '').trim(), key = String(q.key || '').trim();
    const hdr = { 'Content-Type': 'text/plain', 'Cache-Control': 'no-store', ...SECURITY_HEADERS };
    if (!SESSION_RE.test(session) || !KEY_RE.test(key)) { res.writeHead(400, hdr); return res.end('bad request'); }
    const v = bindings.peek(session, key);
    if (v === 'mismatch') { res.writeHead(401, hdr); return res.end('mismatch'); }
    res.writeHead(200, hdr); return res.end(v);
  }
  if (req.url === '/stats') {
    let consumers = 0;
    for (const s of sessions.values()) consumers += s.consumers.size;
    res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    return res.end(JSON.stringify({ sessions: sessions.size, consumers, bindings: bindings.size, uptime: process.uptime() }));
  }
  serveStatic(req, res);
});

// ── WebSocket keepalive ─────────────────────────────────────────────
// Peers sometimes vanish without a Close frame (laptop sleep, network cut).
// Ping every 30s; terminate anything that didn't pong the previous ping.
const PING_INTERVAL_MS = 30000;
function attachKeepalive(ws) {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
}
setInterval(() => {
  for (const s of sessions.values()) {
    for (const ws of [s.producer, ...s.consumers].filter(Boolean)) {
      if (ws.isAlive === false) { try { ws.terminate(); } catch {} continue; }
      ws.isAlive = false;
      try { ws.ping(); } catch {}
    }
  }
}, PING_INTERVAL_MS).unref();

// ── WebSocket upgrade ───────────────────────────────────────────────
const wss = new WebSocketServer({ noServer: true });

function reject(socket, status, text) {
  socket.write(`HTTP/1.1 ${status} ${text}\r\nConnection: close\r\n\r\n`);
  socket.destroy();
}

httpServer.on('upgrade', (req, socket, head) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname || '';
  if (pathname !== '/producer' && pathname !== '/consumer') return socket.destroy();

  const session = String(parsed.query.session || '').trim();
  if (!SESSION_RE.test(session)) return reject(socket, 400, 'Bad Request');

  if (pathname === '/producer') {
    const key = String(parsed.query.key || '').trim();
    if (!KEY_RE.test(key)) return reject(socket, 400, 'Bad Request');
    const verdict = bindings.verify(session, key);
    if (verdict === 'mismatch') { log(session, 'rejected producer connect: key mismatch'); return reject(socket, 401, 'Unauthorized'); }
    if (verdict === 'bound') log(session, 'producer key bound');
  }

  wss.handleUpgrade(req, socket, head, ws => {
    ws.role = pathname.slice(1);
    ws.session = session;
    wss.emit('connection', ws, req);
  });
});

wss.on('connection', ws => {
  const s = getOrCreateSession(ws.session);
  if (ws.role === 'producer') return onProducer(ws, s);
  return onConsumer(ws, s);
});

// ── Producer ────────────────────────────────────────────────────────
function onProducer(ws, s) {
  if (s.producer && s.producer !== ws) {
    try { s.producer.close(4000, 'replaced by newer producer'); } catch {}
  }
  s.producer = ws;
  attachKeepalive(ws);
  log(ws.session, `producer connected (consumers: ${s.consumers.size}, history: ${s.history.lines} lines)`);

  ws.send(JSON.stringify({
    type: 'producer-hello', session: ws.session,
    captureId: s.history.captureId, lastIndex: s.history.lastIndex, lines: s.history.lines,
  }));
  fanout(s.consumers, JSON.stringify({ type: 'producer-ready' }), SEND_OPTS);

  ws.on('message', buf => {
    let raw = buf.toString();
    let m = null;
    try { m = JSON.parse(raw); } catch { return; }
    if (!m || typeof m.type !== 'string') return;
    switch (m.type) {
      case 'log': {
        // Pre-batching agents: normalize into a 1-item batch so history and
        // viewers only ever deal with one shape.
        const items = [{ i: m.i, ns: m.ns, line: m.line }];
        raw = JSON.stringify({ type: 'log-batch', items });
        s.history.pushBatch(raw, items);
        break;
      }
      case 'log-batch':
        s.history.pushBatch(raw, m.items);
        break;
      case 'capture-start':
        s.history.reset(m.captureId);
        break;
      case 'cleared':
        s.history.clear();
        break;
      case 'capture-state':
        // Agent → relay only: resync after a reconnect. If the agent moved on
        // to a different capture while we weren't talking, drop the old one.
        if (m.captureId !== s.history.captureId) s.history.reset(m.captureId);
        return;
      default:
        break;
    }
    fanout(s.consumers, raw, SEND_OPTS);
  });

  ws.on('close', () => {
    if (s.producer === ws) s.producer = null;
    bindings.touch(ws.session);
    log(ws.session, 'producer disconnected');
    fanout(s.consumers, JSON.stringify({ type: 'producer-gone' }), SEND_OPTS);
    dropIfEmpty(ws.session);
  });
  ws.on('error', e => log(ws.session, `producer error: ${e.message}`));
}

// ── Consumer ────────────────────────────────────────────────────────
function onConsumer(ws, s) {
  attachKeepalive(ws);
  s.consumers.add(ws);
  log(ws.session, `consumer connected (producer: ${s.producer ? 'yes' : 'no'}, total: ${s.consumers.size})`);

  sendOrKick(ws, JSON.stringify({ type: 'relay-hello', protocol: 2, session: ws.session, producerConnected: !!s.producer }), SEND_OPTS);
  replayHistory(ws, s.history, SEND_OPTS).catch(e => log(ws.session, `replay error: ${e.message}`));

  ws.on('message', buf => {
    const raw = buf.toString();
    let m = null;
    try { m = JSON.parse(raw); } catch { return; }
    if (!m || typeof m.action !== 'string') return;
    if (s.producer && s.producer.readyState === 1) { try { s.producer.send(raw); } catch {} }
  });

  ws.on('close', (code) => {
    s.consumers.delete(ws);
    log(ws.session, `consumer disconnected (code ${code}, remaining: ${s.consumers.size})`);
    dropIfEmpty(ws.session);
  });
  ws.on('error', e => log(ws.session, `consumer error: ${e.message}`));
}

// ── Startup ─────────────────────────────────────────────────────────
httpServer.listen(PORT, HOST, () => {
  console.log(`\n  Kube Logger Relay  [protocol 2]`);
  console.log(`  Listening on http://${HOST}:${PORT}`);
  console.log(`  Viewer:        GET  /            ← ${PUBLIC_DIR}`);
  for (const [prefix, dir] of MOUNTS) console.log(`                 GET  ${prefix.padEnd(12)} ← ${dir}`);
  console.log(`  Producer WS:   /producer?session=<id>&key=<key>`);
  console.log(`  Consumer WS:   /consumer?session=<id>`);
  console.log(`  State:         ${STATE_FILE} (${bindings.size} bindings)`);
  console.log(`  Stats:         GET  /stats\n`);
});

function shutdown() {
  bindings.saveNow();
  httpServer.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
