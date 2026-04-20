#!/usr/bin/env node
// Kube Logger SaaS Relay
//
// Architecture:
//   local agent (wss ->) /producer?session=ABC  --[routes]-->  /consumer?session=ABC (web viewer)
//
// - Producers (local agents) push log-stream messages.
// - Consumers (web viewers) receive them.
// - Pairing is by a random session id; any message from a producer is
//   broadcast to every consumer on the same session (and vice-versa for
//   control messages the viewer may eventually send back).
// - Zero persistence: if no consumer is connected when the producer emits,
//   the lines are gone. Sessions are dropped when both sides disconnect.

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const { WebSocketServer } = require('ws');

const PORT = parseInt(process.env.PORT || '4040', 10);
const HOST = process.env.HOST || '127.0.0.1';
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const MIN_SESSION_LEN = 16;

// ── Sessions ────────────────────────────────────────────────────
// session id -> { producer: WebSocket|null, consumers: Set<WebSocket>, startedAt: number }
const sessions = new Map();

function getOrCreateSession(id) {
  let s = sessions.get(id);
  if (!s) { s = { producer: null, consumers: new Set(), startedAt: Date.now() }; sessions.set(id, s); }
  return s;
}

function dropIfEmpty(id) {
  const s = sessions.get(id);
  if (!s) return;
  if (!s.producer && s.consumers.size === 0) sessions.delete(id);
}

// ── Static file serving ─────────────────────────────────────────
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js':   'application/javascript; charset=utf-8',
  '.css':  'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg':  'image/svg+xml',
  '.png':  'image/png',
  '.ico':  'image/x-icon',
};

function serveStatic(req, res) {
  const parsed = url.parse(req.url);
  let rel = decodeURIComponent(parsed.pathname || '/');
  if (rel === '/' || rel === '') rel = '/index.html';
  const full = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!full.startsWith(PUBLIC_DIR)) { res.writeHead(400); return res.end('bad path'); }
  fs.stat(full, (err, st) => {
    if (err || !st.isFile()) { res.writeHead(404); return res.end('not found'); }
    const ext = path.extname(full).toLowerCase();
    res.writeHead(200, {
      'Content-Type': MIME[ext] || 'application/octet-stream',
      'Cache-Control': ext === '.html' ? 'no-cache' : 'public, max-age=300',
    });
    fs.createReadStream(full).pipe(res);
  });
}

// ── HTTP server ─────────────────────────────────────────────────
const httpServer = http.createServer((req, res) => {
  if (req.url === '/health') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('ok'); }
  if (req.url === '/stats')  { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ sessions: sessions.size, uptime: process.uptime() })); }
  serveStatic(req, res);
});

// ── WebSocket upgrade (routed by pathname + ?session=) ─────────
const wss = new WebSocketServer({ noServer: true });

httpServer.on('upgrade', (req, socket, head) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname || '';
  const session = String(parsed.query.session || '').trim();

  if (pathname !== '/producer' && pathname !== '/consumer') return socket.destroy();
  if (!session || session.length < MIN_SESSION_LEN) { socket.write('HTTP/1.1 400 Bad Request\r\n\r\n'); return socket.destroy(); }

  wss.handleUpgrade(req, socket, head, ws => {
    ws.role = pathname.slice(1); // 'producer' | 'consumer'
    ws.session = session;
    wss.emit('connection', ws, req);
  });
});

wss.on('connection', ws => {
  const s = getOrCreateSession(ws.session);

  if (ws.role === 'producer') {
    // Only one producer per session — boot any prior producer.
    if (s.producer && s.producer !== ws) {
      try { s.producer.close(4000, 'replaced by newer producer'); } catch {}
    }
    s.producer = ws;
    log(ws.session, `producer connected (consumers: ${s.consumers.size})`);

    // Notify consumers producer is live
    fanoutToConsumers(s, JSON.stringify({ type: 'producer-ready' }));

    ws.on('message', buf => {
      // Forward raw (already JSON-serialized by the agent) to all consumers.
      const raw = buf.toString();
      fanoutToConsumers(s, raw);
    });

    ws.on('close', () => {
      if (s.producer === ws) s.producer = null;
      log(ws.session, `producer disconnected`);
      fanoutToConsumers(s, JSON.stringify({ type: 'producer-gone' }));
      dropIfEmpty(ws.session);
    });

    ws.on('error', e => log(ws.session, `producer error: ${e.message}`));
    return;
  }

  // consumer
  s.consumers.add(ws);
  log(ws.session, `consumer connected (producer: ${s.producer ? 'yes' : 'no'}, total consumers: ${s.consumers.size})`);

  // Initial handshake — tell the viewer what it's connected to.
  safeSend(ws, JSON.stringify({
    type: 'relay-hello',
    session: ws.session,
    producerConnected: !!s.producer,
  }));

  ws.on('message', buf => {
    // Consumer -> producer: lets the viewer eventually send control messages.
    if (s.producer && s.producer.readyState === 1) s.producer.send(buf.toString());
  });

  ws.on('close', () => {
    s.consumers.delete(ws);
    log(ws.session, `consumer disconnected (remaining: ${s.consumers.size})`);
    dropIfEmpty(ws.session);
  });

  ws.on('error', e => log(ws.session, `consumer error: ${e.message}`));
});

function fanoutToConsumers(session, raw) {
  for (const c of session.consumers) if (c.readyState === 1) c.send(raw);
}

function safeSend(ws, raw) { try { if (ws.readyState === 1) ws.send(raw); } catch {} }

function log(session, msg) {
  console.log(`[${new Date().toISOString()}] [${session.slice(0, 8)}…] ${msg}`);
}

// ── Startup ─────────────────────────────────────────────────────
httpServer.listen(PORT, HOST, () => {
  console.log(`\n  Kube Logger Relay (SaaS)  [build:saas-v1]`);
  console.log(`  Listening on http://${HOST}:${PORT}`);
  console.log(`  Viewer:        GET  /               (static from ${PUBLIC_DIR})`);
  console.log(`  Producer WS:   /producer?session=<id>`);
  console.log(`  Consumer WS:   /consumer?session=<id>`);
  console.log(`  Health:        GET  /health\n`);
});

process.on('SIGTERM', () => { httpServer.close(() => process.exit(0)); });
process.on('SIGINT',  () => { httpServer.close(() => process.exit(0)); });
