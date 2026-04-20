#!/usr/bin/env node
// Kube Logger SaaS Relay
//
// Architecture:
//   local agent ── wss ──► /producer?session=ABC&key=KKK
//        ▲                      │
//        │                      │ broadcast
//        │                      ▼
//   producer-originated    /consumer?session=ABC   (owner's browser — read/write)
//   control replies        /consumer?rotoken=TTT   (invitee's browser — read-only)
//
// - Only one producer per session. The first producer binds its `key`; later
//   producer connects must present the same key or they're rejected.
// - Invites: producer asks the relay to mint a high-entropy code tied to its
//   session. Anyone who opens `GET /i/<code>` gets a short-lived read-only
//   token and is redirected into the viewer. Invitee consumers cannot send
//   control messages back to the producer.

const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');

const PORT = parseInt(process.env.PORT || '4040', 10);
const HOST = process.env.HOST || '127.0.0.1';
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const MIN_SESSION_LEN = 16;

const DEFAULT_INVITE_TTL_MS   = 60 * 60 * 1000;  // 1h
const MAX_INVITE_TTL_MS       = 24 * 60 * 60 * 1000; // 24h
const RO_TOKEN_TTL_MS         = 12 * 60 * 60 * 1000; // 12h once redeemed
const LOOKUP_FAIL_WINDOW_MS   = 5 * 60 * 1000;
const LOOKUP_FAIL_LIMIT       = 10;
const LOOKUP_FAIL_BLOCK_MS    = 60 * 60 * 1000;  // 1h lockout

// ── Sessions ────────────────────────────────────────────────────
// session id -> { producer, producerKey, consumers: Set<WebSocket>, startedAt }
const sessions = new Map();

function getOrCreateSession(id) {
  let s = sessions.get(id);
  if (!s) { s = { producer: null, producerKey: null, consumers: new Set(), startedAt: Date.now() }; sessions.set(id, s); }
  return s;
}

function dropIfEmpty(id) {
  const s = sessions.get(id);
  if (!s) return;
  if (!s.producer && s.consumers.size === 0) sessions.delete(id);
}

// ── Invites + ro-tokens ─────────────────────────────────────────
// code   -> { session, expiresAt, oneUse, used }
// token  -> { session, expiresAt }
// Persisted to disk so deploys / pm2 reloads don't invalidate live invites.
// File lives at ./data/state.json; deploy.yml excludes ./data so rsync --delete
// doesn't wipe it on each push.
const DATA_DIR  = path.join(__dirname, '..', 'data');
const STATE_FILE = path.join(DATA_DIR, 'state.json');
const invites  = new Map();
const roTokens = new Map();

function loadState() {
  try {
    const j = JSON.parse(fs.readFileSync(STATE_FILE, 'utf8'));
    const now = Date.now();
    let loaded = 0, skipped = 0;
    for (const [k, v] of (j.invites || []))  { if (v.expiresAt > now && !v.used) { invites.set(k, v); loaded++; } else skipped++; }
    for (const [k, v] of (j.roTokens || [])) { if (v.expiresAt > now)            { roTokens.set(k, v); loaded++; } else skipped++; }
    console.log(`[state] loaded ${loaded} live entries, pruned ${skipped} expired`);
  } catch (e) {
    if (e.code !== 'ENOENT') console.error(`[state] could not load ${STATE_FILE}: ${e.message}`);
  }
}

let saveTimer = null;
function scheduleSave() {
  if (saveTimer) return;
  // Coalesce bursts (multiple invites in a tick) into one write.
  saveTimer = setTimeout(() => {
    saveTimer = null;
    try {
      fs.mkdirSync(DATA_DIR, { recursive: true });
      const data = { version: 1, invites: [...invites], roTokens: [...roTokens] };
      const tmp = STATE_FILE + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(data));
      fs.renameSync(tmp, STATE_FILE);
    } catch (e) {
      console.error(`[state] save failed: ${e.message}`);
    }
  }, 200);
}
loadState();

function newInviteCode() { return crypto.randomBytes(16).toString('base64url'); }  // ~128 bits
function newRoToken()   { return crypto.randomBytes(24).toString('base64url'); }  // ~192 bits

// Per-IP rate limit on invite-code lookups. Not strictly needed against 128-bit
// codes, but keeps logs tidy and blocks obvious scanners.
const lookupFailures = new Map(); // ip -> { count, firstFailAt, blockedUntil }

function isBlocked(ip) {
  const r = lookupFailures.get(ip);
  if (!r) return false;
  if (r.blockedUntil && Date.now() < r.blockedUntil) return true;
  return false;
}

function recordLookupFailure(ip) {
  const now = Date.now();
  let r = lookupFailures.get(ip);
  if (!r || (now - r.firstFailAt) > LOOKUP_FAIL_WINDOW_MS) {
    r = { count: 0, firstFailAt: now, blockedUntil: 0 };
    lookupFailures.set(ip, r);
  }
  r.count++;
  if (r.count >= LOOKUP_FAIL_LIMIT) r.blockedUntil = now + LOOKUP_FAIL_BLOCK_MS;
}

// Periodic sweep of expired invites and ro-tokens.
setInterval(() => {
  const now = Date.now();
  let mutated = false;
  for (const [k, v] of invites)   if (v.expiresAt  < now || v.used) { invites.delete(k); mutated = true; }
  for (const [k, v] of roTokens)  if (v.expiresAt  < now)           { roTokens.delete(k); mutated = true; }
  for (const [ip, r] of lookupFailures) if (r.blockedUntil && now > r.blockedUntil) lookupFailures.delete(ip);
  if (mutated) scheduleSave();
}, 5 * 60 * 1000).unref();

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

function clientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim()
      || req.socket.remoteAddress || 'unknown';
}

function handleInviteRedeem(req, res) {
  const m = /^\/i\/([A-Za-z0-9_-]{8,64})\/?$/.exec(url.parse(req.url).pathname || '');
  if (!m) { res.writeHead(404); return res.end('not found'); }
  const ip = clientIp(req);
  if (isBlocked(ip)) { res.writeHead(429, { 'Content-Type': 'text/plain' }); return res.end('too many attempts'); }

  const code = m[1];
  const inv = invites.get(code);
  if (!inv || inv.expiresAt < Date.now() || inv.used) {
    recordLookupFailure(ip);
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    return res.end('invalid or expired invite');
  }
  if (inv.oneUse) inv.used = true;

  const token = newRoToken();
  roTokens.set(token, { session: inv.session, expiresAt: Date.now() + RO_TOKEN_TTL_MS });
  scheduleSave();
  log(inv.session, `invite redeemed (ip ${ip}, oneUse=${!!inv.oneUse})`);

  res.writeHead(302, { Location: `/?rotoken=${encodeURIComponent(token)}` });
  return res.end();
}

// ── HTTP server ─────────────────────────────────────────────────
const httpServer = http.createServer((req, res) => {
  if (req.url === '/health') { res.writeHead(200, { 'Content-Type': 'text/plain' }); return res.end('ok'); }
  if (req.url === '/stats')  { res.writeHead(200, { 'Content-Type': 'application/json' }); return res.end(JSON.stringify({ sessions: sessions.size, invites: invites.size, roTokens: roTokens.size, uptime: process.uptime() })); }
  if ((req.url || '').startsWith('/i/')) return handleInviteRedeem(req, res);
  serveStatic(req, res);
});

// ── WebSocket upgrade ──────────────────────────────────────────
// /producer?session=X&key=Y — first connect binds the key; later producers
//   presenting a different key are rejected.
// /consumer?session=X       — owner's browser, read/write.
// /consumer?rotoken=T       — invitee, read-only; session derived from token.
const wss = new WebSocketServer({ noServer: true });

httpServer.on('upgrade', (req, socket, head) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname || '';
  if (pathname !== '/producer' && pathname !== '/consumer') return socket.destroy();

  const session = String(parsed.query.session || '').trim();
  const key     = String(parsed.query.key     || '').trim();
  const rotoken = String(parsed.query.rotoken || '').trim();

  let effectiveSession = session;
  let readOnly = false;

  if (pathname === '/consumer' && rotoken) {
    const t = roTokens.get(rotoken);
    if (!t || t.expiresAt < Date.now()) { socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); return socket.destroy(); }
    effectiveSession = t.session;
    readOnly = true;
  } else if (!session || session.length < MIN_SESSION_LEN) {
    socket.write('HTTP/1.1 400 Bad Request\r\n\r\n'); return socket.destroy();
  }

  if (pathname === '/producer') {
    // Enforce producer key if already bound.
    const s = sessions.get(session);
    if (s && s.producerKey && s.producerKey !== key) {
      log(session, `rejected producer connect: key mismatch`);
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); return socket.destroy();
    }
  }

  wss.handleUpgrade(req, socket, head, ws => {
    ws.role = pathname.slice(1);
    ws.session = effectiveSession;
    ws.readOnly = readOnly;
    ws.producerKey = key || null;
    wss.emit('connection', ws, req);
  });
});

wss.on('connection', ws => {
  const s = getOrCreateSession(ws.session);

  if (ws.role === 'producer') {
    if (!s.producerKey && ws.producerKey) s.producerKey = ws.producerKey;  // bind on first connect
    if (s.producer && s.producer !== ws) {
      try { s.producer.close(4000, 'replaced by newer producer'); } catch {}
    }
    s.producer = ws;
    log(ws.session, `producer connected (consumers: ${s.consumers.size})`);
    fanoutToConsumers(s, JSON.stringify({ type: 'producer-ready' }));

    ws.on('message', buf => {
      fanoutToConsumers(s, buf.toString());
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
  log(ws.session, `consumer connected (producer: ${s.producer ? 'yes' : 'no'}, readOnly: ${ws.readOnly}, total: ${s.consumers.size})`);

  safeSend(ws, JSON.stringify({
    type: 'relay-hello',
    session: ws.session,
    producerConnected: !!s.producer,
    readOnly: ws.readOnly,
  }));

  ws.on('message', buf => {
    // Read-only consumers (invitees) cannot send anything upstream.
    if (ws.readOnly) return;
    const raw = buf.toString();
    // Intercept relay-handled actions before forwarding the rest to the producer.
    try {
      const m = JSON.parse(raw);
      if (m && m.action === 'create-invite') { handleCreateInvite(ws, m); return; }
      if (m && m.action === 'revoke-invite') { handleRevokeInvite(ws, m); return; }
    } catch {}
    if (s.producer && s.producer.readyState === 1) s.producer.send(raw);
  });

  ws.on('close', () => {
    s.consumers.delete(ws);
    log(ws.session, `consumer disconnected (remaining: ${s.consumers.size})`);
    dropIfEmpty(ws.session);
  });
  ws.on('error', e => log(ws.session, `consumer error: ${e.message}`));
});

// ── Invite handlers (invoked from an owner's consumer socket) ───────
// `ws.session` is the owner's session; fan the reply out to all consumers
// on that session so whichever browser tab asked will see the result.
function handleCreateInvite(ws, msg) {
  const ttlMs = Math.min(Math.max(parseInt(msg.ttl, 10) || DEFAULT_INVITE_TTL_MS / 1000, 60), MAX_INVITE_TTL_MS / 1000) * 1000;
  const oneUse = !!msg.oneUse;
  const code = newInviteCode();
  const expiresAt = Date.now() + ttlMs;
  invites.set(code, { session: ws.session, expiresAt, oneUse, used: false });
  scheduleSave();
  log(ws.session, `invite minted (oneUse=${oneUse}, ttl=${Math.round(ttlMs/1000)}s)`);
  const s = sessions.get(ws.session);
  if (s) fanoutToConsumers(s, JSON.stringify({
    type: 'invite-created',
    code,
    path: `/i/${code}`,   // relative; the viewer prepends its own origin
    expiresAt,
    oneUse,
  }));
}

function handleRevokeInvite(ws, msg) {
  const code = String(msg.code || '');
  const inv = invites.get(code);
  if (inv && inv.session === ws.session) {
    invites.delete(code);
    scheduleSave();
    log(ws.session, `invite revoked`);
    const s = sessions.get(ws.session);
    if (s) fanoutToConsumers(s, JSON.stringify({ type: 'invite-revoked', code }));
  }
}

function fanoutToConsumers(session, raw) {
  for (const c of session.consumers) if (c.readyState === 1) c.send(raw);
}

function safeSend(ws, raw) { try { if (ws.readyState === 1) ws.send(raw); } catch {} }

function log(session, msg) {
  const short = (session || '').slice(0, 8);
  console.log(`[${new Date().toISOString()}] [${short}…] ${msg}`);
}

// ── Startup ─────────────────────────────────────────────────────
httpServer.listen(PORT, HOST, () => {
  console.log(`\n  Kube Logger Relay  [build:invite-v1]`);
  console.log(`  Listening on http://${HOST}:${PORT}`);
  console.log(`  Viewer:        GET  /`);
  console.log(`  Invite redeem: GET  /i/<code>   → 302 to /?rotoken=...`);
  console.log(`  Producer WS:   /producer?session=<id>&key=<key>`);
  console.log(`  Consumer WS:   /consumer?session=<id> | ?rotoken=<token>`);
  console.log(`  Stats:         GET  /stats\n`);
});

process.on('SIGTERM', () => { httpServer.close(() => process.exit(0)); });
process.on('SIGINT',  () => { httpServer.close(() => process.exit(0)); });
