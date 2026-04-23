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
  if (!s) { s = { producer: null, producerKey: null, consumers: new Set(), presenter: null, lastPresenterState: null, startedAt: Date.now() }; sessions.set(id, s); }
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

// ── WebSocket keepalive ────────────────────────────────────────
// Browsers / agents sometimes drop the connection without sending a Close
// frame (laptop sleep, network cut, browser-tab killed). Without a ping
// the server never notices and the consumer lingers in s.consumers forever
// — making the presence pill report ghost viewers. Every 30s we ping each
// open socket; if the previous ping wasn't pong'd back, terminate.
const PING_INTERVAL_MS = 30000;
function attachKeepalive(ws) {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
}
setInterval(() => {
  for (const s of sessions.values()) {
    const all = [s.producer, ...s.consumers].filter(Boolean);
    for (const ws of all) {
      if (ws.isAlive === false) { try { ws.terminate(); } catch {} continue; }
      ws.isAlive = false;
      try { ws.ping(); } catch {}
    }
  }
}, PING_INTERVAL_MS).unref();

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
    attachKeepalive(ws);
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
  ws.idle = false;
  ws.following = false;      // explicitly opted-in to follow
  ws.forceFollowing = false; // forced to follow because an owner is presenting
  ws.presenting = false;
  attachKeepalive(ws);
  s.consumers.add(ws);
  log(ws.session, `consumer connected (producer: ${s.producer ? 'yes' : 'no'}, readOnly: ${ws.readOnly}, total: ${s.consumers.size})`);

  safeSend(ws, JSON.stringify({
    type: 'relay-hello',
    session: ws.session,
    producerConnected: !!s.producer,
    readOnly: ws.readOnly,
  }));
  broadcastPresence(s);
  // A new consumer joining while an owner is already presenting should be
  // force-followed too, so they immediately track the ongoing presentation.
  if (s.presenter && !s.presenter.readOnly && ws !== s.presenter) {
    ws.forceFollowing = true;
  }
  safeSend(ws, JSON.stringify({
    type: 'presenter-status',
    presenting: !!s.presenter,
    presenterIsOwner: !!s.presenter && !s.presenter.readOnly,
    forced: !!(s.presenter && !s.presenter.readOnly),
    followers: [...s.consumers].filter(c => c.following || c.forceFollowing).length,
  }));
  // Replay the last snapshot so a late joiner immediately matches the current
  // view instead of staring at their pre-join state until the presenter
  // happens to act again.
  if (s.presenter && s.lastPresenterState && (ws.forceFollowing || ws.following)) {
    safeSend(ws, JSON.stringify({ type: 'presenter-state', state: s.lastPresenterState }));
  }
  // Tell the presenter their follower count just bumped.
  if (s.presenter && s.presenter !== ws) broadcastPresenterStatus(s);

  ws.on('message', buf => {
    const raw = buf.toString();
    let m = null;
    try { m = JSON.parse(raw); } catch {}
    // Bookkeeping actions are allowed from any consumer, including invitees.
    if (m && m.action === 'presence') { ws.idle = !!m.idle; broadcastPresence(s); return; }
    if (m && m.action === 'follow')   {
      // Invitees who are being force-followed can still send follow:false,
      // but the relay ignores it — they can't opt out of an owner's drive.
      const prev = ws.following;
      if (!ws.forceFollowing) ws.following = !!m.following;
      // Just-opted-in follower deserves a replay of the current view — they
      // shouldn't have to wait for the presenter's next action to see anything.
      if (!prev && ws.following && s.presenter && s.lastPresenterState) {
        safeSend(ws, JSON.stringify({ type: 'presenter-state', state: s.lastPresenterState }));
      }
      broadcastPresenterStatus(s); return;
    }
    // Presenter actions — BOTH owners and invitees may present. Only owner
    // presentations are "forced" on invitees; an invitee's presentation is
    // opt-in for everyone else (including other invitees AND the owner).
    if (m && m.action === 'presenter-start') { handlePresenterStart(ws, s); return; }
    if (m && m.action === 'presenter-stop')  { handlePresenterStop(ws, s);  return; }
    if (m && m.action === 'presenter-state' && ws.presenting) {
      fanoutPresenterState(s, ws, m.state);
      return;
    }
    // Everything else from invitees is dropped.
    if (ws.readOnly) return;
    if (m && m.action === 'create-invite') { handleCreateInvite(ws, m); return; }
    if (m && m.action === 'revoke-invite') { handleRevokeInvite(ws, m); return; }
    if (m && m.action === 'kick-invitees') { handleKickInvitees(ws); return; }
    if (s.producer && s.producer.readyState === 1) s.producer.send(raw);
  });

  ws.on('close', () => {
    s.consumers.delete(ws);
    log(ws.session, `consumer disconnected (remaining: ${s.consumers.size})`);
    const wasFollowing = ws.following || ws.forceFollowing;
    if (s.presenter === ws) clearPresenter(s);
    // Any follower leaving — including the presenter themselves — can change
    // the count the presenter sees. Always re-broadcast when someone with a
    // bearing on presenter status drops.
    if (s.presenter || wasFollowing) broadcastPresenterStatus(s);
    broadcastPresence(s);
    dropIfEmpty(ws.session);
  });
  ws.on('error', e => log(ws.session, `consumer error: ${e.message}`));
});

// Start a presentation. Anyone (owner or invitee) can start, but:
//  - Owner presenter → every non-owner consumer is marked forceFollowing,
//    so invitees can't opt out of the owner's drive.
//  - Invitee presenter → no one is forced; others opt in via `follow:true`.
// Taking over from a prior presenter revokes them with a `presenter-revoked`
// ack so their local UI can flip back.
function handlePresenterStart(ws, s) {
  // Invitees cannot take over an owner's force-presentation — that would
  // defeat the whole "force-follow" premise (invitee could just click Present
  // and immediately become the driver). Owners can take over invitees freely.
  if (s.presenter && s.presenter !== ws && !s.presenter.readOnly && ws.readOnly) {
    safeSend(ws, JSON.stringify({ type: 'presenter-denied', reason: 'owner-presenting' }));
    return;
  }
  if (s.presenter && s.presenter !== ws) {
    const prev = s.presenter;
    prev.presenting = false;
    safeSend(prev, JSON.stringify({ type: 'presenter-revoked' }));
  }
  s.presenter = ws;
  ws.presenting = true;
  s.lastPresenterState = null;  // new presenter, new view — drop stale cache
  const forced = !ws.readOnly;
  for (const c of s.consumers) {
    c.forceFollowing = forced && c !== ws;
  }
  broadcastPresenterStatus(s);
}

function handlePresenterStop(ws, s) {
  if (s.presenter === ws) clearPresenter(s);
  else ws.presenting = false;
  broadcastPresenterStatus(s);
}

function clearPresenter(s) {
  if (s.presenter) { s.presenter.presenting = false; }
  s.presenter = null;
  s.lastPresenterState = null;
  for (const c of s.consumers) c.forceFollowing = false;
}

function broadcastPresenterStatus(s) {
  let followers = 0;
  for (const c of s.consumers) if (c.following || c.forceFollowing) followers++;
  const payload = JSON.stringify({
    type: 'presenter-status',
    presenting: !!s.presenter,
    presenterIsOwner: !!s.presenter && !s.presenter.readOnly,
    forced: !!(s.presenter && !s.presenter.readOnly),
    followers,
  });
  for (const c of s.consumers) if (c.readyState === 1) { try { c.send(payload); } catch {} }
}

function fanoutPresenterState(s, sender, state) {
  s.lastPresenterState = state;
  const payload = JSON.stringify({ type: 'presenter-state', state });
  for (const c of s.consumers) {
    if (c === sender) continue;
    if (!(c.following || c.forceFollowing)) continue;
    if (c.readyState !== 1) continue;
    try { c.send(payload); } catch {}
  }
}

function broadcastPresence(s) {
  let owners = 0, invitees = 0, idle = 0;
  for (const c of s.consumers) {
    if (c.readOnly) invitees++; else owners++;
    if (c.idle) idle++;
  }
  const totalAll = owners + invitees;
  // Each viewer sees a count of *other* viewers — not themselves. Otherwise
  // a solo session always shows "1 viewing · 0 idle" which is just confusing.
  for (const c of s.consumers) {
    if (c.readyState !== 1) continue;
    const selfOwner = !c.readOnly;
    const selfIdle  = !!c.idle;
    const counts = {
      total:    totalAll - 1,
      owners:   owners   - (selfOwner ? 1 : 0),
      invitees: invitees - (selfOwner ? 0 : 1),
      idle:     idle     - (selfIdle  ? 1 : 0),
    };
    counts.active = counts.total - counts.idle;
    try { c.send(JSON.stringify({ type: 'presence', counts })); } catch {}
  }
}

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

// Owner-initiated panic button: invalidate every outstanding invite + ro-token
// for this session and forcibly close any read-only consumer currently viewing.
// Owners stay connected (only invitees / read-only sockets get the boot).
function handleKickInvitees(ws) {
  let revokedInvites = 0, revokedTokens = 0, kicked = 0;
  for (const [code, inv] of invites)   if (inv.session === ws.session)  { invites.delete(code); revokedInvites++; }
  for (const [tok, t]   of roTokens)   if (t.session   === ws.session)  { roTokens.delete(tok); revokedTokens++; }
  scheduleSave();
  const s = sessions.get(ws.session);
  if (s) {
    for (const c of [...s.consumers]) {
      if (c.readOnly) { try { c.close(4001, 'kicked by owner'); } catch {} kicked++; }
    }
    safeSend(ws, JSON.stringify({ type: 'kicked', revokedInvites, revokedTokens, kicked }));
  }
  log(ws.session, `kick-invitees: revoked ${revokedInvites} invites, ${revokedTokens} tokens; kicked ${kicked} sockets`);
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
