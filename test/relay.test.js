// Boot server/index.js on an ephemeral port + temp data dir, drive it
// with ws + fetch, assert behavior. Run: `npm test`.

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const WebSocket = require('ws');

const TIMEOUT = 5000;

const sid = () => crypto.randomBytes(16).toString('hex');
const key = () => crypto.randomBytes(16).toString('hex');

let relayProc, baseHttp, baseWs, tmpRoot;

before(async () => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'kube-logger-test-'));
  fs.mkdirSync(path.join(tmpRoot, 'server'));
  fs.mkdirSync(path.join(tmpRoot, 'public'));
  fs.copyFileSync(path.join(__dirname, '..', 'server', 'index.js'), path.join(tmpRoot, 'server', 'index.js'));
  fs.writeFileSync(path.join(tmpRoot, 'public', 'index.html'), '<!-- test -->');
  fs.symlinkSync(
    path.join(__dirname, '..', 'node_modules'),
    path.join(tmpRoot, 'node_modules'),
    'dir',
  );

  const port = await getFreePort();
  baseHttp = `http://127.0.0.1:${port}`;
  baseWs   = `ws://127.0.0.1:${port}`;
  relayProc = spawn(process.execPath, [path.join(tmpRoot, 'server', 'index.js')], {
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  // Silence relay output by default; un-comment when debugging.
  // relayProc.stdout.on('data', d => process.stderr.write(`[relay] ${d}`));
  relayProc.stderr.on('data', d => process.stderr.write(`[relay-err] ${d}`));
  await waitFor(async () => (await fetch(`${baseHttp}/health`)).ok, 3000);
});

after(async () => {
  if (relayProc) relayProc.kill('SIGKILL');
  if (tmpRoot && fs.existsSync(tmpRoot)) fs.rmSync(tmpRoot, { recursive: true, force: true });
});

// ── Tests ──────────────────────────────────────────────────────────

test('producer bound to session key is honored on reconnect', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const k = key();
  const p1 = await openProducer(session, k);
  // A second producer with the same key replaces the first.
  const p2 = await openProducer(session, k);
  const closeCode = await waitForClose(p1);
  assert.equal(closeCode, 4000, 'old producer should be closed with 4000 replaced-by-newer');
  // Different key on the same session is rejected (401 at upgrade → 'error').
  await assert.rejects(openProducer(session, key()), /401|Unexpected server/);
  p2.close();
});

test('consumer with short session is rejected at upgrade', { timeout: TIMEOUT }, async () => {
  await assert.rejects(openConsumer('too-short'), /400|Unexpected server/);
});

test('producer log broadcasts reach all consumers on the session', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const prod = await openProducer(session, key());
  const c1 = await openConsumer(session);
  const c2 = await openConsumer(session);
  await drainSetup(c1);
  await drainSetup(c2);
  prod.send(JSON.stringify({ type: 'log', line: 'hello', ns: 'demo', i: 0 }));
  const m1 = await waitForMessage(c1, m => m.type === 'log');
  const m2 = await waitForMessage(c2, m => m.type === 'log');
  assert.equal(m1.line, 'hello');
  assert.equal(m2.line, 'hello');
  prod.close(); c1.close(); c2.close();
});

test('invite create → /i/<code> → ro-token → read-only consumer', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const owner = await openConsumer(session);
  await drainSetup(owner);
  owner.send(JSON.stringify({ action: 'create-invite', ttl: 900, oneUse: false }));
  const msg = await waitForMessage(owner, m => m.type === 'invite-created');
  const res = await fetch(`${baseHttp}${msg.path}`, { redirect: 'manual' });
  assert.equal(res.status, 302);
  const loc = res.headers.get('location') || '';
  const token = new URL(loc, baseHttp).searchParams.get('rotoken');
  assert.ok(token && token.length >= 16, `rotoken missing in ${loc}`);
  const invitee = new WebSocket(`${baseWs}/consumer?rotoken=${encodeURIComponent(token)}`);
  await waitForOpen(invitee);
  const hello = await waitForMessage(invitee, m => m.type === 'relay-hello');
  assert.equal(hello.readOnly, true);
  assert.equal(hello.session, session);
  owner.close(); invitee.close();
});

test('one-use invite burns on first redeem', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const owner = await openConsumer(session);
  await drainSetup(owner);
  owner.send(JSON.stringify({ action: 'create-invite', ttl: 900, oneUse: true }));
  const msg = await waitForMessage(owner, m => m.type === 'invite-created');
  const url = `${baseHttp}${msg.path}`;
  const first  = await fetch(url, { redirect: 'manual' });
  const second = await fetch(url, { redirect: 'manual' });
  assert.equal(first.status, 302);
  assert.equal(second.status, 404);
  owner.close();
});

test('invalid invite code returns 404', { timeout: TIMEOUT }, async () => {
  const res = await fetch(`${baseHttp}/i/totally-made-up-${Date.now()}`);
  assert.equal(res.status, 404);
});

test('read-only consumer cannot become presenter', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const owner = await openConsumer(session);
  await drainSetup(owner);
  // Mint an invite, redeem, connect as the invitee.
  owner.send(JSON.stringify({ action: 'create-invite', ttl: 900, oneUse: false }));
  const inv = await waitForMessage(owner, m => m.type === 'invite-created');
  const redirect = await fetch(`${baseHttp}${inv.path}`, { redirect: 'manual' });
  const token = new URL(redirect.headers.get('location'), baseHttp).searchParams.get('rotoken');
  const invitee = new WebSocket(`${baseWs}/consumer?rotoken=${encodeURIComponent(token)}`);
  await waitForOpen(invitee);
  await drainSetup(invitee);

  // Invitee tries to claim presenter — relay should silently ignore.
  invitee.send(JSON.stringify({ action: 'presenter-start' }));
  // No presenter-status with presenting=true should arrive within 500ms.
  await assert.rejects(
    waitForMessage(owner, m => m.type === 'presenter-status' && m.presenting, 500),
    /timeout/,
  );
  owner.close(); invitee.close();
});

test('presenter-state fans out to followers but not to the sender', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const owner     = await openConsumer(session);
  const follower  = await openConsumer(session);
  const bystander = await openConsumer(session);
  await drainSetup(owner);
  await drainSetup(follower);
  await drainSetup(bystander);

  follower.send(JSON.stringify({ action: 'follow', following: true }));
  owner.send(JSON.stringify({ action: 'presenter-start' }));
  await sleep(50);
  owner.send(JSON.stringify({ action: 'presenter-state', state: { search: 'hi' } }));

  const got = await waitForMessage(follower, m => m.type === 'presenter-state', 800);
  assert.equal(got.state.search, 'hi');

  // Bystander (not following) shouldn't have received presenter-state.
  await assert.rejects(
    waitForMessage(bystander, m => m.type === 'presenter-state', 300),
    /timeout/,
  );
  owner.close(); follower.close(); bystander.close();
});

test('kick-invitees revokes invites and closes invitee sockets', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const owner = await openConsumer(session);
  await drainSetup(owner);
  owner.send(JSON.stringify({ action: 'create-invite', ttl: 900, oneUse: false }));
  const inv = await waitForMessage(owner, m => m.type === 'invite-created');
  const redirect = await fetch(`${baseHttp}${inv.path}`, { redirect: 'manual' });
  const token = new URL(redirect.headers.get('location'), baseHttp).searchParams.get('rotoken');
  const invitee = new WebSocket(`${baseWs}/consumer?rotoken=${encodeURIComponent(token)}`);
  await waitForOpen(invitee);
  await drainSetup(invitee);

  owner.send(JSON.stringify({ action: 'kick-invitees' }));

  const ack = await waitForMessage(owner, m => m.type === 'kicked');
  assert.ok(ack.kicked >= 1, 'should report at least one socket kicked');
  assert.ok(ack.revokedInvites >= 1, 'should report at least one invite revoked');
  // Invitee socket is force-closed by the relay.
  const code = await waitForClose(invitee);
  assert.equal(code, 4001);
  // The original invite no longer redeems.
  const after = await fetch(`${baseHttp}${inv.path}`, { redirect: 'manual' });
  assert.equal(after.status, 404);
  owner.close();
});

// ── Helpers ────────────────────────────────────────────────────────

function getFreePort() {
  return new Promise((resolve, reject) => {
    const net = require('node:net');
    const s = net.createServer();
    s.listen(0, '127.0.0.1', () => {
      const p = s.address().port;
      s.close(() => resolve(p));
    });
    s.on('error', reject);
  });
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

async function waitFor(fn, ms) {
  const until = Date.now() + ms;
  let lastErr;
  while (Date.now() < until) {
    try { if (await fn()) return; } catch (e) { lastErr = e; }
    await sleep(50);
  }
  throw lastErr || new Error('waitFor timed out');
}

// Open helpers — resolve only after 'open', reject on first 'error'.
function waitForOpen(ws, ms = 2000) {
  return new Promise((resolve, reject) => {
    if (ws.readyState === 1) return resolve(ws);
    const t = setTimeout(() => { cleanup(); reject(new Error('open timeout')); }, ms);
    function cleanup() { clearTimeout(t); ws.off('open', ok); ws.off('error', err); }
    function ok()    { cleanup(); resolve(ws); }
    function err(e)  { cleanup(); reject(e); }
    ws.once('open', ok);
    ws.once('error', err);
  });
}

function openProducer(session, keyVal) {
  const url = `${baseWs}/producer?session=${encodeURIComponent(session)}&key=${encodeURIComponent(keyVal)}`;
  return waitForOpen(new WebSocket(url));
}

function openConsumer(session) {
  const url = `${baseWs}/consumer?session=${encodeURIComponent(session)}`;
  return waitForOpen(new WebSocket(url));
}

function waitForClose(ws, ms = 2000) {
  return new Promise((resolve, reject) => {
    if (ws.readyState === 3) return resolve(0);
    const t = setTimeout(() => { ws.off('close', cb); reject(new Error('close timeout')); }, ms);
    function cb(code) { clearTimeout(t); resolve(code); }
    ws.once('close', cb);
  });
}

// Eat the burst of setup messages (relay-hello, presence, presenter-status)
// the relay sends on consumer connect, so per-test waitForMessage gets the
// next *real* message rather than these.
function drainSetup(ws, ms = 200) {
  return new Promise(resolve => {
    const onMsg = () => {};
    ws.on('message', onMsg);
    setTimeout(() => { ws.off('message', onMsg); resolve(); }, ms);
  });
}

function waitForMessage(ws, pred, ms = 2000) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => { ws.off('message', onMsg); reject(new Error('timeout')); }, ms);
    function onMsg(raw) {
      try {
        const m = JSON.parse(raw.toString());
        if (pred(m)) { clearTimeout(t); ws.off('message', onMsg); resolve(m); }
      } catch {}
    }
    ws.on('message', onMsg);
  });
}
