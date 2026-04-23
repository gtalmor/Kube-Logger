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

test('owner presenting force-follows invitees without opt-in', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const owner = await openConsumer(session);
  await drainSetup(owner);
  const invitee = await redeemInvitee(owner, session);
  await drainSetup(invitee);

  owner.send(JSON.stringify({ action: 'presenter-start' }));
  // Relay status should mark the presentation as owner + forced.
  const status = await waitForMessage(invitee, m => m.type === 'presenter-status' && m.presenting);
  assert.equal(status.presenterIsOwner, true);
  assert.equal(status.forced, true);

  // Invitee never sent `follow:true` — but should still receive presenter-state.
  owner.send(JSON.stringify({ action: 'presenter-state', state: { search: 'forced' } }));
  const got = await waitForMessage(invitee, m => m.type === 'presenter-state', 800);
  assert.equal(got.state.search, 'forced');

  owner.close(); invitee.close();
});

test('invitee cannot opt out of an owner force-follow', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const owner = await openConsumer(session);
  await drainSetup(owner);
  const invitee = await redeemInvitee(owner, session);
  await drainSetup(invitee);

  owner.send(JSON.stringify({ action: 'presenter-start' }));
  await waitForMessage(invitee, m => m.type === 'presenter-status' && m.presenting);

  // Invitee tries to opt out. Relay should ignore and keep forwarding state.
  invitee.send(JSON.stringify({ action: 'follow', following: false }));
  await sleep(50);
  owner.send(JSON.stringify({ action: 'presenter-state', state: { search: 'still-forced' } }));
  const got = await waitForMessage(invitee, m => m.type === 'presenter-state', 800);
  assert.equal(got.state.search, 'still-forced');

  owner.close(); invitee.close();
});

test('invitee presenter is opt-in — other invitees must follow explicitly', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const owner = await openConsumer(session);
  await drainSetup(owner);
  const inv1 = await redeemInvitee(owner, session);
  const inv2 = await redeemInvitee(owner, session);
  await drainSetup(inv1); await drainSetup(inv2);

  inv1.send(JSON.stringify({ action: 'presenter-start' }));
  const status = await waitForMessage(inv2, m => m.type === 'presenter-status' && m.presenting);
  assert.equal(status.presenterIsOwner, false);
  assert.equal(status.forced, false);

  // inv2 did NOT opt in — should NOT receive presenter-state.
  inv1.send(JSON.stringify({ action: 'presenter-state', state: { search: 'invitee-broadcast' } }));
  await assert.rejects(
    waitForMessage(inv2, m => m.type === 'presenter-state', 400),
    /timeout/,
  );

  // After inv2 explicitly follows, presenter-state arrives.
  inv2.send(JSON.stringify({ action: 'follow', following: true }));
  await sleep(50);
  inv1.send(JSON.stringify({ action: 'presenter-state', state: { search: 'now-delivered' } }));
  // Opt-in triggers a cached replay first, then the new frame arrives — wait
  // for the specific one we sent post-opt-in.
  const got = await waitForMessage(inv2,
    m => m.type === 'presenter-state' && m.state.search === 'now-delivered', 800);
  assert.equal(got.state.search, 'now-delivered');

  owner.close(); inv1.close(); inv2.close();
});

test('owner takeover revokes invitee presenter and force-follows', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const owner = await openConsumer(session);
  await drainSetup(owner);
  const invitee = await redeemInvitee(owner, session);
  await drainSetup(invitee);

  invitee.send(JSON.stringify({ action: 'presenter-start' }));
  await waitForMessage(owner, m => m.type === 'presenter-status' && m.presenting);

  // Owner takes over. Invitee should get a presenter-revoked ack.
  owner.send(JSON.stringify({ action: 'presenter-start' }));
  const revoked = await waitForMessage(invitee, m => m.type === 'presenter-revoked', 800);
  assert.ok(revoked);

  // Now it's owner-forced — invitee should receive the owner's state.
  owner.send(JSON.stringify({ action: 'presenter-state', state: { search: 'owner-took-over' } }));
  const got = await waitForMessage(invitee, m => m.type === 'presenter-state', 800);
  assert.equal(got.state.search, 'owner-took-over');

  owner.close(); invitee.close();
});

test('late-joining invitee is force-followed into an ongoing owner presentation', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const owner = await openConsumer(session);
  await drainSetup(owner);
  owner.send(JSON.stringify({ action: 'presenter-start' }));
  await sleep(50);

  const invitee = await redeemInvitee(owner, session);
  // Initial presenter-status on connect should already show forced.
  const status = await waitForMessage(invitee, m => m.type === 'presenter-status' && m.presenting);
  assert.equal(status.forced, true);

  // A subsequent presenter-state reaches the new invitee without opting in.
  owner.send(JSON.stringify({ action: 'presenter-state', state: { search: 'late-join' } }));
  const got = await waitForMessage(invitee, m => m.type === 'presenter-state', 800);
  assert.equal(got.state.search, 'late-join');

  owner.close(); invitee.close();
});

test('owner second tab is NOT force-followed when owner presents', { timeout: TIMEOUT }, async () => {
  // If the relay flagged a second owner tab as forceFollowing, the viewer
  // (which only shows the forced UX when RO_TOKEN is present) would show an
  // opt-in Follow button — clicking it would be silently ignored by the
  // relay because forceFollowing is sticky. Stateful desync.
  const session = sid();
  const tab1 = await openConsumer(session);
  const tab2 = await openConsumer(session);
  await drainSetup(tab1); await drainSetup(tab2);

  tab1.send(JSON.stringify({ action: 'presenter-start' }));
  await waitForMessage(tab2, m => m.type === 'presenter-status' && m.presenting);

  // tab2 never opted in — should NOT receive presenter-state.
  tab1.send(JSON.stringify({ action: 'presenter-state', state: { search: 'not-for-tab2' } }));
  await assert.rejects(
    waitForMessage(tab2, m => m.type === 'presenter-state', 400),
    /timeout/,
  );

  // Opting in works — tab2 controls whether they follow. Opt-in triggers a
  // cached replay ('not-for-tab2') immediately, followed by new frames.
  tab2.send(JSON.stringify({ action: 'follow', following: true }));
  await sleep(30);
  tab1.send(JSON.stringify({ action: 'presenter-state', state: { search: 'opted-in' } }));
  const got = await waitForMessage(tab2,
    m => m.type === 'presenter-state' && m.state.search === 'opted-in', 800);
  assert.equal(got.state.search, 'opted-in');

  // And opting back OUT must actually unfollow (not ignored as if forced).
  tab2.send(JSON.stringify({ action: 'follow', following: false }));
  await sleep(30);
  tab1.send(JSON.stringify({ action: 'presenter-state', state: { search: 'unfollowed' } }));
  await assert.rejects(
    waitForMessage(tab2,
      m => m.type === 'presenter-state' && m.state.search === 'unfollowed', 400),
    /timeout/,
  );

  tab1.close(); tab2.close();
});

test('owner presenting force-follows ALL invitees at once', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const owner = await openConsumer(session);
  await drainSetup(owner);
  const invs = [
    await redeemInvitee(owner, session),
    await redeemInvitee(owner, session),
    await redeemInvitee(owner, session),
  ];
  for (const i of invs) await drainSetup(i);
  await drainSetup(owner);

  // Attach listeners FIRST, then send — avoids any race where the broadcast
  // lands before waitForMessage registers its listener.
  const statusP = Promise.all(invs.map(i =>
    waitForMessage(i, m => m.type === 'presenter-status' && m.presenting, 1500)));
  const countP = waitForMessage(owner,
    m => m.type === 'presenter-status' && m.followers === 3, 1500);
  owner.send(JSON.stringify({ action: 'presenter-start' }));
  const statuses = await statusP;
  for (const s of statuses) assert.equal(s.forced, true);
  const finalStatus = await countP;
  assert.equal(finalStatus.followers, 3);

  const stateP = Promise.all(invs.map(i =>
    waitForMessage(i, m => m.type === 'presenter-state', 1500)));
  owner.send(JSON.stringify({ action: 'presenter-state', state: { search: 'broadcast' } }));
  const gets = await stateP;
  for (const g of gets) assert.equal(g.state.search, 'broadcast');

  owner.close(); for (const i of invs) i.close();
});

test('late joiner immediately receives the cached presenter-state', { timeout: TIMEOUT }, async () => {
  // If the owner pushed state BEFORE the invitee joined, the invitee should
  // still get the current view on connect — not sit with a blank screen until
  // the owner happens to act again.
  const session = sid();
  const owner = await openConsumer(session);
  await drainSetup(owner);
  owner.send(JSON.stringify({ action: 'presenter-start' }));
  await sleep(30);
  owner.send(JSON.stringify({ action: 'presenter-state', state: { search: 'preset-view', hideTrace: true } }));
  await sleep(50);

  const invitee = await redeemInvitee(owner, session);
  // Replay should arrive without the owner doing anything further.
  const got = await waitForMessage(invitee, m => m.type === 'presenter-state', 800);
  assert.equal(got.state.search, 'preset-view');
  assert.equal(got.state.hideTrace, true);

  owner.close(); invitee.close();
});

test('invitee cannot take over an owner who is force-presenting', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const owner = await openConsumer(session);
  await drainSetup(owner);
  const invitee = await redeemInvitee(owner, session);
  await drainSetup(invitee);

  owner.send(JSON.stringify({ action: 'presenter-start' }));
  await waitForMessage(invitee, m => m.type === 'presenter-status' && m.presenting);

  // Invitee tries to take over. Relay should deny — owner stays presenter.
  invitee.send(JSON.stringify({ action: 'presenter-start' }));
  const denied = await waitForMessage(invitee, m => m.type === 'presenter-denied', 800);
  assert.equal(denied.reason, 'owner-presenting');

  // Owner should NOT have been revoked.
  await assert.rejects(
    waitForMessage(owner, m => m.type === 'presenter-revoked', 300),
    /timeout/,
  );

  // And owner can still drive — invitee still force-followed.
  owner.send(JSON.stringify({ action: 'presenter-state', state: { search: 'still-owner' } }));
  const got = await waitForMessage(invitee, m => m.type === 'presenter-state', 800);
  assert.equal(got.state.search, 'still-owner');

  owner.close(); invitee.close();
});

test('follower opting in mid-presentation receives the cached state immediately', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const owner = await openConsumer(session);
  await drainSetup(owner);
  const inv1 = await redeemInvitee(owner, session);
  const inv2 = await redeemInvitee(owner, session);
  await drainSetup(inv1); await drainSetup(inv2);

  inv1.send(JSON.stringify({ action: 'presenter-start' }));
  await sleep(30);
  inv1.send(JSON.stringify({ action: 'presenter-state', state: { search: 'current-view' } }));
  await sleep(50);

  // inv2 opts in now — should get the cached view as soon as they follow.
  inv2.send(JSON.stringify({ action: 'follow', following: true }));
  const got = await waitForMessage(inv2, m => m.type === 'presenter-state', 800);
  assert.equal(got.state.search, 'current-view');

  owner.close(); inv1.close(); inv2.close();
});

test('presenter follower-count updates when a follower joins or leaves', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const owner = await openConsumer(session);
  await drainSetup(owner);
  owner.send(JSON.stringify({ action: 'presenter-start' }));

  // First status: just the owner presenting, 0 followers.
  const s0 = await waitForMessage(owner, m => m.type === 'presenter-status' && m.presenting);
  assert.equal(s0.followers, 0);

  // An invitee joins — they're auto-forcefollowed, presenter should see 1.
  const invitee = await redeemInvitee(owner, session);
  const s1 = await waitForMessage(owner, m => m.type === 'presenter-status' && m.followers === 1, 1000);
  assert.equal(s1.followers, 1);

  // Invitee disconnects — presenter's follower count should drop to 0.
  invitee.close();
  const s2 = await waitForMessage(owner, m => m.type === 'presenter-status' && m.followers === 0, 1000);
  assert.equal(s2.followers, 0);

  owner.close();
});

test('presenter-state does NOT echo to the sender', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const owner = await openConsumer(session);
  await drainSetup(owner);
  owner.send(JSON.stringify({ action: 'presenter-start' }));
  await sleep(30);
  owner.send(JSON.stringify({ action: 'presenter-state', state: { search: 'self' } }));
  await assert.rejects(
    waitForMessage(owner, m => m.type === 'presenter-state', 300),
    /timeout/,
  );
  owner.close();
});

test('late joiner receives log history replay from the session buffer', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const prod = await openProducer(session, key());
  // Producer streams a few logs BEFORE any consumer is connected.
  prod.send(JSON.stringify({ type: 'log', line: 'pre-1', i: 1 }));
  prod.send(JSON.stringify({ type: 'log', line: 'pre-2', i: 2 }));
  prod.send(JSON.stringify({ type: 'log', line: 'pre-3', i: 3 }));
  await sleep(60);

  const late = await openConsumer(session);
  const begin = await waitForMessage(late, m => m.type === 'history-begin', 1000);
  assert.equal(begin.count, 3);
  const m1 = await waitForMessage(late, m => m.type === 'log' && m.line === 'pre-1', 1000);
  const m2 = await waitForMessage(late, m => m.type === 'log' && m.line === 'pre-2', 1000);
  const m3 = await waitForMessage(late, m => m.type === 'log' && m.line === 'pre-3', 1000);
  const end = await waitForMessage(late, m => m.type === 'history-end', 1000);
  assert.ok(m1 && m2 && m3 && end);

  // And live logs after the replay still reach the late joiner.
  prod.send(JSON.stringify({ type: 'log', line: 'live-1', i: 4 }));
  const m4 = await waitForMessage(late, m => m.type === 'log' && m.line === 'live-1', 1000);
  assert.equal(m4.line, 'live-1');

  prod.close(); late.close();
});

test('history buffer does not replay non-log producer frames', { timeout: TIMEOUT }, async () => {
  // Status / ack-style messages from the producer are ephemeral — they
  // shouldn't leak into a late joiner's replay as if they were fresh events.
  const session = sid();
  const prod = await openProducer(session, key());
  prod.send(JSON.stringify({ type: 'log', line: 'real-log', i: 1 }));
  prod.send(JSON.stringify({ type: 'auth-status', ok: true, arn: 'arn:ephemeral' }));
  prod.send(JSON.stringify({ type: 'init', capturing: false }));
  await sleep(60);

  const late = await openConsumer(session);
  const begin = await waitForMessage(late, m => m.type === 'history-begin', 1000);
  assert.equal(begin.count, 1, 'only the log frame should be replayed');
  const log = await waitForMessage(late, m => m.type === 'log', 1000);
  assert.equal(log.line, 'real-log');

  prod.close(); late.close();
});

test('history survives a producer reconnect', { timeout: TIMEOUT }, async () => {
  const session = sid();
  const k = key();
  const prod1 = await openProducer(session, k);
  // Keep one consumer connected across the swap so the relay doesn't
  // dropIfEmpty the session (which would wipe history along with it).
  const keeper = await openConsumer(session);
  prod1.send(JSON.stringify({ type: 'log', line: 'before-reconnect', i: 1 }));
  await sleep(50);
  prod1.close();
  await sleep(50);

  const prod2 = await openProducer(session, k);
  prod2.send(JSON.stringify({ type: 'log', line: 'after-reconnect', i: 2 }));
  await sleep(50);

  const late = await openConsumer(session);
  const m1 = await waitForMessage(late, m => m.type === 'log' && m.line === 'before-reconnect', 1000);
  const m2 = await waitForMessage(late, m => m.type === 'log' && m.line === 'after-reconnect', 1000);
  assert.ok(m1 && m2);

  prod2.close(); keeper.close(); late.close();
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
// Every opened socket is instrumented with an in-memory queue so tests can
// match messages that arrived before they got a chance to attach a listener
// (the server sends a burst — relay-hello, presenter-status, history — as
// soon as the handshake completes; a naive listener-after-open loses them).
function instrument(ws) {
  ws._queue = [];
  ws._waiters = [];
  ws.on('message', raw => {
    let parsed = null;
    try { parsed = JSON.parse(raw.toString()); } catch { return; }
    ws._queue.push(parsed);
    for (let i = 0; i < ws._waiters.length; i++) {
      const w = ws._waiters[i];
      const idx = ws._queue.findIndex(w.pred);
      if (idx >= 0) {
        const m = ws._queue.splice(idx, 1)[0];
        ws._waiters.splice(i, 1);
        clearTimeout(w.timeout);
        w.resolve(m);
        i--;
      }
    }
  });
  return ws;
}

function waitForOpen(ws, ms = 2000) {
  return new Promise((resolve, reject) => {
    if (ws.readyState === 1) return resolve(instrument(ws));
    const t = setTimeout(() => { cleanup(); reject(new Error('open timeout')); }, ms);
    function cleanup() { clearTimeout(t); ws.off('open', ok); ws.off('error', err); }
    function ok()    { cleanup(); resolve(instrument(ws)); }
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
    setTimeout(() => { if (ws._queue) ws._queue.length = 0; resolve(); }, ms);
  });
}

// Mint an invite from `ownerWs`, redeem it over HTTP, and return an open
// read-only consumer WebSocket. Each call to this bumps the owner's in-flight
// messages so make sure you've drainSetup'd before the first call.
async function redeemInvitee(ownerWs, session) {
  ownerWs.send(JSON.stringify({ action: 'create-invite', ttl: 900, oneUse: false }));
  const inv = await waitForMessage(ownerWs, m => m.type === 'invite-created');
  const res = await fetch(`${baseHttp}${inv.path}`, { redirect: 'manual' });
  const loc = res.headers.get('location') || '';
  const token = new URL(loc, baseHttp).searchParams.get('rotoken');
  const ws = new WebSocket(`${baseWs}/consumer?rotoken=${encodeURIComponent(token)}`);
  await waitForOpen(ws);
  return ws;
}

function waitForMessage(ws, pred, ms = 2000) {
  return new Promise((resolve, reject) => {
    // Drain any already-queued matching message first.
    if (ws._queue) {
      const idx = ws._queue.findIndex(pred);
      if (idx >= 0) return resolve(ws._queue.splice(idx, 1)[0]);
    }
    const waiter = { pred, resolve };
    waiter.timeout = setTimeout(() => {
      if (ws._waiters) {
        const i = ws._waiters.indexOf(waiter);
        if (i >= 0) ws._waiters.splice(i, 1);
      }
      reject(new Error('timeout'));
    }, ms);
    (ws._waiters || (ws._waiters = [])).push(waiter);
  });
}
