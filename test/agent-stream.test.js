// End-to-end: agent + real relay + a fake stern that cannot reach the cluster.
// Checks that watch failures are rate-limited on the way to the viewer, that
// the stream is restarted with a stream-status message, and that it reports
// recovery once lines flow. Run: npm test.
const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const WebSocket = require('ws');
const { startRelay, waitFor } = require('./helpers/relay');

const AGENT = path.join(__dirname, '..', 'agent', 'index.js');
const FAKE_STERN = path.join(__dirname, 'helpers', 'fake-stern.js');

test('agent: a stream that cannot reach the cluster is rate-limited, restarted and reported', { timeout: 30000 }, async () => {
  const relay = await startRelay({ quiet: true });
  const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'kl-stream-'));
  const sternDir = path.join(HOME, 'stern'); fs.mkdirSync(sternDir);
  // A shell shim so the agent can spawn "stern" as a plain executable.
  const shim = path.join(sternDir, 'stern');
  fs.writeFileSync(shim, `#!/bin/sh\nexec "${process.execPath}" "${FAKE_STERN}" "$@"\n`, { mode: 0o755 });
  const agent = spawn(process.execPath, [AGENT], {
    env: { ...process.env, HOME, FAKE_STERN_DIR: sternDir, KUBE_LOGGER_STERN: shim, KUBE_LOGGER_RELAY: relay.baseHttp, KUBE_LOGGER_NO_BROWSER: '1', KUBE_LOGGER_NO_UPDATE_CHECK: '1', KUBE_LOGGER_NO_SYSTEM_CA: '1' },
  });
  let agentOut = '';
  agent.stdout.on('data', d => { agentOut += d; });
  agent.stderr.on('data', d => { agentOut += d; });
  const msgs = [];
  let ws;
  try {
    await waitFor(() => /\[saas\] connected/.test(agentOut), 10000);
    const session = fs.readFileSync(path.join(HOME, '.kube-logger', 'session'), 'utf8').trim();
    ws = new WebSocket(`${relay.baseWs}/consumer?session=${session}`);
    ws.on('message', d => msgs.push(JSON.parse(d.toString())));
    await new Promise((res, rej) => { ws.once('open', res); ws.once('error', rej); });
    ws.send(JSON.stringify({ action: 'start', ns: ['monokee'] }));

    // 15 failures at 100 ms → first restart after ~1.5 s, scheduled 3 s out.
    await waitFor(() => msgs.some(m => m.type === 'stream-status' && m.state === 'degraded'), 8000);
    const degraded = msgs.find(m => m.type === 'stream-status' && m.state === 'degraded');
    assert.equal(degraded.ns, 'monokee');
    assert.equal(degraded.restarts, 1);
    assert.equal(degraded.retryInMs, 3000);
    assert.match(degraded.reason, /^proxyconnect tcp: dial tcp: lookup proxy\.dmz\.gemaltocloud\.com: no such host$/);
    assert.equal(typeof degraded.since, 'number');
    const forwarded = msgs.filter(m => m.type === 'stderr' && /Watch failed/.test(m.msg));
    assert.equal(forwarded.length, 1, 'one failure line forwarded per minute, not one per retry');
    assert.match(agentOut, /\[monokee\] 15 watch failures in a minute — restarting stream in 3s \(restart #1\)/);
    // A viewer that loads mid-outage learns about it from init.
    ws.send(JSON.stringify({ action: 'get-init' }));
    await waitFor(() => msgs.some(m => m.type === 'init' && m.streams && m.streams.monokee), 3000);
    const init = msgs.filter(m => m.type === 'init').pop();
    assert.equal(init.streams.monokee.state, 'degraded');
    assert.equal(init.streams.monokee.restarts, 1);

    // The network comes back: the respawned stream streams lines → recovery.
    fs.writeFileSync(path.join(sternDir, 'healthy'), '');
    await waitFor(() => msgs.some(m => m.type === 'stream-status' && m.state === 'ok'), 10000);
    // The ok status goes out on the first stdout chunk; the batcher flushes the lines 50 ms later.
    await waitFor(() => msgs.some(m => m.type === 'log-batch' && m.items.some(i => i.ns === 'monokee' && /INFO line/.test(i.line))), 3000);
    assert.match(agentOut, /\[monokee\] stream recovered/);
    assert.equal(msgs.filter(m => m.type === 'stderr' && /Watch failed/.test(m.msg)).length, 1);
  } finally {
    try { ws && ws.close(); } catch {}
    agent.kill('SIGTERM');
    await new Promise(r => { agent.once('exit', r); setTimeout(() => { try { agent.kill('SIGKILL'); } catch {} }, 2000); });
    await relay.stop(); relay.cleanup();
    try { fs.rmSync(HOME, { recursive: true, force: true }); } catch {}
  }
});
