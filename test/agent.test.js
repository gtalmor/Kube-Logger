// Spawn kube-logger-agent with a throwaway HOME and assert CLI behavior.
// We don't connect to the live relay — KUBE_LOGGER_RELAY points at a black-
// holed host and KUBE_LOGGER_NO_BROWSER / NO_UPDATE_CHECK suppress side
// effects. Run: npm test.

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { spawnSync, spawn } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const AGENT = path.join(__dirname, '..', 'agent', 'index.js');

function freshHome() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kl-agent-test-'));
  return { dir, cleanup: () => { try { fs.rmSync(dir, { recursive: true, force: true }); } catch {} } };
}

function runSync(args, env = {}, opts = {}) {
  return spawnSync(process.execPath, [AGENT, ...args], {
    encoding: 'utf8',
    env: { ...process.env, KUBE_LOGGER_NO_BROWSER: '1', KUBE_LOGGER_NO_UPDATE_CHECK: '1', ...env },
    timeout: 5000,
    ...opts,
  });
}

test('--version prints version + platform and exits 0', () => {
  const r = runSync(['--version'], { HOME: freshHome().dir });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /^kube-logger-agent \d+\.\d+\.\d+ \(/);
});

test('--help prints flag reference + exits 0', () => {
  const r = runSync(['--help'], { HOME: freshHome().dir });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /USAGE/);
  assert.match(r.stdout, /--new-session/);
  assert.match(r.stdout, /KUBE_LOGGER_RELAY/);
});

test('--new-session wipes session + producer-key, generates fresh ones', async () => {
  const { dir: HOME, cleanup } = freshHome();
  try {
    // First run: just create the session non-rotating, capture the id.
    const first = await runWithStartupBanner(['--new-session'], { HOME });
    assert.match(first.banner, /Viewer: .*?\?session=([a-f0-9]{16,})/);
    const id1 = first.banner.match(/\?session=([a-f0-9]{16,})/)[1];
    const onDisk1 = fs.readFileSync(path.join(HOME, '.kube-logger', 'session'), 'utf8').trim();
    assert.equal(onDisk1, id1, 'persisted session matches printed URL');

    // Second run with --new-session: id should be different + old file replaced.
    const second = await runWithStartupBanner(['--new-session'], { HOME });
    const id2 = second.banner.match(/\?session=([a-f0-9]{16,})/)[1];
    assert.notEqual(id2, id1, 'new-session must yield a different session id');
    const onDisk2 = fs.readFileSync(path.join(HOME, '.kube-logger', 'session'), 'utf8').trim();
    assert.equal(onDisk2, id2);

    // Producer key should also have rotated.
    const keyPath = path.join(HOME, '.kube-logger', 'producer-key');
    const key2 = fs.readFileSync(keyPath, 'utf8').trim();
    assert.ok(key2.length >= 16);
  } finally { cleanup(); }
});

test('plain run reuses the persisted session id', async () => {
  const { dir: HOME, cleanup } = freshHome();
  try {
    const first  = await runWithStartupBanner([], { HOME });
    const second = await runWithStartupBanner([], { HOME });
    const id1 = first.banner.match(/\?session=([a-f0-9]{16,})/)[1];
    const id2 = second.banner.match(/\?session=([a-f0-9]{16,})/)[1];
    assert.equal(id1, id2, 'persisted session id must be stable across runs');
  } finally { cleanup(); }
});

// Spawn the agent, wait until it prints the boot banner (which contains the
// viewer URL), then SIGTERM it. We can't wait for clean exit because the agent
// loops trying to connect to the relay; we just need its first second of output.
function runWithStartupBanner(args, env) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [AGENT, ...args], {
      env: { ...process.env, KUBE_LOGGER_NO_BROWSER: '1', KUBE_LOGGER_NO_UPDATE_CHECK: '1', KUBE_LOGGER_RELAY: 'http://127.0.0.1:1', ...env },
    });
    let banner = '';
    let done = false;
    const finish = err => { if (done) return; done = true; try { child.kill('SIGTERM'); } catch {} (err ? reject(err) : resolve({ banner })); };
    child.stdout.on('data', d => {
      banner += d.toString();
      if (/Viewer: /.test(banner)) finish();
    });
    child.stderr.on('data', d => { banner += d.toString(); });
    child.on('error', finish);
    setTimeout(() => finish(new Error(`timeout — banner so far:\n${banner}`)), 3000);
  });
}
