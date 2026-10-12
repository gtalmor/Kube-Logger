// Spawn the real relay (server/index.js) on an ephemeral port with throwaway
// data/public dirs. Shared by the relay and agent test suites.
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');

const RELAY = path.join(__dirname, '..', '..', 'server', 'index.js');

function getFreePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.listen(0, '127.0.0.1', () => { const { port } = srv.address(); srv.close(() => resolve(port)); });
    srv.on('error', reject);
  });
}

async function waitFor(fn, timeoutMs = 5000, everyMs = 25) {
  const until = Date.now() + timeoutMs;
  for (;;) {
    try { if (await fn()) return; } catch {}
    if (Date.now() > until) throw new Error('waitFor timeout');
    await new Promise(r => setTimeout(r, everyMs));
  }
}

// opts: { dataDir, publicDir, env, quiet }
async function startRelay(opts = {}) {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'kube-logger-relay-'));
  const dataDir = opts.dataDir || path.join(tmp, 'data');
  const publicDir = opts.publicDir || path.join(tmp, 'public');
  fs.mkdirSync(publicDir, { recursive: true });
  if (!fs.existsSync(path.join(publicDir, 'index.html'))) fs.writeFileSync(path.join(publicDir, 'index.html'), '<!-- test -->');
  const port = opts.port || await getFreePort();
  const proc = spawn(process.execPath, [RELAY], {
    env: { ...process.env, PORT: String(port), HOST: '127.0.0.1', DATA_DIR: dataDir, PUBLIC_DIR: publicDir, NEXT_DIR: path.join(tmp, 'nope'), LEGACY_DIR: path.join(tmp, 'nope'), ...(opts.env || {}) },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let out = '';
  proc.stdout.on('data', d => { out += d; if (opts.verbose || process.env.RELAY_TEST_VERBOSE) process.stderr.write(`[relay] ${d}`); });
  proc.stderr.on('data', d => { out += d; if (!opts.quiet || process.env.RELAY_TEST_VERBOSE) process.stderr.write(`[relay-err] ${d}`); });
  const baseHttp = `http://127.0.0.1:${port}`;
  const baseWs = `ws://127.0.0.1:${port}`;
  await waitFor(async () => (await fetch(`${baseHttp}/health`)).ok, 5000);
  return {
    proc, port, baseHttp, baseWs, dataDir, publicDir, tmp,
    output: () => out,
    stop: () => new Promise(resolve => {
      // After SIGKILL `exitCode` stays null and `signalCode` is set, so check both.
      if (proc.exitCode !== null || proc.signalCode !== null) return resolve();
      proc.once('exit', () => resolve());
      proc.kill('SIGKILL');
    }),
    cleanup() { try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {} },
  };
}

module.exports = { startRelay, getFreePort, waitFor };
