#!/usr/bin/env node
// Kube Logger Agent — streams kube logs from the user's laptop to the hosted
// relay + web viewer. Auth, namespace listing, and `stern` live here; parsing
// and rendering happen in the browser.
//
// Security model: the viewer URL's session id is the owner credential. Every
// value that arrives from the viewer (via the relay) is validated before use
// and only ever passed to child processes as argv arrays — never through a
// shell. See agent/lib/validate.js.

const { spawn, execFile } = require('child_process');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');

const V = require('./lib/validate');
const { LineRing } = require('./lib/ring');
const { LogBatcher } = require('./lib/batch');
const { podQuery, parsePodsOutput, PODS_JSONPATH } = require('./lib/workloads');
const { isNewerVersion } = require('./lib/version');
const { normalizeConfig, templateConfig, clusterFor, regionFor, withClusterMapping } = require('./lib/config');
const awscfg = require('./lib/awsconfig');

// Version comes from package.json, which the release workflow rewrites to the
// tag (e.g. "0.3.0") before `bun build --compile` bundles it into the binary.
const { version: VERSION } = require('../package.json');

const DEFAULT_RELAY = 'https://logviewer.gtalmor.com';

// ── CLI ─────────────────────────────────────────────────────────────
const _cli = process.argv.slice(2);
// --max-log-requests: starting limit passed to stern. If the namespace has
// more pods than this, stern aborts at startup; attachStream's close handler
// self-heals by re-spawning with a doubled limit, up to
// MAX_LOG_REQUESTS_CEILING. An explicit flag is a hard cap (no escalation
// past it) so users can bound API-server load.
let maxLogRequests = '100';
let maxLogRequestsExplicit = false;
for (let i = 0; i < _cli.length; i++) {
  if (_cli[i] === '--max-log-requests') {
    if (i + 1 < _cli.length) maxLogRequests = _cli[i + 1];
    maxLogRequestsExplicit = true;
  } else if (_cli[i].startsWith('--max-log-requests=')) {
    maxLogRequests = _cli[i].substring('--max-log-requests='.length);
    maxLogRequestsExplicit = true;
  }
}
const MAX_LOG_REQUESTS_CEILING = maxLogRequestsExplicit ? (parseInt(maxLogRequests, 10) || 100) : 5000;

if (_cli.some(a => a === '--help' || a === '-h')) {
  console.log(`kube-logger-agent ${VERSION}

  Streams Kubernetes logs from this machine to ${DEFAULT_RELAY}.

USAGE
  kube-logger-agent [flags]

FLAGS
  -h, --help           Show this help and exit.
  -v, --version        Print version + platform and exit.
  -o, --open           Print the viewer URL for the persisted session and
                       open it in your default browser, then exit. Useful
                       when the agent is already running in the background.
      --new-session    Wipe ~/.kube-logger/session + producer-key, generate
      --rotate         fresh ones, and continue normal startup. Invalidates
                       the existing viewer URL.
      --max-log-requests <num>  Starting limit for concurrent pod log streams
                       (default: 100). If a namespace has more pods, the
                       limit auto-doubles up to 5000. Passing this flag caps
                       escalation at <num> to bound API-server load.

ENVIRONMENT
  KUBE_LOGGER_RELAY            Override the relay endpoint (default:
                               ${DEFAULT_RELAY}). Useful for
                               pointing at a local relay for testing.
  KUBE_LOGGER_STERN            Path to the stern binary (default: "stern"
                               found on PATH). stern is required.
  KUBE_LOGGER_NO_BROWSER=1     Don't auto-open the viewer on boot.
  KUBE_LOGGER_NO_UPDATE_CHECK=1
                               Skip the GitHub release check.
  KUBE_LOGGER_FORCE=1          In non-TTY runs, take over an existing agent
                               instead of refusing to start.

FILES
  ~/.kube-logger/session       Persisted 32-char session id (in viewer URL).
  ~/.kube-logger/producer-key  Per-machine secret binding this agent to the
                               session at the relay.
  ~/.kube-logger/config.json   Region + AWS-profile-to-EKS-cluster map +
                               disabled profiles + per-profile login commands
                               (externalAuthCommands) for non-SSO profiles like
                               saml2aws/Keycloak. A cluster entry is either
                               "cluster-name" or {"name": "...", "region": "..."}.
                               Edit by hand.
  ~/.kube-logger/agent.pid     PID of the live agent on this machine.
`);
  process.exit(0);
}
if (_cli.some(a => a === '--version' || a === '-v')) {
  console.log(`kube-logger-agent ${VERSION} (${process.platform}-${process.arch})`);
  process.exit(0);
}

const RELAY_HTTP_URL = (process.env.KUBE_LOGGER_RELAY || DEFAULT_RELAY).replace(/\/+$/, '');
const RELAY_WS_URL = RELAY_HTTP_URL.replace(/^http:/, 'ws:').replace(/^https:/, 'wss:');
const CONFIG_DIR = path.join(os.homedir(), '.kube-logger');
const SESSION_FILE = path.join(CONFIG_DIR, 'session');
const PRODUCER_KEY_FILE = path.join(CONFIG_DIR, 'producer-key');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');
const PID_FILE = path.join(CONFIG_DIR, 'agent.pid');

function openInBrowser(url) {
  const opener = { darwin: 'open', linux: 'xdg-open', win32: 'start' }[process.platform];
  if (!opener) return;
  try { spawn(opener, [url], { stdio: 'ignore', detached: true, shell: process.platform === 'win32' }).unref(); }
  catch {}
}

if (_cli.some(a => a === '--open' || a === '-o')) {
  let sid = '';
  try { sid = fs.readFileSync(SESSION_FILE, 'utf8').trim(); } catch {}
  if (!sid || sid.length < 16) {
    console.error('No session yet — start `kube-logger-agent` at least once first.');
    process.exit(1);
  }
  const url = `${RELAY_HTTP_URL}/?session=${sid}`;
  console.log(url);
  openInBrowser(url);
  process.exit(0);
}

// ── Local files: pid, secrets, config ───────────────────────────────
function existingAgentPid() {
  try {
    const pid = parseInt(fs.readFileSync(PID_FILE, 'utf8').trim(), 10);
    if (!pid || Number.isNaN(pid) || pid === process.pid) return null;
    try { process.kill(pid, 0); return pid; } catch { return null; }
  } catch { return null; }
}

function writePidFile() {
  try {
    fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(PID_FILE, String(process.pid), { mode: 0o600 });
  } catch {}
  process.on('exit', () => {
    try {
      const pid = fs.readFileSync(PID_FILE, 'utf8').trim();
      if (pid === String(process.pid)) fs.unlinkSync(PID_FILE);
    } catch {}
  });
}

// Read a 16-byte hex secret from `file`, or generate and persist a new one.
function loadOrCreateSecret(file, label) {
  try {
    const existing = fs.readFileSync(file, 'utf8').trim();
    if (existing.length >= 16) return existing;
  } catch {}
  const id = crypto.randomBytes(16).toString('hex');
  try {
    fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
    fs.writeFileSync(file, id + '\n', { mode: 0o600 });
  } catch (e) {
    console.error(`[${label}] could not persist to ${file}: ${e.message}`);
  }
  return id;
}

function loadAgentConfig() {
  try {
    return normalizeConfig(JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')));
  } catch {
    try {
      fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
      fs.writeFileSync(CONFIG_FILE, JSON.stringify(templateConfig(), null, 2) + '\n', { mode: 0o600 });
    } catch (e) {
      console.error(`[config] could not write template to ${CONFIG_FILE}: ${e.message}`);
    }
    return normalizeConfig(templateConfig());
  }
}
const CFG = loadAgentConfig();

// Persist a profile→cluster mapping so future logins skip discovery.
function persistClusterMapping(profile, cluster, region) {
  CFG.clusters[profile] = { name: cluster, region };
  try {
    let j = {};
    try { j = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8')); } catch {}
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(withClusterMapping(j, profile, cluster, region), null, 2) + '\n', { mode: 0o600 });
  } catch (e) {
    console.error(`[config] could not persist cluster mapping: ${e.message}`);
  }
}

// ── Tool discovery ──────────────────────────────────────────────────
function findOnPath(cmd) {
  if (path.isAbsolute(cmd)) { try { fs.accessSync(cmd, fs.constants.X_OK); return cmd; } catch { return null; } }
  const exts = process.platform === 'win32' ? ['.exe', '.cmd', ''] : [''];
  for (const dir of (process.env.PATH || '').split(path.delimiter)) {
    if (!dir) continue;
    for (const ext of exts) {
      const full = path.join(dir, cmd + ext);
      try { fs.accessSync(full, fs.constants.X_OK); return full; } catch {}
    }
  }
  return null;
}
const STERN_BIN = process.env.KUBE_LOGGER_STERN || 'stern';
const STERN_PATH = findOnPath(STERN_BIN);
const STERN_MISSING_MSG = `stern not found (looked for "${STERN_BIN}"). Install it (brew install stern) or set KUBE_LOGGER_STERN=/path/to/stern, then restart the agent.`;
const LOG_TOOL = 'stern';

// ── AWS profile helpers ─────────────────────────────────────────────
const readText = p => { try { return fs.readFileSync(p, 'utf8'); } catch { return ''; } };
const AWS_CONFIG_PATH = path.join(os.homedir(), '.aws', 'config');
const AWS_CREDS_PATH = path.join(os.homedir(), '.aws', 'credentials');

function discoverProfiles() {
  const names = awscfg.parseProfiles(readText(AWS_CONFIG_PATH));
  const base = names.length ? names : Object.keys(CFG.clusters);
  return base.filter(n => !CFG.disabledProfiles.has(n));
}
const isSsoProfile = name => awscfg.isSsoProfile(readText(AWS_CONFIG_PATH), name);
const getCredExpiration = profile => awscfg.credExpiration(readText(AWS_CREDS_PATH), profile);
function getSsoExpiration() {
  const cacheDir = path.join(os.homedir(), '.aws', 'sso', 'cache');
  let blobs = [];
  try {
    blobs = fs.readdirSync(cacheDir).filter(f => f.endsWith('.json')).map(f => {
      try { return JSON.parse(fs.readFileSync(path.join(cacheDir, f), 'utf8')); } catch { return null; }
    });
  } catch {}
  return awscfg.latestSsoExpiry(blobs);
}

// How the agent authenticates a given profile:
//   'sso'      → `aws sso login` (browser).
//   'command'  → a configured command (saml2aws/assume-role helper). No browser.
//   'external' → non-SSO with no command: verify creds the user wrote by hand.
function authMode(name) {
  if (isSsoProfile(name)) return 'sso';
  if (name && CFG.externalAuthCommands[name]) return 'command';
  return 'external';
}
function authLabel(name) {
  return CFG.externalAuthLabels[name] || (authMode(name) === 'sso' ? 'SSO' : 'External');
}
function externalAuthHint(name) {
  if (authMode(name) === 'command')
    return `Not authenticated for "${name}". Click ${authLabel(name)} Login to run your login command.`;
  const custom = CFG.externalAuthHints[name];
  if (custom) return `External login required for "${name}". Run: ${custom}`;
  return `External login required for "${name}". Run your saml2aws / credential helper in a terminal, then click Login again.`;
}

// ── Child processes ─────────────────────────────────────────────────
// Strip every AWS_* variable the parent shell might have set so it can't
// shadow the --profile we pass explicitly.
function cleanAwsEnv(extra) {
  const env = {};
  for (const k of Object.keys(process.env)) if (!k.startsWith('AWS_')) env[k] = process.env[k];
  if (extra) Object.assign(env, extra);
  return env;
}
function profileEnv() {
  return authCache && authCache.profile
    ? { AWS_DEFAULT_PROFILE: authCache.profile, AWS_REGION: regionFor(CFG, authCache.profile) }
    : undefined;
}

// Run a command with an argv array (never a shell). Resolves with
// { ok, code, out } where `out` is stdout+stderr, trimmed.
function run(cmd, args, { timeout = 15000, env } = {}) {
  return new Promise(resolve => {
    execFile(cmd, args, { timeout, env: env || cleanAwsEnv(), maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      const out = `${stdout || ''}${stderr || ''}`.trim();
      if (err) resolve({ ok: false, code: typeof err.code === 'number' ? err.code : 1, out: out || err.message });
      else resolve({ ok: true, code: 0, out, stdout: String(stdout || '') });
    });
  });
}

// ── State ───────────────────────────────────────────────────────────
// capture: { id, procs: Map<ns, proc>, nsList, start, ring: LineRing, filters: Map<ns, workloads[]> }
let capture = null;
let authCache = null;  // { ts, profile, ok, arn, account, err, expiresAt, cluster }

const RING_MAX_LINES = 20000;
const RING_MAX_BYTES = 10 * 1024 * 1024;

// ── Relay producer connection ───────────────────────────────────────
let producer = null;           // live ws to the relay
let reconnectTimer = null;
let reconnectDelay = 3000;
let replaying = false;         // true while a post-hello replay is in flight (live lines go via the ring instead)

function broadcast(msg) {
  if (producer && producer.readyState === 1) {
    try { producer.send(JSON.stringify(msg)); } catch {}
  }
}
const batcher = new LogBatcher({ maxItems: 200, maxDelayMs: 50, send: items => broadcast({ type: 'log-batch', items }) });

function scheduleReconnect() {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => { reconnectTimer = null; connectProducer(); }, reconnectDelay);
  reconnectDelay = Math.min(reconnectDelay * 2, 30000);
}

// The producer key is a secret: never let it reach the console (bun's ws
// error messages include the full URL).
const scrubKey = s => String(s).replace(/([?&]key=)[^&\s'"]+/g, '$1***');

function explainRejectedAndExit() {
  console.error(`\n  The relay rejected this agent: another agent owns session ${SESSION_ID.slice(0, 8)}….`);
  console.error(`  Either another machine is running kube-logger-agent with this session id, or`);
  console.error(`  ~/.kube-logger/producer-key was lost. Fix: run \`kube-logger-agent --new-session\``);
  console.error(`  for a fresh viewer URL, or copy ~/.kube-logger/producer-key from the owning machine.\n`);
  process.exit(1);
}

// A connect that never reached 'open' may have been refused at the HTTP
// upgrade (401 = key mismatch). Ask the relay's read-only check endpoint so
// we can stop instead of retrying forever. Works under node and bun.
async function classifyFailedConnect() {
  try {
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 3000);
    const res = await fetch(`${RELAY_HTTP_URL}/producer/check?session=${encodeURIComponent(SESSION_ID)}&key=${encodeURIComponent(PRODUCER_KEY)}`, { signal: ctl.signal });
    clearTimeout(t);
    if (res.status === 401) explainRejectedAndExit();
  } catch {}
  scheduleReconnect();
}

function connectProducer() {
  if (producer && producer.readyState !== 3 /* CLOSED */) return;
  const { WebSocket } = require('ws');
  const wsUrl = `${RELAY_WS_URL}/producer?session=${encodeURIComponent(SESSION_ID)}&key=${encodeURIComponent(PRODUCER_KEY)}`;
  // Keep the "[saas] connecting" / "[saas] connected" wording: Assume Keycloaker
  // and other wrappers parse these lines to show the agent's status.
  console.log(`[saas] connecting to ${RELAY_WS_URL}/producer?session=${SESSION_ID}`);
  const ws = new WebSocket(wsUrl);
  producer = ws;
  let opened = false;

  ws.on('open', () => {
    opened = true;
    reconnectDelay = 3000;
    console.log(`[saas] connected (session ${SESSION_ID.slice(0, 8)}…)`);
    ws.send(JSON.stringify(buildInitMessage()));
    // History is replayed only after the relay tells us what it already has
    // (producer-hello), so a blip doesn't re-send 20k lines.
  });

  ws.on('message', async raw => {
    const send = m => { try { if (ws.readyState === 1) ws.send(JSON.stringify(m)); } catch {} };
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }
    if (!msg || typeof msg !== 'object') return;
    if (msg.type === 'producer-hello') { handleProducerHello(ws, msg); return; }
    if (typeof msg.action !== 'string') return;
    try { await handleAction(msg, send); }
    catch (e) { send({ type: 'error', msg: e.message }); }
  });

  // HTTP-level rejection at upgrade (node's ws only; bun lacks this event
  // and goes through classifyFailedConnect from 'close' instead).
  if (typeof Bun === 'undefined') {
    ws.on('unexpected-response', (req, res) => {
      try { req.destroy(); } catch {}
      if (producer === ws) producer = null;
      opened = true; // don't classify again from 'close'
      if (res.statusCode === 401) explainRejectedAndExit();
      console.error(`[saas] connect rejected with HTTP ${res.statusCode}; retrying in ${reconnectDelay / 1000}s`);
      scheduleReconnect();
    });
  }

  ws.on('close', (code, reason) => {
    console.log(`[saas] disconnected (code ${code}, reason: ${scrubKey(reason || 'n/a')})`);
    if (producer === ws) producer = null;
    replaying = false;
    // Code 4000 = the relay kicked us because a newer agent (same session+key)
    // claimed the session. Reconnecting would just kick that one back.
    if (code === 4000) {
      console.error(`\n  Another agent has taken over this session.`);
      console.error(`  Likely you have a duplicate kube-logger-agent running. Find it:`);
      console.error(`    pgrep -af kube-logger-agent\n`);
      process.exit(1);
    }
    if (!opened) { classifyFailedConnect(); return; }
    scheduleReconnect();
  });

  ws.on('error', e => {
    // Node's ws reports HTTP rejections via 'unexpected-response'; everything
    // else (ECONNREFUSED, DNS, TLS, and bun's upgrade failures) lands here and
    // 'close' decides whether to classify or retry.
    if (!/Unexpected server response/.test(e.message)) console.error(`[saas] error: ${scrubKey(e.message)}`);
  });
}

// The relay tells us what it still holds for this session. Replay only what
// it is missing: nothing if the capture id matches and it has everything,
// the tail after `lastIndex` if it matches, the whole ring otherwise.
function handleProducerHello(ws, hello) {
  if (!capture) return;
  const ring = capture.ring;
  ws.send(JSON.stringify({
    type: 'capture-state', captureId: capture.id, ns: capture.nsList, start: capture.start,
    filters: Object.fromEntries(capture.filters), n: ring.total, first: ring.firstIndex, last: ring.lastIndex,
  }));
  const same = hello.captureId === capture.id && Number.isFinite(hello.lastIndex);
  const from = same ? hello.lastIndex + 1 : ring.firstIndex;
  replayFrom(ws, capture, from).catch(e => console.error(`[saas] replay failed: ${e.message}`));
}

const sleep = ms => new Promise(r => setTimeout(r, ms));
async function replayFrom(ws, cap, from) {
  if (from > cap.ring.lastIndex) return;
  console.log(`[saas] replaying from ${Math.max(from, cap.ring.firstIndex)} (ring ${cap.ring.firstIndex}..${cap.ring.lastIndex})`);
  // Lines queued in the batcher are in the ring too; the loop below covers them.
  batcher.discard();
  replaying = true;
  let next = from;
  try {
    while (true) {
      if (producer !== ws || ws.readyState !== 1 || capture !== cap) return;
      const items = cap.ring.slice(next, 500);
      if (items.length === 0) break;
      ws.send(JSON.stringify({ type: 'log-batch', items }));
      next = items[items.length - 1].i + 1;
      while (ws.bufferedAmount > 4 * 1024 * 1024) {
        await sleep(20);
        if (producer !== ws || ws.readyState !== 1 || capture !== cap) return;
      }
      await sleep(0);
    }
  } finally {
    replaying = false;
  }
}

// ── Auth ────────────────────────────────────────────────────────────
function checkAuth(profile, force) {
  return (async () => {
    const now = Date.now();
    if (!force && authCache && authCache.profile === profile && (now - authCache.ts) < 30000) return authCache;
    const r = profile
      ? await run('aws', ['sts', 'get-caller-identity', '--profile', profile, '--output', 'json'], { timeout: 10000 })
      : await run('kubectl', ['auth', 'can-i', 'get', 'pods', '--all-namespaces'], { timeout: 10000 });
    const prevCluster = authCache && authCache.profile === profile ? authCache.cluster : undefined;
    if (!r.ok) {
      authCache = { ts: now, profile, ok: false, err: r.out.slice(0, 200) };
    } else {
      try {
        const id = JSON.parse(r.stdout);
        authCache = { ts: now, profile, ok: true, arn: id.Arn, account: id.Account };
      } catch {
        authCache = { ts: now, profile, ok: r.out.toLowerCase() === 'yes' };
      }
    }
    if (prevCluster) authCache.cluster = prevCluster;
    authCache.expiresAt = (profile && !isSsoProfile(profile)) ? getCredExpiration(profile) : getSsoExpiration();
    return authCache;
  })();
}

function authStatusMessage(extra) {
  const p = authCache ? authCache.profile : undefined;
  return { type: 'auth-status', ...authCache, authMode: authMode(p), authLabel: authLabel(p), ...extra };
}

async function finishLogin(profile, mode, send) {
  await checkAuth(profile, true);
  broadcast(authStatusMessage({ authMode: mode }));
  const cluster = clusterFor(CFG, profile);
  if (cluster) return applyCluster(profile, cluster, regionFor(CFG, profile), send);
  return discoverAndApplyCluster(profile, send);
}

// 'command' mode: run the user's configured login command on the agent
// machine. Through a login shell so PATH/Keychain/$(…) behave like the user's
// terminal. This command comes from the user's own config file, never from
// the viewer.
async function runAuthCommand(profile, send) {
  const label = authLabel(profile);
  send({ type: 'auth-progress', msg: `Checking ${label} session…` });
  const r = await checkAuth(profile, true);
  if (r.ok) {
    send({ type: 'auth-progress', msg: `${label} session already active — connecting…` });
    return finishLogin(profile, 'command', send);
  }
  send({ type: 'auth-progress', msg: `Authenticating (${label}) on agent machine…` });
  const shell = process.env.SHELL || '/bin/bash';
  const proc = spawn(shell, ['-lc', CFG.externalAuthCommands[profile]], { stdio: ['ignore', 'pipe', 'pipe'], env: cleanAwsEnv() });
  let out = '';
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; try { proc.kill('SIGKILL'); } catch {} }, 90000);
  proc.stdout.on('data', d => out += d);
  proc.stderr.on('data', d => out += d);
  proc.on('error', e => {
    clearTimeout(timer);
    broadcast({ type: 'auth-status', ok: false, profile, authMode: 'command', err: `${label} login couldn't start: ${e.message}. ${externalAuthHint(profile)}` });
  });
  proc.on('close', async () => {
    clearTimeout(timer);
    await checkAuth(profile, true);
    if (!authCache.ok) {
      const tail = out.trim().slice(-200);
      const why = timedOut ? 'timed out after 90s' : (tail ? `: ${tail}` : '');
      broadcast({ type: 'auth-status', ok: false, profile, authMode: 'command', err: `${label} login failed ${why}. ${externalAuthHint(profile)}` });
      return;
    }
    finishLogin(profile, 'command', send);
  });
}

async function doLogin(profile, send) {
  const mode = authMode(profile);
  if (mode === 'command') return runAuthCommand(profile, send);
  if (mode === 'external') {
    send({ type: 'auth-progress', msg: `Verifying ${profile} credentials…` });
    const r = await checkAuth(profile, true);
    if (!r.ok) { broadcast({ type: 'auth-status', ok: false, profile, authMode: mode, err: externalAuthHint(profile) }); return; }
    return finishLogin(profile, mode, send);
  }
  send({ type: 'auth-progress', msg: 'Opening browser for SSO...' });
  const proc = spawn('aws', ['sso', 'login', '--profile', profile], { stdio: ['pipe', 'pipe', 'pipe'], env: cleanAwsEnv() });
  let out = '';
  proc.stdout.on('data', d => out += d);
  proc.stderr.on('data', d => out += d);
  proc.on('error', e => broadcast({ type: 'auth-status', ok: false, profile, authMode: mode, err: `SSO failed: ${e.message}` }));
  proc.on('close', code => {
    if (code !== 0) { broadcast({ type: 'auth-status', ok: false, profile, authMode: mode, err: `SSO failed: ${out.slice(0, 200)}` }); return; }
    finishLogin(profile, mode, send);
  });
}

// ── Cluster / namespaces / pods ─────────────────────────────────────
async function loadNamespaces(out) {
  const r = await run('kubectl', ['get', 'namespaces', '-o', 'jsonpath={.items[*].metadata.name}'], { timeout: 10000, env: cleanAwsEnv(profileEnv()) });
  if (!r.ok) out({ type: 'namespaces', list: [], err: r.out.slice(0, 300) });
  else out({ type: 'namespaces', list: r.stdout.replace(/"/g, '').split(/\s+/).filter(Boolean).sort() });
}

async function applyCluster(profile, cluster, region, send) {
  const r = await run('aws', ['eks', 'update-kubeconfig', '--name', cluster, '--region', region],
    { timeout: 15000, env: cleanAwsEnv({ AWS_DEFAULT_PROFILE: profile, AWS_REGION: region }) });
  if (!r.ok) { send({ type: 'auth-result', ok: true, msg: `kubeconfig update failed: ${r.out.slice(0, 120)}` }); return; }
  persistClusterMapping(profile, cluster, region);
  authCache = { ...authCache, cluster };
  broadcast(authStatusMessage());
  send({ type: 'auth-result', ok: true, msg: `Connected to ${cluster}` });
  loadNamespaces(broadcast);
}

async function discoverAndApplyCluster(profile, send) {
  const region = regionFor(CFG, profile);
  send({ type: 'auth-progress', msg: `Discovering EKS clusters in ${region}…` });
  const r = await run('aws', ['eks', 'list-clusters', '--region', region, '--profile', profile, '--output', 'json'], { timeout: 15000 });
  if (!r.ok) { send({ type: 'auth-result', ok: true, msg: `Cluster discovery failed: ${r.out.slice(0, 200)}` }); return; }
  let clusters = [];
  try { clusters = JSON.parse(r.stdout).clusters || []; } catch {}
  clusters = clusters.filter(V.isCluster);
  if (clusters.length === 0) send({ type: 'auth-result', ok: true, msg: `No EKS clusters found in ${region} for "${profile}".` });
  else if (clusters.length === 1) applyCluster(profile, clusters[0], region, send);
  else send({ type: 'cluster-pick', profile, region, clusters });
}

async function listWorkloads(ns, send) {
  const r = await run('kubectl', ['get', 'pods', '-n', ns, '-o', 'jsonpath=' + PODS_JSONPATH], { timeout: 12000, env: cleanAwsEnv(profileEnv()) });
  if (!r.ok) { send({ type: 'pods', ns, workloads: [], err: r.out.slice(0, 300) }); return; }
  send({ type: 'pods', ns, workloads: parsePodsOutput(r.stdout) });
}

function buildInitMessage() {
  const profiles = discoverProfiles();
  return {
    type: 'init',
    auth: authCache ? { ...authCache, authMode: authMode(authCache.profile), authLabel: authLabel(authCache.profile) } : null,
    capturing: !!capture,
    tool: LOG_TOOL,
    sternAvailable: !!STERN_PATH,
    profiles,
    profileModes: Object.fromEntries(profiles.map(p => [p, { mode: authMode(p), label: authLabel(p) }])),
    ns: capture ? capture.nsList : null,
    filters: capture ? Object.fromEntries(capture.filters) : null,
    captureId: capture ? capture.id : null,
    start: capture ? capture.start : null,
    n: capture ? capture.ring.total : 0,
  };
}

// Validate a profile from the viewer: well-formed and actually configured.
function knownProfile(p) {
  V.assertValid('profile', p);
  if (!discoverProfiles().includes(p)) throw new Error('unknown profile');
  return p;
}

// Dispatches a viewer action forwarded by the relay. `send` replies to the
// requester; broadcast() is for state changes every viewer should see.
// Every input is validated here before it reaches a child process.
async function handleAction(msg, send) {
  switch (msg.action) {
    case 'check-auth': {
      const profile = msg.profile ? knownProfile(msg.profile) : undefined;
      const r = await checkAuth(profile);
      const mode = authMode(profile);
      const meta = { authMode: mode, authLabel: authLabel(profile) };
      if (!r.ok && profile && mode !== 'sso') send({ type: 'auth-status', ...r, ...meta, err: externalAuthHint(profile) });
      else send({ type: 'auth-status', ...r, ...meta });
      break;
    }
    case 'login':
      await doLogin(knownProfile(msg.profile), send);
      break;
    case 'namespaces':
      await loadNamespaces(send);
      break;
    case 'pick-cluster': {
      const profile = knownProfile(msg.profile);
      const cluster = V.assertValid('cluster', msg.cluster);
      const region = msg.region != null ? V.assertValid('region', msg.region) : regionFor(CFG, profile);
      await applyCluster(profile, cluster, region, send);
      break;
    }
    case 'get-init':
      send(buildInitMessage());
      break;
    case 'start':
      startCapture(V.namespaceList(msg.ns), V.filterMap(msg.filters), send);
      break;
    case 'add-ns':
      addNamespaces(V.namespaceList(msg.ns), V.filterMap(msg.filters), send);
      break;
    case 'remove-ns':
      removeNamespaces(V.namespaceList(msg.ns));
      break;
    case 'pods':
      await listWorkloads(V.assertValid('namespace', msg.ns), send);
      break;
    case 'set-filter': {
      const ns = V.assertValid('namespace', msg.ns);
      const workloads = msg.workloads == null ? [] : V.assertValid('workloadList', msg.workloads);
      setFilter(ns, workloads);
      break;
    }
    case 'stop': {
      const r = stopCapture();
      broadcast({ type: 'capture-stop', ...r });
      break;
    }
    case 'clear':
      if (capture) stopCapture();
      broadcast({ type: 'cleared' });
      break;
    default:
      // Unknown / legacy actions (saas-connect, save, presence, …) are ignored.
      break;
  }
}

// ── Capture ─────────────────────────────────────────────────────────
function spawnStream(ns, env, limit, workloads) {
  const args = ['-n', ns, podQuery(workloads), '--since', '1s', '--no-follow=false', '--color', 'never',
    '--max-log-requests', String(limit || maxLogRequests)];
  return spawn(STERN_PATH || STERN_BIN, args, { env });
}

function attachStream(ns, startLimit) {
  if (!capture || capture.procs.has(ns)) return;
  const cap = capture;
  const env = cleanAwsEnv(profileEnv());
  const limit = startLimit || parseInt(maxLogRequests, 10) || 100;
  const workloads = cap.filters.get(ns) || null;
  const proc = spawnStream(ns, env, limit, workloads);
  let buf = '';
  let firstData = true;
  let stderrBuf = '';
  console.log(`[${ns}] spawned ${LOG_TOOL} (pid ${proc.pid})`);

  const isCurrent = () => capture === cap && cap.procs.get(ns) === proc;

  proc.stdout.on('data', chunk => {
    if (!isCurrent()) return;
    if (firstData) { firstData = false; console.log(`[${ns}] first line received`); }
    buf += chunk.toString();
    const parts = buf.split('\n');
    buf = parts.pop();
    for (const line of parts) {
      if (!line.trim()) continue;
      const i = cap.ring.push(ns, line);
      // During a post-reconnect replay the replay loop reads straight from
      // the ring, so don't double-send through the batcher.
      if (!replaying) batcher.push({ i, ns, line });
    }
  });

  proc.stderr.on('data', d => {
    const msg = d.toString().trim();
    if (!msg || msg.includes('ExperimentalWarning')) return;
    stderrBuf += msg + '\n';
    if (stderrBuf.length > 4000) stderrBuf = stderrBuf.slice(-4000);
    console.error(`[${ns}] stderr: ${msg.slice(0, 500)}`);
    // Early auth-expiration detection: stern surfaces these long before the
    // 60s periodic checkAuth would.
    if (/Token has expired|ExpiredToken|InvalidClientTokenId|UnauthorizedOperation|refresh failed|ExpiredTokenException|unable to get a Token|SSOTokenLoadError/i.test(msg)) {
      const prev = authCache || {};
      authCache = { ts: Date.now(), profile: prev.profile, ok: false, err: 'SSO token expired — re-login' };
      broadcast(authStatusMessage());
    }
    if (isCurrent()) broadcast({ type: 'stderr', ns, msg });
  });

  proc.on('close', code => {
    const lineCountForNs = cap.ring.countFor(ns);
    console.log(`[${ns}] ${LOG_TOOL} exited (code ${code}, ${lineCountForNs} lines for this ns in buffer)`);
    if (code !== 0 && stderrBuf) console.error(`[${ns}] ─── tail of stderr ───\n${stderrBuf.slice(-1500)}─── end stderr ───`);
    if (!isCurrent()) return;

    // Self-healing: stern aborts at startup if the namespace has more pods
    // than --max-log-requests. Re-spawn with a doubled limit, up to the
    // ceiling. Fires before any logs stream, so nothing is lost or repeated.
    const overLimit = code !== 0 && /maximum number of log requests \(\d+\)/.test(stderrBuf);
    if (overLimit && limit < MAX_LOG_REQUESTS_CEILING) {
      const next = Math.min(limit * 2, MAX_LOG_REQUESTS_CEILING);
      console.log(`[${ns}] stern hit max-log-requests (${limit}); retrying with ${next}`);
      broadcast({ type: 'stderr', ns, msg: `Namespace has more pods than the stream limit (${limit}); retrying with ${next}.` });
      cap.procs.delete(ns);
      attachStream(ns, next);
      return;
    }
    if (overLimit) {
      console.error(`[${ns}] stern still over the limit at ceiling ${MAX_LOG_REQUESTS_CEILING}`);
      broadcast({ type: 'stderr', ns, msg: `Namespace exceeds the maximum stream limit (${MAX_LOG_REQUESTS_CEILING}). Narrow the namespace${maxLogRequestsExplicit ? ' or raise --max-log-requests' : ''}.` });
    }
    cap.procs.delete(ns);
    cap.nsList = cap.nsList.filter(n => n !== ns);
    broadcast({ type: 'stream-end', ns, code, stderr: stderrBuf.slice(-500) });
    if (cap.procs.size === 0) {
      const n = cap.ring.total;
      console.log(`[capture] all streams ended — ending capture. Total: ${n} lines.`);
      batcher.flush();
      capture = null;
      broadcast({ type: 'capture-end', code, n });
    } else {
      console.log(`[capture] ${ns} done, still running: [${[...cap.procs.keys()].join(', ')}]`);
    }
  });

  proc.on('error', e => {
    console.error(`[${ns}] spawn error: ${e.message}`);
    broadcast({ type: 'error', ns, msg: e.message });
  });

  cap.procs.set(ns, proc);
  if (!cap.nsList.includes(ns)) cap.nsList.push(ns);
}

// filters: { ns: [workload,...] }. A namespace absent (or empty) → all pods.
function mergeFilters(filters) {
  if (!capture || !filters) return;
  for (const [ns, wls] of Object.entries(filters)) {
    if (Array.isArray(wls) && wls.length) capture.filters.set(ns, wls);
    else capture.filters.delete(ns);
  }
}

function requireStern(send) {
  if (STERN_PATH) return true;
  const m = { type: 'error', msg: STERN_MISSING_MSG };
  if (send) send(m); else broadcast(m);
  return false;
}

function startCapture(nsList, filters, send) {
  if (!requireStern(send)) return;
  if (capture) stopCapture();
  if (!nsList.length) return;
  capture = {
    id: crypto.randomBytes(8).toString('hex'),
    procs: new Map(), nsList: [], start: Date.now(),
    ring: new LineRing({ maxLines: RING_MAX_LINES, maxBytes: RING_MAX_BYTES }),
    filters: new Map(),
  };
  mergeFilters(filters);
  for (const ns of nsList) attachStream(ns);
  broadcast({ type: 'capture-start', captureId: capture.id, ns: [...capture.nsList], start: capture.start, tool: LOG_TOOL, filters: Object.fromEntries(capture.filters) });
}

function addNamespaces(nsList, filters, send) {
  if (!capture) return;
  if (!requireStern(send)) return;
  mergeFilters(filters);
  const added = [];
  for (const ns of nsList) {
    if (capture.procs.has(ns)) continue;
    attachStream(ns);
    if (capture && capture.procs.has(ns)) added.push(ns);
  }
  if (added.length) broadcast({ type: 'ns-added', ns: added });
}

function killLater(proc) {
  try { proc.kill('SIGTERM'); } catch {}
  const t = setTimeout(() => { try { proc.kill('SIGKILL'); } catch {} }, 2000);
  if (t.unref) t.unref();
}

// Live-change which workloads a namespace captures: update the filter and
// re-spawn just that namespace's stream. Deleting the old proc from the map
// before killing it means its close handler no-ops.
function setFilter(ns, workloads) {
  if (!capture) return;
  if (workloads.length) capture.filters.set(ns, workloads); else capture.filters.delete(ns);
  const old = capture.procs.get(ns);
  if (!old) return;
  capture.procs.delete(ns);
  attachStream(ns);
  killLater(old);
  broadcast({ type: 'ns-refiltered', ns, workloads });
}

function removeNamespaces(nsList) {
  if (!capture) return;
  for (const ns of nsList) {
    const proc = capture.procs.get(ns);
    if (proc) killLater(proc);
  }
}

function stopCapture() {
  if (!capture) return null;
  const { procs, nsList, start, ring } = capture;
  for (const proc of procs.values()) killLater(proc);
  batcher.flush();
  const result = { ns: nsList, start, end: Date.now(), n: ring.total };
  capture = null;
  return result;
}

// ── Startup ─────────────────────────────────────────────────────────
if (_cli.some(a => a === '--new-session' || a === '--rotate')) {
  try { fs.unlinkSync(SESSION_FILE); } catch {}
  try { fs.unlinkSync(PRODUCER_KEY_FILE); } catch {}
  console.log('  Session rotated — old viewer URL is now invalid.');
}

let SESSION_ID = '';
let PRODUCER_KEY = '';
let VIEWER_URL = '';

// If another kube-logger-agent is already running on this machine, ask the
// user what to do — kill it, take over with a fresh session, or quit.
async function promptDuplicateAgent() {
  const pid = existingAgentPid();
  if (!pid) return { freshSession: false };
  if (!process.stdin.isTTY) {
    console.error(`\n  Another kube-logger-agent is already running (PID ${pid}).`);
    console.error(`  Stop it first or pass KUBE_LOGGER_FORCE=1 to take over.\n`);
    if (!process.env.KUBE_LOGGER_FORCE) process.exit(1);
    try { process.kill(pid, 'SIGTERM'); } catch {}
    await sleep(1500);
    return { freshSession: false };
  }
  const readline = require('readline');
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ans = await new Promise(resolve => {
    rl.question(
      `\n  Another kube-logger-agent is already running (PID ${pid}).\n` +
      `    [k] kill it and take over (keep my session URL)\n` +
      `    [n] new session (this run only — won't touch your saved session)\n` +
      `    [q] quit\n  > `,
      a => { rl.close(); resolve((a || '').trim().toLowerCase()); }
    );
  });
  if (ans === 'k') {
    try { process.kill(pid, 'SIGTERM'); console.log(`  Sent SIGTERM to PID ${pid}.`); }
    catch (e) { console.error(`  Failed to kill PID ${pid}: ${e.message}`); process.exit(1); }
    await sleep(1500);
    return { freshSession: false };
  }
  if (ans === 'n') return { freshSession: true };
  process.exit(0);
}

// Hit the GitHub Releases API once at boot and print a banner if a newer
// agent is available. Resolves true if a banner was printed.
function checkForUpdate() {
  return new Promise(resolve => {
    if (process.env.KUBE_LOGGER_NO_UPDATE_CHECK) return resolve(false);
    const https = require('https');
    const done = v => { try { resolve(v); } catch {} };
    const req = https.get({
      host: 'api.github.com',
      path: '/repos/gtalmor/Kube-Logger/releases/latest',
      headers: { 'User-Agent': `kube-logger-agent/${VERSION}`, Accept: 'application/vnd.github+json' },
      timeout: 3000,
    }, res => {
      if (res.statusCode !== 200) { res.resume(); return done(false); }
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        try {
          const tag = JSON.parse(body).tag_name;
          if (!tag) return done(false);
          const latest = tag.replace(/^v/, '');
          if (!isNewerVersion(latest, VERSION)) return done(false);
          const bar = '─'.repeat(64);
          console.error(`\n  ${bar}`);
          console.error(`  A newer kube-logger-agent is available: v${latest} (you're on v${VERSION})`);
          console.error(`  Upgrade:  brew update && brew upgrade kube-logger-agent`);
          console.error(`  Notes:    https://github.com/gtalmor/Kube-Logger/releases/tag/${tag}`);
          console.error(`  ${bar}\n`);
          done(true);
        } catch { done(false); }
      });
    });
    req.on('error', () => done(false));
    req.on('timeout', () => { req.destroy(); done(false); });
  });
}

(async function start() {
  const { freshSession } = await promptDuplicateAgent();
  if (freshSession) {
    SESSION_ID = crypto.randomBytes(16).toString('hex');
    PRODUCER_KEY = crypto.randomBytes(16).toString('hex');
    console.log(`  Using a fresh in-memory session (won't overwrite ~/.kube-logger/session).`);
  } else {
    SESSION_ID = loadOrCreateSecret(SESSION_FILE, 'session');
    PRODUCER_KEY = loadOrCreateSecret(PRODUCER_KEY_FILE, 'producer-key');
  }
  VIEWER_URL = `${RELAY_HTTP_URL}/?session=${SESSION_ID}`;
  writePidFile();

  const clusterCount = Object.keys(CFG.clusters).length;
  console.log(`\n  Kube Logger Agent v${VERSION}`);
  console.log(`  Tool: ${STERN_PATH ? `stern (${STERN_PATH})` : 'stern (NOT FOUND)'} | Region: ${CFG.region} | Clusters configured: ${clusterCount || `0 — edit ${CONFIG_FILE}`}`);
  console.log(`  Viewer: ${VIEWER_URL}\n`);
  if (!STERN_PATH) console.error(`  WARNING: ${STERN_MISSING_MSG}\n`);

  connectProducer();

  const updateAvailable = await checkForUpdate();
  if (updateAvailable && process.stdin.isTTY) {
    const haveBrew = !!findOnPath('brew');
    const prompt = haveBrew
      ? "  Press Enter to continue, or 'u' + Enter to run brew update && upgrade now: "
      : '  Press Enter to continue (or Ctrl-C to upgrade first)… ';
    process.stderr.write(prompt);
    const choice = await new Promise(resolve => {
      let buf = '';
      const onData = chunk => {
        buf += chunk.toString();
        if (buf.includes('\n')) { process.stdin.removeListener('data', onData); process.stdin.pause(); resolve(buf.trim().toLowerCase()); }
      };
      process.stdin.resume();
      process.stdin.on('data', onData);
    });
    if (haveBrew && choice === 'u') {
      process.stderr.write('\n  Running: brew update && brew upgrade kube-logger-agent\n\n');
      const r = require('child_process').spawnSync('brew', ['upgrade', 'kube-logger-agent'], { stdio: 'inherit' });
      process.stderr.write(r.status === 0
        ? '\n  Upgraded. Re-run kube-logger-agent to use the new version.\n'
        : `\n  brew upgrade exited with status ${r.status}. You may need to upgrade manually.\n`);
      process.exit(r.status || 0);
    }
  }

  if (!process.env.KUBE_LOGGER_NO_BROWSER) openInBrowser(VIEWER_URL);

  // Periodic auth re-check so viewer countdowns stay honest.
  const authTimer = setInterval(() => {
    if (!authCache || !authCache.profile) return;
    checkAuth(authCache.profile, true).then(() => broadcast(authStatusMessage()));
  }, 60000);
  authTimer.unref();

  const shutdown = () => { stopCapture(); process.exit(0); };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
})();
