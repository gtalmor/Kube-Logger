#!/usr/bin/env node
// Kube Logger Agent — streams kube logs from the user's laptop to the hosted
// relay + web viewer. Auth, namespace listing, and `stern`/`kubectl` live here;
// parsing and rendering happen in the browser.

const { spawn, exec, execSync } = require('child_process');
const crypto = require('crypto');
const path = require('path');
const os = require('os');
const fs = require('fs');

// Version comes from package.json, which the release workflow rewrites to the
// tag (e.g. "0.1.3") before `bun build --compile` bundles it into the binary.
const { version: VERSION } = require('../package.json');

// Handle early CLI flags before any side-effects (no relay connect, no
// config file written). Useful for `brew list --versions` cross-checks and
// for re-opening the viewer tab against a background-running agent.
const _cli = process.argv.slice(2);
if (_cli.some(a => a === '--help' || a === '-h')) {
  console.log(`kube-logger-agent ${VERSION}

  Streams Kubernetes logs from this machine to https://logviewer.gtalmor.com.

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
                       any existing viewer URL or invite link.

ENVIRONMENT
  KUBE_LOGGER_RELAY            Override the relay endpoint (default:
                               https://logviewer.gtalmor.com). Useful for
                               pointing at a local relay for testing.
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
                               disabled profile list. Edit by hand.
  ~/.kube-logger/agent.pid     PID of the live agent on this machine.
`);
  process.exit(0);
}
if (_cli.some(a => a === '--version' || a === '-v')) {
  console.log(`kube-logger-agent ${VERSION} (${process.platform}-${process.arch})`);
  process.exit(0);
}
if (_cli.some(a => a === '--open' || a === '-o')) {
  // Read the persisted session without creating one — if it's missing, the
  // agent hasn't been started yet, so tell the user and bail.
  const sessionFile = path.join(os.homedir(), '.kube-logger', 'session');
  let sid = '';
  try { sid = fs.readFileSync(sessionFile, 'utf8').trim(); } catch {}
  if (!sid || sid.length < 16) {
    console.error('No session yet — start `kube-logger-agent` at least once first.');
    process.exit(1);
  }
  const relay = (process.env.KUBE_LOGGER_RELAY || 'https://logviewer.gtalmor.com').replace(/\/+$/, '');
  const url = `${relay}/?session=${sid}`;
  console.log(url);
  const opener = { darwin: 'open', linux: 'xdg-open', win32: 'start' }[process.platform];
  if (opener) {
    try { spawn(opener, [url], { stdio: 'ignore', detached: true, shell: process.platform === 'win32' }).unref(); }
    catch {}
  }
  process.exit(0);
}

// Override the relay target with KUBE_LOGGER_RELAY=http://localhost:4040 (or
// wss://...) when you want to point a local agent at a local relay for testing.
const RELAY_HTTP_URL = (process.env.KUBE_LOGGER_RELAY || 'https://logviewer.gtalmor.com').replace(/\/+$/, '');
const RELAY_WS_URL = RELAY_HTTP_URL.replace(/^http:/, 'ws:').replace(/^https:/, 'wss:');
const CONFIG_DIR = path.join(os.homedir(), '.kube-logger');
const SESSION_FILE = path.join(CONFIG_DIR, 'session');
const PRODUCER_KEY_FILE = path.join(CONFIG_DIR, 'producer-key');
const CONFIG_FILE = path.join(CONFIG_DIR, 'config.json');
const PID_FILE = path.join(CONFIG_DIR, 'agent.pid');

// Returns the PID of an already-running agent on this machine, or null.
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
  const cleanup = () => {
    try {
      const pid = fs.readFileSync(PID_FILE, 'utf8').trim();
      if (pid === String(process.pid)) fs.unlinkSync(PID_FILE);
    } catch {}
  };
  process.on('exit', cleanup);
  process.on('SIGINT',  () => process.exit(0));
  process.on('SIGTERM', () => process.exit(0));
}

// Read a 16-byte hex secret from `file`, or generate and persist a new one.
// Used for both the session id (public — in the viewer URL) and the producer
// key (private — kept local so only this agent can own the session at the relay).
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
const loadOrCreateSession     = () => loadOrCreateSecret(SESSION_FILE, 'session');
const loadOrCreateProducerKey = () => loadOrCreateSecret(PRODUCER_KEY_FILE, 'producer-key');

// ── User config (profile→cluster mapping, region, disabled profiles) ───
// Edited by hand at ~/.kube-logger/config.json. Shape:
//   { "region": "us-east-1",
//     "clusters": { "<aws-profile>": "<eks-cluster-name>", ... },
//     "disabledProfiles": ["profile-to-hide-from-drawer"] }
// Changes take effect on agent restart.
function loadAgentConfig() {
  try {
    const j = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf8'));
    return {
      region: j.region || 'us-east-1',
      clusters: j.clusters || {},
      disabledProfiles: new Set(j.disabledProfiles || []),
    };
  } catch {
    const template = { region: 'us-east-1', clusters: {}, disabledProfiles: [] };
    try {
      fs.mkdirSync(CONFIG_DIR, { recursive: true, mode: 0o700 });
      fs.writeFileSync(CONFIG_FILE, JSON.stringify(template, null, 2) + '\n', { mode: 0o600 });
    } catch (e) {
      console.error(`[config] could not write template to ${CONFIG_FILE}: ${e.message}`);
    }
    return { region: 'us-east-1', clusters: {}, disabledProfiles: new Set() };
  }
}
const CFG = loadAgentConfig();

function which(cmd) { try { execSync(`which ${cmd}`, { stdio: 'pipe' }); return true; } catch { return false; } }
const LOG_TOOL = which('stern') ? 'stern' : which('kubelog') ? 'kubelog' : 'kubectl';

// Discover profile names from ~/.aws/config. Handles `[default]`, `[profile X]`.
// Profiles listed in CFG.disabledProfiles are filtered out so the drawer only
// shows the ones the user cares about.
function discoverProfiles() {
  const cfgPath = path.join(os.homedir(), '.aws/config');
  try {
    const text = fs.readFileSync(cfgPath, 'utf8');
    const names = [];
    for (const line of text.split('\n')) {
      const m = line.trim().match(/^\[(.+)\]$/);
      if (!m) continue;
      const section = m[1];
      if (section === 'default') names.push('default');
      else if (section.startsWith('profile ')) names.push(section.slice(8).trim());
    }
    return [...new Set(names)].filter(n => !CFG.disabledProfiles.has(n)).sort();
  } catch { return Object.keys(CFG.clusters).filter(n => !CFG.disabledProfiles.has(n)); }
}

// ── State ───────────────────────────────────────────────────────────
// capture: { procs: Map<ns, proc>, nsList:[...], start, lines: [{line, ns}] }
let capture = null;
let authCache = null;  // { ts, profile, ok, arn, err }

// ── Helpers ─────────────────────────────────────────────────────────
function broadcast(msg) {
  if (saasProducer && saasProducer.readyState === 1) {
    try { saasProducer.send(JSON.stringify(msg)); } catch {}
  }
}

// ── SaaS producer mode ─────────────────────────────────────────────
// When the extension calls `saas-connect` with a relay URL + session id, we
// open an outbound WebSocket to the relay and forward every broadcast to it.
// The relay then fans it out to the web viewer(s) on the same session.
let saasProducer = null;
let saasTarget = null;   // { url, session }
let saasReconnectTimer = null;

function setSaasTarget(url, session) {
  if (!url || !session) { clearSaasTarget(); return; }
  saasTarget = { url, session };
  connectSaas();
}

function clearSaasTarget() {
  saasTarget = null;
  if (saasReconnectTimer) { clearTimeout(saasReconnectTimer); saasReconnectTimer = null; }
  if (saasProducer) { try { saasProducer.close(1000, 'disconnected by agent'); } catch {} }
  saasProducer = null;
}

function connectSaas() {
  if (!saasTarget) return;
  if (saasProducer && saasProducer.readyState !== 3 /* CLOSED */) return;
  const { WebSocket } = require('ws');
  const { url, session } = saasTarget;
  const wsUrl = `${url.replace(/\/+$/, '')}/producer?session=${encodeURIComponent(session)}&key=${encodeURIComponent(PRODUCER_KEY)}`;
  // Log the session but not the key — the key is a secret that binds this
  // agent to the relay-side session so stray producers can't hijack it.
  console.log(`[saas] connecting to ${url.replace(/\/+$/, '')}/producer?session=${session}`);
  const ws = new WebSocket(wsUrl);
  saasProducer = ws;

  ws.on('open', () => {
    console.log(`[saas] connected (session ${session.slice(0, 8)}…)`);
    // Send a snapshot so late-joining viewers know we're live and capturing state.
    ws.send(JSON.stringify(buildInitMessage()));
    if (capture) {
      ws.send(JSON.stringify({
        type: 'capture-state',
        ns: capture.nsList, start: capture.start, n: capture.lines.length,
      }));
      for (let i = 0; i < capture.lines.length; i++) {
        const { line, ns } = capture.lines[i];
        ws.send(JSON.stringify({ type: 'log', line, ns, i }));
      }
    }
  });

  // Consumer → producer messages, forwarded by the relay, arrive here. Dispatch
  // them through the same action handler the local extension uses, so the web
  // viewer can drive auth / namespaces / capture on its own.
  ws.on('message', async raw => {
    const send = m => { try { if (ws.readyState === 1) ws.send(JSON.stringify(m)); } catch {} };
    try {
      const msg = JSON.parse(raw.toString());
      await handleAction(msg, send);
    } catch (e) { send({ type: 'error', msg: e.message }); }
  });

  ws.on('close', (code, reason) => {
    console.log(`[saas] disconnected (code ${code}, reason: ${reason || 'n/a'})`);
    if (saasProducer === ws) saasProducer = null;
    // Code 4000 = the relay kicked us because a newer agent (same session+key)
    // claimed the session. Reconnecting would just kick that one back — endless
    // ping-pong. Bail loudly so the user can stop the duplicate.
    if (code === 4000) {
      console.error(`\n  Another agent has taken over this session.`);
      console.error(`  Likely you have a duplicate kube-logger-agent running. Find it:`);
      console.error(`    pgrep -af kube-logger-agent\n`);
      process.exit(1);
    }
    if (saasTarget && !saasReconnectTimer) {
      saasReconnectTimer = setTimeout(() => { saasReconnectTimer = null; connectSaas(); }, 3000);
    }
  });

  ws.on('error', e => console.error(`[saas] error: ${e.message}`));
}

function getSsoExpiration() {
  const cacheDir = path.join(os.homedir(), '.aws/sso/cache');
  try {
    const files = fs.readdirSync(cacheDir).filter(f => f.endsWith('.json'));
    let latest = null;
    for (const f of files) {
      try {
        const j = JSON.parse(fs.readFileSync(path.join(cacheDir, f), 'utf8'));
        // only access-token files have both accessToken + expiresAt
        if (j.accessToken && j.expiresAt) {
          const ts = new Date(j.expiresAt).getTime();
          if (!Number.isNaN(ts) && (!latest || ts > latest)) latest = ts;
        }
      } catch {}
    }
    return latest;
  } catch { return null; }
}

function checkAuth(profile, force) {
  return new Promise(resolve => {
    const now = Date.now();
    if (!force && authCache && authCache.profile === profile && (now - authCache.ts) < 30000)
      return resolve(authCache);

    const cmd = profile
      ? `aws sts get-caller-identity --profile ${profile} 2>&1`
      : `kubectl auth can-i get pods --all-namespaces 2>&1`;

    exec(cmd, { timeout: 10000 }, (err, out) => {
      if (err) {
        authCache = { ts: now, profile, ok: false, err: (out || '').trim().slice(0, 200) };
      } else {
        try {
          const id = JSON.parse(out);
          authCache = { ts: now, profile, ok: true, arn: id.Arn, account: id.Account };
        } catch {
          authCache = { ts: now, profile, ok: out.trim().toLowerCase() === 'yes' };
        }
      }
      authCache.expiresAt = getSsoExpiration();
      resolve(authCache);
    });
  });
}

function doLogin(profile, send) {
  const cluster = CFG.clusters[profile];
  const region = CFG.region;
  const proc = spawn('aws', ['sso', 'login', '--profile', profile], { stdio: ['pipe', 'pipe', 'pipe'] });
  let out = '';
  proc.stdout.on('data', d => out += d);
  proc.stderr.on('data', d => out += d);
  proc.on('close', async code => {
    if (code !== 0) { broadcast({ type: 'auth-status', ok: false, profile, err: `SSO failed: ${out.slice(0, 200)}` }); return; }

    // Always verify via `sts get-caller-identity` so authCache reflects the
    // real authed state regardless of whether we also try to touch kubeconfig.
    await checkAuth(profile, true);
    broadcast({ type: 'auth-status', ...authCache });

    if (!cluster) {
      send({ type: 'auth-result', ok: true, msg: `No cluster mapping for "${profile}" — add it to ${CONFIG_FILE} or run \`aws eks update-kubeconfig\` manually.` });
      return;
    }
    try {
      execSync(`aws eks update-kubeconfig --name ${cluster} --region ${region}`, {
        env: { ...process.env, AWS_DEFAULT_PROFILE: profile, AWS_REGION: region }, timeout: 15000
      });
      authCache = { ...authCache, cluster };
      broadcast({ type: 'auth-status', ...authCache });
      send({ type: 'auth-result', ok: true, msg: `Connected to ${cluster}` });
    } catch (e) {
      send({ type: 'auth-result', ok: true, msg: `kubeconfig update failed: ${e.message.slice(0, 120)}` });
    }
  });
}

function buildInitMessage() {
  return {
    type: 'init',
    auth: authCache,
    capturing: !!capture,
    tool: LOG_TOOL,
    profiles: discoverProfiles(),
    ns: capture ? capture.nsList : null,
    saas: saasTarget ? { url: saasTarget.url, session: saasTarget.session, connected: !!(saasProducer && saasProducer.readyState === 1) } : null,
  };
}

// Dispatches a client action (from either the local extension or a web viewer
// via the SaaS relay). `send` replies only to the requester; broadcast() is
// used when all connected clients should see the state change.
async function handleAction(msg, send) {
  switch (msg.action) {
    case 'check-auth':
      send({ type: 'auth-status', ...(await checkAuth(msg.profile)) });
      break;
    case 'login':
      send({ type: 'auth-progress', msg: 'Opening browser for SSO...' });
      doLogin(msg.profile, send);
      break;
    case 'namespaces':
      exec('kubectl get namespaces -o jsonpath="{.items[*].metadata.name}"', { timeout: 10000 }, (e, o) => {
        send({ type: 'namespaces', list: e ? [] : o.replace(/"/g, '').split(/\s+/).filter(Boolean).sort() });
      });
      break;
    case 'saas-connect':
      setSaasTarget(msg.url, msg.session);
      send({ type: 'saas-status', connected: !!saasTarget, url: saasTarget && saasTarget.url, session: saasTarget && saasTarget.session });
      break;
    case 'saas-disconnect':
      clearSaasTarget();
      send({ type: 'saas-status', connected: false });
      break;
    case 'get-init':
      send(buildInitMessage());
      break;
    case 'start':
      startCapture(msg.ns);
      break;
    case 'add-ns':
      addNamespaces(msg.ns);
      break;
    case 'remove-ns':
      removeNamespaces(msg.ns);
      break;
    case 'stop': {
      const r = stopCapture();
      broadcast({ type: 'capture-stop', ...r });
      break;
    }
    case 'save': {
      const items = msg.lines || (capture ? capture.lines : []);
      const fn = `logs-${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
      const fp = path.join(os.homedir(), 'Downloads', fn);
      const text = items.map(l => typeof l === 'string' ? l : `[${l.ns || '?'}] ${l.line}`).join('\n');
      fs.writeFileSync(fp, text, 'utf8');
      send({ type: 'saved', path: fp, fn });
      break;
    }
    case 'clear': {
      if (capture) stopCapture();
      broadcast({ type: 'cleared' });
      break;
    }
  }
}

function spawnStream(ns, env) {
  if (LOG_TOOL === 'stern')
    return spawn('stern', ['-n', ns, '.*', '--since', '1s', '--no-follow=false', '--color', 'never'], { env });
  if (LOG_TOOL === 'kubelog')
    return spawn('kubelog', ['-n', ns, '-f', 'default', '-s', '1s'], { env });
  return spawn('kubectl', ['logs', '-n', ns, '-l', 'app', '--all-containers=true', '-f', '--since=1s', '--prefix=true'], { env });
}

function attachStream(ns) {
  if (!capture || capture.procs.has(ns)) return;
  const env = { ...process.env };
  if (authCache && authCache.profile) {
    env.AWS_DEFAULT_PROFILE = authCache.profile;
    env.AWS_REGION = CFG.region;
  }

  const proc = spawnStream(ns, env);
  let buf = '';
  let firstData = true;
  let stderrBuf = '';
  console.log(`[${ns}] spawned ${LOG_TOOL} (pid ${proc.pid})`);

  const isCurrent = () => capture && capture.procs.get(ns) === proc;

  proc.stdout.on('data', chunk => {
    if (!isCurrent()) return;
    if (firstData) { firstData = false; console.log(`[${ns}] first line received`); }
    buf += chunk.toString();
    const parts = buf.split('\n');
    buf = parts.pop();
    for (const line of parts) {
      if (!line.trim()) continue;
      const i = capture.lines.length;
      capture.lines.push({ line, ns });
      broadcast({ type: 'log', line, ns, i });
    }
  });

  proc.stderr.on('data', d => {
    const msg = d.toString().trim();
    if (!msg || msg.includes('ExperimentalWarning')) return;
    stderrBuf += msg + '\n';
    if (stderrBuf.length > 4000) stderrBuf = stderrBuf.slice(-4000);
    console.error(`[${ns}] stderr: ${msg.slice(0, 500)}`);
    // Early SSO/auth-expiration detection: stern/kubectl surfaces these on
    // stderr well before our 60s periodic checkAuth would notice. Invalidate
    // authCache immediately so the viewer gets an instant signal.
    if (/Token has expired|ExpiredToken|InvalidClientTokenId|UnauthorizedOperation|refresh failed|ExpiredTokenException|unable to get a Token|SSOTokenLoadError/i.test(msg)) {
      const prev = authCache || {};
      authCache = { ts: Date.now(), profile: prev.profile, ok: false, err: 'SSO token expired — re-login' };
      broadcast({ type: 'auth-status', ...authCache });
    }
    if (isCurrent()) broadcast({ type: 'stderr', ns, msg });
  });

  proc.on('close', code => {
    const lineCountForNs = capture ? capture.lines.filter(l => l.ns === ns).length : 0;
    console.log(`[${ns}] ${LOG_TOOL} exited (code ${code}, captured ${lineCountForNs} lines for this ns)`);
    if (code !== 0 && stderrBuf) {
      console.error(`[${ns}] ─── tail of stderr ───\n${stderrBuf.slice(-1500)}─── end stderr ───`);
    }
    if (!capture || capture.procs.get(ns) !== proc) return;
    capture.procs.delete(ns);
    capture.nsList = capture.nsList.filter(n => n !== ns);
    broadcast({ type: 'stream-end', ns, code, stderr: stderrBuf.slice(-500) });
    if (capture.procs.size === 0) {
      const n = capture.lines.length;
      console.log(`[capture] all streams ended — ending capture. Total: ${n} lines. Remaining procs: 0`);
      capture = null;
      broadcast({ type: 'capture-end', code, n });
    } else {
      console.log(`[capture] ${ns} done, still running: [${[...capture.procs.keys()].join(', ')}]`);
    }
  });

  proc.on('error', e => {
    console.error(`[${ns}] spawn error: ${e.message}`);
    broadcast({ type: 'error', ns, msg: e.message });
  });

  capture.procs.set(ns, proc);
  if (!capture.nsList.includes(ns)) capture.nsList.push(ns);
}

function startCapture(nsInput) {
  if (capture) stopCapture();

  const nsList = (Array.isArray(nsInput) ? nsInput : [nsInput]).filter(Boolean);
  if (!nsList.length) return;

  capture = { procs: new Map(), nsList: [], start: Date.now(), lines: [] };

  for (const ns of nsList) attachStream(ns);

  broadcast({ type: 'capture-start', ns: [...capture.nsList], start: capture.start, tool: LOG_TOOL });
}

function addNamespaces(nsInput) {
  if (!capture) return;
  const nsList = (Array.isArray(nsInput) ? nsInput : [nsInput]).filter(Boolean);
  const added = [];
  for (const ns of nsList) {
    if (capture.procs.has(ns)) continue;
    attachStream(ns);
    if (capture && capture.procs.has(ns)) added.push(ns);
  }
  if (added.length) broadcast({ type: 'ns-added', ns: added });
}

function removeNamespaces(nsInput) {
  if (!capture) return;
  const nsList = (Array.isArray(nsInput) ? nsInput : [nsInput]).filter(Boolean);
  for (const ns of nsList) {
    const proc = capture.procs.get(ns);
    if (!proc) continue;
    try { proc.kill('SIGTERM'); } catch {}
    const pinned = proc;
    setTimeout(() => { try { pinned.kill('SIGKILL'); } catch {} }, 2000);
  }
}

function stopCapture() {
  if (!capture) return null;
  const { procs, nsList, start, lines } = capture;
  for (const proc of procs.values()) {
    try { proc.kill('SIGTERM'); } catch {}
    setTimeout(() => { try { proc.kill('SIGKILL'); } catch {} }, 2000);
  }
  const result = { ns: nsList, start, end: Date.now(), n: lines.length };
  capture = null;
  return result;
}

// `--new-session` / `--rotate` wipes the persisted session id + producer key
// so this run (and every future run) gets fresh ones. The previous viewer URL
// becomes useless — anyone holding it lands on "Waiting for agent…".
if (_cli.some(a => a === '--new-session' || a === '--rotate')) {
  try { fs.unlinkSync(SESSION_FILE); } catch {}
  try { fs.unlinkSync(PRODUCER_KEY_FILE); } catch {}
  console.log('  Session rotated — old viewer URL is now invalid.');
}

// Booted lazily so we can prompt about a duplicate agent before claiming
// the session file. Module-level so the rest of the file can close over them.
let SESSION_ID = '';
let PRODUCER_KEY = '';
let VIEWER_URL = '';

// If another kube-logger-agent is already running on this machine, ask the
// user what to do — kill it, take over with a fresh session, or quit. Avoids
// the relay-side ping-pong that older builds could fall into.
async function promptDuplicateAgent() {
  const pid = existingAgentPid();
  if (!pid) return { freshSession: false };
  if (!process.stdin.isTTY) {
    console.error(`\n  Another kube-logger-agent is already running (PID ${pid}).`);
    console.error(`  Stop it first or pass KUBE_LOGGER_FORCE=1 to take over.\n`);
    if (!process.env.KUBE_LOGGER_FORCE) process.exit(1);
    try { process.kill(pid, 'SIGTERM'); } catch {}
    await new Promise(r => setTimeout(r, 1500));
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
    await new Promise(r => setTimeout(r, 1500));
    return { freshSession: false };
  }
  if (ans === 'n') return { freshSession: true };
  process.exit(0);
}

(async function start() {
  const { freshSession } = await promptDuplicateAgent();
  if (freshSession) {
    SESSION_ID = crypto.randomBytes(16).toString('hex');
    PRODUCER_KEY = crypto.randomBytes(16).toString('hex');
    console.log(`  Using a fresh in-memory session (won't overwrite ~/.kube-logger/session).`);
  } else {
    SESSION_ID = loadOrCreateSession();
    PRODUCER_KEY = loadOrCreateProducerKey();
  }
  VIEWER_URL = `${RELAY_HTTP_URL}/?session=${SESSION_ID}`;
  writePidFile();

  const clusterCount = Object.keys(CFG.clusters).length;
  console.log(`\n  Kube Logger Agent v${VERSION}`);
  console.log(`  Tool: ${LOG_TOOL} | Region: ${CFG.region} | Clusters configured: ${clusterCount || `0 — edit ${CONFIG_FILE}`}`);
  console.log(`  Viewer: ${VIEWER_URL}\n`);

  setSaasTarget(RELAY_WS_URL, SESSION_ID);

// Hit the GitHub Releases API once at boot and print a banner if a newer
// kube-logger-agent is available. 3s timeout, silent on any error. Returns
// a promise resolving to true if an upgrade banner was printed (so the
// caller can pause before opening a browser tab on top of it). Set
// KUBE_LOGGER_NO_UPDATE_CHECK=1 to skip entirely (daemonized runs).
function checkForUpdate() {
  return new Promise(resolve => {
    if (process.env.KUBE_LOGGER_NO_UPDATE_CHECK) return resolve(false);
    const https = require('https');
    const done = v => { try { resolve(v); } catch {} };
    const req = https.get({
      host: 'api.github.com',
      path: '/repos/gtalmor/Kube-Logger/releases/latest',
      headers: {
        'User-Agent': `kube-logger-agent/${VERSION}`,
        Accept: 'application/vnd.github+json',
      },
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

// Tiny semver-ish comparator — parts beyond what both have default to 0.
function isNewerVersion(a, b) {
  const pa = a.split('.').map(n => parseInt(n, 10) || 0);
  const pb = b.split('.').map(n => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || 0, y = pb[i] || 0;
    if (x > y) return true;
    if (x < y) return false;
  }
  return false;
}

// Open the viewer in the user's default browser, AFTER the update check has
// finished. If a newer version is available we pause for a keystroke so the
// upgrade banner doesn't get buried under the new tab opening — but only in
// an interactive TTY (daemons just continue).
const updateAvailable = await checkForUpdate();

if (updateAvailable && process.stdin.isTTY) {
  // Offer an in-place 'brew update && brew upgrade' if brew is on PATH.
  const haveBrew = (() => {
    try { execSync('command -v brew', { stdio: 'ignore' }); return true; }
    catch { return false; }
  })();
  const prompt = haveBrew
    ? "  Press Enter to continue, or 'u' + Enter to run brew update && upgrade now: "
    : '  Press Enter to continue (or Ctrl-C to upgrade first)… ';
  process.stderr.write(prompt);
  const choice = await new Promise(resolve => {
    let buf = '';
    const onData = chunk => {
      buf += chunk.toString();
      if (buf.includes('\n')) {
        process.stdin.removeListener('data', onData);
        process.stdin.pause();
        resolve(buf.trim().toLowerCase());
      }
    };
    process.stdin.resume();
    process.stdin.on('data', onData);
  });
  if (haveBrew && choice === 'u') {
    process.stderr.write('\n  Running: brew update && brew upgrade kube-logger-agent\n\n');
    const r = require('child_process').spawnSync('sh', ['-c', 'brew update && brew upgrade kube-logger-agent'], { stdio: 'inherit' });
    if (r.status === 0) {
      process.stderr.write('\n  Upgraded. Re-run kube-logger-agent to use the new version.\n');
    } else {
      process.stderr.write(`\n  brew upgrade exited with status ${r.status}. You may need to upgrade manually.\n`);
    }
    process.exit(r.status || 0);
  }
}

// Open the viewer in the user's default browser. Most OS openers focus an
// existing tab if one is already on the same URL, so restarts don't spam
// duplicate tabs. Set KUBE_LOGGER_NO_BROWSER=1 to skip.
if (!process.env.KUBE_LOGGER_NO_BROWSER) {
  const opener = { darwin: 'open', linux: 'xdg-open', win32: 'start' }[process.platform];
  if (opener) {
    try {
      spawn(opener, [VIEWER_URL], { stdio: 'ignore', detached: true, shell: process.platform === 'win32' }).unref();
    } catch {}
  }
}

// Periodic AWS auth re-check. Every 60s force a fresh check and broadcast
// updated auth-status (including SSO expiresAt) to all clients, so popup +
// viewer countdowns stay honest without each client polling.
setInterval(() => {
  if (!authCache || !authCache.profile) return;
  checkAuth(authCache.profile, true).then(r => broadcast({ type: 'auth-status', ...r }));
}, 60000);

  process.on('SIGINT', () => { stopCapture(); process.exit(0); });
  process.on('SIGTERM', () => { stopCapture(); process.exit(0); });
})();
