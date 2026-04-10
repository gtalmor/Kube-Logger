#!/usr/bin/env node
// IO Log Agent — lightweight WebSocket relay
// Handles: auth checks, namespace listing, log streaming via stern/kubelog
// All parsing & analysis happens in the Chrome extension (client-side)

const { WebSocketServer } = require('ws');
const { spawn, exec, execSync } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const PORT = parseInt(process.env.PORT || '4040', 10);

// ── Config ──────────────────────────────────────────────────────────
const CLUSTERS = {
  'example-profile-a': 'example-cluster-a',
  'example-profile-b': 'example-cluster-b',
};

function which(cmd) { try { execSync(`which ${cmd}`, { stdio: 'pipe' }); return true; } catch { return false; } }
const LOG_TOOL = which('stern') ? 'stern' : which('kubelog') ? 'kubelog' : 'kubectl';

// ── State ───────────────────────────────────────────────────────────
let capture = null;   // { proc, ns, start, lines[] }
let authCache = null;  // { ts, profile, ok, arn, err }

// ── Helpers ─────────────────────────────────────────────────────────
function broadcast(msg) {
  const raw = JSON.stringify(msg);
  for (const c of wss.clients) if (c.readyState === 1) c.send(raw);
}

function checkAuth(profile) {
  return new Promise(resolve => {
    const now = Date.now();
    if (authCache && authCache.profile === profile && (now - authCache.ts) < 30000)
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
      resolve(authCache);
    });
  });
}

function doLogin(profile, ws) {
  const cluster = CLUSTERS[profile];
  const proc = spawn('aws', ['sso', 'login', '--profile', profile], { stdio: ['pipe', 'pipe', 'pipe'] });
  let out = '';
  proc.stdout.on('data', d => out += d);
  proc.stderr.on('data', d => out += d);
  proc.on('close', code => {
    if (code !== 0) return ws.send(JSON.stringify({ type: 'auth-result', ok: false, msg: `SSO failed: ${out.slice(0, 200)}` }));
    if (!cluster) return ws.send(JSON.stringify({ type: 'auth-result', ok: true, msg: 'SSO OK — no cluster mapping, set kubeconfig manually' }));
    try {
      execSync(`aws eks update-kubeconfig --name ${cluster} --region us-east-1`, {
        env: { ...process.env, AWS_DEFAULT_PROFILE: profile, AWS_REGION: 'us-east-1' }, timeout: 15000
      });
      authCache = { ts: Date.now(), profile, ok: true, cluster };
      broadcast({ type: 'auth-status', ...authCache });
      ws.send(JSON.stringify({ type: 'auth-result', ok: true, msg: `Connected to ${cluster}` }));
    } catch (e) {
      ws.send(JSON.stringify({ type: 'auth-result', ok: true, msg: `SSO OK, kubeconfig failed: ${e.message.slice(0, 100)}` }));
    }
  });
}

function startCapture(ns) {
  if (capture) stopCapture();

  const env = { ...process.env };
  if (authCache && authCache.profile) {
    env.AWS_DEFAULT_PROFILE = authCache.profile;
    env.AWS_REGION = 'us-east-1';
  }

  let proc;
  if (LOG_TOOL === 'stern')
    proc = spawn('stern', ['-n', ns, '.*', '--since', '1s', '--no-follow=false', '--color', 'never'], { env });
  else if (LOG_TOOL === 'kubelog')
    proc = spawn('kubelog', ['-n', ns, '-f', 'default', '-s', '1s'], { env });
  else
    proc = spawn('kubectl', ['logs', '-n', ns, '-l', 'app', '--all-containers=true', '-f', '--since=1s', '--prefix=true'], { env });

  const lines = [];
  let buf = '';

  proc.stdout.on('data', chunk => {
    buf += chunk.toString();
    const parts = buf.split('\n');
    buf = parts.pop();
    for (const line of parts) {
      if (!line.trim()) continue;
      lines.push(line);
      broadcast({ type: 'log', line, i: lines.length - 1 });
    }
  });

  proc.stderr.on('data', d => {
    const msg = d.toString().trim();
    if (msg && !msg.includes('ExperimentalWarning'))
      broadcast({ type: 'stderr', msg });
  });

  proc.on('close', code => {
    broadcast({ type: 'capture-end', code, n: lines.length });
    if (capture && capture.proc === proc) capture = null;
  });

  proc.on('error', e => broadcast({ type: 'error', msg: e.message }));

  capture = { proc, ns, start: Date.now(), lines };
  broadcast({ type: 'capture-start', ns, start: capture.start, tool: LOG_TOOL });
}

function stopCapture() {
  if (!capture) return;
  capture.proc.kill('SIGTERM');
  setTimeout(() => { try { capture.proc.kill('SIGKILL'); } catch {} }, 2000);
  const result = { ns: capture.ns, start: capture.start, end: Date.now(), n: capture.lines.length };
  capture = null;
  return result;
}

// ── WebSocket Server ────────────────────────────────────────────────
const wss = new WebSocketServer({ port: PORT });

wss.on('connection', ws => {
  // Send init state
  ws.send(JSON.stringify({ type: 'init', auth: authCache, capturing: !!capture, tool: LOG_TOOL, profiles: Object.keys(CLUSTERS) }));

  // If capturing, replay buffered lines
  if (capture) {
    ws.send(JSON.stringify({ type: 'capture-state', ns: capture.ns, start: capture.start, n: capture.lines.length }));
    for (let i = 0; i < capture.lines.length; i++) {
      ws.send(JSON.stringify({ type: 'log', line: capture.lines[i], i }));
    }
  }

  ws.on('message', async raw => {
    try {
      const msg = JSON.parse(raw.toString());
      switch (msg.action) {
        case 'check-auth':
          ws.send(JSON.stringify({ type: 'auth-status', ...(await checkAuth(msg.profile)) }));
          break;
        case 'login':
          ws.send(JSON.stringify({ type: 'auth-progress', msg: 'Opening browser for SSO...' }));
          doLogin(msg.profile, ws);
          break;
        case 'namespaces':
          exec('kubectl get namespaces -o jsonpath="{.items[*].metadata.name}"', { timeout: 10000 }, (e, o) => {
            ws.send(JSON.stringify({ type: 'namespaces', list: e ? [] : o.replace(/"/g, '').split(/\s+/).filter(Boolean).sort() }));
          });
          break;
        case 'start':
          startCapture(msg.ns);
          break;
        case 'stop':
          const r = stopCapture();
          broadcast({ type: 'capture-stop', ...r });
          break;
        case 'save': {
          const lines = msg.lines || (capture ? capture.lines : []);
          const fn = `logs-${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
          const fp = path.join(os.homedir(), 'Downloads', fn);
          fs.writeFileSync(fp, lines.join('\n'), 'utf8');
          ws.send(JSON.stringify({ type: 'saved', path: fp, fn }));
          break;
        }
      }
    } catch (e) { ws.send(JSON.stringify({ type: 'error', msg: e.message })); }
  });
});

console.log(`\n  IO Log Agent on ws://localhost:${PORT}`);
console.log(`  Tool: ${LOG_TOOL} | Profiles: ${Object.keys(CLUSTERS).join(', ')}\n`);

process.on('SIGINT', () => { stopCapture(); process.exit(0); });
process.on('SIGTERM', () => { stopCapture(); process.exit(0); });
