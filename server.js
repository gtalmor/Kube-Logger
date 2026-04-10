#!/usr/bin/env node
const http = require('http');
const express = require('express');
const { WebSocketServer } = require('ws');
const { spawn, execSync, exec } = require('child_process');
const path = require('path');
const os = require('os');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const PORT = process.env.PORT || 4040;

// ---- State ----
let currentCapture = null;  // { process, namespace, profile, startTime, lines[] }
let authState = { authenticated: false, profile: null, cluster: null, lastCheck: 0 };

// ---- Profile/Cluster mapping (from user's zshrc) ----
const CPL_CLUSTERS = {
  'example-profile-a': 'example-cluster-a',
  'example-profile-b': 'example-cluster-b',
};

// ---- Utility ----
function which(cmd) {
  try {
    execSync(`which ${cmd}`, { stdio: 'pipe' });
    return true;
  } catch { return false; }
}

function detectLogTool() {
  if (which('stern')) return 'stern';
  if (which('kubelog')) return 'kubelog';
  return 'kubectl'; // fallback
}

const LOG_TOOL = detectLogTool();

// ---- Auth ----
async function checkAuth(profile) {
  return new Promise((resolve) => {
    const now = Date.now();
    // Cache for 30 seconds
    if (authState.lastCheck && (now - authState.lastCheck) < 30000 && authState.profile === profile) {
      return resolve(authState);
    }

    const cmd = profile
      ? `aws sts get-caller-identity --profile ${profile} 2>&1`
      : `kubectl auth can-i get pods --all-namespaces 2>&1`;

    exec(cmd, { timeout: 10000 }, (err, stdout, stderr) => {
      if (err) {
        authState = { authenticated: false, profile, cluster: null, lastCheck: now, error: (stdout || stderr || '').trim() };
      } else {
        try {
          const identity = JSON.parse(stdout);
          authState = {
            authenticated: true,
            profile,
            cluster: CPL_CLUSTERS[profile] || null,
            lastCheck: now,
            account: identity.Account,
            arn: identity.Arn,
          };
        } catch {
          // kubectl auth can-i returns "yes"/"no"
          const ok = stdout.trim().toLowerCase() === 'yes';
          authState = { authenticated: ok, profile, cluster: null, lastCheck: now };
        }
      }
      resolve(authState);
    });
  });
}

async function triggerLogin(profile) {
  return new Promise((resolve, reject) => {
    if (!profile) return reject(new Error('Profile required'));

    const cluster = CPL_CLUSTERS[profile];

    // Step 1: aws sso login (opens browser)
    const loginProc = spawn('aws', ['sso', 'login', '--profile', profile], {
      stdio: ['pipe', 'pipe', 'pipe'],
    });

    let output = '';
    loginProc.stdout.on('data', (d) => { output += d.toString(); });
    loginProc.stderr.on('data', (d) => { output += d.toString(); });

    loginProc.on('close', (code) => {
      if (code !== 0) {
        return reject(new Error(`SSO login failed (code ${code}): ${output}`));
      }

      // Step 2: update kubeconfig
      const clusterName = cluster;
      if (!clusterName) {
        return resolve({ success: true, message: 'SSO login OK, but no cluster mapping found. Set kubeconfig manually.' });
      }

      try {
        execSync(`aws eks update-kubeconfig --name ${clusterName} --region us-east-1`, {
          env: { ...process.env, AWS_DEFAULT_PROFILE: profile, AWS_REGION: 'us-east-1' },
          timeout: 15000,
        });
        authState = { authenticated: true, profile, cluster: clusterName, lastCheck: Date.now() };
        resolve({ success: true, message: `Connected to cluster: ${clusterName}` });
      } catch (e) {
        resolve({ success: true, message: `SSO login OK, but kubeconfig update failed: ${e.message}` });
      }
    });
  });
}

// ---- Namespace discovery ----
async function getNamespaces() {
  return new Promise((resolve) => {
    exec('kubectl get namespaces -o jsonpath="{.items[*].metadata.name}"', { timeout: 10000 }, (err, stdout) => {
      if (err) return resolve([]);
      const ns = stdout.replace(/"/g, '').split(/\s+/).filter(Boolean).sort();
      resolve(ns);
    });
  });
}

async function getPodsInNamespace(namespace) {
  return new Promise((resolve) => {
    exec(`kubectl get pods -n ${namespace} -o jsonpath="{.items[*].metadata.name}"`, { timeout: 10000 }, (err, stdout) => {
      if (err) return resolve([]);
      resolve(stdout.replace(/"/g, '').split(/\s+/).filter(Boolean));
    });
  });
}

// ---- Log Streaming ----
function startCapture(namespace, ws) {
  if (currentCapture) {
    stopCapture();
  }

  const startTime = new Date();
  const lines = [];

  let proc;
  const env = { ...process.env };
  if (authState.profile) {
    env.AWS_DEFAULT_PROFILE = authState.profile;
    env.AWS_REGION = 'us-east-1';
  }

  if (LOG_TOOL === 'stern') {
    // stern gives us the best multi-pod output
    proc = spawn('stern', ['-n', namespace, '.*', '--since', '1s', '--no-follow=false', '--color', 'never'], {
      env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } else if (LOG_TOOL === 'kubelog') {
    proc = spawn('kubelog', ['-n', namespace, '-f', 'default', '-s', '1s'], {
      env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } else {
    // Fallback: kubectl logs with label selector
    proc = spawn('kubectl', ['logs', '-n', namespace, '-l', 'app', '--all-containers=true', '-f', '--since=1s', '--prefix=true'], {
      env,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  }

  let buffer = '';

  proc.stdout.on('data', (data) => {
    buffer += data.toString();
    const parts = buffer.split('\n');
    buffer = parts.pop(); // keep incomplete line in buffer

    for (const line of parts) {
      if (line.trim()) {
        lines.push(line);
        // Send to all connected WebSocket clients
        broadcastWs({ type: 'log', line, index: lines.length - 1 });
      }
    }
  });

  proc.stderr.on('data', (data) => {
    const msg = data.toString().trim();
    if (msg) {
      broadcastWs({ type: 'stderr', message: msg });
    }
  });

  proc.on('close', (code) => {
    broadcastWs({ type: 'capture-ended', code, lineCount: lines.length });
    if (currentCapture && currentCapture.process === proc) {
      currentCapture = null;
    }
  });

  proc.on('error', (err) => {
    broadcastWs({ type: 'error', message: `Failed to start log capture: ${err.message}` });
  });

  currentCapture = { process: proc, namespace, startTime, lines };
  broadcastWs({ type: 'capture-started', namespace, startTime: startTime.toISOString(), tool: LOG_TOOL });
}

function stopCapture() {
  if (!currentCapture) return null;

  const { process: proc, namespace, startTime, lines } = currentCapture;
  proc.kill('SIGTERM');
  setTimeout(() => { try { proc.kill('SIGKILL'); } catch {} }, 2000);

  const result = {
    namespace,
    startTime: startTime.toISOString(),
    endTime: new Date().toISOString(),
    lineCount: lines.length,
    lines: lines,
  };

  currentCapture = null;
  return result;
}

// ---- WebSocket ----
const clients = new Set();

function broadcastWs(msg) {
  const payload = JSON.stringify(msg);
  for (const ws of clients) {
    if (ws.readyState === 1) { // OPEN
      ws.send(payload);
    }
  }
}

wss.on('connection', (ws) => {
  clients.add(ws);

  // Send current state
  ws.send(JSON.stringify({ type: 'init', auth: authState, capturing: !!currentCapture, tool: LOG_TOOL, profiles: Object.keys(CPL_CLUSTERS) }));

  // If capturing, send all existing lines
  if (currentCapture) {
    ws.send(JSON.stringify({
      type: 'capture-state',
      namespace: currentCapture.namespace,
      startTime: currentCapture.startTime.toISOString(),
      lineCount: currentCapture.lines.length,
    }));
    // Send lines in batches
    const batch = currentCapture.lines.map((line, i) => ({ type: 'log', line, index: i }));
    for (const msg of batch) {
      ws.send(JSON.stringify(msg));
    }
  }

  ws.on('message', async (data) => {
    try {
      const msg = JSON.parse(data.toString());

      switch (msg.action) {
        case 'check-auth': {
          const auth = await checkAuth(msg.profile);
          ws.send(JSON.stringify({ type: 'auth-status', ...auth }));
          break;
        }

        case 'login': {
          ws.send(JSON.stringify({ type: 'auth-progress', message: 'Opening browser for SSO login...' }));
          try {
            const result = await triggerLogin(msg.profile);
            ws.send(JSON.stringify({ type: 'auth-result', ...result }));
            // Re-check and broadcast
            const auth = await checkAuth(msg.profile);
            broadcastWs({ type: 'auth-status', ...auth });
          } catch (e) {
            ws.send(JSON.stringify({ type: 'auth-result', success: false, message: e.message }));
          }
          break;
        }

        case 'namespaces':
        case 'get-namespaces': {
          const namespaces = await getNamespaces();
          ws.send(JSON.stringify({ type: 'namespaces', list: namespaces, namespaces }));
          break;
        }

        case 'get-pods': {
          const pods = await getPodsInNamespace(msg.namespace);
          ws.send(JSON.stringify({ type: 'pods', pods, namespace: msg.namespace }));
          break;
        }

        case 'start':
        case 'start-capture': {
          startCapture(msg.namespace || msg.ns, ws);
          break;
        }

        case 'clear': {
          if (currentCapture) stopCapture();
          broadcastWs({ type: 'cleared' });
          break;
        }

        case 'stop':
        case 'stop-capture': {
          const result = stopCapture();
          broadcastWs({ type: 'capture-stopped', ...result });
          break;
        }

        case 'save-capture': {
          // Save current captured lines to a file
          if (currentCapture || msg.lines) {
            const lines = msg.lines || (currentCapture ? currentCapture.lines : []);
            const filename = `logs-${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
            const filepath = path.join(os.homedir(), 'Downloads', filename);
            fs.writeFileSync(filepath, lines.join('\n'), 'utf8');
            ws.send(JSON.stringify({ type: 'saved', path: filepath, filename }));
          }
          break;
        }
      }
    } catch (e) {
      ws.send(JSON.stringify({ type: 'error', message: e.message }));
    }
  });

  ws.on('close', () => {
    clients.delete(ws);
  });
});

// ---- HTTP Routes ----
// Serve the extension viewer as the main web UI (single source of truth)
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'extension', 'viewer.html')));
app.use('/viewer.js', express.static(path.join(__dirname, 'extension', 'viewer.js')));
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/status', async (req, res) => {
  res.json({
    auth: authState,
    capturing: !!currentCapture,
    capture: currentCapture ? {
      namespace: currentCapture.namespace,
      startTime: currentCapture.startTime.toISOString(),
      lineCount: currentCapture.lines.length,
    } : null,
    tool: LOG_TOOL,
    profiles: Object.keys(CPL_CLUSTERS),
  });
});

// ---- Start ----
server.listen(PORT, () => {
  const url = `http://localhost:${PORT}`;
  console.log(`\n  IO Log Viewer running at ${url}\n`);
  console.log(`  Log tool: ${LOG_TOOL}`);
  console.log(`  Profiles: ${Object.keys(CPL_CLUSTERS).join(', ')}`);
  console.log('');

  // Auto-open browser if --open flag
  if (process.argv.includes('--open')) {
    const openCmd = process.platform === 'darwin' ? 'open'
                  : process.platform === 'win32' ? 'start'
                  : 'xdg-open';
    exec(`${openCmd} ${url}`);
  }
});

// Cleanup on exit
process.on('SIGINT', () => {
  if (currentCapture) stopCapture();
  process.exit(0);
});

process.on('SIGTERM', () => {
  if (currentCapture) stopCapture();
  process.exit(0);
});
