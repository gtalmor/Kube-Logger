// Popup — compact controls for the IO Log Agent

const AGENT_URL = 'ws://localhost:4040';
let ws = null;
let connected = false;
let capturing = false;

const $ = id => document.getElementById(id);

function connect() {
  try { ws = new WebSocket(AGENT_URL); } catch { return setAgent(false); }

  ws.onopen = () => {
    connected = true;
    setAgent(true);
    chrome.runtime.sendMessage({ type: 'badge', text: '', color: '#3fb950' });
  };

  ws.onclose = () => {
    connected = false;
    setAgent(false);
    chrome.runtime.sendMessage({ type: 'badge', text: '!', color: '#f85149' });
    setTimeout(connect, 3000);
  };

  ws.onerror = () => {};

  ws.onmessage = ev => {
    const msg = JSON.parse(ev.data);

    switch (msg.type) {
      case 'init':
        if (msg.profiles) populateProfiles(msg.profiles);
        if (msg.auth && msg.auth.ok) setAuth(true, msg.auth.arn);
        if (msg.capturing) setCaptureState(true);
        break;

      case 'auth-status':
        setAuth(msg.ok, msg.arn, msg.err);
        if (msg.ok) $('loadNs').disabled = false;
        break;

      case 'auth-progress':
        $('authInfo').textContent = msg.msg;
        break;

      case 'auth-result':
        $('authInfo').textContent = msg.msg;
        if (msg.ok) $('loadNs').disabled = false;
        break;

      case 'namespaces':
        populateNs(msg.list);
        break;

      case 'capture-start':
        setCaptureState(true, msg.ns);
        break;

      case 'log':
        if (capturing) {
          $('captureInfo').innerHTML = `<span class="num">${msg.i + 1}</span> lines captured`;
        }
        break;

      case 'capture-stop':
      case 'capture-end':
        setCaptureState(false);
        if (msg.n !== undefined) $('captureInfo').innerHTML = `Done: <span class="num">${msg.n}</span> lines`;
        break;
    }
  };
}

function send(msg) { if (ws && ws.readyState === 1) ws.send(JSON.stringify(msg)); }

function setAgent(ok) {
  $('agentDot').className = `dot ${ok ? 'ok' : 'fail'}`;
  $('agentStatus').textContent = ok ? 'Connected to agent' : 'Agent not running — start with: cd agent && npm start';
}

function setAuth(ok, arn, err) {
  $('authDot').className = `dot ${ok ? 'ok' : 'fail'}`;
  $('authInfo').textContent = ok ? (arn ? arn.split('/').pop() : 'Authenticated') : (err || 'Not authenticated');
  if (ok) $('loadNs').disabled = false;
}

function setCaptureState(active, ns) {
  capturing = active;
  $('startBtn').style.display = active ? 'none' : '';
  $('stopBtn').style.display = active ? '' : 'none';
  $('startBtn').disabled = !$('ns').value;

  if (active) {
    chrome.runtime.sendMessage({ type: 'badge', text: 'REC', color: '#f85149' });
    $('captureInfo').textContent = `Capturing ${ns || ''}...`;
  } else {
    chrome.runtime.sendMessage({ type: 'badge', text: '', color: '#3fb950' });
  }
}

function populateProfiles(profiles) {
  const sel = $('profile');
  sel.innerHTML = '<option value="">Select profile...</option>';
  for (const p of profiles) {
    const opt = document.createElement('option');
    opt.value = p;
    opt.textContent = p.replace('example-', '').replace('-profile-a', ' (Lab)').replace('-profile-b', ' (Prod)');
    sel.appendChild(opt);
  }
  // Restore last used
  chrome.storage.local.get('lastProfile', d => {
    if (d.lastProfile) sel.value = d.lastProfile;
  });
}

function populateNs(list) {
  const sel = $('ns');
  sel.innerHTML = '<option value="">Select namespace...</option>';
  const priority = list.filter(n => n.includes('io') || n.includes('productpod'));
  const rest = list.filter(n => !priority.includes(n));
  for (const n of [...priority, ...rest]) {
    const opt = document.createElement('option');
    opt.value = n; opt.textContent = n;
    sel.appendChild(opt);
  }
  sel.disabled = false;
  // Restore last used
  chrome.storage.local.get('lastNs', d => {
    if (d.lastNs && list.includes(d.lastNs)) sel.value = d.lastNs;
    $('startBtn').disabled = !sel.value;
  });
}

// ── Events ──────────────────────────────────────────────────────────

$('profile').addEventListener('change', e => {
  const p = e.target.value;
  if (p) {
    chrome.storage.local.set({ lastProfile: p });
    send({ action: 'check-auth', profile: p });
    $('authDot').className = 'dot pending';
    $('authInfo').textContent = 'Checking...';
  }
});

$('checkBtn').addEventListener('click', () => {
  const p = $('profile').value;
  if (!p) return;
  send({ action: 'check-auth', profile: p });
  $('authDot').className = 'dot pending';
  $('authInfo').textContent = 'Checking...';
});

$('loginBtn').addEventListener('click', () => {
  const p = $('profile').value;
  if (!p) return;
  send({ action: 'login', profile: p });
  $('authDot').className = 'dot pending';
  $('authInfo').textContent = 'Opening SSO in browser...';
});

$('loadNs').addEventListener('click', () => {
  send({ action: 'namespaces' });
  $('ns').innerHTML = '<option value="">Loading...</option>';
});

$('ns').addEventListener('change', e => {
  $('startBtn').disabled = !e.target.value;
  if (e.target.value) chrome.storage.local.set({ lastNs: e.target.value });
});

$('startBtn').addEventListener('click', () => {
  const ns = $('ns').value;
  if (!ns) return;
  send({ action: 'start', ns });
  // Also open the viewer automatically
  chrome.runtime.sendMessage({ type: 'open-viewer' });
});

$('stopBtn').addEventListener('click', () => send({ action: 'stop' }));

$('openViewer').addEventListener('click', e => {
  e.preventDefault();
  chrome.runtime.sendMessage({ type: 'open-viewer' });
  window.close();
});

// ── Init ────────────────────────────────────────────────────────────
connect();
