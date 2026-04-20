// Popup — compact controls for the Kube Logger Agent

const AGENT_URL = 'ws://localhost:4040';
const DEFAULT_SAAS_URL = 'https://logviewer.gtalmor.com';
const NS_PALETTE = ['#3fb950', '#58a6ff', '#d29922', '#bc8cff', '#39c5cf', '#ff7b72', '#79c0ff', '#e6db74'];

function generateSessionId() {
  const bytes = new Uint8Array(16);
  (self.crypto || window.crypto).getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function toWssUrl(httpUrl) {
  if (!httpUrl) return '';
  return httpUrl.replace(/^http:/, 'ws:').replace(/^https:/, 'wss:');
}

let ws = null;
let connected = false;
let capturing = false;
let hasCaptureData = false;
let cachedNsList = [];
let selectedNs = new Set();
let nsColors = {};
let allProfiles = [];         // full list from agent (sourced from ~/.aws/config)
let disabledProfiles = new Set(); // profile names the user has hidden from the dropdown
let authState = { ok: false, arn: null, expiresAt: null, err: null };
let authTicker = null;
let saasUrl = DEFAULT_SAAS_URL;  // HTTPS URL of the SaaS (or blank to disable)
let sessionId = '';               // current session id (empty = no active SaaS session)
let saasConnected = false;        // agent's outbound SaaS connection state

const $ = id => document.getElementById(id);

function connect() {
  try { ws = new WebSocket(AGENT_URL); } catch { return setAgent(false); }

  ws.onopen = () => {
    connected = true;
    setAgent(true);
    chrome.runtime.sendMessage({ type: 'badge', text: '', color: '#3fb950' });
    updateStartBtn();
  };

  ws.onclose = () => {
    connected = false;
    setAgent(false);
    chrome.runtime.sendMessage({ type: 'badge', text: '!', color: '#f85149' });
    updateStartBtn();
    setTimeout(connect, 3000);
  };

  ws.onerror = () => {};

  ws.onmessage = ev => {
    const msg = JSON.parse(ev.data);

    switch (msg.type) {
      case 'init':
        if (msg.profiles) populateProfiles(msg.profiles);
        if (msg.auth && (msg.auth.ok || msg.auth.authenticated)) {
          setAuth(true, msg.auth.arn, null, msg.auth.expiresAt);
          chrome.storage.local.get('cachedNs', d => {
            if (d.cachedNs && d.cachedNs.length) { cachedNsList = d.cachedNs; renderNsList(); }
            send({ action: 'namespaces' });
          });
        }
        if (msg.capturing) {
          // Sync selection to the currently-active capture
          if (Array.isArray(msg.ns)) {
            selectedNs = new Set(msg.ns);
            for (const n of selectedNs) assignColor(n);
            chrome.storage.local.set({ selectedNs: [...selectedNs], nsColors });
            renderNsList();
          }
          setCaptureState(true);
        }
        if (msg.saas) {
          sessionId = msg.saas.session || '';
          saasConnected = !!msg.saas.connected;
          renderSaasStatus();
        }
        break;

      case 'auth-status':
        setAuth(msg.ok || msg.authenticated, msg.arn, msg.err || msg.error, msg.expiresAt);
        if (msg.ok || msg.authenticated) $('loadNs').disabled = false;
        break;

      case 'auth-progress':
        $('authInfo').textContent = msg.msg || msg.message;
        break;

      case 'auth-result':
        $('authInfo').textContent = msg.msg || msg.message;
        if (msg.ok || msg.success) $('loadNs').disabled = false;
        break;

      case 'namespaces': {
        const list = msg.list || msg.namespaces || [];
        if (list.length) chrome.storage.local.set({ cachedNs: list });
        cachedNsList = list;
        renderNsList();
        break;
      }

      case 'capture-start':
      case 'capture-started':
        setCaptureState(true, msg.ns || msg.namespace);
        break;

      case 'log':
        if (capturing) {
          $('captureInfo').innerHTML = `<span class="num">${(msg.i ?? 0) + 1}</span> lines captured`;
        }
        break;

      case 'capture-stop':
      case 'capture-stopped':
      case 'capture-end':
      case 'capture-ended':
        setCaptureState(false);
        { const count = msg.n ?? msg.lineCount;
          if (count !== undefined) $('captureInfo').innerHTML = `Done: <span class="num">${count}</span> lines`; }
        break;

      case 'cleared':
        hasCaptureData = false;
        capturing = false;
        $('captureInfo').textContent = '';
        $('clearBtn').style.display = 'none';
        $('startBtn').style.display = '';
        $('stopBtn').style.display = 'none';
        break;

      case 'saas-status':
        saasConnected = !!msg.connected;
        if (msg.session) sessionId = msg.session;
        renderSaasStatus();
        break;
    }
  };
}

function send(msg) { if (ws && ws.readyState === 1) ws.send(JSON.stringify(msg)); }

function setAgent(ok) {
  $('agentDot').className = `dot ${ok ? 'ok' : 'fail'}`;
  $('agentStatus').textContent = ok ? 'Connected to agent' : 'Agent not running — start with: cd agent && npm start';
}

function setAuth(ok, arn, err, expiresAt) {
  authState = { ok, arn: arn || null, expiresAt: expiresAt || null, err: err || null };
  if (ok) $('loadNs').disabled = false;
  renderAuthStatus();

  // (Re)start the 30s ticker only while authenticated with an expiration. Cheap
  // and avoids relying on the 60s server-side broadcast for countdown accuracy.
  if (authTicker) { clearInterval(authTicker); authTicker = null; }
  if (ok && authState.expiresAt) {
    authTicker = setInterval(renderAuthStatus, 30000);
  }
}

function formatRemaining(ms) {
  if (ms <= 0) return 'expired';
  const totalMin = Math.floor(ms / 60000);
  if (totalMin < 60) return `${totalMin}m left`;
  const h = Math.floor(totalMin / 60);
  const m = totalMin % 60;
  return `${h}h ${m}m left`;
}

function renderAuthStatus() {
  const dot = $('authDot');
  const info = $('authInfo');
  if (!authState.ok) {
    dot.className = 'dot fail';
    info.textContent = authState.err || 'Not authenticated';
    return;
  }
  const label = authState.arn ? authState.arn.split('/').pop() : 'Authenticated';
  if (!authState.expiresAt) {
    dot.className = 'dot ok';
    info.textContent = label;
    return;
  }
  const ms = authState.expiresAt - Date.now();
  const remaining = formatRemaining(ms);
  info.textContent = `${label} — ${remaining}`;
  // Color: red if expired, yellow if <10 min, green otherwise
  if (ms <= 0) dot.className = 'dot fail';
  else if (ms < 10 * 60 * 1000) dot.className = 'dot pending';
  else dot.className = 'dot ok';
}

function setCaptureState(active, ns) {
  capturing = active;
  $('startBtn').style.display = active ? 'none' : '';
  $('stopBtn').style.display = active ? '' : 'none';
  $('clearBtn').style.display = active ? 'none' : (hasCaptureData ? '' : 'none');

  if (active) {
    hasCaptureData = true;
    chrome.runtime.sendMessage({ type: 'badge', text: 'REC', color: '#f85149' });
    const label = Array.isArray(ns) ? ns.join(', ') : (ns || [...selectedNs].join(', '));
    $('captureInfo').textContent = `Capturing ${label}...`;
  } else {
    chrome.runtime.sendMessage({ type: 'badge', text: '', color: '#3fb950' });
    if (hasCaptureData) $('clearBtn').style.display = '';
  }
  updateStartBtn();
}

function prettyProfileName(p) {
  return p.replace('example-', '').replace('-profile-a', ' (Lab)').replace('-profile-b', ' (Prod)');
}

function populateProfiles(profiles) {
  if (profiles) allProfiles = profiles;
  const sel = $('profile');
  const previous = sel.value;
  sel.innerHTML = '<option value="">Select profile...</option>';
  for (const p of allProfiles) {
    if (disabledProfiles.has(p)) continue;
    const opt = document.createElement('option');
    opt.value = p;
    opt.textContent = prettyProfileName(p);
    sel.appendChild(opt);
  }
  // Restore previous selection, or last-used, if still enabled
  if (previous && !disabledProfiles.has(previous)) {
    sel.value = previous;
  } else {
    chrome.storage.local.get('lastProfile', d => {
      if (d.lastProfile && !disabledProfiles.has(d.lastProfile) && allProfiles.includes(d.lastProfile)) sel.value = d.lastProfile;
    });
  }
  renderProfilesPanel();
}

function renderProfilesPanel() {
  const el = $('profilesList');
  if (!allProfiles.length) {
    el.innerHTML = '<div class="profile-hint">No profiles in ~/.aws/config</div>';
    return;
  }
  let h = '';
  for (const p of allProfiles) {
    const enabled = !disabledProfiles.has(p);
    h += `<div class="profile-item" data-profile="${escapeAttr(p)}">`
      + `<input type="checkbox" ${enabled ? 'checked' : ''} />`
      + `<span class="pn" title="${escapeAttr(p)}">${escapeText(p)}</span>`
      + `</div>`;
  }
  el.innerHTML = h;
}

// ── Namespace multi-select ─────────────────────────────────────────
function assignColor(ns) {
  if (nsColors[ns]) return nsColors[ns];
  const used = new Set(Object.values(nsColors));
  const next = NS_PALETTE.find(c => !used.has(c)) || NS_PALETTE[Object.keys(nsColors).length % NS_PALETTE.length];
  nsColors[ns] = next;
  return next;
}

function renderNsList() {
  const el = $('nsList');
  if (!cachedNsList.length) {
    el.innerHTML = '<div class="ns-empty">Load namespaces first</div>';
    renderSelectedSummary();
    return;
  }

  const filter = $('nsFilter').value.toLowerCase();
  const priority = cachedNsList.filter(n => n.includes('io') || n.includes('productpod'));
  const rest = cachedNsList.filter(n => !priority.includes(n));
  const ordered = [...priority, ...rest];
  const filtered = filter ? ordered.filter(n => n.toLowerCase().includes(filter)) : ordered;

  if (!filtered.length) {
    el.innerHTML = '<div class="ns-empty">No matches</div>';
    renderSelectedSummary();
    return;
  }

  // Put checked ones at the top so they're always visible
  filtered.sort((a, b) => (selectedNs.has(b) ? 1 : 0) - (selectedNs.has(a) ? 1 : 0));

  let html = '';
  for (const ns of filtered) {
    const checked = selectedNs.has(ns);
    const color = checked ? assignColor(ns) : (nsColors[ns] || '#30363d');
    html += `<div class="ns-item" data-ns="${escapeAttr(ns)}">
      <input type="checkbox" ${checked ? 'checked' : ''} />
      <span class="ns-name" title="${escapeAttr(ns)}">${escapeText(ns)}</span>
      ${checked ? `<input type="color" value="${color}" title="Color for ${escapeAttr(ns)}" />` : ''}
    </div>`;
  }
  el.innerHTML = html;
  renderSelectedSummary();
}

function renderSelectedSummary() {
  const el = $('nsSelectedSummary');
  if (!selectedNs.size) { el.innerHTML = '<span style="color:var(--muted)">None selected</span>'; return; }
  let h = '';
  for (const ns of selectedNs) {
    const c = nsColors[ns] || '#30363d';
    h += `<span class="ns-chip"><span class="ns-dot" style="background:${c}"></span>${escapeText(ns)}</span>`;
  }
  el.innerHTML = h;
}

function escapeText(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function escapeAttr(s) { return escapeText(s).replace(/"/g,'&quot;'); }

function updateStartBtn() {
  $('startBtn').disabled = !selectedNs.size || !connected || capturing;
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
  if (!connected) { $('authInfo').textContent = 'Agent not connected'; return; }
  const p = $('profile').value;
  if (!p) { $('authInfo').textContent = 'Select a profile first'; return; }
  send({ action: 'check-auth', profile: p });
  $('authDot').className = 'dot pending';
  $('authInfo').textContent = 'Checking...';
});

$('loginBtn').addEventListener('click', () => {
  if (!connected) { $('authInfo').textContent = 'Agent not connected'; return; }
  const p = $('profile').value;
  if (!p) { $('authInfo').textContent = 'Select a profile first'; return; }
  send({ action: 'login', profile: p });
  $('authDot').className = 'dot pending';
  $('authInfo').textContent = 'Opening SSO in browser...';
});

$('loadNs').addEventListener('click', () => {
  send({ action: 'namespaces' });
  $('nsList').innerHTML = '<div class="ns-empty">Loading...</div>';
});

$('nsFilter').addEventListener('input', () => renderNsList());

$('nsList').addEventListener('change', e => {
  const item = e.target.closest('.ns-item');
  if (!item) return;
  const ns = item.dataset.ns;
  if (e.target.type === 'checkbox') {
    if (e.target.checked) { selectedNs.add(ns); assignColor(ns); }
    else selectedNs.delete(ns);
    chrome.storage.local.set({ selectedNs: [...selectedNs], nsColors });
    // If a capture is active, add/remove the stream live instead of waiting for the next Start.
    if (capturing) {
      send({ action: e.target.checked ? 'add-ns' : 'remove-ns', ns: [ns] });
    }
    renderNsList();
    updateStartBtn();
  } else if (e.target.type === 'color') {
    nsColors[ns] = e.target.value;
    chrome.storage.local.set({ nsColors });
    renderSelectedSummary();
  }
});

// Click anywhere on a row toggles the checkbox
$('nsList').addEventListener('click', e => {
  if (e.target.tagName === 'INPUT') return;
  const item = e.target.closest('.ns-item');
  if (!item) return;
  const cb = item.querySelector('input[type=checkbox]');
  if (cb) { cb.checked = !cb.checked; cb.dispatchEvent(new Event('change', { bubbles: true })); }
});

$('startBtn').addEventListener('click', () => {
  const ns = [...selectedNs];
  if (!ns.length) return;

  if (saasUrl) {
    // SaaS path: ensure we have a session, tell the agent to connect to the relay
    // as a producer for that session, then open the web viewer for it.
    if (!sessionId) sessionId = generateSessionId();
    send({ action: 'saas-connect', url: toWssUrl(saasUrl), session: sessionId });
    send({ action: 'start', ns });
    const viewer = `${saasUrl.replace(/\/+$/, '')}/?s=${encodeURIComponent(sessionId)}`;
    chrome.tabs.create({ url: viewer });
  } else {
    // No SaaS configured — fall back to the extension's local viewer tab.
    send({ action: 'start', ns });
    chrome.runtime.sendMessage({ type: 'open-viewer' });
  }
});

$('stopBtn').addEventListener('click', () => send({ action: 'stop' }));

$('clearBtn').addEventListener('click', () => {
  send({ action: 'clear' });
  hasCaptureData = false;
  $('captureInfo').textContent = '';
  $('clearBtn').style.display = 'none';
});

$('openViewerHeader').addEventListener('click', e => {
  e.preventDefault();
  if (saasUrl && sessionId) {
    chrome.tabs.create({ url: `${saasUrl.replace(/\/+$/, '')}/?s=${encodeURIComponent(sessionId)}` });
  } else {
    chrome.runtime.sendMessage({ type: 'open-viewer' });
  }
  window.close();
});

// SaaS relay config panel
$('saasManage').addEventListener('click', () => {
  const panel = $('saasConfig');
  panel.style.display = panel.style.display === 'none' ? '' : 'none';
  if (panel.style.display !== 'none') $('saasUrl').focus();
});

$('saasUrl').addEventListener('change', e => {
  saasUrl = e.target.value.trim().replace(/\/+$/, '');
  chrome.storage.local.set({ saasUrl });
  renderSaasStatus();
});

function renderSaasStatus() {
  const dot = $('saasDot');
  const info = $('saasInfo');
  $('saasUrl').value = saasUrl;
  if (!saasUrl) { dot.className = 'dot fail'; info.textContent = 'Relay disabled'; return; }
  if (!sessionId) { dot.className = 'dot'; info.textContent = 'Relay: ' + saasUrl.replace(/^https?:\/\//, ''); return; }
  const short = sessionId.slice(0, 8) + '…';
  if (saasConnected) { dot.className = 'dot ok'; info.textContent = `Session ${short} — live`; }
  else               { dot.className = 'dot pending'; info.textContent = `Session ${short} — connecting…`; }
}

// Profiles manage panel
$('profilesManage').addEventListener('click', () => {
  const panel = $('profilesPanel');
  panel.style.display = panel.style.display === 'none' ? '' : 'none';
});

$('profilesList').addEventListener('change', e => {
  const item = e.target.closest('.profile-item');
  if (!item || e.target.type !== 'checkbox') return;
  const name = item.dataset.profile;
  if (e.target.checked) disabledProfiles.delete(name);
  else disabledProfiles.add(name);
  chrome.storage.local.set({ disabledProfiles: [...disabledProfiles] });
  populateProfiles();
});

// Click anywhere on a row toggles the checkbox
$('profilesList').addEventListener('click', e => {
  if (e.target.tagName === 'INPUT') return;
  const item = e.target.closest('.profile-item');
  if (!item) return;
  const cb = item.querySelector('input[type=checkbox]');
  if (cb) { cb.checked = !cb.checked; cb.dispatchEvent(new Event('change', { bubbles: true })); }
});

// React to color/selection changes made in the viewer
chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  let changed = false;
  if (changes.nsColors) { nsColors = changes.nsColors.newValue || {}; changed = true; }
  if (changes.selectedNs) { selectedNs = new Set(changes.selectedNs.newValue || []); changed = true; }
  if (changed) renderNsList();
});

// ── Init ────────────────────────────────────────────────────────────
chrome.storage.local.get(['selectedNs', 'nsColors', 'cachedNs', 'disabledProfiles', 'saasUrl'], d => {
  selectedNs = new Set(d.selectedNs || []);
  nsColors = d.nsColors || {};
  disabledProfiles = new Set(d.disabledProfiles || []);
  if (typeof d.saasUrl === 'string') saasUrl = d.saasUrl;  // allow empty string to disable SaaS
  if (d.cachedNs) { cachedNsList = d.cachedNs; renderNsList(); }
  renderSaasStatus();
  updateStartBtn();
  connect();
});
