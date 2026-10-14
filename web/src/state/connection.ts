// WebSocket client to the relay + the message dispatcher (protocol v2).
import { signal } from '@preact/signals';
import { loadLastSession, saveLastSession } from '../lib/storage';
import { store } from './app';
import * as setup from './setup';
import { toast } from './toasts';
import { failureReason, hintFor, stderrKey, stripKlog, WATCH_FAIL_RE } from '../lib/stderr';
import { applyStreamStatus, clearStreamStatus, isDegraded } from './streams';

export interface AuthState {
  ok: boolean; profile?: string; arn?: string; account?: string; err?: string;
  expiresAt?: number | null; authMode?: string; authLabel?: string; cluster?: string;
}
export interface CaptureState { active: boolean; ns: string[]; start: number | null; n: number; captureId: string | null }

export const sessionId = ((): string => {
  if (typeof location === 'undefined') return '';
  const q = new URLSearchParams(location.search);
  return (q.get('session') || q.get('s') || '').trim();
})();
export const wsConnected = signal(false);
export const agentConnected = signal(false);
export const replaying = signal(false);
export const auth = signal<AuthState | null>(null);
export const capture = signal<CaptureState>({ active: false, ns: [], start: null, n: 0, captureId: null });
export const agentInfo = signal<{ tool?: string; sternAvailable?: boolean }>({});
export const lastAgentLine = signal(0);   // agent's running line count (from log-batch i)

let ws: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let reconnectDelay = 1500;

export function send(m: Record<string, unknown>): void {
  if (ws && ws.readyState === 1) { try { ws.send(JSON.stringify(m)); } catch { /* ignore */ } }
}
setup.bindSend(send);

function wsUrl(): string {
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${location.host}/consumer?session=${encodeURIComponent(sessionId)}`;
}

/** Bare domain visit → bounce to the last session so the domain is a valid bookmark. */
export function maybeRedirectToLastSession(): boolean {
  if (sessionId) { saveLastSession(sessionId); return false; }
  if (new URLSearchParams(location.search).has('demo')) return false;
  const last = loadLastSession();
  if (!last) return false;
  location.replace(`?session=${last}`);
  return true;
}

export function connect(): void {
  if (!sessionId) return;
  if (ws && (ws.readyState === 0 || ws.readyState === 1)) return;
  try { ws = new WebSocket(wsUrl()); } catch { scheduleReconnect(); return; }
  const sock = ws;
  sock.onopen = () => { reconnectDelay = 1500; wsConnected.value = true; };
  sock.onclose = () => { if (ws === sock) ws = null; wsConnected.value = false; agentConnected.value = false; replaying.value = false; scheduleReconnect(); };
  sock.onerror = () => { /* onclose follows */ };
  sock.onmessage = ev => {
    let m: Msg;
    try { m = JSON.parse(ev.data); } catch { return; }
    try { dispatch(m); } catch (e) { console.error('[viewer] dispatch error', e, m); }
  };
}
function scheduleReconnect(): void {
  if (reconnectTimer) return;
  reconnectTimer = setTimeout(() => { reconnectTimer = null; connect(); }, reconnectDelay);
  reconnectDelay = Math.min(reconnectDelay * 2, 15000);
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type Msg = Record<string, any> & { type: string };

// stern repeats the same stderr line on every retry (e.g. "Watch failed"
// every second per namespace). The agent already forwards at most one such
// line per minute per namespace; here identical lines are collapsed further
// and, once the agent has flagged the stream as degraded, dropped in favour
// of the StreamStrip banner.
const stderrSeen = new Map<string, { at: number; n: number }>();
function stderrToast(ns: string | undefined, msg: string): void {
  if (WATCH_FAIL_RE.test(msg) && isDegraded(ns)) return;
  const watch = WATCH_FAIL_RE.test(msg);
  const clean = watch ? `Watch failed: ${failureReason(msg)}` : stripKlog(msg);
  const key = stderrKey(ns, clean);
  const now = Date.now();
  const seen = stderrSeen.get(key);
  if (seen && now - seen.at < 60000) { seen.n++; return; }
  const n = seen ? seen.n : 0;
  stderrSeen.set(key, { at: now, n: 1 });
  if (stderrSeen.size > 200) { const oldest = [...stderrSeen.entries()].sort((a, b) => a[1].at - b[1].at)[0]; if (oldest) stderrSeen.delete(oldest[0]); }
  const hint = hintFor(failureReason(msg));
  toast(`${ns ? `[${ns}] ` : ''}${clean.slice(0, 160)}${n > 1 ? ` (×${n} in the last minute)` : ''}${hint ? ` — ${hint}` : ''}`, 'error', 6000);
}

function setCapture(active: boolean, m: Partial<Msg> = {}): void {
  const ns = Array.isArray(m.ns) ? m.ns : (typeof m.ns === 'string' ? m.ns.split(',').map((s: string) => s.trim()).filter(Boolean) : capture.value.ns);
  capture.value = {
    active, ns, captureId: m.captureId ?? (active ? capture.value.captureId : null),
    start: active ? (m.start ?? capture.value.start ?? Date.now()) : null,
    n: typeof m.n === 'number' ? m.n : capture.value.n,
  };
}

export function dispatch(m: Msg): void {
  switch (m.type) {
    case 'relay-hello':
      agentConnected.value = !!m.producerConnected;
      if (m.producerConnected) send({ action: 'get-init' });
      break;
    case 'producer-ready':
      agentConnected.value = true;
      toast('Agent connected', 'ok');
      send({ action: 'get-init' });
      break;
    case 'producer-gone':
      agentConnected.value = false;
      setCapture(false);
      clearStreamStatus();
      toast('Agent disconnected', 'error');
      break;

    case 'init': {
      agentInfo.value = { tool: m.tool, sternAvailable: m.sternAvailable };
      clearStreamStatus();
      if (m.streams && typeof m.streams === 'object') for (const [ns, st] of Object.entries(m.streams as Record<string, Record<string, unknown>>)) applyStreamStatus({ ...st, ns });
      if (m.auth) auth.value = { ...m.auth, ok: !!(m.auth.ok || m.auth.authenticated) };
      if (m.capturing) {
        store.resetForCapture(m.captureId ?? null, m.start ?? null, Array.isArray(m.ns) ? m.ns : []);
        setCapture(true, m);
      } else {
        setCapture(false);
      }
      setup.onInit(m, !!(m.auth && (m.auth.ok || m.auth.authenticated)));
      break;
    }
    case 'capture-start':
      store.resetForCapture(m.captureId ?? null, m.start ?? null, Array.isArray(m.ns) ? m.ns : []);
      setCapture(true, m);
      setup.onCaptureStart(m);
      clearStreamStatus();
      break;
    case 'stream-status':
      applyStreamStatus(m);
      break;
    case 'capture-state':   // not fanned out by the v2 relay; harmless if it arrives
      store.resetForCapture(m.captureId ?? null, m.start ?? null, Array.isArray(m.ns) ? m.ns : []);
      setCapture(true, m);
      break;

    case 'history-begin':
      replaying.value = true;
      if (m.captureId !== undefined && m.captureId !== store.captureId) store.resetForCapture(m.captureId, null, store.nsCapturing);
      if (m.lines) toast(`Loading ${m.lines} previously captured lines…`);
      break;
    case 'history-end':
      replaying.value = false;
      store.flushNow();
      break;

    case 'log':
      store.ingest([{ i: m.i, ns: m.ns, line: m.line }]);
      if (typeof m.i === 'number') lastAgentLine.value = m.i + 1;
      break;
    case 'log-batch': {
      const items = Array.isArray(m.items) ? m.items : [];
      store.ingest(items);
      const last = items[items.length - 1];
      if (last && typeof last.i === 'number') lastAgentLine.value = last.i + 1;
      break;
    }

    case 'cleared':
      store.clear();
      setCapture(false);
      clearStreamStatus();
      break;
    case 'ns-added': {
      const arr: string[] = Array.isArray(m.ns) ? m.ns : [m.ns];
      for (const n of arr) if (n) { store.nsCapturing.add(n); store.nsSeen.add(n); }
      setup.onNsAdded(arr.filter(Boolean));
      capture.value = { ...capture.value, ns: [...new Set([...capture.value.ns, ...arr])] };
      store.flushNow();
      if (arr.length) toast(`Added: ${arr.join(', ')}`);
      break;
    }
    case 'ns-refiltered':
      toast(`${m.ns}: ${Array.isArray(m.workloads) && m.workloads.length ? m.workloads.length + ' workload(s)' : 'all pods'}`);
      break;
    case 'stream-end':
      if (m.ns) { store.nsCapturing.delete(m.ns); clearStreamStatus(m.ns); capture.value = { ...capture.value, ns: capture.value.ns.filter(n => n !== m.ns) }; toast(`Stream ended: ${m.ns}`); }
      break;
    case 'capture-stop': case 'capture-stopped': case 'capture-end': case 'capture-ended':
      setCapture(false, m);
      store.flushNow();
      clearStreamStatus();
      if (m.n !== undefined) toast(`Captured ${m.n} lines`);
      break;

    case 'stderr':
      if (m.msg && !String(m.msg).includes('Experimental')) stderrToast(m.ns, String(m.msg));
      break;
    case 'error':
      toast('Error: ' + (m.msg || 'unknown'), 'error', 5000);
      break;

    case 'auth-status':
      auth.value = { ...m, ok: !!(m.ok || m.authenticated), err: m.err || m.error };
      setup.onAuthStatus(m);
      break;
    case 'auth-progress': setup.onAuthProgress(m); break;
    case 'auth-result': setup.onAuthResult(m); break;
    case 'cluster-pick': setup.onClusterPick(m); break;
    case 'namespaces': setup.onNamespaces(m); break;
    case 'pods': setup.onPods(m); break;
    case 'saved': toast(`Saved ${m.fn || ''}`); break;
    default:
      break;   // presence / presenter / invite / saas-status: ignored
  }
}
