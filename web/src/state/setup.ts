// Setup drawer state: AWS profiles/auth, namespaces, workload filters,
// capture control. Talks to the agent through connection.send().
import { computed, effect, signal } from '@preact/signals';
import { loadDrawerState, saveDrawerState } from '../lib/storage';
import { nextNsColor } from '../lib/colors';
import { toast } from './toasts';

export interface ProfileMode { mode: string; label: string }
export interface Workload { name: string; count: number }

const saved = loadDrawerState();

export const profiles = signal<string[]>([]);
export const profileModes = signal<Record<string, ProfileMode>>({});
export const disabledProfiles = signal<string[]>(saved.disabledProfiles);
export const selectedProfile = signal<string>(saved.lastProfile);
export const cachedNs = signal<string[]>(saved.cachedNs);
export const selectedNs = signal<string[]>(saved.selectedNs);
export const selectedWf = signal<Record<string, string[]>>(saved.selectedWf);
export const cachedWf = signal<Record<string, Workload[]>>({});
export const expandedNs = signal<string[]>([]);
export const loadingWf = signal<string[]>([]);
export const nsColors = signal<Record<string, string>>(saved.nsColors);
export const nsFilter = signal('');
export const clusterPick = signal<{ profile: string; region?: string; clusters: string[] } | null>(null);
export const progress = signal<string>('');          // transient auth/progress line
export const nsLoading = signal(false);
export const manageOpen = signal(false);

export const visibleProfiles = computed(() => profiles.value.filter(p => !disabledProfiles.value.includes(p)));
export const modeFor = (p: string): ProfileMode => profileModes.value[p] || { mode: 'sso', label: 'SSO' };
export const wfFor = (ns: string): string[] => selectedWf.value[ns] || [];
export function buildFilters(): Record<string, string[]> {
  const f: Record<string, string[]> = {};
  for (const ns of selectedNs.value) { const w = wfFor(ns); if (w.length) f[ns] = w; }
  return f;
}

let sendFn: (m: Record<string, unknown>) => void = () => {};
export function bindSend(fn: (m: Record<string, unknown>) => void): void { sendFn = fn; }
const send = (m: Record<string, unknown>) => sendFn(m);

// Persist the remembered bits.
effect(() => {
  saveDrawerState({
    disabledProfiles: disabledProfiles.value, cachedNs: cachedNs.value, selectedNs: selectedNs.value,
    selectedWf: selectedWf.value, nsColors: nsColors.value, lastProfile: selectedProfile.value,
  });
});

export function ensureNsColor(ns: string): string {
  const cur = nsColors.value[ns];
  if (cur) return cur;
  const c = nextNsColor(nsColors.value);
  nsColors.value = { ...nsColors.value, [ns]: c };
  return c;
}
export function setNsColor(ns: string, color: string): void {
  nsColors.value = { ...nsColors.value, [ns]: color };
}

// ── actions ─────────────────────────────────────────────────────────
export function checkAuth(profile = selectedProfile.value): void {
  if (!profile) return;
  progress.value = 'Checking…';
  send({ action: 'check-auth', profile });
}
export function selectProfile(p: string): void {
  selectedProfile.value = p;
  if (p) checkAuth(p);
}
export function login(): void {
  const p = selectedProfile.value;
  if (!p) { progress.value = 'Select a profile first'; return; }
  const { mode, label } = modeFor(p);
  progress.value = mode === 'sso' ? 'Opening SSO on agent machine…' : `Authenticating (${label}) on agent machine…`;
  send({ action: 'login', profile: p });
}
export function loadNamespaces(): void {
  nsLoading.value = true;
  send({ action: 'namespaces' });
}
export function toggleProfileEnabled(p: string, enabled: boolean): void {
  disabledProfiles.value = enabled ? disabledProfiles.value.filter(x => x !== p) : [...disabledProfiles.value, p];
}
export function toggleNs(ns: string, on: boolean, capturing: boolean): void {
  if (on) { if (!selectedNs.value.includes(ns)) selectedNs.value = [...selectedNs.value, ns]; ensureNsColor(ns); }
  else { selectedNs.value = selectedNs.value.filter(n => n !== ns); expandedNs.value = expandedNs.value.filter(n => n !== ns); }
  if (capturing) send({ action: on ? 'add-ns' : 'remove-ns', ns: [ns], filters: buildFilters() });
}
export function toggleExpanded(ns: string): void {
  if (expandedNs.value.includes(ns)) { expandedNs.value = expandedNs.value.filter(n => n !== ns); return; }
  expandedNs.value = [...expandedNs.value, ns];
  if (!cachedWf.value[ns]) { loadingWf.value = [...loadingWf.value, ns]; send({ action: 'pods', ns }); }
}
export function refreshWorkloads(ns: string): void {
  loadingWf.value = [...loadingWf.value, ns];
  send({ action: 'pods', ns });
}
export function toggleWorkload(ns: string, wl: string, on: boolean, capturing: boolean): void {
  const set = new Set(wfFor(ns));
  if (on) set.add(wl); else set.delete(wl);
  const next = { ...selectedWf.value };
  if (set.size) next[ns] = [...set]; else delete next[ns];
  selectedWf.value = next;
  if (capturing && selectedNs.value.includes(ns)) send({ action: 'set-filter', ns, workloads: wfFor(ns) });
}
export function clearWorkloads(ns: string, capturing: boolean): void {
  const next = { ...selectedWf.value };
  delete next[ns];
  selectedWf.value = next;
  if (capturing && selectedNs.value.includes(ns)) send({ action: 'set-filter', ns, workloads: [] });
}
export function startCapture(): boolean {
  const ns = [...selectedNs.value];
  if (!ns.length) return false;
  send({ action: 'start', ns, filters: buildFilters() });
  return true;
}
export function stopCapture(): void { send({ action: 'stop' }); }
export function pickCluster(profile: string, cluster: string, region?: string): void {
  send({ action: 'pick-cluster', profile, cluster, ...(region ? { region } : {}) });
  clusterPick.value = null;
  progress.value = `Connecting to ${cluster}…`;
}

// ── agent message hooks (called by the connection dispatcher) ───────
type Loose = { [k: string]: unknown };
export function onInit(m: { profiles?: string[]; profileModes?: Record<string, ProfileMode>; auth?: { profile?: string; ok?: boolean } | null; capturing?: boolean; ns?: string[] | null; filters?: Record<string, string[]> | null } & Loose, authOk: boolean): void {
  if (m.profileModes) profileModes.value = m.profileModes;
  if (Array.isArray(m.profiles)) {
    profiles.value = m.profiles;
    if (!selectedProfile.value || !m.profiles.includes(selectedProfile.value)) {
      const first = m.profiles.find(p => !disabledProfiles.value.includes(p));
      if (!selectedProfile.value && first && m.profiles.length === 1) selectedProfile.value = first;
    }
  }
  if (m.capturing && Array.isArray(m.ns)) {
    selectedNs.value = m.ns;
    for (const n of m.ns) ensureNsColor(n);
    if (m.filters && typeof m.filters === 'object') selectedWf.value = { ...m.filters };
  }
  const p = (m.auth && m.auth.profile) || selectedProfile.value;
  if (p) { if (!selectedProfile.value) selectedProfile.value = p; send({ action: 'check-auth', profile: p }); }
  if (authOk && !cachedNs.value.length) loadNamespaces();
}
export function onAuthStatus(m: { profile?: string; authMode?: string; authLabel?: string; ok?: boolean } & Loose): void {
  if (m.profile && m.authMode) profileModes.value = { ...profileModes.value, [m.profile]: { mode: m.authMode, label: m.authLabel || profileModes.value[m.profile]?.label || 'External' } };
  progress.value = '';
  if (m.ok && !cachedNs.value.length && !nsLoading.value) loadNamespaces();
}
export function onAuthProgress(m: { msg?: string; message?: string } & Loose): void { progress.value = m.msg || m.message || ''; }
export function onAuthResult(m: { ok?: boolean; success?: boolean; msg?: string; message?: string } & Loose): void {
  const msg = m.msg || m.message;
  if (msg) toast(msg, m.ok || m.success ? 'ok' : 'error');
  if (m.ok || m.success) { const p = selectedProfile.value; if (p) send({ action: 'check-auth', profile: p }); }
}
export function onNamespaces(m: { list?: string[]; namespaces?: string[]; err?: string } & Loose): void {
  nsLoading.value = false;
  const list = m.list || m.namespaces || [];
  cachedNs.value = list;
  if (!list.length && m.err) toast(`kubectl: ${String(m.err).slice(0, 200)}`, 'error', 5000);
}
export function onPods(m: { ns?: string; workloads?: Workload[]; err?: string } & Loose): void {
  if (typeof m.ns !== 'string') return;
  const ns = m.ns;
  loadingWf.value = loadingWf.value.filter(n => n !== ns);
  const list = Array.isArray(m.workloads) ? m.workloads : [];
  cachedWf.value = { ...cachedWf.value, [ns]: list };
  if (m.err) toast(`pods (${ns}): ${String(m.err).slice(0, 160)}`, 'error', 5000);
  const sel = selectedWf.value[ns];
  if (sel) {
    const live = new Set(list.map(w => w.name));
    const kept = sel.filter(w => live.has(w));
    const next = { ...selectedWf.value };
    if (kept.length) next[ns] = kept; else delete next[ns];
    selectedWf.value = next;
  }
}
export function onClusterPick(m: { profile?: string; region?: string; clusters?: string[] } & Loose): void {
  const clusters = (m.clusters || []).map(String);
  clusterPick.value = clusters.length && typeof m.profile === 'string' ? { profile: m.profile, region: m.region, clusters } : null;
}
export function onCaptureStart(m: { ns?: string[] | string } & Loose): void {
  const ns = Array.isArray(m.ns) ? m.ns : (typeof m.ns === 'string' ? m.ns.split(',').map(s => s.trim()).filter(Boolean) : []);
  if (ns.length) { selectedNs.value = ns; for (const n of ns) ensureNsColor(n); }
}
export function onNsAdded(ns: string[]): void {
  for (const n of ns) { ensureNsColor(n); if (!selectedNs.value.includes(n)) selectedNs.value = [...selectedNs.value, n]; }
}
