// Typed localStorage accessors. Key names are kept from the legacy viewer so
// settings carry over (and stay shared with /legacy/ during the transition).

import { migrateFilterField, type FilterState, type TriFilter } from './filters';
import { PALETTE_DEFAULTS, type LevelPalette } from './colors';

export const KEYS = {
  lastSession: 'kubelogger.lastSession.v1',
  hiddenPatterns: 'kube-logger-hidden-patterns',
  highlights: 'kube-logger-highlights',
  presets: 'kube-logger-filter-presets',
  flowDefs: 'kubelogger.flowDefs.v1',
  drawer: 'kubelogger.drawer.v1',
  shimNsColors: 'chrome-shim:nsColors',
  paletteV1: 'kubelogger.palette.v1',
  paletteV2: 'kubelogger.palette.v2',
  tpWidth: 'kubelogger.tpWidth.v1',
  ui: 'kubelogger.ui.v1',
} as const;

type Store = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;
let store: Store | null = null;
function ls(): Store | null {
  if (store) return store;
  try { store = typeof localStorage !== 'undefined' ? localStorage : null; } catch { store = null; }
  return store;
}
/** Tests inject a fake. */
export function useStorage(s: Store | null): void { store = s; }

export function getJson<T>(key: string, fallback: T): T {
  try {
    const raw = ls()?.getItem(key);
    if (raw == null) return fallback;
    return JSON.parse(raw) as T;
  } catch { return fallback; }
}
export function setJson(key: string, value: unknown): void {
  try { ls()?.setItem(key, JSON.stringify(value)); } catch { /* quota / private mode */ }
}
export function getString(key: string): string | null {
  try { return ls()?.getItem(key) ?? null; } catch { return null; }
}
export function setString(key: string, value: string): void {
  try { ls()?.setItem(key, value); } catch { /* ignore */ }
}

// ── UI prefs ────────────────────────────────────────────────────────
export type Theme = 'system' | 'light' | 'dark';
export interface UiPrefs {
  theme: Theme;
  wrap: boolean;
  autoScroll: boolean;
  bufferCap: number;
  stripsCollapsed: { errors?: boolean; flow?: boolean };
  panelWidth: number;
  jumpToFirstErrorOnEnd: boolean;
}
export const UI_DEFAULTS: UiPrefs = { theme: 'system', wrap: false, autoScroll: true, bufferCap: 50000, stripsCollapsed: {}, panelWidth: 520, jumpToFirstErrorOnEnd: true };
export function loadUiPrefs(): UiPrefs {
  const j = getJson<Partial<UiPrefs>>(KEYS.ui, {});
  const out: UiPrefs = { ...UI_DEFAULTS, ...j, stripsCollapsed: { ...(j.stripsCollapsed || {}) } };
  if (j.panelWidth === undefined) {
    const w = parseInt(getString(KEYS.tpWidth) || '', 10);
    if (w > 200) out.panelWidth = w;
  }
  if (!(out.bufferCap >= 1000)) out.bufferCap = UI_DEFAULTS.bufferCap;
  return out;
}
export function saveUiPrefs(p: UiPrefs): void { setJson(KEYS.ui, p); }

// ── filters / presets ───────────────────────────────────────────────
export function loadHiddenPatterns(): string[] { const v = getJson<unknown>(KEYS.hiddenPatterns, []); return Array.isArray(v) ? v.filter(x => typeof x === 'string') : []; }
export function saveHiddenPatterns(v: string[]): void { setJson(KEYS.hiddenPatterns, v); }
export function loadHighlights(): string[] { const v = getJson<unknown>(KEYS.highlights, []); return Array.isArray(v) ? v.filter(x => typeof x === 'string') : []; }
export function saveHighlights(v: string[]): void { setJson(KEYS.highlights, v); }

export interface PresetStore { current: string; presets: Record<string, Partial<FilterState> & { level?: unknown; pod?: unknown; req?: unknown }> }
export function loadPresets(): PresetStore {
  const j = getJson<Partial<PresetStore>>(KEYS.presets, {});
  return { current: typeof j.current === 'string' ? j.current : '', presets: (j.presets && typeof j.presets === 'object') ? j.presets : {} };
}
export function savePresets(p: PresetStore): void { setJson(KEYS.presets, p); }
/** Normalize a stored preset (any vintage) into a full FilterState. */
export function presetToFilters(p: Partial<FilterState> & { level?: unknown; pod?: unknown; req?: unknown }): FilterState {
  return {
    search: typeof p.search === 'string' ? p.search : '',
    level: migrateFilterField(p.level) as TriFilter,
    pod: migrateFilterField(p.pod) as TriFilter,
    req: migrateFilterField(p.req) as TriFilter,
    hideTrace: !!p.hideTrace,
    hiddenPatterns: Array.isArray(p.hiddenPatterns) ? [...p.hiddenPatterns] : [],
    hiddenExecIds: Array.isArray(p.hiddenExecIds) ? [...p.hiddenExecIds] : [],
    highlights: Array.isArray(p.highlights) ? [...p.highlights] : [],
  };
}

// ── flow definitions ────────────────────────────────────────────────
export interface FlowDefFile { name: string; filename: string; nodeCount: number; labels: Record<string, string> }
export interface FlowDefsStore { files: FlowDefFile[]; labels: Record<string, string> }
export function loadFlowDefs(): FlowDefsStore {
  const j = getJson<Partial<FlowDefsStore>>(KEYS.flowDefs, {});
  const files = Array.isArray(j.files) ? j.files.filter(f => f && typeof f.name === 'string') : [];
  const labels: Record<string, string> = {};
  for (const f of files) Object.assign(labels, f.labels || {});
  return { files, labels };
}
export function saveFlowDefs(s: FlowDefsStore): void { setJson(KEYS.flowDefs, s); }

/** Parse an uploaded IO flow JSON into nodeId → title labels. */
export function parseFlowDef(json: unknown, filename: string): FlowDefFile | null {
  const j = json as { content?: unknown; name?: unknown } | null;
  const flow = (j && typeof j === 'object' && (j.content || j)) as { nodes?: Record<string, { meta?: { title?: string }; title?: string }>; name?: string } | null;
  if (!flow || !flow.nodes || typeof flow.nodes !== 'object') return null;
  const labels: Record<string, string> = {};
  let count = 0;
  for (const [id, n] of Object.entries(flow.nodes)) {
    const title = (n && n.meta && n.meta.title) || (n && n.title) || '';
    if (title) { labels[id] = title; count++; }
  }
  return { name: String((j && typeof j === 'object' && typeof j.name === 'string' && j.name) || flow.name || filename || 'unnamed'), filename: filename || '', nodeCount: count, labels };
}

// ── drawer state (profiles, namespaces, colours) ────────────────────
export interface DrawerState {
  disabledProfiles: string[];
  cachedNs: string[];
  selectedNs: string[];
  selectedWf: Record<string, string[]>;
  nsColors: Record<string, string>;
  lastProfile: string;
}
export function loadDrawerState(): DrawerState {
  const j = getJson<Partial<DrawerState>>(KEYS.drawer, {});
  const out: DrawerState = {
    disabledProfiles: Array.isArray(j.disabledProfiles) ? j.disabledProfiles : [],
    cachedNs: Array.isArray(j.cachedNs) ? j.cachedNs : [],
    selectedNs: Array.isArray(j.selectedNs) ? j.selectedNs : [],
    selectedWf: (j.selectedWf && typeof j.selectedWf === 'object') ? j.selectedWf : {},
    nsColors: (j.nsColors && typeof j.nsColors === 'object') ? { ...j.nsColors } : {},
    lastProfile: typeof j.lastProfile === 'string' ? j.lastProfile : '',
  };
  // One-time merge of the legacy chrome-shim colour store (it won there).
  const shim = getJson<Record<string, string> | null>(KEYS.shimNsColors, null);
  if (shim && typeof shim === 'object') {
    Object.assign(out.nsColors, shim);
    try { ls()?.removeItem(KEYS.shimNsColors); } catch { /* ignore */ }
    saveDrawerState(out);
  }
  return out;
}
export function saveDrawerState(s: DrawerState): void { setJson(KEYS.drawer, s); }

// ── level palette ───────────────────────────────────────────────────
export interface PaletteStore { dark: LevelPalette; light: LevelPalette }
export function loadPalette(): PaletteStore {
  const v2 = getJson<Partial<PaletteStore> | null>(KEYS.paletteV2, null);
  if (v2 && typeof v2 === 'object') {
    return { dark: { ...PALETTE_DEFAULTS.dark, ...(v2.dark || {}) }, light: { ...PALETTE_DEFAULTS.light, ...(v2.light || {}) } };
  }
  const v1 = getJson<Partial<LevelPalette>>(KEYS.paletteV1, {});
  const out = { dark: { ...PALETTE_DEFAULTS.dark, ...v1 }, light: { ...PALETTE_DEFAULTS.light } };
  if (Object.keys(v1).length) setJson(KEYS.paletteV2, out);
  return out;
}
export function savePalette(p: PaletteStore): void { setJson(KEYS.paletteV2, p); }

// ── last session (bare-domain redirect) ─────────────────────────────
export function loadLastSession(): string | null {
  const s = getString(KEYS.lastSession);
  return s && /^[a-f0-9]{16,}$/.test(s) ? s : null;
}
export function saveLastSession(s: string): void { setString(KEYS.lastSession, s); }
