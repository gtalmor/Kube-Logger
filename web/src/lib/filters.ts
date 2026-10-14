// Filter model: tri-state include/exclude maps, regex search, hidden
// patterns, hidden flow executions. Compiles the current filter state into a
// predicate once so per-line evaluation is cheap.

import { isMultilineMember, type LogLine } from './parse';

export type TriState = 'include' | 'exclude';
export type TriFilter = Record<string, TriState>;

export interface FilterState {
  search: string;
  level: TriFilter;
  pod: TriFilter;
  req: TriFilter;
  tenant: TriFilter;
  hideTrace: boolean;
  hiddenPatterns: string[];
  hiddenExecIds: string[];
  highlights: string[];
}

export function emptyFilters(): FilterState {
  return { search: '', level: {}, pod: {}, req: {}, tenant: {}, hideTrace: false, hiddenPatterns: [], hiddenExecIds: [], highlights: [] };
}

// ── tri-state helpers ───────────────────────────────────────────────
/** Empty map → everything passes. Any include flips to whitelist mode. */
export function triPass(filter: TriFilter | undefined, value: string | undefined): boolean {
  if (!filter) return true;
  const keys = Object.keys(filter);
  if (!keys.length) return true;
  const state = value === undefined ? undefined : filter[value];
  const hasIncludes = keys.some(k => filter[k] === 'include');
  if (hasIncludes) return state === 'include';
  return state !== 'exclude';
}
/** none → include → exclude → none. Returns a new object. */
export function triCycle(filter: TriFilter, value: string): TriFilter {
  const next = { ...filter };
  const s = next[value];
  if (!s) next[value] = 'include';
  else if (s === 'include') next[value] = 'exclude';
  else delete next[value];
  return next;
}
export function triHasAny(filter: TriFilter | undefined): boolean {
  return Object.keys(filter || {}).length > 0;
}
export function triSummary(filter: TriFilter | undefined, baseLabel: string): string {
  const vals = Object.values(filter || {});
  const incs = vals.filter(v => v === 'include').length;
  const exs = vals.filter(v => v === 'exclude').length;
  if (!incs && !exs) return `All ${baseLabel}`;
  const bits: string[] = [];
  if (incs) bits.push(`+${incs}`);
  if (exs) bits.push(`−${exs}`);
  return `${baseLabel} (${bits.join(' ')})`;
}
/** Older presets stored { level: 'all' | 'ERROR' }; migrate to tri-state. */
export function migrateFilterField(v: unknown): TriFilter {
  if (v && typeof v === 'object') return { ...(v as TriFilter) };
  if (!v || v === 'all') return {};
  return { [String(v)]: 'include' };
}
export function activeConstraintCount(f: FilterState): number {
  return (f.search ? 1 : 0) + (f.hideTrace ? 1 : 0)
    + Object.keys(f.level).length + Object.keys(f.pod).length + Object.keys(f.req).length + Object.keys(f.tenant || {}).length
    + f.hiddenPatterns.length + f.hiddenExecIds.length;
}

// ── compiled predicate ──────────────────────────────────────────────
interface CompiledTri { mode: 'none' | 'include' | 'exclude'; set: Set<string> }
function compileTri(f: TriFilter): CompiledTri {
  const keys = Object.keys(f);
  if (!keys.length) return { mode: 'none', set: new Set() };
  const incs = keys.filter(k => f[k] === 'include');
  if (incs.length) return { mode: 'include', set: new Set(incs) };
  return { mode: 'exclude', set: new Set(keys.filter(k => f[k] === 'exclude')) };
}
function triOk(c: CompiledTri, v: string | undefined): boolean {
  if (c.mode === 'none') return true;
  if (c.mode === 'include') return v !== undefined && c.set.has(v);
  return v === undefined || !c.set.has(v);
}

export interface SearchMatcher { re: RegExp | null; lower: string; valid: boolean }
export function compileSearch(search: string): SearchMatcher {
  const s = search.trim();
  if (!s) return { re: null, lower: '', valid: true };
  try { return { re: new RegExp(s, 'i'), lower: s.toLowerCase(), valid: true }; }
  catch { return { re: null, lower: s.toLowerCase(), valid: false }; }
}

export interface Predicate {
  /** Full filter: hidden patterns, hidden execs, tri-state, trace, search. */
  full(l: LogLine, hiddenReqIds: ReadonlySet<string>): boolean;
  /** Relaxed check used to keep multi-line context around a shown line. */
  continuation(l: LogLine, hiddenReqIds: ReadonlySet<string>): boolean;
  readonly search: SearchMatcher;
  readonly hasSearch: boolean;
  /** True when a tenant constraint is active (the store re-evaluates after late attribution). */
  readonly usesTenant: boolean;
}

export function compilePredicate(f: FilterState): Predicate {
  const level = compileTri(f.level), pod = compileTri(f.pod), req = compileTri(f.req), tenant = compileTri(f.tenant || {});
  const hidden = f.hiddenPatterns.map(p => p.toLowerCase()).filter(Boolean);
  const hiddenExecs = new Set(f.hiddenExecIds);
  const search = compileSearch(f.search);
  const hideTrace = f.hideTrace;

  const hiddenByPattern = (l: LogLine): boolean => {
    if (!hidden.length) return false;
    const t = (l.msg || l.raw).toLowerCase();
    for (const p of hidden) if (t.includes(p)) return true;
    return false;
  };
  const hiddenByExec = (l: LogLine, hiddenReqIds: ReadonlySet<string>): boolean => {
    if (!hiddenExecs.size) return false;
    if (l.flowExecId && hiddenExecs.has(l.flowExecId)) return true;
    return !!(l.reqId && hiddenReqIds.has(l.reqId));
  };
  const matchesSearch = (l: LogLine): boolean => {
    if (!search.lower) return true;
    const text = l.raw || l.msg || '';
    if (search.re) return search.re.test(text);
    return text.toLowerCase().includes(search.lower);
  };

  return {
    search,
    hasSearch: !!search.lower,
    usesTenant: tenant.mode !== 'none',
    full(l, hiddenReqIds) {
      if (hiddenByPattern(l)) return false;
      if (hiddenByExec(l, hiddenReqIds)) return false;
      if (!triOk(level, l.level)) return false;
      if (hideTrace && l.level === 'TRACE') return false;
      if (!triOk(pod, l.pod)) return false;
      if (!triOk(req, l.reqId)) return false;
      if (!triOk(tenant, l.tenant)) return false;
      return matchesSearch(l);
    },
    continuation(l, hiddenReqIds) {
      if (hiddenByPattern(l)) return false;
      if (hiddenByExec(l, hiddenReqIds)) return false;
      return triOk(pod, l.pod);
    },
  };
}

/**
 * Incremental decision for a newly appended line (port of the legacy
 * appendLive): show if it passes, or if it continues a multi-line group whose
 * previous line (id-1) is the current tail of the view.
 */
export function appendDecision(l: LogLine, viewTail: LogLine | undefined, pred: Predicate, hiddenReqIds: ReadonlySet<string>): boolean {
  if (pred.full(l, hiddenReqIds)) return true;
  if (!isMultilineMember(l) || !viewTail || viewTail.id !== l.id - 1) return false;
  if (!isMultilineMember(viewTail) || viewTail.pod !== l.pod) return false;
  return pred.continuation(l, hiddenReqIds);
}

/**
 * Full recompute (port of rebuildFiltered): first pass marks lines that pass,
 * second pass sweeps contiguous same-pod multi-line neighbours in both
 * directions so a matched stack-trace line keeps its context.
 */
export function recomputeView(lines: readonly LogLine[], pred: Predicate, hiddenReqIds: ReadonlySet<string>): number[] {
  const n = lines.length;
  const included = new Uint8Array(n);
  for (let i = 0; i < n; i++) if (pred.full(lines[i], hiddenReqIds)) included[i] = 1;
  for (let i = 0; i < n; i++) {
    if (!included[i]) continue;
    const l = lines[i];
    if (!isMultilineMember(l)) continue;
    for (let j = i - 1; j >= 0; j--) {
      const pl = lines[j];
      if (!isMultilineMember(pl) || pl.pod !== l.pod) break;
      if (included[j]) break;
      if (!pred.continuation(pl, hiddenReqIds)) break;
      included[j] = 1;
    }
    for (let j = i + 1; j < n; j++) {
      const nl = lines[j];
      if (!isMultilineMember(nl) || nl.pod !== l.pod) break;
      if (included[j]) continue;
      if (!pred.continuation(nl, hiddenReqIds)) break;
      included[j] = 1;
    }
  }
  const out: number[] = [];
  for (let i = 0; i < n; i++) if (included[i]) out.push(lines[i].id);
  return out;
}

/** Heuristic pattern for "hide messages like this" (port of extractPattern). */
export function extractPattern(l: LogLine): string {
  const msg = l.msg || l.raw || '';
  const hp = /Health "(\w+)" probe request received/.exec(msg);
  if (hp) return 'Health "' + hp[1] + '" probe request received';
  const db = /(MongoDB\w+Repository)[\s\S]*?(count started|count finished|query started|query finished)/.exec(msg);
  if (db) return db[1] + ': ' + db[2];
  const fn = /Node\s+(\S+)\s+is\s+in\s+(\w+)\s+state/.exec(msg);
  if (fn) return 'Node ' + fn[1] + ' is in ' + fn[2] + ' state';
  if (msg.includes('ExperimentalWarning')) return 'ExperimentalWarning';
  if (msg.includes('node --trace-warnings')) return 'node --trace-warnings';
  return msg.slice(0, 80).trim();
}
