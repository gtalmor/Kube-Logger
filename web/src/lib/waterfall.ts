// Per-execution timing model: bars (node start→end), type summary, idle gaps,
// proxy-hop and authId re-entry detection, and the drill-down context for a
// bar (nested flows, inline children, DB pairs, HTTP calls, silence gaps).
// Ported from the legacy buildWaterfall/renderNodeDetail/buildBarContext but
// querying indices instead of scanning every line.

import type { FlowState, LogLine } from './parse';
import type { ExecRecord, FlowIndex, NodeEvent } from './flow';
import { httpLines, inWindow, reqLines, type LineSource } from './source';

export type LabelFn = (nodeId: string | undefined) => string | undefined;

export interface Bar {
  node: string;
  title?: string;
  id?: string;
  start: number;
  dur: number;
  lineId: number;
  state: FlowState;
}
export interface Waterfall { minStart: number; total: number; bars: Bar[] }

const START = new Set<FlowState>(['pre', 'process']);
const END = new Set<FlowState>(['done', 'post', 'failed']);

/** Match each start event with the next end event of the same node type. */
export function buildWaterfall(events: readonly NodeEvent[], labelOf: LabelFn): Waterfall | null {
  const sorted = events.filter(e => e.ts !== undefined).slice().sort((a, b) => (a.ts as number) - (b.ts as number));
  const open = new Map<string, NodeEvent>();
  const bars: Bar[] = [];
  for (const e of sorted) {
    const t = e.ts as number;
    if (START.has(e.state)) open.set(e.node, e);
    else if (END.has(e.state)) {
      const s = open.get(e.node);
      if (!s) continue;
      open.delete(e.node);
      bars.push({ node: e.node, title: labelOf(s.nodeId), id: s.nodeId, start: s.ts as number, dur: t - (s.ts as number), lineId: s.lineId, state: e.state });
    }
  }
  if (!bars.length) return null;
  bars.sort((a, b) => a.start - b.start);
  const minStart = bars[0].start;
  const maxEnd = bars.reduce((m, b) => Math.max(m, b.start + b.dur), minStart);
  return { minStart, total: maxEnd - minStart, bars };
}

export interface TypeSummaryRow { name: string; count: number; total: number; max: number; mean: number; titles: string[] }
export function summarizeByType(bars: readonly Bar[]): TypeSummaryRow[] {
  const m = new Map<string, { name: string; count: number; total: number; max: number; titles: Set<string> }>();
  for (const b of bars) {
    let r = m.get(b.node);
    if (!r) m.set(b.node, r = { name: b.node, count: 0, total: 0, max: 0, titles: new Set() });
    r.count++; r.total += b.dur; if (b.dur > r.max) r.max = b.dur; if (b.title) r.titles.add(b.title);
  }
  return [...m.values()].map(r => ({ ...r, titles: [...r.titles], mean: r.total / Math.max(1, r.count) })).sort((a, b) => b.total - a.total);
}

export interface IdleSummary { totalMs: number; gaps: { start: number; dur: number }[] }
/** Gaps > 500ms between consecutive bars: usually waiting on user input. */
export function summarizeIdle(bars: readonly Bar[]): IdleSummary {
  if (!bars || bars.length < 2) return { totalMs: 0, gaps: [] };
  const sorted = [...bars].sort((a, b) => a.start - b.start);
  const gaps: { start: number; dur: number }[] = [];
  let totalMs = 0;
  for (let i = 1; i < sorted.length; i++) {
    const prevEnd = sorted[i - 1].start + sorted[i - 1].dur;
    const gap = sorted[i].start - prevEnd;
    if (gap > 500) { gaps.push({ start: prevEnd, dur: gap }); totalMs += gap; }
  }
  return { totalMs, gaps };
}

/** Hide bars fully contained inside a nested_flow bar (they show as inline children). */
export function filterTopLevelBars(bars: readonly Bar[]): Bar[] {
  const nfBars = bars.filter(b => b.node === 'nested_flow');
  if (!nfBars.length) return [...bars];
  return bars.filter(b => {
    for (const nf of nfBars) {
      if (b === nf) continue;
      const bEnd = b.start + b.dur, nfEnd = nf.start + nf.dur;
      if (b.start >= nf.start - 5 && bEnd <= nfEnd + 5) return false;
    }
    return true;
  });
}

export interface ProxyHop { path: string; status: number | null; size: number; lineId: number | null }
/** An api_be bar whose window contains a POST /flow/execute/… — the authId/proxy hop. */
export function detectProxyHop(src: LineSource, bar: Bar): ProxyHop | null {
  if (!bar || bar.node !== 'api_be') return null;
  const titleHit = (bar.title || '').toLowerCase().includes('proxy');
  const startMs = bar.start, endMs = bar.start + bar.dur;
  for (const l of httpLines(src)) {
    if (!inWindow(l, startMs, endMs)) continue;
    if ((l.method || '').toUpperCase() === 'POST' && /\/flow\/execute\//.test(l.path || '')) {
      return { path: l.path || '', status: l.status ?? null, size: l.size || 0, lineId: l.id };
    }
  }
  return titleHit ? { path: '(no captured http line)', status: null, size: 0, lineId: null } : null;
}

export interface Reentry { childExecId: string; childTotal: number; taxMs: number }
/** A child exec of the same flow nested inside the outer's window = the re-entry tax. */
export function detectAuthIdReentry(outer: ExecRecord, outerWf: Waterfall, candidates: readonly ExecRecord[], labelOf: LabelFn): Reentry | null {
  if (!outer.name) return null;
  const oStart = outerWf.minStart, oEnd = oStart + outerWf.total;
  let best: { f: ExecRecord; cwf: Waterfall } | null = null;
  for (const f of candidates) {
    if (f === outer || f.execId === outer.execId || f.name !== outer.name) continue;
    const cwf = buildWaterfall(f.events, labelOf);
    if (!cwf) continue;
    const cStart = cwf.minStart, cEnd = cStart + cwf.total;
    if (cStart < oStart - 50 || cEnd > oEnd + 50) continue;
    if (!best || cwf.total > best.cwf.total) best = { f, cwf };
  }
  if (!best) return null;
  return { childExecId: best.f.execId, childTotal: best.cwf.total, taxMs: Math.max(0, outerWf.total - best.cwf.total) };
}

// ── Bar drill-down context ──────────────────────────────────────────
export interface NestedFlow { execId: string; name?: string; waterfall: Waterfall; events: NodeEvent[] }
export interface DbCall { label: string; durMs: number; startLineId: number }
export interface HttpCall { status: number; method: string; path: string; sizeB: number; lineId: number }
export interface Gap { ms: number; afterLineId: number; nextLineId: number; nextMsg: string }
export interface BarContext {
  selfMs: number;
  childMs: number;
  nestedFlows: NestedFlow[];
  /** For nested_flow bars: same-exec library nodes that ran inside this window. */
  inline: Waterfall | null;
  dbCalls: DbCall[];
  httpCalls: HttpCall[];
  gaps: Gap[];
  keyEvents: LogLine[];
}

const DB_RE = /^(.+?)(?:\s+(?:count|query|find|aggregate))?\s+(started|finished)$/;

export function barContext(src: LineSource, flow: FlowIndex, bar: Bar, reqId: string, parentExecId: string, labelOf: LabelFn): BarContext {
  const startMs = bar.start, endMs = bar.start + bar.dur;

  // Child flows: other execs with events inside this bar's window.
  const nestedFlows: NestedFlow[] = [];
  let childMs = 0;
  for (const r of flow.execsInWindow(startMs, endMs, parentExecId)) {
    const events = r.events.filter(e => e.ts !== undefined && e.ts >= startMs && e.ts <= endMs);
    if (!events.length) continue;
    const wf = buildWaterfall(events, labelOf);
    if (!wf) continue;
    childMs += wf.total;
    nestedFlows.push({ execId: r.execId, name: r.name, waterfall: wf, events });
  }

  let inline: Waterfall | null = null;
  if (bar.node === 'nested_flow') {
    const parent = flow.execs.get(parentExecId);
    if (parent) {
      const ev = parent.events.filter(e => e.lineId !== bar.lineId && e.ts !== undefined && e.ts >= startMs && e.ts <= endMs);
      if (ev.length) inline = buildWaterfall(ev, labelOf);
    }
  }

  const rl = reqLines(src, reqId).filter(l => inWindow(l, startMs, endMs));
  const hl = httpLines(src).filter(l => inWindow(l, startMs, endMs));

  const dbStarts = new Map<string, { ts: number; lineId: number }>();
  const dbCalls: DbCall[] = [];
  for (const l of rl) {
    const m = DB_RE.exec(l.msg || '');
    if (!m || l.ts === undefined) continue;
    if (m[2] === 'started') dbStarts.set(m[1], { ts: l.ts, lineId: l.id });
    else {
      const s = dbStarts.get(m[1]);
      if (!s) continue;
      dbStarts.delete(m[1]);
      const dur = l.ts - s.ts;
      if (dur >= 0) dbCalls.push({ label: m[1], durMs: dur, startLineId: s.lineId });
    }
  }
  dbCalls.sort((a, b) => b.durMs - a.durMs);

  const sortedTs = rl.filter(l => l.ts !== undefined).map(l => ({ t: l.ts as number, id: l.id, msg: (l.msg || l.raw || '').slice(0, 200) })).sort((a, b) => a.t - b.t);
  const gaps: Gap[] = [];
  for (let i = 1; i < sortedTs.length; i++) {
    const gap = sortedTs[i].t - sortedTs[i - 1].t;
    if (gap >= 200) gaps.push({ ms: gap, afterLineId: sortedTs[i - 1].id, nextLineId: sortedTs[i].id, nextMsg: sortedTs[i].msg });
  }
  gaps.sort((a, b) => b.ms - a.ms);

  const keyEvents = rl.filter(l => l.level === 'ERROR' || l.level === 'FATAL' || l.flowState || l.isFlowError || l.isErrorDetail);

  return {
    selfMs: Math.max(0, bar.dur - childMs), childMs, nestedFlows, inline, dbCalls,
    httpCalls: hl.map(l => ({ status: l.status || 0, method: l.method || '', path: l.path || '', sizeB: l.size || 0, lineId: l.id })),
    gaps, keyEvents,
  };
}
