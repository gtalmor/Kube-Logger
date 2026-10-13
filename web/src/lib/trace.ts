// Trace model for one request id (port of the data half of openTrace).

import type { LogLine } from './parse';
import type { ExecRecord, FlowIndex, NodeEvent } from './flow';
import { execLines, httpLines, reqLines, type LineSource } from './source';
import {
  buildWaterfall, detectAuthIdReentry, detectProxyHop, filterTopLevelBars, summarizeByType, summarizeIdle,
  type Bar, type LabelFn, type ProxyHop, type Reentry, type TypeSummaryRow, type Waterfall, type IdleSummary,
} from './waterfall';

export interface TraceFailure { nodeId: string; label: string; lineId: number }
export interface TraceError { msg: string; lineId: number; level: string }
export interface PathNode { node: string; states: string[]; next?: string; reason?: string; lineId: number; lastLineId: number; label?: string }
export interface TraceFlow {
  execId: string;
  name?: string;
  record: ExecRecord;
  events: NodeEvent[];
  failures: TraceFailure[];
  errors: TraceError[];
  waterfall: Waterfall | null;
  idle: IdleSummary;
  activeMs: number;
  reentry: Reentry | null;
  typeSummary: TypeSummaryRow[];
  /** Top-level bars with proxy-hop annotation, in start order. */
  rows: { bar: Bar; hop: ProxyHop | null; gapBefore: number }[];
  path: PathNode[];
}
export interface TraceModel {
  reqId: string;
  reqLines: LogLine[];
  relatedLines: LogLine[];
  flows: TraceFlow[];
  http: LogLine[];
  keyEvents: LogLine[];
  nodeLabels: Map<string, string>;
}

/** Merge process→done pairs into one path entry per node, first-appearance order. */
export function buildFlowPath(events: readonly NodeEvent[], labels: Map<string, string>): PathNode[] {
  const nodeStates = new Map<string, PathNode>();
  for (const n of events) {
    let e = nodeStates.get(n.node);
    if (!e) nodeStates.set(n.node, e = { node: n.node, states: [], next: undefined, reason: n.reason, lineId: n.lineId, lastLineId: n.lineId });
    if (!e.states.includes(n.state)) e.states.push(n.state);
    if (n.next) e.next = n.next;
    if (n.reason) e.reason = n.reason;
    e.lastLineId = n.lineId;
  }
  const out: PathNode[] = [];
  const seen = new Set<string>();
  for (const n of events) {
    if (seen.has(n.node)) continue;
    seen.add(n.node);
    const e = nodeStates.get(n.node) as PathNode;
    e.label = e.next ? labels.get(e.next) : undefined;
    out.push(e);
  }
  return out;
}

const byTs = (a: LogLine, b: LogLine) => ((a.ts ?? 0) - (b.ts ?? 0)) || (a.id - b.id);

export function buildTrace(src: LineSource, flow: FlowIndex, reqId: string, labelOf: LabelFn): TraceModel | null {
  const rl = reqLines(src, reqId);
  if (!rl.length) return null;

  const nodeLabels = new Map<string, string>();
  for (const l of rl) {
    if (l.failNodeId && l.failNodeLabel) nodeLabels.set(l.failNodeId, l.failNodeLabel);
    if (l.flowFailReason && l.flowNode) nodeLabels.set(l.flowNode, l.flowFailReason);
  }
  const execIds: string[] = [];
  for (const l of rl) if (l.flowExecId && !execIds.includes(l.flowExecId)) execIds.push(l.flowExecId);
  const related: LogLine[] = [];
  for (const e of execIds) {
    for (const l of execLines(src, e)) {
      if (l.reqId === reqId) continue;
      related.push(l);
      if (l.failNodeId && l.failNodeLabel) nodeLabels.set(l.failNodeId, l.failNodeLabel);
    }
  }
  const all = [...rl, ...related].sort(byTs);

  // Group by exec in first-appearance order; failures/errors attach to the
  // most recently created flow (legacy behaviour).
  const flows: TraceFlow[] = [];
  const byExec = new Map<string, TraceFlow>();
  for (const l of all) {
    if (l.flowExecId) {
      let f = byExec.get(l.flowExecId);
      if (!f) {
        const record = flow.execs.get(l.flowExecId) || { execId: l.flowExecId, name: l.flowName, events: [], reqIds: new Set<string>(), firstId: l.id, lastId: l.id, lineCount: 0, chips: [] };
        f = { execId: l.flowExecId, name: record.name || l.flowName, record, events: record.events, failures: [], errors: [], waterfall: null, idle: { totalMs: 0, gaps: [] }, activeMs: 0, reentry: null, typeSummary: [], rows: [], path: [] };
        byExec.set(l.flowExecId, f);
        flows.push(f);
      }
      if (!f.name && l.flowName) f.name = l.flowName;
    }
    const last = flows[flows.length - 1];
    if (l.failNodeId && last) last.failures.push({ nodeId: l.failNodeId, label: l.failNodeLabel || '', lineId: l.id });
    if ((l.apiError || l.isFlowError) && last) last.errors.push({ msg: l.apiError || l.msg || '', lineId: l.id, level: l.level });
  }

  const records = flows.map(f => f.record);
  for (const f of flows) {
    f.waterfall = buildWaterfall(f.events, labelOf);
    if (f.waterfall) {
      f.idle = summarizeIdle(f.waterfall.bars);
      f.activeMs = Math.max(0, f.waterfall.total - f.idle.totalMs);
      f.reentry = detectAuthIdReentry(f.record, f.waterfall, records, labelOf);
      f.typeSummary = summarizeByType(f.waterfall.bars);
      const top = filterTopLevelBars([...f.waterfall.bars].sort((a, b) => a.start - b.start));
      f.rows = top.map((bar, i) => {
        const prev = i > 0 ? top[i - 1] : null;
        const gapBefore = prev ? bar.start - (prev.start + prev.dur) : 0;
        return { bar, hop: detectProxyHop(src, bar), gapBefore };
      });
    }
    f.path = buildFlowPath(f.events, nodeLabels);
  }

  const flowNames = new Set(flows.map(f => f.name).filter(Boolean));
  const http = httpLines(src).filter(l => l.flowName && flowNames.has(l.flowName));

  const keyEvents = rl.filter(l => l.level !== 'TRACE' && !(l.msg || '').includes('Health')
    && !(l.msg || '').includes('count started') && !(l.msg || '').includes('count finished')
    && !(l.msg || '').includes('query started') && !(l.msg || '').includes('query finished'));

  return { reqId, reqLines: rl, relatedLines: related, flows, http, keyEvents, nodeLabels };
}

/** Lines sharing a reqId that have flow context, for the failure popover. */
export interface FailureContext {
  flowName?: string;
  flowExecId?: string;
  nestingDepth: number;
  calledFrom?: { node: string; state: string };
  pathBefore: { node: string; state: string }[];
}
export function failureContext(src: LineSource, l: LogLine): FailureContext {
  const out: FailureContext = { nestingDepth: 0, pathBefore: [] };
  if (!l.reqId) return out;
  const seen = new Set<string>();
  for (const ol of reqLines(src, l.reqId)) {
    if (ol.flowName && !out.flowName) out.flowName = ol.flowName;
    if (ol.flowExecId && !out.flowExecId) out.flowExecId = ol.flowExecId;
    if (ol.flowNode && ol.id <= l.id) {
      const k = ol.flowNode + '-' + ol.flowState;
      if (!seen.has(k)) { seen.add(k); out.pathBefore.push({ node: ol.flowNode, state: ol.flowState || '' }); }
      if (ol.flowNode === 'nested_flow' && ol.flowState === 'process') out.nestingDepth++;
    }
    if (l.failNodeId && !out.calledFrom && ol.flowNext === l.failNodeId && ol.id < l.id) out.calledFrom = { node: ol.flowNode || '', state: ol.flowState || '' };
  }
  return out;
}
