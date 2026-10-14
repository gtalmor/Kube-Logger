// JSON export of a trace (schema kube-logger-trace-export/v1), mirroring what
// the trace panel shows plus the raw lines, for sharing with a coworker/AI.

import type { LogLine } from './parse';
import type { FlowIndex } from './flow';
import { execLines, type LineSource } from './source';
import { barContext, filterTopLevelBars, summarizeByType, summarizeIdle, type Bar, type LabelFn, type Waterfall } from './waterfall';
import { buildTrace } from './trace';

export const EXPORT_SCHEMA = 'kube-logger-trace-export/v1';

interface ExportBar {
  node: string; title?: string; id?: string; state: string;
  startMs: number; durMs: number; lineIdx: number;
  selfMs: number; childMs: number;
  nestedFlows: { execId: string; name: string | null; totalMs: number; bars: ExportBar[] }[];
  inlineBars?: ExportBar[];
  dbCalls: { label: string; durMs: number; startLineIdx: number }[];
  httpCalls: { status: number; method: string; path: string; sizeB: number; lineIdx: number }[];
  gaps: { ms: number; afterLineIdx: number; nextLineIdx: number; nextMsg: string }[];
}

function enrichBar(src: LineSource, flow: FlowIndex, bar: Bar, minStart: number, reqId: string, parentExecId: string, labelOf: LabelFn, depth: number, childExecIds: Set<string>): ExportBar {
  const ctx = barContext(src, flow, bar, reqId, parentExecId, labelOf);
  const recurse = (wf: Waterfall, execId: string) => depth < 8 ? wf.bars.map(cb => enrichBar(src, flow, cb, wf.minStart, reqId, execId, labelOf, depth + 1, childExecIds)) : [];
  for (const nf of ctx.nestedFlows) childExecIds.add(nf.execId);
  return {
    node: bar.node, title: bar.title, id: bar.id, state: bar.state,
    startMs: bar.start - minStart, durMs: bar.dur, lineIdx: bar.lineId,
    selfMs: ctx.selfMs, childMs: ctx.childMs,
    nestedFlows: ctx.nestedFlows.map(nf => ({ execId: nf.execId, name: nf.name || null, totalMs: nf.waterfall.total, bars: recurse(nf.waterfall, nf.execId) })),
    ...(ctx.inline ? { inlineBars: recurse(ctx.inline, parentExecId) } : {}),
    dbCalls: ctx.dbCalls.map(d => ({ label: d.label, durMs: d.durMs, startLineIdx: d.startLineId })),
    httpCalls: ctx.httpCalls.map(h => ({ status: h.status, method: h.method, path: h.path, sizeB: h.sizeB, lineIdx: h.lineId })),
    gaps: ctx.gaps.map(g => ({ ms: g.ms, afterLineIdx: g.afterLineId, nextLineIdx: g.nextLineId, nextMsg: g.nextMsg })),
  };
}

function lineOut(l: LogLine) {
  return {
    idx: l.id, ts: l.ts !== undefined ? new Date(l.ts).toISOString() : l.tsText, ns: l.ns, pod: l.pod, container: l.container,
    level: l.level, type: l.kind, msg: l.msg, reqId: l.reqId, tenant: l.tenant,
    flowExecId: l.flowExecId, flowName: l.flowName, flowNode: l.flowNode,
    flowState: l.flowState, flowNext: l.flowNext, flowFailReason: l.flowFailReason,
    failNodeId: l.failNodeId, failNodeLabel: l.failNodeLabel,
    apiError: l.apiError, isFlowError: l.isFlowError,
    method: l.method, path: l.path, status: l.status,
    raw: l.raw,
  };
}

export function buildTraceExport(src: LineSource, flow: FlowIndex, reqId: string, labelOf: LabelFn, captureStart: number | null, now = () => new Date()) {
  const t = buildTrace(src, flow, reqId, labelOf);
  if (!t) return null;
  const childExecIds = new Set<string>();
  const flowsOut = t.flows.map(f => {
    const wf = f.waterfall;
    const nodes = f.events.map(e => ({ node: e.node, state: e.state, next: e.next, reason: e.reason, lineIdx: e.lineId, ts: e.ts !== undefined ? new Date(e.ts).toISOString() : undefined }));
    if (!wf) return { execId: f.execId, name: f.name, nodes, failures: f.failures.map(x => ({ nodeId: x.nodeId, label: x.label, lineIdx: x.lineId })), errors: f.errors.map(x => ({ msg: x.msg, lineIdx: x.lineId, level: x.level })), waterfall: null };
    const idle = summarizeIdle(wf.bars);
    return {
      execId: f.execId, name: f.name, nodes,
      failures: f.failures.map(x => ({ nodeId: x.nodeId, label: x.label, lineIdx: x.lineId })),
      errors: f.errors.map(x => ({ msg: x.msg, lineIdx: x.lineId, level: x.level })),
      waterfall: {
        totalMs: wf.total, activeMs: Math.max(0, wf.total - idle.totalMs), idleMs: idle.totalMs, idleGaps: idle.gaps,
        bars: filterTopLevelBars(wf.bars).map(b => enrichBar(src, flow, b, wf.minStart, reqId, f.execId, labelOf, 0, childExecIds)),
        typeSummary: summarizeByType(wf.bars).map(r => ({ name: r.name, count: r.count, meanMs: r.mean, maxMs: r.max, totalMs: r.total, titles: r.titles })),
      },
    };
  });

  const all = [...t.reqLines, ...t.relatedLines];
  const seen = new Set(all.map(l => l.id));
  const extra: LogLine[] = [];
  for (const e of childExecIds) for (const l of execLines(src, e)) if (!seen.has(l.id)) { seen.add(l.id); extra.push(l); }
  const finalLines = [...all, ...extra].sort((a, b) => ((a.ts ?? 0) - (b.ts ?? 0)) || (a.id - b.id));

  return {
    schema: EXPORT_SCHEMA,
    exportedAt: now().toISOString(),
    captureStart,
    reqId,
    flowExecIds: t.flows.map(f => f.execId),
    counts: { lines: finalLines.length, reqLines: t.reqLines.length, relatedLines: t.relatedLines.length, childExecLines: extra.length, flows: flowsOut.length },
    flows: flowsOut,
    lines: finalLines.map(lineOut),
  };
}
