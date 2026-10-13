import { describe, expect, it } from 'vitest';
import { FlowIndex } from './flow';
import { flowLines, jsonLine, nodeMsg, parseAll, sampleCapture } from './testutil';
import type { LogLine } from './parse';

// ── Legacy oracles (ported from viewer.js) ─────────────────────────
function legacyAnnotate(lines: LogLine[]): Map<number, string> {
  const out = new Map<number, string>();
  const nextByExec = new Map<string, string>();
  for (const l of lines) {
    if (!l.flowExecId || !l.flowState) continue;
    if (l.flowState === 'pre' || l.flowState === 'process') { const id = nextByExec.get(l.flowExecId); if (id) out.set(l.id, id); }
    if ((l.flowState === 'done' || l.flowState === 'post' || l.flowState === 'failed') && l.flowNext) nextByExec.set(l.flowExecId, l.flowNext);
  }
  return out;
}
function legacyDurations(lines: LogLine[]): Map<string, number> {
  const starts = new Map<string, number>(), ends = new Map<string, number>();
  for (const l of lines) {
    if (!l.flowExecId || !l.flowNode || !l.flowState || l.ts === undefined) continue;
    const key = l.flowExecId + '|' + l.flowNode;
    if (l.flowState === 'pre' || l.flowState === 'process') { const c = starts.get(key); if (c === undefined || l.ts < c) starts.set(key, l.ts); }
    else if (l.flowState === 'done' || l.flowState === 'post' || l.flowState === 'failed') { const c = ends.get(key); if (c === undefined || l.ts > c) ends.set(key, l.ts); }
  }
  const out = new Map<string, number>();
  for (const [k, e] of ends) { const s = starts.get(k); if (s === undefined) continue; const ms = e - s; if (ms >= 0) out.set(k, ms); }
  return out;
}

describe('FlowIndex', () => {
  it('matches the legacy duration oracle and node-id chaining', () => {
    const lines = parseAll(sampleCapture(600));
    const fi = new FlowIndex();
    for (const l of lines) fi.add(l);
    const ours = fi.durations();
    const theirs = legacyDurations(lines);
    expect(ours.size).toBe(theirs.size);
    for (const [k, ms] of theirs) expect(ours.get(k)?.ms).toBe(ms);

    const ann = legacyAnnotate(lines);
    for (const r of fi.execs.values()) for (const e of r.events) {
      if (e.state === 'pre' || e.state === 'process') expect(e.nodeId).toBe(ann.get(e.lineId));
    }
  });

  it('timeline groups chips per execution with durations and next labels', () => {
    const raws = [
      ...flowLines({ exec: 'e1', flow: 'login', reqId: 'r1', t0: 1000, nodes: [{ node: 'a', dur: 50, next: '#2' }, { node: 'b', dur: 10, fail: 'bad thing' }] }),
      jsonLine({ ts: 2000, reqId: 'r1', msg: 'Failure from node #2 (Check B)' }),
      ...flowLines({ exec: 'e2', flow: 'login', reqId: 'r2', t0: 3000, nodes: [{ node: 'a', dur: 70, next: '#2' }] }),
    ];
    const lines = parseAll(raws);
    const fi = new FlowIndex();
    for (const l of lines) fi.add(l);
    const { groups, earlier } = fi.timeline(20);
    expect(earlier).toBe(0);
    expect(groups.map(g => g.execId)).toEqual(['e1', 'e2']);
    const g1 = groups[0];
    expect(g1.name).toBe('login');
    // Node events first, then failure chips attached by request id ('#2').
    expect(g1.chips.map(c => c.node + ':' + c.state)).toEqual(['a:process', 'a:done', 'b:process', 'b:failed', '#2:failed']);
    expect(g1.chips[4].label).toBe('Check B');
    expect(g1.chips[0].durMs).toBe(50);
    expect(g1.chips[1].next).toBe('#2');
    expect(g1.chips[1].nextLabel).toBe('Check B');
    expect(g1.chips[3].label).toBe('bad thing');
    // Second execution of the same flow still gets its own chips (per-exec dedupe).
    expect(groups[1].chips.length).toBe(2);
    expect(fi.timeline(1).earlier).toBe(1);
    expect(fi.timeline(20, new Set(['e1'])).groups.map(g => g.execId)).toEqual(['e2']);
  });

  it('attaches orphan failures / script errors to the exec of the same request', () => {
    const raws = [
      ...flowLines({ exec: 'e1', flow: 'f', reqId: 'r1', t0: 0, nodes: [{ node: 'a', dur: 5, next: '77' }] }),
      jsonLine({ ts: 10, reqId: 'r1', msg: '"Failure" output of node 77 is not connected' }),
      'io-flow-engine-x flow-engine     TypeError: boom',
    ];
    const lines = parseAll(raws);
    const fi = new FlowIndex();
    for (const l of lines) fi.add(l);
    const { groups } = fi.timeline();
    expect(groups[0].chips.map(c => c.node)).toContain('a → FAIL');
    expect(groups[groups.length - 1].chips.some(c => c.node === 'script-executor')).toBe(true);
  });

  it('aggregate rolls up per node type', () => {
    const lines = parseAll(sampleCapture(300));
    const fi = new FlowIndex();
    for (const l of lines) fi.add(l);
    const rows = fi.aggregate();
    expect(rows.length).toBeGreaterThan(0);
    for (const r of rows) { expect(r.count).toBeGreaterThan(0); expect(r.max).toBeGreaterThanOrEqual(r.mean); expect(r.p95).toBeLessThanOrEqual(r.max); }
    expect(rows).toEqual([...rows].sort((a, b) => b.mean - a.mean));
  });

  it('evictBefore drops executions whose lines are gone and trims partial ones', () => {
    const lines = parseAll([
      ...flowLines({ exec: 'e1', flow: 'f', reqId: 'r1', t0: 0, nodes: [{ node: 'a', dur: 5 }] }),
      ...flowLines({ exec: 'e2', flow: 'f', reqId: 'r2', t0: 100, nodes: [{ node: 'a', dur: 5 }, { node: 'b', dur: 5 }] }),
    ]);
    const fi = new FlowIndex();
    for (const l of lines) fi.add(l);
    expect(fi.order).toEqual(['e1', 'e2']);
    const e2First = fi.execs.get('e2')!.firstId;
    fi.evictBefore(e2First + 2);   // all of e1 and the first two e2 events gone
    expect(fi.order).toEqual(['e2']);
    expect(fi.execs.get('e2')!.events.every(e => e.lineId >= e2First + 2)).toBe(true);
    fi.evictBefore(10_000);
    expect(fi.isEmpty).toBe(true);
  });

  it('execsInWindow and execForReq', () => {
    const lines = parseAll([
      ...flowLines({ exec: 'outer', flow: 'f', reqId: 'r1', t0: 0, nodes: [{ node: 'nested_flow', dur: 500 }] }),
      ...flowLines({ exec: 'inner', flow: 'g', reqId: 'r1', t0: 50, nodes: [{ node: 'x', dur: 100 }] }),
      ...flowLines({ exec: 'later', flow: 'g', reqId: 'r9', t0: 5000, nodes: [{ node: 'x', dur: 100 }] }),
    ]);
    const fi = new FlowIndex();
    for (const l of lines) fi.add(l);
    expect(fi.execsInWindow(0, 600, 'outer').map(r => r.execId)).toEqual(['inner']);
    expect(fi.execForReq('r1')?.execId).toBe('inner');
    expect(fi.execForReq('nope')).toBeUndefined();
    expect(fi.timeline().groups.find(g => g.execId === 'inner')!.chips[0].node).toBe('x');
    expect(parseAll([jsonLine({ ts: 1, msg: nodeMsg('e', 'f', 'n', 'weird') })])[0].flowState).toBeUndefined();
  });
});
