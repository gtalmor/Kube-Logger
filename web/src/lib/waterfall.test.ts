import { describe, expect, it } from 'vitest';
import { FlowIndex } from './flow';
import { ArraySource } from './source';
import { barContext, buildWaterfall, detectAuthIdReentry, detectProxyHop, filterTopLevelBars, summarizeByType, summarizeIdle, type Bar } from './waterfall';
import { buildTrace, failureContext } from './trace';
import { buildTraceExport, EXPORT_SCHEMA } from './trace-export';
import { flowLines, httpLine, jsonLine, parseAll } from './testutil';

const labelOf = (id: string | undefined) => (id === '#2' ? 'Check Two' : undefined);

// Times are on whole-second boundaries where HTTP lines are involved: CLF
// access-log timestamps only carry second precision.
const T0 = 100_000;
function build() {
  const raws = [
    httpLine({ ts: T0 - 1000, path: '/flow/execute/login', status: 200 }),
    ...flowLines({ exec: 'outer', flow: 'login', reqId: 'r1', t0: T0, nodes: [
      { node: 'script_be_v2', dur: 1000, next: '#2' },
      { node: 'api_be', dur: 4000, next: '#3' },            // window ≈ [101010, 105010]: proxy hop inside
      { node: 'nested_flow', dur: 3000, next: '#4' },
      { node: 'condition', dur: 200, gapBefore: 9000 },     // idle gap before
    ] }),
    httpLine({ ts: 103_000, path: '/flow/execute/login', status: 200 }),   // POST during api_be → hop
    ...flowLines({ exec: 'inner', flow: 'login', reqId: 'r2', t0: 103_100, nodes: [{ node: 'script_be_v2', dur: 1500 }] }),   // same flow, nested → reentry
    jsonLine({ ts: 103_200, reqId: 'r1', level: 'debug', msg: 'MongoDBSessionRepository count started' }),
    jsonLine({ ts: 103_600, reqId: 'r1', level: 'debug', msg: 'MongoDBSessionRepository count finished' }),
    jsonLine({ ts: 104_000, reqId: 'r1', level: 'error', msg: 'Error occurred: AxiosError: Request failed with status code 502' }),
    jsonLine({ ts: 104_100, reqId: 'r1', msg: 'Failure from node #3 (Call API)' }),
  ];
  const lines = parseAll(raws);
  const fi = new FlowIndex();
  for (const l of lines) fi.add(l);
  return { lines, fi, src: new ArraySource(lines) };
}

describe('waterfall', () => {
  it('builds bars from matched start/end events with titles', () => {
    const { fi } = build();
    const wf = buildWaterfall(fi.execs.get('outer')!.events, labelOf)!;
    expect(wf.bars.map(b => b.node)).toEqual(['script_be_v2', 'api_be', 'nested_flow', 'condition']);
    expect(wf.bars[0].dur).toBe(1000);
    expect(wf.bars[1].id).toBe('#2');
    expect(wf.bars[1].title).toBe('Check Two');
    expect(wf.minStart).toBe(T0 + 5);
    expect(wf.total).toBe(wf.bars[3].start + 200 - (T0 + 5));
    expect(buildWaterfall([], labelOf)).toBeNull();
  });

  it('summaries, idle and top-level filtering', () => {
    const bars: Bar[] = [
      { node: 'nested_flow', start: 0, dur: 100, lineId: 1, state: 'done' },
      { node: 'a', start: 10, dur: 20, lineId: 2, state: 'done', title: 'A1' },
      { node: 'a', start: 50, dur: 30, lineId: 3, state: 'done' },
      { node: 'b', start: 800, dur: 5, lineId: 4, state: 'failed' },
    ];
    expect(filterTopLevelBars(bars).map(b => b.lineId)).toEqual([1, 4]);
    const ts = summarizeByType(bars);
    expect(ts[0].name).toBe('nested_flow');
    expect(ts.find(r => r.name === 'a')).toMatchObject({ count: 2, total: 50, max: 30, mean: 25, titles: ['A1'] });
    const idle = summarizeIdle(bars);
    expect(idle.gaps.length).toBe(1);
    expect(idle.totalMs).toBe(800 - 80);   // gap after the last bar by start order (a @50..80)
    expect(summarizeIdle([bars[0]]).totalMs).toBe(0);
  });

  it('detects proxy hops and authId re-entry', () => {
    const { fi, src } = build();
    const outer = fi.execs.get('outer')!;
    const wf = buildWaterfall(outer.events, labelOf)!;
    const api = wf.bars.find(b => b.node === 'api_be')!;
    const hop = detectProxyHop(src, api);
    expect(hop?.path).toBe('/flow/execute/login');
    expect(detectProxyHop(src, wf.bars[0])).toBeNull();
    expect(detectProxyHop(src, { ...api, start: 5, dur: 1, title: 'Proxy call' })?.path).toContain('no captured');
    const re = detectAuthIdReentry(outer, wf, [outer, fi.execs.get('inner')!], labelOf);
    expect(re?.childExecId).toBe('inner');
    expect(re?.childTotal).toBe(1500);
    expect(re?.taxMs).toBe(wf.total - 1500);
  });

  it('barContext finds nested flows, db pairs, http calls, gaps and key events', () => {
    const { fi, src } = build();
    const outer = fi.execs.get('outer')!;
    const wf = buildWaterfall(outer.events, labelOf)!;
    const api = wf.bars.find(b => b.node === 'api_be')!;
    const ctx = barContext(src, fi, api, 'r1', 'outer', labelOf);
    expect(ctx.nestedFlows.map(n => n.execId)).toEqual(['inner']);
    expect(ctx.childMs).toBe(1500);
    expect(ctx.selfMs).toBe(4000 - 1500);
    expect(ctx.dbCalls).toEqual([{ label: 'MongoDBSessionRepository', durMs: 400, startLineId: expect.any(Number) }]);
    expect(ctx.httpCalls.length).toBe(1);
    expect(ctx.keyEvents.some(l => l.apiError)).toBe(true);
    expect(ctx.inline).toBeNull();
  });
});

describe('trace', () => {
  it('builds the trace model for a request', () => {
    const { fi, src } = build();
    const t = buildTrace(src, fi, 'r1', labelOf)!;
    expect(t.flows.map(f => f.execId)).toEqual(['outer']);
    const f = t.flows[0];
    expect(f.waterfall?.bars.length).toBe(4);
    expect(f.idle.totalMs).toBeGreaterThan(500);
    expect(f.activeMs).toBe(f.waterfall!.total - f.idle.totalMs);
    expect(f.rows.map(r => r.bar.node)).toEqual(['script_be_v2', 'api_be', 'nested_flow', 'condition']);
    expect(f.rows[1].hop).not.toBeNull();
    expect(f.rows[3].gapBefore).toBeGreaterThan(500);
    expect(f.failures.map(x => x.nodeId)).toEqual(['#3']);
    expect(f.errors.length).toBe(1);
    expect(f.path.map(p => p.node)).toEqual(['script_be_v2', 'api_be', 'nested_flow', 'condition']);
    expect(f.path[0].states).toEqual(['process', 'done']);
    expect(f.path[1].label).toBe('Call API');   // next '#3' → failure label
    expect(t.http.length).toBe(2);
    expect(t.keyEvents.length).toBeLessThan(t.reqLines.length);
    expect(buildTrace(src, fi, 'nope', labelOf)).toBeNull();
    const fc = failureContext(src, src.get(src.byReq('r1').at(-1)!)!);
    expect(fc.flowName).toBe('login');
    expect(fc.flowExecId).toBe('outer');
    expect(fc.nestingDepth).toBe(1);
    expect(fc.calledFrom?.node).toBe('api_be');
    expect(fc.pathBefore.length).toBeGreaterThan(0);
  });

  it('exports schema v1 with enriched bars and all related lines', () => {
    const { fi, src } = build();
    const e = buildTraceExport(src, fi, 'r1', labelOf, 123, () => new Date(0))!;
    expect(e.schema).toBe(EXPORT_SCHEMA);
    expect(e.exportedAt).toBe('1970-01-01T00:00:00.000Z');
    expect(e.captureStart).toBe(123);
    expect(e.flowExecIds).toEqual(['outer']);
    const wf = e.flows[0].waterfall!;
    expect(wf.bars.length).toBe(4);
    const api = wf.bars[1];
    expect(api.nestedFlows[0].execId).toBe('inner');
    expect(api.nestedFlows[0].bars[0].node).toBe('script_be_v2');
    expect(api.dbCalls.length).toBe(1);
    expect(api.httpCalls.length).toBe(1);
    expect(wf.typeSummary[0]).toHaveProperty('meanMs');
    // Lines from the nested exec (r2) are pulled in even though the pivot is r1.
    expect(e.lines.some(l => l.reqId === 'r2')).toBe(true);
    expect(e.counts.childExecLines).toBeGreaterThan(0);
    expect(e.lines[0]).toHaveProperty('raw');
    expect(e.lines[0]).not.toHaveProperty('json');
    expect(JSON.parse(JSON.stringify(e)).counts.lines).toBe(e.lines.length);
  });
});
