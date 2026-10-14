import { describe, expect, it } from 'vitest';
import { LogStore } from './store';
import { compilePredicate, emptyFilters, recomputeView } from '../lib/filters';
import { jsonLine, parseAll, sampleCapture } from '../lib/testutil';
import type { LogLine } from '../lib/parse';

const pred = compilePredicate(emptyFilters());
const mk = (cap: number, p = pred) => new LogStore(cap, p, { schedule: cb => cb() });

// Brute-force expectations from the current ring contents.
function brute(s: LogStore) {
  const lines = s.lines();
  const pods = new Map<string, number>(), ns = new Map<string, number>(), req = new Map<string, number>();
  const byReq = new Map<string, number[]>(), byExec = new Map<string, number[]>();
  const http: number[] = [];
  for (const l of lines) {
    if (l.pod) pods.set(l.pod, (pods.get(l.pod) || 0) + 1);
    if (l.ns) ns.set(l.ns, (ns.get(l.ns) || 0) + 1);
    if (l.reqId) { req.set(l.reqId, (req.get(l.reqId) || 0) + 1); byReq.set(l.reqId, [...(byReq.get(l.reqId) || []), l.id]); }
    if (l.flowExecId) byExec.set(l.flowExecId, [...(byExec.get(l.flowExecId) || []), l.id]);
    if (l.kind === 'http') http.push(l.id);
  }
  return { lines, pods, ns, req, byReq, byExec, http };
}
function check(s: LogStore) {
  const b = brute(s);
  expect([...s.podCounts.entries()].sort()).toEqual([...b.pods.entries()].sort());
  expect([...s.nsCounts.entries()].sort()).toEqual([...b.ns.entries()].sort());
  expect([...s.reqCounts.entries()].sort()).toEqual([...b.req.entries()].sort());
  for (const [r, ids] of b.byReq) expect([...s.byReq(r)]).toEqual(ids);
  for (const [e, ids] of b.byExec) expect([...s.byExec(e)]).toEqual(ids);
  expect([...s.execIds()].sort()).toEqual([...b.byExec.keys()].sort());
  expect([...s.httpIds()]).toEqual(b.http);
  // view == full recompute
  const view = recomputeView(b.lines, pred, s.hiddenReqIds);
  expect(s.ids).toEqual(view);
  const c = { total: 0, err: 0, warn: 0, dbg: 0, trc: 0, http: 0 };
  const errs: number[] = [];
  for (const id of view) {
    const l = s.get(id) as LogLine;
    c.total++;
    if (l.level === 'ERROR' || l.level === 'FATAL') c.err++; else if (l.level === 'WARN') c.warn++; else if (l.level === 'DEBUG') c.dbg++; else if (l.level === 'TRACE') c.trc++;
    if (l.kind === 'http') c.http++;
    if (l.isErr) errs.push(id);
  }
  expect(s.counts).toEqual(c);
  expect(s.errIds).toEqual(errs);
  for (const e of s.flow.order) expect(s.flow.execs.get(e)!.lastId).toBeGreaterThanOrEqual(s.ring.firstId);
}

describe('LogStore', () => {
  const raws = sampleCapture(900);

  it('ingests in batches and keeps indices/view consistent (no eviction)', () => {
    const s = mk(10_000);
    for (let k = 0; k < raws.length; k += 37) s.ingest(raws.slice(k, k + 37).map((line, j) => ({ i: k + j, ns: 'ns', line })));
    expect(s.size).toBe(parseAll(raws).length);
    expect(s.dataVersion.value).toBeGreaterThan(0);
    check(s);
  });

  it('evicts and stays consistent with a small cap, including after a filter change', () => {
    const s = mk(150);
    for (let k = 0; k < raws.length; k += 50) {
      s.ingest(raws.slice(k, k + 50).map((line, j) => ({ i: k + j, ns: 'ns', line })));
      check(s);
    }
    expect(s.size).toBe(150);
    expect(s.usage.value.evicted).toBeGreaterThan(0);
    s.setPredicate(compilePredicate({ ...emptyFilters(), level: { ERROR: 'include' } }), []);
    // Every visible line is an ERROR or a same-pod multi-line neighbour kept for context.
    expect(s.ids.every(id => { const l = s.get(id)!; return l.level === 'ERROR' || l.kind === 'plain' || l.kind === 'script-error'; })).toBe(true);
    expect(s.ids.some(id => s.get(id)!.level === 'ERROR')).toBe(true);
    s.setPredicate(pred, []);
    check(s);
    s.setCapacity(60);
    expect(s.size).toBe(60);
    check(s);
    s.setCapacity(500);
    s.ingest(raws.slice(0, 100).map((line, j) => ({ i: 5000 + j, ns: 'ns', line })));
    check(s);
  });

  it('dedupes replays by agent index and resets per capture epoch', () => {
    const s = mk(1000);
    s.resetForCapture('cap1', 1, ['ns']);
    const batch = raws.slice(0, 20).map((line, j) => ({ i: j, ns: 'ns', line }));
    s.ingest(batch);
    const n = s.size;
    s.ingest(batch);                              // replay → ignored
    expect(s.size).toBe(n);
    s.ingest(raws.slice(20, 30).map((line, j) => ({ i: 20 + j, ns: 'ns', line })));
    expect(s.size).toBeGreaterThan(n);
    expect(s.resetForCapture('cap1', 1, ['ns'])).toBe(false);   // same epoch keeps data
    expect(s.size).toBeGreaterThan(n);
    expect(s.resetForCapture('cap2', 2, ['ns', 'other'])).toBe(true);
    expect(s.size).toBe(0);
    expect(s.nsCapturing.has('other')).toBe(true);
    s.ingest(batch);                              // indices restart after reset
    expect(s.size).toBe(n);
    s.ingest(raws.slice(0, 5).map(line => ({ line })), { dedupe: false });   // file load, no i
    expect(s.size).toBeGreaterThan(n);
  });

  it('hidden exec ids propagate to request ids incrementally', () => {
    const s = mk(1000);
    s.ingest(raws.slice(0, 40).map((line, j) => ({ i: j, ns: 'ns', line })));
    const exec = s.flow.order[0];
    const req = [...s.flow.execs.get(exec)!.reqIds][0];
    s.setPredicate(compilePredicate({ ...emptyFilters(), hiddenExecIds: [exec] }), [exec]);
    expect(s.hiddenReqIds.has(req)).toBe(true);
    expect(s.ids.some(id => s.get(id)!.reqId === req)).toBe(false);
    // A later line of the same request is also hidden.
    const jsonRaw = raws.find(r => r.includes('"req_id"'))!;
    s.ingest([{ i: 99, ns: 'ns', line: jsonRaw.replace(/req-\d{4}-ab12cd34/, req) }]);
    expect(s.ids.some(id => s.get(id)!.reqId === req)).toBe(false);
    expect(s.locate(s.ring.lastId)).toBe('filtered');
    expect(s.locate(-5)).toBe('evicted');
    expect(s.locate(s.ids[0])).toBe('ok');
    expect(s.viewIndexOf(s.ids[3])).toBe(3);
  });
});

describe('tenant attribution', () => {
  const TA = 'a5ad1f2e-7c3b-4d1e-9f00-0123456789ab';
  it('inherits the tenant of a request id, forwards and backwards, with counts', () => {
    const s = mk(1000);
    s.ingest([
      { i: 0, ns: 'ns', line: jsonLine({ ts: 1, reqId: 'R', msg: 'no tenant yet' }) },
      { i: 1, ns: 'ns', line: jsonLine({ ts: 2, reqId: 'R', domain: TA, msg: 'has tenant' }) },
      { i: 2, ns: 'ns', line: jsonLine({ ts: 3, reqId: 'R', msg: 'later line' }) },
      { i: 3, ns: 'ns', line: jsonLine({ ts: 4, reqId: 'Q', msg: 'other request' }) },
    ]);
    const [a, b, c, d] = s.lines();
    expect(a.tenant).toBe(TA); expect(a.tenantAttributed).toBe(true);
    expect(b.tenant).toBe(TA); expect(b.tenantAttributed).toBeUndefined();
    expect(c.tenant).toBe(TA); expect(c.tenantAttributed).toBe(true);
    expect(d.tenant).toBeUndefined();
    expect(s.tenantCounts.get(TA)).toBe(3);
    s.setPredicate(compilePredicate({ ...emptyFilters(), tenant: { [TA]: 'include' } }), []);
    expect(s.ids).toEqual([a.id, b.id, c.id]);
    s.setPredicate(compilePredicate({ ...emptyFilters(), tenant: { [TA]: 'exclude' } }), []);
    expect(s.ids).toEqual([d.id]);
  });
  it('re-evaluates the view when attribution arrives after a tenant filter is active', () => {
    const s = mk(1000);
    s.setPredicate(compilePredicate({ ...emptyFilters(), tenant: { [TA]: 'include' } }), []);
    s.ingest([{ i: 0, ns: 'ns', line: jsonLine({ ts: 1, reqId: 'R', msg: 'early' }) }]);
    expect(s.ids).toEqual([]);
    s.ingest([{ i: 1, ns: 'ns', line: jsonLine({ ts: 2, reqId: 'R', domain: TA, msg: 'tenant known now' }) }]);
    expect(s.ids).toEqual([0, 1]);
    expect(s.counts.total).toBe(2);
  });
  it('eviction keeps tenant counts consistent', () => {
    const s = mk(120);
    const raws = sampleCapture(500);
    s.ingest(raws.map((line, j) => ({ i: j, ns: 'ns', line })));
    const brute = new Map<string, number>();
    for (const l of s.lines()) if (l.tenant) brute.set(l.tenant, (brute.get(l.tenant) || 0) + 1);
    expect([...s.tenantCounts.entries()].sort()).toEqual([...brute.entries()].sort());
    expect(s.tenantCounts.has('health')).toBe(true);
  });
});
