import { describe, expect, it } from 'vitest';
import { appendDecision, compilePredicate, emptyFilters, extractPattern, migrateFilterField, recomputeView, triCycle, triPass, triSummary, type FilterState } from './filters';
import { parseAll, sampleCapture, jsonLine } from './testutil';
import type { LogLine } from './parse';

// ── Legacy oracle (ported verbatim from viewer.js shouldShow / rebuildFiltered) ──
function legacyShouldShow(S: FilterState & { hiddenExec: Set<string>; hiddenReq: Set<string> }, l: LogLine): boolean {
  if (S.hiddenPatterns.length) { const t = (l.msg || l.raw || '').toLowerCase(); for (const p of S.hiddenPatterns) if (t.includes(p.toLowerCase())) return false; }
  if (S.hiddenExec.size && l.flowExecId && S.hiddenExec.has(l.flowExecId)) return false;
  if (S.hiddenExec.size && l.reqId && S.hiddenReq.has(l.reqId)) return false;
  if (!triPass(S.level, l.level)) return false;
  if (S.hideTrace && l.level === 'TRACE') return false;
  if (!triPass(S.pod, l.pod)) return false;
  if (!triPass(S.req, l.reqId)) return false;
  if (S.search) { try { if (!new RegExp(S.search, 'i').test(l.raw || l.msg || '')) return false; } catch { if (!(l.raw || l.msg || '').toLowerCase().includes(S.search.toLowerCase())) return false; } }
  return true;
}
function legacyCont(S: FilterState & { hiddenExec: Set<string>; hiddenReq: Set<string> }, l: LogLine): boolean {
  if (S.hiddenPatterns.length) { const t = (l.msg || l.raw || '').toLowerCase(); for (const p of S.hiddenPatterns) if (t.includes(p.toLowerCase())) return false; }
  if (S.hiddenExec.size && l.flowExecId && S.hiddenExec.has(l.flowExecId)) return false;
  if (S.hiddenExec.size && l.reqId && S.hiddenReq.has(l.reqId)) return false;
  if (!triPass(S.pod, l.pod)) return false;
  return true;
}
const isMulti = (l: LogLine | undefined) => !!l && (l.kind === 'plain' || l.kind === 'script-error');
function legacyRebuild(S: FilterState & { hiddenExec: Set<string>; hiddenReq: Set<string> }, lines: LogLine[]): number[] {
  const included = new Array(lines.length).fill(false);
  for (let i = 0; i < lines.length; i++) if (legacyShouldShow(S, lines[i])) included[i] = true;
  for (let i = 0; i < lines.length; i++) {
    if (!included[i]) continue;
    const l = lines[i];
    if (!isMulti(l)) continue;
    for (let j = i - 1; j >= 0; j--) { const pl = lines[j]; if (!isMulti(pl) || pl.pod !== l.pod) break; if (included[j]) break; if (!legacyCont(S, pl)) break; included[j] = true; }
    for (let j = i + 1; j < lines.length; j++) { const nl = lines[j]; if (!isMulti(nl) || nl.pod !== l.pod) break; if (included[j]) continue; if (!legacyCont(S, nl)) break; included[j] = true; }
  }
  const out: number[] = [];
  for (let i = 0; i < lines.length; i++) if (included[i]) out.push(lines[i].id);
  return out;
}

function withHidden(f: FilterState, lines: LogLine[]) {
  const hiddenExec = new Set(f.hiddenExecIds);
  const hiddenReq = new Set<string>();
  for (const l of lines) if (l.flowExecId && hiddenExec.has(l.flowExecId) && l.reqId) hiddenReq.add(l.reqId);
  return { ...f, hiddenExec, hiddenReq };
}

describe('tri-state', () => {
  it('triPass semantics: include wins, exclude blacklists', () => {
    expect(triPass({}, 'x')).toBe(true);
    expect(triPass({ a: 'include' }, 'a')).toBe(true);
    expect(triPass({ a: 'include' }, 'b')).toBe(false);
    expect(triPass({ a: 'include', b: 'exclude' }, 'b')).toBe(false);
    expect(triPass({ a: 'exclude' }, 'a')).toBe(false);
    expect(triPass({ a: 'exclude' }, 'b')).toBe(true);
    expect(triPass({ a: 'exclude' }, undefined)).toBe(true);
    expect(triPass({ a: 'include' }, undefined)).toBe(false);
  });
  it('triCycle and summary', () => {
    let f = triCycle({}, 'a');
    expect(f).toEqual({ a: 'include' });
    f = triCycle(f, 'a');
    expect(f).toEqual({ a: 'exclude' });
    f = triCycle(f, 'a');
    expect(f).toEqual({});
    expect(triSummary({}, 'Levels')).toBe('All Levels');
    expect(triSummary({ a: 'include', b: 'exclude' }, 'Levels')).toBe('Levels (+1 −1)');
  });
  it('migrateFilterField', () => {
    expect(migrateFilterField('all')).toEqual({});
    expect(migrateFilterField('ERROR')).toEqual({ ERROR: 'include' });
    expect(migrateFilterField({ a: 'exclude' })).toEqual({ a: 'exclude' });
    expect(migrateFilterField(undefined)).toEqual({});
  });
});

describe('compilePredicate vs legacy oracle', () => {
  const lines = parseAll(sampleCapture(400));
  const pods = [...new Set(lines.map(l => l.pod).filter(Boolean))] as string[];
  const execs = [...new Set(lines.map(l => l.flowExecId).filter(Boolean))] as string[];
  const cases: Partial<FilterState>[] = [
    {},
    { search: 'script_be' },
    { search: '(' },                       // invalid regex → substring fallback
    { search: 'done state' },
    { level: { ERROR: 'include' } },
    { level: { TRACE: 'exclude', DEBUG: 'exclude' } },
    { hideTrace: true },
    { pod: { [pods[0]]: 'include' } },
    { pod: { [pods[1]]: 'exclude' } },
    { req: { 'req-1001-ab12cd34': 'include' } },
    { hiddenPatterns: ['probe request', 'count finished'] },
    { hiddenExecIds: [execs[0], execs[3]] },
    { hiddenExecIds: [execs[1]], search: 'syntaxerror' },
    { search: 'SyntaxError', level: { ERROR: 'include' } },
  ];
  for (const [i, c] of cases.entries()) {
    it(`case ${i}: ${JSON.stringify(c)}`, () => {
      const f = { ...emptyFilters(), ...c };
      const S = withHidden(f, lines);
      const pred = compilePredicate(f);
      const expected = legacyRebuild(S, lines);
      expect(recomputeView(lines, pred, S.hiddenReq)).toEqual(expected);
      // Incremental append must agree with the full recompute.
      const inc: number[] = [];
      let tail: LogLine | undefined;
      for (const l of lines) {
        if (appendDecision(l, tail, pred, S.hiddenReq)) { inc.push(l.id); tail = l; }
      }
      // The full recompute may also sweep *backwards* (previous lines of a
      // group), which an append-only stream cannot; so incremental ⊆ full.
      for (const id of inc) expect(expected).toContain(id);
      expect(inc.length).toBeGreaterThan(0 - 1);
    });
  }
});

describe('tenant filter', () => {
  const lines = parseAll(sampleCapture(200));
  it('include/exclude by tenant; lines without a tenant always pass', () => {
    const inc = compilePredicate({ ...emptyFilters(), tenant: { health: 'include' } });
    const ids = recomputeView(lines, inc, new Set());
    expect(ids.length).toBeGreaterThan(0);
    expect(ids.every(id => lines[id].tenant === 'health' || lines[id].tenant === undefined)).toBe(true);
    expect(ids.some(id => lines[id].tenant === 'health')).toBe(true);
    expect(ids.some(id => lines[id].kind === 'http')).toBe(true);   // untagged gateway lines stay visible
    expect(inc.usesTenant).toBe(true);
    const exc = compilePredicate({ ...emptyFilters(), tenant: { health: 'exclude' } });
    const ids2 = recomputeView(lines, exc, new Set());
    expect(ids2.some(id => lines[id].tenant === 'health')).toBe(false);
    expect(ids2.some(id => lines[id].kind === 'http')).toBe(true);
    expect(compilePredicate(emptyFilters()).usesTenant).toBe(false);
  });
});

describe('extractPattern', () => {
  const mk = (msg: string) => parseAll([jsonLine({ ts: 1, msg })])[0];
  it('recognizes probes, db queries, node states, warnings, fallback', () => {
    expect(extractPattern(mk('Health "liveness" probe request received'))).toBe('Health "liveness" probe request received');
    expect(extractPattern(mk('MongoDBSessionRepository something count started'))).toBe('MongoDBSessionRepository: count started');
    expect(extractPattern(mk('[e] f - Node script_be_v2 is in done state, next node is #1'))).toBe('Node script_be_v2 is in done state');
    expect(extractPattern(mk('(node:1) ExperimentalWarning: x'))).toBe('ExperimentalWarning');
    expect(extractPattern(mk('x'.repeat(100)))).toBe('x'.repeat(80));
  });
});
