import { describe, expect, it } from 'vitest';
import { parseLine, parseTs, stripAnsi } from './parse';
import { httpLine, jsonLine, nodeMsg, failMsg } from './testutil';

const NS = new Set(['ns1', 'ns2']);
const p = (raw: string, ns?: string) => parseLine(raw, ns, NS, 7);

describe('parseLine', () => {
  it('drops blank and stern pod events', () => {
    expect(p('')).toBeNull();
    expect(p('   ')).toBeNull();
    expect(p('+ io-flow-engine-abc › flow-engine')).toBeNull();
    expect(p('- io-flow-engine-abc › flow-engine')).toBeNull();
  });

  it('parses http access-log lines including CLF timestamps', () => {
    const l = p(httpLine({ ts: Date.UTC(2026, 9, 12, 10, 0, 5), path: '/flow/execute/custom/my-flow?x=1', status: 502, size: 42 }))!;
    expect(l.kind).toBe('http');
    expect(l.level).toBe('HTTP');
    expect(l.method).toBe('POST');
    expect(l.path).toBe('/flow/execute/custom/my-flow?x=1');
    expect(l.status).toBe(502);
    expect(l.size).toBe(42);
    expect(l.flowName).toBe('my-flow');
    expect(l.ts).toBe(Date.UTC(2026, 9, 12, 10, 0, 5));
    expect(l.isErr).toBe(true);
    expect(l.id).toBe(7);
  });

  it('parses json lines with mixed data[] and flow node messages', () => {
    const ts = Date.UTC(2026, 9, 12, 10, 0, 0, 123);
    const raw = jsonLine({ ts, level: 'info', reqId: 'req-1', msg: nodeMsg('exec-1', 'login', 'JS Executer', 'done', '#9191'), extra: { data: [nodeMsg('exec-1', 'login', 'JS Executer', 'done', '#9191'), { file: 'x.js' }, { k: 1 }] } });
    const l = p(raw)!;
    expect(l.kind).toBe('json');
    expect(l.pod).toBe('io-flow-engine-7d9f8c6b5-x1k2q');
    expect(l.container).toBe('flow-engine');
    expect(l.ts).toBe(ts);
    expect(l.reqId).toBe('req-1');
    expect(l.level).toBe('INFO');
    expect(l.flowExecId).toBe('exec-1');
    expect(l.flowName).toBe('login');
    expect(l.flowNode).toBe('JS Executer');
    expect(l.flowState).toBe('done');
    expect(l.flowNext).toBe('#9191');
    expect(l.msg).toContain('{"k":1}');
    expect(l.msg).not.toContain('x.js');
    expect(l.jsonOff).toBeGreaterThan(0);
    expect(JSON.parse(l.raw.slice(l.jsonOff!)).req_id).toBe('req-1');
    expect(l.hasJsonHint).toBe(true);
    expect(l.isErr).toBe(false);
  });

  it('parses failures, axios errors and not-connected outputs', () => {
    const f = p(jsonLine({ ts: 1, level: 'error', reqId: 'r', msg: failMsg('exec-1', 'login', 'condition', 'bad input') }))!;
    expect(f.flowExecId).toBe('exec-1');
    expect(f.flowNode).toBe('condition');
    expect(f.flowFailReason).toBe('bad input');
    expect(f.flowState).toBe('failed');
    expect(f.isErr).toBe(true);

    const short = p(jsonLine({ ts: 1, msg: 'Failure from node 42 (Check password)' }))!;
    expect(short.failNodeId).toBe('42');
    expect(short.failNodeLabel).toBe('Check password');
    expect(short.flowState).toBe('failed');

    const ax = p(jsonLine({ ts: 1, msg: 'Error occurred: AxiosError: Request failed with status code 502' }))!;
    expect(ax.apiError).toBe('AxiosError: Request failed with status code 502');

    const nc = p(jsonLine({ ts: 1, msg: '"Failure" output of node 77 is not connected' }))!;
    expect(nc.failNodeId).toBe('77');
    expect(nc.isFlowError).toBe(true);
    expect(nc.isErr).toBe(true);

    const save = p(jsonLine({ ts: 1, msg: 'Error and save error in session' }))!;
    expect(save.isFlowError).toBe(true);

    const start = p(jsonLine({ ts: 1, msg: '[exec-9] other-flow - Starting flow execution' }))!;
    expect(start.flowExecId).toBe('exec-9');
    expect(start.flowName).toBe('other-flow');
    expect(start.flowNode).toBeUndefined();
  });

  it('normalizes levels', () => {
    expect(p(jsonLine({ ts: 1, level: 'warning', msg: 'x' }))!.level).toBe('WARN');
    expect(p(jsonLine({ ts: 1, level: 'err', msg: 'x' }))!.level).toBe('ERROR');
    expect(p(jsonLine({ ts: 1, msg: 'x', extra: { level: undefined } }))!.level).toBe('INFO');
  });

  it('parses plain io- pod lines, ANSI, script-executor and error-detail continuations', () => {
    const plain = p('io-flow-engine-abc flow-engine \x1b[31mSomething bad happened\x1b[0m')!;
    expect(plain.kind).toBe('plain');
    expect(plain.msg).toBe('Something bad happened');
    expect(plain.level).toBe('INFO');
    const warn = p('io-x-1 c there was a Warning here')!;
    expect(warn.level).toBe('WARN');
    const err = p('io-x-1 c fatal error here')!;
    expect(err.level).toBe('ERROR');

    const se = p('io-script-executor-1 se [2026-10-12T10:00:00.000] [ERROR] [req-se-1] [domain] [caller] [obo] [source] - boom')!;
    expect(se.kind).toBe('script-error');
    expect(se.reqId).toBe('req-se-1');
    expect(se.level).toBe('ERROR');
    expect(se.ts).toBe(Date.parse('2026-10-12T10:00:00.000'));

    const det = p('io-flow-engine-abc flow-engine     SyntaxError: Illegal return statement')!;
    expect(det.kind).toBe('plain');
    expect(det.isErrorDetail).toBe(true);
    expect(det.level).toBe('ERROR');
    expect(det.msg).toBe('SyntaxError: Illegal return statement');
    expect(det.isErr).toBe(true);
  });

  it('falls back to raw for anything else', () => {
    const l = p('just some text without structure')!;
    expect(l.kind).toBe('raw');
    expect(l.msg).toBe('just some text without structure');
    expect(l.level).toBe('INFO');
  });

  it('strips a leading namespace from multi-namespace stern output', () => {
    const base = jsonLine({ ts: 1, msg: 'hello' });
    const withNs = p('ns2 ' + base)!;
    expect(withNs.ns).toBe('ns2');
    expect(withNs.pod).toBe('io-flow-engine-7d9f8c6b5-x1k2q');
    const tagged = p('ns1 ' + base, 'ns1')!;
    expect(tagged.ns).toBe('ns1');
    expect(tagged.kind).toBe('json');
    const other = p('ns9 ' + base)!;
    expect(other.kind).toBe('raw');
  });

  it('keeps unparseable timestamps as text', () => {
    const l = p(jsonLine({ ts: 1, msg: 'x', extra: { timestamp: 'yesterday' } }))!;
    expect(l.ts).toBeUndefined();
    expect(l.tsText).toBe('yesterday');
  });
});

describe('helpers', () => {
  it('parseTs handles ISO, CLF with offsets, and garbage', () => {
    expect(parseTs('2026-10-12T10:00:00Z')).toBe(Date.UTC(2026, 9, 12, 10));
    expect(parseTs('12/Oct/2026:10:00:00 +0000')).toBe(Date.UTC(2026, 9, 12, 10));
    expect(parseTs('12/Oct/2026:12:00:00 +0200')).toBe(Date.UTC(2026, 9, 12, 10));
    expect(parseTs('12/Oct/2026:08:00:00 -0200')).toBe(Date.UTC(2026, 9, 12, 10));
    expect(parseTs('nope')).toBeUndefined();
    expect(parseTs(undefined)).toBeUndefined();
  });
  it('stripAnsi', () => {
    expect(stripAnsi('\x1b[31mred\x1b[0m [32mx')).toBe('red x');
  });
});
