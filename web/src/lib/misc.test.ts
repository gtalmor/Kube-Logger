import { beforeEach, describe, expect, it } from 'vitest';
import { compileHighlights, segmentize } from './highlight';
import { extractJson, lineJson } from './json-extract';
import { durBucket, fmtMs, fmtRemaining, fmtTs, hexToRgba, shortPod, shortReq } from './format';
import { nextNsColor, NS_PALETTE } from './colors';
import { KEYS, loadDrawerState, loadPalette, loadPresets, loadUiPrefs, parseFlowDef, presetToFilters, useStorage } from './storage';
import { jsonLine, parseAll } from './testutil';

describe('highlight segmentize', () => {
  it('returns plain text with no spec', () => {
    expect(segmentize('abc', null)).toEqual([{ text: 'abc' }]);
    expect(segmentize('', null)).toEqual([]);
  });
  it('marks highlight terms and search, search wins overlaps', () => {
    const spec = compileHighlights(['foo', 'bar'], 'o b');
    const segs = segmentize('xx foo bar yy', spec);
    expect(segs.map(s => s.text).join('')).toBe('xx foo bar yy');
    expect(segs).toEqual([
      { text: 'xx ' }, { text: 'fo', hi: 0 }, { text: 'o b', search: true }, { text: 'ar', hi: 1 }, { text: ' yy' },
    ]);
  });
  it('tolerates invalid search regex and regex metachars in terms', () => {
    const spec = compileHighlights(['a.b'], '(');
    expect(segmentize('a.b ( axb', spec)).toEqual([{ text: 'a.b', hi: 0 }, { text: ' ' }, { text: '(', search: true }, { text: ' axb' }]);
  });
});

describe('json extraction', () => {
  it('finds the largest JSON substring', () => {
    expect(extractJson('prefix {"a":1} mid {"b":[1,2,3],"c":{"d":"}"}} tail')).toEqual({ b: [1, 2, 3], c: { d: '}' } });
    expect(extractJson('nothing here')).toBeNull();
    expect(extractJson('[1,2] and {"x":1}')).toEqual({ x: 1 });   // longest wins
    expect(extractJson('[1,2,3,4] and {"x":1}')).toEqual([1, 2, 3, 4]);
  });
  it('lineJson re-parses json lines lazily', () => {
    const l = parseAll([jsonLine({ ts: 1, reqId: 'r', msg: 'hi', extra: { foo: { bar: 1 } } })])[0];
    expect((lineJson(l) as { foo: { bar: number } }).foo.bar).toBe(1);
    const plain = parseAll(['io-x-1 c payload {"k":[true]} end'])[0];
    expect(lineJson(plain)).toEqual({ k: [true] });
  });
});

describe('format', () => {
  it('formats durations, timestamps, pods', () => {
    expect(fmtMs(12)).toBe('12ms');
    expect(fmtMs(1500)).toBe('1.50s');
    expect(fmtMs(15000)).toBe('15.0s');
    expect(fmtMs(120000)).toBe('2.0m');
    expect(fmtTs(Date.UTC(2026, 0, 1, 1, 2, 3, 4))).toBe('01:02:03.004');
    expect(fmtTs(undefined, '12/Oct/2026:10:00:00 +0000')).toBe('12/Oct/2026:');
    expect(shortPod('io-flow-engine-7d9f8c6b5-x1k2q9')).toBe('flow-engine');
    expect(shortPod('averyveryverylongpodnamethatkeepsgoing')).toBe('averyveryverylongpod..');
    expect(shortReq('abcdefghijkl')).toBe('abcdefgh');
    expect(durBucket(50)).toBe('fast'); expect(durBucket(300)).toBe('ok'); expect(durBucket(1000)).toBe('warn'); expect(durBucket(5000)).toBe('slow');
    expect(hexToRgba('#ff0000', 0.5)).toBe('rgba(255,0,0,0.5)');
    expect(hexToRgba('bad', 1)).toContain('rgba(88,166,255');
    expect(fmtRemaining(0)).toBe('expired');
    expect(fmtRemaining(5 * 60000)).toBe('5m left');
    expect(fmtRemaining(125 * 60000)).toBe('2h 5m left');
  });
  it('nextNsColor cycles', () => {
    const used: Record<string, string> = {};
    for (let i = 0; i < NS_PALETTE.length; i++) used['n' + i] = nextNsColor(used);
    expect(new Set(Object.values(used)).size).toBe(NS_PALETTE.length);
    expect(NS_PALETTE).toContain(nextNsColor(used));
  });
});

describe('storage migrations', () => {
  let mem: Map<string, string>;
  beforeEach(() => {
    mem = new Map();
    useStorage({ getItem: k => mem.get(k) ?? null, setItem: (k, v) => { mem.set(k, v); }, removeItem: k => { mem.delete(k); } });
  });
  it('presets from older shapes', () => {
    mem.set(KEYS.presets, JSON.stringify({ current: 'p1', presets: { p1: { search: 'x', level: 'ERROR', pod: 'all', hideTrace: true } } }));
    const ps = loadPresets();
    expect(ps.current).toBe('p1');
    const f = presetToFilters(ps.presets.p1);
    expect(f.level).toEqual({ ERROR: 'include' });
    expect(f.pod).toEqual({});
    expect(f.hideTrace).toBe(true);
    expect(f.hiddenExecIds).toEqual([]);
  });
  it('merges the chrome-shim ns colours into the drawer state once', () => {
    mem.set(KEYS.drawer, JSON.stringify({ nsColors: { a: '#111111' }, selectedNs: ['a'] }));
    mem.set(KEYS.shimNsColors, JSON.stringify({ a: '#222222', b: '#333333' }));
    const d = loadDrawerState();
    expect(d.nsColors).toEqual({ a: '#222222', b: '#333333' });
    expect(mem.has(KEYS.shimNsColors)).toBe(false);
    expect(JSON.parse(mem.get(KEYS.drawer)!).nsColors.b).toBe('#333333');
  });
  it('palette v1 → v2 per theme; ui prefs pick up legacy panel width', () => {
    mem.set(KEYS.paletteV1, JSON.stringify({ error: '#abcdef' }));
    const p = loadPalette();
    expect(p.dark.error).toBe('#abcdef');
    expect(p.light.error).not.toBe('#abcdef');
    expect(mem.has(KEYS.paletteV2)).toBe(true);
    mem.set(KEYS.tpWidth, '640');
    const ui = loadUiPrefs();
    expect(ui.panelWidth).toBe(640);
    expect(ui.theme).toBe('system');
    expect(ui.bufferCap).toBe(50000);
  });
  it('parses flow definitions', () => {
    const def = parseFlowDef({ name: 'Login', content: { nodes: { '1': { meta: { title: 'Start' } }, '2': { title: 'Check' }, '3': {} } } }, 'login.json')!;
    expect(def).toMatchObject({ name: 'Login', nodeCount: 2, labels: { '1': 'Start', '2': 'Check' } });
    expect(parseFlowDef({ nope: 1 }, 'x')).toBeNull();
  });
});
