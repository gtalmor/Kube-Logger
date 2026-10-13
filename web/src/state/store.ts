// The bounded line store: ring buffer + incremental indices + filtered view.
// Big arrays live as plain fields; signals only carry version counters so
// the UI renders at most once per animation frame regardless of ingest rate.
import { signal } from '@preact/signals';
import { parseLine, type LogLine } from '../lib/parse';
import { RingBuffer } from '../lib/ring';
import { FlowIndex } from '../lib/flow';
import { appendDecision, recomputeView, type Predicate } from '../lib/filters';
import type { LineSource } from '../lib/source';

export interface Counts { total: number; err: number; warn: number; dbg: number; trc: number; http: number }
export interface IngestItem { i?: number; ns?: string; line: string }

const lowerBound = (arr: number[], x: number): number => {
  let lo = 0, hi = arr.length;
  while (lo < hi) { const m = (lo + hi) >> 1; if (arr[m] < x) lo = m + 1; else hi = m; }
  return lo;
};
const bump = (c: Counts, l: LogLine, d: 1 | -1) => {
  c.total += d;
  if (l.level === 'ERROR' || l.level === 'FATAL') c.err += d;
  else if (l.level === 'WARN') c.warn += d;
  else if (l.level === 'DEBUG') c.dbg += d;
  else if (l.level === 'TRACE') c.trc += d;
  if (l.kind === 'http') c.http += d;
};
const dec = (m: Map<string, number>, k: string) => { const v = (m.get(k) || 0) - 1; if (v <= 0) m.delete(k); else m.set(k, v); };
const inc = (m: Map<string, number>, k: string) => m.set(k, (m.get(k) || 0) + 1);

export class LogStore implements LineSource {
  ring: RingBuffer<LogLine>;
  readonly flow = new FlowIndex();
  // indices
  private reqIdx = new Map<string, number[]>();
  private execIdx = new Map<string, number[]>();
  private execOrder: string[] = [];
  private https: number[] = [];
  readonly podCounts = new Map<string, number>();
  readonly nsCounts = new Map<string, number>();
  readonly reqCounts = new Map<string, number>();
  readonly nsSeen = new Set<string>();
  nsCapturing = new Set<string>();
  // view
  ids: number[] = [];
  errIds: number[] = [];
  /** Cumulative number of rows removed from the front of the view (for scroll correction). */
  viewEvicted = 0;
  counts: Counts = { total: 0, err: 0, warn: 0, dbg: 0, trc: 0, http: 0 };
  hiddenReqIds = new Set<string>();
  private hiddenExecs = new Set<string>();
  private pred: Predicate;
  // capture epoch + dedupe
  captureId: string | null = null;
  captureStart: number | null = null;
  lastSrc = -1;
  // signals (notification only)
  readonly dataVersion = signal(0);
  readonly viewVersion = signal(0);
  readonly flowVersion = signal(0);
  readonly usage = signal({ size: 0, cap: 0, evicted: 0, total: 0 });
  private flushScheduled = false;
  private lastFlowBump = 0;
  private flushFn: (cb: () => void) => void;

  constructor(capacity: number, pred: Predicate, opts: { schedule?: (cb: () => void) => void } = {}) {
    this.ring = new RingBuffer<LogLine>(capacity);
    this.pred = pred;
    this.flushFn = opts.schedule || (typeof requestAnimationFrame === 'function' ? cb => requestAnimationFrame(() => cb()) : cb => setTimeout(cb, 0));
    this.usage.value = { size: 0, cap: capacity, evicted: 0, total: 0 };
  }

  // ── LineSource ────────────────────────────────────────────────────
  get(id: number): LogLine | undefined { return this.ring.get(id); }
  byReq(reqId: string): readonly number[] { return this.reqIdx.get(reqId) || []; }
  byExec(execId: string): readonly number[] { return this.execIdx.get(execId) || []; }
  httpIds(): readonly number[] { return this.https; }
  execIds(): readonly string[] { return this.execOrder; }
  get size(): number { return this.ring.size; }
  lines(): LogLine[] { return [...this.ring.iter()]; }
  viewTail(): LogLine | undefined { return this.ids.length ? this.ring.get(this.ids[this.ids.length - 1]) : undefined; }

  // ── ingest ────────────────────────────────────────────────────────
  /** Parse and add lines. `items[].i` (agent index) is used to skip replays. */
  ingest(items: readonly IngestItem[], opts: { dedupe?: boolean } = {}): number {
    let added = 0;
    let viewFront = 0, errFront = 0;
    for (const it of items) {
      if (opts.dedupe !== false && it.i !== undefined) {
        if (it.i <= this.lastSrc) continue;
        this.lastSrc = it.i;
      }
      let line: LogLine | null;
      try { line = parseLine(it.line, it.ns, this.nsCapturing, this.ring.nextId, it.i); }
      catch { line = { id: this.ring.nextId, kind: 'raw', raw: it.line, msg: it.line, ns: it.ns, level: 'INFO', isErr: false, hasJsonHint: false }; }
      if (!line) continue;
      const evicted = this.ring.push(line);
      if (evicted) {
        this.unindex(evicted);
        if (viewFront < this.ids.length && this.ids[viewFront] === evicted.id) { viewFront++; bump(this.counts, evicted, -1); }
        if (errFront < this.errIds.length && this.errIds[errFront] === evicted.id) errFront++;
      }
      this.index(line);
      if (appendDecision(line, this.viewTail(), this.pred, this.hiddenReqIds)) {
        this.ids.push(line.id);
        if (line.isErr) this.errIds.push(line.id);
        bump(this.counts, line, 1);
      }
      added++;
    }
    if (viewFront) { this.ids.splice(0, viewFront); this.viewEvicted += viewFront; }
    if (errFront) this.errIds.splice(0, errFront);
    if (this.ring.evicted) this.flow.evictBefore(this.ring.firstId);
    if (added) this.scheduleFlush();
    return added;
  }

  private index(l: LogLine): void {
    if (l.ns) { inc(this.nsCounts, l.ns); this.nsSeen.add(l.ns); }
    if (l.pod) inc(this.podCounts, l.pod);
    if (l.reqId) {
      inc(this.reqCounts, l.reqId);
      let a = this.reqIdx.get(l.reqId);
      if (!a) this.reqIdx.set(l.reqId, a = []);
      a.push(l.id);
    }
    if (l.flowExecId) {
      let a = this.execIdx.get(l.flowExecId);
      if (!a) { this.execIdx.set(l.flowExecId, a = []); this.execOrder.push(l.flowExecId); }
      a.push(l.id);
      if (this.hiddenExecs.has(l.flowExecId) && l.reqId) this.hiddenReqIds.add(l.reqId);
    }
    if (l.kind === 'http') this.https.push(l.id);
    this.flow.add(l);
  }

  private unindex(l: LogLine): void {
    if (l.ns) dec(this.nsCounts, l.ns);
    if (l.pod) dec(this.podCounts, l.pod);
    if (l.reqId) {
      dec(this.reqCounts, l.reqId);
      const a = this.reqIdx.get(l.reqId);
      if (a) { if (a[0] === l.id) a.shift(); if (!a.length) this.reqIdx.delete(l.reqId); }
    }
    if (l.flowExecId) {
      const a = this.execIdx.get(l.flowExecId);
      if (a) {
        if (a[0] === l.id) a.shift();
        if (!a.length) { this.execIdx.delete(l.flowExecId); const k = this.execOrder.indexOf(l.flowExecId); if (k >= 0) this.execOrder.splice(k, 1); }
      }
    }
    if (l.kind === 'http' && this.https[0] === l.id) this.https.shift();
  }

  private scheduleFlush(): void {
    if (this.flushScheduled) return;
    this.flushScheduled = true;
    this.flushFn(() => {
      this.flushScheduled = false;
      this.dataVersion.value++;
      this.viewVersion.value++;
      this.usage.value = { size: this.ring.size, cap: this.ring.capacity, evicted: this.ring.evicted, total: this.ring.nextId };
      const now = Date.now();
      if (now - this.lastFlowBump > 250) { this.lastFlowBump = now; this.flowVersion.value = this.flow.version; }
    });
  }
  /** Force the pending frame now (tests, capture end). */
  flushNow(): void {
    this.flushScheduled = false;
    this.dataVersion.value++;
    this.viewVersion.value++;
    this.usage.value = { size: this.ring.size, cap: this.ring.capacity, evicted: this.ring.evicted, total: this.ring.nextId };
    this.flowVersion.value = this.flow.version;
  }

  // ── epochs ────────────────────────────────────────────────────────
  /** Start a new capture epoch; a repeat of the current epoch is a no-op. */
  resetForCapture(captureId: string | null, start: number | null, ns: Iterable<string>): boolean {
    const nsSet = new Set(ns);
    const same = captureId !== null && captureId === this.captureId;
    this.nsCapturing = nsSet;
    for (const n of nsSet) this.nsSeen.add(n);
    if (same) { this.flushNow(); return false; }
    this.clear(false);
    this.captureId = captureId;
    this.captureStart = start;
    this.nsCapturing = nsSet;
    for (const n of nsSet) this.nsSeen.add(n);
    this.flushNow();
    return true;
  }

  /** Drop all lines (keeps namespace colours etc. elsewhere). */
  clear(bumpSignals = true): void {
    this.ring.reset();
    this.flow.clear();
    this.reqIdx.clear(); this.execIdx.clear(); this.execOrder = []; this.https = [];
    this.podCounts.clear(); this.nsCounts.clear(); this.reqCounts.clear(); this.nsSeen.clear();
    this.ids = []; this.errIds = []; this.counts = { total: 0, err: 0, warn: 0, dbg: 0, trc: 0, http: 0 };
    this.hiddenReqIds.clear();
    this.lastSrc = -1;
    this.captureId = null;
    this.captureStart = null;
    if (bumpSignals) this.flushNow();
  }

  setCapacity(n: number): void {
    if (n === this.ring.capacity) return;
    let viewFront = 0, errFront = 0;
    this.ring.setCapacity(n, l => {
      this.unindex(l);
      if (viewFront < this.ids.length && this.ids[viewFront] === l.id) { viewFront++; bump(this.counts, l, -1); }
      if (errFront < this.errIds.length && this.errIds[errFront] === l.id) errFront++;
    });
    if (viewFront) { this.ids.splice(0, viewFront); this.viewEvicted += viewFront; }
    if (errFront) this.errIds.splice(0, errFront);
    this.flow.evictBefore(this.ring.firstId);
    this.flushNow();
  }

  // ── view ──────────────────────────────────────────────────────────
  setPredicate(pred: Predicate, hiddenExecIds: readonly string[]): void {
    this.pred = pred;
    this.hiddenExecs = new Set(hiddenExecIds);
    this.hiddenReqIds = new Set();
    for (const e of this.hiddenExecs) for (const id of this.byExec(e)) { const l = this.ring.get(id); if (l && l.reqId) this.hiddenReqIds.add(l.reqId); }
    this.recompute();
  }
  recompute(): void {
    const lines = this.lines();
    this.ids = recomputeView(lines, this.pred, this.hiddenReqIds);
    this.errIds = [];
    this.counts = { total: 0, err: 0, warn: 0, dbg: 0, trc: 0, http: 0 };
    for (const id of this.ids) {
      const l = this.ring.get(id) as LogLine;
      bump(this.counts, l, 1);
      if (l.isErr) this.errIds.push(id);
    }
    this.flushNow();
  }
  /** Index of `id` in the view, or -1. */
  viewIndexOf(id: number): number {
    const k = lowerBound(this.ids, id);
    return k < this.ids.length && this.ids[k] === id ? k : -1;
  }
  errIndexOf(id: number): number {
    const k = lowerBound(this.errIds, id);
    return k < this.errIds.length && this.errIds[k] === id ? k : -1;
  }
  /** Where a line is: visible, hidden by filters, or already evicted. */
  locate(id: number): 'ok' | 'filtered' | 'evicted' {
    if (!this.ring.has(id)) return 'evicted';
    return this.viewIndexOf(id) >= 0 ? 'ok' : 'filtered';
  }
  /** Raw text of the visible lines (export). */
  *visibleRaw(): IterableIterator<string> {
    for (const id of this.ids) { const l = this.ring.get(id); if (l) yield l.raw; }
  }
}
