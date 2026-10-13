// Read-only view of the line store that the analysis modules query. The
// store implements it with its indices; tests implement it over an array.

import type { LogLine } from './parse';

export interface LineSource {
  get(id: number): LogLine | undefined;
  /** Ascending ids of lines with this reqId. */
  byReq(reqId: string): readonly number[];
  /** Ascending ids of lines with this flowExecId. */
  byExec(execId: string): readonly number[];
  /** Ascending ids of http access-log lines. */
  httpIds(): readonly number[];
  /** All flowExecIds currently known, in first-appearance order. */
  execIds(): readonly string[];
}

/** Lines with reqId, in id order. */
export function reqLines(src: LineSource, reqId: string): LogLine[] {
  const out: LogLine[] = [];
  for (const id of src.byReq(reqId)) { const l = src.get(id); if (l) out.push(l); }
  return out;
}
export function execLines(src: LineSource, execId: string): LogLine[] {
  const out: LogLine[] = [];
  for (const id of src.byExec(execId)) { const l = src.get(id); if (l) out.push(l); }
  return out;
}
export function httpLines(src: LineSource): LogLine[] {
  const out: LogLine[] = [];
  for (const id of src.httpIds()) { const l = src.get(id); if (l) out.push(l); }
  return out;
}
export const inWindow = (l: LogLine, startMs: number, endMs: number): boolean =>
  l.ts !== undefined && l.ts >= startMs && l.ts <= endMs;

/** Simple array-backed source for tests and offline tools. */
export class ArraySource implements LineSource {
  private map = new Map<number, LogLine>();
  private reqIdx = new Map<string, number[]>();
  private execIdx = new Map<string, number[]>();
  private execOrder: string[] = [];
  private https: number[] = [];
  constructor(lines: Iterable<LogLine>) {
    for (const l of lines) {
      this.map.set(l.id, l);
      if (l.reqId) { let a = this.reqIdx.get(l.reqId); if (!a) this.reqIdx.set(l.reqId, a = []); a.push(l.id); }
      if (l.flowExecId) {
        let a = this.execIdx.get(l.flowExecId);
        if (!a) { this.execIdx.set(l.flowExecId, a = []); this.execOrder.push(l.flowExecId); }
        a.push(l.id);
      }
      if (l.kind === 'http') this.https.push(l.id);
    }
  }
  get(id: number) { return this.map.get(id); }
  byReq(r: string) { return this.reqIdx.get(r) || []; }
  byExec(e: string) { return this.execIdx.get(e) || []; }
  httpIds() { return this.https; }
  execIds() { return this.execOrder; }
}
