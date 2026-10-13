// Incremental index of flow executions. Replaces the legacy extractFlow /
// computeNodeDurations / annotateNodeIds, which re-scanned every line. Each
// flow line is added once; evicted lines are dropped lazily by id.

import type { FlowState, LogLine } from './parse';

export interface NodeEvent {
  node: string;
  state: FlowState;
  next?: string;
  reason?: string;
  lineId: number;
  ts?: number;
  /** Concrete node id, chained from the previous node's `next` (annotateNodeIds). */
  nodeId?: string;
}

export interface ExecRecord {
  execId: string;
  name?: string;
  events: NodeEvent[];          // arrival order == id order
  reqIds: Set<string>;
  firstId: number;
  lastId: number;
  lineCount: number;
  minTs?: number;
  maxTs?: number;
  /** annotateNodeIds chain: the `next` announced by the latest done/post/failed event. */
  nextNodeId?: string;
  /** Failure chips attached by request id (not node events; timeline only). */
  chips: TimelineChip[];
}

/** A chip in the timeline strip (port of extractFlow's node entries). */
export interface TimelineChip {
  key: string;
  node: string;
  label?: string;
  state: FlowState;
  next?: string;
  nextLabel?: string;
  lineId: number;
  flowExecId?: string;
  flowName?: string;
  reqId?: string;
  nodeId?: string;
  /** Matched duration for this node within its exec, if both ends were seen. */
  durMs?: number;
}

export interface TimelineGroup { execId?: string; name?: string; firstId: number; chips: TimelineChip[] }

export interface SlowRow { name: string; count: number; mean: number; max: number; p95: number; total: number }

const END_STATES = new Set<FlowState>(['done', 'post', 'failed']);
const START_STATES = new Set<FlowState>(['pre', 'process']);

export class FlowIndex {
  readonly execs = new Map<string, ExecRecord>();
  /** First-appearance order of exec ids. */
  readonly order: string[] = [];
  /** node id → label, from "Failure from node X (label)" style messages. */
  readonly nodeLabels = new Map<string, string>();
  /** Orphan chips (failures / script errors with no exec). */
  private orphans: TimelineChip[] = [];
  private firstLiveId = 0;
  /** Bumped on every structural change; cheap signal for throttled UI. */
  version = 0;

  clear(): void {
    this.execs.clear();
    this.order.length = 0;
    this.nodeLabels.clear();
    this.orphans = [];
    this.firstLiveId = 0;
    this.version++;
  }

  private rec(execId: string, line: LogLine): ExecRecord {
    let r = this.execs.get(execId);
    if (!r) {
      r = { execId, name: line.flowName, events: [], reqIds: new Set(), firstId: line.id, lastId: line.id, lineCount: 0, chips: [] };
      this.execs.set(execId, r);
      this.order.push(execId);
    }
    if (!r.name && line.flowName) r.name = line.flowName;
    return r;
  }

  add(line: LogLine): void {
    let touched = false;
    if (line.failNodeId && line.failNodeLabel) { this.nodeLabels.set(line.failNodeId, line.failNodeLabel); touched = true; }
    if (line.flowFailReason && line.flowNode) { this.nodeLabels.set(line.flowNode, line.flowFailReason); touched = true; }

    if (line.flowExecId) {
      const r = this.rec(line.flowExecId, line);
      r.lineCount++;
      r.lastId = line.id;
      if (line.reqId) r.reqIds.add(line.reqId);
      if (line.ts !== undefined) {
        if (r.minTs === undefined || line.ts < r.minTs) r.minTs = line.ts;
        if (r.maxTs === undefined || line.ts > r.maxTs) r.maxTs = line.ts;
      }
      if (line.flowNode && line.flowState) {
        const ev: NodeEvent = { node: line.flowNode, state: line.flowState, next: line.flowNext, reason: line.flowFailReason, lineId: line.id, ts: line.ts };
        if (START_STATES.has(line.flowState) && r.nextNodeId) ev.nodeId = r.nextNodeId;
        if (END_STATES.has(line.flowState) && line.flowNext) r.nextNodeId = line.flowNext;
        r.events.push(ev);
      }
      touched = true;
    } else if (line.isErrorDetail || (line.failNodeId && line.flowState === 'failed') || (line.failNodeId && line.isFlowError)) {
      // Failure chips without an exec: attach to the exec of the same reqId
      // when we know one (legacy looked for a preceding node with the reqId).
      const chip: TimelineChip = line.isErrorDetail
        ? { key: 'se-' + line.id, node: 'script-executor', label: line.msg, state: 'failed', lineId: line.id, reqId: line.reqId }
        : line.isFlowError
          ? { key: 'nc-' + line.id, node: '#' + line.failNodeId, label: 'Failure output not connected (#' + line.failNodeId + ')', state: 'failed', lineId: line.id, reqId: line.reqId }
          : { key: 'f-' + line.id, node: line.failNodeId as string, label: line.failNodeLabel, state: 'failed', lineId: line.id, reqId: line.reqId };
      const home = line.reqId ? this.execForReq(line.reqId) : undefined;
      if (home) {
        if (chip.key.startsWith('nc-')) {
          const prev = [...home.events].reverse().find(e => e.next === line.failNodeId);
          if (prev) chip.node = prev.node + ' → FAIL';
        }
        chip.flowExecId = home.execId; chip.flowName = home.name;
        home.chips.push(chip);
        home.lineCount++; home.lastId = line.id;
      } else {
        this.orphans.push(chip);
      }
      touched = true;
    }
    if (touched) this.version++;
  }

  /** Drop everything the ring evicted (ids below `firstLiveId`). */
  evictBefore(firstLiveId: number): void {
    if (firstLiveId <= this.firstLiveId) return;
    this.firstLiveId = firstLiveId;
    let changed = false;
    for (const [id, r] of this.execs) {
      if (r.lastId < firstLiveId) {
        this.execs.delete(id);
        const k = this.order.indexOf(id);
        if (k >= 0) this.order.splice(k, 1);
        changed = true;
      } else if (r.firstId < firstLiveId) {
        const before = r.events.length + r.chips.length;
        r.events = r.events.filter(e => e.lineId >= firstLiveId);
        r.chips = r.chips.filter(c => c.lineId >= firstLiveId);
        r.firstId = firstLiveId;
        if (r.events.length + r.chips.length !== before) changed = true;
      }
    }
    if (this.orphans.length && this.orphans[0].lineId < firstLiveId) {
      this.orphans = this.orphans.filter(c => c.lineId >= firstLiveId);
      changed = true;
    }
    if (changed) this.version++;
  }

  execForReq(reqId: string): ExecRecord | undefined {
    for (let k = this.order.length - 1; k >= 0; k--) {
      const r = this.execs.get(this.order[k]);
      if (r && r.reqIds.has(reqId)) return r;
    }
    return undefined;
  }

  /** Execs whose [minTs, maxTs] overlaps the window, excluding `except`. */
  execsInWindow(startMs: number, endMs: number, except?: string): ExecRecord[] {
    const out: ExecRecord[] = [];
    for (const id of this.order) {
      if (id === except) continue;
      const r = this.execs.get(id);
      if (!r || r.minTs === undefined || r.maxTs === undefined) continue;
      if (r.maxTs < startMs || r.minTs > endMs) continue;
      out.push(r);
    }
    return out;
  }

  /**
   * Per exec+node durations (port of computeNodeDurations): earliest start
   * state paired with the latest end state. Key "execId|node".
   */
  durations(): Map<string, { ms: number; startMs: number; endMs: number; state: FlowState }> {
    const starts = new Map<string, number>();
    const ends = new Map<string, { ms: number; state: FlowState }>();
    for (const r of this.execs.values()) {
      for (const e of r.events) {
        if (e.ts === undefined) continue;
        const key = r.execId + '|' + e.node;
        if (START_STATES.has(e.state)) {
          const cur = starts.get(key);
          if (cur === undefined || e.ts < cur) starts.set(key, e.ts);
        } else if (END_STATES.has(e.state)) {
          const cur = ends.get(key);
          if (!cur || e.ts > cur.ms) ends.set(key, { ms: e.ts, state: e.state });
        }
      }
    }
    const out = new Map<string, { ms: number; startMs: number; endMs: number; state: FlowState }>();
    for (const [key, end] of ends) {
      const start = starts.get(key);
      if (start === undefined) continue;
      const ms = end.ms - start;
      if (ms < 0) continue;
      out.set(key, { ms, startMs: start, endMs: end.ms, state: end.state });
    }
    return out;
  }

  /** Aggregate per node type across the capture (port of aggregateNodeDurations). */
  aggregate(): SlowRow[] {
    const byNode = new Map<string, number[]>();
    for (const [key, info] of this.durations()) {
      const name = key.split('|', 2)[1] || '?';
      let a = byNode.get(name);
      if (!a) byNode.set(name, a = []);
      a.push(info.ms);
    }
    const rows: SlowRow[] = [];
    for (const [name, samples] of byNode) {
      samples.sort((a, b) => a - b);
      const sum = samples.reduce((a, b) => a + b, 0);
      rows.push({
        name, count: samples.length, mean: sum / samples.length, max: samples[samples.length - 1],
        p95: samples[Math.min(samples.length - 1, Math.floor(samples.length * 0.95))], total: sum,
      });
    }
    rows.sort((a, b) => b.mean - a.mean);
    return rows;
  }

  /**
   * Timeline groups (port of extractFlow + updateFlow), newest-last. Chips
   * are deduped per execution by node+state, so a repeated flow still shows.
   */
  timeline(limit = 20, hidden?: ReadonlySet<string>): { groups: TimelineGroup[]; earlier: number } {
    const dur = this.durations();
    const groups: TimelineGroup[] = [];
    for (const id of this.order) {
      if (hidden && hidden.has(id)) continue;
      const r = this.execs.get(id);
      if (!r || (!r.events.length && !r.chips.length)) continue;
      const seen = new Set<string>();
      const chips: TimelineChip[] = [];
      for (const e of r.events) {
        const k = e.node + '-' + e.state;
        if (seen.has(k)) continue;
        seen.add(k);
        const d = dur.get(r.execId + '|' + e.node);
        chips.push({
          key: r.execId + ':' + k, node: e.node, state: e.state, next: e.next,
          nextLabel: e.next ? this.nodeLabels.get(e.next) : undefined,
          label: e.state === 'failed' ? e.reason : undefined,
          lineId: e.lineId, flowExecId: r.execId, flowName: r.name, nodeId: e.nodeId,
          reqId: [...r.reqIds][0], durMs: d ? d.ms : undefined,
        });
      }
      for (const c of r.chips) {
        const k = c.node + '-' + c.state;
        if (seen.has(k)) continue;
        seen.add(k);
        chips.push(c);
      }
      groups.push({ execId: r.execId, name: r.name, firstId: r.firstId, chips });
    }
    if (this.orphans.length) groups.push({ firstId: this.orphans[0].lineId, chips: this.orphans.slice(-limit) });
    const earlier = Math.max(0, groups.length - limit);
    return { groups: groups.slice(earlier), earlier };
  }

  get isEmpty(): boolean { return this.execs.size === 0 && this.orphans.length === 0; }
}
