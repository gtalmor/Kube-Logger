import { useEffect, useMemo, useRef, useState } from 'preact/hooks';
import { closePanel, panelOpen, panelTab, panelWidth, type PanelTab } from '../state/ui';
import { inspect, traceReqId } from '../state/panels';
import { store, jumpTo } from '../state/app';
import { labelOf } from '../state/flowDefs';
import { toast } from '../state/toasts';
import { buildTrace, type TraceFlow } from '../lib/trace';
import { barContext, type Bar, type BarContext, type Waterfall } from '../lib/waterfall';
import { buildTraceExport } from '../lib/trace-export';
import { durBucket, fmtMs, fmtTs, shortReq, fmtCount } from '../lib/format';
import type { LogLine } from '../lib/parse';
import { JsonTree } from './JsonTree';

// ── Trace ───────────────────────────────────────────────────────────
function Row({ l, children, cls }: { l?: LogLine; children: preact.ComponentChildren; cls?: string }) {
  return <div class={`tp-row ${cls || ''}`} onClick={() => l && jumpTo(l.id)}>{children}</div>;
}

function NodeDetail({ bar, reqId, execId, depth }: { bar: Bar; reqId: string; execId: string; depth: number }) {
  const ctx: BarContext = useMemo(() => barContext(store, store.flow, bar, reqId, execId, labelOf), [bar, reqId, execId, store.dataVersion.value]);
  const pct = bar.dur ? Math.round(ctx.selfMs / bar.dur * 100) : 0;
  const empty = !ctx.nestedFlows.length && !ctx.inline && !ctx.dbCalls.length && !ctx.httpCalls.length && !ctx.gaps.length && !ctx.keyEvents.length;
  return (
    <div class="wf-detail">
      {ctx.nestedFlows.length > 0 && (
        <div class="wf-section">
          <div class="wf-label">Time breakdown</div>
          <div class="wf-drow"><span class={`wf-tag dur-${durBucket(ctx.selfMs)}`}>{fmtMs(ctx.selfMs)}</span><span>self time ({pct}%)</span></div>
          <div class="wf-drow"><span class={`wf-tag dur-${durBucket(ctx.childMs)}`}>{fmtMs(ctx.childMs)}</span><span>in {ctx.nestedFlows.length} nested flow{ctx.nestedFlows.length === 1 ? '' : 's'}</span></div>
          {ctx.nestedFlows.map(nf => (
            <div key={nf.execId} class="wf-section">
              <div class="wf-label">↳ Nested flow: {nf.name || 'unknown'} <span class="mono faint">{nf.execId.slice(0, 8)}</span> · {fmtMs(nf.waterfall.total)}</div>
              <WaterfallRows wf={nf.waterfall} bars={nf.waterfall.bars} reqId={reqId} execId={nf.execId} depth={depth + 1} />
            </div>
          ))}
        </div>
      )}
      {ctx.inline && (
        <div class="wf-section">
          <div class="wf-label">↳ Inline contents (same exec, {ctx.inline.bars.length} node{ctx.inline.bars.length === 1 ? '' : 's'}) · {fmtMs(ctx.inline.total)}</div>
          <WaterfallRows wf={ctx.inline} bars={ctx.inline.bars} reqId={reqId} execId={execId} depth={depth + 1} />
        </div>
      )}
      {ctx.dbCalls.length > 0 && (
        <div class="wf-section"><div class="wf-label">DB / external calls ({ctx.dbCalls.length})</div>
          {ctx.dbCalls.slice(0, 8).map((d, i) => <div key={i} class="wf-drow click" onClick={() => jumpTo(d.startLineId)}><span class={`wf-tag dur-${durBucket(d.durMs)}`}>{fmtMs(d.durMs)}</span><span class="truncate">{d.label}</span></div>)}
        </div>
      )}
      {ctx.httpCalls.length > 0 && (
        <div class="wf-section"><div class="wf-label">HTTP requests during this node ({ctx.httpCalls.length})</div>
          {ctx.httpCalls.slice(0, 8).map((h, i) => <div key={i} class="wf-drow click" onClick={() => jumpTo(h.lineId)}><span class={`wf-tag hs ${h.status >= 500 ? 's5' : h.status >= 400 ? 's4' : 's2'}`}>{h.status}</span><span class="truncate">{h.method} {h.path} · {h.sizeB}B</span></div>)}
        </div>
      )}
      {ctx.gaps.length > 0 && (
        <div class="wf-section"><div class="wf-label">Silence gaps ≥ 200ms</div>
          {ctx.gaps.slice(0, 5).map((g, i) => <div key={i} class="wf-drow click" onClick={() => jumpTo(g.nextLineId)}><span class={`wf-tag dur-${durBucket(g.ms)}`}>{fmtMs(g.ms)}</span><span class="truncate">… then: {g.nextMsg.slice(0, 90)}</span></div>)}
        </div>
      )}
      {ctx.keyEvents.length > 0 && (
        <div class="wf-section"><div class="wf-label">Key events in window ({ctx.keyEvents.length})</div>
          {ctx.keyEvents.slice(0, 12).map(l => <div key={l.id} class={`wf-drow click ${l.isErr ? 'err' : ''}`} onClick={() => jumpTo(l.id)}><span class="wf-ts num">{fmtTs(l.ts, l.tsText)}</span><span class="truncate">{(l.msg || l.raw).slice(0, 220)}</span></div>)}
        </div>
      )}
      {empty && <div class="pop-hint">No additional detail in this node's window.</div>}
    </div>
  );
}

function WaterfallRows({ wf, bars, reqId, execId, depth, rows }: { wf: Waterfall; bars: Bar[]; reqId: string; execId: string; depth: number; rows?: TraceFlow['rows'] }) {
  const [open, setOpen] = useState<Set<number>>(new Set());
  const list = rows || bars.map(bar => ({ bar, hop: null, gapBefore: 0 }));
  return (
    <div class="wf">
      {list.map((r, i) => {
        const b = r.bar;
        const off = wf.total ? ((b.start - wf.minStart) / wf.total * 100) : 0;
        const w = wf.total ? Math.max(0.5, b.dur / wf.total * 100) : 100;
        const isOpen = open.has(i);
        return (
          <div key={b.lineId + ':' + i}>
            {r.gapBefore > 500 && (
              <div class="wf-row idle" title={`${fmtMs(r.gapBefore)} idle — likely user input or external wait`}>
                <span class="wf-caret" /><span class="wf-name faint">⏸ idle</span>
                <span class="wf-track"><span class="wf-bar idle" style={{ left: `${((b.start - r.gapBefore - wf.minStart) / wf.total * 100).toFixed(2)}%`, width: `${(r.gapBefore / wf.total * 100).toFixed(2)}%` }} /></span>
                <span class="wf-dur num faint">{fmtMs(r.gapBefore)}</span>
              </div>
            )}
            <div class="wf-row" onClick={() => { const n = new Set(open); if (n.has(i)) n.delete(i); else n.add(i); setOpen(n); }} title={`${b.title ? b.title + ' • ' : ''}${b.node}${b.id ? ' #' + b.id : ''} — ${fmtMs(b.dur)} (${b.state})`}>
              <span class="wf-caret">{isOpen ? '▾' : '▸'}</span>
              <span class="wf-name truncate">{b.title || b.node}{r.hop && <span class="wf-hop" title={`api_be re-POSTs to ${r.hop.path} — the authId/proxy hop`}>authId hop</span>}</span>
              <span class="wf-track"><span class={`wf-bar bg-dur-${durBucket(b.dur)} ${b.state === 'failed' ? 'failed' : ''} ${r.hop ? 'hop' : ''}`} style={{ left: `${off.toFixed(2)}%`, width: `${w.toFixed(2)}%` }} /></span>
              <span class={`wf-dur num dur-${durBucket(b.dur)}`}>{fmtMs(b.dur)}</span>
            </div>
            {isOpen && depth < 6 && <NodeDetail bar={b} reqId={reqId} execId={execId} depth={depth} />}
          </div>
        );
      })}
    </div>
  );
}

function TracePanel() {
  const reqId = traceReqId.value;
  const ver = store.dataVersion.value;
  const t = useMemo(() => (reqId ? buildTrace(store, store.flow, reqId, labelOf) : null), [reqId, ver]);
  if (!reqId) return <div class="panel-empty">Click a request id in the log to open its trace.</div>;
  if (!t) return <div class="panel-empty">No logs for request {shortReq(reqId)} in the buffer.</div>;
  const failures = t.flows.flatMap(f => f.failures), errors = t.flows.flatMap(f => f.errors);
  return (
    <div class="trace">
      {(failures.length > 0 || errors.length > 0) && (
        <section class="tp-section errors">
          <h5>Root cause</h5>
          {failures.map((f, i) => <div key={'f' + i} class="tp-row click" onClick={() => jumpTo(f.lineId)}>⚠ <b>{f.label}</b> <span class="faint">(node {f.nodeId})</span></div>)}
          {errors.map((e, i) => <div key={'e' + i} class="tp-row click err" onClick={() => jumpTo(e.lineId)}>✗ {e.msg.length > 200 ? e.msg.slice(0, 200) + '…' : e.msg}</div>)}
        </section>
      )}
      {t.flows.map(f => f.waterfall && (
        <section class="tp-section" key={f.execId}>
          <h5>Timing — {f.name || 'flow'} <span class="mono faint">{f.execId.slice(0, 8)}</span> · total {fmtMs(f.waterfall.total)}
            {f.idle.totalMs > 0 && <span class="faint" title={`${f.idle.gaps.length} gap(s) > 500ms — typically user input`}> · active {fmtMs(f.activeMs)} · idle {fmtMs(f.idle.totalMs)}</span>}
            {f.reentry && <span class="tp-tax" title={`A child exec of the same flow (${f.reentry.childExecId.slice(0, 8)}) ran inside this one — the authId/proxy hop.`}> · authId tax {fmtMs(f.reentry.taxMs)} (inner {fmtMs(f.reentry.childTotal)})</span>}
          </h5>
          {f.typeSummary.length > 0 && (
            <div class="wf-summary">
              <div class="wf-srow head"><span>type</span><span /><span class="num">runs</span><span class="num">mean</span><span class="num">max</span><span class="num">total</span></div>
              {f.typeSummary.slice(0, 15).map(r => {
                const pct = f.waterfall ? Math.round(r.total / f.waterfall.total * 100) : 0;
                return (
                  <div key={r.name} class="wf-srow" title={r.titles.length ? `${r.name} — ${r.titles.slice(0, 4).join(', ')}` : r.name}>
                    <span class="truncate">{r.name}</span>
                    <span class="wf-sbar"><span class={`bg-dur-${durBucket(r.mean)}`} style={{ width: `${pct}%` }} /></span>
                    <span class="num">{r.count}</span>
                    <span class={`num dur-${durBucket(r.mean)}`}>{fmtMs(r.mean)}</span>
                    <span class={`num dur-${durBucket(r.max)}`}>{fmtMs(r.max)}</span>
                    <span class={`num dur-${durBucket(r.total)}`}>{fmtMs(r.total)}</span>
                  </div>
                );
              })}
            </div>
          )}
          <WaterfallRows wf={f.waterfall} bars={f.waterfall.bars} rows={f.rows} reqId={t.reqId} execId={f.execId} depth={0} />
        </section>
      ))}
      {t.flows.length > 0 && (
        <section class="tp-section">
          <h5>Flow execution path</h5>
          {t.flows.map(f => (
            <div key={f.execId}>
              <div class="tp-flowname">{f.name || 'unknown'} <span class="mono faint">{f.execId.slice(0, 8)}</span></div>
              <div class="tp-path">
                {f.path.map((n, i) => {
                  const isFail = n.states.includes('failed') || (n.node.includes('failure') && n.states.includes('pre'));
                  const cls = isFail ? 'failed' : n.states.includes('pre') && !n.states.includes('done') ? 'pre' : n.states.includes('done') ? 'done' : 'process';
                  return (
                    <span key={i}>
                      {i > 0 && <span class="tp-arrow">→</span>}
                      <span class={`tp-node ${cls}`} title={`${n.node} [${n.states.join(' → ')}]${n.next ? ' → next: ' + n.next : ''}${n.label ? ' (' + n.label + ')' : ''}${n.reason ? ' — ' + n.reason : ''}`} onClick={() => jumpTo(n.lineId)}>
                        {n.node === 'nested_flow' ? 'nested_flow ↴' : n.node}{n.next && <span class="faint"> #{n.next}</span>}
                      </span>
                    </span>
                  );
                })}
              </div>
              {f.failures.map((fl, i) => <div key={i} class="tp-row click err" onClick={() => jumpTo(fl.lineId)}>⚠ Failure from <b>#{fl.nodeId}</b>: {fl.label}</div>)}
            </div>
          ))}
        </section>
      )}
      {t.http.length > 0 && (
        <section class="tp-section">
          <h5>HTTP requests</h5>
          {t.http.map(l => <Row key={l.id} l={l} cls={`click ${(l.status || 0) >= 400 ? 'err' : ''}`}><span class="mono">{l.method}</span> {l.path} <span class={`hs ${(l.status || 0) >= 500 ? 's5' : (l.status || 0) >= 400 ? 's4' : 's2'}`}>{l.status}</span> <span class="faint">{l.size}B</span></Row>)}
        </section>
      )}
      <section class="tp-section">
        <h5>Key events <span class="faint">({t.keyEvents.length} of {t.reqLines.length} lines)</span></h5>
        {t.keyEvents.map(l => (
          <Row key={l.id} l={l} cls={`click kv ${l.isErr ? 'err' : ''}`}>
            <span class="wf-ts num">{fmtTs(l.ts, l.tsText)}</span>
            <span class={`r-lv lv-${l.level.toLowerCase()}`}>{l.level}</span>
            {l.flowNode ? <span class="tp-tag">{l.flowNode}</span> : l.failNodeId ? <span class="tp-tag fail">#{l.failNodeId}</span> : null}
            <span class="truncate">{(l.msg || l.raw).slice(0, 300)}</span>
          </Row>
        ))}
      </section>
    </div>
  );
}

function downloadTrace(reqId: string): void {
  const data = buildTraceExport(store, store.flow, reqId, labelOf, store.captureStart);
  if (!data) { toast('No trace open'); return; }
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `trace-${reqId.slice(0, 8)}-${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}.json`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  toast(`Exported ${data.counts.lines} lines · ${data.counts.flows} flow${data.counts.flows === 1 ? '' : 's'}`, 'ok');
}

// ── Inspect ─────────────────────────────────────────────────────────
function InspectPanel({ collapseTick, expandTick }: { collapseTick: number; expandTick: number }) {
  const v = inspect.value;
  if (!v) return <div class="panel-empty">Click <span class="mono">{'{ }'}</span> on a line to inspect its JSON.</div>;
  if (v.value == null) return <div class="panel-empty">No JSON found in that line.</div>;
  return <div class="jv"><JsonTree value={v.value} collapseAllTick={collapseTick} expandAllTick={expandTick} /></div>;
}

// ── Slow nodes ──────────────────────────────────────────────────────
function SlowPanel() {
  void store.flowVersion.value;
  const rows = store.flow.aggregate();
  if (!rows.length) return <div class="panel-empty">No completed node executions yet.</div>;
  return (
    <div class="slow">
      <div class="sl-row head"><span>Node</span><span class="num">runs</span><span class="num">mean</span><span class="num">p95</span><span class="num">max</span></div>
      {rows.slice(0, 40).map(r => (
        <div key={r.name} class="sl-row">
          <span class="truncate" title={r.name}>{r.name}</span>
          <span class="num">{fmtCount(r.count)}</span>
          <span class={`num dur-${durBucket(r.mean)}`}>{fmtMs(r.mean)}</span>
          <span class={`num dur-${durBucket(r.p95)}`}>{fmtMs(r.p95)}</span>
          <span class={`num dur-${durBucket(r.max)}`}>{fmtMs(r.max)}</span>
        </div>
      ))}
    </div>
  );
}

// ── Panel shell ─────────────────────────────────────────────────────
export function SidePanel() {
  const open = panelOpen.value;
  const tab = panelTab.value;
  const width = panelWidth.value;
  const [collapseTick, setC] = useState(0);
  const [expandTick, setE] = useState(0);
  const drag = useRef<{ x: number; w: number } | null>(null);
  useEffect(() => {
    const mv = (e: MouseEvent) => { if (!drag.current) return; panelWidth.value = Math.max(320, Math.min(window.innerWidth - 320, drag.current.w + (drag.current.x - e.clientX))); };
    const up = () => { drag.current = null; document.body.classList.remove('resizing'); };
    document.addEventListener('mousemove', mv); document.addEventListener('mouseup', up);
    return () => { document.removeEventListener('mousemove', mv); document.removeEventListener('mouseup', up); };
  }, []);
  if (!open) return null;
  const tabs: { k: PanelTab; label: string }[] = [{ k: 'trace', label: traceReqId.value ? `Trace · ${shortReq(traceReqId.value)}` : 'Trace' }, { k: 'inspect', label: 'Inspect' }, { k: 'slow', label: 'Slow nodes' }];
  return (
    <aside class="panel" style={{ width }}>
      <div class="panel-resize" onMouseDown={e => { drag.current = { x: e.clientX, w: width }; document.body.classList.add('resizing'); e.preventDefault(); }} />
      <div class="panel-head">
        <div class="tabs">{tabs.map(t => <button key={t.k} class={`tab ${tab === t.k ? 'on' : ''}`} onClick={() => { panelTab.value = t.k; }}>{t.label}</button>)}</div>
        <div class="panel-actions">
          {tab === 'trace' && traceReqId.value && <button class="btn sm" onClick={() => downloadTrace(traceReqId.value as string)}>Export JSON</button>}
          {tab === 'inspect' && inspect.value && <>
            <button class="btn sm" onClick={() => setE(x => x + 1)}>Expand all</button>
            <button class="btn sm" onClick={() => setC(x => x + 1)}>Collapse all</button>
            <button class="btn sm" onClick={() => { navigator.clipboard.writeText(JSON.stringify(inspect.value?.value, null, 2)).then(() => toast('Copied JSON', 'ok'), () => toast('Copy failed', 'error')); }}>Copy</button>
          </>}
          <button class="btn sm ghost" title="Close (Esc)" onClick={closePanel}>✕</button>
        </div>
      </div>
      {tab === 'inspect' && inspect.value && <div class="panel-sub truncate">{inspect.value.title}</div>}
      <div class="panel-body">
        {tab === 'trace' && <TracePanel />}
        {tab === 'inspect' && <InspectPanel collapseTick={collapseTick} expandTick={expandTick} />}
        {tab === 'slow' && <SlowPanel />}
      </div>
    </aside>
  );
}
