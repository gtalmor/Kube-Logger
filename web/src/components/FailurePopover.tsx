import type { LogLine } from '../lib/parse';
import type { TimelineChip } from '../lib/flow';
import { failureContext } from '../lib/trace';
import { fmtMs } from '../lib/format';
import { store, jumpTo } from '../state/app';
import { openTrace } from '../state/panels';
import { showAnchored, closeAnchored } from './AnchoredPopover';

const Row = ({ k, children, cls }: { k: string; children: preact.ComponentChildren; cls?: string }) => (
  <div class="np-row"><span class="np-label">{k}</span><span class={`np-val ${cls || ''}`}>{children}</span></div>
);
const Actions = ({ lineId, reqId }: { lineId: number; reqId?: string }) => (
  <div class="np-actions">
    <button class="btn sm" onClick={() => { jumpTo(lineId); closeAnchored(); }}>Jump to log line</button>
    {reqId && <button class="btn sm primary" onClick={() => { openTrace(reqId); closeAnchored(); }}>Open trace</button>}
  </div>
);

export function showFailurePopover(anchor: HTMLElement, l: LogLine): void {
  const ctx = failureContext(store, l);
  showAnchored(anchor, (
    <div class="np">
      <Row k="Node" cls="np-fail">{l.failNodeLabel}</Row>
      <Row k="Node ID">#{l.failNodeId}</Row>
      {ctx.flowName && <Row k="Flow">{ctx.flowName}</Row>}
      {ctx.flowExecId && <Row k="Exec">{ctx.flowExecId.slice(0, 12)}…</Row>}
      {ctx.nestingDepth > 0 && <Row k="Nesting">{ctx.nestingDepth} level{ctx.nestingDepth > 1 ? 's' : ''} deep</Row>}
      {ctx.calledFrom && <Row k="Called from">{ctx.calledFrom.node} ({ctx.calledFrom.state})</Row>}
      {l.reqId && <Row k="Request"><span class="link" onClick={() => { openTrace(l.reqId as string); closeAnchored(); }}>{l.reqId.slice(0, 12)}… ↗</span></Row>}
      {ctx.pathBefore.length > 0 && (
        <>
          <div class="np-section">Execution path to failure</div>
          <div class="np-path">
            {ctx.pathBefore.map((n, i) => <span key={i} class={`np-node ${n.node === 'nested_flow' ? 'nested' : n.state === 'done' ? 'done' : ''}`}>{n.node}</span>)}
            <span class="np-node fail">{l.failNodeLabel}</span>
          </div>
        </>
      )}
      <Actions lineId={l.id} reqId={l.reqId} />
    </div>
  ));
}

export function showNodePopover(anchor: HTMLElement, n: TimelineChip): void {
  showAnchored(anchor, (
    <div class="np">
      {n.state === 'failed' && n.label && n.label !== n.node && <Row k="Error" cls="np-fail">{n.label}</Row>}
      <Row k="Node">{n.node}{n.nodeId ? <span class="faint"> #{n.nodeId}</span> : null}</Row>
      <Row k="State" cls={`st-${n.state}`}>{n.state}{n.durMs !== undefined ? <span class="faint"> · {fmtMs(n.durMs)}</span> : null}</Row>
      {n.flowName && <Row k="Flow">{n.flowName}</Row>}
      {n.flowExecId && <Row k="Exec">{n.flowExecId.slice(0, 12)}…</Row>}
      {n.next && <Row k="Next">#{n.next}{n.nextLabel ? <em> ({n.nextLabel})</em> : null}</Row>}
      {n.reqId && <Row k="Request"><span class="link" onClick={() => { openTrace(n.reqId as string); closeAnchored(); }}>{n.reqId.slice(0, 12)}… ↗</span></Row>}
      <Actions lineId={n.lineId} reqId={n.reqId} />
    </div>
  ));
}
