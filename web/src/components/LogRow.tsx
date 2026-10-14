import { memo } from 'preact/compat';
import { useState } from 'preact/hooks';
import type { LogLine } from '../lib/parse';
import { isMultilineMember } from '../lib/parse';
import { fmtTs, shortPod, shortReq, hexToRgba } from '../lib/format';
import { displayTenant, tenantColor, tenantName } from '../state/tenants';
import { segmentize, type HighlightSpec } from '../lib/highlight';
import { lineJson } from '../lib/json-extract';
import { extractPattern } from '../lib/filters';
import { addHiddenPattern, includeOnly } from '../state/filters';
import { jumpTo } from '../state/app';
import { openInspector, openTrace } from '../state/panels';
import { toast } from '../state/toasts';
import { showFailurePopover } from './FailurePopover';

interface Props {
  line: LogLine;
  prev?: LogLine;
  spec: HighlightSpec | null;
  nsColor?: string;
  isCurrent: boolean;
  expanded: boolean;
  onToggleExpand: (id: number) => void;
}

const LEVEL_CLASS: Record<string, string> = { ERROR: 'lv-error', FATAL: 'lv-error', WARN: 'lv-warn', INFO: 'lv-info', DEBUG: 'lv-debug', TRACE: 'lv-trace', HTTP: 'lv-http' };
const MAX_MSG = 500;

function Message({ l, spec }: { l: LogLine; spec: HighlightSpec | null }) {
  const [more, setMore] = useState(false);
  if (l.kind === 'http') {
    const sc = (l.status || 0) >= 500 ? 's5' : (l.status || 0) >= 400 ? 's4' : (l.status || 0) >= 300 ? 's3' : 's2';
    const text = `${l.method} ${l.path} `;
    return <>{segmentize(text, spec).map((s, i) => <Seg key={i} s={s} />)}<span class={`hs ${sc}`}>{l.status}</span> <span class="faint">{l.size}B</span></>;
  }
  if (l.failNodeId && l.failNodeLabel) {
    return (
      <span class="r-fail" onClick={e => { e.stopPropagation(); showFailurePopover(e.currentTarget as HTMLElement, l); }}>
        ⚠ <strong>{l.failNodeLabel}</strong> <span class="r-fail-id">#{l.failNodeId}</span> <span class="r-fail-hint">click for context</span>
      </span>
    );
  }
  const m = l.msg || l.raw || '';
  const long = m.length > MAX_MSG && !more;
  const shown = long ? m.slice(0, MAX_MSG) : m;
  return <>{segmentize(shown, spec).map((s, i) => <Seg key={i} s={s} />)}{long && <span class="r-more link" onClick={e => { e.stopPropagation(); setMore(true); }}>… more</span>}</>;
}
function Seg({ s }: { s: { text: string; hi?: number; search?: boolean } }) {
  if (s.search) return <mark class="hi search">{s.text}</mark>;
  if (s.hi !== undefined) return <mark class="hi" style={{ background: `var(--hi-${s.hi % 8})` }}>{s.text}</mark>;
  return <>{s.text}</>;
}

function ExpandedJson({ l }: { l: LogLine }) {
  const v = lineJson(l);
  if (v == null) return <div class="r-json faint">No JSON found in this line.</div>;
  return <pre class="r-json">{JSON.stringify(v, null, 2)}</pre>;
}

export const LogRow = memo(function LogRow({ line: l, prev, spec, nsColor, isCurrent, expanded, onToggleExpand }: Props) {
  const multi = !!prev && isMultilineMember(l) && isMultilineMember(prev) && l.pod === prev.pod;
  const cls = ['row', LEVEL_CLASS[l.level] || 'lv-info', l.isErr ? 'is-err' : '', isCurrent ? 'is-current' : '', multi ? 'is-multi' : '', l.isErrorDetail ? 'is-detail' : '', l.kind === 'http' && (l.status || 0) >= 500 ? 'h5' : l.kind === 'http' && (l.status || 0) >= 400 ? 'h4' : ''].join(' ');
  const style = nsColor ? { '--ns-color': nsColor, '--ns-bg': hexToRgba(nsColor, 0.07) } as Record<string, string> : undefined;
  return (
    <div class="rowwrap">
      <div class={cls} style={style} data-id={l.id}>
        <span class="r-ns" title={l.ns} />
        <span class="r-ln num" title="Show this line in full context" onClick={() => jumpTo(l.id)}>{l.id + 1}</span>
        <span class="r-ts num">{fmtTs(l.ts, l.tsText)}</span>
        <span class="r-lv">{multi ? '' : l.level}</span>
        <span class="r-pod truncate" title={l.pod} onClick={() => { if (l.pod) { includeOnly('pod', l.pod); toast(`Filtered: ${shortPod(l.pod)}`); } }}>{multi ? '│' : shortPod(l.pod)}</span>
        <span class="r-req num" title={l.reqId} onClick={e => { if (!l.reqId) return; if (e.shiftKey) { includeOnly('req', l.reqId); toast(`Request: ${shortReq(l.reqId)}`); } else openTrace(l.reqId); }}>{shortReq(l.reqId)}</span>
        <span class="r-ten">{l.tenant && (
          <span class={`r-ten-pill truncate ${l.tenantAttributed ? 'attr' : ''}`} style={{ '--t': tenantColor(l.tenant) } as Record<string, string>}
            title={`${tenantName(l.tenant) ? tenantName(l.tenant) + ' · ' : ''}${l.tenant}${l.tenantAttributed ? ' (via request id)' : ''} — click to show only this tenant`}
            onClick={() => { includeOnly('tenant', l.tenant as string); toast(`Tenant: ${displayTenant(l.tenant)}`); }}>{displayTenant(l.tenant)}</span>
        )}</span>
        <span class="r-msg"><Message l={l} spec={spec} /></span>
        <span class="r-actions">
          {l.kind === 'json' && <button class="r-act" title="Expand JSON" onClick={() => onToggleExpand(l.id)}>{expanded ? '[−]' : '[+]'}</button>}
          {(l.hasJsonHint || l.kind === 'json') && <button class="r-act" title="Open in JSON inspector" onClick={() => openInspector(`Line ${l.id + 1}${l.pod ? ' · ' + shortPod(l.pod) : ''}${l.reqId ? ' · ' + shortReq(l.reqId) : ''}`, lineJson(l))}>{'{ }'}</button>}
          {!multi && <button class="r-act r-hide" title="Hide messages like this" onClick={() => { const p = extractPattern(l); addHiddenPattern(p); toast(`Hidden: "${p.slice(0, 40)}${p.length > 40 ? '…' : ''}"`); }}>×</button>}
        </span>
      </div>
      {expanded && <ExpandedJson l={l} />}
    </div>
  );
});
