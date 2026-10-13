// Secondary strips under the header: auth banner, error issues, flow timeline.
import { useState } from 'preact/hooks';
import { store, jumpErr, jumpTo, curErr } from '../state/app';
import { agentConnected, auth } from '../state/connection';
import { login, selectedProfile, selectProfile } from '../state/setup';
import { filters, hideExec, clearHiddenExecs } from '../state/filters';
import { stripsCollapsed, toggleStrip } from '../state/ui';
import { labelOf } from '../state/flowDefs';
import { fmtMs, durBucket, fmtCount } from '../lib/format';
import type { LogLine } from '../lib/parse';
import { showNodePopover } from './FailurePopover';
import { toast } from '../state/toasts';

function expiredLabel(mode?: string, label?: string): string {
  if (!mode || mode === 'sso') return 'SSO expired';
  return `${label || 'Session'} expired`;
}

export function AuthBanner() {
  const a = auth.value;
  if (!agentConnected.value || !a || a.ok) return null;
  const head = expiredLabel(a.authMode, a.authLabel);
  return (
    <div class="strip auth-strip">
      <span class="strip-icon">⚠</span>
      <span class="strip-text"><b>{head}</b>{a.profile ? ` for ${a.profile}` : ''}{a.err ? ` — ${String(a.err).slice(0, 140)}` : ''}</span>
      <button class="btn sm" onClick={() => { if (a.profile && !selectedProfile.value) selectProfile(a.profile); login(); toast('Login started on the agent machine'); }}>Re-login</button>
    </div>
  );
}

function summary(l: LogLine): string {
  if (l.kind === 'http') return `${l.method} ${l.path} → ${l.status}`;
  return (l.msg || l.raw || '').slice(0, 90);
}

export function ErrorStrip() {
  void store.viewVersion.value;
  const n = store.errIds.length;
  const [open, setOpen] = useState(false);
  if (!n) return null;
  const collapsed = !!stripsCollapsed.value.errors;
  const k = curErr.value;
  const first = store.errIds.slice(0, 3).map(id => store.get(id)).filter(Boolean) as LogLine[];
  return (
    <div class={`strip err-strip ${collapsed ? 'collapsed' : ''}`}>
      <button class="strip-toggle" onClick={() => toggleStrip('errors')} title={collapsed ? 'Expand' : 'Collapse'}>{collapsed ? '▸' : '▾'}</button>
      <span class="strip-icon">⚠</span>
      <span class="strip-text"><b>{fmtCount(n)} issue{n === 1 ? '' : 's'}</b>{!collapsed && <span class="muted"> · {first.map(summary).join(' | ')}</span>}</span>
      <span class="strip-actions">
        <span class="num faint">{k >= 0 ? `${k + 1}/${n}` : ''}</span>
        <button class="btn sm" title="Previous error (p)" onClick={() => jumpErr('prev')}>▲</button>
        <button class="btn sm" title="Next error (n)" onClick={() => jumpErr('next')}>▼</button>
        <button class={`btn sm ${open ? 'active' : ''}`} onClick={() => setOpen(!open)}>List</button>
      </span>
      {open && (
        <div class="err-list">
          {store.errIds.slice(0, 300).map((id, i) => { const l = store.get(id); if (!l) return null; return (
            <div key={id} class={`err-item ${k === i ? 'cur' : ''}`} onClick={() => { curErr.value = i; jumpTo(id, { clearFilters: false }); setOpen(false); }}>
              <span class="num faint">#{id + 1}</span> <span class="truncate">{summary(l)}</span>
            </div>
          ); })}
          {n > 300 && <div class="pop-hint">…and {fmtCount(n - 300)} more</div>}
        </div>
      )}
    </div>
  );
}

export function FlowTimelineStrip() {
  void store.flowVersion.value;
  const hidden = new Set(filters.value.hiddenExecIds);
  const { groups, earlier } = store.flow.timeline(20, hidden);
  if (!groups.length && !hidden.size) return null;
  const collapsed = !!stripsCollapsed.value.flow;
  return (
    <div class={`strip flow-strip ${collapsed ? 'collapsed' : ''}`}>
      <button class="strip-toggle" onClick={() => toggleStrip('flow')} title={collapsed ? 'Expand' : 'Collapse'}>{collapsed ? '▸' : '▾'}</button>
      <span class="strip-label">Flows</span>
      {!collapsed && (
        <div class="flow-track">
          {hidden.size > 0 && <button class="chip hidden-badge" title="Click to restore hidden flows" onClick={() => { clearHiddenExecs(); toast('All flows restored'); }}>{hidden.size} hidden</button>}
          {earlier > 0 && <span class="chip faint">{earlier} earlier</span>}
          {groups.map(g => (
            <div class="flow-group" key={g.execId || 'orphans-' + g.firstId}>
              {g.execId && (
                <span class="flow-name" title={`exec ${g.execId}`}>
                  {g.name || '?'}
                  <button class="flow-hide" title="Hide this flow execution" onClick={e => { e.stopPropagation(); hideExec(g.execId as string); toast(`Hidden flow: ${g.name || (g.execId as string).slice(0, 8)}`); }}>×</button>
                </span>
              )}
              {g.chips.map(c => {
                const title = c.nodeId ? labelOf(c.nodeId) : undefined;
                const b = c.durMs !== undefined ? durBucket(c.durMs) : '';
                return (
                  <span key={c.key} class={`fnode st-${c.state} ${b ? 'dur-' + b : ''}`}
                    title={`${title ? title + ' • ' : ''}${c.node}${c.nodeId ? ' #' + c.nodeId : ''} (${c.state})${c.durMs !== undefined ? ' — ' + fmtMs(c.durMs) : ''}${c.next ? ' → #' + c.next : ''}${c.nextLabel ? ' (' + c.nextLabel + ')' : ''}`}
                    onClick={e => showNodePopover(e.currentTarget as HTMLElement, c)}>
                    {title || c.label || c.node}{c.durMs !== undefined && <span class="fnode-dur">{fmtMs(c.durMs)}</span>}
                  </span>
                );
              })}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
