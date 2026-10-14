import { useEffect, useRef, useState } from 'preact/hooks';
import { Popover } from './Popover';
import { FiltersMenu } from './FiltersMenu';
import { ViewMenu } from './ViewMenu';
import { activeCount, filters, setSearch, predicate } from '../state/filters';
import { drawerOpen, openMenu, searchFocusTick } from '../state/ui';
import { agentConnected, auth, capture, send, wsConnected } from '../state/connection';
import { store } from '../state/app';
import { toast } from '../state/toasts';
import { fmtCount, fmtElapsed } from '../lib/format';

function expiredLabel(mode?: string, label?: string): string {
  if (!mode || mode === 'sso') return 'SSO expired';
  return `${label || 'Session'} expired`;
}

function StatusCluster() {
  const ws = wsConnected.value, ag = agentConnected.value;
  const a = auth.value;
  const cap = capture.value;
  const [, tick] = useState(0);
  useEffect(() => { if (!cap.active) return; const t = setInterval(() => tick(x => x + 1), 1000); return () => clearInterval(t); }, [cap.active]);
  void store.dataVersion.value;
  const status = !ws ? 'Connecting to relay…' : ag ? 'Agent connected' : 'Waiting for agent…';
  const dot = !ws ? 'fail' : ag ? 'ok' : 'pending';
  const authChip = ag && a ? (a.ok ? (a.arn ? a.arn.split('/').pop() : 'Authenticated') : expiredLabel(a.authMode, a.authLabel)) : null;
  return (
    <div class="status">
      <span class={`dot ${dot}`} />
      <span class="status-text">{status}</span>
      {authChip && <button class={`chip auth-chip ${a && a.ok ? '' : 'bad'}`} title="Open Setup" onClick={() => { drawerOpen.value = true; }}>{authChip}</button>}
      {cap.active && (
        <span class="chip rec" title={`Capturing ${cap.ns.join(', ')}`}>
          <span class="dot rec-dot" /> {cap.start ? fmtElapsed(Date.now() - cap.start) : ''} · {fmtCount(store.usage.value.total)} lines
        </span>
      )}
    </div>
  );
}

function SearchBox() {
  const ref = useRef<HTMLInputElement>(null);
  const [val, setVal] = useState(filters.value.search);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const tickv = searchFocusTick.value;
  useEffect(() => { if (tickv) { ref.current?.focus(); ref.current?.select(); } }, [tickv]);
  const external = filters.value.search;
  useEffect(() => { if (external !== val && document.activeElement !== ref.current) setVal(external); }, [external]);
  const invalid = !predicate.value.search.valid;
  void store.viewVersion.value;
  const count = filters.value.search ? store.counts.total : null;
  return (
    <div class={`search ${invalid ? 'invalid' : ''}`}>
      <span class="search-icon">⌕</span>
      <input ref={ref} class="search-input" placeholder="Search (regex) — press /" value={val}
        onInput={e => { const v = (e.target as HTMLInputElement).value; setVal(v); if (timer.current) clearTimeout(timer.current); timer.current = setTimeout(() => setSearch(v.trim()), 150); }}
        onKeyDown={e => { if (e.key === 'Enter') { if (timer.current) clearTimeout(timer.current); setSearch(val.trim()); } }} />
      {count !== null && <span class="search-count num" title={invalid ? 'Invalid regex: matching as plain text' : ''}>{fmtCount(count)}{invalid ? ' · text' : ''}</span>}
      {val && <button class="search-clear" title="Clear" onClick={() => { setVal(''); setSearch(''); ref.current?.focus(); }}>×</button>}
    </div>
  );
}

export function Header() {
  const fRef = useRef<HTMLButtonElement>(null);
  const vRef = useRef<HTMLButtonElement>(null);
  const menu = openMenu.value;
  const n = activeCount.value;
  const cap = capture.value;
  void store.usage.value;
  const hasData = store.size > 0;
  const onClear = () => {
    if (cap.active) { store.clear(); toast('Display cleared — still capturing'); }
    else { send({ action: 'clear' }); store.clear(); }
  };
  return (
    <header class="header">
      <div class="brand"><span class="brand-mark">◉</span> Kube Logger</div>
      <StatusCluster />
      <div class="header-spacer" />
      <SearchBox />
      <button ref={fRef} class={`btn ${n ? 'active' : ''} ${menu === 'filters' ? 'open' : ''}`} onClick={() => { openMenu.value = menu === 'filters' ? null : 'filters'; }}>
        Filters {n ? <span class="badge">{n}</span> : null} <span class="chev">▾</span>
      </button>
      <Popover open={menu === 'filters'} anchor={fRef} onClose={() => { if (openMenu.value === 'filters') openMenu.value = null; }} align="right" width={760}>
        <FiltersMenu />
      </Popover>
      <button ref={vRef} class={`btn ${menu === 'view' ? 'open' : ''}`} onClick={() => { openMenu.value = menu === 'view' ? null : 'view'; }}>View <span class="chev">▾</span></button>
      <Popover open={menu === 'view'} anchor={vRef} onClose={() => { if (openMenu.value === 'view') openMenu.value = null; }} align="right" width={320}>
        <ViewMenu />
      </Popover>
      {hasData && <button class="btn ghost" title={cap.active ? 'Clear the display (keeps capturing)' : 'Clear everything'} onClick={onClear}>Clear</button>}
      <button class="btn primary" onClick={() => { drawerOpen.value = true; }}>⚙ Setup</button>
    </header>
  );
}
