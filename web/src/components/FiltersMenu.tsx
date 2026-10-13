import { useState } from 'preact/hooks';
import { store } from '../state/app';
import {
  addHiddenPattern, addHighlight, applyPreset, clearHiddenExecs, clearHiddenPatterns, clearHighlights, clearTri, cycleTri,
  deletePreset, filters, presets, removeHiddenPattern, removeHighlight, resetFilters, savePreset, setHideTrace, unhideExec,
} from '../state/filters';
import { triHasAny, type TriFilter } from '../lib/filters';
import { shortPod, shortReq, fmtCount } from '../lib/format';
import { toast } from '../state/toasts';

const LEVELS = ['ERROR', 'WARN', 'INFO', 'DEBUG', 'TRACE', 'HTTP'];

function TriList({ name, title, options, filter }: { name: 'level' | 'pod' | 'req'; title: string; options: { value: string; label: string; count?: number }[]; filter: TriFilter }) {
  const [q, setQ] = useState('');
  const shown = q ? options.filter(o => o.label.toLowerCase().includes(q.toLowerCase()) || o.value.toLowerCase().includes(q.toLowerCase())) : options;
  return (
    <section>
      <h4>{title}{triHasAny(filter) && <span class="link" onClick={() => clearTri(name)}>Reset</span>}</h4>
      {options.length > 12 && <div class="pop-inline"><input class="input" placeholder={`Filter ${title.toLowerCase()}…`} value={q} onInput={e => setQ((e.target as HTMLInputElement).value)} /></div>}
      {!shown.length && <div class="pop-empty">None yet</div>}
      <div class="tri-list">
        {shown.slice(0, 200).map(o => {
          const st = filter[o.value];
          return (
            <div key={o.value} class="pop-row" title={`${o.value}\nclick: include → exclude → clear`} onClick={() => cycleTri(name, o.value)}>
              <span class={`tri ${st === 'include' ? 'inc' : st === 'exclude' ? 'exc' : ''}`}>{st === 'include' ? '+' : st === 'exclude' ? '−' : '·'}</span>
              <span class="grow truncate">{o.label}</span>
              {o.count !== undefined && <span class="count">{fmtCount(o.count)}</span>}
            </div>
          );
        })}
      </div>
    </section>
  );
}

function AddInline({ placeholder, onAdd }: { placeholder: string; onAdd: (v: string) => void }) {
  const [v, setV] = useState('');
  const go = () => { const t = v.trim(); if (t) { onAdd(t); setV(''); } };
  return (
    <div class="pop-inline">
      <input class="input" placeholder={placeholder} value={v} onInput={e => setV((e.target as HTMLInputElement).value)} onKeyDown={e => { if (e.key === 'Enter') go(); }} />
      <button class="btn sm" onClick={go}>Add</button>
    </div>
  );
}

export function FiltersMenu() {
  const f = filters.value;
  void store.dataVersion.value;
  const pods = [...store.podCounts.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([p, c]) => ({ value: p, label: shortPod(p), count: c }));
  const reqs = [...store.reqCounts.entries()].sort((a, b) => b[1] - a[1]).map(([r, c]) => ({ value: r, label: shortReq(r), count: c }));
  const execNames = (id: string) => store.flow.execs.get(id)?.name || id.slice(0, 8);
  const ps = presets.value;
  const [presetName, setPresetName] = useState('');
  return (
    <div class="filters-menu">
      <div class="fm-cols">
        <TriList name="level" title="Levels" options={LEVELS.map(v => ({ value: v, label: v }))} filter={f.level} />
        <TriList name="pod" title="Services" options={pods} filter={f.pod} />
        <TriList name="req" title="Requests" options={reqs} filter={f.req} />
      </div>
      <div class="pop-divider" />
      <label class="toggle"><input type="checkbox" checked={f.hideTrace} onChange={e => setHideTrace((e.target as HTMLInputElement).checked)} /> Hide TRACE lines</label>

      <section>
        <h4>Hidden patterns {f.hiddenPatterns.length ? `(${f.hiddenPatterns.length})` : ''}{f.hiddenPatterns.length > 0 && <span class="link" onClick={clearHiddenPatterns}>Clear</span>}</h4>
        {f.hiddenPatterns.map((p, i) => <div key={i} class="pop-row static"><span class="grow truncate mono" title={p}>{p}</span><button class="r-act" onClick={() => removeHiddenPattern(i)}>×</button></div>)}
        <AddInline placeholder="Hide lines containing…" onAdd={addHiddenPattern} />
        {f.hiddenExecIds.length > 0 && (
          <>
            <h4>Hidden flow executions ({f.hiddenExecIds.length})<span class="link" onClick={() => { clearHiddenExecs(); toast('All flows restored'); }}>Restore all</span></h4>
            {f.hiddenExecIds.map(e => <div key={e} class="pop-row static"><span class="grow truncate">{execNames(e)} <span class="faint mono">{e.slice(0, 8)}</span></span><button class="r-act" onClick={() => unhideExec(e)}>×</button></div>)}
          </>
        )}
      </section>

      <section>
        <h4>Highlights {f.highlights.length ? `(${f.highlights.length})` : ''}{f.highlights.length > 0 && <span class="link" onClick={clearHighlights}>Clear</span>}</h4>
        {f.highlights.map((h, i) => <div key={i} class="pop-row static"><span class="sw" style={{ background: `var(--hi-${i % 8})` }} /><span class="grow truncate mono">{h}</span><button class="r-act" onClick={() => removeHighlight(i)}>×</button></div>)}
        <AddInline placeholder="Highlight term…" onAdd={addHighlight} />
      </section>

      <section>
        <h4>Presets</h4>
        <div class="pop-inline">
          <select class="input" value={ps.current} onChange={e => { const n = (e.target as HTMLSelectElement).value; if (n && applyPreset(n)) toast(`Loaded preset "${n}"`); }}>
            <option value="">— choose —</option>
            {Object.keys(ps.presets).sort().map(n => <option key={n} value={n}>{n}</option>)}
          </select>
          <button class="btn sm" disabled={!ps.current} onClick={() => { if (confirm(`Delete preset "${ps.current}"?`)) deletePreset(ps.current); }}>Delete</button>
        </div>
        <div class="pop-inline">
          <input class="input" placeholder="Save current filters as…" value={presetName} onInput={e => setPresetName((e.target as HTMLInputElement).value)} onKeyDown={e => { if (e.key === 'Enter' && presetName.trim()) { savePreset(presetName); toast(`Saved preset "${presetName.trim()}"`); setPresetName(''); } }} />
          <button class="btn sm" disabled={!presetName.trim()} onClick={() => { savePreset(presetName); toast(`Saved preset "${presetName.trim()}"`); setPresetName(''); }}>Save</button>
        </div>
      </section>
      <div class="pop-divider" />
      <div class="pop-inline"><button class="btn sm" onClick={resetFilters}>Reset search, levels, services, requests</button></div>
    </div>
  );
}
