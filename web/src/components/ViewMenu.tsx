import { useRef } from 'preact/hooks';
import { autoScroll, bufferCap, BUFFER_CHOICES, effectiveTheme, jumpToFirstErrorOnEnd, palette, resetPalette, setPaletteColor, theme, wrap } from '../state/ui';
import { PALETTE_LABELS, type LevelPalette } from '../lib/colors';
import { store } from '../state/app';
import { toast } from '../state/toasts';
import { readFileInto } from './Welcome';
import { fmtCount } from '../lib/format';

function exportVisible(): void {
  const text = [...store.visibleRaw()].join('\n');
  const b = new Blob([text], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(b);
  a.download = `logs-${new Date().toISOString().slice(0, 19).replace(/[:.]/g, '-')}.txt`;
  a.click();
  setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  toast(`Exported ${fmtCount(store.ids.length)} lines`, 'ok');
}

export function ViewMenu() {
  const file = useRef<HTMLInputElement>(null);
  const t = theme.value;
  const pal = palette.value[effectiveTheme()];
  return (
    <div class="view-menu">
      <label class="toggle"><input type="checkbox" checked={autoScroll.value} onChange={e => { autoScroll.value = (e.target as HTMLInputElement).checked; }} /> Follow new lines (auto-scroll)</label>
      <label class="toggle"><input type="checkbox" checked={wrap.value} onChange={e => { wrap.value = (e.target as HTMLInputElement).checked; }} /> Wrap long lines</label>
      <label class="toggle"><input type="checkbox" checked={jumpToFirstErrorOnEnd.value} onChange={e => { jumpToFirstErrorOnEnd.value = (e.target as HTMLInputElement).checked; }} /> Jump to first error when a capture ends</label>
      <div class="pop-divider" />
      <h4>Theme</h4>
      <div class="pop-inline">
        <div class="seg">
          {(['system', 'light', 'dark'] as const).map(k => <button key={k} class={t === k ? 'on' : ''} onClick={() => { theme.value = k; }}>{k[0].toUpperCase() + k.slice(1)}</button>)}
        </div>
      </div>
      <h4>Level colours <span class="link" onClick={resetPalette}>Reset</span></h4>
      <div class="palette">
        {(Object.keys(PALETTE_LABELS) as (keyof LevelPalette)[]).map(k => (
          <label key={k} class="pal-row"><input type="color" value={pal[k]} onInput={e => setPaletteColor(k, (e.target as HTMLInputElement).value)} /> {PALETTE_LABELS[k]}</label>
        ))}
      </div>
      <div class="pop-hint">Row tints derive from these, per theme.</div>
      <div class="pop-divider" />
      <h4>Buffer size</h4>
      <div class="pop-inline">
        <select class="input" value={String(bufferCap.value)} onChange={e => { bufferCap.value = +(e.target as HTMLSelectElement).value; }}>
          {BUFFER_CHOICES.map(n => <option key={n} value={String(n)}>{fmtCount(n)} lines (~{Math.round(n * 0.6 / 1000)} MB)</option>)}
        </select>
      </div>
      <div class="pop-hint">Older lines are dropped when the buffer is full. The agent keeps 20k and the relay 20k for replay.</div>
      <div class="pop-divider" />
      <div class="pop-inline">
        <button class="btn sm" onClick={exportVisible} disabled={!store.ids.length}>Export visible lines…</button>
        <button class="btn sm" onClick={() => file.current?.click()}>Open log file…</button>
        <input ref={file} type="file" accept=".log,.txt,text/plain" style="display:none" onChange={e => { const f = (e.target as HTMLInputElement).files?.[0]; if (f) readFileInto(f); (e.target as HTMLInputElement).value = ''; }} />
      </div>
    </div>
  );
}
