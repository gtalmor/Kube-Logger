import { store } from '../state/app';
import { cycleTri, filters } from '../state/filters';
import { autoScroll } from '../state/ui';
import { ensureNsColor, nsColors, setNsColor } from '../state/setup';
import { fmtCount } from '../lib/format';

function LevelCount({ label, n, level, cls }: { label: string; n: number; level: string; cls: string }) {
  const state = filters.value.level[level];
  return (
    <button class={`sb-count ${cls} ${state ? 'on-' + state : ''}`} title={`${label}: click to include/exclude`} onClick={() => cycleTri('level', level)}>
      <span class="dot" /> <span class="num">{fmtCount(n)}</span> <span class="lbl">{label}</span>
    </button>
  );
}

export function StatusBar() {
  void store.viewVersion.value;
  void store.dataVersion.value;
  const c = store.counts;
  const u = store.usage.value;
  const colors = nsColors.value;
  const nsList = [...store.nsSeen].sort();
  const live = autoScroll.value;
  return (
    <div class="statusbar">
      <div class="sb-counts">
        <span class="sb-total num" title="Visible lines">{fmtCount(c.total)} lines</span>
        <LevelCount label="err" n={c.err} level="ERROR" cls="c-err" />
        <LevelCount label="warn" n={c.warn} level="WARN" cls="c-warn" />
        <LevelCount label="dbg" n={c.dbg} level="DEBUG" cls="c-dbg" />
        <LevelCount label="trc" n={c.trc} level="TRACE" cls="c-trc" />
        <LevelCount label="http" n={c.http} level="HTTP" cls="c-http" />
      </div>
      <div class="sb-ns">
        {nsList.map(ns => {
          const col = colors[ns] || ensureNsColor(ns);
          return (
            <label class="chip ns-chip" key={ns} title={`${ns}: change colour`}>
              <input type="color" value={col} onInput={e => setNsColor(ns, (e.target as HTMLInputElement).value)} />
              <span class="dot" style={{ background: col }} />
              <span>{ns}</span>
              <span class="num faint">{fmtCount(store.nsCounts.get(ns) || 0)}</span>
            </label>
          );
        })}
      </div>
      <div class="sb-right">
        <span class="sb-buffer num" title="Lines held in memory / buffer size · evicted so far">
          {fmtCount(u.size)} / {fmtCount(u.cap)}{u.evicted ? ` · ${fmtCount(u.evicted)} evicted` : ''}
        </span>
        <button class={`sb-live ${live ? 'on' : ''}`} onClick={() => { autoScroll.value = !live; }} title={live ? 'Following new lines (click to pause)' : 'Paused — click or press End to follow'}>
          <span class="dot" /> {live ? 'Live' : 'Paused'}
        </button>
      </div>
    </div>
  );
}
