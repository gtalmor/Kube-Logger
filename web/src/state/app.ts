// The single store instance and the glue between filters/prefs and it.
import { effect, signal } from '@preact/signals';
import { LogStore } from './store';
import { filters, predicate, clearAllHiding } from './filters';
import { bufferCap } from './ui';
import { toast } from './toasts';
import { ensureTenantColors } from './tenants';
import type { IngestItem } from './store';

export const store = new LogStore(bufferCap.value, predicate.value);

// Store updates are deferred to a microtask: they bump the store's version
// signals, and doing that synchronously inside the signals batch that
// triggered the effect can be flagged as a cycle.
let firstPred = true;
let pendingPred: { p: typeof predicate.value; hidden: readonly string[] } | null = null;
effect(() => {
  const p = predicate.value;
  const hidden = filters.value.hiddenExecIds;
  if (firstPred) { firstPred = false; return; }
  const first = !pendingPred;
  pendingPred = { p, hidden };
  if (first) queueMicrotask(() => { const x = pendingPred; pendingPred = null; if (x) store.setPredicate(x.p, x.hidden); });
});
effect(() => { const n = bufferCap.value; queueMicrotask(() => store.setCapacity(n)); });
// Assign colours to newly seen tenants outside of render and outside the batch.
effect(() => { void store.dataVersion.value; queueMicrotask(() => ensureTenantColors(store.tenantCounts.keys())); });

/** { id, tick } so the list reacts even when the same id is requested twice. */
export const jumpRequest = signal<{ id: number; tick: number } | null>(null);
export const currentId = signal<number | null>(null);
export const curErr = signal<number>(-1);
let tick = 0;

/** Scroll to a line, clearing filters first if it is hidden. */
export function jumpTo(id: number, opts: { clearFilters?: boolean } = {}): void {
  const where = store.locate(id);
  if (where === 'evicted') { toast(`Line #${id + 1} is no longer in the buffer`); return; }
  if (where === 'filtered') {
    if (opts.clearFilters === false) { toast(`Line #${id + 1} is hidden by the current filters`); return; }
    if (clearAllHiding()) toast(`Cleared filters — showing context around line ${id + 1}`);
    else { toast(`Line #${id + 1} is hidden by a pattern or hidden flow`); return; }
  }
  const e = store.errIndexOf(id);
  if (e >= 0) curErr.value = e;
  currentId.value = id;
  jumpRequest.value = { id, tick: ++tick };
}

export function jumpErr(dir: 'next' | 'prev'): void {
  const n = store.errIds.length;
  if (!n) { toast('No errors'); return; }
  let k = curErr.value;
  k = dir === 'next' ? (k + 1) % n : (k <= 0 ? n - 1 : k - 1);
  curErr.value = k;
  jumpTo(store.errIds[k], { clearFilters: false });
  toast(`Error ${k + 1}/${n}`);
}

/** Load a whole file / pasted text as an offline capture. */
export function loadText(text: string, label = 'file'): void {
  const lines = text.split('\n');
  store.resetForCapture(`local-${Date.now()}`, Date.now(), []);
  const items: IngestItem[] = lines.map(line => ({ line }));
  const n = store.ingest(items, { dedupe: false });
  store.flushNow();
  toast(`Loaded ${n.toLocaleString()} lines from ${label}`, 'ok');
}
