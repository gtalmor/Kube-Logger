// Filter state (search, tri-state maps, hidden patterns/execs, highlights)
// and presets. The store subscribes to `filters` and recomputes its view.
import { computed, signal } from '@preact/signals';
export type TriName = 'level' | 'pod' | 'req' | 'tenant';
import { activeConstraintCount, compilePredicate, emptyFilters, triCycle, type FilterState, type TriFilter } from '../lib/filters';
import { compileHighlights } from '../lib/highlight';
import { loadHiddenPatterns, loadHighlights, loadPresets, presetToFilters, saveHiddenPatterns, saveHighlights, savePresets, type PresetStore } from '../lib/storage';

export const filters = signal<FilterState>({ ...emptyFilters(), hiddenPatterns: loadHiddenPatterns(), highlights: loadHighlights() });
export const predicate = computed(() => compilePredicate(filters.value));
export const highlightSpec = computed(() => compileHighlights(filters.value.highlights, filters.value.search));
export const activeCount = computed(() => activeConstraintCount(filters.value));
export const presets = signal<PresetStore>(loadPresets());
export const currentPreset = computed(() => presets.value.current);

function update(patch: Partial<FilterState>): void {
  const next = { ...filters.value, ...patch };
  filters.value = next;
  if (patch.hiddenPatterns) saveHiddenPatterns(next.hiddenPatterns);
  if (patch.highlights) saveHighlights(next.highlights);
}

export const setSearch = (search: string) => update({ search });
export const setHideTrace = (hideTrace: boolean) => update({ hideTrace });
export const cycleTri = (name: TriName, value: string) => update({ [name]: triCycle(filters.value[name], value) } as Partial<FilterState>);
export const clearTri = (name: TriName) => update({ [name]: {} } as Partial<FilterState>);
export const setTri = (name: TriName, tri: TriFilter) => update({ [name]: tri } as Partial<FilterState>);
export const includeOnly = (name: TriName, value: string) => update({ [name]: { [value]: 'include' } } as Partial<FilterState>);
/** Add one include entry without touching the others (manual tenant ids). */
export const addInclude = (name: TriName, value: string) => update({ [name]: { ...filters.value[name], [value]: 'include' } } as Partial<FilterState>);

export function addHiddenPattern(p: string): void {
  if (!p || filters.value.hiddenPatterns.includes(p)) return;
  update({ hiddenPatterns: [...filters.value.hiddenPatterns, p] });
}
export const removeHiddenPattern = (idx: number) => update({ hiddenPatterns: filters.value.hiddenPatterns.filter((_, i) => i !== idx) });
export const clearHiddenPatterns = () => update({ hiddenPatterns: [] });

export function hideExec(execId: string): void {
  if (!execId || filters.value.hiddenExecIds.includes(execId)) return;
  update({ hiddenExecIds: [...filters.value.hiddenExecIds, execId] });
}
export const unhideExec = (execId: string) => update({ hiddenExecIds: filters.value.hiddenExecIds.filter(e => e !== execId) });
export const clearHiddenExecs = () => update({ hiddenExecIds: [] });

export function addHighlight(t: string): void {
  if (!t || filters.value.highlights.includes(t)) return;
  update({ highlights: [...filters.value.highlights, t] });
}
export const removeHighlight = (idx: number) => update({ highlights: filters.value.highlights.filter((_, i) => i !== idx) });
export const clearHighlights = () => update({ highlights: [] });

/** Clear search, tri-state and trace filters; keep hidden/highlights (legacy Reset). */
export function resetFilters(): void {
  update({ search: '', level: {}, pod: {}, req: {}, tenant: {}, hideTrace: false });
}
/** Clear everything that hides lines, so context around a line is visible. */
export function clearAllHiding(): boolean {
  const f = filters.value;
  const had = !!f.search || Object.keys(f.level).length > 0 || Object.keys(f.pod).length > 0 || Object.keys(f.req).length > 0 || Object.keys(f.tenant).length > 0 || f.hideTrace;
  if (had) update({ search: '', level: {}, pod: {}, req: {}, tenant: {}, hideTrace: false });
  return had;
}

// ── presets ─────────────────────────────────────────────────────────
export function savePreset(name: string): void {
  name = (name || '').trim();
  if (!name) return;
  const f = filters.value;
  const next: PresetStore = { current: name, presets: { ...presets.value.presets, [name]: { ...f, hiddenPatterns: [...f.hiddenPatterns], hiddenExecIds: [...f.hiddenExecIds], highlights: [...f.highlights] } } };
  presets.value = next;
  savePresets(next);
}
export function deletePreset(name: string): void {
  if (!name || !presets.value.presets[name]) return;
  const copy = { ...presets.value.presets };
  delete copy[name];
  const next: PresetStore = { current: presets.value.current === name ? '' : presets.value.current, presets: copy };
  presets.value = next;
  savePresets(next);
}
export function applyPreset(name: string): boolean {
  const p = presets.value.presets[name];
  if (!p) return false;
  const f = presetToFilters(p);
  filters.value = f;
  saveHiddenPatterns(f.hiddenPatterns);
  saveHighlights(f.highlights);
  const next: PresetStore = { ...presets.value, current: name };
  presets.value = next;
  savePresets(next);
  return true;
}
