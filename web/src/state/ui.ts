// UI preferences and transient UI state (theme, panel, strips, toasts).
import { effect, signal } from '@preact/signals';
import { loadUiPrefs, saveUiPrefs, type Theme, type UiPrefs } from '../lib/storage';
import { loadPalette, savePalette, type PaletteStore } from '../lib/storage';
import { PALETTE_DEFAULTS, type LevelPalette } from '../lib/colors';

const prefs = loadUiPrefs();
export const theme = signal<Theme>(prefs.theme);
export const wrap = signal<boolean>(prefs.wrap);
export const autoScroll = signal<boolean>(prefs.autoScroll);
export const bufferCap = signal<number>(prefs.bufferCap);
export const panelWidth = signal<number>(prefs.panelWidth);
export const stripsCollapsed = signal<{ errors?: boolean; flow?: boolean }>(prefs.stripsCollapsed);
export const jumpToFirstErrorOnEnd = signal<boolean>(prefs.jumpToFirstErrorOnEnd);

export type PanelTab = 'trace' | 'inspect' | 'slow';
export const panelOpen = signal<boolean>(false);
export const panelTab = signal<PanelTab>('trace');
export const drawerOpen = signal<boolean>(false);
export const openMenu = signal<'filters' | 'view' | null>(null);
export const searchFocusTick = signal(0);

export function openPanel(tab: PanelTab): void { panelTab.value = tab; panelOpen.value = true; }
export function closePanel(): void { panelOpen.value = false; }

export function toggleStrip(name: 'errors' | 'flow'): void {
  stripsCollapsed.value = { ...stripsCollapsed.value, [name]: !stripsCollapsed.value[name] };
}

export const BUFFER_CHOICES = [10000, 25000, 50000, 100000, 250000];

// ── theme ───────────────────────────────────────────────────────────
export const systemDark = signal<boolean>(typeof matchMedia === 'function' ? matchMedia('(prefers-color-scheme: dark)').matches : true);
if (typeof matchMedia === 'function') {
  try { matchMedia('(prefers-color-scheme: dark)').addEventListener('change', e => { systemDark.value = e.matches; }); } catch { /* old browsers */ }
}
export const effectiveTheme = (): 'light' | 'dark' => theme.value === 'system' ? (systemDark.value ? 'dark' : 'light') : theme.value;

// ── level palette (per theme) ───────────────────────────────────────
export const palette = signal<PaletteStore>(loadPalette());
export function setPaletteColor(key: keyof LevelPalette, color: string): void {
  const t = effectiveTheme();
  palette.value = { ...palette.value, [t]: { ...palette.value[t], [key]: color } };
}
export function resetPalette(): void {
  const t = effectiveTheme();
  palette.value = { ...palette.value, [t]: { ...PALETTE_DEFAULTS[t] } };
}

// Persist + apply to the document.
if (typeof document !== 'undefined') {
  effect(() => {
    saveUiPrefs({
      theme: theme.value, wrap: wrap.value, autoScroll: autoScroll.value, bufferCap: bufferCap.value,
      stripsCollapsed: stripsCollapsed.value, panelWidth: panelWidth.value, jumpToFirstErrorOnEnd: jumpToFirstErrorOnEnd.value,
    } satisfies UiPrefs);
  });
  effect(() => {
    const t = theme.value;
    if (t === 'system') document.documentElement.removeAttribute('data-theme');
    else document.documentElement.setAttribute('data-theme', t);
  });
  effect(() => {
    savePalette(palette.value);
    const p = palette.value[effectiveTheme()];
    const r = document.documentElement.style;
    r.setProperty('--lvl-error', p.error);
    r.setProperty('--lvl-warn', p.warn);
    r.setProperty('--lvl-info', p.info);
    r.setProperty('--lvl-debug', p.debug);
    r.setProperty('--lvl-trace', p.trace);
  });
}
