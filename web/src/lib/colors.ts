// Namespace stripe palette and highlight colours (legacy values preserved so
// existing per-namespace choices still look the same).

export const NS_PALETTE = ['#3fb950', '#58a6ff', '#d29922', '#bc8cff', '#39c5cf', '#ff7b72', '#79c0ff', '#e6db74'];
export const HI_COLORS = ['#e6db74', '#a6e22e', '#66d9ef', '#fd971f', '#ae81ff', '#f92672', '#e6db74', '#a1efe4'];
export const FALLBACK_NS_COLOR = '#8b949e';

/** Pick the first palette colour not already used, cycling when exhausted. */
export function nextNsColor(existing: Record<string, string>): string {
  const used = new Set(Object.values(existing));
  return NS_PALETTE.find(p => !used.has(p)) || NS_PALETTE[Object.keys(existing).length % NS_PALETTE.length];
}

export interface LevelPalette { error: string; warn: string; info: string; debug: string; trace: string }
export const PALETTE_DEFAULTS: { dark: LevelPalette; light: LevelPalette } = {
  dark:  { error: '#f85149', warn: '#d29922', info: '#58a6ff', debug: '#8b949e', trace: '#484f58' },
  light: { error: '#cf222e', warn: '#9a6700', info: '#0969da', debug: '#57606a', trace: '#8c959f' },
};
export const PALETTE_LABELS: Record<keyof LevelPalette, string> = {
  error: 'ERROR / FATAL', warn: 'WARN', info: 'INFO / HTTP', debug: 'DEBUG', trace: 'TRACE',
};
