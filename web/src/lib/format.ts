export function fmtMs(ms: number): string {
  if (ms < 1000) return Math.round(ms) + 'ms';
  if (ms < 60000) return (ms / 1000).toFixed(ms < 10000 ? 2 : 1) + 's';
  return (ms / 60000).toFixed(1) + 'm';
}

/** HH:MM:SS.mmm in UTC, matching the legacy viewer. */
export function fmtTs(ts: number | undefined, fallback?: string): string {
  if (ts === undefined) return fallback ? fallback.slice(0, 12) : '';
  try { return new Date(ts).toISOString().slice(11, 23); } catch { return fallback ? fallback.slice(0, 12) : ''; }
}

export function fmtClock(ts: number): string {
  try { return new Date(ts).toISOString().slice(11, 19); } catch { return ''; }
}
/** Wall-clock time in the viewer's zone, for "since 09:44:21" style labels. */
export function fmtLocalClock(ts: number): string {
  try { return new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }); } catch { return ''; }
}

/** "io-flow-engine-7d9f8c6b5-x1k2q" → "flow-engine"; other long names get truncated. */
export function shortPod(p: string | undefined): string {
  if (!p) return '';
  const m = /^io-(.+?)(?:-[a-f0-9]{6,})+/.exec(p);
  return m ? m[1] : p.length > 22 ? p.slice(0, 20) + '..' : p;
}

export function shortReq(r: string | undefined): string {
  return r ? r.slice(0, 8) : '';
}

export type DurBucket = 'fast' | 'ok' | 'warn' | 'slow';
export function durBucket(ms: number): DurBucket {
  if (ms < 100) return 'fast';
  if (ms < 500) return 'ok';
  if (ms < 2000) return 'warn';
  return 'slow';
}

export function hexToRgba(hex: string | undefined, a: number): string {
  const m = /^#?([0-9a-f]{6})$/i.exec(hex || '');
  if (!m) return `rgba(88,166,255,${a})`;
  const n = parseInt(m[1], 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${a})`;
}

export function fmtRemaining(ms: number): string {
  if (ms <= 0) return 'expired';
  const tm = Math.floor(ms / 60000);
  if (tm < 60) return `${tm}m left`;
  return `${Math.floor(tm / 60)}h ${tm % 60}m left`;
}

export function fmtElapsed(ms: number): string {
  const e = Math.max(0, Math.floor(ms / 1000));
  return `${Math.floor(e / 60)}:${String(e % 60).padStart(2, '0')}`;
}

export function fmtCount(n: number): string {
  return n.toLocaleString('en-US');
}

export function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** UUID-ish tenant ids are shortened to their first 8 chars; names stay as-is. */
export function shortTenant(t: string | undefined): string {
  if (!t) return '';
  return /^[0-9a-f]{8}-/i.test(t) || t.length > 16 ? t.slice(0, 8) : t;
}
