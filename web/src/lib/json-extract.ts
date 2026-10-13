import type { LogLine } from './parse';

/** Find the largest parseable JSON substring in a message (legacy port). */
export function extractJson(msg: string): unknown {
  if (!msg) return null;
  let best: unknown = null, bestLen = 0;
  for (let i = 0; i < msg.length; i++) {
    const c = msg[i];
    if (c !== '{' && c !== '[') continue;
    let depth = 0, inStr = false, escCh = false;
    for (let j = i; j < msg.length; j++) {
      const ch = msg[j];
      if (inStr) {
        if (escCh) escCh = false;
        else if (ch === '\\') escCh = true;
        else if (ch === '"') inStr = false;
      } else {
        if (ch === '"') inStr = true;
        else if (ch === '{' || ch === '[') depth++;
        else if (ch === '}' || ch === ']') {
          depth--;
          if (depth === 0) {
            const cand = msg.slice(i, j + 1);
            try { const p = JSON.parse(cand); if (cand.length > bestLen) { best = p; bestLen = cand.length; } } catch { /* not json */ }
            break;
          }
        }
      }
    }
  }
  return best;
}

/** The JSON a line carries: the structured object for json lines, else the largest embedded JSON. */
export function lineJson(l: LogLine): unknown {
  if (l.kind === 'json' && l.jsonOff !== undefined) {
    try { return JSON.parse(l.raw.slice(l.jsonOff)); } catch { /* fall through */ }
  }
  return extractJson(l.msg || l.raw || '');
}
