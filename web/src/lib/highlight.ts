// Split a message into segments for rendering: plain text, user highlight
// terms (each with a colour index) and search matches. Produces a flat list
// instead of nested HTML replace chains, so rendering never touches innerHTML.

import { escapeRegex } from './format';

export interface Segment { text: string; hi?: number; search?: boolean }

export interface HighlightSpec { terms: RegExp[]; search: RegExp | null }

export function compileHighlights(terms: readonly string[], search: string): HighlightSpec {
  const out: RegExp[] = [];
  for (const t of terms) {
    if (!t) { out.push(/$^/); continue; }
    try { out.push(new RegExp(escapeRegex(t), 'gi')); } catch { out.push(/$^/); }
  }
  let s: RegExp | null = null;
  const q = search.trim();
  if (q) {
    try { s = new RegExp(q, 'gi'); } catch { s = new RegExp(escapeRegex(q), 'gi'); }
  }
  return { terms: out, search: s };
}

interface Mark { start: number; end: number; hi?: number; search?: boolean }

export function segmentize(text: string, spec: HighlightSpec | null): Segment[] {
  if (!text) return [];
  if (!spec || (!spec.terms.length && !spec.search)) return [{ text }];
  const marks: Mark[] = [];
  spec.terms.forEach((re, idx) => {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    let guard = 0;
    while ((m = re.exec(text)) && guard++ < 2000) {
      if (m[0].length === 0) { re.lastIndex++; continue; }
      marks.push({ start: m.index, end: m.index + m[0].length, hi: idx });
    }
  });
  if (spec.search) {
    const re = spec.search;
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    let guard = 0;
    while ((m = re.exec(text)) && guard++ < 2000) {
      if (m[0].length === 0) { re.lastIndex++; continue; }
      marks.push({ start: m.index, end: m.index + m[0].length, search: true });
    }
  }
  if (!marks.length) return [{ text }];
  // Resolve overlaps per character: search beats highlight; lower hi index wins.
  const owner = new Int16Array(text.length).fill(-1); // -1 none, -2 search, >=0 hi index
  for (const mk of marks) {
    for (let i = mk.start; i < mk.end; i++) {
      if (mk.search) owner[i] = -2;
      else if (owner[i] === -1 || (owner[i] >= 0 && owner[i] > (mk.hi as number))) owner[i] = mk.hi as number;
    }
  }
  const out: Segment[] = [];
  let cur = owner[0], from = 0;
  for (let i = 1; i <= text.length; i++) {
    if (i === text.length || owner[i] !== cur) {
      const seg: Segment = { text: text.slice(from, i) };
      if (cur === -2) seg.search = true; else if (cur >= 0) seg.hi = cur;
      out.push(seg);
      from = i; cur = owner[i];
    }
  }
  return out;
}
