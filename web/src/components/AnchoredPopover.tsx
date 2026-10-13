// A single app-level popover anchored to an arbitrary element (node chips,
// failure tags). Only one is open at a time.
import { signal } from '@preact/signals';
import { useEffect, useRef } from 'preact/hooks';
import type { ComponentChildren } from 'preact';

interface Anchored { x: number; y: number; content: ComponentChildren }
export const anchored = signal<Anchored | null>(null);

export function showAnchored(el: HTMLElement, content: ComponentChildren): void {
  const r = el.getBoundingClientRect();
  anchored.value = { x: r.left, y: r.bottom + 4, content };
}
export function closeAnchored(): void { anchored.value = null; }

export function AnchoredPopover() {
  const a = anchored.value;
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!a) return;
    const onDoc = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) anchored.value = null; };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') anchored.value = null; };
    const t = setTimeout(() => { document.addEventListener('mousedown', onDoc); document.addEventListener('keydown', onKey, true); }, 0);
    return () => { clearTimeout(t); document.removeEventListener('mousedown', onDoc); document.removeEventListener('keydown', onKey, true); };
  }, [a]);
  if (!a) return null;
  const left = Math.max(8, Math.min(a.x, window.innerWidth - 360 - 8));
  const top = Math.min(a.y, window.innerHeight - 240);
  return <div ref={ref} class="popover anchored" style={{ position: 'fixed', left, top, width: 360 }}>{a.content}</div>;
}
