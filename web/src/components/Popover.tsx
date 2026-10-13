import { useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import type { ComponentChildren, RefObject } from 'preact';

interface Props {
  open: boolean;
  anchor: RefObject<HTMLElement>;
  onClose: () => void;
  align?: 'left' | 'right';
  width?: number;
  children: ComponentChildren;
  class?: string;
}

/** Fixed-position popover below an anchor; closes on outside click / Esc. */
export function Popover({ open, anchor, onClose, align = 'left', width, children, class: cls }: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [pos, setPos] = useState<{ top: number; left?: number; right?: number }>({ top: 0 });

  useLayoutEffect(() => {
    if (!open || !anchor.current) return;
    const r = anchor.current.getBoundingClientRect();
    const top = r.bottom + 6;
    if (align === 'right') setPos({ top, right: Math.max(8, window.innerWidth - r.right) });
    else setPos({ top, left: Math.max(8, Math.min(r.left, window.innerWidth - (width || 320) - 8)) });
  }, [open, anchor, align, width]);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      const t = e.target as Node;
      if (ref.current && ref.current.contains(t)) return;
      if (anchor.current && anchor.current.contains(t)) return;
      onClose();
    };
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') { e.stopPropagation(); onClose(); } };
    document.addEventListener('mousedown', onDoc);
    document.addEventListener('keydown', onKey, true);
    return () => { document.removeEventListener('mousedown', onDoc); document.removeEventListener('keydown', onKey, true); };
  }, [open, onClose, anchor]);

  if (!open) return null;
  return (
    <div ref={ref} class={`popover ${cls || ''}`} style={{ position: 'fixed', top: pos.top, left: pos.left, right: pos.right, width }} role="dialog">
      {children}
    </div>
  );
}
