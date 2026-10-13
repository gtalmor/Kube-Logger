// Virtualized log view. Reads the store's plain arrays and re-renders on its
// version signals (one render per animation frame at most).
import { useEffect, useLayoutEffect, useRef, useState } from 'preact/hooks';
import { useSignal } from '@preact/signals';
import { useVirtualizer } from './useVirtualizer';
import { LogRow } from './LogRow';
import { store, jumpRequest, currentId } from '../state/app';
import { autoScroll, wrap } from '../state/ui';
import { highlightSpec } from '../state/filters';
import { nsColors } from '../state/setup';

export const ROW_H = 22;

export function LogList() {
  const scrollRef = useRef<HTMLDivElement>(null);
  const expanded = useSignal<Set<number>>(new Set());
  const version = store.viewVersion.value;          // subscribe
  const count = store.ids.length;
  const wrapOn = wrap.value;
  const spec = highlightSpec.value;
  const colors = nsColors.value;
  const [, setTick] = useState(0);
  const lastEvicted = useRef(store.viewEvicted);
  const stickRef = useRef(true);

  const v = useVirtualizer({
    count,
    getScrollElement: () => scrollRef.current,
    estimateSize: i => (expanded.value.has(store.ids[i]) ? 240 : ROW_H),
    getItemKey: i => store.ids[i] ?? i,
    overscan: 24,
  });

  // Stick to the bottom after each data frame; correct for rows evicted off the front.
  useLayoutEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const removed = store.viewEvicted - lastEvicted.current;
    lastEvicted.current = store.viewEvicted;
    if (autoScroll.value && stickRef.current) {
      el.scrollTop = el.scrollHeight;
    } else if (removed > 0) {
      el.scrollTop = Math.max(0, el.scrollTop - removed * ROW_H);
    }
  }, [version, count]);

  // Re-enabling auto-scroll jumps to the tail.
  useEffect(() => {
    if (autoScroll.value) { stickRef.current = true; const el = scrollRef.current; if (el) el.scrollTop = el.scrollHeight; }
  }, [autoScroll.value]);

  // Jump requests.
  const jr = jumpRequest.value;
  useEffect(() => {
    if (!jr) return;
    const k = store.viewIndexOf(jr.id);
    if (k < 0) return;
    autoScroll.value = false;
    stickRef.current = false;
    v.scrollToIndex(k, { align: 'center' });
    // Second pass after measurement settles.
    const t = setTimeout(() => v.scrollToIndex(k, { align: 'center' }), 60);
    return () => clearTimeout(t);
  }, [jr?.tick]);

  const onScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    const dist = el.scrollHeight - el.clientHeight - el.scrollTop;
    if (dist > 40) { if (autoScroll.value) autoScroll.value = false; stickRef.current = false; }
    else if (dist <= 2) { stickRef.current = true; }
  };

  const toggleExpand = (id: number) => {
    const next = new Set(expanded.value);
    if (next.has(id)) next.delete(id); else next.add(id);
    expanded.value = next;
    setTick(t => t + 1);
    requestAnimationFrame(() => v.measure());
  };

  const items = v.getVirtualItems();
  const cur = currentId.value;

  return (
    <div ref={scrollRef} class={`loglist ${wrapOn ? 'wrap' : ''}`} onScroll={onScroll} tabIndex={0}>
      <div class="loglist-inner" style={{ height: v.getTotalSize() }}>
        {items.map(it => {
          const id = store.ids[it.index];
          const line = store.get(id);
          if (!line) return null;
          const prev = it.index > 0 ? store.get(store.ids[it.index - 1]) : undefined;
          const isExp = expanded.value.has(id);
          return (
            <div
              key={it.key}
              data-index={it.index}
              ref={(isExp || wrapOn) ? (el => { if (el) v.measureElement(el); }) : undefined}
              class="loglist-item"
              style={{ transform: `translateY(${it.start}px)` }}
            >
              <LogRow line={line} prev={prev} spec={spec} nsColor={line.ns ? colors[line.ns] : undefined} isCurrent={cur === id} expanded={isExp} onToggleExpand={toggleExpand} />
            </div>
          );
        })}
      </div>
    </div>
  );
}
