import { useEffect } from 'preact/hooks';
import { autoScroll, drawerOpen, openMenu, panelOpen, searchFocusTick } from '../state/ui';
import { filters, setSearch } from '../state/filters';
import { jumpErr } from '../state/app';

const inInput = (e: KeyboardEvent) => {
  const t = e.target as HTMLElement | null;
  return !!t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable);
};

export function useKeyboard(): void {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      if (mod && e.key.toLowerCase() === 'f') { e.preventDefault(); searchFocusTick.value++; return; }
      if (mod && e.key.toLowerCase() === 'e') { e.preventDefault(); jumpErr(e.shiftKey ? 'prev' : 'next'); return; }
      if (e.key === 'Escape') {
        if (openMenu.value) { openMenu.value = null; return; }
        if (drawerOpen.value) { drawerOpen.value = false; return; }
        if (panelOpen.value) { panelOpen.value = false; return; }
        if (inInput(e)) { (e.target as HTMLElement).blur(); }
        if (filters.value.search) setSearch('');
        return;
      }
      if (inInput(e) || mod || e.altKey) return;
      if (e.key === '/') { e.preventDefault(); searchFocusTick.value++; }
      else if (e.key === 'n') jumpErr('next');
      else if (e.key === 'p') jumpErr('prev');
      else if (e.key === 'End') { autoScroll.value = true; }
    };
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, []);
}
