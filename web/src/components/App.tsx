import { useEffect } from 'preact/hooks';
import { Header } from './Header';
import { AuthBanner, ErrorStrip, FlowTimelineStrip, StreamStrip } from './Strips';
import { LogList } from './LogList';
import { Welcome, readFileInto } from './Welcome';
import { SidePanel } from './SidePanel';
import { StatusBar } from './StatusBar';
import { SetupDrawer } from './SetupDrawer';
import { Toasts } from './Toasts';
import { AnchoredPopover } from './AnchoredPopover';
import { useKeyboard } from './useKeyboard';
import { store, jumpTo, curErr } from '../state/app';
import { capture, replaying } from '../state/connection';
import { jumpToFirstErrorOnEnd } from '../state/ui';

export function App() {
  useKeyboard();
  const u = store.usage.value;
  const hasData = u.size > 0 || replaying.value;

  // Jump to the first error when a capture ends (legacy behaviour, optional).
  const active = capture.value.active;
  useEffect(() => {
    if (active || !jumpToFirstErrorOnEnd.value || !store.errIds.length) return;
    const t = setTimeout(() => { curErr.value = 0; jumpTo(store.errIds[0], { clearFilters: false }); }, 400);
    return () => clearTimeout(t);
  }, [active]);

  // Drop a file anywhere.
  useEffect(() => {
    const over = (e: DragEvent) => e.preventDefault();
    const drop = (e: DragEvent) => { e.preventDefault(); const f = e.dataTransfer?.files[0]; if (f) readFileInto(f); };
    document.body.addEventListener('dragover', over);
    document.body.addEventListener('drop', drop);
    return () => { document.body.removeEventListener('dragover', over); document.body.removeEventListener('drop', drop); };
  }, []);

  return (
    <div class="app">
      <Header />
      <AuthBanner />
      <StreamStrip />
      <ErrorStrip />
      <FlowTimelineStrip />
      <div class="main">
        {hasData ? <LogList /> : <Welcome />}
        <SidePanel />
      </div>
      <StatusBar />
      <SetupDrawer />
      <AnchoredPopover />
      <Toasts />
    </div>
  );
}
