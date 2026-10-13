import { useRef, useState } from 'preact/hooks';
import { loadText } from '../state/app';
import { drawerOpen } from '../state/ui';
import { agentConnected, auth, sessionId } from '../state/connection';
import { selectedNs, startCapture } from '../state/setup';
import { toast } from '../state/toasts';

export function readFileInto(file: File): void {
  const r = new FileReader();
  r.onload = ev => loadText(String(ev.target?.result || ''), file.name);
  r.onerror = () => toast(`Could not read ${file.name}`, 'error');
  r.readAsText(file);
}

export function Welcome() {
  const input = useRef<HTMLInputElement>(null);
  const [over, setOver] = useState(false);
  const canResume = agentConnected.value && !!auth.value?.ok && selectedNs.value.length > 0;
  const noSession = !sessionId;
  return (
    <div class="welcome">
      <div class="welcome-card">
        <div class="welcome-logo">◉</div>
        <h2>Waiting for logs</h2>
        {noSession
          ? <p class="muted">No session in the URL. Run <code>kube-logger-agent</code> and open the URL it prints.</p>
          : <p class="muted">Pick a profile and namespaces in <b>Setup</b>, resume your last capture, or drop a log file here.</p>}
        <div class="welcome-actions">
          {!noSession && <button class="btn primary" onClick={() => { drawerOpen.value = true; }}>Open Setup</button>}
          {!noSession && <button class="btn" disabled={!canResume} title={canResume ? `Start capturing ${selectedNs.value.join(', ')}` : 'Needs a connected agent, valid auth and remembered namespaces'} onClick={() => { if (startCapture()) toast(`Starting ${selectedNs.value.join(', ')}…`); }}>
            Resume last capture{selectedNs.value.length ? ` (${selectedNs.value.length})` : ''}
          </button>}
          <button class="btn ghost" onClick={() => input.current?.click()}>Open log file…</button>
        </div>
        <div
          class={`dropzone ${over ? 'over' : ''}`}
          onDragOver={e => { e.preventDefault(); setOver(true); }}
          onDragLeave={() => setOver(false)}
          onDrop={e => { e.preventDefault(); setOver(false); const f = e.dataTransfer?.files[0]; if (f) readFileInto(f); }}
          onClick={() => input.current?.click()}
        >
          Drop a stern log file here
        </div>
        <input ref={input} type="file" accept=".log,.txt,text/plain" style="display:none" onChange={e => { const f = (e.target as HTMLInputElement).files?.[0]; if (f) readFileInto(f); (e.target as HTMLInputElement).value = ''; }} />
        <p class="faint welcome-keys"><kbd>/</kbd> search · <kbd>n</kbd>/<kbd>p</kbd> next/prev error · <kbd>Esc</kbd> close</p>
      </div>
    </div>
  );
}
