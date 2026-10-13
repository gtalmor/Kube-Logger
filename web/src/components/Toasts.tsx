import { toasts } from '../state/toasts';

export function Toasts() {
  const list = toasts.value;
  if (!list.length) return null;
  return (
    <div class="toasts" aria-live="polite">
      {list.map(t => <div key={t.id} class={`toast ${t.kind || ''}`}>{t.text}</div>)}
    </div>
  );
}
