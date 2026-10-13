import { signal } from '@preact/signals';

export interface Toast { id: number; text: string; kind?: 'info' | 'error' | 'ok' }
export const toasts = signal<Toast[]>([]);
let seq = 0;

export function toast(text: string, kind: Toast['kind'] = 'info', ms = 2500): void {
  const id = ++seq;
  toasts.value = [...toasts.value.slice(-3), { id, text, kind }];
  setTimeout(() => { toasts.value = toasts.value.filter(t => t.id !== id); }, ms);
}
