// What the side panel is showing.
import { signal } from '@preact/signals';
import { openPanel } from './ui';

export const traceReqId = signal<string | null>(null);
export const inspect = signal<{ title: string; value: unknown } | null>(null);

export function openTrace(reqId: string): void {
  traceReqId.value = reqId;
  openPanel('trace');
}
export function openInspector(title: string, value: unknown): void {
  inspect.value = { title, value };
  openPanel('inspect');
}
