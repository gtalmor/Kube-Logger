// Uploaded IO flow definitions → friendly node titles.
import { signal } from '@preact/signals';
import { loadFlowDefs, parseFlowDef, saveFlowDefs, type FlowDefFile, type FlowDefsStore } from '../lib/storage';

export const flowDefs = signal<FlowDefsStore>(loadFlowDefs());

function rebuild(files: FlowDefFile[]): FlowDefsStore {
  const labels: Record<string, string> = {};
  for (const f of files) Object.assign(labels, f.labels || {});
  const next = { files, labels };
  saveFlowDefs(next);
  return next;
}

export function addFlowDef(json: unknown, filename: string): FlowDefFile | null {
  const def = parseFlowDef(json, filename);
  if (!def) return null;
  flowDefs.value = rebuild([...flowDefs.value.files.filter(f => f.name !== def.name), def]);
  return def;
}
export function removeFlowDef(idx: number): void {
  flowDefs.value = rebuild(flowDefs.value.files.filter((_, i) => i !== idx));
}
export function clearFlowDefs(): void {
  flowDefs.value = rebuild([]);
}
/** Friendly title for a node id, if any definition knows it. */
export const labelOf = (nodeId: string | undefined): string | undefined => (nodeId ? flowDefs.value.labels[nodeId] : undefined);
