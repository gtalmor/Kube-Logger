// Per-namespace stream health as reported by the agent (`stream-status`):
// a stream is "degraded" while stern keeps failing to reach the cluster and
// the agent is restarting it with backoff. Shown as one banner, not toasts.
import { computed, signal } from '@preact/signals';

export interface StreamStatus { reason: string; restarts: number; since: number | null; retryInMs?: number; at: number }
export const streamStatus = signal<Record<string, StreamStatus>>({});
export const degradedNs = computed(() => Object.keys(streamStatus.value).sort());

export interface StreamStatusMsg { ns?: string; state?: string; reason?: string; restarts?: number; since?: number | null; retryInMs?: number; [k: string]: unknown }
export function applyStreamStatus(m: StreamStatusMsg, now = Date.now()): void {
  if (!m.ns) return;
  if (m.state === 'degraded') {
    streamStatus.value = { ...streamStatus.value, [m.ns]: { reason: String(m.reason || ''), restarts: Number(m.restarts) || 0, since: typeof m.since === 'number' ? m.since : null, retryInMs: m.retryInMs, at: now } };
  } else {
    clearStreamStatus(m.ns);
  }
}
export function clearStreamStatus(ns?: string): void {
  if (ns === undefined) { if (Object.keys(streamStatus.value).length) streamStatus.value = {}; return; }
  if (!(ns in streamStatus.value)) return;
  const next = { ...streamStatus.value };
  delete next[ns];
  streamStatus.value = next;
}
export function isDegraded(ns: string | undefined): boolean {
  return !!ns && ns in streamStatus.value;
}
