// Shaping of stern / client-go stderr lines for display.

/** klog prefix: `E1014 09:44:06.439055 99686 retrywatcher.go:129] ` */
export const KLOG_RE = /^[EWIF]\d{4} \d\d:\d\d:\d\d\.\d+\s+\d+\s+\S+\]\s*/;
/** Lines that mean "the stream can't reach the cluster", which the agent rate-limits and may restart on. */
export const WATCH_FAIL_RE = /Watch failed|connection refused|no such host|i\/o timeout|TLS handshake timeout/i;

export function stripKlog(msg: string): string {
  return msg.replace(KLOG_RE, '');
}

/** The human part of a failure: klog prefix, `err="…"` quoting and the request URL dropped. */
export function failureReason(msg: string): string {
  let s = stripKlog(String(msg || '').trim());
  const m = /err="((?:[^"\\]|\\.)*)"/.exec(s);
  if (m) s = m[1].replace(/\\"/g, '"');
  return s.replace(/^"?Watch failed"?\s*/i, '').replace(/^Get "https?:\/\/[^"]*":\s*/, '').slice(0, 300);
}

/** Why a reason like that happens on this network, when we can tell. Empty when we can't. */
export function hintFor(reason: string): string {
  const nx = /lookup ([^:\s"]+): no such host/.exec(reason);
  if (nx && /proxyconnect/.test(reason)) return `the proxy ${nx[1]} from your kubeconfig doesn't resolve on this network (VPN off?); stern can't reach the cluster API`;
  if (nx) return `${nx[1]} doesn't resolve on this network`;
  if (/proxyconnect/.test(reason)) return 'the kubeconfig proxy is unreachable on this network';
  if (/TLS handshake timeout|i\/o timeout/i.test(reason)) return 'the cluster API is not answering from this network';
  if (/connection refused/i.test(reason)) return 'the cluster API refused the connection';
  return '';
}

/** Dedupe key for repeated stderr lines: digits (timestamps, pids) ignored. */
export function stderrKey(ns: string | undefined, clean: string): string {
  return (ns || '') + '|' + clean.replace(/\d+/g, '#').slice(0, 160);
}
