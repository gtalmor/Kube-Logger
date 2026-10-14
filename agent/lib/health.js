'use strict';
// Per-namespace stream health. stern's pod watch does not recover from a
// network change: client-go retries "Watch failed" every second with a stale
// resolver until the process is restarted. StreamHealth counts failures in a
// sliding window, says when to restart the stream (with exponential backoff
// while the network stays broken) and rate-limits how often a failure line is
// forwarded to the viewer, so a dead proxy is one banner rather than a toast
// per namespace per second.

const KLOG_RE = /^[EWIF]\d{4} \d\d:\d\d:\d\d\.\d+\s+\d+\s+\S+\]\s*/;   // E1014 09:44:06.439055 99686 retrywatcher.go:129]

/** The human part of a client-go failure line: klog prefix and the quoted request URL dropped. */
function failureReason(msg) {
  let s = String(msg || '').trim().replace(KLOG_RE, '');
  const m = /err="((?:[^"\\]|\\.)*)"/.exec(s);
  if (m) s = m[1].replace(/\\"/g, '"');
  s = s.replace(/^"?Watch failed"?\s*/i, '').replace(/^Get "https?:\/\/[^"]*":\s*/, '');
  return s.slice(0, 300);
}

class StreamHealth {
  constructor({ failLimit = 15, windowMs = 60000, baseDelayMs = 3000, maxDelayMs = 60000, forwardEveryMs = 60000, now = Date.now } = {}) {
    this.failLimit = failLimit; this.windowMs = windowMs; this.baseDelayMs = baseDelayMs;
    this.maxDelayMs = maxDelayMs; this.forwardEveryMs = forwardEveryMs; this.now = now;
    this.ns = new Map();
  }
  _get(ns) {
    let s = this.ns.get(ns);
    if (!s) this.ns.set(ns, s = { fails: [], restarts: 0, degradedSince: null, reason: '', lastForwardAt: -Infinity });
    return s;
  }
  /**
   * A watch/connect failure line for `ns`. Returns what to do with it:
   * forward (send this line to the viewer; at most one per forwardEveryMs),
   * restart (respawn the stream after delayMs), plus the state for a
   * stream-status message.
   */
  failure(ns, reason) {
    const s = this._get(ns);
    const t = this.now();
    s.fails.push(t);
    while (s.fails.length && t - s.fails[0] > this.windowMs) s.fails.shift();
    s.reason = reason || s.reason;
    const forward = t - s.lastForwardAt >= this.forwardEveryMs;
    if (forward) s.lastForwardAt = t;
    let restart = false, delayMs = 0, failures = s.fails.length;
    if (s.fails.length >= this.failLimit) {
      restart = true;
      delayMs = Math.min(this.baseDelayMs * 2 ** s.restarts, this.maxDelayMs);
      s.restarts++;
      if (s.degradedSince === null) s.degradedSince = t;
      s.fails = [];
    }
    return { forward, restart, delayMs, failures, restarts: s.restarts, degraded: s.degradedSince !== null, since: s.degradedSince, reason: s.reason };
  }
  /** Data flowed for `ns`: failures and backoff reset. True when this ends a degraded period. */
  healthy(ns) {
    const s = this.ns.get(ns);
    if (!s) return false;
    const was = s.degradedSince !== null;
    s.fails = []; s.restarts = 0; s.degradedSince = null;
    return was;
  }
  status(ns) {
    const s = this.ns.get(ns);
    return s ? { degraded: s.degradedSince !== null, since: s.degradedSince, restarts: s.restarts, reason: s.reason } : { degraded: false, since: null, restarts: 0, reason: '' };
  }
  forget(ns) { this.ns.delete(ns); }
}

module.exports = { StreamHealth, failureReason, KLOG_RE };
