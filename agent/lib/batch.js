'use strict';
// Coalesces individual log lines into `log-batch` frames: flushes when the
// batch reaches `maxItems` or `maxDelayMs` after the first queued item,
// whichever comes first. Timers are injectable for tests.

class LogBatcher {
  constructor({ maxItems = 200, maxDelayMs = 50, send, setTimer = setTimeout, clearTimer = clearTimeout }) {
    if (typeof send !== 'function') throw new Error('send is required');
    this.maxItems = maxItems;
    this.maxDelayMs = maxDelayMs;
    this.send = send;
    this.setTimer = setTimer;
    this.clearTimer = clearTimer;
    this.items = [];
    this.timer = null;
  }

  get size() { return this.items.length; }

  push(item) {
    this.items.push(item);
    if (this.items.length >= this.maxItems) { this.flush(); return; }
    if (!this.timer) {
      this.timer = this.setTimer(() => { this.timer = null; this.flush(); }, this.maxDelayMs);
      if (this.timer && typeof this.timer.unref === 'function') this.timer.unref();
    }
  }

  flush() {
    if (this.timer) { this.clearTimer(this.timer); this.timer = null; }
    if (this.items.length === 0) return;
    const batch = this.items;
    this.items = [];
    this.send(batch);
  }

  // Drop queued items without sending (they'll be sent another way).
  discard() {
    if (this.timer) { this.clearTimer(this.timer); this.timer = null; }
    this.items = [];
  }
}

module.exports = { LogBatcher };
