'use strict';
// Per-session history of `log-batch` frames so late-joining viewers can
// replay what was captured before they connected. Stores raw frames (no
// re-serialization on replay) and evicts whole oldest batches until both the
// line-count and byte caps are satisfied.

class BatchHistory {
  constructor({ maxLines = 20000, maxBytes = 10 * 1024 * 1024 } = {}) {
    this.maxLines = maxLines;
    this.maxBytes = maxBytes;
    this.captureId = null;
    this.batches = [];   // { raw, count, bytes, first, last }
    this.lines = 0;
    this.bytes = 0;
  }

  get firstIndex() { return this.batches.length ? this.batches[0].first : -1; }
  get lastIndex()  { return this.batches.length ? this.batches[this.batches.length - 1].last : -1; }

  // `items` is the parsed `items` array of the frame; `raw` the frame text.
  pushBatch(raw, items) {
    if (!Array.isArray(items) || items.length === 0) return;
    const prevLast = this.lastIndex;
    const first = Number.isFinite(items[0].i) ? items[0].i : prevLast + 1;
    const last  = Number.isFinite(items[items.length - 1].i) ? items[items.length - 1].i : first + items.length - 1;
    const bytes = Buffer.byteLength(raw, 'utf8');
    this.batches.push({ raw, count: items.length, bytes, first, last });
    this.lines += items.length;
    this.bytes += bytes;
    while ((this.lines > this.maxLines || this.bytes > this.maxBytes) && this.batches.length > 1) {
      const dropped = this.batches.shift();
      this.lines -= dropped.count;
      this.bytes -= dropped.bytes;
    }
  }

  frames() { return this.batches.map(b => b.raw); }

  clear() { this.batches = []; this.lines = 0; this.bytes = 0; }

  reset(captureId) { this.clear(); this.captureId = captureId || null; }
}

module.exports = { BatchHistory };
