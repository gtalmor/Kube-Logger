'use strict';
// Bounded ring buffer of captured log lines. Bounded by line count AND by
// byte size so a few huge lines can't blow the budget. Every pushed line gets
// a monotonic index `i` that survives eviction, so consumers can refer to
// lines by index and ask for "everything after N" on reconnect.

class LineRing {
  constructor({ maxLines = 20000, maxBytes = 10 * 1024 * 1024 } = {}) {
    if (!(maxLines > 0)) throw new Error('maxLines must be > 0');
    this.maxLines = maxLines;
    this.maxBytes = maxBytes;
    this.buf = new Array(maxLines);
    this.head = 0;      // slot of the oldest entry
    this.size = 0;      // entries currently held
    this.bytes = 0;     // sum of line byte lengths currently held
    this.total = 0;     // lines ever pushed == next index to assign
    this.nsCounts = new Map();
  }

  get firstIndex() { return this.total - this.size; }
  get lastIndex()  { return this.total - 1; }

  push(ns, line) {
    const i = this.total++;
    const b = Buffer.byteLength(line, 'utf8');
    if (this.size === this.maxLines) this._evict();
    this.buf[(this.head + this.size) % this.maxLines] = { i, ns, line, b };
    this.size++;
    this.bytes += b;
    this.nsCounts.set(ns, (this.nsCounts.get(ns) || 0) + 1);
    // Keep at least one line even if it alone exceeds the byte budget.
    while (this.bytes > this.maxBytes && this.size > 1) this._evict();
    return i;
  }

  _evict() {
    const e = this.buf[this.head];
    this.buf[this.head] = undefined;
    this.head = (this.head + 1) % this.maxLines;
    this.size--;
    this.bytes -= e.b;
    const c = (this.nsCounts.get(e.ns) || 1) - 1;
    if (c <= 0) this.nsCounts.delete(e.ns); else this.nsCounts.set(e.ns, c);
  }

  countFor(ns) { return this.nsCounts.get(ns) || 0; }

  get(i) {
    if (i < this.firstIndex || i > this.lastIndex) return undefined;
    const e = this.buf[(this.head + (i - this.firstIndex)) % this.maxLines];
    return { i: e.i, ns: e.ns, line: e.line };
  }

  // Lines with index >= from, oldest first, at most `limit`. `from` below
  // firstIndex is clamped (those lines were evicted).
  slice(from, limit = Infinity) {
    const out = [];
    let i = Math.max(from, this.firstIndex);
    for (; i <= this.lastIndex && out.length < limit; i++) out.push(this.get(i));
    return out;
  }

  clear() {
    this.buf = new Array(this.maxLines);
    this.head = 0; this.size = 0; this.bytes = 0;
    this.nsCounts.clear();
    // `total` deliberately keeps counting so indices stay unique for the
    // lifetime of a capture.
  }
}

module.exports = { LineRing };
