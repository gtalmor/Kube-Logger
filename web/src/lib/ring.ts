// Fixed-capacity ring buffer keyed by dense monotonic ids. O(1) get by id.

export class RingBuffer<T extends { id: number }> {
  private buf: (T | undefined)[];
  private head = 0;          // slot of the oldest item
  private _size = 0;
  private _firstId = 0;      // id of the oldest item (valid when size > 0)
  private _nextId = 0;       // id the next pushed item receives

  constructor(private _capacity: number) {
    if (!(_capacity > 0)) throw new Error('capacity must be > 0');
    this.buf = new Array(_capacity);
  }

  get capacity(): number { return this._capacity; }
  get size(): number { return this._size; }
  get firstId(): number { return this._size ? this._firstId : this._nextId; }
  get lastId(): number { return this._nextId - 1; }
  get nextId(): number { return this._nextId; }
  /** Items ever pushed minus items held = items evicted. */
  get evicted(): number { return this._nextId - this._size; }

  /** Push an item whose `id` must equal `nextId`. Returns the evicted item, if any. */
  push(item: T): T | undefined {
    if (item.id !== this._nextId) throw new Error(`id ${item.id} != expected ${this._nextId}`);
    let evicted: T | undefined;
    if (this._size === this._capacity) {
      evicted = this.buf[this.head];
      this.buf[this.head] = undefined;
      this.head = (this.head + 1) % this._capacity;
      this._size--;
      this._firstId++;
    }
    if (this._size === 0) this._firstId = item.id;
    this.buf[(this.head + this._size) % this._capacity] = item;
    this._size++;
    this._nextId++;
    return evicted;
  }

  get(id: number): T | undefined {
    if (this._size === 0 || id < this._firstId || id > this.lastId) return undefined;
    return this.buf[(this.head + (id - this._firstId)) % this._capacity];
  }

  has(id: number): boolean { return this.get(id) !== undefined; }

  /** Shrinking evicts the oldest items through `onEvict`. */
  setCapacity(n: number, onEvict?: (t: T) => void): void {
    if (!(n > 0) || n === this._capacity) return;
    const items = [...this.iter()];
    const drop = Math.max(0, items.length - n);
    for (let k = 0; k < drop; k++) onEvict?.(items[k]);
    const keep = items.slice(drop);
    this._capacity = n;
    this.buf = new Array(n);
    this.head = 0;
    this._size = keep.length;
    this._firstId = keep.length ? keep[0].id : this._nextId;
    for (let k = 0; k < keep.length; k++) this.buf[k] = keep[k];
  }

  *iter(fromId?: number, toId?: number): IterableIterator<T> {
    if (this._size === 0) return;
    const a = Math.max(fromId ?? this._firstId, this._firstId);
    const b = Math.min(toId ?? this.lastId, this.lastId);
    for (let id = a; id <= b; id++) {
      const t = this.get(id);
      if (t !== undefined) yield t;
    }
  }

  clear(): void {
    this.buf = new Array(this._capacity);
    this.head = 0;
    this._size = 0;
    this._firstId = this._nextId;
  }

  /** Forget ids too (used when a new capture starts). */
  reset(): void {
    this.clear();
    this._nextId = 0;
    this._firstId = 0;
  }
}
