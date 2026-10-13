import { describe, expect, it } from 'vitest';
import { RingBuffer } from './ring';

const item = (id: number) => ({ id, v: `v${id}` });

describe('RingBuffer', () => {
  it('pushes, evicts oldest, keeps ids stable', () => {
    const r = new RingBuffer<{ id: number; v: string }>(3);
    expect(r.push(item(0))).toBeUndefined();
    r.push(item(1)); r.push(item(2));
    expect(r.size).toBe(3);
    expect(r.push(item(3))?.id).toBe(0);
    expect(r.firstId).toBe(1);
    expect(r.lastId).toBe(3);
    expect(r.evicted).toBe(1);
    expect(r.get(0)).toBeUndefined();
    expect(r.get(2)?.v).toBe('v2');
    expect([...r.iter()].map(x => x.id)).toEqual([1, 2, 3]);
    expect([...r.iter(2)].map(x => x.id)).toEqual([2, 3]);
    expect([...r.iter(0, 1)].map(x => x.id)).toEqual([1]);
  });

  it('rejects out-of-sequence ids', () => {
    const r = new RingBuffer<{ id: number }>(2);
    r.push({ id: 0 });
    expect(() => r.push({ id: 5 })).toThrow();
  });

  it('wraps around many times', () => {
    const r = new RingBuffer<{ id: number }>(4);
    for (let i = 0; i < 1000; i++) r.push({ id: i });
    expect([...r.iter()].map(x => x.id)).toEqual([996, 997, 998, 999]);
    expect(r.get(995)).toBeUndefined();
    expect(r.get(999)?.id).toBe(999);
  });

  it('setCapacity shrinks evicting oldest, grows keeping everything', () => {
    const r = new RingBuffer<{ id: number }>(5);
    for (let i = 0; i < 5; i++) r.push({ id: i });
    const ev: number[] = [];
    r.setCapacity(2, t => ev.push(t.id));
    expect(ev).toEqual([0, 1, 2]);
    expect([...r.iter()].map(x => x.id)).toEqual([3, 4]);
    r.push({ id: 5 });
    expect([...r.iter()].map(x => x.id)).toEqual([4, 5]);
    r.setCapacity(10);
    r.push({ id: 6 });
    expect([...r.iter()].map(x => x.id)).toEqual([4, 5, 6]);
    expect(r.capacity).toBe(10);
  });

  it('clear keeps counting; reset starts over', () => {
    const r = new RingBuffer<{ id: number }>(3);
    r.push({ id: 0 }); r.push({ id: 1 });
    r.clear();
    expect(r.size).toBe(0);
    expect(r.firstId).toBe(2);
    r.push({ id: 2 });
    r.reset();
    r.push({ id: 0 });
    expect(r.get(0)?.id).toBe(0);
  });
});
