import { beforeEach, describe, expect, it } from 'vitest';
import { applyStreamStatus, clearStreamStatus, degradedNs, isDegraded, streamStatus } from './streams';

describe('stream status', () => {
  beforeEach(() => clearStreamStatus());
  it('tracks degraded namespaces and clears on ok', () => {
    applyStreamStatus({ ns: 'b', state: 'degraded', reason: 'no such host', restarts: 2, since: 5 }, 10);
    applyStreamStatus({ ns: 'a', state: 'degraded', reason: 'x' }, 11);
    expect(degradedNs.value).toEqual(['a', 'b']);
    expect(streamStatus.value.b).toEqual({ reason: 'no such host', restarts: 2, since: 5, retryInMs: undefined, at: 10 });
    expect(isDegraded('a')).toBe(true);
    applyStreamStatus({ ns: 'a', state: 'ok' });
    expect(isDegraded('a')).toBe(false);
    expect(degradedNs.value).toEqual(['b']);
    clearStreamStatus();
    expect(degradedNs.value).toEqual([]);
  });
  it('ignores malformed messages', () => {
    applyStreamStatus({ state: 'degraded' });
    expect(degradedNs.value).toEqual([]);
  });
});
