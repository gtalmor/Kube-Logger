import { describe, expect, it } from 'vitest';
import { failureReason, hintFor, stderrKey, stripKlog, WATCH_FAIL_RE } from './stderr';

const WATCH = 'E1014 09:44:06.439055 99686 retrywatcher.go:129] "Watch failed" err="Get \\"https://4CA8.gr7.us-east-1.eks.amazonaws.com/api/v1/namespaces/monokee/pods?watch=true\\": proxyconnect tcp: dial tcp: lookup proxy.dmz.gemaltocloud.com: no such host"';

describe('stderr shaping', () => {
  it('strips the klog prefix', () => {
    expect(stripKlog(WATCH).startsWith('"Watch failed"')).toBe(true);
    expect(stripKlog('plain text')).toBe('plain text');
  });
  it('extracts the failure reason', () => {
    expect(failureReason(WATCH)).toBe('proxyconnect tcp: dial tcp: lookup proxy.dmz.gemaltocloud.com: no such host');
    expect(failureReason('dial tcp 1.2.3.4:443: i/o timeout')).toBe('dial tcp 1.2.3.4:443: i/o timeout');
  });
  it('explains common reasons', () => {
    expect(hintFor(failureReason(WATCH))).toMatch(/proxy proxy\.dmz\.gemaltocloud\.com .*VPN off/);
    expect(hintFor('dial tcp: lookup api.example: no such host')).toBe('api.example doesn\'t resolve on this network');
    expect(hintFor('dial tcp 1.2.3.4:443: i/o timeout')).toMatch(/not answering/);
    expect(hintFor('something else')).toBe('');
  });
  it('matches the lines the agent rate-limits', () => {
    expect(WATCH_FAIL_RE.test(WATCH)).toBe(true);
    expect(WATCH_FAIL_RE.test('+ pod-abc › container')).toBe(false);
  });
  it('dedupe key ignores digits and namespace-scopes', () => {
    expect(stderrKey('a', 'x 12:00:01 pid 5')).toBe(stderrKey('a', 'x 12:00:02 pid 6'));
    expect(stderrKey('a', 'x')).not.toBe(stderrKey('b', 'x'));
  });
});
