// Unit tests for the agent's pure modules (agent/lib/*). Run: npm test.
const { test } = require('node:test');
const assert = require('node:assert/strict');

const V = require('../agent/lib/validate');
const { LineRing } = require('../agent/lib/ring');
const { LogBatcher } = require('../agent/lib/batch');
const W = require('../agent/lib/workloads');
const { isNewerVersion } = require('../agent/lib/version');
const C = require('../agent/lib/config');
const A = require('../agent/lib/awsconfig');
const { StreamHealth, failureReason } = require('../agent/lib/health');

// ── validate ────────────────────────────────────────────────────────
test('validate: namespaces are DNS labels', () => {
  for (const ok of ['default', 'kube-system', 'a', 'io-prod-1', 'x'.repeat(63)]) assert.ok(V.isNamespace(ok), ok);
  for (const bad of ['', 'Default', '-x', 'x-', 'a b', 'a;b', 'a/b', 'x'.repeat(64), 'ns; touch /tmp/pwned', '$(id)', 42, null])
    assert.ok(!V.isNamespace(bad), String(bad));
});

test('validate: clusters, profiles, regions, workloads', () => {
  assert.ok(V.isCluster('my-eks_cluster-1'));
  assert.ok(!V.isCluster('x --region y'));
  assert.ok(!V.isCluster('a;b'));
  assert.ok(V.isProfileName('dev'));
  assert.ok(V.isProfileName('team@acme.com:role+1'));
  assert.ok(!V.isProfileName('dev; rm -rf ~'));
  assert.ok(!V.isProfileName('a b'));
  assert.ok(!V.isProfileName('ünïcode'));
  assert.ok(V.isRegion('us-east-1'));
  assert.ok(V.isRegion('ap-southeast-2'));
  assert.ok(!V.isRegion('us-east'));
  assert.ok(!V.isRegion('US-EAST-1'));
  assert.ok(V.isWorkload('api-gateway'));
  assert.ok(V.isWorkload('io.flow-engine'));
  assert.ok(!V.isWorkload('-bad'));
  assert.ok(!V.isWorkload('a b'));
  assert.ok(V.isWorkloadList(['a', 'b']));
  assert.ok(V.isWorkloadList([]));
  assert.ok(!V.isWorkloadList(['a', 'b c']));
  assert.ok(!V.isWorkloadList('a'));
  assert.ok(!V.isWorkloadList(new Array(V.MAX_WORKLOADS + 1).fill('a')));
});

test('validate: assertValid throws terse errors without echoing input', () => {
  assert.equal(V.assertValid('namespace', 'ok'), 'ok');
  assert.throws(() => V.assertValid('namespace', 'bad value; rm'), /^Error: invalid namespace$/);
  assert.throws(() => V.assertValid('nope', 'x'), /unknown validation kind/);
});

test('validate: namespaceList normalizes string/array and dedupes', () => {
  assert.deepEqual(V.namespaceList('a'), ['a']);
  assert.deepEqual(V.namespaceList(['a', 'b', 'a', '', null]), ['a', 'b']);
  assert.throws(() => V.namespaceList(['a', 'B']), /invalid namespace/);
});

test('validate: filterMap keeps only valid entries', () => {
  assert.deepEqual(V.filterMap(undefined), {});
  assert.deepEqual(V.filterMap({ ns1: ['w1', 'w2'], ns2: null }), { ns1: ['w1', 'w2'] });
  assert.throws(() => V.filterMap({ 'bad ns': ['w'] }), /invalid namespace/);
  assert.throws(() => V.filterMap({ ns: ['bad w'] }), /invalid workloadList/);
  assert.throws(() => V.filterMap([]), /invalid filters/);
});

// ── ring ────────────────────────────────────────────────────────────
test('ring: indices are monotonic across eviction and countFor tracks', () => {
  const r = new LineRing({ maxLines: 3, maxBytes: 1e6 });
  assert.equal(r.push('a', 'l0'), 0);
  assert.equal(r.push('a', 'l1'), 1);
  assert.equal(r.push('b', 'l2'), 2);
  assert.equal(r.size, 3);
  assert.equal(r.push('b', 'l3'), 3);           // evicts l0
  assert.equal(r.size, 3);
  assert.equal(r.firstIndex, 1);
  assert.equal(r.lastIndex, 3);
  assert.equal(r.total, 4);
  assert.equal(r.countFor('a'), 1);
  assert.equal(r.countFor('b'), 2);
  assert.equal(r.get(0), undefined);
  assert.deepEqual(r.get(1), { i: 1, ns: 'a', line: 'l1' });
  assert.deepEqual(r.slice(0).map(x => x.i), [1, 2, 3]);   // clamps to firstIndex
  assert.deepEqual(r.slice(2, 1).map(x => x.i), [2]);
  assert.deepEqual(r.slice(99), []);
});

test('ring: byte cap evicts oldest but keeps at least one line', () => {
  const r = new LineRing({ maxLines: 100, maxBytes: 10 });
  r.push('a', '12345');
  r.push('a', '67890');
  assert.equal(r.size, 2);
  r.push('a', 'x');            // 11 bytes → evict first
  assert.equal(r.size, 2);
  assert.equal(r.firstIndex, 1);
  r.push('a', 'y'.repeat(50)); // alone exceeds cap; still kept
  assert.equal(r.size, 1);
  assert.equal(r.firstIndex, 3);
});

test('ring: wraparound preserves order and clear keeps counting', () => {
  const r = new LineRing({ maxLines: 4, maxBytes: 1e6 });
  for (let i = 0; i < 10; i++) r.push('ns', `line${i}`);
  assert.deepEqual(r.slice(0).map(x => x.line), ['line6', 'line7', 'line8', 'line9']);
  r.clear();
  assert.equal(r.size, 0);
  assert.equal(r.countFor('ns'), 0);
  assert.equal(r.push('ns', 'after'), 10);
});

// ── batch ───────────────────────────────────────────────────────────
test('batch: flushes on count, on timer, and on demand; never sends empty', () => {
  const sent = [];
  const timers = [];
  const b = new LogBatcher({
    maxItems: 3, maxDelayMs: 50, send: x => sent.push(x),
    setTimer: (fn) => { timers.push(fn); return timers.length; },
    clearTimer: (id) => { timers[id - 1] = null; },
  });
  b.push(1); b.push(2);
  assert.equal(sent.length, 0);
  assert.equal(b.size, 2);
  b.push(3);                       // hits maxItems
  assert.deepEqual(sent, [[1, 2, 3]]);
  assert.equal(timers.filter(Boolean).length, 0, 'timer cleared on count flush');
  b.push(4);
  assert.equal(timers.filter(Boolean).length, 1);
  timers.find(Boolean)();          // fire timer
  assert.deepEqual(sent[1], [4]);
  b.flush();                       // nothing queued
  assert.equal(sent.length, 2);
});

// ── workloads ───────────────────────────────────────────────────────
test('workloads: workloadOf strips ReplicaSet hash, podQuery escapes', () => {
  assert.equal(W.workloadOf('api-7d9f8c6b5-x1k2q', 'ReplicaSet', 'api-7d9f8c6b5'), 'api');
  assert.equal(W.workloadOf('redis-0', 'StatefulSet', 'redis'), 'redis');
  assert.equal(W.workloadOf('bare', '', ''), 'bare');
  assert.equal(W.podQuery([]), '.*');
  assert.equal(W.podQuery(null), '.*');
  assert.equal(W.podQuery(['api', 'a.b']), '^(api|a\\.b)(-|$)');
  assert.ok(new RegExp(W.podQuery(['redis'])).test('redis-0'));
  assert.ok(!new RegExp(W.podQuery(['redis'])).test('redis2-0'));
});

test('workloads: parsePodsOutput groups and sorts', () => {
  const out = W.parsePodsOutput('api-7d9f8c6b5-a\tReplicaSet\tapi-7d9f8c6b5\napi-7d9f8c6b5-b\tReplicaSet\tapi-7d9f8c6b5\nredis-0\tStatefulSet\tredis\n\n');
  assert.deepEqual(out, [{ name: 'api', count: 2 }, { name: 'redis', count: 1 }]);
  assert.deepEqual(W.parsePodsOutput(''), []);
});

// ── version ─────────────────────────────────────────────────────────
test('version: isNewerVersion', () => {
  assert.ok(isNewerVersion('0.3.0', '0.2.10'));
  assert.ok(isNewerVersion('1.0', '0.9.9'));
  assert.ok(!isNewerVersion('0.2.10', '0.2.10'));
  assert.ok(!isNewerVersion('0.2.9', '0.2.10'));
  assert.ok(!isNewerVersion('0.2', '0.2.0'));
});

// ── config ──────────────────────────────────────────────────────────
test('config: string and object cluster forms normalize to {name, region}', () => {
  const cfg = C.normalizeConfig({
    region: 'us-east-1',
    clusters: { dev: 'eks-dev', eu: { name: 'eks-eu', region: 'eu-west-1' }, junk: 42, noname: { region: 'x' } },
    disabledProfiles: ['hidden'],
  });
  assert.deepEqual(cfg.clusters, { dev: { name: 'eks-dev', region: 'us-east-1' }, eu: { name: 'eks-eu', region: 'eu-west-1' } });
  assert.equal(C.clusterFor(cfg, 'eu'), 'eks-eu');
  assert.equal(C.regionFor(cfg, 'eu'), 'eu-west-1');
  assert.equal(C.regionFor(cfg, 'dev'), 'us-east-1');
  assert.equal(C.regionFor(cfg, 'unknown'), 'us-east-1');
  assert.equal(C.clusterFor(cfg, 'unknown'), undefined);
  assert.ok(cfg.disabledProfiles.has('hidden'));
});

test('config: normalizeConfig tolerates garbage and empty input', () => {
  const cfg = C.normalizeConfig(null, { region: 'eu-central-1' });
  assert.equal(cfg.region, 'eu-central-1');
  assert.deepEqual(cfg.clusters, {});
  assert.equal(cfg.disabledProfiles.size, 0);
});

test('config: withClusterMapping round-trips and keeps the compact form when possible', () => {
  let j = C.withClusterMapping({ region: 'us-east-1', clusters: { a: 'x' } }, 'b', 'eks-b', 'us-east-1');
  assert.deepEqual(j.clusters, { a: 'x', b: 'eks-b' });
  j = C.withClusterMapping(j, 'c', 'eks-c', 'eu-west-1');
  assert.deepEqual(j.clusters.c, { name: 'eks-c', region: 'eu-west-1' });
  const cfg = C.normalizeConfig(j);
  assert.equal(C.clusterFor(cfg, 'c'), 'eks-c');
  assert.equal(C.regionFor(cfg, 'c'), 'eu-west-1');
  assert.equal(C.regionFor(cfg, 'b'), 'us-east-1');
  // Does not mutate the input.
  const orig = { clusters: {} };
  C.withClusterMapping(orig, 'p', 'c', 'us-east-1');
  assert.deepEqual(orig, { clusters: {} });
});

// ── awsconfig ───────────────────────────────────────────────────────
const AWS_CONFIG = `
[default]
region = us-east-1

[profile dev]
sso_start_url = https://x.awsapps.com/start
sso_region = us-east-1

[profile saml]
region = us-east-1
output = json

[profile sess]
sso_session = corp
[profile dev]
`;

test('awsconfig: parseProfiles + isSsoProfile', () => {
  assert.deepEqual(A.parseProfiles(AWS_CONFIG), ['default', 'dev', 'saml', 'sess']);
  assert.ok(A.isSsoProfile(AWS_CONFIG, 'dev'));
  assert.ok(A.isSsoProfile(AWS_CONFIG, 'sess'));
  assert.ok(!A.isSsoProfile(AWS_CONFIG, 'saml'));
  assert.ok(!A.isSsoProfile(AWS_CONFIG, 'default'));
  assert.ok(!A.isSsoProfile(AWS_CONFIG, ''));
  assert.deepEqual(A.parseProfiles(''), []);
});

test('awsconfig: credExpiration reads any of the known keys per section', () => {
  const creds = `
[saml]
aws_access_key_id = AKIA
x_security_token_expires = 2026-10-12T12:00:00+00:00
[other]
aws_expiration = not-a-date
`;
  assert.equal(A.credExpiration(creds, 'saml'), Date.parse('2026-10-12T12:00:00+00:00'));
  assert.equal(A.credExpiration(creds, 'other'), null);
  assert.equal(A.credExpiration(creds, 'missing'), null);
  assert.equal(A.credExpiration(creds, ''), null);
});

test('awsconfig: latestSsoExpiry picks the newest access-token blob', () => {
  const blobs = [
    { accessToken: 'a', expiresAt: '2026-10-12T10:00:00Z' },
    { clientId: 'x', expiresAt: '2099-01-01T00:00:00Z' },        // not an access token
    { accessToken: 'b', expiresAt: '2026-10-12T11:00:00Z' },
    { accessToken: 'c', expiresAt: 'garbage' },
  ];
  assert.equal(A.latestSsoExpiry(blobs), Date.parse('2026-10-12T11:00:00Z'));
  assert.equal(A.latestSsoExpiry([]), null);
});

// ── health ──────────────────────────────────────────────────────────
const WATCH = 'E1014 09:44:06.439055 99686 retrywatcher.go:129] "Watch failed" err="Get \\"https://4CA8.gr7.us-east-1.eks.amazonaws.com/api/v1/namespaces/monokee/pods?watch=true\\": proxyconnect tcp: dial tcp: lookup proxy.dmz.gemaltocloud.com: no such host"';

test('health: failureReason drops the klog prefix and the request URL', () => {
  assert.equal(failureReason(WATCH), 'proxyconnect tcp: dial tcp: lookup proxy.dmz.gemaltocloud.com: no such host');
  assert.equal(failureReason('dial tcp 1.2.3.4:443: i/o timeout'), 'dial tcp 1.2.3.4:443: i/o timeout');
  assert.equal(failureReason(''), '');
});

test('health: forwards one failure per minute, restarts at the limit with backoff, recovers on data', () => {
  let t = 1_000_000;
  const h = new StreamHealth({ failLimit: 3, windowMs: 10_000, baseDelayMs: 1000, maxDelayMs: 4000, forwardEveryMs: 60_000, now: () => t });
  let r = h.failure('ns', 'boom');
  assert.deepEqual([r.forward, r.restart, r.failures, r.degraded], [true, false, 1, false]);
  t += 1000; r = h.failure('ns', 'boom');
  assert.deepEqual([r.forward, r.restart, r.failures], [false, false, 2]);     // same minute: not forwarded again
  t += 1000; r = h.failure('ns', 'boom');
  assert.deepEqual([r.forward, r.restart, r.delayMs, r.restarts, r.degraded, r.since, r.reason], [false, true, 1000, 1, true, t, 'boom']);
  // Still broken after the restart: next restart doubles the delay, then caps.
  for (let i = 0; i < 3; i++) { t += 1000; r = h.failure('ns', 'boom'); }
  assert.deepEqual([r.restart, r.delayMs, r.restarts], [true, 2000, 2]);
  for (let i = 0; i < 3; i++) { t += 1000; r = h.failure('ns', 'boom'); }
  assert.equal(r.delayMs, 4000);
  for (let i = 0; i < 3; i++) { t += 1000; r = h.failure('ns', 'boom'); }
  assert.deepEqual([r.delayMs, r.restarts], [4000, 4]);                        // capped
  assert.equal(h.status('ns').degraded, true);
  // Data flows: degraded period ends, backoff resets, other namespaces untouched.
  assert.equal(h.healthy('ns'), true);
  assert.equal(h.healthy('ns'), false);
  assert.equal(h.healthy('other'), false);
  assert.equal(h.status('ns').restarts, 0);
  t += 61_000; r = h.failure('ns', 'again');
  assert.deepEqual([r.forward, r.restart, r.failures], [true, false, 1]);     // a minute later: forwarded again
});

test('health: failures outside the window do not count', () => {
  let t = 0;
  const h = new StreamHealth({ failLimit: 3, windowMs: 5000, now: () => t });
  h.failure('ns'); t += 6000; h.failure('ns'); t += 6000;
  assert.equal(h.failure('ns').restart, false);
  t += 100; assert.equal(h.failure('ns').restart, false);
  t += 100; assert.equal(h.failure('ns').restart, true);
});
