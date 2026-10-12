'use strict';
// Input validation for everything that arrives from the viewer via the relay.
// Every value that ends up in an argv array (or a filename, or a regex) must
// pass one of these first. Pure — no I/O.

const NS_RE       = /^[a-z0-9]([-a-z0-9]{0,61}[a-z0-9])?$/;         // DNS label
const CLUSTER_RE  = /^[A-Za-z0-9_-]{1,100}$/;                        // EKS cluster name
const PROFILE_RE  = /^[A-Za-z0-9._@:+-]{1,128}$/;                    // AWS profile name
const REGION_RE   = /^[a-z]{2}(-[a-z]+)+-\d$/;                       // us-east-1, eu-central-1, ap-southeast-2
const WORKLOAD_RE = /^[a-z0-9][a-z0-9.-]{0,252}$/i;                  // controller / pod name
const MAX_WORKLOADS = 200;
const MAX_NAMESPACES = 100;

const isNamespace   = v => typeof v === 'string' && NS_RE.test(v);
const isCluster     = v => typeof v === 'string' && CLUSTER_RE.test(v);
const isProfileName = v => typeof v === 'string' && PROFILE_RE.test(v);
const isRegion      = v => typeof v === 'string' && REGION_RE.test(v);
const isWorkload    = v => typeof v === 'string' && WORKLOAD_RE.test(v);
const isWorkloadList = a => Array.isArray(a) && a.length <= MAX_WORKLOADS && a.every(isWorkload);

const CHECKS = {
  namespace: isNamespace,
  cluster: isCluster,
  profile: isProfileName,
  region: isRegion,
  workload: isWorkload,
  workloadList: isWorkloadList,
};

// Throws `Error('invalid <kind>')` so handleAction can relay a terse, safe
// message back to the viewer without echoing the offending value.
function assertValid(kind, value) {
  const check = CHECKS[kind];
  if (!check) throw new Error(`unknown validation kind: ${kind}`);
  if (!check(value)) throw new Error(`invalid ${kind}`);
  return value;
}

// Accepts a string or an array of strings; returns a de-duplicated array of
// validated namespaces. Throws on any invalid entry.
function namespaceList(input) {
  const arr = Array.isArray(input) ? input : [input];
  const out = [];
  for (const v of arr) {
    if (v == null || v === '') continue;
    assertValid('namespace', v);
    if (!out.includes(v)) out.push(v);
  }
  if (out.length > MAX_NAMESPACES) throw new Error('invalid namespace list');
  return out;
}

// `filters` is `{ ns: [workload, ...] }`. Returns a fresh object with only
// valid entries; throws on any invalid namespace or workload.
function filterMap(input) {
  if (input == null) return {};
  if (typeof input !== 'object' || Array.isArray(input)) throw new Error('invalid filters');
  const out = {};
  for (const [ns, wls] of Object.entries(input)) {
    assertValid('namespace', ns);
    if (wls == null) continue;
    assertValid('workloadList', wls);
    out[ns] = [...wls];
  }
  return out;
}

module.exports = {
  isNamespace, isCluster, isProfileName, isRegion, isWorkload, isWorkloadList,
  assertValid, namespaceList, filterMap,
  MAX_WORKLOADS, MAX_NAMESPACES,
};
