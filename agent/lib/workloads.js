'use strict';
// Pod ↔ workload helpers for the viewer's pod picker and stern pod queries.

// Map a pod to its "workload" (the controller name, replica hash stripped) so
// selecting a workload survives restarts/scaling. Deployment pods are owned by
// a ReplicaSet named "<deploy>-<template-hash>"; strip the trailing hash
// segment. StatefulSet/DaemonSet/Job pods are owned directly by the named
// controller. Bare pods (no controller) group under their own name.
function workloadOf(name, kind, owner) {
  if (kind === 'ReplicaSet' && owner) return owner.replace(/-[a-z0-9]+$/i, '');
  if (owner) return owner;
  return name;
}

// stern pod-query regex for a set of workloads. Empty → all pods. Anchored at
// the start with a "(-|$)" boundary so "redis" matches redis-0 / redis-... but
// not (most) unrelated pods. Regex metachars in names are escaped.
function podQuery(workloads) {
  if (!workloads || !workloads.length) return '.*';
  const alt = workloads.map(w => String(w).replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|');
  return `^(${alt})(-|$)`;
}

// Parse `kubectl get pods -o jsonpath=...` output of "name\tkind\towner" rows
// into workloads with pod counts, sorted by name.
function parsePodsOutput(text) {
  const groups = new Map();
  for (const raw of String(text || '').split('\n')) {
    if (!raw.trim()) continue;
    const [name, kind, owner] = raw.split('\t');
    const wl = workloadOf(name, kind, owner);
    groups.set(wl, (groups.get(wl) || 0) + 1);
  }
  return [...groups.entries()]
    .map(([name, count]) => ({ name, count }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

// The jsonpath template handed to kubectl for the above.
const PODS_JSONPATH = '{range .items[*]}{.metadata.name}{"\\t"}{.metadata.ownerReferences[0].kind}{"\\t"}{.metadata.ownerReferences[0].name}{"\\n"}{end}';

module.exports = { workloadOf, podQuery, parsePodsOutput, PODS_JSONPATH };
