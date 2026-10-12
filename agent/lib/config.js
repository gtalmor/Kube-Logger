'use strict';
// ~/.kube-logger/config.json handling (pure: callers do the file I/O).
//
// On-disk shape:
//   { "region": "us-east-1",
//     "clusters": {
//       "<aws-profile>": "<eks-cluster-name>",                       // uses the default region
//       "<aws-profile>": { "name": "<cluster>", "region": "eu-west-1" } // per-cluster region
//     },
//     "disabledProfiles": ["profile-to-hide-from-drawer"],
//     "externalAuthCommands": { "<aws-profile>": "saml2aws login --profile <p> …" },
//     "externalAuthLabels":   { "<aws-profile>": "Keycloak" },
//     "externalAuthHints":    { "<aws-profile>": "run your helper, then click Login" } }

const DEFAULT_REGION = 'us-east-1';

function templateConfig(region = DEFAULT_REGION) {
  return { region, clusters: {}, disabledProfiles: [], externalAuthHints: {}, externalAuthCommands: {}, externalAuthLabels: {} };
}

// Normalize a parsed config file into the in-memory CFG shape. Every
// `clusters[profile]` becomes `{ name, region }` regardless of how it was
// written on disk.
function normalizeConfig(json, defaults = {}) {
  const j = (json && typeof json === 'object') ? json : {};
  const region = (typeof j.region === 'string' && j.region) || defaults.region || DEFAULT_REGION;
  const clusters = {};
  for (const [profile, v] of Object.entries(j.clusters || {})) {
    if (typeof v === 'string' && v) clusters[profile] = { name: v, region };
    else if (v && typeof v === 'object' && typeof v.name === 'string' && v.name) {
      clusters[profile] = { name: v.name, region: (typeof v.region === 'string' && v.region) || region };
    }
  }
  return {
    region,
    clusters,
    disabledProfiles: new Set(Array.isArray(j.disabledProfiles) ? j.disabledProfiles : []),
    externalAuthHints: j.externalAuthHints || {},
    externalAuthCommands: j.externalAuthCommands || {},
    externalAuthLabels: j.externalAuthLabels || {},
  };
}

const clusterFor = (cfg, profile) => (cfg.clusters[profile] || {}).name;
const regionFor  = (cfg, profile) => (cfg.clusters[profile] || {}).region || cfg.region;

// Return a new on-disk JSON object with `profile → cluster` recorded. Writes
// the compact string form when the region is the file's default, the object
// form otherwise, so hand-edited files stay readable.
function withClusterMapping(json, profile, cluster, region) {
  const j = { ...((json && typeof json === 'object') ? json : {}) };
  j.region = j.region || DEFAULT_REGION;
  j.clusters = { ...(j.clusters || {}) };
  j.disabledProfiles = j.disabledProfiles || [];
  j.clusters[profile] = (region && region !== j.region) ? { name: cluster, region } : cluster;
  return j;
}

module.exports = { DEFAULT_REGION, templateConfig, normalizeConfig, clusterFor, regionFor, withClusterMapping };
