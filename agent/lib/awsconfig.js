'use strict';
// Pure parsers for ~/.aws/config, ~/.aws/credentials and the SSO token cache.
// Callers read the files; these functions only look at text / parsed JSON.

// Profile names from ~/.aws/config: `[default]` and `[profile X]` sections.
function parseProfiles(text) {
  const names = [];
  for (const line of String(text || '').split('\n')) {
    const m = line.trim().match(/^\[(.+)\]$/);
    if (!m) continue;
    const section = m[1];
    if (section === 'default') names.push('default');
    else if (section.startsWith('profile ')) names.push(section.slice(8).trim());
  }
  return [...new Set(names)].sort();
}

// True if the profile section has SSO keys (sso_start_url or sso_session).
function isSsoProfile(text, name) {
  if (!name) return false;
  const header = name === 'default' ? '[default]' : `[profile ${name}]`;
  let inSection = false;
  for (const raw of String(text || '').split('\n')) {
    const line = raw.trim();
    if (line.startsWith('[')) { inSection = (line === header); continue; }
    if (!inSection) continue;
    if (/^sso_(start_url|session)\s*=/.test(line)) return true;
  }
  return false;
}

// Expiration for a non-SSO profile from ~/.aws/credentials. saml2aws writes
// `x_security_token_expires`; aws's own role-cred writers use
// `aws_session_expiration` / `aws_expiration`. ISO-8601 with tz. Returns ms
// epoch or null.
function credExpiration(text, profile) {
  if (!profile) return null;
  const header = `[${profile}]`;
  let inSection = false;
  for (const raw of String(text || '').split('\n')) {
    const line = raw.trim();
    if (line.startsWith('[')) { inSection = (line === header); continue; }
    if (!inSection) continue;
    const m = line.match(/^(x_security_token_expires|aws_session_expiration|aws_expiration)\s*=\s*(.+)$/);
    if (m) { const ts = new Date(m[2].trim()).getTime(); return Number.isNaN(ts) ? null : ts; }
  }
  return null;
}

// Latest `expiresAt` across parsed ~/.aws/sso/cache/*.json blobs. Only
// access-token files (accessToken + expiresAt) count.
function latestSsoExpiry(blobs) {
  let latest = null;
  for (const j of blobs || []) {
    if (j && j.accessToken && j.expiresAt) {
      const ts = new Date(j.expiresAt).getTime();
      if (!Number.isNaN(ts) && (!latest || ts > latest)) latest = ts;
    }
  }
  return latest;
}

module.exports = { parseProfiles, isSsoProfile, credExpiration, latestSsoExpiry };
