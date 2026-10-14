// Tenant registry: friendly names, colours and aliases per id, persisted in
// this browser. IO logs identify a customer by `domain_id`, other services by
// `tenant_id`; marking one id as an alias of another makes them one customer
// everywhere (filter, pill, chips, counts). Colours auto-assign on first sight.
import { computed, signal } from '@preact/signals';
import { getJson, setJson } from '../lib/storage';
import { shortTenant } from '../lib/format';

export interface TenantMeta { name?: string; color?: string; /** id of the customer this id belongs to */ alias?: string }
const KEY = 'kubelogger.tenants.v1';
export const TENANT_PALETTE = ['#bc8cff', '#39c5cf', '#ff7b72', '#d29922', '#3fb950', '#79c0ff', '#e6db74', '#f778ba', '#ffa657', '#7ee787'];
const HEALTH_COLOR = '#8b949e';

export const tenantMeta = signal<Record<string, TenantMeta>>(getJson<Record<string, TenantMeta>>(KEY, {}));

function persist(next: Record<string, TenantMeta>): void {
  tenantMeta.value = next;
  setJson(KEY, next);
}

/** The customer id an id resolves to (one level of alias). */
export function canonicalTenant(id: string): string {
  const a = tenantMeta.value[id]?.alias;
  return a && a !== id ? a : id;
}
export function tenantName(id: string | undefined): string | undefined {
  return id ? tenantMeta.value[canonicalTenant(id)]?.name || undefined : undefined;
}
/** Name if set, else the shortened (canonical) id. */
export function displayTenant(id: string | undefined): string {
  return tenantName(id) || shortTenant(id ? canonicalTenant(id) : id);
}
/** Only the alias mapping; the filter predicate depends on this, not on names/colours. */
export const aliasKey = computed(() => JSON.stringify(Object.entries(tenantMeta.value).filter(([, m]) => m.alias).map(([k, m]) => [k, m.alias]).sort()));

function hashColor(id: string): string {
  let h = 0;
  for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0;
  return TENANT_PALETTE[h % TENANT_PALETTE.length];
}
/** Colour for a tenant's customer. Read-only (safe during render); unassigned ids get a stable fallback. */
export function tenantColor(id: string | undefined): string {
  if (!id) return HEALTH_COLOR;
  const c0 = canonicalTenant(id);
  return tenantMeta.value[c0]?.color || (c0 === 'health' ? HEALTH_COLOR : hashColor(c0));
}
/** Assign and persist colours for customers that have none yet. Call from an effect, never from render. */
export function ensureTenantColors(ids: Iterable<string>): void {
  let next: Record<string, TenantMeta> | null = null;
  const used = new Set(Object.values(tenantMeta.value).map(m => m.color).filter(Boolean));
  for (const id of ids) {
    const c0 = canonicalTenant(id);
    if ((next || tenantMeta.value)[c0]?.color) continue;
    const c = c0 === 'health' ? HEALTH_COLOR : (TENANT_PALETTE.find(p => !used.has(p)) || hashColor(c0));
    used.add(c);
    next = { ...(next || tenantMeta.value), [c0]: { ...(next || tenantMeta.value)[c0], color: c } };
  }
  if (next) persist(next);
}
export function setTenantName(id: string, name: string): void {
  const n = name.trim();
  persist({ ...tenantMeta.value, [id]: { ...tenantMeta.value[id], name: n || undefined } });
}
export function setTenantColor(id: string, color: string): void {
  persist({ ...tenantMeta.value, [id]: { ...tenantMeta.value[id], color } });
}
/** Make `id` part of customer `primary` (or standalone again with null). */
export function setTenantAlias(id: string, primary: string | null): void {
  const next = { ...tenantMeta.value };
  const target = primary ? canonicalTenant(primary) : null;
  if (!target || target === id) { const m = { ...next[id] }; delete m.alias; next[id] = m; }
  else {
    next[id] = { ...next[id], alias: target };
    // Anything that pointed at `id` now points at the new primary too.
    for (const [k, m] of Object.entries(next)) if (m.alias === id) next[k] = { ...m, alias: target };
  }
  persist(next);
}
export function forgetTenant(id: string): void {
  const next = { ...tenantMeta.value };
  delete next[id];
  for (const [k, m] of Object.entries(next)) if (m.alias === id) { const c = { ...m }; delete c.alias; next[k] = c; }
  persist(next);
}
/** Ids that are seen in the logs or have metadata, deduped, seen-first. */
export function knownTenants(seen: Iterable<string>): string[] {
  const out: string[] = [];
  for (const t of seen) if (!out.includes(t)) out.push(t);
  for (const t of Object.keys(tenantMeta.value)) if (!out.includes(t)) out.push(t);
  return out;
}
/** Raw per-id counts folded into customers, most lines first. */
export function customerCounts(counts: ReadonlyMap<string, number>): { id: string; count: number; ids: string[] }[] {
  const m = new Map<string, { id: string; count: number; ids: string[] }>();
  for (const [raw, n] of counts) {
    const c = canonicalTenant(raw);
    let e = m.get(c);
    if (!e) m.set(c, e = { id: c, count: 0, ids: [] });
    e.count += n; e.ids.push(raw);
  }
  return [...m.values()].sort((a, b) => b.count - a.count);
}
