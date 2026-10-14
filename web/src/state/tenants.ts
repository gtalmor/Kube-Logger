// Tenant registry: friendly names and colours per domain id, persisted in
// this browser. Colours are auto-assigned the first time a tenant shows up.
import { signal } from '@preact/signals';
import { getJson, setJson } from '../lib/storage';
import { shortTenant } from '../lib/format';

export interface TenantMeta { name?: string; color?: string }
const KEY = 'kubelogger.tenants.v1';
export const TENANT_PALETTE = ['#bc8cff', '#39c5cf', '#ff7b72', '#d29922', '#3fb950', '#79c0ff', '#e6db74', '#f778ba', '#ffa657', '#7ee787'];
const HEALTH_COLOR = '#8b949e';

export const tenantMeta = signal<Record<string, TenantMeta>>(getJson<Record<string, TenantMeta>>(KEY, {}));

function persist(next: Record<string, TenantMeta>): void {
  tenantMeta.value = next;
  setJson(KEY, next);
}

export function tenantName(id: string | undefined): string | undefined {
  return id ? tenantMeta.value[id]?.name || undefined : undefined;
}
/** Name if set, else the shortened id. */
export function displayTenant(id: string | undefined): string {
  return tenantName(id) || shortTenant(id);
}
/** Colour for a tenant, assigning and persisting one on first sight. */
export function tenantColor(id: string | undefined): string {
  if (!id) return HEALTH_COLOR;
  const cur = tenantMeta.value[id]?.color;
  if (cur) return cur;
  const c = id === 'health' ? HEALTH_COLOR : nextColor();
  persist({ ...tenantMeta.value, [id]: { ...tenantMeta.value[id], color: c } });
  return c;
}
function nextColor(): string {
  const used = new Set(Object.values(tenantMeta.value).map(m => m.color).filter(Boolean));
  return TENANT_PALETTE.find(p => !used.has(p)) || TENANT_PALETTE[Object.keys(tenantMeta.value).length % TENANT_PALETTE.length];
}
export function setTenantName(id: string, name: string): void {
  const n = name.trim();
  persist({ ...tenantMeta.value, [id]: { ...tenantMeta.value[id], name: n || undefined } });
}
export function setTenantColor(id: string, color: string): void {
  persist({ ...tenantMeta.value, [id]: { ...tenantMeta.value[id], color } });
}
export function forgetTenant(id: string): void {
  const next = { ...tenantMeta.value };
  delete next[id];
  persist(next);
}
/** Ids that are seen in the logs or have metadata, deduped, seen-first. */
export function knownTenants(seen: Iterable<string>): string[] {
  const out: string[] = [];
  for (const t of seen) if (!out.includes(t)) out.push(t);
  for (const t of Object.keys(tenantMeta.value)) if (!out.includes(t)) out.push(t);
  return out;
}
