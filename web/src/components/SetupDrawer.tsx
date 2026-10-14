import { useEffect, useRef, useState } from 'preact/hooks';
import { drawerOpen } from '../state/ui';
import { agentConnected, agentInfo, auth, capture } from '../state/connection';
import * as S from '../state/setup';
import { addFlowDef, clearFlowDefs, flowDefs, removeFlowDef } from '../state/flowDefs';
import { toast } from '../state/toasts';
import { fmtRemaining, fmtCount, shortTenant } from '../lib/format';
import { store } from '../state/app';
import { forgetTenant, knownTenants, setTenantColor, setTenantName, tenantColor, tenantMeta, tenantName } from '../state/tenants';

function AuthLine() {
  const a = auth.value;
  const p = S.progress.value;
  const [, tick] = useState(0);
  useEffect(() => { const t = setInterval(() => tick(x => x + 1), 30000); return () => clearInterval(t); }, []);
  if (p) return <div class="sd-auth"><span class="dot pending" /> <span>{p}</span></div>;
  if (!a) return <div class="sd-auth"><span class="dot fail" /> <span class="muted">Not checked yet</span></div>;
  if (!a.ok) return <div class="sd-auth"><span class="dot fail" /> <span class="truncate" title={a.err}>{a.err || 'Not authenticated'}</span></div>;
  const label = a.arn ? a.arn.split('/').pop() : 'Authenticated';
  const ms = a.expiresAt ? a.expiresAt - Date.now() : null;
  const dot = ms === null ? 'ok' : ms <= 0 ? 'fail' : ms < 10 * 60 * 1000 ? 'pending' : 'ok';
  return <div class="sd-auth"><span class={`dot ${dot}`} /> <span class="truncate">{label}{ms !== null ? ` — ${fmtRemaining(ms)}` : ''}{a.cluster ? ` · ${a.cluster}` : ''}</span></div>;
}

function TenantTable() {
  void store.dataVersion.value;
  void tenantMeta.value;
  const ids = knownTenants([...store.tenantCounts.entries()].sort((a, b) => b[1] - a[1]).map(([t]) => t));
  const [newId, setNewId] = useState('');
  const [newName, setNewName] = useState('');
  const add = () => { const id = newId.trim(); if (!id) return; setTenantName(id, newName); tenantColor(id); setNewId(''); setNewName(''); };
  return (
    <div class="sd-list">
      {!ids.length && <div class="pop-empty">No tenants seen yet. Tenant = the domain_id on each log line.</div>}
      {ids.map(id => {
        const n = store.tenantCounts.get(id) || 0;
        return (
          <div key={id} class="sd-tenant">
            <input type="color" value={tenantColor(id)} title="Colour" onInput={e => setTenantColor(id, (e.target as HTMLInputElement).value)} />
            <span class="id truncate" title={id}>{shortTenant(id)}{n ? <span class="faint"> · {fmtCount(n)}</span> : <span class="faint"> · not seen</span>}</span>
            <input class="input" placeholder="Name…" value={tenantName(id) || ''} onInput={e => setTenantName(id, (e.target as HTMLInputElement).value)} />
            <button class="r-act" title="Forget name and colour" onClick={() => forgetTenant(id)}>×</button>
          </div>
        );
      })}
      <div class="sd-tenant">
        <span />
        <input class="input" placeholder="domain id…" value={newId} onInput={e => setNewId((e.target as HTMLInputElement).value)} onKeyDown={e => { if (e.key === 'Enter') add(); }} />
        <input class="input" placeholder="Name…" value={newName} onInput={e => setNewName((e.target as HTMLInputElement).value)} onKeyDown={e => { if (e.key === 'Enter') add(); }} />
        <button class="r-act" title="Add" disabled={!newId.trim()} onClick={add}>+</button>
      </div>
    </div>
  );
}

export function SetupDrawer() {
  const open = drawerOpen.value;
  const capturing = capture.value.active;
  const a = auth.value;
  const authOk = !!a?.ok;
  const profs = S.visibleProfiles.value;
  const sel = S.selectedProfile.value;
  const mode = S.modeFor(sel);
  const nsList = S.cachedNs.value;
  const q = S.nsFilter.value.toLowerCase();
  const selected = new Set(S.selectedNs.value);
  const priority = nsList.filter(n => n.includes('io') || n.includes('productpod'));
  const ordered = [...priority, ...nsList.filter(n => !priority.includes(n))];
  const filtered = (q ? ordered.filter(n => n.toLowerCase().includes(q)) : ordered).sort((x, y) => (selected.has(y) ? 1 : 0) - (selected.has(x) ? 1 : 0));
  const colors = S.nsColors.value;
  const fileRef = useRef<HTMLInputElement>(null);
  const [advanced, setAdvanced] = useState(false);
  const defs = flowDefs.value;
  const cp = S.clusterPick.value;
  void store.usage.value;

  // Open → fresh auth check.
  useEffect(() => { if (open && sel) S.checkAuth(sel); }, [open]);
  // Esc handled by useKeyboard; focus the drawer when opened.
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => { if (open) ref.current?.focus(); }, [open]);

  if (!open) return null;
  const close = () => { drawerOpen.value = false; };
  const onFiles = (files: FileList | null) => {
    if (!files) return;
    for (const f of Array.from(files)) {
      const r = new FileReader();
      r.onload = ev => { try { const d = addFlowDef(JSON.parse(String(ev.target?.result)), f.name); if (d) toast(`Loaded ${d.name} (${d.nodeCount} nodes)`, 'ok'); else toast(`${f.name}: not a flow definition`, 'error'); } catch { toast(`${f.name}: invalid JSON`, 'error'); } };
      r.readAsText(f);
    }
  };
  return (
    <>
      <div class="backdrop" onClick={close} />
      <div ref={ref} class="drawer" tabIndex={-1} role="dialog" aria-label="Setup">
        <div class="drawer-head"><h3>Setup</h3><button class="btn sm ghost" onClick={close} title="Close (Esc)">✕</button></div>
        <div class="drawer-body">
          {!agentConnected.value && <div class="sd-note warn">Agent not connected. Start <code>kube-logger-agent</code> on your machine.</div>}
          {agentInfo.value.sternAvailable === false && <div class="sd-note warn">stern was not found on the agent machine; capturing will fail until it is installed.</div>}

          <section class="sd-section">
            <div class="sd-title">AWS profile <button class="link" onClick={() => { S.manageOpen.value = !S.manageOpen.value; }}>{S.manageOpen.value ? 'Done' : 'Manage'}</button></div>
            {S.manageOpen.value ? (
              <div class="sd-list">
                {S.profiles.value.length === 0 && <div class="pop-empty">No profiles in ~/.aws/config</div>}
                {S.profiles.value.map(p => <label key={p} class="sd-item"><input type="checkbox" checked={!S.disabledProfiles.value.includes(p)} onChange={e => S.toggleProfileEnabled(p, (e.target as HTMLInputElement).checked)} /><span class="truncate">{p}</span></label>)}
              </div>
            ) : (
              <>
                <div class="sd-row">
                  <select class="input grow" value={sel} onChange={e => S.selectProfile((e.target as HTMLSelectElement).value)}>
                    <option value="">Select profile…</option>
                    {profs.map(p => <option key={p} value={p}>{p}</option>)}
                  </select>
                  <button class={`btn ${authOk ? '' : 'primary'}`} disabled={!sel} onClick={S.login}>{mode.label} Login</button>
                </div>
                <AuthLine />
                {cp && (
                  <div class="sd-pick">
                    <div class="muted">Several EKS clusters for "{cp.profile}" — pick one:</div>
                    {cp.clusters.map(c => <button key={c} class="btn sm" onClick={() => S.pickCluster(cp.profile, c, cp.region)}>{c}</button>)}
                  </div>
                )}
              </>
            )}
          </section>

          <section class="sd-section">
            <div class="sd-title">Namespaces
              <span class="sd-title-actions">
                <input class="input sm" placeholder="Filter…" value={S.nsFilter.value} onInput={e => { S.nsFilter.value = (e.target as HTMLInputElement).value; }} />
                <button class="btn sm" title="Reload namespaces from the cluster" disabled={!authOk} onClick={S.loadNamespaces}>{S.nsLoading.value ? '…' : '↻'}</button>
              </span>
            </div>
            <div class="sd-list ns">
              {!nsList.length && <div class="pop-empty">{authOk ? (S.nsLoading.value ? 'Loading namespaces…' : 'No namespaces loaded — click ↻') : 'Log in first'}</div>}
              {nsList.length > 0 && !filtered.length && <div class="pop-empty">No matches</div>}
              {filtered.map(ns => {
                const on = selected.has(ns);
                const wf = S.wfFor(ns);
                const exp = S.expandedNs.value.includes(ns);
                const col = on ? (colors[ns] || S.ensureNsColor(ns)) : colors[ns];
                return (
                  <div key={ns} class={`sd-ns ${on ? 'on' : ''}`}>
                    <label class="sd-item">
                      <input type="checkbox" checked={on} onChange={e => S.toggleNs(ns, (e.target as HTMLInputElement).checked, capturing)} />
                      <span class="dot" style={{ background: col || 'var(--border-strong)' }} />
                      <span class="truncate" title={ns}>{ns}</span>
                      {on && <button class={`btn sm ${wf.length ? 'active' : ''}`} onClick={e => { e.preventDefault(); S.toggleExpanded(ns); }}>{exp ? '▾' : '▸'} {wf.length ? `${wf.length} workload${wf.length === 1 ? '' : 's'}` : 'all pods'}</button>}
                      {on && <input type="color" value={col} title={`Colour for ${ns}`} onInput={e => S.setNsColor(ns, (e.target as HTMLInputElement).value)} />}
                    </label>
                    {on && exp && (
                      <div class="sd-wf">
                        {S.loadingWf.value.includes(ns) || !S.cachedWf.value[ns] ? <div class="pop-empty">Loading pods…</div> : !S.cachedWf.value[ns].length ? <div class="pop-empty">No pods in this namespace</div> : (
                          <>
                            <div class="sd-wf-head">{wf.length ? `${wf.length} selected` : 'All pods'} {wf.length > 0 && <span class="link" onClick={() => S.clearWorkloads(ns, capturing)}>clear</span>} <span class="link" onClick={() => S.refreshWorkloads(ns)}>refresh</span></div>
                            {S.cachedWf.value[ns].map(w => (
                              <label key={w.name} class="sd-item small">
                                <input type="checkbox" checked={wf.includes(w.name)} onChange={e => S.toggleWorkload(ns, w.name, (e.target as HTMLInputElement).checked, capturing)} />
                                <span class="truncate" title={w.name}>{w.name}</span><span class="num faint">{w.count}</span>
                              </label>
                            ))}
                          </>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </section>

          <section class="sd-section">
            <div class="sd-title">Tenants <span class="faint" style="text-transform:none;letter-spacing:0;font-weight:400">names and colours, stored in this browser</span></div>
            <TenantTable />
          </section>

          <section class="sd-section">
            <button class="link sd-adv" onClick={() => setAdvanced(!advanced)}>{advanced ? '▾' : '▸'} Advanced: flow definitions {defs.files.length ? `(${defs.files.length})` : ''}</button>
            {advanced && (
              <div class="sd-defs">
                <div class="sd-row">
                  <button class="btn sm" onClick={() => fileRef.current?.click()}>Add JSON file(s)…</button>
                  <button class="btn sm" disabled={!defs.files.length} onClick={() => { if (confirm('Forget all uploaded flow definitions?')) clearFlowDefs(); }}>Clear all</button>
                  <input ref={fileRef} type="file" accept=".json,application/json" multiple style="display:none" onChange={e => { onFiles((e.target as HTMLInputElement).files); (e.target as HTMLInputElement).value = ''; }} />
                </div>
                {defs.files.map((f, i) => <div key={f.name} class="sd-item static"><span class="truncate" title={f.filename || f.name}>{f.name}</span><span class="faint">{f.nodeCount} nodes</span><button class="r-act" onClick={() => removeFlowDef(i)}>×</button></div>)}
                <div class="pop-hint">Upload IO (Identity Orchestrator) flow JSON to show friendly node titles in the timeline, waterfall and slow-node panel. Stored in this browser only.</div>
              </div>
            )}
          </section>
        </div>
        <div class="drawer-foot">
          {capturing
            ? <>
                <span class="muted truncate">Capturing {capture.value.ns.join(', ')} · <span class="num">{fmtCount(store.usage.value.total)}</span> lines</span>
                <button class="btn danger" onClick={S.stopCapture}>Stop capture</button>
              </>
            : <>
                <span class="muted truncate">{selected.size ? `${selected.size} namespace${selected.size === 1 ? '' : 's'} selected` : 'Select at least one namespace'}</span>
                <button class="btn primary" disabled={!selected.size || !authOk || !agentConnected.value} onClick={() => { if (S.startCapture()) close(); }}>Start capture{selected.size ? ` (${selected.size})` : ''}</button>
              </>}
        </div>
      </div>
    </>
  );
}
