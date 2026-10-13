import { useState } from 'preact/hooks';

interface Props { value: unknown; name?: string; depth?: number; collapseAllTick?: number; expandAllTick?: number; isLast?: boolean }

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

export function JsonTree({ value, name, depth = 0, collapseAllTick = 0, expandAllTick = 0, isLast = true }: Props) {
  const [open, setOpen] = useState(depth < 2);
  const [tickC, setTickC] = useState(collapseAllTick);
  const [tickE, setTickE] = useState(expandAllTick);
  if (collapseAllTick !== tickC) { setTickC(collapseAllTick); setOpen(false); }
  if (expandAllTick !== tickE) { setTickE(expandAllTick); setOpen(true); }
  const key = name !== undefined ? <span class="jv-key">"{name}"</span> : null;
  const colon = name !== undefined ? <span class="jv-punct">: </span> : null;
  const comma = isLast ? null : <span class="jv-punct">,</span>;

  if (Array.isArray(value) || isObj(value)) {
    const arr = Array.isArray(value);
    const entries = arr ? (value as unknown[]).map((v, i) => [String(i), v] as const) : Object.entries(value);
    const [o, c] = arr ? ['[', ']'] : ['{', '}'];
    return (
      <div class="jv-node">
        <div class="jv-line" onClick={() => setOpen(!open)}>
          <span class="jv-tog">{open ? '▾' : '▸'}</span>{key}{colon}
          <span class="jv-punct">{o}</span>
          {!open && <span class="jv-summary">{entries.length} {arr ? 'items' : 'keys'}</span>}
          {!open && <span class="jv-punct">{c}</span>}{!open && comma}
        </div>
        {open && (
          <div class="jv-children">
            {entries.map(([k, v], i) => <JsonTree key={k} name={arr ? undefined : k} value={v} depth={depth + 1} collapseAllTick={collapseAllTick} expandAllTick={expandAllTick} isLast={i === entries.length - 1} />)}
            <div class="jv-line"><span class="jv-punct">{c}</span>{comma}</div>
          </div>
        )}
      </div>
    );
  }
  let cls = 'jv-num', text: string;
  if (value === null) { cls = 'jv-null'; text = 'null'; }
  else if (value === undefined) { cls = 'jv-null'; text = 'undefined'; }
  else if (typeof value === 'string') { cls = 'jv-str'; text = JSON.stringify(value); }
  else if (typeof value === 'boolean') { cls = 'jv-bool'; text = String(value); }
  else text = String(value);
  const long = text.length > 300;
  const [more, setMore] = useState(false);
  return (
    <div class="jv-line leaf">{key}{colon}<span class={cls}>{long && !more ? text.slice(0, 300) + '…' : text}</span>{long && <span class="link jv-more" onClick={() => setMore(!more)}>{more ? ' [less]' : ' [more]'}</span>}{comma}</div>
  );
}
