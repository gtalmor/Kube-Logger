// Log line parser for OneWelcome IO (Identity Orchestrator) pods as emitted by
// stern: "<pod> <container> <message>" (optionally prefixed by "<ns> ").
// Pure: no DOM, no state. Each line is parsed exactly once into a LogLine
// that keeps a single copy of the text plus the small derived fields the UI
// filters and analyses on.

export type FlowState = 'pre' | 'process' | 'done' | 'post' | 'failed';
export type Kind = 'http' | 'json' | 'plain' | 'script-error' | 'raw';

export interface LogLine {
  /** Dense, store-assigned, monotonic id. Display number = id + 1. */
  id: number;
  /** The agent's own index (`i`) when known; used for replay dedupe only. */
  src?: number;
  kind: Kind;
  /** The only copy of the text (namespace prefix already stripped). */
  raw: string;
  ns?: string;
  pod?: string;
  container?: string;
  /** Epoch ms when the timestamp parsed; undefined otherwise. */
  ts?: number;
  /** Original timestamp text when it did not parse (shown verbatim). */
  tsText?: string;
  level: string;
  msg?: string;
  reqId?: string;
  /** kind === 'json': offset in `raw` where the JSON object starts. */
  jsonOff?: number;
  // http access log
  method?: string;
  path?: string;
  status?: number;
  size?: number;
  // flow engine
  flowExecId?: string;
  flowName?: string;
  flowNode?: string;
  flowState?: FlowState;
  flowNext?: string;
  flowFailReason?: string;
  failNodeId?: string;
  failNodeLabel?: string;
  apiError?: string;
  isFlowError?: boolean;
  isErrorDetail?: boolean;
  /** Precomputed "counts as an issue" flag (errors, failures, 5xx). */
  isErr: boolean;
  /** Precomputed "looks like it contains JSON" hint for the inspect button. */
  hasJsonHint: boolean;
}

// ── Regexes (ported verbatim from the legacy viewer) ─────────────────
export const NX = /^(\S+)\s+(\S+)\s+(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"/;
export const SJ = /^(\S+)\s+(\S+)\s+(\{.+\})$/;
export const SP = /^([+-])\s+(\S+)\s+.\s+(\S+)$/;
export const FLOW_NODE_RE = /\[([^\]]+)\]\s+(\S+)\s+-\s+Node\s+(.+?)\s+is\s+in\s+(\w+)\s+state(?:,\s+next\s+node\s+is\s+(\S+))?/;
export const FLOW_FAIL_RE = /Failure from node\s+(.+?)\s+\(([^)]+)\)/;
export const FLOW_FAIL_FULL_RE = /\[([^\]]+)\]\s+(\S+)\s+-\s+Failure from node\s+(.+?)\s+\(([^)]+)\)/;
export const FLOW_START_RE = /\[([^\]]+)\]\s+(\S+)\s+-\s+(Starting|Executing|Running)\s/i;
export const FLOW_PATH_RE = /\/flow\/execute\/(?:custom\/)?([^?\s/]+)/;
export const AXIOS_ERR_RE = /Error.*?:\s*(AxiosError:.*)/;
export const SE_RE = /\[(\d{4}-\d{2}-\d{2}T[\d:.]+)\]\s*\[(\w+)\]\s*\[([^\]]+)\]\s*\[([^\]]*)\]/;
export const ERR_DETAIL_RE = /^\s+((?:Syntax|Type|Reference|Range|URI|Eval)Error:\s*.+)/;
export const NOT_CONNECTED_RE = /"Failure" output of node (\d+) is not connected/;
const JSON_HINT_RE = /\{\s*["']|\[\s*[\{\[]|:\s*\{/;
const CLF_TS_RE = /^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})(?:\s*([+-])(\d{2})(\d{2}))?$/;
const MONTHS: Record<string, number> = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

export function stripAnsi(s: string): string {
  return s.replace(/\x1b\[[0-9;]*m/g, '').replace(/\[[\d]+m/g, '');
}

/** Parse ISO-8601 or Common Log Format timestamps to epoch ms. */
export function parseTs(text: string | undefined): number | undefined {
  if (!text) return undefined;
  const m = CLF_TS_RE.exec(text);
  if (m) {
    const mon = MONTHS[m[2].toLowerCase()];
    if (mon === undefined) return undefined;
    let t = Date.UTC(+m[3], mon, +m[1], +m[4], +m[5], +m[6]);
    if (m[7]) {
      const off = (+m[8] * 60 + +m[9]) * 60000;
      t -= m[7] === '+' ? off : -off;
    }
    return t;
  }
  const t = Date.parse(text);
  return Number.isNaN(t) ? undefined : t;
}

const FLOW_STATES = new Set(['pre', 'process', 'done', 'post', 'failed']);
function asFlowState(s: string): FlowState | undefined {
  return FLOW_STATES.has(s) ? (s as FlowState) : undefined;
}

function normalizeLevel(l: string): string {
  const u = l.toUpperCase();
  if (u === 'WARNING') return 'WARN';
  if (u === 'ERR') return 'ERROR';
  if (u === 'CRITICAL') return 'FATAL';
  return u;
}

function computeIsErr(l: Omit<LogLine, 'isErr' | 'hasJsonHint'>): boolean {
  return l.level === 'ERROR' || l.level === 'FATAL' || !!l.isFlowError || !!l.isErrorDetail
    || l.flowState === 'failed' || (l.kind === 'http' && (l.status || 0) >= 500);
}

type Draft = Omit<LogLine, 'isErr' | 'hasJsonHint'>;
function finish(d: Draft, hint?: boolean): LogLine {
  return { ...d, isErr: computeIsErr(d), hasJsonHint: hint ?? JSON_HINT_RE.test(d.msg || d.raw) };
}

/**
 * Parse one raw line. Returns null for blank lines and stern's own
 * "+ pod › container" / "- pod" events (never shown).
 * @param ns namespace the agent tagged the line with (may be undefined for files)
 * @param nsCapturing namespaces of the current capture, used to strip a
 *        leading "<ns> " that stern adds when streaming several namespaces
 */
export function parseLine(raw: string, ns: string | undefined, nsCapturing: ReadonlySet<string>, id: number, src?: number): LogLine | null {
  let t = raw.trimEnd();
  if (!t) return null;
  if (ns && t.startsWith(ns + ' ')) t = t.slice(ns.length + 1);
  else if (nsCapturing.size) {
    for (const n of nsCapturing) {
      if (t.startsWith(n + ' ')) { ns = n; t = t.slice(n.length + 1); break; }
    }
  }
  if (SP.test(t)) return null;

  const nm = NX.exec(t);
  if (nm) {
    const ts = parseTs(nm[4]);
    const d: Draft = {
      id, src, kind: 'http', raw: t, ns, pod: nm[1], container: nm[2],
      ts, tsText: ts === undefined ? nm[4] : undefined,
      method: nm[5], path: nm[6], status: +nm[7], size: +nm[8], level: 'HTTP',
    };
    const fp = FLOW_PATH_RE.exec(nm[6]);
    if (fp) d.flowName = fp[1];
    return finish(d, false);
  }

  const jm = SJ.exec(t);
  if (jm) {
    try {
      const j = JSON.parse(jm[3]);
      const data: unknown[] = Array.isArray(j.data) ? j.data : [];
      let msg = '';
      for (const x of data) {
        if (typeof x === 'string') msg += (msg ? ' ' : '') + x;
        else if (x && typeof x === 'object' && (x as { file?: unknown }).file) continue;
        else if (x && typeof x === 'object') msg += (msg ? ' ' : '') + JSON.stringify(x);
      }
      const ts = parseTs(typeof j.timestamp === 'string' ? j.timestamp : undefined);
      const d: Draft = {
        id, src, kind: 'json', raw: t, ns, pod: jm[1], container: jm[2],
        ts, tsText: ts === undefined && typeof j.timestamp === 'string' ? j.timestamp : undefined,
        level: normalizeLevel(typeof j.level === 'string' ? j.level : 'INFO'),
        reqId: typeof j.req_id === 'string' ? j.req_id : undefined,
        msg, jsonOff: t.length - jm[3].length,
      };
      const fn = FLOW_NODE_RE.exec(msg);
      if (fn) {
        d.flowExecId = fn[1]; d.flowName = fn[2]; d.flowNode = fn[3]; d.flowState = asFlowState(fn[4]); d.flowNext = fn[5];
      } else {
        const ff = FLOW_FAIL_FULL_RE.exec(msg);
        if (ff) { d.flowExecId = ff[1]; d.flowName = ff[2]; d.flowNode = ff[3]; d.flowFailReason = ff[4]; d.flowState = 'failed'; }
        else {
          const fl = FLOW_FAIL_RE.exec(msg);
          if (fl) { d.failNodeId = fl[1]; d.failNodeLabel = fl[2]; d.flowState = 'failed'; }
        }
      }
      if (!d.flowName) {
        const fs = FLOW_START_RE.exec(msg);
        if (fs) { d.flowExecId = fs[1]; d.flowName = fs[2]; }
      }
      const ax = AXIOS_ERR_RE.exec(msg);
      if (ax) d.apiError = ax[1];
      if (msg.includes('Error and save error in session')) d.isFlowError = true;
      const fnc = NOT_CONNECTED_RE.exec(msg);
      if (fnc) { d.failNodeId = fnc[1]; d.isFlowError = true; }
      return finish(d, true);
    } catch { /* fall through to plain */ }
  }

  // Single separator after the container so a continuation line's leading
  // indentation ("    SyntaxError: …") survives for ERR_DETAIL_RE.
  const tp = /^(\S+)\s+(\S+)\s(.+)$/.exec(t);
  if (tp && tp[1].startsWith('io-')) {
    const cleanMsg = stripAnsi(tp[3]);
    const se = SE_RE.exec(cleanMsg);
    if (se) {
      const ts = parseTs(se[1]);
      return finish({
        id, src, kind: 'script-error', raw: t, ns, pod: tp[1], container: tp[2],
        ts, tsText: ts === undefined ? se[1] : undefined,
        level: normalizeLevel(se[2]), reqId: se[3], msg: cleanMsg,
      });
    }
    const ed = ERR_DETAIL_RE.exec(cleanMsg);
    if (ed) {
      return finish({ id, src, kind: 'plain', raw: t, ns, pod: tp[1], container: tp[2], msg: ed[1], level: 'ERROR', isErrorDetail: true });
    }
    const msg = cleanMsg.trimStart();
    const lower = msg.toLowerCase();
    const level = lower.includes('error') ? 'ERROR' : lower.includes('warn') ? 'WARN' : 'INFO';
    return finish({ id, src, kind: 'plain', raw: t, ns, pod: tp[1], container: tp[2], msg, level });
  }

  return finish({ id, src, kind: 'raw', raw: t, ns, msg: t, level: 'INFO' });
}

/** Lines that can form a multi-line group (stack traces etc.). */
export function isMultilineMember(l: LogLine | undefined): boolean {
  return !!l && (l.kind === 'plain' || l.kind === 'script-error');
}
