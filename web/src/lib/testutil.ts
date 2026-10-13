// Synthetic stern-style log lines for tests and the ?demo=1 mode. Shapes
// mirror what the OneWelcome IO pods emit; see parse.ts for the regexes.

import { parseLine, type LogLine } from './parse';

const POD_ENGINE = 'io-flow-engine-7d9f8c6b5-x1k2q';
const POD_GW = 'io-gateway-5c4d3b2a1-p0z9';

export function jsonLine(opts: { ts: number; level?: string; reqId?: string; msg: string; pod?: string; container?: string; extra?: Record<string, unknown> }): string {
  const j = { timestamp: new Date(opts.ts).toISOString(), level: opts.level || 'info', req_id: opts.reqId, data: [opts.msg], ...(opts.extra || {}) };
  return `${opts.pod || POD_ENGINE} ${opts.container || 'flow-engine'} ${JSON.stringify(j)}`;
}
export function httpLine(opts: { ts: number; method?: string; path: string; status?: number; size?: number; pod?: string }): string {
  const d = new Date(opts.ts);
  const mon = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'][d.getUTCMonth()];
  const p = (n: number) => String(n).padStart(2, '0');
  const clf = `${p(d.getUTCDate())}/${mon}/${d.getUTCFullYear()}:${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} +0000`;
  return `${opts.pod || POD_GW} gateway 10.0.0.1 - - [${clf}] "${opts.method || 'POST'} ${opts.path} HTTP/1.1" ${opts.status ?? 200} ${opts.size ?? 300} "-" "curl/8"`;
}
export const nodeMsg = (exec: string, flow: string, node: string, state: string, next?: string) =>
  `[${exec}] ${flow} - Node ${node} is in ${state} state${next ? `, next node is ${next}` : ''}`;
export const startMsg = (exec: string, flow: string) => `[${exec}] ${flow} - Starting flow execution`;
export const failMsg = (exec: string, flow: string, node: string, reason: string) => `[${exec}] ${flow} - Failure from node ${node} (${reason})`;

export interface FlowScript { exec: string; flow: string; reqId: string; t0: number; nodes: { node: string; dur: number; next?: string; fail?: string; gapBefore?: number }[] }

/** Build the raw lines for one flow execution: start, then pre/done per node. */
export function flowLines(s: FlowScript): string[] {
  const out: string[] = [];
  let t = s.t0;
  out.push(jsonLine({ ts: t, reqId: s.reqId, msg: startMsg(s.exec, s.flow) }));
  for (const n of s.nodes) {
    t += n.gapBefore || 5;
    out.push(jsonLine({ ts: t, reqId: s.reqId, msg: nodeMsg(s.exec, s.flow, n.node, 'process') }));
    t += n.dur;
    if (n.fail) out.push(jsonLine({ ts: t, reqId: s.reqId, level: 'error', msg: failMsg(s.exec, s.flow, n.node, n.fail) }));
    else out.push(jsonLine({ ts: t, reqId: s.reqId, msg: nodeMsg(s.exec, s.flow, n.node, 'done', n.next) }));
  }
  return out;
}

export function parseAll(raws: string[], ns = 'ns'): LogLine[] {
  const out: LogLine[] = [];
  for (const r of raws) { const l = parseLine(r, ns, new Set([ns]), out.length); if (l) out.push(l); }
  return out;
}

/** A deterministic, realistic-looking capture of `n` lines. */
export function sampleCapture(n = 200, t0 = Date.UTC(2026, 9, 12, 10, 0, 0)): string[] {
  const out: string[] = [];
  const nodes = ['script_be_v2', 'http_request', 'condition', 'JS Executer', 'set_var'];
  let t = t0;
  let k = 0;
  while (out.length < n) {
    const exec = `exec-${k}`;
    const req = `req-${String(1000 + k).padStart(4, '0')}-ab12cd34`;
    out.push(httpLine({ ts: t, path: '/flow/execute/my-login-flow', status: k % 7 === 6 ? 502 : 200, size: 300 + k }));
    const script: FlowScript = { exec, flow: 'my-login-flow', reqId: req, t0: t, nodes: [] };
    for (let i = 0; i < 4; i++) {
      const node = nodes[(k + i) % nodes.length];
      script.nodes.push({ node, dur: 20 + ((k * 37 + i * 91) % 600), next: `#${9000 + i}`, fail: (k % 7 === 6 && i === 3) ? 'AxiosError: Request failed with status code 502' : undefined });
    }
    out.push(...flowLines(script));
    out.push(jsonLine({ ts: t + 2, level: 'debug', reqId: req, msg: 'MongoDBSessionRepository count started' }));
    out.push(jsonLine({ ts: t + 40, level: 'debug', reqId: req, msg: 'MongoDBSessionRepository count finished' }));
    out.push(jsonLine({ ts: t + 50, level: 'trace', reqId: req, msg: 'Health "liveness" probe request received' }));
    if (k % 5 === 4) {
      out.push(`${POD_ENGINE} flow-engine \x1b[31mSomething went wrong in script\x1b[0m`);
      out.push(`${POD_ENGINE} flow-engine     SyntaxError: Illegal return statement`);
    }
    t += 1200;
    k++;
  }
  return out.slice(0, n);
}
