// SaaS viewer: connects to the relay as a consumer using ?s=<session> from the URL.
console.log('[Kube Logger web viewer] build:saas-v1 loaded');

// Read session from URL (?s=<id> or ?session=<id>).
const _urlParams = new URLSearchParams(location.search);
const SESSION_ID = (_urlParams.get('s') || _urlParams.get('session') || '').trim();
const AGENT_URL = (() => {
  // Same host as the page, /consumer?session=<id>. Use wss:// if the page is https.
  const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
  return `${proto}//${location.host}/consumer?session=${encodeURIComponent(SESSION_ID)}`;
})();

// localStorage-backed shim for the chrome.* APIs the legacy extension-shared
// code calls. Named `_ext` (not `chrome`) because Chromium exposes `chrome` as
// a non-shadowable global on regular pages — declaring `const chrome` there
// throws "Identifier 'chrome' has already been declared" at parse time.
const _ext = (() => {
  const LS_PREFIX = 'chrome-shim:';
  return {
    storage: {
      local: {
        get(keys, cb) {
          const out = {};
          const arr = typeof keys === 'string' ? [keys]
            : Array.isArray(keys) ? keys
            : keys && typeof keys === 'object' ? Object.keys(keys)
            : [];
          for (const k of arr) {
            const raw = localStorage.getItem(LS_PREFIX + k);
            if (raw !== null) { try { out[k] = JSON.parse(raw); } catch {} }
          }
          (cb || (() => {}))(out);
        },
        set(obj, cb) {
          for (const [k, v] of Object.entries(obj || {})) localStorage.setItem(LS_PREFIX + k, JSON.stringify(v));
          (cb || (() => {}))();
        },
      },
      onChanged: { addListener() {} },
    },
    runtime: { sendMessage() {} },
  };
})();
// One-time migration from the old `io-*` localStorage keys.
(function migrateStorageKeys(){
  const map = {
    'io-hidden-patterns': 'kube-logger-hidden-patterns',
    'io-highlights':      'kube-logger-highlights',
    'io-last-ns':         'kube-logger-last-ns',
  };
  for (const [oldK, newK] of Object.entries(map)) {
    const v = localStorage.getItem(oldK);
    if (v === null) continue;
    if (localStorage.getItem(newK) === null) localStorage.setItem(newK, v);
    localStorage.removeItem(oldK);
  }
})();
const HIDDEN_KEY='kube-logger-hidden-patterns';
const HIGHLIGHT_KEY='kube-logger-highlights';
const PRESETS_KEY='kube-logger-filter-presets';
const HI_COLORS=['#e6db74','#a6e22e','#66d9ef','#fd971f','#ae81ff','#f92672','#e6db74','#a1efe4'];
const S = {
  ws:null, lines:[], raw:[], filtered:[], errIdx:[], curErr:-1,
  pods:new Set(), reqs:new Map(), flowNodes:[],
  search:'', hideTrace:false, level:'all', pod:'all', req:'all',
  autoScroll:true, capturing:false, start:null, buf:[], scheduled:false,
  hiddenPatterns:JSON.parse(localStorage.getItem(HIDDEN_KEY)||'[]'),
  hiddenExecIds:new Set(),
  highlights:JSON.parse(localStorage.getItem(HIGHLIGHT_KEY)||'[]'),
  nsColors:{},         // { ns: '#rrggbb' } — shared with popup via chrome.storage
  nsCounts:new Map(),  // ns -> line count (filtered view)
  nsSeen:new Set(),    // all ns that have emitted at least one line this session
  nsCapturing:new Set(),// all ns the current capture is subscribed to (from capture-start)
  presets:{},          // { name: {filter state snapshot} }
  currentPreset:'',    // name of the currently-loaded preset (UI display only)
};

const $=id=>document.getElementById(id);

// ── Parse ─────────────────────
const NX=/^(\S+)\s+(\S+)\s+(\S+)\s+-\s+-\s+\[([^\]]+)\]\s+"(\w+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)\s+"([^"]*)"\s+"([^"]*)"/;
const SJ=/^(\S+)\s+(\S+)\s+(\{.+\})$/;
const SP=/^([+-])\s+(\S+)\s+.\s+(\S+)$/;

const FLOW_NODE_RE=/\[([^\]]+)\]\s+(\S+)\s+-\s+Node\s+(\S+)\s+is\s+in\s+(\w+)\s+state(?:,\s+next\s+node\s+is\s+(\S+))?/;
const FLOW_FAIL_RE=/Failure from node\s+(\S+)\s+\(([^)]+)\)/;
const FLOW_FAIL_FULL_RE=/\[([^\]]+)\]\s+(\S+)\s+-\s+Failure from node\s+(\S+)\s+\(([^)]+)\)/;
const FLOW_START_RE=/\[([^\]]+)\]\s+(\S+)\s+-\s+(Starting|Executing|Running)\s/i;
const FLOW_PATH_RE=/\/flow\/execute\/(?:custom\/)?([^?\s/]+)/;
const AXIOS_ERR_RE=/Error.*?:\s*(AxiosError:.*)/;

// Strip ANSI escape codes
function stripAnsi(s){return s.replace(/\x1b\[[0-9;]*m/g,'').replace(/\[[\d]+m/g,'');}

// Script-executor structured log: [timestamp] [LEVEL] [reqId] [domainId] [Caller] [On Behalf Of] [source] - service
const SE_RE=/\[(\d{4}-\d{2}-\d{2}T[\d:.]+)\]\s*\[(\w+)\]\s*\[([^\]]+)\]\s*\[([^\]]*)\]/;
// Error detail continuation: leading whitespace + ErrorType: message
const ERR_DETAIL_RE=/^\s+((?:Syntax|Type|Reference|Range|URI|Eval)Error:\s*.+)/;

function parse(raw,i,ns){
  let t=raw.trimEnd(); if(!t)return null;
  // Stern may emit "<ns> <pod> <container> <msg>" when running across multiple
  // namespaces in one process. Strip the leading ns so the downstream regexes
  // that expect "<pod> <container> <msg>" still match.
  if(ns&&t.startsWith(ns+' ')){t=t.slice(ns.length+1);}
  else if(S.nsCapturing&&S.nsCapturing.size){
    for(const n of S.nsCapturing){if(t.startsWith(n+' ')){ns=n;t=t.slice(n.length+1);break;}}
  }
  if(SP.test(t))return{type:'stern',idx:i,raw:t,ns};
  const nm=t.match(NX);
  if(nm){
    const s=+nm[7];
    const r={type:'http',pod:nm[1],container:nm[2],timestamp:nm[4],method:nm[5],path:nm[6],status:s,size:+nm[8],level:'HTTP',idx:i,raw:t,ns};
    const fp=nm[6].match(FLOW_PATH_RE);if(fp)r.flowName=fp[1];
    return r;
  }
  const jm=t.match(SJ);
  if(jm){try{const j=JSON.parse(jm[3]),d=j.data||[];let msg='',fi=null;for(const x of d){if(typeof x==='string')msg+=(msg?' ':'')+x;else if(x&&x.file)fi=x;else if(x&&typeof x==='object')msg+=(msg?' ':'')+JSON.stringify(x);}
    const r={type:'json',pod:jm[1],container:jm[2],timestamp:j.timestamp,level:(j.level||'INFO').toUpperCase(),reqId:j.req_id,msg,fileInfo:fi,data:j.data,json:j,idx:i,raw:t,ns};
    const fn=(msg||'').match(FLOW_NODE_RE);
    if(fn){r.flowExecId=fn[1];r.flowName=fn[2];r.flowNode=fn[3];r.flowState=fn[4];r.flowNext=fn[5];}
    else{const ff=(msg||'').match(FLOW_FAIL_FULL_RE);if(ff){r.flowExecId=ff[1];r.flowName=ff[2];r.flowNode=ff[3];r.flowFailReason=ff[4];r.flowState='failed';}
    else{const fl=(msg||'').match(FLOW_FAIL_RE);if(fl){r.failNodeId=fl[1];r.failNodeLabel=fl[2];r.flowState='failed';}}}
    if(!r.flowName){const fs=(msg||'').match(FLOW_START_RE);if(fs){r.flowExecId=fs[1];r.flowName=fs[2];}}
    // Extract API errors
    const ax=(msg||'').match(AXIOS_ERR_RE);if(ax)r.apiError=ax[1];
    // Extract "save error in session" errors
    if((msg||'').includes('Error and save error in session'))r.isFlowError=true;
    // Extract "Failure output not connected" errors
    const fnc=(msg||'').match(/"Failure" output of node (\d+) is not connected/);
    if(fnc){r.failNodeId=fnc[1];r.isFlowError=true;}
    return r;
  }catch{}}
  const tp=t.match(/^(\S+)\s+(\S+)\s+(.+)$/);
  if(tp&&tp[1].startsWith('io-')){
    const cleanMsg=stripAnsi(tp[3]);
    // Try to parse script-executor structured log format
    const se=cleanMsg.match(SE_RE);
    if(se){
      return{type:'script-error',pod:tp[1],container:tp[2],timestamp:se[1],level:se[2].toUpperCase(),scriptReqId:se[3],msg:cleanMsg,idx:i,raw:t,ns};
    }
    // Check for error detail continuation (e.g., "    SyntaxError: Illegal return statement")
    const ed=cleanMsg.match(ERR_DETAIL_RE);
    if(ed){
      return{type:'plain',pod:tp[1],container:tp[2],msg:ed[1],level:'ERROR',isErrorDetail:true,idx:i,raw:t,ns};
    }
    return{type:'plain',pod:tp[1],container:tp[2],msg:cleanMsg,level:cleanMsg.toLowerCase().includes('error')?'ERROR':cleanMsg.toLowerCase().includes('warn')?'WARN':'INFO',idx:i,raw:t,ns};
  }
  return{type:'raw',msg:t,level:'INFO',idx:i,raw:t,ns};
}

function extractFlow(lines){
  const nodes=[],seen=new Set();
  const nr=/\[([^\]]+)\]\s+(\S+)\s+-\s+Node\s+(\S+)\s+is\s+in\s+(\w+)\s+state(?:,\s+next\s+node\s+is\s+(\S+))?/;
  const fr=/Failure from node\s+(\S+)\s+\(([^)]+)\)/;
  const fnc=/"Failure" output of node (\d+) is not connected/;
  // Build a map of numeric node ID -> label from failure messages
  const idLabels=new Map();
  for(const l of lines){if(!l||l.type!=='json')continue;
    const fm=(l.msg||'').match(fr);if(fm)idLabels.set(fm[1],fm[2]);}
  // Also collect script-executor errors to show in timeline
  const scriptErrors=[];
  for(const l of lines){
    if(l&&l.isErrorDetail){scriptErrors.push({msg:l.msg,lineIdx:l.idx,pod:l.pod});}
    if(!l||l.type!=='json')continue;
    const m=(l.msg||'').match(nr);if(m){const k=m[3]+'-'+m[4];if(!seen.has(k)){seen.add(k);nodes.push({node:m[3],state:m[4],next:m[5],nextLabel:m[5]?idLabels.get(m[5]):null,lineIdx:l.idx,label:m[3],flowExecId:m[1],flowName:m[2],reqId:l.reqId});}}
    const fm2=(l.msg||'').match(fr);if(fm2){const k=fm2[1]+'-f';if(!seen.has(k)){seen.add(k);nodes.push({node:fm2[1],label:fm2[2],state:'failed',lineIdx:l.idx,reqId:l.reqId});}}
    // "Failure output not connected" - add as a failed node, try to look up the node type
    const nc=(l.msg||'').match(fnc);if(nc){const k='nc-'+nc[1];if(!seen.has(k)){seen.add(k);
      // Find the preceding node whose "next" was this ID to get the node type + flow context
      let nodeType='#'+nc[1],fExecId=null,fName=null;
      for(const prev of nodes){if(prev.reqId===l.reqId&&prev.flowExecId){fExecId=prev.flowExecId;fName=prev.flowName;}if(prev.next===nc[1]){nodeType=prev.node+' → FAIL';if(prev.flowExecId){fExecId=prev.flowExecId;fName=prev.flowName;}break;}}
      nodes.push({node:nodeType,label:'Failure output not connected (#'+nc[1]+')',state:'failed',lineIdx:l.idx,reqId:l.reqId,flowExecId:fExecId,flowName:fName});}}}
  // Add script-executor errors as failed nodes in the timeline
  for(const se of scriptErrors){const k='se-'+se.lineIdx;if(!seen.has(k)){seen.add(k);nodes.push({node:'script-executor',label:se.msg,state:'failed',lineIdx:se.lineIdx});}}
  return nodes;
}

// ── Render helpers ────────────
function esc(s){return(s==null?'':String(s)).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function hiSearch(t,q){
  let r=esc(t);
  // Apply highlight terms first (each with its own color)
  for(let i=0;i<S.highlights.length;i++){
    const h=S.highlights[i];if(!h)continue;
    try{const e=h.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');r=r.replace(new RegExp('('+e+')','gi'),`<span class="hi hi${i%HI_COLORS.length}">$1</span>`);}catch{}
  }
  // Apply search highlight on top
  if(q){try{const e=q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');r=r.replace(new RegExp('('+e+')','gi'),'<span class="hi">$1</span>');}catch{}}
  return r;
}
function shortPod(p){if(!p)return'';const m=p.match(/^io-(.+?)(?:-[a-f0-9]{6,})+/);return m?m[1]:p.length>22?p.slice(0,20)+'..':p;}
function shortReq(r){return r?r.slice(0,8):'';}
function fmtTs(ts){if(!ts)return'';try{return new Date(ts).toISOString().slice(11,23);}catch{return ts.slice(0,12);}}

function lineHtml(l,q,prev){
  if(l.type==='stern')return'';
  // Detect multi-line continuation: consecutive plain/script-error lines from the same pod
  const plainTypes=['plain','script-error'];
  const isMultiCont=prev&&plainTypes.includes(l.type)&&plainTypes.includes(prev.type)&&l.pod===prev.pod;
  let c='ll';
  if(l.type==='plain'||l.type==='script-error')c+=' lplain';
  if(l.type==='script-error')c+=' lscript-err';
  if(l.isErrorDetail)c+=' lerror-detail';
  if(isMultiCont)c+=' lmulti';
  if(l.level)c+=' l'+l.level;
  if(l.type==='http'&&l.status>=500)c+=' h5';else if(l.type==='http'&&l.status>=400)c+=' h4';
  if(l.level==='ERROR'||l.level==='FATAL'||l.isFlowError||l.isErrorDetail||l.flowState==='failed')c+=' fl';
  const nsColor=l.ns?ensureNsColor(l.ns):'';
  const nsStyle=nsColor?` style="--ns-color:${nsColor};--ns-bg:${hexToRgba(nsColor,0.35)}"`:'';
  const nsTitle=l.ns?` data-ns="${esc(l.ns)}"`:'';
  let h=`<div class="${c}"${nsStyle}${nsTitle} data-i="${l.idx}">`;
  if(l.ns)h+=`<span class="ll-ns-stripe" title="${esc(l.ns)}"></span>`;
  h+=`<span class="ln" data-jump="${l.idx}" title="Show this line in full context">${l.idx+1}</span>`;
  h+=`<span class="lt">${l.timestamp?fmtTs(l.timestamp):''}</span>`;
  h+=`<span class="lv ${l.level||''}">${isMultiCont?'':l.level||''}</span>`;
  h+=`<span class="lp" title="${esc(l.pod||'')}" data-pod="${esc(l.pod||'')}">${isMultiCont?'&#x2502;':esc(shortPod(l.pod))}</span>`;
  h+=`<span class="lr" title="${esc(l.reqId||'')}" data-req="${esc(l.reqId||'')}">${l.reqId?shortReq(l.reqId):''}</span>`;
  if(l.type==='http'){const sc=l.status>=500?'s5':l.status>=400?'s4':l.status>=300?'s3':'s2';h+=`<span class="lm">${hiSearch(l.method+' '+l.path+' ',q)}<span class="hs ${sc}">${l.status}</span> ${l.size}B</span>`;}
  else if(l.failNodeId){
    h+=`<span class="lm"><span class="lfail" data-fail="${l.idx}">&#x26A0; <strong>${esc(l.failNodeLabel)}</strong> <span class="lfail-id">#${esc(l.failNodeId)}</span> <span class="lfail-hint">click for context</span></span></span>`;
  }
  else{const m=l.msg||l.raw||'';const d=m.length>500?m.slice(0,500)+'...':m;
    const hasJson=l.json||l.data||/\{\s*["']|\[\s*[\{\[]|:\s*\{/.test(m);
    const inspectBtn=hasJson?`<span class="jin" data-inspect="${l.idx}" title="Open in JSON Inspector">{&nbsp;}</span>`:'';
    h+=`<span class="lm">${hiSearch(d,q)}${l.type==='json'&&l.data?`<span class="je" data-li="${l.idx}">[+]</span>`:''}${inspectBtn}</span>`;}
  if(!isMultiCont)h+=`<span class="lh" data-hide="${l.idx}" title="Hide messages like this">&times;</span>`;
  return h+'</div>';
}

function jsonDetailHtml(l){
  const str=JSON.stringify(l.json||l.data,null,2).replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,m=>{
    let c='jn';if(/^"/.test(m))c=/:$/.test(m)?'jk':'js';else if(/true|false/.test(m))c='jb';else if(/null/.test(m))c='jl';return`<span class="${c}">${m}</span>`;});
  return`<div class="jd" id="jd-${l.idx}">${str}</div>`;
}

// ── Filter / render ───────────
function isMultilineMember(l){return l&&(l.type==='plain'||l.type==='script-error');}

function shouldShow(l){
  if(!l||l.type==='stern')return false;
  // 1. Your manually hidden patterns (click × on a line)
  if(S.hiddenPatterns.length){const t=(l.msg||l.raw||'').toLowerCase();for(const p of S.hiddenPatterns){if(t.includes(p.toLowerCase()))return false;}}
  // 2. Your manually hidden flow executions (click × on flow label)
  if(S.hiddenExecIds.size&&l.flowExecId&&S.hiddenExecIds.has(l.flowExecId))return false;
  if(S.hiddenExecIds.size&&l.reqId&&S._hiddenReqIds&&S._hiddenReqIds.has(l.reqId))return false;
  // 3. Filter dropdowns (only if you explicitly set them)
  if(S.level!=='all'&&l.level!==S.level)return false;
  if(S.hideTrace&&l.level==='TRACE')return false;
  if(S.pod!=='all'&&l.pod!==S.pod)return false;
  if(S.req!=='all'&&l.reqId!==S.req)return false;
  // 4. Search
  if(S.search){try{if(!new RegExp(S.search,'i').test(l.raw||l.msg||''))return false;}catch{if(!(l.raw||l.msg||'').toLowerCase().includes(S.search.toLowerCase()))return false;}}
  return true;
}

// Like shouldShow but bypasses search/level/req/trace filters — used to keep
// multi-line continuation context visible when the FIRST line matched the search.
function shouldShowAsContinuation(l){
  if(!l||l.type==='stern')return false;
  if(S.hiddenPatterns.length){const t=(l.msg||l.raw||'').toLowerCase();for(const p of S.hiddenPatterns){if(t.includes(p.toLowerCase()))return false;}}
  if(S.hiddenExecIds.size&&l.flowExecId&&S.hiddenExecIds.has(l.flowExecId))return false;
  if(S.hiddenExecIds.size&&l.reqId&&S._hiddenReqIds&&S._hiddenReqIds.has(l.reqId))return false;
  if(S.pod!=='all'&&l.pod!==S.pod)return false;
  return true;
}

function rebuildFiltered(){
  S.filtered=[];S.errIdx=[];S.curErr=-1;
  const included=new Array(S.lines.length).fill(false);
  // First pass: lines passing the full filter
  for(let i=0;i<S.lines.length;i++){if(shouldShow(S.lines[i]))included[i]=true;}
  // Second pass: for every included multi-line group member, sweep its contiguous
  // same-pod neighbors (both directions) so the rest of the group stays visible.
  for(let i=0;i<S.lines.length;i++){
    if(!included[i])continue;
    const l=S.lines[i];
    if(!isMultilineMember(l))continue;
    for(let j=i-1;j>=0;j--){
      const pl=S.lines[j];
      if(!isMultilineMember(pl)||pl.pod!==l.pod)break;
      if(included[j])break;
      if(!shouldShowAsContinuation(pl))break;
      included[j]=true;
    }
    for(let j=i+1;j<S.lines.length;j++){
      const nl=S.lines[j];
      if(!isMultilineMember(nl)||nl.pod!==l.pod)break;
      if(included[j])continue;
      if(!shouldShowAsContinuation(nl))break;
      included[j]=true;
    }
  }
  for(let i=0;i<S.lines.length;i++){
    if(!included[i])continue;
    const l=S.lines[i];
    S.filtered.push(i);
    if(l.level==='ERROR'||l.level==='FATAL'||l.isFlowError||l.isErrorDetail||l.flowState==='failed'||(l.type==='http'&&l.status>=500))S.errIdx.push(i);
  }
}

function fullRender(){
  const c=$('lc');let h='';let prev=null;
  for(const i of S.filtered){const l=S.lines[i];try{h+=lineHtml(l,S.search,prev);}catch(e){console.error('lineHtml error at',i,e);h+=`<div class="ll lERROR" data-i="${i}"><span class="ln">${i+1}</span><span class="lm" style="color:var(--error)">[render error: ${e.message}]</span></div>`;}prev=l;}
  c.innerHTML=h;
  c.classList.add('v');$('welcome').classList.add('h');$('filterBar').style.display='flex';
  updateStats();updateErrBanner();updateFlow();
}

function appendLive(l){
  let show=shouldShow(l);
  // If this is a continuation line of a multi-line group whose previous line was already
  // shown (e.g., matched the search), include it so we don't lose the content body.
  if(!show&&isMultilineMember(l)&&shouldShowAsContinuation(l)&&S.filtered.length){
    const prevIdx=S.filtered[S.filtered.length-1];
    if(prevIdx===l.idx-1){
      const pl=S.lines[prevIdx];
      if(isMultilineMember(pl)&&pl.pod===l.pod)show=true;
    }
  }
  if(!show)return;
  S.filtered.push(l.idx);
  if(l.level==='ERROR'||l.level==='FATAL'||l.isFlowError||l.isErrorDetail||l.flowState==='failed'||(l.type==='http'&&l.status>=500))S.errIdx.push(l.idx);
  S.buf.push(l);
  if(!S.scheduled){S.scheduled=true;requestAnimationFrame(flushBuf);}
}

function flushBuf(){
  S.scheduled=false;if(!S.buf.length)return;
  const c=$('lc');let h='';
  // Get the last rendered line for multi-line detection
  let prev=S.filtered.length>S.buf.length?S.lines[S.filtered[S.filtered.length-S.buf.length-1]]:null;
  for(const l of S.buf){try{h+=lineHtml(l,S.search,prev);}catch(e){console.error('lineHtml error:',e);h+=`<div class="ll lERROR" data-i="${l.idx}"><span class="ln">${l.idx+1}</span><span class="lm" style="color:var(--error)">[render error: ${e.message}]</span></div>`;}prev=l;}
  c.insertAdjacentHTML('beforeend',h);S.buf=[];
  if(S.autoScroll)c.scrollTop=c.scrollHeight;
  updateStats();
  if(S.filtered.length%50===0){updateFlow();updateErrBanner();}
}

function updateStats(){
  const c={t:S.filtered.length,E:0,W:0,D:0,T:0,H:0};
  for(const i of S.filtered){const l=S.lines[i];if(!l)continue;if(l.level==='ERROR'||l.level==='FATAL')c.E++;else if(l.level==='WARN')c.W++;else if(l.level==='DEBUG')c.D++;else if(l.level==='TRACE')c.T++;if(l.type==='http')c.H++;}
  $('stats').innerHTML=`<span class="s"><span class="d to"></span>${c.t}</span>${c.E?`<span class="s"><span class="d er"></span>${c.E} err</span>`:''}${c.W?`<span class="s"><span class="d wr"></span>${c.W} warn</span>`:''}<span class="s"><span class="d db"></span>${c.D} dbg</span><span class="s"><span class="d tr"></span>${c.T} trc</span>${c.H?`<span class="s"><span class="d ht"></span>${c.H} http</span>`:''}`;
  $('searchCount').textContent=S.search?`${S.filtered.length} matches`:'';
}

function updateErrBanner(){
  const b=$('errBanner');
  if(S.errIdx.length){
    const sums=[];for(const i of S.errIdx.slice(0,3)){const l=S.lines[i];if(l.type==='http')sums.push(`${l.method} ${l.path} -> ${l.status}`);else if(l.msg)sums.push(l.msg.slice(0,80));}
    b.textContent=`${S.errIdx.length} issue(s): ${sums.join(' | ')}`;b.classList.add('v');
  }else b.classList.remove('v');
}

function updateFlow(){
  S.flowNodes=extractFlow(S.lines.filter(Boolean));
  const c=$('fnodes'),w=$('ftl');c.innerHTML='';
  // Filter out hidden executions
  const visible=S.flowNodes.filter(n=>!n.flowExecId||!S.hiddenExecIds.has(n.flowExecId));
  if(!visible.length&&!S.hiddenExecIds.size){w.classList.remove('v');return;}
  w.classList.add('v');
  // Show hidden count badge if any are hidden
  if(S.hiddenExecIds.size){
    // Build list of hidden flow names for the badge
    const hiddenNames=[];
    for(const eid of S.hiddenExecIds){
      let name='';
      for(const fn of S.flowNodes){if(fn.flowExecId===eid&&fn.flowName){name=fn.flowName;break;}}
      hiddenNames.push(name||eid.slice(0,8));
    }
    const badge=document.createElement('span');badge.className='fhidden-badge';
    badge.textContent=`${S.hiddenExecIds.size} hidden: ${hiddenNames.join(', ')}`;
    badge.title='Click to restore: '+hiddenNames.join(', ');
    badge.addEventListener('click',()=>{clearHiddenExecs();toast('All flows restored');});
    c.appendChild(badge);
    if(visible.length)c.insertAdjacentHTML('beforeend','<span class="farrow fsep">|</span>');
  }
  let lastExec='';
  visible.forEach((n,i)=>{
    // Insert flow name separator when flow exec changes
    if(n.flowExecId&&n.flowExecId!==lastExec){
      if(i||(S.hiddenExecIds.size))c.insertAdjacentHTML('beforeend','<span class="farrow fsep">|</span>');
      const fl=document.createElement('span');fl.className='fflow-label';
      fl.innerHTML=`${esc(n.flowName||'?')}<span class="fflow-hide" title="Hide this flow execution">&times;</span>`;
      fl.querySelector('.fflow-hide').addEventListener('click',ev=>{
        ev.stopPropagation();
        hideFlowExec(n.flowExecId,n.flowName);
      });
      fl.addEventListener('click',()=>showNodePopover(fl,n));
      c.appendChild(fl);
      lastExec=n.flowExecId;
    }
    if(i||S.hiddenExecIds.size)c.insertAdjacentHTML('beforeend','<span class="farrow">&#8594;</span>');
    const e=document.createElement('span');e.className=`fnode ${n.state}`;
    e.textContent=n.label||n.node;
    e.title=`${n.node} (${n.state})${n.next?' → #'+n.next:''}${n.nextLabel?' ('+n.nextLabel+')':''}${n.flowName?' | flow: '+n.flowName:''}${n.flowExecId?' | exec: '+n.flowExecId.slice(0,8):''}`;
    e.addEventListener('click',ev=>{
      ev.stopPropagation();
      showNodePopover(e,n);
    });
    c.appendChild(e);
  });
}

function showNodePopover(anchor,n){
  let pop=document.getElementById('nodePopover');
  if(pop)pop.remove();
  pop=document.createElement('div');pop.id='nodePopover';pop.className='node-pop';
  let h='';
  // For error/failure nodes, show label prominently first
  if(n.state==='failed'&&n.label&&n.label!==n.node){
    h+=`<div class="np-row"><span class="np-label">Error</span><span class="np-val np-fail">${esc(n.label)}</span></div>`;
  }
  h+=`<div class="np-row"><span class="np-label">Node</span><span class="np-val">${esc(n.node)}</span></div>`;
  h+=`<div class="np-row"><span class="np-label">State</span><span class="np-val np-state-${n.state}">${esc(n.state)}</span></div>`;
  if(n.flowName)h+=`<div class="np-row"><span class="np-label">Flow</span><span class="np-val">${esc(n.flowName)}</span></div>`;
  if(n.flowExecId)h+=`<div class="np-row"><span class="np-label">Exec ID</span><span class="np-val">${esc(n.flowExecId.slice(0,12))}...</span></div>`;
  if(n.next)h+=`<div class="np-row"><span class="np-label">Next Node</span><span class="np-val">#${esc(n.next)}${n.nextLabel?' <em>('+esc(n.nextLabel)+')</em>':''}</span></div>`;
  if(n.reqId)h+=`<div class="np-row"><span class="np-label">Request</span><span class="np-val np-link" data-req="${esc(n.reqId)}">${esc(n.reqId.slice(0,12))}... &#8599;</span></div>`;
  h+=`<div class="np-actions"><span class="np-btn" data-action="scroll">Jump to log line</span>${n.reqId?'<span class="np-btn" data-action="trace">Open trace</span>':''}</div>`;
  pop.innerHTML=h;
  document.body.appendChild(pop);
  // Position below anchor
  const r=anchor.getBoundingClientRect();
  pop.style.left=Math.min(r.left,window.innerWidth-pop.offsetWidth-10)+'px';
  pop.style.top=(r.bottom+4)+'px';
  pop.addEventListener('click',e=>{
    const btn=e.target.closest('[data-action]');
    if(btn){
      if(btn.dataset.action==='scroll'){scrollTo(n.lineIdx);pop.remove();}
      else if(btn.dataset.action==='trace'&&n.reqId){openTrace(n.reqId);pop.remove();}
    }
    const req=e.target.closest('[data-req]');
    if(req&&!btn){openTrace(req.dataset.req);pop.remove();}
  });
  // Close on outside click
  setTimeout(()=>document.addEventListener('click',function cl(e){if(!pop.contains(e.target)){pop.remove();document.removeEventListener('click',cl);}},{once:false}),0);
}

function showFailurePopover(anchor,l){
  let pop=document.getElementById('nodePopover');
  if(pop)pop.remove();

  // Look up flow context: find lines with same reqId that have flow info
  const reqId=l.reqId;
  let flowName=null,flowExecId=null;
  const nestedPath=[];
  const nodesBefore=[];
  if(reqId){
    for(const ol of S.lines){
      if(!ol||ol.reqId!==reqId)continue;
      if(ol.flowName&&!flowName)flowName=ol.flowName;
      if(ol.flowExecId&&!flowExecId)flowExecId=ol.flowExecId;
      // Collect node execution path leading up to this failure
      if(ol.flowNode&&ol.idx<=l.idx){
        nodesBefore.push({node:ol.flowNode,state:ol.flowState,next:ol.flowNext});
        if(ol.flowNode==='nested_flow'&&ol.flowState==='process')nestedPath.push(ol.flowNext||'?');
      }
    }
  }

  // Also check if the failNodeId appears as a "next" target to find which node type points to it
  let calledFrom=null;
  if(reqId&&l.failNodeId){
    for(const ol of S.lines){
      if(!ol||ol.reqId!==reqId)continue;
      if(ol.flowNext===l.failNodeId&&ol.idx<l.idx){calledFrom={node:ol.flowNode,state:ol.flowState};break;}
    }
  }

  pop=document.createElement('div');pop.id='nodePopover';pop.className='node-pop';
  let h=`<div class="np-row"><span class="np-label">Node Label</span><span class="np-val np-fail">${esc(l.failNodeLabel)}</span></div>`;
  h+=`<div class="np-row"><span class="np-label">Node ID</span><span class="np-val">#${esc(l.failNodeId)}</span></div>`;
  if(flowName)h+=`<div class="np-row"><span class="np-label">Flow</span><span class="np-val">${esc(flowName)}</span></div>`;
  if(flowExecId)h+=`<div class="np-row"><span class="np-label">Exec ID</span><span class="np-val">${esc(flowExecId.slice(0,12))}...</span></div>`;
  if(nestedPath.length)h+=`<div class="np-row"><span class="np-label">Nesting Depth</span><span class="np-val">${nestedPath.length} level${nestedPath.length>1?'s':''} deep</span></div>`;
  if(calledFrom)h+=`<div class="np-row"><span class="np-label">Called From</span><span class="np-val">${esc(calledFrom.node)} (${esc(calledFrom.state)})</span></div>`;
  if(reqId)h+=`<div class="np-row"><span class="np-label">Request</span><span class="np-val np-link" data-req="${esc(reqId)}">${esc(reqId.slice(0,12))}... &#8599;</span></div>`;

  // Show the node execution path leading here
  if(nodesBefore.length){
    h+='<div class="np-divider"></div><div class="np-section-label">Execution path to failure</div><div class="np-path">';
    const seen=new Set();
    for(const n of nodesBefore){
      const k=n.node+'-'+n.state;if(seen.has(k))continue;seen.add(k);
      const cls=n.node==='nested_flow'?'np-nested':n.state==='done'?'np-done':'';
      h+=`<span class="np-path-node ${cls}">${esc(n.node)}</span><span class="np-path-arrow">&#8594;</span>`;
    }
    h+=`<span class="np-path-node np-path-fail">${esc(l.failNodeLabel)}</span>`;
    h+='</div>';
  }

  h+=`<div class="np-actions"><span class="np-btn" data-action="scroll">Jump to log line</span>${reqId?'<span class="np-btn" data-action="trace">Open full trace</span>':''}</div>`;
  pop.innerHTML=h;
  document.body.appendChild(pop);
  const r=anchor.getBoundingClientRect();
  pop.style.left=Math.max(10,Math.min(r.left,window.innerWidth-pop.offsetWidth-10))+'px';
  pop.style.top=(r.bottom+4)+'px';
  pop.addEventListener('click',e=>{
    const btn=e.target.closest('[data-action]');
    if(btn){
      if(btn.dataset.action==='scroll'){scrollTo(l.idx);pop.remove();}
      else if(btn.dataset.action==='trace'&&reqId){openTrace(reqId);pop.remove();}
    }
    const req=e.target.closest('[data-req]');
    if(req&&!btn){openTrace(req.dataset.req);pop.remove();}
  });
  setTimeout(()=>document.addEventListener('click',function cl(e){if(!pop.contains(e.target)){pop.remove();document.removeEventListener('click',cl);}},{once:false}),0);
}

function populateFilters(){
  const ps=$('podFilter'),rs=$('reqidFilter');
  ps.innerHTML='<option value="all">All Services</option>';
  for(const p of[...S.pods].sort()){const o=document.createElement('option');o.value=p;o.textContent=shortPod(p);ps.appendChild(o);}
  rs.innerHTML='<option value="all">All Requests</option>';
  for(const[id,ct]of[...S.reqs.entries()].sort((a,b)=>b[1]-a[1])){const o=document.createElement('option');o.value=id;o.textContent=`${shortReq(id)} (${ct})`;rs.appendChild(o);}
}

function scrollTo(idx){
  if(idx===undefined||idx===null){toast('No line index');return;}
  const c=$('lc');let el=c.querySelector(`[data-i="${idx}"]`);
  if(!el){
    // Line not in DOM (was filtered out). Inject it so we can scroll to it.
    const l=S.lines[idx];
    if(l){
      // Make sure log container is visible
      c.classList.add('v');$('welcome').classList.add('h');$('filterBar').style.display='flex';
      c.insertAdjacentHTML('beforeend',lineHtml(l,'',null));
      el=c.querySelector(`[data-i="${idx}"]`);
    }
  }
  if(el){
    c.querySelectorAll('.hl').forEach(e=>e.classList.remove('hl'));
    el.classList.add('hl');
    el.scrollIntoView({behavior:'smooth',block:'center'});
  } else {
    toast('Line #'+(idx+1)+' not in captured data');
  }
}

function jumpErr(dir){
  if(!S.errIdx.length){toast('No errors');return;}
  S.curErr=dir==='next'?(S.curErr+1)%S.errIdx.length:S.curErr<=0?S.errIdx.length-1:S.curErr-1;
  scrollTo(S.errIdx[S.curErr]);toast(`Error ${S.curErr+1}/${S.errIdx.length}`);
}

function toast(m){const e=$('toast');e.textContent=m;e.classList.add('v');clearTimeout(e._t);e._t=setTimeout(()=>e.classList.remove('v'),2500);}

// ── Hidden patterns ──────────
function extractPattern(l){
  const msg=l.msg||l.raw||'';
  // For health probes, use the probe type
  const hp=msg.match(/Health "(\w+)" probe request received/);if(hp)return'Health "'+hp[1]+'" probe request received';
  // For DB queries, use the repository + action
  const db=msg.match(/(MongoDB\w+Repository)[\s\S]*?(count started|count finished|query started|query finished)/);if(db)return db[1]+': '+db[2];
  // For flow node states, use the node type + state
  const fn=msg.match(/Node\s+(\S+)\s+is\s+in\s+(\w+)\s+state/);if(fn)return'Node '+fn[1]+' is in '+fn[2]+' state';
  // For experimental warnings
  if(msg.includes('ExperimentalWarning'))return'ExperimentalWarning';
  if(msg.includes('node --trace-warnings'))return'node --trace-warnings';
  // Fallback: first 80 chars, trimmed
  return msg.slice(0,80).trim();
}

// ── Hidden flow executions ───
function hideFlowExec(execId,flowName){
  if(!execId||S.hiddenExecIds.has(execId))return;
  S.hiddenExecIds.add(execId);
  // Also find all reqIds associated with this execId so we can hide their non-flow lines too
  rebuildHiddenReqIds();
  updateFlow();updateHiddenBtn();rebuildFiltered();fullRender();
  toast(`Hidden flow: ${flowName||execId.slice(0,8)}`);
}

function unhideFlowExec(execId){
  S.hiddenExecIds.delete(execId);
  rebuildHiddenReqIds();
  updateFlow();updateHiddenBtn();rebuildFiltered();fullRender();
}

function clearHiddenExecs(){
  S.hiddenExecIds.clear();
  S._hiddenReqIds=null;
  updateFlow();updateHiddenBtn();rebuildFiltered();fullRender();
}

function rebuildHiddenReqIds(){
  if(!S.hiddenExecIds.size){S._hiddenReqIds=null;return;}
  S._hiddenReqIds=new Set();
  for(const l of S.lines){
    if(l&&l.flowExecId&&S.hiddenExecIds.has(l.flowExecId)&&l.reqId)S._hiddenReqIds.add(l.reqId);
  }
}

// ── Highlights ───────────────
function addHighlight(term){
  if(!term||S.highlights.includes(term))return;
  S.highlights.push(term);
  localStorage.setItem(HIGHLIGHT_KEY,JSON.stringify(S.highlights));
  updateHighlightBtn();
  fullRender();
}

function removeHighlight(idx){
  S.highlights.splice(idx,1);
  localStorage.setItem(HIGHLIGHT_KEY,JSON.stringify(S.highlights));
  updateHighlightBtn();
  fullRender();
}

function clearHighlights(){
  S.highlights=[];
  localStorage.setItem(HIGHLIGHT_KEY,JSON.stringify(S.highlights));
  updateHighlightBtn();
  fullRender();
}

function updateHighlightBtn(){
  const btn=$('highlightBtn');
  const n=S.highlights.length;
  btn.textContent=n?'Highlights ('+n+')':'Highlights';
  btn.classList.toggle('active',n>0);
}

// ── Filter presets ──
function loadPresets(){
  try{
    const d=JSON.parse(localStorage.getItem(PRESETS_KEY)||'{}');
    S.presets=d.presets||{};
    S.currentPreset=d.current||'';
  }catch{S.presets={};S.currentPreset='';}
}

function savePresetsToStorage(){
  localStorage.setItem(PRESETS_KEY,JSON.stringify({current:S.currentPreset,presets:S.presets}));
}

function captureFilterState(){
  return{
    search:S.search,
    level:S.level,
    pod:S.pod,
    req:S.req,
    hideTrace:S.hideTrace,
    hiddenPatterns:[...S.hiddenPatterns],
    hiddenExecIds:[...S.hiddenExecIds],
    highlights:[...S.highlights],
  };
}

function applyFilterState(state){
  S.search=state.search||'';
  S.level=state.level||'all';
  S.pod=state.pod||'all';
  S.req=state.req||'all';
  S.hideTrace=!!state.hideTrace;
  S.hiddenPatterns=[...(state.hiddenPatterns||[])];
  S.hiddenExecIds=new Set(state.hiddenExecIds||[]);
  S.highlights=[...(state.highlights||[])];
  // Persist the individual keys (maintains existing cross-session behavior)
  localStorage.setItem(HIDDEN_KEY,JSON.stringify(S.hiddenPatterns));
  localStorage.setItem(HIGHLIGHT_KEY,JSON.stringify(S.highlights));
  // Update UI controls
  $('searchInput').value=S.search;
  $('levelFilter').value=S.level;
  // pod/req may reference a value that isn't in the current dropdown; selects silently ignore
  $('podFilter').value=S.pod;
  $('reqidFilter').value=S.req;
  $('hideTrace').classList.toggle('active',S.hideTrace);
  $('hideTrace').textContent=S.hideTrace?'Show TRACE':'Hide TRACE';
  updateHiddenBtn();
  updateHighlightBtn();
  rebuildHiddenReqIds();
  rebuildFiltered();
  fullRender();
}

function savePreset(name){
  name=(name||'').trim();
  if(!name)return;
  S.presets[name]=captureFilterState();
  S.currentPreset=name;
  savePresetsToStorage();
  renderPresetDropdown();
  toast(`Saved preset "${name}"`);
}

function deletePreset(name){
  if(!name||!S.presets[name])return;
  delete S.presets[name];
  if(S.currentPreset===name)S.currentPreset='';
  savePresetsToStorage();
  renderPresetDropdown();
  toast(`Deleted preset "${name}"`);
}

function applyPreset(name){
  if(!name||!S.presets[name])return;
  S.currentPreset=name;
  applyFilterState(S.presets[name]);
  savePresetsToStorage();
  renderPresetDropdown();
  toast(`Loaded preset "${name}"`);
}

function renderPresetDropdown(){
  const sel=$('presetSelect');if(!sel)return;
  sel.innerHTML='<option value="">— Preset —</option>';
  for(const name of Object.keys(S.presets).sort()){
    const opt=document.createElement('option');
    opt.value=name;opt.textContent=name;
    sel.appendChild(opt);
  }
  sel.value=S.currentPreset||'';
  const del=$('presetDel');if(del)del.disabled=!S.currentPreset;
}

function showHighlightPanel(){
  let pop=document.getElementById('highlightPanel');
  if(pop){pop.remove();return;}
  pop=document.createElement('div');pop.id='highlightPanel';pop.className='hidden-panel';
  let h='<div class="hp-header"><span>Highlights</span>';
  if(S.highlights.length)h+='<span class="hp-clear" data-clear="hi">Clear All</span>';
  h+='</div>';
  // Add input
  h+='<div class="hi-add"><input type="text" id="hiInput" placeholder="Type text to highlight..." /><button class="np-btn" id="hiAddBtn">Add</button></div>';
  // List
  if(S.highlights.length){
    h+='<div class="hp-list">';
    for(let i=0;i<S.highlights.length;i++){
      h+=`<div class="hp-item"><span class="hi-swatch" style="background:${HI_COLORS[i%HI_COLORS.length]}"></span><span class="hp-pattern">${esc(S.highlights[i])}</span><span class="hp-remove" data-hi="${i}">&times;</span></div>`;
    }
    h+='</div>';
  }
  pop.innerHTML=h;
  document.body.appendChild(pop);
  const r=$('highlightBtn').getBoundingClientRect();
  pop.style.left=Math.max(10,Math.min(r.left,window.innerWidth-340))+'px';
  pop.style.top=(r.bottom+4)+'px';
  // Focus input
  const inp=document.getElementById('hiInput');
  setTimeout(()=>inp.focus(),50);
  // Add on Enter or button click
  function doAdd(){const v=inp.value.trim();if(v){addHighlight(v);pop.remove();showHighlightPanel();}}
  inp.addEventListener('keydown',e=>{if(e.key==='Enter')doAdd();});
  document.getElementById('hiAddBtn').addEventListener('click',doAdd);
  pop.addEventListener('click',e=>{
    const rm=e.target.closest('.hp-remove');
    if(rm&&rm.dataset.hi!==undefined){removeHighlight(+rm.dataset.hi);pop.remove();showHighlightPanel();return;}
    if(e.target.closest('[data-clear="hi"]')){clearHighlights();pop.remove();toast('Highlights cleared');return;}
  });
  setTimeout(()=>document.addEventListener('click',function cl(e){if(!pop.contains(e.target)&&e.target!==$('highlightBtn')){pop.remove();document.removeEventListener('click',cl);}},{once:false}),0);
}

function addHiddenPattern(pattern){
  if(!pattern||S.hiddenPatterns.includes(pattern))return;
  S.hiddenPatterns.push(pattern);
  saveHiddenPatterns();
  updateHiddenBtn();
  rebuildFiltered();fullRender();
}

function removeHiddenPattern(idx){
  S.hiddenPatterns.splice(idx,1);
  saveHiddenPatterns();
  updateHiddenBtn();
  rebuildFiltered();fullRender();
}

function clearHiddenPatterns(){
  S.hiddenPatterns=[];
  saveHiddenPatterns();
  updateHiddenBtn();
  rebuildFiltered();fullRender();
}

function saveHiddenPatterns(){
  localStorage.setItem(HIDDEN_KEY,JSON.stringify(S.hiddenPatterns));
}

function updateHiddenBtn(){
  const btn=$('hiddenBtn');
  const n=S.hiddenPatterns.length+S.hiddenExecIds.size;
  btn.textContent=n?'Hidden ('+n+')':'Hidden';
  btn.classList.toggle('active',n>0);
}

function showHiddenPanel(){
  let pop=document.getElementById('hiddenPanel');
  if(pop){pop.remove();return;}
  pop=document.createElement('div');pop.id='hiddenPanel';pop.className='hidden-panel';
  const total=S.hiddenPatterns.length+S.hiddenExecIds.size;
  let h='<div class="hp-header"><span>Hidden Items</span>';
  if(total)h+='<span class="hp-clear" data-clear="all">Clear All</span>';
  h+='</div>';

  // Hidden flow executions
  if(S.hiddenExecIds.size){
    h+='<div class="hp-section-label">Hidden Flows</div><div class="hp-list">';
    // Look up flow names for each exec ID
    for(const eid of S.hiddenExecIds){
      let name='';
      for(const n of S.flowNodes){if(n.flowExecId===eid&&n.flowName){name=n.flowName;break;}}
      h+=`<div class="hp-item"><span class="hp-flow-icon">&#9654;</span><span class="hp-pattern">${esc(name||'unknown')} <span class="hp-exec-id">${esc(eid.slice(0,8))}</span></span><span class="hp-remove" data-exec="${esc(eid)}">&times;</span></div>`;
    }
    h+='</div>';
  }

  // Hidden message patterns
  if(S.hiddenPatterns.length){
    h+='<div class="hp-section-label">Hidden Messages</div><div class="hp-list">';
    for(let i=0;i<S.hiddenPatterns.length;i++){
      h+=`<div class="hp-item"><span class="hp-pattern">${esc(S.hiddenPatterns[i])}</span><span class="hp-remove" data-idx="${i}">&times;</span></div>`;
    }
    h+='</div>';
  }

  if(!total)h+='<div class="hp-empty">Nothing hidden. Click × on log lines or × on flow labels in the timeline to hide.</div>';

  pop.innerHTML=h;
  document.body.appendChild(pop);
  const r=$('hiddenBtn').getBoundingClientRect();
  pop.style.left=Math.max(10,Math.min(r.left,window.innerWidth-340))+'px';
  pop.style.top=(r.bottom+4)+'px';
  pop.addEventListener('click',e=>{
    const rm=e.target.closest('.hp-remove');
    if(rm){
      if(rm.dataset.idx!==undefined){removeHiddenPattern(+rm.dataset.idx);pop.remove();showHiddenPanel();}
      else if(rm.dataset.exec){unhideFlowExec(rm.dataset.exec);pop.remove();showHiddenPanel();}
      return;
    }
    if(e.target.closest('[data-clear="all"]')){clearHiddenPatterns();clearHiddenExecs();pop.remove();toast('All cleared');return;}
  });
  setTimeout(()=>document.addEventListener('click',function cl(e){if(!pop.contains(e.target)&&e.target!==($('hiddenBtn'))){pop.remove();document.removeEventListener('click',cl);}},{once:false}),0);
}

function clearState(){
  S.lines=[];S.raw=[];S.filtered=[];S.pods=new Set();S.reqs=new Map();S.errIdx=[];S.curErr=-1;S.flowNodes=[];S.buf=[];S.search='';S.hiddenExecIds=new Set();S._hiddenReqIds=null;
  S.nsSeen=new Set();S.nsCounts=new Map();S.nsCapturing=new Set();
  $('lc').innerHTML='';$('lc').classList.remove('v');
  $('welcome').classList.remove('h');$('filterBar').style.display='none';
  $('errBanner').classList.remove('v');$('ftl').classList.remove('v');
  $('stats').innerHTML='';$('searchInput').value='';$('searchCount').textContent='';
  $('clearBtn').style.display='none';
  renderNsLegend();
  closeTrace();
  closeInspector();
  toast('Cleared');
}

// ── Flow Trace ───────────────
function buildNodeLabelMap(reqLines){
  // Build a map of numeric node ID -> human-readable label from log_be "Failure from node" messages
  const labels=new Map();
  for(const l of reqLines){
    if(l.failNodeId&&l.failNodeLabel)labels.set(l.failNodeId,l.failNodeLabel);
    if(l.flowFailReason&&l.flowNode)labels.set(l.flowNode,l.flowFailReason);
  }
  return labels;
}

function buildFlowPath(nodes){
  // Build a clean execution path: merge process->done pairs into single entries
  const path=[];
  const nodeStates=new Map(); // node -> {states, next, ...}
  for(const n of nodes){
    const key=n.node;
    if(!nodeStates.has(key))nodeStates.set(key,{node:n.node,states:[],next:null,lineIdx:n.lineIdx,reason:n.reason});
    const entry=nodeStates.get(key);
    if(!entry.states.includes(n.state))entry.states.push(n.state);
    if(n.next)entry.next=n.next;
    if(n.reason)entry.reason=n.reason;
    entry.lastLineIdx=n.lineIdx;
  }
  // Walk in order of first appearance
  const seen=new Set();
  for(const n of nodes){
    if(seen.has(n.node))continue;seen.add(n.node);
    path.push(nodeStates.get(n.node));
  }
  return path;
}

function openTrace(reqId){
  const reqLines=S.lines.filter(l=>l&&l.reqId===reqId);
  if(!reqLines.length){toast('No logs for this request');return;}

  // Build node ID -> label map from failure messages
  const nodeLabels=buildNodeLabelMap(reqLines);

  // Also scan ALL lines for labels (cross-request, same flow execution)
  const flowExecIds=new Set();
  for(const l of reqLines){if(l.flowExecId)flowExecIds.add(l.flowExecId);}
  // Find related lines from other req_ids that share the same flowExecId
  const relatedLines=[];
  if(flowExecIds.size){
    for(const l of S.lines){
      if(l&&l.flowExecId&&flowExecIds.has(l.flowExecId)&&l.reqId!==reqId){
        relatedLines.push(l);
        if(l.failNodeId&&l.failNodeLabel)nodeLabels.set(l.failNodeId,l.failNodeLabel);
      }
    }
  }
  const allLines=[...reqLines,...relatedLines].sort((a,b)=>(a.timestamp||'').localeCompare(b.timestamp||''));

  // Group flow executions by flowExecId
  const flows=new Map();
  const flowOrder=[];
  for(const l of allLines){
    if(l.flowExecId){
      if(!flows.has(l.flowExecId)){
        const f={execId:l.flowExecId,name:l.flowName,nodes:[],failures:[],errors:[]};
        flows.set(l.flowExecId,f);
        flowOrder.push(f);
      }
      const f=flows.get(l.flowExecId);
      if(!f.name&&l.flowName)f.name=l.flowName;
      if(l.flowNode)f.nodes.push({node:l.flowNode,state:l.flowState,next:l.flowNext,reason:l.flowFailReason,lineIdx:l.idx,ts:l.timestamp});
    }
    // Collect failures and errors regardless of flowExecId
    if(l.failNodeId)flows.size&&[...flows.values()].slice(-1)[0].failures.push({nodeId:l.failNodeId,label:l.failNodeLabel,lineIdx:l.idx});
    if(l.apiError||l.isFlowError){const last=flows.size?[...flows.values()].slice(-1)[0]:null;if(last)last.errors.push({msg:l.apiError||l.msg,lineIdx:l.idx,level:l.level});}
  }

  // Find HTTP lines
  const flowNames=new Set([...flows.values()].map(f=>f.name).filter(Boolean));
  const httpLines=S.lines.filter(l=>l&&l.type==='http'&&l.flowName&&flowNames.has(l.flowName));

  // ── Render ──
  let h='';

  // Errors summary at the top
  const allErrors=[];const allFailures=[];
  for(const f of flowOrder){allErrors.push(...f.errors);allFailures.push(...f.failures);}
  if(allErrors.length||allFailures.length){
    h+='<div class="tp-section tp-errors">';
    h+='<div class="tp-section-label">Root Cause</div>';
    for(const f of allFailures){
      h+=`<div class="tp-failure" data-i="${f.lineIdx}"><span class="tp-fail-icon">&#x26A0;</span> <strong>${esc(f.label)}</strong> <span class="tp-fail-id">(node ${esc(f.nodeId)})</span></div>`;
    }
    for(const e of allErrors){
      h+=`<div class="tp-error-detail" data-i="${e.lineIdx}"><span class="tp-fail-icon">&#x2717;</span> ${esc(e.msg.length>200?e.msg.slice(0,200)+'...':e.msg)}</div>`;
    }
    h+='</div>';
  }

  // Flow execution paths
  if(flowOrder.length){
    h+='<div class="tp-section"><div class="tp-section-label">Flow Execution Path</div>';
    for(const f of flowOrder){
      h+=`<div class="tp-flow-name">${esc(f.name||'unknown')}<span class="tp-exec-id">${esc(f.execId.slice(0,8))}</span></div>`;
      const path=buildFlowPath(f.nodes);
      if(path.length){
        h+='<div class="tp-path">';
        for(let i=0;i<path.length;i++){
          const n=path[i];
          if(i>0)h+='<span class="tp-arrow">&rarr;</span>';
          const isFail=n.states.includes('failed')||(n.node.includes('failure')&&n.states.includes('pre'));
          const isPre=n.states.includes('pre')&&!n.states.includes('done');
          const isDone=n.states.includes('done');
          const cls=isFail?'failed':isPre?'pre':isDone?'done':'process';
          // Show label from nodeLabels map if the "next" points to a known node
          const label=nodeLabels.get(n.next)||'';
          const title=`${n.node} [${n.states.join(' → ')}]${n.next?' → next: '+n.next:''}${label?' ('+label+')':''}${n.reason?' — '+n.reason:''}`;
          // For nested_flow nodes, indicate nesting
          const displayName=n.node==='nested_flow'?'nested_flow ↴':n.node;
          h+=`<span class="tp-node ${cls}" data-i="${n.lineIdx}" title="${esc(title)}">${esc(displayName)}${n.next?'<span class="tp-next-id"> #'+esc(n.next)+'</span>':''}</span>`;
        }
        h+='</div>';
      }
      // Show failures inline with this flow
      if(f.failures.length){
        for(const fl of f.failures){
          h+=`<div class="tp-inline-fail" data-i="${fl.lineIdx}">&#x26A0; Failure from <strong>#${esc(fl.nodeId)}</strong>: ${esc(fl.label)}</div>`;
        }
      }
    }
    h+='</div>';
  }

  // HTTP requests
  if(httpLines.length){
    h+='<div class="tp-section"><div class="tp-section-label">HTTP Requests</div>';
    for(const l of httpLines){
      const sc=l.status>=500?'s5':l.status>=400?'s4':'s2';
      h+=`<div class="tp-http${l.status>=400?' err':''}" data-i="${l.idx}"><span class="tp-method">${esc(l.method)}</span> ${esc(l.path)} <span class="tp-status ${sc}">${l.status}</span> ${l.size}B</div>`;
    }
    h+='</div>';
  }

  // Significant log lines (skip TRACE and health checks, show only flow-relevant lines)
  const sigLines=reqLines.filter(l=>l.level!=='TRACE'&&!(l.msg||'').includes('Health')&&!(l.msg||'').includes('count started')&&!(l.msg||'').includes('count finished')&&!(l.msg||'').includes('query started')&&!(l.msg||'').includes('query finished'));
  h+='<div class="tp-section"><div class="tp-section-label">Key Events ('+sigLines.length+' of '+reqLines.length+' lines)</div></div>';
  for(const l of sigLines){
    const isErr=l.level==='ERROR'||l.level==='FATAL'||l.isFlowError||l.flowState==='failed';
    const msg=l.msg||l.raw||'';
    const short=msg.length>300?msg.slice(0,300)+'...':msg;
    h+=`<div class="tp-line${isErr?' err':''}" data-i="${l.idx}">`;
    h+=`<span class="tp-ts">${l.timestamp?fmtTs(l.timestamp):''}</span>`;
    h+=`<span class="tp-lv ${l.level||''}">${l.level||''}</span>`;
    if(l.flowNode)h+=`<span class="tp-flow-tag">${esc(l.flowNode)}</span>`;
    else if(l.failNodeId)h+=`<span class="tp-flow-tag fail">#${esc(l.failNodeId)}</span>`;
    h+=`<span class="tp-msg">${esc(short)}</span>`;
    h+='</div>';
  }

  if(!h)h='<div class="tp-empty">No trace data found</div>';

  $('tpTitle').textContent='Trace: '+shortReq(reqId);
  $('tpBody').innerHTML=h;
  $('tracePanel').classList.add('v');

  $('tpBody').onclick=e=>{
    const el=e.target.closest('[data-i]');
    if(el){const idx=+el.dataset.i;scrollTo(idx);}
  };
}

function closeTrace(){$('tracePanel').classList.remove('v');}

// ── JSON Inspector ──────────
let jvCounter=0;
let currentInspectValue=null;

// Find the largest parseable JSON substring in a line's message
function getInspectData(l){
  if(!l)return null;
  if(l.json)return l.json;
  if(l.data)return l.data;
  const msg=l.msg||l.raw||'';
  if(!msg)return null;
  let best=null,bestLen=0;
  for(let i=0;i<msg.length;i++){
    const c=msg[i];
    if(c!=='{'&&c!=='[')continue;
    let depth=0,inStr=false,escCh=false;
    for(let j=i;j<msg.length;j++){
      const ch=msg[j];
      if(inStr){
        if(escCh)escCh=false;
        else if(ch==='\\')escCh=true;
        else if(ch==='"')inStr=false;
      }else{
        if(ch==='"')inStr=true;
        else if(ch==='{'||ch==='[')depth++;
        else if(ch==='}'||ch===']'){
          depth--;
          if(depth===0){
            const cand=msg.slice(i,j+1);
            try{const p=JSON.parse(cand);if(cand.length>bestLen){best=p;bestLen=cand.length;}}catch{}
            break;
          }
        }
      }
    }
  }
  return best;
}

function renderJv(value,key,isLast){
  const comma=isLast?'':',';
  const keyHtml=key!==undefined&&key!==null?`<span class="jv-k">${typeof key==='number'?key:`"${esc(String(key))}"`}</span>: `:'';
  const row=document.createElement('div');
  row.className='jv-row';

  if(value===null){row.innerHTML=keyHtml+'<span class="jv-null">null</span>'+comma;return row;}
  if(value===undefined){row.innerHTML=keyHtml+'<span class="jv-null">undefined</span>'+comma;return row;}
  const tp=typeof value;
  if(tp==='boolean'){row.innerHTML=keyHtml+`<span class="jv-bool">${value}</span>`+comma;return row;}
  if(tp==='number'){row.innerHTML=keyHtml+`<span class="jv-num">${value}</span>`+comma;return row;}
  if(tp==='string'){
    // Try to detect embedded JSON in the string value
    const trimmed=value.trim();
    if(trimmed.length>2&&((trimmed[0]==='{'&&trimmed[trimmed.length-1]==='}')||(trimmed[0]==='['&&trimmed[trimmed.length-1]===']'))){
      try{const parsed=JSON.parse(trimmed);return renderJvObject(parsed,key,isLast,true);}catch{}
    }
    // Long string: show short + [more] toggle
    if(value.length>160){
      const id='jvs'+(++jvCounter);
      row.innerHTML=keyHtml+
        `<span class="jv-str" id="${id}s">"${esc(value.slice(0,160))}"</span>`+
        `<span class="jv-str jv-hide" id="${id}f">"${esc(value)}"</span>`+
        ` <span class="jv-more" data-short="${id}s" data-full="${id}f">[more]</span>`+comma;
      return row;
    }
    row.innerHTML=keyHtml+`<span class="jv-str">"${esc(value)}"</span>`+comma;
    return row;
  }
  if(tp==='object'){return renderJvObject(value,key,isLast,false);}
  row.innerHTML=keyHtml+`<span>${esc(String(value))}</span>`+comma;
  return row;
}

function renderJvObject(value,key,isLast,wasString){
  const isArray=Array.isArray(value);
  const keys=isArray?value.map((_,i)=>i):Object.keys(value);
  const count=keys.length;
  const brackets=isArray?['[',']']:['{','}'];
  const comma=isLast?'':',';
  const keyHtml=key!==undefined&&key!==null?`<span class="jv-k">${typeof key==='number'?key:`"${esc(String(key))}"`}</span>: `:'';

  const wrap=document.createElement('div');
  wrap.className='jv-obj';

  const id='jv'+(++jvCounter);
  const header=document.createElement('div');
  header.className='jv-row jv-hdr';
  // Preview a few keys for quick scanning when collapsed
  let preview='';
  if(count&&!isArray){
    const preKeys=keys.slice(0,3).map(k=>`"${esc(k)}"`).join(', ');
    preview=`<span class="jv-preview">${preKeys}${count>3?', ...':''}</span>`;
  }
  header.innerHTML=
    `<span class="jv-tog" data-target="${id}">▾</span>${keyHtml}`+
    (wasString?'<span class="jv-hint">(JSON in string)</span>':'')+
    `<span class="jv-br">${brackets[0]}</span><span class="jv-count">${count} ${isArray?'item'+(count===1?'':'s'):'key'+(count===1?'':'s')}</span>${preview}`;
  wrap.appendChild(header);

  const body=document.createElement('div');
  body.className='jv-body';
  body.id=id;
  for(let i=0;i<keys.length;i++){
    const k=keys[i];
    body.appendChild(renderJv(value[k],isArray?i:k,i===keys.length-1));
  }
  wrap.appendChild(body);

  const closer=document.createElement('div');
  closer.className='jv-row jv-close';
  closer.innerHTML=`<span class="jv-br">${brackets[1]}</span>`+comma;
  wrap.appendChild(closer);

  return wrap;
}

function openInspector(value,title){
  if(value===null||value===undefined){toast('No JSON found in this line');return;}
  jvCounter=0;
  currentInspectValue=value;
  $('ipTitle').textContent=title||'JSON Inspector';
  const body=$('ipBody');
  body.innerHTML='';
  const root=document.createElement('div');
  root.className='jv-root';
  root.appendChild(renderJv(value,undefined,true));
  body.appendChild(root);
  $('inspectPanel').classList.add('v');
}

function closeInspector(){$('inspectPanel').classList.remove('v');currentInspectValue=null;}

function inspectorSetAll(collapsed){
  const bodies=$('ipBody').querySelectorAll('.jv-body');
  bodies.forEach(b=>{
    b.classList.toggle('jv-collapsed',collapsed);
    const tog=document.querySelector(`.jv-tog[data-target="${b.id}"]`);
    if(tog)tog.textContent=collapsed?'▸':'▾';
  });
}

// ── File load ─────────────────
function loadFile(text){
  S.lines=[];S.raw=text.split('\n');S.pods=new Set();S.reqs=new Map();
  for(let i=0;i<S.raw.length;i++){const p=parse(S.raw[i],i);S.lines.push(p);if(p){if(p.pod)S.pods.add(p.pod);if(p.reqId)S.reqs.set(p.reqId,(S.reqs.get(p.reqId)||0)+1);}}
  populateFilters();rebuildFiltered();fullRender();
  if(S.errIdx.length)setTimeout(()=>{S.curErr=0;scrollTo(S.errIdx[0]);},300);
  toast(`Loaded ${S.raw.length} lines`);
}

// ── Live line ─────────────────
function addLive(raw,ns){
  const i=S.lines.length;S.raw.push(raw);
  let p;try{p=parse(raw,i,ns);}catch(e){console.error('parse error:',e);p={type:'raw',msg:raw,level:'INFO',idx:i,raw:raw,ns};}
  S.lines.push(p);
  if(p){
    if(p.ns){const hadNs=S.nsSeen.has(p.ns);S.nsSeen.add(p.ns);if(!hadNs){ensureNsColor(p.ns);renderNsLegend();}}
    if(p.pod){const had=S.pods.has(p.pod);S.pods.add(p.pod);if(!had)populateFilters();}
    if(p.reqId){S.reqs.set(p.reqId,(S.reqs.get(p.reqId)||0)+1);if(S.lines.length%100===0)populateFilters();}
    appendLive(p);
  }
}

// ── WebSocket ─────────────────
function connect(){
  if(!SESSION_ID){
    $('cLabel').textContent='No session — add ?s=<id> to the URL';
    setConn(false);
    return;
  }
  try{S.ws=new WebSocket(AGENT_URL);}catch{return setConn(false);}
  S.ws.onopen=()=>{setConn(true);send({action:'get-init'});};
  S.ws.onclose=()=>{setConn(false);setTimeout(connect,3000);};
  S.ws.onerror=()=>{};
  S.ws.onmessage=ev=>{
    const m=JSON.parse(ev.data);
    switch(m.type){
      // Relay-specific control messages
      case'relay-hello':
        $('cLabel').textContent=m.producerConnected?'Agent connected':'Waiting for agent…';
        if(m.producerConnected)send({action:'get-init'});
        break;
      case'producer-ready':
        $('cLabel').textContent='Agent connected';
        toast('Agent connected');
        send({action:'get-init'});
        break;
      case'producer-gone':
        $('cLabel').textContent='Agent disconnected';
        setCap(false);
        toast('Agent disconnected');
        break;

      case'init':
        if(m.auth&&(m.auth.ok||m.auth.authenticated)){
          $('cLabel').textContent=m.auth.arn?m.auth.arn.split('/').pop():'Authenticated';
        }
        if(m.capturing)setCap(true,m.ns);
        Drawer.onInit(m);
        break;
      case'capture-start':case'capture-state':
        setCap(true,m.ns);
        S.lines=[];S.raw=[];S.filtered=[];S.pods=new Set();S.reqs=new Map();S.errIdx=[];
        S.nsSeen=new Set();S.nsCounts=new Map();
        // Normalize m.ns to an array: new agent sends array, old agent may send a
        // single comma-joined string (which stern will have parsed as multi-ns).
        {
          let nsArr=[];
          if(Array.isArray(m.ns))nsArr=m.ns;
          else if(typeof m.ns==='string')nsArr=m.ns.split(',').map(x=>x.trim()).filter(Boolean);
          S.nsCapturing=new Set(nsArr);
          for(const n of nsArr){S.nsSeen.add(n);ensureNsColor(n);}
        }
        renderNsLegend();
        $('lc').innerHTML='';$('lc').classList.add('v');$('welcome').classList.add('h');$('filterBar').style.display='flex';
        Drawer.onCaptureStart(m);
        break;
      case'log':try{addLive(m.line,m.ns);}catch(e){console.error('addLive error:',e);}Drawer.onLog(m);break;
      case'cleared':clearState();Drawer.onCleared();break;
      case'ns-added':{
        const arr=Array.isArray(m.ns)?m.ns:[m.ns];
        for(const n of arr){if(!n)continue;S.nsCapturing.add(n);S.nsSeen.add(n);ensureNsColor(n);}
        renderNsLegend();
        if(arr.length)toast(`Added: ${arr.join(', ')}`);
        break;}
      case'stream-end':
        if(m.ns){S.nsCapturing.delete(m.ns);renderNsLegend();toast(`Stream ended: ${m.ns}`);}
        break;
      case'capture-stop':case'capture-stopped':case'capture-end':case'capture-ended':
        setCap(false);populateFilters();updateFlow();updateErrBanner();updateStats();renderNsLegend();
        if(m.n!==undefined)toast(`Captured ${m.n} lines`);
        if(S.errIdx.length)setTimeout(()=>{S.curErr=0;scrollTo(S.errIdx[0]);},500);
        Drawer.onCaptureEnd(m);
        break;
      case'stderr':if(m.msg&&!m.msg.includes('Experimental'))toast((m.ns?`[${m.ns}] `:'')+m.msg.slice(0,80));break;
      case'error':toast('Error: '+(m.msg||'unknown'));break;
      case'auth-status':
        $('cLabel').textContent=(m.ok||m.authenticated)?(m.arn?m.arn.split('/').pop():'Auth OK'):'Not authed';
        Drawer.onAuthStatus(m);
        break;
      case'auth-progress':Drawer.onAuthProgress(m);break;
      case'auth-result':Drawer.onAuthResult(m);break;
      case'namespaces':Drawer.onNamespaces(m);break;
      case'saved':toast('Saved: '+(m.fn||m.path||''));break;
    }
  };
}

function send(m){if(S.ws&&S.ws.readyState===1)S.ws.send(JSON.stringify(m));}
function badge(text,color){try{_ext.runtime.sendMessage({type:'badge',text,color});}catch{}}

function setConn(ok){
  $('cDot').className='dot '+(ok?'ok':'fail');
  $('cLabel').textContent=ok?'Connected':'Disconnected — agent not running?';
  if(ok)badge('','#3fb950');
}

let timerIv;
function setCap(on,ns){
  S.capturing=on;
  $('clearBtn').style.display=(on||S.lines.length)?'':'none';
  const rb=$('recBanner');
  const label=Array.isArray(ns)?ns.join(', '):(ns||'');
  if(on){rb.classList.add('v');S.start=S.start||Date.now();clearInterval(timerIv);
    timerIv=setInterval(()=>{if(!S.capturing){clearInterval(timerIv);return;}const e=Math.floor((Date.now()-S.start)/1000);$('recInfo').textContent=`Capturing ${label} — ${Math.floor(e/60)}:${String(e%60).padStart(2,'0')} — ${S.lines.length} lines`;},1000);
    badge('REC','#f85149');
  }else{rb.classList.remove('v');clearInterval(timerIv);S.start=null;badge('','#3fb950');}
}

// ── Namespace color legend ────
function hexToRgba(hex,a){
  const m=/^#?([0-9a-f]{6})$/i.exec(hex||'');
  if(!m)return `rgba(88,166,255,${a})`;
  const n=parseInt(m[1],16);
  return `rgba(${(n>>16)&255},${(n>>8)&255},${n&255},${a})`;
}

function ensureNsColor(ns){
  if(!ns||S.nsColors[ns])return S.nsColors[ns];
  const palette=['#3fb950','#58a6ff','#d29922','#bc8cff','#39c5cf','#ff7b72','#79c0ff','#e6db74'];
  const used=new Set(Object.values(S.nsColors));
  const c=palette.find(p=>!used.has(p))||palette[Object.keys(S.nsColors).length%palette.length];
  S.nsColors[ns]=c;
  try{_ext.storage.local.set({nsColors:S.nsColors});}catch{}
  return c;
}

function applyNsStyle(el,color){
  el.style.setProperty('--ns-color',color);
  el.style.setProperty('--ns-bg',hexToRgba(color,0.35));
}

function renderNsLegend(){
  const el=$('nsLegend');if(!el)return;
  const nsList=[...S.nsSeen].sort();
  if(!nsList.length){el.innerHTML='';return;}
  // Count lines per ns
  const counts=new Map();for(const l of S.lines){if(l&&l.ns)counts.set(l.ns,(counts.get(l.ns)||0)+1);}
  let h='';
  for(const ns of nsList){
    const c=S.nsColors[ns]||'#30363d';
    const ct=counts.get(ns)||0;
    h+=`<span class="ns-chip" data-ns="${esc(ns)}">`
      +`<input type="color" value="${c}" data-ns-color="${esc(ns)}" title="Change color for ${esc(ns)}" />`
      +`<span>${esc(ns)}</span>`
      +`<span class="ns-ct">${ct}</span>`
      +`</span>`;
  }
  el.innerHTML=h;
}

function applyNsColorChange(ns,color){
  S.nsColors[ns]=color;
  try{_ext.storage.local.set({nsColors:S.nsColors});}catch{}
  // Re-tint existing lines without full re-render
  $('lc').querySelectorAll(`.ll[data-ns="${CSS.escape(ns)}"]`).forEach(el=>applyNsStyle(el,color));
  renderNsLegend();
}

$('nsLegend').addEventListener('input',e=>{
  const t=e.target;
  if(t&&t.dataset&&t.dataset.nsColor){applyNsColorChange(t.dataset.nsColor,t.value);}
});

// Sync when popup (or another viewer tab) changes colors
try{
  _ext.storage.onChanged.addListener((changes,area)=>{
    if(area!=='local')return;
    if(!changes.nsColors)return;
    const next=changes.nsColors.newValue||{};
    // Only apply changes for ns we've seen
    let any=false;
    for(const[ns,c]of Object.entries(next)){
      if(S.nsColors[ns]!==c){S.nsColors[ns]=c;
        if(S.nsSeen.has(ns)){any=true;
          $('lc').querySelectorAll(`.ll[data-ns="${CSS.escape(ns)}"]`).forEach(el=>applyNsStyle(el,c));}
      }
    }
    if(any)renderNsLegend();
  });
  _ext.storage.local.get('nsColors',d=>{
    if(!d||!d.nsColors)return;
    // Popup-stored colors are authoritative — override anything the viewer auto-assigned
    // and re-tint any lines that are already in the DOM.
    for(const[ns,c] of Object.entries(d.nsColors)){
      S.nsColors[ns]=c;
      $('lc').querySelectorAll(`.ll[data-ns="${CSS.escape(ns)}"]`).forEach(el=>applyNsStyle(el,c));
    }
    renderNsLegend();
  });
}catch{}

// ── Events ────────────────────
$('clearBtn').addEventListener('click',()=>{
  if(S.capturing){
    // Clear display but keep capturing — new lines will keep flowing in
    S.lines=[];S.raw=[];S.filtered=[];S.pods=new Set();S.reqs=new Map();S.errIdx=[];S.curErr=-1;S.flowNodes=[];S.buf=[];
    S.hiddenExecIds=new Set();S._hiddenReqIds=null;
    $('lc').innerHTML='';$('errBanner').classList.remove('v');$('ftl').classList.remove('v');
    $('stats').innerHTML='';closeTrace();renderNsLegend();
    toast('Display cleared — still capturing');
  } else {
    send({action:'clear'});
    clearState();
  }
});
$('tpClose').addEventListener('click',closeTrace);
$('ipClose').addEventListener('click',closeInspector);
$('ipExpand').addEventListener('click',()=>inspectorSetAll(false));
$('ipCollapse').addEventListener('click',()=>inspectorSetAll(true));
$('ipCopy').addEventListener('click',()=>{
  if(currentInspectValue==null){toast('Nothing to copy');return;}
  try{navigator.clipboard.writeText(JSON.stringify(currentInspectValue,null,2));toast('Copied JSON');}
  catch{toast('Copy failed');}
});
$('ipBody').addEventListener('click',e=>{
  const tog=e.target.closest('.jv-tog');
  if(tog){
    const target=document.getElementById(tog.dataset.target);
    if(target){
      const collapsed=target.classList.toggle('jv-collapsed');
      tog.textContent=collapsed?'▸':'▾';
    }
    return;
  }
  const hdr=e.target.closest('.jv-hdr');
  if(hdr){
    const tg=hdr.querySelector('.jv-tog');
    if(tg)tg.click();
    return;
  }
  const more=e.target.closest('.jv-more');
  if(more){
    const s=document.getElementById(more.dataset.short);
    const f=document.getElementById(more.dataset.full);
    if(s&&f){s.classList.toggle('jv-hide');f.classList.toggle('jv-hide');more.textContent=f.classList.contains('jv-hide')?'[more]':'[less]';}
    return;
  }
});

let sto;$('searchInput').addEventListener('input',e=>{clearTimeout(sto);sto=setTimeout(()=>{S.search=e.target.value.trim();rebuildFiltered();fullRender();},200);});
$('levelFilter').addEventListener('change',e=>{S.level=e.target.value;rebuildFiltered();fullRender();});
$('podFilter').addEventListener('change',e=>{S.pod=e.target.value;rebuildFiltered();fullRender();});
$('reqidFilter').addEventListener('change',e=>{S.req=e.target.value;rebuildFiltered();fullRender();});
$('hideTrace').addEventListener('click',e=>{S.hideTrace=!S.hideTrace;e.target.classList.toggle('active',S.hideTrace);e.target.textContent=S.hideTrace?'Show TRACE':'Hide TRACE';rebuildFiltered();fullRender();});
$('hiddenBtn').addEventListener('click',e=>{e.stopPropagation();showHiddenPanel();});
$('highlightBtn').addEventListener('click',e=>{e.stopPropagation();showHighlightPanel();});
$('autoScroll').addEventListener('click',e=>{S.autoScroll=!S.autoScroll;e.target.textContent=`Auto-scroll: ${S.autoScroll?'ON':'OFF'}`;e.target.classList.toggle('active',S.autoScroll);});
$('prevErr').addEventListener('click',()=>jumpErr('prev'));
$('nextErr').addEventListener('click',()=>jumpErr('next'));
$('errBanner').addEventListener('click',()=>jumpErr('next'));
$('resetBtn').addEventListener('click',()=>{S.search='';S.hideTrace=false;S.level='all';S.pod='all';S.req='all';$('searchInput').value='';$('levelFilter').value='all';$('podFilter').value='all';$('reqidFilter').value='all';$('hideTrace').classList.remove('active');$('hideTrace').textContent='Hide TRACE';rebuildFiltered();fullRender();});
$('exportBtn').addEventListener('click',()=>{const t=S.filtered.map(i=>S.raw[i]).join('\n');const b=new Blob([t],{type:'text/plain'});const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download=`logs-${new Date().toISOString().slice(0,19).replace(/[:.]/g,'-')}.txt`;a.click();toast('Exported');});
$('openFile').addEventListener('click',()=>$('fileInput').click());
$('fileInput').addEventListener('change',e=>{const f=e.target.files[0];if(f){const r=new FileReader();r.onload=ev=>loadFile(ev.target.result);r.readAsText(f);}});

// Drop zone
const dz=$('dz');
dz.addEventListener('dragover',e=>{e.preventDefault();dz.classList.add('over');});
dz.addEventListener('dragleave',()=>dz.classList.remove('over'));
dz.addEventListener('drop',e=>{e.preventDefault();dz.classList.remove('over');const f=e.dataTransfer.files[0];if(f){const r=new FileReader();r.onload=ev=>loadFile(ev.target.result);r.readAsText(f);}});
dz.addEventListener('click',()=>$('fileInput').click());
document.body.addEventListener('dragover',e=>e.preventDefault());
document.body.addEventListener('drop',e=>{e.preventDefault();const f=e.dataTransfer.files[0];if(f){const r=new FileReader();r.onload=ev=>loadFile(ev.target.result);r.readAsText(f);}});

// Log container clicks
$('lc').addEventListener('click',e=>{
  const ln=e.target.closest('.ln');if(ln&&ln.dataset.jump!==undefined){
    const idx=+ln.dataset.jump;
    // Clear search (and any active line/trace filter that'd hide context) so neighbours reappear.
    const hadSearch=!!S.search;
    if(hadSearch||S.level!=='all'||S.pod!=='all'||S.req!=='all'||S.hideTrace){
      S.search='';S.level='all';S.pod='all';S.req='all';S.hideTrace=false;
      $('searchInput').value='';$('searchCount').textContent='';
      $('levelFilter').value='all';$('podFilter').value='all';$('reqidFilter').value='all';
      $('hideTrace').classList.remove('active');$('hideTrace').textContent='Hide TRACE';
      rebuildFiltered();fullRender();
      requestAnimationFrame(()=>scrollTo(idx));
      toast('Cleared filters — showing context around line '+(idx+1));
    } else {
      scrollTo(idx);
    }
    return;
  }
  const hb=e.target.closest('.lh');if(hb){const idx=+hb.dataset.hide;const l=S.lines[idx];if(l){const pat=extractPattern(l);addHiddenPattern(pat);toast(`Hidden: "${pat.slice(0,40)}${pat.length>40?'...':''}"`);}return;}
  const fb=e.target.closest('.lfail');if(fb){e.stopPropagation();const idx=+fb.dataset.fail;const l=S.lines[idx];if(l)showFailurePopover(fb,l);return;}
  const pod=e.target.closest('.lp');if(pod&&pod.dataset.pod){S.pod=pod.dataset.pod;$('podFilter').value=pod.dataset.pod;rebuildFiltered();fullRender();toast(`Filtered: ${shortPod(pod.dataset.pod)}`);return;}
  const req=e.target.closest('.lr');if(req&&req.dataset.req){
    if(e.shiftKey){S.req=req.dataset.req;$('reqidFilter').value=req.dataset.req;rebuildFiltered();fullRender();toast(`Request: ${shortReq(req.dataset.req)}`);}
    else{openTrace(req.dataset.req);}
    return;}
  const je=e.target.closest('.je');if(je){const i=+je.dataset.li;const ex=document.getElementById('jd-'+i);if(ex){ex.classList.toggle('v');je.textContent=ex.classList.contains('v')?'[-]':'[+]';}else{const l=S.lines[i];if(l){je.closest('.ll').insertAdjacentHTML('afterend',jsonDetailHtml(l));document.getElementById('jd-'+i).classList.add('v');je.textContent='[-]';}}return;}
  const jin=e.target.closest('.jin');if(jin){e.stopPropagation();const i=+jin.dataset.inspect;const l=S.lines[i];if(l){const data=getInspectData(l);const title=`Line ${i+1}${l.pod?' — '+shortPod(l.pod):''}${l.reqId?' — '+shortReq(l.reqId):''}`;openInspector(data,title);}return;}
});

// Keyboard
document.addEventListener('keydown',e=>{
  if((e.ctrlKey||e.metaKey)&&e.key==='f'){e.preventDefault();$('searchInput').focus();}
  if(e.key==='Escape'){if($('inspectPanel').classList.contains('v')){closeInspector();}else if($('tracePanel').classList.contains('v')){closeTrace();}else{$('searchInput').blur();if(S.search){S.search='';$('searchInput').value='';rebuildFiltered();fullRender();}}}
  if((e.ctrlKey||e.metaKey)&&e.key==='e'){e.preventDefault();jumpErr(e.shiftKey?'prev':'next');}
});

// Paste
document.addEventListener('paste',e=>{if(e.target.tagName==='INPUT')return;const t=e.clipboardData.getData('text');if(t&&t.length>50){e.preventDefault();loadFile(t);}});

updateHiddenBtn();
updateHighlightBtn();
loadPresets();
renderPresetDropdown();
connect();

// ── Preset events ──
$('presetSelect').addEventListener('change',e=>{
  if(e.target.value)applyPreset(e.target.value);
  else {S.currentPreset='';savePresetsToStorage();renderPresetDropdown();}
});
$('presetSave').addEventListener('click',()=>{
  const defaultName=S.currentPreset||'';
  const name=prompt('Name this preset (enter an existing name to overwrite):',defaultName);
  if(name!==null&&name.trim())savePreset(name);
});
$('presetDel').addEventListener('click',()=>{
  if(!S.currentPreset)return;
  if(!confirm(`Delete preset "${S.currentPreset}"?`))return;
  deletePreset(S.currentPreset);
});

// ── Setup drawer ─────────────────────────────────────────────────────
// Contains the popup controls (profile picker, SSO login, namespace picker,
// capture start/stop). Uses localStorage for persistence (no chrome.storage
// in a plain web page). Sends WS actions back to the agent via the relay.
const Drawer = (() => {
  const PALETTE = ['#3fb950','#58a6ff','#d29922','#bc8cff','#39c5cf','#ff7b72','#79c0ff','#e6db74'];
  const LS_KEY = 'kubelogger.drawer.v1';

  let allProfiles = [];
  let disabledProfiles = new Set();
  let cachedNsList = [];
  let selectedNs = new Set();
  let lastProfile = '';
  let authState = { ok:false, arn:null, err:null, expiresAt:null };
  let authTicker = null;
  let capturing = false;

  function loadState() {
    try {
      const j = JSON.parse(localStorage.getItem(LS_KEY) || '{}');
      disabledProfiles = new Set(j.disabledProfiles || []);
      cachedNsList = Array.isArray(j.cachedNs) ? j.cachedNs : [];
      selectedNs = new Set(j.selectedNs || []);
      if (j.nsColors) for (const [ns,c] of Object.entries(j.nsColors)) S.nsColors[ns] = c;
      lastProfile = j.lastProfile || '';
    } catch {}
  }
  function saveState() {
    try {
      localStorage.setItem(LS_KEY, JSON.stringify({
        disabledProfiles: [...disabledProfiles],
        cachedNs: cachedNsList,
        selectedNs: [...selectedNs],
        nsColors: S.nsColors,
        lastProfile,
      }));
    } catch {}
  }

  function open() {
    $('setupDrawer').classList.add('v');
    $('setupBackdrop').classList.add('v');
    $('setupDrawer').setAttribute('aria-hidden','false');
  }
  function close() {
    $('setupDrawer').classList.remove('v');
    $('setupBackdrop').classList.remove('v');
    $('setupDrawer').setAttribute('aria-hidden','true');
  }

  // Shorten Example-specific profile names; leave others as-is.
  function prettyProfileName(p) {
    return p.replace('example-','').replace('-profile-a',' (Lab)').replace('-profile-b',' (Prod)');
  }

  function populateProfiles(profiles) {
    if (profiles) allProfiles = profiles;
    const sel = $('profile');
    const previous = sel.value;
    sel.innerHTML = '<option value="">Select profile…</option>';
    for (const p of allProfiles) {
      if (disabledProfiles.has(p)) continue;
      const opt = document.createElement('option');
      opt.value = p; opt.textContent = prettyProfileName(p);
      sel.appendChild(opt);
    }
    const choose = (previous && !disabledProfiles.has(previous)) ? previous
                 : (lastProfile && !disabledProfiles.has(lastProfile) && allProfiles.includes(lastProfile)) ? lastProfile : '';
    if (choose) sel.value = choose;
    renderProfilesPanel();
  }

  function renderProfilesPanel() {
    const el = $('profilesPanel');
    if (!allProfiles.length) { el.innerHTML = '<div class="sd-empty">No profiles in ~/.aws/config</div>'; return; }
    let h = '';
    for (const p of allProfiles) {
      const enabled = !disabledProfiles.has(p);
      h += `<div class="sd-item" data-profile="${esc(p)}">`
        +  `<input type="checkbox" ${enabled?'checked':''} />`
        +  `<span class="sd-name" title="${esc(p)}">${esc(p)}</span>`
        +  `</div>`;
    }
    el.innerHTML = h;
  }

  // Assign a color from PALETTE to a namespace and persist it. Shared with
  // the viewer's S.nsColors so the log legend and drawer stay in sync.
  function ensureColor(ns) {
    if (S.nsColors[ns]) return S.nsColors[ns];
    const used = new Set(Object.values(S.nsColors));
    const c = PALETTE.find(p => !used.has(p)) || PALETTE[Object.keys(S.nsColors).length % PALETTE.length];
    S.nsColors[ns] = c;
    return c;
  }

  function renderNsList() {
    const el = $('nsList');
    if (!cachedNsList.length) { el.innerHTML = '<div class="sd-empty">Load namespaces first</div>'; renderSelectedSummary(); return; }
    const filter = $('nsFilter').value.toLowerCase();
    const priority = cachedNsList.filter(n => n.includes('io') || n.includes('productpod'));
    const rest = cachedNsList.filter(n => !priority.includes(n));
    const ordered = [...priority, ...rest];
    const filtered = filter ? ordered.filter(n => n.toLowerCase().includes(filter)) : ordered;
    if (!filtered.length) { el.innerHTML = '<div class="sd-empty">No matches</div>'; renderSelectedSummary(); return; }
    filtered.sort((a,b) => (selectedNs.has(b)?1:0) - (selectedNs.has(a)?1:0));
    let h = '';
    for (const ns of filtered) {
      const checked = selectedNs.has(ns);
      const color = checked ? ensureColor(ns) : (S.nsColors[ns] || '#30363d');
      h += `<div class="sd-item" data-ns="${esc(ns)}">`
        +  `<input type="checkbox" ${checked?'checked':''} />`
        +  `<span class="sd-name" title="${esc(ns)}">${esc(ns)}</span>`
        +  (checked ? `<input type="color" value="${color}" title="Color for ${esc(ns)}" />` : '')
        +  `</div>`;
    }
    el.innerHTML = h;
    renderSelectedSummary();
  }

  function renderSelectedSummary() {
    const el = $('nsSelectedSummary');
    if (!selectedNs.size) { el.innerHTML = '<span>None selected</span>'; return; }
    let h = '';
    for (const ns of selectedNs) {
      const c = S.nsColors[ns] || '#30363d';
      h += `<span class="sd-chip"><span class="sd-chip-dot" style="background:${c}"></span>${esc(ns)}</span>`;
    }
    el.innerHTML = h;
  }

  function fmtRemaining(ms) {
    if (ms <= 0) return 'expired';
    const tm = Math.floor(ms / 60000);
    if (tm < 60) return `${tm}m left`;
    return `${Math.floor(tm/60)}h ${tm%60}m left`;
  }

  function renderAuthStatus() {
    const dot = $('authDot'); const info = $('authInfo');
    if (!authState.ok) { dot.className = 'dot fail'; info.textContent = authState.err || 'Not authenticated'; return; }
    const label = authState.arn ? authState.arn.split('/').pop() : 'Authenticated';
    if (!authState.expiresAt) { dot.className = 'dot ok'; info.textContent = label; return; }
    const ms = authState.expiresAt - Date.now();
    info.textContent = `${label} — ${fmtRemaining(ms)}`;
    if (ms <= 0) dot.className = 'dot fail';
    else if (ms < 10*60*1000) dot.className = 'dot pending';
    else dot.className = 'dot ok';
  }

  function setAuth(ok, arn, err, expiresAt) {
    authState = { ok, arn: arn||null, err: err||null, expiresAt: expiresAt||null };
    if (ok) $('loadNs').disabled = false;
    renderAuthStatus();
    if (authTicker) { clearInterval(authTicker); authTicker = null; }
    if (ok && authState.expiresAt) authTicker = setInterval(renderAuthStatus, 30000);
    updateStartBtn();
  }

  function setCaptureState(active) {
    capturing = active;
    $('startBtn').style.display = active ? 'none' : '';
    $('stopBtn').style.display = active ? '' : 'none';
    updateStartBtn();
  }

  function updateStartBtn() {
    $('startBtn').disabled = !selectedNs.size || !authState.ok || capturing;
  }

  // Public API called from the onmessage switch in connect().
  return {
    init() {
      loadState();
      renderNsList();
      renderSelectedSummary();
      renderAuthStatus();
      updateStartBtn();

      $('setupBtn').addEventListener('click', open);
      $('sdClose').addEventListener('click', close);
      $('setupBackdrop').addEventListener('click', close);
      document.addEventListener('keydown', e => {
        if (e.key === 'Escape' && $('setupDrawer').classList.contains('v')) close();
      });

      $('profile').addEventListener('change', e => {
        const p = e.target.value;
        if (!p) return;
        lastProfile = p; saveState();
        send({ action: 'check-auth', profile: p });
        $('authDot').className = 'dot pending';
        $('authInfo').textContent = 'Checking…';
      });

      $('checkBtn').addEventListener('click', () => {
        const p = $('profile').value;
        if (!p) { $('authInfo').textContent = 'Select a profile first'; return; }
        send({ action: 'check-auth', profile: p });
        $('authDot').className = 'dot pending';
        $('authInfo').textContent = 'Checking…';
      });

      $('loginBtn').addEventListener('click', () => {
        const p = $('profile').value;
        if (!p) { $('authInfo').textContent = 'Select a profile first'; return; }
        send({ action: 'login', profile: p });
        $('authDot').className = 'dot pending';
        $('authInfo').textContent = 'Opening SSO on agent machine…';
      });

      $('loadNs').addEventListener('click', () => {
        send({ action: 'namespaces' });
        $('nsList').innerHTML = '<div class="sd-empty">Loading…</div>';
      });

      $('nsFilter').addEventListener('input', () => renderNsList());

      $('nsList').addEventListener('change', e => {
        const item = e.target.closest('.sd-item'); if (!item) return;
        const ns = item.dataset.ns;
        if (e.target.type === 'checkbox') {
          if (e.target.checked) { selectedNs.add(ns); ensureColor(ns); }
          else selectedNs.delete(ns);
          saveState();
          // Live add/remove while capturing so the user can iterate without a restart.
          if (capturing) send({ action: e.target.checked ? 'add-ns' : 'remove-ns', ns: [ns] });
          renderNsList(); updateStartBtn();
        } else if (e.target.type === 'color') {
          S.nsColors[ns] = e.target.value; saveState();
          renderSelectedSummary();
          if (typeof renderNsLegend === 'function') renderNsLegend();
        }
      });

      $('nsList').addEventListener('click', e => {
        if (e.target.tagName === 'INPUT') return;
        const item = e.target.closest('.sd-item'); if (!item) return;
        const cb = item.querySelector('input[type=checkbox]');
        if (cb) { cb.checked = !cb.checked; cb.dispatchEvent(new Event('change', { bubbles: true })); }
      });

      $('startBtn').addEventListener('click', () => {
        const ns = [...selectedNs];
        if (!ns.length) return;
        send({ action: 'start', ns });
        close();
      });
      $('stopBtn').addEventListener('click', () => send({ action: 'stop' }));

      $('profilesManage').addEventListener('click', () => {
        const el = $('profilesPanel');
        el.style.display = el.style.display === 'none' ? '' : 'none';
      });
      $('profilesPanel').addEventListener('change', e => {
        const item = e.target.closest('.sd-item');
        if (!item || e.target.type !== 'checkbox') return;
        const name = item.dataset.profile;
        if (e.target.checked) disabledProfiles.delete(name);
        else disabledProfiles.add(name);
        saveState(); populateProfiles();
      });
      $('profilesPanel').addEventListener('click', e => {
        if (e.target.tagName === 'INPUT') return;
        const item = e.target.closest('.sd-item'); if (!item) return;
        const cb = item.querySelector('input[type=checkbox]');
        if (cb) { cb.checked = !cb.checked; cb.dispatchEvent(new Event('change', { bubbles: true })); }
      });
    },

    onInit(m) {
      if (Array.isArray(m.profiles)) populateProfiles(m.profiles);
      if (m.auth) setAuth(m.auth.ok || m.auth.authenticated, m.auth.arn, m.auth.err, m.auth.expiresAt);
      if (m.capturing) {
        setCaptureState(true);
        if (Array.isArray(m.ns)) {
          selectedNs = new Set(m.ns);
          for (const n of selectedNs) ensureColor(n);
          saveState();
          renderNsList();
        }
      } else {
        setCaptureState(false);
      }
      // If authed but we have no namespace list yet, pull it so the drawer's usable immediately.
      if (authState.ok && !cachedNsList.length) send({ action: 'namespaces' });
    },

    onAuthStatus(m) { setAuth(m.ok || m.authenticated, m.arn, m.err || m.error, m.expiresAt); },
    onAuthProgress(m) { $('authInfo').textContent = m.msg || m.message || ''; },
    onAuthResult(m) {
      $('authInfo').textContent = m.msg || m.message || '';
      if (m.ok || m.success) $('loadNs').disabled = false;
    },

    onNamespaces(m) {
      const list = m.list || m.namespaces || [];
      cachedNsList = list;
      if (list.length) saveState();
      renderNsList();
    },

    onCaptureStart(m) {
      setCaptureState(true);
      const ns = Array.isArray(m.ns) ? m.ns
               : (typeof m.ns === 'string' ? m.ns.split(',').map(s=>s.trim()).filter(Boolean) : []);
      if (ns.length) {
        selectedNs = new Set(ns);
        for (const n of ns) ensureColor(n);
        saveState(); renderNsList();
      }
      $('captureInfo').textContent = `Capturing ${ns.join(', ')}…`;
    },
    onCaptureEnd(m) {
      setCaptureState(false);
      if (m && m.n !== undefined) $('captureInfo').innerHTML = `Done: <span class="num">${m.n}</span> lines`;
    },
    onLog(m) {
      if (capturing) $('captureInfo').innerHTML = `<span class="num">${(m.i ?? 0)+1}</span> lines captured`;
    },
    onCleared() {
      setCaptureState(false);
      $('captureInfo').textContent = '';
    },
  };
})();

Drawer.init();
