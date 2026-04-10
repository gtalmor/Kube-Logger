const AGENT_URL = 'ws://localhost:4040';
const HIDDEN_KEY='io-hidden-patterns';
const S = {
  ws:null, lines:[], raw:[], filtered:[], errIdx:[], curErr:-1,
  pods:new Set(), reqs:new Map(), flowNodes:[],
  search:'', hideTrace:false, level:'all', pod:'all', req:'all',
  autoScroll:true, capturing:false, start:null, buf:[], scheduled:false,
  hiddenPatterns:JSON.parse(localStorage.getItem(HIDDEN_KEY)||'[]'),
  hiddenExecIds:new Set(), // flow execution IDs hidden this session
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

function parse(raw,i){
  const t=raw.trimEnd(); if(!t)return null;
  if(SP.test(t))return{type:'stern',idx:i,raw:t};
  const nm=t.match(NX);
  if(nm){
    const s=+nm[7];
    const r={type:'http',pod:nm[1],container:nm[2],timestamp:nm[4],method:nm[5],path:nm[6],status:s,size:+nm[8],level:'HTTP',idx:i,raw:t};
    const fp=nm[6].match(FLOW_PATH_RE);if(fp)r.flowName=fp[1];
    return r;
  }
  const jm=t.match(SJ);
  if(jm){try{const j=JSON.parse(jm[3]),d=j.data||[];let msg='',fi=null;for(const x of d){if(typeof x==='string')msg+=(msg?' ':'')+x;else if(x&&x.file)fi=x;else if(x&&typeof x==='object')msg+=(msg?' ':'')+JSON.stringify(x);}
    const r={type:'json',pod:jm[1],container:jm[2],timestamp:j.timestamp,level:(j.level||'INFO').toUpperCase(),reqId:j.req_id,msg,fileInfo:fi,data:j.data,json:j,idx:i,raw:t};
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
      return{type:'script-error',pod:tp[1],container:tp[2],timestamp:se[1],level:se[2].toUpperCase(),scriptReqId:se[3],msg:cleanMsg,idx:i,raw:t};
    }
    // Check for error detail continuation (e.g., "    SyntaxError: Illegal return statement")
    const ed=cleanMsg.match(ERR_DETAIL_RE);
    if(ed){
      return{type:'plain',pod:tp[1],container:tp[2],msg:ed[1],level:'ERROR',isErrorDetail:true,idx:i,raw:t};
    }
    return{type:'plain',pod:tp[1],container:tp[2],msg:cleanMsg,level:cleanMsg.toLowerCase().includes('error')?'ERROR':cleanMsg.toLowerCase().includes('warn')?'WARN':'INFO',idx:i,raw:t};
  }
  return{type:'raw',msg:t,level:'INFO',idx:i,raw:t};
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
      // Find the preceding node whose "next" was this ID to get the node type
      let nodeType='#'+nc[1];
      for(const prev of nodes){if(prev.next===nc[1]){nodeType=prev.node+' → FAIL';break;}}
      nodes.push({node:nodeType,label:'Failure output not connected (#'+nc[1]+')',state:'failed',lineIdx:l.idx,reqId:l.reqId,flowExecId:l.flowExecId||l.flowExecId,flowName:l.flowName});}}}
  // Add script-executor errors as failed nodes in the timeline
  for(const se of scriptErrors){const k='se-'+se.lineIdx;if(!seen.has(k)){seen.add(k);nodes.push({node:'script-executor',label:se.msg,state:'failed',lineIdx:se.lineIdx});}}
  return nodes;
}

// ── Render helpers ────────────
function esc(s){return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function hiSearch(t,q){if(!q)return esc(t);try{const e=q.replace(/[.*+?^${}()|[\]\\]/g,'\\$&');return esc(t).replace(new RegExp('('+e+')','gi'),'<span class="hi">$1</span>');}catch{return esc(t);}}
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
  if(l.msg&&/failure|fail|error/i.test(l.msg)&&l.level!=='TRACE')c+=' fl';
  let h=`<div class="${c}" data-i="${l.idx}">`;
  h+=`<span class="ln">${l.idx+1}</span>`;
  h+=`<span class="lt">${l.timestamp?fmtTs(l.timestamp):''}</span>`;
  h+=`<span class="lv ${l.level||''}">${isMultiCont?'':l.level||''}</span>`;
  h+=`<span class="lp" title="${esc(l.pod||'')}" data-pod="${esc(l.pod||'')}">${isMultiCont?'&#x2502;':esc(shortPod(l.pod))}</span>`;
  h+=`<span class="lr" title="${esc(l.reqId||'')}" data-req="${esc(l.reqId||'')}">${l.reqId?shortReq(l.reqId):''}</span>`;
  if(l.type==='http'){const sc=l.status>=500?'s5':l.status>=400?'s4':l.status>=300?'s3':'s2';h+=`<span class="lm">${hiSearch(l.method+' '+l.path+' ',q)}<span class="hs ${sc}">${l.status}</span> ${l.size}B</span>`;}
  else if(l.failNodeId){
    h+=`<span class="lm"><span class="lfail" data-fail="${l.idx}">&#x26A0; <strong>${esc(l.failNodeLabel)}</strong> <span class="lfail-id">#${esc(l.failNodeId)}</span> <span class="lfail-hint">click for context</span></span></span>`;
  }
  else{const m=l.msg||l.raw||'';const d=m.length>500?m.slice(0,500)+'...':m;h+=`<span class="lm">${hiSearch(d,q)}${l.type==='json'&&l.data?`<span class="je" data-li="${l.idx}">[+]</span>`:''}</span>`;}
  h+=`<span class="lh" data-hide="${l.idx}" title="Hide messages like this">&times;</span>`;
  return h+'</div>';
}

function jsonDetailHtml(l){
  const str=JSON.stringify(l.json||l.data,null,2).replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g,m=>{
    let c='jn';if(/^"/.test(m))c=/:$/.test(m)?'jk':'js';else if(/true|false/.test(m))c='jb';else if(/null/.test(m))c='jl';return`<span class="${c}">${m}</span>`;});
  return`<div class="jd" id="jd-${l.idx}">${str}</div>`;
}

// ── Filter / render ───────────
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

function rebuildFiltered(){
  S.filtered=[];S.errIdx=[];S.curErr=-1;
  for(let i=0;i<S.lines.length;i++){const l=S.lines[i];if(!shouldShow(l))continue;S.filtered.push(i);
    if(l.level==='ERROR'||l.level==='FATAL'||(l.type==='http'&&l.status>=500)||(l.msg&&/failure|fail/i.test(l.msg)&&l.level!=='TRACE'))S.errIdx.push(i);}
}

function fullRender(){
  const c=$('lc');let h='';let prev=null;
  for(const i of S.filtered){const l=S.lines[i];try{h+=lineHtml(l,S.search,prev);}catch(e){console.error('lineHtml error at',i,e);h+=`<div class="ll lERROR" data-i="${i}"><span class="ln">${i+1}</span><span class="lm" style="color:var(--error)">[render error: ${e.message}]</span></div>`;}prev=l;}
  c.innerHTML=h;
  c.classList.add('v');$('welcome').classList.add('h');$('filterBar').style.display='flex';
  updateStats();updateErrBanner();updateFlow();
}

function appendLive(l){
  if(!shouldShow(l))return;
  S.filtered.push(l.idx);
  if(l.level==='ERROR'||l.level==='FATAL'||(l.type==='http'&&l.status>=500)||(l.msg&&/failure|fail/i.test(l.msg)&&l.level!=='TRACE'))S.errIdx.push(l.idx);
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
  $('lc').innerHTML='';$('lc').classList.remove('v');
  $('welcome').classList.remove('h');$('filterBar').style.display='none';
  $('errBanner').classList.remove('v');$('ftl').classList.remove('v');
  $('stats').innerHTML='';$('searchInput').value='';$('searchCount').textContent='';
  $('clearBtn').style.display='none';
  closeTrace();
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

// ── File load ─────────────────
function loadFile(text){
  S.lines=[];S.raw=text.split('\n');S.pods=new Set();S.reqs=new Map();
  for(let i=0;i<S.raw.length;i++){const p=parse(S.raw[i],i);S.lines.push(p);if(p){if(p.pod)S.pods.add(p.pod);if(p.reqId)S.reqs.set(p.reqId,(S.reqs.get(p.reqId)||0)+1);}}
  populateFilters();rebuildFiltered();fullRender();
  if(S.errIdx.length)setTimeout(()=>{S.curErr=0;scrollTo(S.errIdx[0]);},300);
  toast(`Loaded ${S.raw.length} lines`);
}

// ── Live line ─────────────────
function addLive(raw){
  const i=S.lines.length;S.raw.push(raw);
  let p;try{p=parse(raw,i);}catch(e){console.error('parse error:',e);p={type:'raw',msg:raw,level:'INFO',idx:i,raw:raw};}
  S.lines.push(p);
  if(p){
    if(p.pod){const had=S.pods.has(p.pod);S.pods.add(p.pod);if(!had)populateFilters();}
    if(p.reqId){S.reqs.set(p.reqId,(S.reqs.get(p.reqId)||0)+1);if(S.lines.length%100===0)populateFilters();}
    appendLive(p);
  }
}

// ── WebSocket ─────────────────
function connect(){
  try{S.ws=new WebSocket(AGENT_URL);}catch{return setConn(false);}
  S.ws.onopen=()=>setConn(true);
  S.ws.onclose=()=>{setConn(false);setTimeout(connect,3000);};
  S.ws.onerror=()=>{};
  S.ws.onmessage=ev=>{
    const m=JSON.parse(ev.data);
    switch(m.type){
      case'init':
        if(m.auth&&(m.auth.ok||m.auth.authenticated)){
          $('cLabel').textContent=m.auth.arn?m.auth.arn.split('/').pop():'Authenticated';
          $('loadNsBtn').disabled=false;
          // Auto-load namespaces if not already loaded
          if(!$('nsSelect').value)send({action:'namespaces'});
          else $('startBtn').disabled=false;
        }
        if(m.capturing)setCap(true);
        else{$('startBtn').style.display='';$('stopBtn').style.display='none';}
        break;
      case'namespaces':{
        const list=m.list||m.namespaces||[];
        const sel=$('nsSelect');sel.innerHTML='<option value="">Select Namespace...</option>';
        const priority=list.filter(n=>n.includes('io')||n.includes('productpod'));
        const rest=list.filter(n=>!priority.includes(n));
        for(const n of[...priority,...rest]){const o=document.createElement('option');o.value=n;o.textContent=n;sel.appendChild(o);}
        // Restore last used
        const last=localStorage.getItem('io-last-ns');
        if(last&&list.includes(last)){sel.value=last;$('startBtn').disabled=false;}
        toast(`Loaded ${list.length} namespaces`);
        break;}
      case'capture-start':case'capture-state':
        setCap(true,m.ns);
        S.lines=[];S.raw=[];S.filtered=[];S.pods=new Set();S.reqs=new Map();S.errIdx=[];
        $('lc').innerHTML='';$('lc').classList.add('v');$('welcome').classList.add('h');$('filterBar').style.display='flex';
        break;
      case'log':try{addLive(m.line);}catch(e){console.error('addLive error:',e);}break;
      case'cleared':clearState();break;
      case'capture-stop':case'capture-stopped':case'capture-end':case'capture-ended':
        setCap(false);populateFilters();updateFlow();updateErrBanner();updateStats();
        if(m.n!==undefined)toast(`Captured ${m.n} lines`);
        if(S.errIdx.length)setTimeout(()=>{S.curErr=0;scrollTo(S.errIdx[0]);},500);
        break;
      case'stderr':if(!m.msg.includes('Experimental'))toast(m.msg.slice(0,80));break;
      case'error':toast('Error: '+m.msg);break;
      case'auth-status':
        $('cLabel').textContent=(m.ok||m.authenticated)?(m.arn?m.arn.split('/').pop():'Auth OK'):'Not authed';
        $('loadNsBtn').disabled=!(m.ok||m.authenticated);
        $('startBtn').disabled=!$('nsSelect').value;
        break;
    }
  };
}

function send(m){if(S.ws&&S.ws.readyState===1)S.ws.send(JSON.stringify(m));}
function badge(text,color){try{chrome.runtime.sendMessage({type:'badge',text,color});}catch{}}

function setConn(ok){
  $('cDot').className='dot '+(ok?'ok':'fail');
  $('cLabel').textContent=ok?'Connected':'Disconnected — agent not running?';
  if(ok)badge('','#3fb950');
}

let timerIv;
function setCap(on,ns){
  S.capturing=on;
  $('startBtn').style.display=on?'none':'';$('stopBtn').style.display=on?'':'none';
  $('startBtn').disabled=!$('nsSelect').value;
  $('clearBtn').style.display=S.lines.length?'':'none';
  const rb=$('recBanner');
  if(on){rb.classList.add('v');S.start=Date.now();clearInterval(timerIv);
    timerIv=setInterval(()=>{if(!S.capturing){clearInterval(timerIv);return;}const e=Math.floor((Date.now()-S.start)/1000);$('recInfo').textContent=`Capturing ${ns||''} — ${Math.floor(e/60)}:${String(e%60).padStart(2,'0')} — ${S.lines.length} lines`;},1000);
    badge('REC','#f85149');
  }else{rb.classList.remove('v');clearInterval(timerIv);badge('','#3fb950');}
}

// ── Events ────────────────────
$('startBtn').addEventListener('click',()=>{const ns=$('nsSelect').value;if(!ns){toast('Select a namespace first');return;}send({action:'start',ns});});
$('loadNsBtn').addEventListener('click',()=>{send({action:'namespaces'});$('nsSelect').innerHTML='<option value="">Loading...</option>';});
$('nsSelect').addEventListener('change',e=>{$('startBtn').disabled=!e.target.value;if(e.target.value)localStorage.setItem('io-last-ns',e.target.value);});
$('stopBtn').addEventListener('click',()=>send({action:'stop'}));
$('clearBtn').addEventListener('click',()=>{
  if(S.capturing){
    // Clear display but keep capturing — new lines will keep flowing in
    S.lines=[];S.raw=[];S.filtered=[];S.pods=new Set();S.reqs=new Map();S.errIdx=[];S.curErr=-1;S.flowNodes=[];S.buf=[];
    S.hiddenExecIds=new Set();S._hiddenReqIds=null;
    $('lc').innerHTML='';$('errBanner').classList.remove('v');$('ftl').classList.remove('v');
    $('stats').innerHTML='';closeTrace();
    toast('Display cleared — still capturing');
  } else {
    send({action:'clear'});
    clearState();
  }
});
$('tpClose').addEventListener('click',closeTrace);

let sto;$('searchInput').addEventListener('input',e=>{clearTimeout(sto);sto=setTimeout(()=>{S.search=e.target.value.trim();rebuildFiltered();fullRender();},200);});
$('levelFilter').addEventListener('change',e=>{S.level=e.target.value;rebuildFiltered();fullRender();});
$('podFilter').addEventListener('change',e=>{S.pod=e.target.value;rebuildFiltered();fullRender();});
$('reqidFilter').addEventListener('change',e=>{S.req=e.target.value;rebuildFiltered();fullRender();});
$('hideTrace').addEventListener('click',e=>{S.hideTrace=!S.hideTrace;e.target.classList.toggle('active',S.hideTrace);e.target.textContent=S.hideTrace?'Show TRACE':'Hide TRACE';rebuildFiltered();fullRender();});
$('hiddenBtn').addEventListener('click',e=>{e.stopPropagation();showHiddenPanel();});
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
  const hb=e.target.closest('.lh');if(hb){const idx=+hb.dataset.hide;const l=S.lines[idx];if(l){const pat=extractPattern(l);addHiddenPattern(pat);toast(`Hidden: "${pat.slice(0,40)}${pat.length>40?'...':''}"`);}return;}
  const fb=e.target.closest('.lfail');if(fb){e.stopPropagation();const idx=+fb.dataset.fail;const l=S.lines[idx];if(l)showFailurePopover(fb,l);return;}
  const pod=e.target.closest('.lp');if(pod&&pod.dataset.pod){S.pod=pod.dataset.pod;$('podFilter').value=pod.dataset.pod;rebuildFiltered();fullRender();toast(`Filtered: ${shortPod(pod.dataset.pod)}`);return;}
  const req=e.target.closest('.lr');if(req&&req.dataset.req){
    if(e.shiftKey){S.req=req.dataset.req;$('reqidFilter').value=req.dataset.req;rebuildFiltered();fullRender();toast(`Request: ${shortReq(req.dataset.req)}`);}
    else{openTrace(req.dataset.req);}
    return;}
  const je=e.target.closest('.je');if(je){const i=+je.dataset.li;const ex=document.getElementById('jd-'+i);if(ex){ex.classList.toggle('v');je.textContent=ex.classList.contains('v')?'[-]':'[+]';}else{const l=S.lines[i];if(l){je.closest('.ll').insertAdjacentHTML('afterend',jsonDetailHtml(l));document.getElementById('jd-'+i).classList.add('v');je.textContent='[-]';}}return;}
});

// Keyboard
document.addEventListener('keydown',e=>{
  if((e.ctrlKey||e.metaKey)&&e.key==='f'){e.preventDefault();$('searchInput').focus();}
  if(e.key==='Escape'){if($('tracePanel').classList.contains('v')){closeTrace();}else{$('searchInput').blur();if(S.search){S.search='';$('searchInput').value='';rebuildFiltered();fullRender();}}}
  if((e.ctrlKey||e.metaKey)&&e.key==='e'){e.preventDefault();jumpErr(e.shiftKey?'prev':'next');}
});

// Paste
document.addEventListener('paste',e=>{if(e.target.tagName==='INPUT')return;const t=e.clipboardData.getData('text');if(t&&t.length>50){e.preventDefault();loadFile(t);}});

updateHiddenBtn();
connect();
