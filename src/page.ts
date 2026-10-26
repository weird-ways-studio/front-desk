// HTML for Ben's phone. Everything shown about a grant comes from the stored
// grant; the agent's reason appears only as a labelled quote.

import type { Grant, LogEntry } from "./desk.ts";
import { JOBS } from "./jobs.ts";

export function esc(text: string): string {
  return text.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
}

const STYLE = `
:root{--bg:#fff;--fg:#111;--muted:#555;--line:#ddd;--ok:#0a7d32;--bad:#b3261e;--btn:#1a56db}
@media (prefers-color-scheme:dark){:root{--bg:#111;--fg:#eee;--muted:#aaa;--line:#333;--ok:#4ade80;--bad:#f87171;--btn:#3b82f6}}
body{background:var(--bg);color:var(--fg);font:17px/1.45 -apple-system,system-ui,sans-serif;margin:0;padding:16px;max-width:560px}
#status{font-size:28px;font-weight:700;min-height:1.4em;margin:4px 0 12px}
#status.pass{color:var(--ok)}#status.fail{color:var(--bad)}
.muted{color:var(--muted);font-size:15px}
blockquote{margin:8px 0;padding:8px 12px;border-left:4px solid var(--line)}
button{width:100%;font-size:20px;padding:16px;border:0;border-radius:12px;background:var(--btn);color:#fff;margin-top:16px}
button:disabled{opacity:.5}
table{border-collapse:collapse;width:100%;font-size:14px}td,th{border-bottom:1px solid var(--line);padding:6px 4px;text-align:left;vertical-align:top}
`;

// Converts between the JSON the server speaks and the bytes the browser API wants.
// navigator.credentials.* is the first call in the tap handler (C5a lesson L3).
const CLIENT = `
const b2u=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
const u2b=s=>Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
const show=(ok,text)=>{const s=document.getElementById('status');s.className=ok?'pass':'fail';s.textContent=text};
function cred(c){const r=c.response,o={id:c.id,rawId:b2u(c.rawId),type:c.type,clientExtensionResults:{},response:{clientDataJSON:b2u(r.clientDataJSON)}};
 if(r.attestationObject){o.response.attestationObject=b2u(r.attestationObject)}else{o.response.authenticatorData=b2u(r.authenticatorData);o.response.signature=b2u(r.signature);if(r.userHandle)o.response.userHandle=b2u(r.userHandle)}return o}
async function finish(path,c){const res=await fetch(path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(cred(c))});
 const j=await res.json().catch(()=>({}));show(res.ok,res.ok?'PASS':'FAIL: '+(j.error||res.status))}
`;

function page(title: string, nonce: string, body: string, script = ""): string {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow"><title>${esc(title)}</title><style>${STYLE}</style></head>
<body>${body}${script ? `<script nonce="${nonce}">${CLIENT}${script}</script>` : ""}</body></html>`;
}

export function approvePage(g: Grant, options: unknown, nonce: string): string {
  const describe = JOBS[g.job].describe(g.params);
  return page(
    "Approve access",
    nonce,
    `<div id="status"></div>
<h1>Approve this?</h1>
<p><strong>${esc(describe)}</strong></p>
<p class="muted">Job <code>${esc(g.job)}</code> · asked by ${esc(g.requester)} · expires ${new Date(g.expires_at).toISOString().slice(11, 16)} UTC</p>
<p class="muted">The agent's words:</p><blockquote>${esc(g.reason)}</blockquote>
<button id="go">Next: approve with Face ID</button><pre id="after" class="muted" style="white-space:pre-wrap"></pre>`,
    `const opts=${JSON.stringify(options)};
document.getElementById('go').onclick=async e=>{e.target.disabled=true;
 let c;try{c=await navigator.credentials.get({publicKey:{challenge:u2b(opts.challenge),rpId:opts.rpId,timeout:opts.timeout,userVerification:'required',
  allowCredentials:(opts.allowCredentials||[]).map(a=>({type:'public-key',id:u2b(a.id)})),...(opts.prfSalt?{extensions:{prf:{eval:{first:u2b(opts.prfSalt)}}}}:{})}})}
 catch(err){show(false,'FAIL: '+err.name);e.target.disabled=false;return}
 const x=(c.getClientExtensionResults&&c.getClientExtensionResults().prf)||{};const first=x.results&&x.results.first;
 const res=await fetch(location.pathname,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({...cred(c),prf:first?b2u(first):null})});
 const j=await res.json().catch(()=>({}));const bad=j.result&&j.result.error;show(res.ok&&!bad,res.ok?(bad?'FAIL: '+bad:'PASS'):'FAIL: '+(j.error||res.status));
 if(j.result)document.getElementById('after').textContent=JSON.stringify(j.result,null,1)};`,
  );
}

export function enrollPage(options: unknown, nonce: string): string {
  return page(
    "Set up your passkey",
    nonce,
    `<div id="status"></div><h1>Set up your passkey</h1>
<p>One time only. After this, approvals need this passkey.</p><button id="go">Next: create passkey</button>`,
    `const opts=${JSON.stringify(options)};
document.getElementById('go').onclick=async e=>{e.target.disabled=true;
 let c;try{c=await navigator.credentials.create({publicKey:{challenge:u2b(opts.challenge),rp:opts.rp,user:{...opts.user,id:u2b(opts.user.id)},
  pubKeyCredParams:opts.pubKeyCredParams,timeout:opts.timeout,authenticatorSelection:opts.authenticatorSelection,attestation:'none',extensions:{prf:{}}}})}
 catch(err){show(false,'FAIL: '+err.name);e.target.disabled=false;return}
 await finish(location.pathname,c)};`,
  );
}

// One tap: Face ID with the enrolled passkey, asking it for its PRF secret (salted with the
// check label, never the master key's). PASS shows a fingerprint; a second tap should match.
export function prfCheckPage(options: unknown, nonce: string): string {
  return page(
    "Passkey secret check",
    nonce,
    `<div id="status"></div><h1>Passkey secret check</h1>
<p>Tests whether your passkey can unlock the master key later. Nothing is stored or changed.</p>
<button id="go">Next: check with Face ID</button><p id="after" class="muted"></p>`,
    `const opts=${JSON.stringify(options)};
document.getElementById('go').onclick=async e=>{e.target.disabled=true;
 let c;try{c=await navigator.credentials.get({publicKey:{challenge:u2b(opts.challenge),rpId:opts.rpId,timeout:opts.timeout,userVerification:'required',
  allowCredentials:(opts.allowCredentials||[]).map(a=>({type:'public-key',id:u2b(a.id)})),extensions:{prf:{eval:{first:u2b(opts.prfSalt)}}}}})}
 catch(err){show(false,'FAIL: '+err.name);e.target.disabled=false;return}
 const x=(c.getClientExtensionResults&&c.getClientExtensionResults().prf)||{};const first=x.results&&x.results.first;
 const res=await fetch(location.pathname,{method:'POST',headers:{'content-type':'application/json'},
  body:JSON.stringify({credential:cred(c),prf:first?b2u(first):null,prf_info:JSON.stringify(Object.keys(x))})});
 const j=await res.json().catch(()=>({}));show(res.ok,res.ok?'PASS: '+j.fingerprint:'FAIL: '+(j.error||res.status));
 document.getElementById('after').textContent='Now reload this page and tap Next once more. The same code twice means it works.'};`,
  );
}

// One time: Ben pastes the Cloudflare token, taps Face ID, and the vault seals it. The page
// then shows the paper recovery key once. The token is read from the box before the
// passkey call, without an await, so the tap still counts as the user's gesture (C5a L3).
export function setupPage(options: unknown, nonce: string): string {
  return page(
    "Store the master key",
    nonce,
    `<div id="status"></div><h1>Store the master key</h1>
<p>Paste the Cloudflare token you just created, then tap Next. It is locked with your passkey and never shown again.</p>
<textarea id="token" rows="3" style="width:100%;font-size:16px" autocomplete="off" autocapitalize="off" spellcheck="false"></textarea>
<button id="go">Next: lock it with Face ID</button><div id="after"></div>`,
    `const opts=${JSON.stringify(options)};
document.getElementById('go').onclick=async e=>{const parent=document.getElementById('token').value.trim();e.target.disabled=true;
 let c;try{c=await navigator.credentials.get({publicKey:{challenge:u2b(opts.challenge),rpId:opts.rpId,timeout:opts.timeout,userVerification:'required',
  allowCredentials:(opts.allowCredentials||[]).map(a=>({type:'public-key',id:u2b(a.id)})),extensions:{prf:{eval:{first:u2b(opts.prfSalt)}}}}})}
 catch(err){show(false,'FAIL: '+err.name);e.target.disabled=false;return}
 const x=(c.getClientExtensionResults&&c.getClientExtensionResults().prf)||{};const first=x.results&&x.results.first;
 const res=await fetch(location.pathname,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({...cred(c),prf:first?b2u(first):null,parent})});
 const j=await res.json().catch(()=>({}));show(res.ok,res.ok?'PASS':'FAIL: '+(j.error||res.status));document.getElementById('token').value='';
 if(res.ok){const a=document.getElementById('after');a.innerHTML='<h2>Paper recovery key</h2><p>Write this down or print it now and keep it away from your phone. It is shown only once.</p><p style="font:20px/1.6 ui-monospace,monospace;word-break:break-all"></p>';
  a.querySelector('p:last-child').textContent=j.recovery_key}};`,
  );
}

export function logPage(entries: LogEntry[], nonce: string): string {
  const time = (ms: number) => new Date(ms).toISOString().replace("T", " ").slice(0, 16);
  const rows = entries
    .slice()
    .reverse()
    .map((e) => {
      const what = e.job ? (e.params ? JOBS[e.job as keyof typeof JOBS]?.describe(e.params) ?? e.job : e.job) : "";
      return `<tr><td>${time(e.at)}</td><td><strong>${esc(e.event)}</strong>${e.grant_id ? `<br><span class="muted">${esc(e.grant_id.slice(0, 8))}</span>` : ""}</td>
<td>${esc(what)}${e.detail ? `<br><span class="muted">${esc(e.detail)}</span>` : ""}</td><td>${esc(e.requester ?? "")}</td>
<td>${e.reason ? `<q>${esc(e.reason)}</q>` : ""}</td><td>${e.expires_at ? time(e.expires_at) : ""}</td></tr>`;
    })
    .join("");
  return page(
    "Grant log",
    nonce,
    `<h1>Grant log</h1><p class="muted">Newest first. Times UTC. Nothing here can be edited or deleted. The reason is the agent's own words.</p>
<table><tr><th>When</th><th>What happened</th><th>Job</th><th>Who</th><th>Why</th><th>Expires</th></tr>${rows}</table>`,
  );
}
