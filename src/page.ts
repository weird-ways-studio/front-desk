// HTML for Ben's phone. Everything shown about a grant comes from the stored
// grant; the agent's reason appears only as a labelled quote.

import type { Grant, LogEntry } from "./desk.ts";
import { JOBS, type Guide } from "./jobs.ts";
import type { CboxKey } from "./cboxkey.ts";

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
h2{font-size:18px;margin:16px 0 4px}ul{margin:0;padding-left:20px}li{margin:2px 0}.warn{color:var(--bad);font-weight:600}details{margin-top:20px}pre{white-space:pre-wrap;word-break:break-word;font-size:13px}
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
// The browser's own words and the seconds since the tap tell a cancel, a timeout and an instant refusal apart.
const failed=(err,t0)=>show(false,'FAIL: '+err.name+(err.message?' -- '+String(err.message).slice(0,160):'')+' ('+((Date.now()-t0)/1000).toFixed(1)+'s after tap)');
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

/**
 * What the phone shows after the tap, from the HTTP status (null: no answer arrived) and the parsed
 * body (null: unreadable). Runs in the browser as written (approvePage embeds its source) and in tests.
 * Done only when the front desk says so; anything unclear says so and asks Ben not to tap again.
 */
export function outcomeView(status: number | null, j: unknown): { ok: boolean; head: string; text: string } {
  const b = (j && typeof j === "object" ? j : {}) as { outcome?: unknown; summary?: unknown; error?: unknown };
  const again = "Do not tap again; tell the agent";
  if (status === null) return { ok: false, head: "Unclear", text: `The connection failed before the front desk answered, so it is unknown whether your tap arrived. ${again}: [no answer]` };
  if (status >= 400 && status < 500 && typeof b.error === "string") return { ok: false, head: "Not approved", text: `The front desk refused the tap, so this request is not approved. Tell the agent the words in brackets: [${b.error}]` };
  if (status !== 200 || typeof b.summary !== "string" || (b.outcome !== "done" && b.outcome !== "not_done")) return { ok: false, head: "Unclear", text: `No clear answer came back (status ${status}), so it is unknown what happened. ${again}: [unclear answer]` };
  return { ok: b.outcome === "done", head: b.outcome === "done" ? "Done" : "Not done", text: b.summary };
}

// Step 1 of 2 is reading what approving does; step 2 is the plain result after the tap. The exact
// technical text is there, folded, never instead of the plain words (instruction.orient-the-person).
export function approvePage(g: Grant, options: unknown, nonce: string): string {
  const guide: Guide = JOBS[g.job].explain(g.params);
  const sections = (guide.sections ?? [])
    .map((s) => `<h2>${esc(s.heading)}</h2><ul>${s.items.map((i) => `<li>${esc(i)}</li>`).join("")}</ul>`)
    .join("");
  const exact = [guide.exact, `Job ${g.job} · asked by ${g.requester} · request ${g.id}`].filter(Boolean).join("\n\n");
  return page(
    "Approve access",
    nonce,
    `<p class="muted" id="step">Step 1 of 2 · Check what this does, then approve</p>
<div id="status"></div>
<h1>Approve this?</h1>
<p><strong>${esc(guide.does)}</strong></p>
${sections}
${guide.warn ? `<p class="warn">${esc(guide.warn)}</p>` : ""}
<p><strong>When you approve:</strong> ${esc(guide.expect)}</p>
<p class="muted">The agent's reason, in its own words:</p><blockquote>${esc(g.reason)}</blockquote>
<p class="muted">This request expires at <span id="expires">${new Date(g.expires_at).toISOString().slice(11, 16)} UTC</span>. Login: your <strong>front desk passkey</strong>; Face ID offers only that one.</p>
<button id="go">Approve with Face ID</button>
<p id="after"></p>
<details><summary class="muted">Exact details (technical)</summary><pre id="exact" class="muted">${esc(exact)}</pre></details>`,
    `const opts=${JSON.stringify(options)};
document.getElementById('expires').textContent=new Date(${g.expires_at}).toLocaleTimeString([],{hour:'numeric',minute:'2-digit'});
document.getElementById('go').onclick=async e=>{const t0=Date.now();e.target.disabled=true;
 let c;try{c=await navigator.credentials.get({publicKey:{challenge:u2b(opts.challenge),rpId:opts.rpId,timeout:opts.timeout,userVerification:'required',
  allowCredentials:(opts.allowCredentials||[]).map(a=>({type:'public-key',id:u2b(a.id)})),...(opts.prfSalt?{extensions:{prf:{eval:{first:u2b(opts.prfSalt)}}}}:{})}})}
 catch(err){failed(err,t0);e.target.disabled=false;return}
 const x=(c.getClientExtensionResults&&c.getClientExtensionResults().prf)||{};const first=x.results&&x.results.first;
 let res=null,j=null;try{res=await fetch(location.pathname,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({...cred(c),prf:first?b2u(first):null})});j=await res.json().catch(()=>null)}catch(_){}
 const v=outcomeView(res?res.status:null,j);
 document.getElementById('step').textContent='Step 2 of 2 · Result';e.target.hidden=true;show(v.ok,v.head);
 document.getElementById('after').textContent=v.text;
 if(j&&j.result)document.getElementById('exact').textContent+='\\n\\nResult:\\n'+JSON.stringify(j.result,null,1)};
${outcomeView.toString()}`,
  );
}

export function enrollPage(options: unknown, nonce: string): string {
  return page(
    "Set up your passkey",
    nonce,
    `<div id="status"></div><h1>Set up your passkey</h1>
<p>One time only. After this, approvals need this passkey.</p><button id="go">Next: create passkey</button>`,
    `const opts=${JSON.stringify(options)};
document.getElementById('go').onclick=async e=>{const t0=Date.now();e.target.disabled=true;
 let c;try{c=await navigator.credentials.create({publicKey:{challenge:u2b(opts.challenge),rp:opts.rp,user:{...opts.user,id:u2b(opts.user.id)},
  pubKeyCredParams:opts.pubKeyCredParams,timeout:opts.timeout,authenticatorSelection:opts.authenticatorSelection,attestation:'none',extensions:{prf:{}}}})}
 catch(err){failed(err,t0);e.target.disabled=false;return}
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
document.getElementById('go').onclick=async e=>{const t0=Date.now();e.target.disabled=true;
 let c;try{c=await navigator.credentials.get({publicKey:{challenge:u2b(opts.challenge),rpId:opts.rpId,timeout:opts.timeout,userVerification:'required',
  allowCredentials:(opts.allowCredentials||[]).map(a=>({type:'public-key',id:u2b(a.id)})),extensions:{prf:{eval:{first:u2b(opts.prfSalt)}}}}})}
 catch(err){failed(err,t0);e.target.disabled=false;return}
 const x=(c.getClientExtensionResults&&c.getClientExtensionResults().prf)||{};const first=x.results&&x.results.first;
 const res=await fetch(location.pathname,{method:'POST',headers:{'content-type':'application/json'},
  body:JSON.stringify({credential:cred(c),prf:first?b2u(first):null,prf_info:JSON.stringify(Object.keys(x))})});
 const j=await res.json().catch(()=>({}));show(res.ok,res.ok?'PASS: '+j.fingerprint:'FAIL: '+(j.error||res.status));
 document.getElementById('after').textContent='Now reload this page and tap Next once more. The same code twice means it works.'};`,
  );
}

// Ben's page for a lost or stolen c-box: shows the enrolled signing key and removes it in one tap.
export function cboxKeyPage(key: CboxKey | undefined, nonce: string): string {
  const when = (ms: number) => new Date(ms).toISOString().replace("T", " ").slice(0, 16);
  if (!key) return page("C-box key", nonce, `<h1>C-box key</h1><p>No c-box key is enrolled. Requests for keys are refused until one is.</p>`, "");
  return page(
    "C-box key",
    nonce,
    `<div id="status"></div><h1>C-box key</h1>
<p>Enrolled key: <strong>${esc(key.fingerprint)}</strong>, since ${when(key.enrolled_at)} UTC.</p>
<p>If the c-box is lost or stolen, remove it. Every key request is then refused until you approve a new one.</p>
<button id="go">Remove c-box key</button>`,
    `document.getElementById('go').onclick=async e=>{const t0=Date.now();e.target.disabled=true;
 const res=await fetch(location.pathname,{method:'POST'});const j=await res.json().catch(()=>({}));
 show(res.ok,res.ok?'PASS: removed '+j.removed:'FAIL: '+(j.error||res.status))};`,
  );
}

export function logPage(entries: LogEntry[], nonce: string): string {
  const time = (ms: number) => new Date(ms).toISOString().replace("T", " ").slice(0, 16);
  const rows = entries
    .slice()
    .reverse()
    .map((e) => {
      const what = e.job ? (e.params ? JOBS[e.job as keyof typeof JOBS]?.explain(e.params).does ?? e.job : e.job) : "";
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
