from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse, JSONResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from .core import ScanConfig, run_assessment, MODULE_LABELS
from .reports import export_docx, export_pdf

app = FastAPI(title="PHP2Scope", version="0.3.0", docs_url=None, redoc_url=None)
_RESULTS: dict[str, dict[str, Any]] = {}
_REPORT_DIR = Path.home() / ".local" / "share" / "php2scope" / "reports"
_REPORT_DIR.mkdir(parents=True, exist_ok=True)

class ScanRequest(BaseModel):
    target_url: str = Field(min_length=1, max_length=2048)
    access_mode: str = "url_only"
    validation_depth: str = "passive"
    modules: list[str] = list(MODULE_LABELS)
    auth_header: str = Field(default="", max_length=4096)
    cookie_header: str = Field(default="", max_length=8192)
    server_evidence: str = Field(default="", max_length=10000)
    scope_confirmed: bool = False

@app.get("/", response_class=HTMLResponse)
async def home():
    return HTMLResponse(PAGE)

@app.get("/api/health")
async def health():
    return {"name": "PHP2Scope", "version": "0.3.0", "validation": "passive-only"}

@app.post("/api/scan")
async def create_scan(req: ScanRequest):
    if not req.scope_confirmed:
        raise HTTPException(400, "Confirm that you are authorized to assess this target.")
    if req.validation_depth != "passive":
        raise HTTPException(400, "This v1 build supports Passive mode only. Safe active mode is not implemented yet.")
    if req.access_mode == "authenticated" and not (req.auth_header.strip() or req.cookie_header.strip()):
        raise HTTPException(400, "Authenticated mode requires an Authorization header value or Cookie header.")
    if req.access_mode == "server_evidence" and not req.server_evidence.strip():
        raise HTTPException(400, "URL plus server-side evidence mode requires PHP version/package evidence.")
    try:
        cfg = ScanConfig(target_url=req.target_url, access_mode=req.access_mode, validation_depth=req.validation_depth,
                         modules=req.modules, auth_header=req.auth_header, cookie_header=req.cookie_header,
                         server_evidence=req.server_evidence, scope_confirmed=req.scope_confirmed)
        result = await run_in_threadpool(run_assessment, cfg)
    except ValueError as e:
        raise HTTPException(400, str(e)) from e
    except Exception as e:
        raise HTTPException(500, f"Assessment failed safely: {type(e).__name__}: {str(e)[:250]}") from e
    payload = result.to_dict()
    _RESULTS[result.scan_id] = payload
    while len(_RESULTS) > 100:
        _RESULTS.pop(next(iter(_RESULTS)))
    # Secrets are not present in the result object; do not echo submitted auth fields.
    return JSONResponse(payload)

@app.get("/api/scan/{scan_id}")
async def get_scan(scan_id: str):
    item = _RESULTS.get(scan_id)
    if not item: raise HTTPException(404, "Scan result not found. It may have expired after app restart or cache rotation.")
    return JSONResponse(item)

@app.get("/api/report/{scan_id}/{kind}")
async def get_report(scan_id: str, kind: str):
    data = _RESULTS.get(scan_id)
    if not data: raise HTTPException(404, "Scan result not found.")
    if "report" not in data.get("modules", []): raise HTTPException(400, "Report generation module was not selected for this assessment.")
    if kind not in {"docx", "pdf"}: raise HTTPException(404, "Report format must be docx or pdf.")
    path = _REPORT_DIR / f"php2scope_{scan_id}_report.{kind}"
    try:
        if kind == "docx": export_docx(data, path)
        else: export_pdf(data, path)
    except Exception as e:
        raise HTTPException(500, f"Report creation failed: {type(e).__name__}: {str(e)[:200]}") from e
    media = "application/vnd.openxmlformats-officedocument.wordprocessingml.document" if kind == "docx" else "application/pdf"
    return FileResponse(path, media_type=media, filename=path.name)

PAGE = r'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>PHP2Scope v0.3.0 · Passive Assessment</title>
<style>
:root{color-scheme:dark;--bg:#09121d;--panel:#101e2c;--panel2:#14283a;--line:#284258;--ink:#e9f2f8;--muted:#9bb2c4;--accent:#65d2c0;--blue:#75b7f2;--warn:#ffd27e;--danger:#ff9f9f}*{box-sizing:border-box}body{margin:0;background:radial-gradient(1100px 550px at 70% -120px,#183a4c 0,transparent 65%),var(--bg);color:var(--ink);font:15px/1.5 ui-sans-serif,system-ui,-apple-system,Segoe UI,sans-serif}.shell{max-width:1120px;margin:auto;padding:26px 18px 60px}.top{display:flex;align-items:center;gap:15px;margin-bottom:24px}.mark{background:linear-gradient(135deg,#65d2c0,#75b7f2);color:#06141e;font-weight:900;border-radius:14px;width:54px;height:54px;display:grid;place-items:center;font-size:20px}.subtitle{color:var(--muted);font-size:13px}.title{font-size:27px;font-weight:850;letter-spacing:-.5px}.layout{display:grid;grid-template-columns:minmax(320px,430px) minmax(0,1fr);gap:18px}.panel{background:linear-gradient(180deg,rgba(20,40,58,.96),rgba(13,27,41,.96));border:1px solid var(--line);border-radius:18px;padding:20px;box-shadow:0 18px 48px #0002}.panel h2{font-size:16px;margin:0 0 13px}.step{font-size:11px;color:var(--accent);font-weight:800;letter-spacing:1.1px;text-transform:uppercase;margin-bottom:5px}label{display:block;color:#c2d5e2;font-size:13px;font-weight:650;margin:14px 0 6px}input[type=text],input[type=password],textarea,select{width:100%;background:#0a1723;color:var(--ink);border:1px solid #36536a;border-radius:10px;padding:10px 11px;font:inherit;outline:none}textarea{resize:vertical;min-height:80px}input:focus,textarea:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 2px #65d2c022}.radio,.check{display:flex;gap:9px;align-items:flex-start;padding:8px 10px;border:1px solid transparent;border-radius:9px;color:#d9e6ed;font-size:13px}.radio:has(input:checked),.check:has(input:checked){background:#65d2c010;border-color:#37675f}.radio input,.check input{margin-top:4px;accent-color:var(--accent)}.small{font-size:12px;color:var(--muted)}.subbox{background:#0b1925;border:1px solid #243d50;border-radius:12px;padding:10px 12px;margin-top:10px}.btn{border:0;border-radius:11px;background:var(--accent);color:#06211f;font:800 14px inherit;padding:12px 16px;cursor:pointer;width:100%;margin-top:15px}.btn:disabled{opacity:.55;cursor:wait}.status{padding:11px 13px;border-radius:10px;background:#0b1925;border:1px solid var(--line);margin-bottom:12px;color:var(--muted);font-size:13px}.status.error{border-color:#854949;color:var(--danger)}.status.ok{border-color:#37675f;color:var(--accent)}.empty{min-height:310px;display:grid;place-items:center;text-align:center;color:var(--muted);padding:24px}.empty .big{font-size:48px;display:block;margin-bottom:12px;color:var(--blue)}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:9px;margin:12px 0}.stat{background:#0a1723;border:1px solid var(--line);padding:12px;border-radius:12px}.stat strong{display:block;font-size:23px}.stat span{font-size:11px;color:var(--muted)}.section{margin-top:20px}.section h3{font-size:14px;margin:0 0 9px}.pill{display:inline-block;font-size:11px;background:#213a4d;color:#cde5f4;padding:3px 8px;border-radius:99px}.pill.warn{background:#48371b;color:var(--warn)}.pill.bad{background:#4b2428;color:var(--danger)}.tablewrap{overflow:auto;border:1px solid var(--line);border-radius:10px}table{border-collapse:collapse;width:100%;font-size:12px}th,td{padding:9px 10px;border-bottom:1px solid #263e51;text-align:left;vertical-align:top}th{background:#11283a;color:#bcd5e5;font-weight:750}td{overflow-wrap:anywhere}tr:last-child td{border-bottom:0}.actions{display:flex;gap:9px;margin-top:15px}.actions a{flex:1;text-align:center;text-decoration:none;padding:10px;border-radius:10px;border:1px solid #3e657c;color:#a9ddff;font-size:13px;font-weight:750}.actions a:hover{background:#15344a}.footer{margin-top:20px;color:#829bab;font-size:11px}.hidden{display:none!important}.split{display:flex;gap:8px;align-items:center}.split>div{flex:1}@media(max-width:800px){.layout{grid-template-columns:1fr}.empty{min-height:170px}.title{font-size:23px}.shell{padding:18px 12px 40px}}
</style></head><body><main class="shell">
<header class="top"><div class="mark">P2</div><div><div class="title">PHP2Scope</div><div class="subtitle">Wizard-driven PHP CVE triage · CVE-2026-109618 / CVE-2026-109619</div></div></header>
<div class="layout"><section class="panel"><div class="step">Step 1 / Scope</div><h2>Define the assessment</h2>
<label for="target">Single target URL (optional if using a list)</label><input id="target" type="text" placeholder="https://authorized-target.example" autocomplete="url">
<label for="domainfile">Upload domain list (.txt / .csv)</label><input id="domainfile" type="file" accept=".txt,.csv,text/plain,text/csv">
<label for="domainlist">Or paste domains / URLs (one per line, max 50)</label><textarea id="domainlist" placeholder="https://site-one.example
https://site-two.example
example.org"></textarea><div class="small">One URL or hostname per line. CSV lines are treated as text and each line should contain one hostname/URL. Only listed targets are checked; redirects are not followed to other hosts.</div>
<div class="subbox"><label style="margin-top:0">Available access</label>
<label class="radio"><input type="radio" name="access" value="url_only" checked><span><b>Website URL only</b><br><span class="small">Unauthenticated black-box assessment</span></span></label>
<label class="radio"><input type="radio" name="access" value="authenticated"><span><b>Authenticated web application</b><br><span class="small">Use a temporary Authorization or Cookie header</span></span></label>
<label class="radio"><input type="radio" name="access" value="server_evidence"><span><b>URL + server-side evidence</b><br><span class="small">Compare an observed web runtime with pasted package/version evidence</span></span></label>
</div>
<div id="auth_fields" class="subbox hidden"><label>Authorization header value <span class="small">(optional)</span></label><input type="password" id="auth" placeholder="Bearer token…" autocomplete="off"><label>Cookie header value <span class="small">(optional)</span></label><input type="password" id="cookie" placeholder="session=value; …" autocomplete="off"><div class="small">Sent in memory for this scan only. Never included in scan results or reports. Avoid using a high-privilege account.</div></div>
<div id="server_fields" class="subbox hidden"><label>Server-side evidence</label><textarea id="evidence" placeholder="Example: PHP 8.4.26 (cli)\nOr package/version output from your server inventory"></textarea><div class="small">Paste only the minimum relevant version/package lines. Do not paste secrets, environment dumps, or credentials.</div></div>
<div class="step" style="margin-top:23px">Step 2 / Validation</div><h2>Choose validation depth</h2>
<label class="radio"><input type="radio" name="depth" value="passive" checked><span><b>Passive</b><br><span class="small">Headers, public fingerprints, normal page response, robots.txt and sitemap.xml</span></span></label>
<label class="radio" style="opacity:.6"><input type="radio" name="depth" value="safe_active" disabled><span><b>Safe active — planned, not enabled in v1</b><br><span class="small">Bounded non-destructive probes will require a later release.</span></span></label>
<div class="step" style="margin-top:23px">Step 3 / Modules</div><h2>Select discovery modules</h2>
<div id="modules">
<label class="check"><input type="checkbox" value="php" checked><span><b>PHP version/runtime fingerprinting</b><br><span class="small">Extract explicit version indicators; no banner means unknown.</span></span></label>
<label class="check"><input type="checkbox" value="cms" checked><span><b>CMS and framework detection</b><br><span class="small">Common markup, asset and cookie signatures.</span></span></label>
<label class="check"><input type="checkbox" value="headers" checked><span><b>HTTP headers, errors and response comparison</b><br><span class="small">Baseline GET vs HEAD; signatures without storing response bodies.</span></span></label>
<label class="check"><input type="checkbox" value="inventory" checked><span><b>Candidate endpoint and parameter inventory</b><br><span class="small">Extract links and form fields from markup; discovered items are not fetched or submitted.</span></span></label>
<label class="check"><input type="checkbox" value="report" checked><span><b>Evidence collection and report generation</b><br><span class="small">DOCX and PDF exports with evidence, limitations and source links.</span></span></label>
</div>
<div class="subbox"><label class="check" style="padding-left:0"><input type="checkbox" id="scope_confirm"><span><b>I have authorization to assess this target and agree to the defined passive request limits.</b></span></label></div>
<button class="btn" id="run" type="button">Run passive assessment</button><div class="section hidden" id="batchwrap"><h3>Batch summary</h3><div id="batchtable"></div></div><div class="small" style="margin-top:9px">v1 sends bounded normal GET/HEAD requests only. No form submission, parameter fuzzing, payloads, or exploit attempts.</div></section>
<section class="panel"><div class="step">Assessment dashboard</div><h2>Results & evidence</h2><div id="status" class="status">Configure the scope and run an assessment. No target requests have been sent yet.</div>
<div id="empty" class="empty"><div><span class="big">⌁</span><b>Ready when you are</b><div class="small" style="margin-top:7px">The tool separates version evidence from confirmed exploitability. It will never label a target exploitable from a banner alone.</div></div></div>
<div id="results" class="hidden"><div class="stats"><div class="stat"><strong id="reqs">0</strong><span>HTTP observations</span></div><div class="stat"><strong id="endpoints">0</strong><span>Candidate endpoints</span></div><div class="stat"><strong id="params">0</strong><span>Candidate parameters</span></div></div>
<div class="section"><h3>PHP version assessment</h3><div id="assessment" class="subbox"></div></div>
<div class="section"><h3>Per-CVE triage (same runtime evidence)</h3><div id="cvetable"></div></div>
<div class="section"><h3>Technology fingerprints</h3><div id="technology"></div></div>
<div class="section"><h3>HTTP observations</h3><div id="httpobs"></div></div>
<div class="section"><h3>Endpoint inventory</h3><div id="endpointtable"></div></div>
<div class="section"><h3>Candidate parameters</h3><div id="paramtable"></div></div>
<div class="section"><h3>Evidence notes</h3><ul id="notes"></ul></div><div class="actions"><a id="docx" href="#">Download DOCX</a><a id="pdf" href="#">Download PDF</a></div></div>
<div class="footer">PHP2Scope v0.3.0 · local-first · Results held in memory until restart · Reports may contain security-sensitive target metadata.</div>
</section></div></main>
<script>
const $=id=>document.getElementById(id);let busy=false;
function selected(name){return document.querySelector('input[name="'+name+'"]:checked')?.value||''}
function addCell(row, value){const td=document.createElement('td');td.textContent=(value===null||value===undefined||value==='')?'—':String(value);row.appendChild(td)}
function table(elId, headers, rows){const host=$(elId);host.replaceChildren();if(!rows||!rows.length){host.textContent='No items found.';return}const wrap=document.createElement('div');wrap.className='tablewrap';const t=document.createElement('table'),thead=document.createElement('thead'),tr=document.createElement('tr');headers.forEach(h=>{const th=document.createElement('th');th.textContent=h;tr.appendChild(th)});thead.appendChild(tr);t.appendChild(thead);const tb=document.createElement('tbody');rows.forEach(data=>{const r=document.createElement('tr');data.forEach(v=>addCell(r,v));tb.appendChild(r)});t.appendChild(tb);wrap.appendChild(t);host.appendChild(wrap)}
function setStatus(msg,cls=''){const el=$('status');el.className='status '+cls;el.textContent=msg}
document.querySelectorAll('input[name="access"]').forEach(el=>el.addEventListener('change',()=>{const v=selected('access');$('auth_fields').classList.toggle('hidden',v!=='authenticated');$('server_fields').classList.toggle('hidden',v!=='server_evidence')}));
$('domainfile').addEventListener('change',async()=>{const f=$('domainfile').files?.[0];if(f){$('domainlist').value=await f.text();}});
$('run').addEventListener('click',async()=>{if(busy)return;const raw=$('domainlist').value.trim();let targets=raw?raw.split(/[\r\n,;]+/).map(x=>x.trim().replace(/^['\"]|['\"]$/g,'')).filter(Boolean):[];if($('target').value.trim())targets.unshift($('target').value.trim());targets=[...new Set(targets)];if(!targets.length){setStatus('Enter a target URL or upload/paste a domain list.','error');return}if(targets.length>50){setStatus('Maximum 50 targets per batch.','error');return}if(!$('scope_confirm').checked){setStatus('Confirm authorization and request limits before running.','error');return}const access=selected('access');if(access==='authenticated'&&!$('auth').value.trim()&&!$('cookie').value.trim()){setStatus('Authenticated mode needs an Authorization or Cookie header value.','error');return}if(access==='server_evidence'&&!$('evidence').value.trim()){setStatus('Paste relevant server-side version/package evidence.','error');return}const modules=[...document.querySelectorAll('#modules input:checked')].map(x=>x.value);if(!modules.length){setStatus('Select at least one discovery module.','error');return}const authValue=$('auth').value,cookieValue=$('cookie').value;const rows=[];busy=true;$('run').disabled=true;$('batchwrap').classList.remove('hidden');setStatus(`Starting passive assessment for ${targets.length} authorized target(s)…`);try{for(let i=0;i<targets.length;i++){setStatus(`Assessing target ${i+1}/${targets.length}: ${targets[i]}`);const payload={target_url:targets[i],access_mode:access,validation_depth:'passive',modules,auth_header:authValue,cookie_header:cookieValue,server_evidence:$('evidence').value,scope_confirmed:true};try{const res=await fetch('/api/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});const data=await res.json();if(!res.ok)throw new Error(data.detail||'Scan failed');rows.push([data.target_url,data.version_assessment?.version||'Not observed',data.version_assessment?.label||'Inconclusive',data.version_assessment?.confidence||'none',`/api/report/${encodeURIComponent(data.scan_id)}/docx`,`/api/report/${encodeURIComponent(data.scan_id)}/pdf`]);if(i===targets.length-1)render(data)}catch(err){rows.push([targets[i],'—','Error: '+(err.message||'failed'),'—','',''])}table('batchtable',['Target','PHP version','Triage','Confidence','DOCX','PDF'],rows.map(r=>[r[0],r[1],r[2],r[3],r[4]?`Download: ${r[4]}`:'—',r[5]?`Download: ${r[5]}`:'—']))} $('auth').value='';$('cookie').value='';setStatus(`Batch complete: ${rows.length} target(s) processed. A result of “Not observed” is inconclusive, not proof of safety.`,'ok')}catch(e){setStatus(e.message||'Batch failed.','error')}finally{busy=false;$('run').disabled=false}});
function render(d){$('empty').classList.add('hidden');$('results').classList.remove('hidden');$('reqs').textContent=d.summary?.http_requests??0;$('endpoints').textContent=d.summary?.endpoint_count??d.endpoint_inventory?.length??0;$('params').textContent=d.summary?.parameter_count??d.parameter_inventory?.length??0;const a=d.version_assessment||{};$('assessment').replaceChildren();const pill=document.createElement('span');pill.className='pill '+(['potentially_affected','vendor_backport_review'].includes(a.status)?'warn':'');pill.textContent=a.label||'PHP version not determined';const p=document.createElement('p');p.appendChild(pill);$('assessment').appendChild(p);const line=document.createElement('p');line.textContent='Version: '+(a.version||'Not observed')+' · Source: '+(a.source||'unknown')+' · Confidence: '+(a.confidence||'none');$('assessment').appendChild(line);const detail=document.createElement('p');detail.textContent=a.detail||'No exact PHP version was determined.';$('assessment').appendChild(detail);const caution=document.createElement('p');caution.className='small';caution.textContent='This is version triage, not a remote exploitability result. Verify the web-serving runtime and vendor backports.';$('assessment').appendChild(caution);
table('cvetable',['CVE','Version-based result','Confidence'],(a.cves||['CVE-2026-109618','CVE-2026-109619']).map(c=>[c,a.label||'PHP version not determined',a.confidence||'none']));table('technology',['Technology','Confidence','Evidence'],(d.technology_findings||[]).map(x=>[x.technology,x.confidence,x.evidence]));table('httpobs',['Method','URL','Status','Elapsed ms','Allowlisted headers','Error / redirect'],(d.http_observations||[]).map(x=>[x.method,x.url,x.status_code,x.elapsed_ms,Object.entries(x.headers||{}).map(([k,v])=>k+': '+v).join('; '),x.error||x.redirect_location]));table('endpointtable',['Method','Path','Query names','Source'],(d.endpoint_inventory||[]).map(x=>[x.method,x.path,(x.query_parameter_names||[]).join(', '),x.source]));table('paramtable',['Path','Parameter','Location','Method','Tested'],(d.parameter_inventory||[]).map(x=>[x.path,x.parameter,x.location,x.method||'GET','No']));const ul=$('notes');ul.replaceChildren();(d.evidence_notes||[]).forEach(note=>{const li=document.createElement('li');li.textContent=note;ul.appendChild(li)});const showReports=(d.modules||[]).includes('report');document.querySelector('.actions').classList.toggle('hidden',!showReports);if(showReports){$('docx').href='/api/report/'+encodeURIComponent(d.scan_id)+'/docx';$('pdf').href='/api/report/'+encodeURIComponent(d.scan_id)+'/pdf';}}
</script></body></html>'''
