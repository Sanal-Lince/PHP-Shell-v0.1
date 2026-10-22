from __future__ import annotations
import getpass
from pathlib import Path
from .core import ScanConfig, run_assessment, MODULE_LABELS
from .reports import export_docx, export_pdf


def _choice(prompt, options, default):
    print(prompt)
    for key, (label, _) in options.items(): print(f"  {key}. {label}")
    v = input(f"Choose [{default}]: ").strip() or default
    return options.get(v, options[default])[1]


def main():
    print("\nPHP2Scope v0.3.0 - passive PHP CVE assessment")
    print("This release performs bounded GET/HEAD fingerprinting only. It does not exploit vulnerabilities.\n")
    target = input("Target URL: ").strip()
    access = _choice("Available access:", {"1": ("Website URL only - black-box", "url_only"), "2": ("Authenticated web application", "authenticated"), "3": ("URL + server-side version/package evidence", "server_evidence")}, "1")
    depth = _choice("Validation depth (v1 supports passive only):", {"1": ("Passive - headers, fingerprints, public evidence", "passive"), "2": ("Safe active - not implemented in v1", "safe_active")}, "1")
    auth = cookie = evidence = ""
    if access == "authenticated":
        auth = getpass.getpass("Authorization header value (blank if unused): ").strip()
        cookie = getpass.getpass("Cookie header value (blank if unused): ").strip()
    elif access == "server_evidence":
        print("Paste one or more relevant version/package lines; finish with an empty line:")
        lines = []
        while True:
            line = input()
            if not line: break
            lines.append(line)
        evidence = "\n".join(lines)
    print("\nDiscovery modules - enter y/n (default y):")
    modules = []
    for key, label in MODULE_LABELS.items():
        if input(f"  {label}? [Y/n]: ").strip().lower() != "n": modules.append(key)
    print("\nAuthorization gate")
    print("Only assess systems where you have explicit authorization. This v1 will send a small number of ordinary GET/HEAD requests to the target and public metadata endpoints.")
    if input("Type AUTHORIZED to continue: ").strip() != "AUTHORIZED":
        print("Cancelled; no target requests were sent."); return
    try:
        cfg = ScanConfig(target_url=target, access_mode=access, validation_depth=depth, modules=modules,
                         auth_header=auth, cookie_header=cookie, server_evidence=evidence, scope_confirmed=True)
        result = run_assessment(cfg).to_dict()
    except Exception as e:
        print(f"Assessment did not run: {type(e).__name__}: {e}"); return
    print("\nAssessment summary")
    print(f"Target: {result['target_url']}")
    va = result.get("version_assessment", {})
    print(f"PHP version: {va.get('version') or 'not determined'}")
    print(f"Result: {va.get('label', 'not determined')} (confidence: {va.get('confidence', 'none')})")
    print(f"HTTP observations: {result.get('summary', {}).get('http_requests', 0)}")
    print(f"Candidate endpoints: {len(result.get('endpoint_inventory', []))}; parameters: {len(result.get('parameter_inventory', []))}")
    if "report" in result.get("modules", []):
        base = Path("php2scope_reports") / f"php2scope_{result['scan_id']}"
        fmt = _choice("Export report:", {"1": ("DOCX", "docx"), "2": ("PDF", "pdf"), "3": ("Both DOCX and PDF", "both"), "4": ("No report", "none")}, "3")
        if fmt in {"docx", "both"}: print(f"DOCX: {export_docx(result, base.with_suffix('.docx'))}")
        if fmt in {"pdf", "both"}: print(f"PDF:  {export_pdf(result, base.with_suffix('.pdf'))}")
    else:
        print("Reporting module disabled; no report generated.")
    print("\nReminder: version fingerprints and supplied package evidence do not prove exploitability. Verify the actual web-serving runtime and any vendor backports.")

if __name__ == "__main__": main()
