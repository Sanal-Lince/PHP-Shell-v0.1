"""Shared passive assessment engine for PHP2Scope.

This v1 sends only bounded, normal HTTP GET/HEAD requests. It does not submit forms,
mutate state, fuzz parameters, send exploit payloads, or attempt code execution.
"""
from __future__ import annotations

import re
import time
import uuid
import socket
import ipaddress
from dataclasses import dataclass, asdict, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from typing import Any, Optional
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl

import requests

ADVISORY_PHP = "https://www.php.net/archive/2026.php"
ADVISORY_GOOGLE = "https://cloud.google.com/blog/products/identity-security/responding-to-core-php-vulnerabilities-cve-2026-109618-cve-2026-109619"
ADVISORY_CANADA = "https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619"
CVE_IDS = ["CVE-2026-109618", "CVE-2026-109619"]
FIXED = {(8, 5): (8, 5, 12), (8, 4): (8, 4, 27), (8, 3): (8, 3, 36), (8, 2): (8, 2, 35)}
MAX_RESPONSE_BYTES = 1_000_000
MAX_DISCOVERED_ITEMS = 250
USER_AGENT = "PHP2Scope/0.1 (passive-assessment; contact project owner before use)"

MODULE_LABELS = {
    "php": "PHP version and runtime fingerprinting",
    "cms": "CMS and framework detection",
    "headers": "HTTP headers, errors and response comparison",
    "inventory": "Candidate endpoint and parameter inventory",
    "report": "Evidence collection and report generation",
}

@dataclass
class ScanConfig:
    target_url: str
    access_mode: str = "url_only"  # url_only | authenticated | server_evidence
    validation_depth: str = "passive"  # v1 only supports passive
    modules: list[str] = field(default_factory=lambda: list(MODULE_LABELS))
    auth_header: str = ""   # e.g. "Bearer ..."; never persisted in report
    cookie_header: str = "" # never persisted in report
    server_evidence: str = "" # user-supplied evidence, reduced to extracted version in report
    scope_confirmed: bool = False
    timeout_seconds: int = 8

@dataclass
class ScanResult:
    scan_id: str
    created_utc: str
    target_url: str
    access_mode: str
    validation_depth: str
    modules: list[str]
    summary: dict[str, Any] = field(default_factory=dict)
    http_observations: list[dict[str, Any]] = field(default_factory=list)
    technology_findings: list[dict[str, Any]] = field(default_factory=list)
    version_assessment: dict[str, Any] = field(default_factory=dict)
    endpoint_inventory: list[dict[str, Any]] = field(default_factory=list)
    parameter_inventory: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    evidence_notes: list[str] = field(default_factory=list)
    advisory_sources: list[str] = field(default_factory=lambda: [ADVISORY_PHP, ADVISORY_GOOGLE, ADVISORY_CANADA])

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_target(raw: str) -> str:
    raw = (raw or "").strip()
    if not raw:
        raise ValueError("Target URL is required.")
    parsed = urlparse(raw if "://" in raw else "https://" + raw)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only http:// and https:// targets are supported.")
    if not parsed.hostname:
        raise ValueError("Enter a valid target hostname.")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("Target URL contains an invalid port.") from exc
    if parsed.username or parsed.password:
        raise ValueError("Do not put credentials in the URL. Use the authentication fields instead.")
    if any(c in (parsed.hostname or "") for c in "\r\n\t "):
        raise ValueError("Invalid hostname.")
    # Query and fragment do not belong in the base scope URL.
    path = parsed.path or "/"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", "", ""))


def origin_of(url: str) -> tuple[str, str, int]:
    p = urlparse(url)
    port = p.port or (443 if p.scheme == "https" else 80)
    return p.scheme, (p.hostname or "").lower(), port


def _version_tuple(v: str) -> Optional[tuple[int, int, int]]:
    m = re.search(r"(?<!\d)(\d+)\.(\d+)(?:\.(\d+))?", v or "")
    if not m:
        return None
    # A two-component version is intentionally not considered precise enough for a finding.
    if m.group(3) is None:
        return (int(m.group(1)), int(m.group(2)), -1)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


def extract_php_version(text: str) -> Optional[str]:
    """Extract a PHP version from common banners/package strings without guessing."""
    if not text:
        return None
    patterns = [
        r"(?i)PHP\s*/?\s*(\d+\.\d+\.\d+(?:[-+~][A-Za-z0-9.+~_-]+)?)",
        r"(?i)php(?:\d{0,2})?[-:]?\s*(\d+\.\d+\.\d+)(?:[-+~][A-Za-z0-9.+~_-]+)?",
        r"(?i)php\s+(\d+\.\d+)(?:\b|$)",
    ]
    for pat in patterns:
        m = re.search(pat, text)
        if m:
            return m.group(1)
    return None


def assess_php_version(version: Optional[str], source: str = "unknown") -> dict[str, Any]:
    """Map an observed version to conservative upstream guidance for both CVEs."""
    base = {
        "version": version,
        "source": source,
        "cves": CVE_IDS,
        "fixed_versions": {f"{major}.{minor}": ".".join(map(str, fix)) for (major, minor), fix in FIXED.items()},
        "confidence": "low" if source == "http_fingerprint" else ("medium" if source == "server_evidence" else "none"),
    }
    parsed = _version_tuple(version or "")
    if not parsed:
        base.update({"status": "not_determined", "label": "PHP version not determined", "detail": "No explicit PHP patch version was observed. Absence of a banner is not evidence that PHP is absent or patched."})
        return base
    major, minor, patch = parsed
    base["version"] = version
    if patch < 0:
        base.update({"status": "inconclusive", "label": "Patch version unknown", "detail": f"Only PHP {major}.{minor} was available. Obtain the exact runtime/package build and check for vendor backports."})
        return base
    if (major, minor) in FIXED:
        fixed = FIXED[(major, minor)]
        if (major, minor, patch) < fixed:
            base.update({
                "status": "potentially_affected",
                "label": "Potentially affected upstream version",
                "detail": f"PHP {version} is older than the upstream fixed release {'.'.join(map(str, fixed))} for this branch. Verify the exact runtime and distribution/vendor backport status; this version observation does not prove remote exploitability.",
                "fixed_version": ".".join(map(str, fixed)),
            })
        else:
            base.update({
                "status": "upstream_fixed_version",
                "label": "At or above upstream fixed version",
                "detail": f"PHP {version} is at or above upstream fixed release {'.'.join(map(str, fixed))} for this branch. Confirm the version belongs to the actual web-serving runtime and is not only a CLI package.",
                "fixed_version": ".".join(map(str, fixed)),
            })
        return base
    if (major, minor) <= (8, 1):
        base.update({
            "status": "vendor_backport_review",
            "label": "Vendor/backport review required",
            "detail": f"PHP {version} is on an older upstream branch. The PHP advisory notes no ordinary upstream security updates for PHP 8.1 and older, while minimal source backports were made for PHP 7.4, 8.0 and 8.1; vendors may also backport fixes. Version alone cannot confirm the package's patch state. Verify the vendor advisory/package build or upgrade to a supported patched branch.",
        })
        return base
    base.update({
        "status": "unknown_branch",
        "label": "Branch not covered by built-in matrix",
        "detail": f"PHP {version} is not covered by the built-in fixed-release matrix. Verify the official PHP advisory and vendor package changelog before drawing a conclusion.",
    })
    return base


class _PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.in_title = False
        self.meta: list[dict[str, str]] = []
        self.links: list[dict[str, str]] = []
        self.forms: list[dict[str, Any]] = []
        self._form: Optional[dict[str, Any]] = None
        self._in_text = False

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag.lower() == "title": self.in_title = True
        if tag.lower() == "meta": self.meta.append({k.lower(): v or "" for k, v in a.items()})
        if tag.lower() in {"a", "link", "script", "iframe"}:
            key = "href" if tag.lower() in {"a", "link"} else "src"
            if a.get(key): self.links.append({"tag": tag.lower(), "url": a[key], "rel": a.get("rel", ""), "text": ""})
        if tag.lower() == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "GET").upper(), "fields": []}
            self.forms.append(self._form)
        if tag.lower() in {"input", "select", "textarea", "button"} and self._form is not None:
            name = a.get("name")
            if name:
                self._form["fields"].append({"name": name[:100], "type": str(a.get("type") or tag.lower())[:40]})

    def handle_endtag(self, tag):
        if tag.lower() == "title": self.in_title = False
        if tag.lower() == "form": self._form = None

    def handle_data(self, data):
        if self.in_title and data.strip(): self.title_parts.append(data.strip())


def _response_excerpt(content: bytes, encoding: Optional[str]) -> str:
    try:
        return content.decode(encoding or "utf-8", errors="replace")
    except Exception:
        return content.decode("utf-8", errors="replace")


def _safe_http(session: requests.Session, url: str, method: str, timeout: int) -> dict[str, Any]:
    """Single bounded request, no redirect following, verify TLS, cap body to 1 MB."""
    started = time.monotonic()
    obs: dict[str, Any] = {"url": url, "method": method, "requested_at_utc": datetime.now(timezone.utc).isoformat(), "status_code": None}
    resp = None
    try:
        resp = session.request(method, url, timeout=(min(timeout, 4), timeout), allow_redirects=False,
                               verify=True, stream=(method.upper() != "HEAD"), headers={"Accept": "text/html,application/xhtml+xml,application/xml,text/plain,*/*;q=0.5"})
        body = b""
        truncated = False
        if method.upper() != "HEAD":
            try:
                for chunk in resp.iter_content(chunk_size=16384):
                    if not chunk: continue
                    remaining = MAX_RESPONSE_BYTES - len(body)
                    if len(chunk) > remaining:
                        body += chunk[:remaining]
                        truncated = True
                        break
                    body += chunk
                    if len(body) >= MAX_RESPONSE_BYTES:
                        truncated = True
                        break
            except requests.RequestException as e:
                obs["body_read_error"] = str(e)[:200]
        # Retain an explicit allowlist only; custom headers can contain secrets.
        allowed_headers = {"server", "x-powered-by", "content-type", "content-security-policy", "strict-transport-security",
                           "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy",
                           "cache-control", "content-length", "date", "allow", "vary", "via", "x-cache",
                           "access-control-allow-origin", "access-control-allow-credentials"}
        headers = {k: v[:500] for k, v in resp.headers.items() if k.lower() in allowed_headers}
        cookie_names = []
        try:
            for cookie_line in resp.raw.headers.getlist("Set-Cookie"):
                cookie_name = str(cookie_line).split("=", 1)[0].strip()
                if cookie_name and re.fullmatch(r"[A-Za-z0-9_!#$%&'*+.^`|~-]{1,100}", cookie_name):
                    cookie_names.append(cookie_name)
        except Exception:
            pass
        obs.update({
            "status_code": resp.status_code,
            "cookie_names": sorted(set(cookie_names)),
            "reason": (resp.reason or "")[:100],
            "headers": headers,
            "content_type": resp.headers.get("Content-Type", "")[:200],
            "content_length_observed": len(body),
            "body_truncated": truncated,
            "elapsed_ms": round((time.monotonic() - started) * 1000),
            "redirect_location": resp.headers.get("Location", "")[:500],
            "body_text": _response_excerpt(body, resp.encoding) if body else "",
        })
        return obs
    except requests.RequestException as e:
        obs.update({"error": f"{type(e).__name__}: {str(e)[:300]}", "elapsed_ms": round((time.monotonic() - started) * 1000), "headers": {}, "body_text": ""})
        return obs
    finally:
        if resp is not None:
            resp.close()


def _is_same_origin(candidate: str, base_origin: tuple[str, str, int]) -> bool:
    try:
        return origin_of(candidate) == base_origin
    except ValueError:
        return False


def _endpoint_record(url: str, method: str, source: str, params: list[str] | None = None) -> dict[str, Any]:
    p = urlparse(url)
    return {"method": method, "path": p.path or "/", "query_parameter_names": sorted(set(params or [])), "source": source}


def _php_indicators(observations: list[dict[str, Any]], html_text: str) -> tuple[list[dict[str, Any]], Optional[str], list[str]]:
    findings: list[dict[str, Any]] = []
    clues: list[str] = []
    version = None
    all_text = "\n".join([str(o.get("headers", {}).get("X-Powered-By", "")) + "\n" + str(o.get("headers", {}).get("Server", "")) for o in observations])
    if re.search(r"(?i)php", all_text):
        clues.append("HTTP response header contains a PHP-related token")
        version = extract_php_version(all_text)
        findings.append({"technology": "PHP", "evidence": "PHP-related HTTP response header", "confidence": "low", "version": version})
    cookie_names = {n.lower() for o in observations for n in o.get("cookie_names", [])}
    if "phpsessid" in cookie_names:
        clues.append("PHPSESSID cookie name observed")
        if not any(f["technology"] == "PHP" for f in findings):
            findings.append({"technology": "PHP", "evidence": "PHPSESSID cookie name", "confidence": "low", "version": None})
    return findings, version, clues


def _cms_framework_findings(html_text: str, observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    checks = [
        (r"(?i)wp-content/|wp-includes/|name=['\"]generator['\"][^>]+WordPress", "WordPress", "WordPress path/generator signature"),
        (r"(?i)/sites/(?:default|all)/files/|drupalSettings|/core/misc/drupal\.js", "Drupal", "Drupal asset/config signature"),
        (r"(?i)/media/system/js/|option=com_|content=\"Joomla!", "Joomla", "Joomla asset/URL signature"),
        (r"(?i)name=['\"]generator['\"][^>]+TYPO3|typo3conf/", "TYPO3", "TYPO3 generator/path signature"),
        (r"(?i)__NEXT_DATA__|/_next/static/", "Next.js", "Next.js page/runtime signature"),
        (r"(?i)name=['\"]generator['\"][^>]+Django|csrfmiddlewaretoken", "Django", "Django-related meta/form token"),
    ]
    for pattern, name, evidence in checks:
        if re.search(pattern, html_text or ""):
            findings.append({"technology": name, "evidence": evidence, "confidence": "low-to-medium"})
    cookie_names = {n.lower() for o in observations for n in o.get("cookie_names", [])}
    for cookie, name, evidence in [
        ("laravel_session", "Laravel", "Laravel session cookie name"),
        ("xsrf-token", "Laravel", "XSRF-TOKEN cookie name; framework association is heuristic"),
        ("ci_session", "CodeIgniter", "CodeIgniter session cookie name"),
        ("symfony", "Symfony", "Symfony-related cookie name"),
    ]:
        if cookie in cookie_names:
            findings.append({"technology": name, "evidence": evidence, "confidence": "low"})
    return findings

def _extract_endpoint_inventory(html_text: str, base_url: str, include_inventory: bool = True) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    if not include_inventory or not html_text:
        return [], [], []
    parser = _PageParser()
    try: parser.feed(html_text[:MAX_RESPONSE_BYTES].replace("\x00", ""))
    except Exception: pass
    origin = origin_of(base_url)
    endpoints: dict[tuple[str, str], dict[str, Any]] = {}
    parameters: dict[tuple[str, str, str], dict[str, Any]] = {}
    # Endpoint and query parameter inventory is derived from markup only. We do not fetch these links.
    for item in parser.links[:MAX_DISCOVERED_ITEMS]:
        raw = (item.get("url") or "").strip()
        if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            continue
        abs_url = urljoin(base_url, raw)
        p = urlparse(abs_url)
        if p.scheme not in {"http", "https"} or not _is_same_origin(abs_url, origin):
            continue
        params = [k for k, _ in parse_qsl(p.query, keep_blank_values=True)]
        rec = _endpoint_record(abs_url, "GET", f"HTML {item.get('tag')} link", params)
        key = (rec["method"], rec["path"])
        endpoints[key] = rec
        for name in params:
            parameters[(rec["path"], name, "URL query") ] = {"path": rec["path"], "parameter": name, "location": "URL query", "source": rec["source"], "tested": False}
    for form in parser.forms[:100]:
        action = urljoin(base_url, form.get("action") or base_url)
        p = urlparse(action)
        if p.scheme not in {"http", "https"} or not _is_same_origin(action, origin):
            continue
        path = p.path or "/"
        method = (form.get("method") or "GET").upper()
        # Record form methods/fields, but never submit the form.
        rec = {"method": method, "path": path, "query_parameter_names": [], "source": "HTML form (not submitted)"}
        endpoints[(method, path)] = rec
        for field in form.get("fields", [])[:100]:
            name = field.get("name", "")
            parameters[(path, name, "form field")] = {"path": path, "parameter": name, "field_type": field.get("type", "unknown"), "location": "form field", "method": method, "source": "HTML form (not submitted)", "tested": False}
    # Include homepage route regardless of markup.
    bp = urlparse(base_url)
    endpoints.setdefault(("GET", bp.path or "/"), {"method": "GET", "path": bp.path or "/", "query_parameter_names": [], "source": "scan target"})
    return list(endpoints.values())[:MAX_DISCOVERED_ITEMS], list(parameters.values())[:MAX_DISCOVERED_ITEMS], parser.title_parts


def _analyze_http(observations: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[str]]:
    notes = []
    findings = []
    for obs in observations:
        if obs.get("error"):
            notes.append(f"{obs['method']} {obs['url']}: {obs['error']}")
            continue
        status = obs.get("status_code")
        if status and status >= 500:
            findings.append({"type": "server_error", "severity": "informational", "url": obs["url"], "status_code": status, "evidence": f"HTTP {status} response; body content not copied into report."})
        body = obs.get("body_text", "")
        for pattern, label in [
            (r"(?i)Fatal error:|Uncaught (?:Exception|Error)|Parse error:", "PHP fatal/uncaught error signature"),
            (r"(?i)Stack trace:", "stack trace signature"),
            (r"(?i)Warning: .* on line \d+", "runtime warning with source line"),
            (r"(?i)SQLSTATE\[[A-Z0-9]+\]|You have an error in your SQL syntax", "database error signature"),
        ]:
            if body and re.search(pattern, body):
                findings.append({"type": "error_disclosure", "severity": "needs_review", "url": obs["url"], "status_code": status, "evidence": label + " present; response body intentionally omitted."})
    # Compare the baseline GET and HEAD observations, when available.
    get_obs = next((o for o in observations if o.get("method") == "GET" and o.get("url", "").split("?")[0].rstrip("/") == observations[0].get("url", "").split("?")[0].rstrip("/")), None) if observations else None
    head_obs = next((o for o in observations if o.get("method") == "HEAD"), None)
    if get_obs and head_obs:
        findings.append({
            "type": "response_comparison", "severity": "informational", "url": get_obs.get("url"),
            "evidence": f"GET status={get_obs.get('status_code')}, HEAD status={head_obs.get('status_code')}; GET body bytes observed={get_obs.get('content_length_observed', 0)}. HEAD may be unsupported or intentionally differ; this is not a vulnerability by itself."
        })
    return findings, notes


def _extract_sitemap_urls(text: str, base_url: str) -> list[str]:
    urls = []
    for m in re.finditer(r"(?is)<loc>\s*(.*?)\s*</loc>", text or ""):
        u = m.group(1).strip()
        if u and _is_same_origin(u, origin_of(base_url)):
            urls.append(urlunparse((*urlparse(u)[:4], "", "")))
    return list(dict.fromkeys(urls))[:100]


def run_assessment(config: ScanConfig) -> ScanResult:
    if not config.scope_confirmed:
        raise ValueError("Scope confirmation is required before a scan can run.")
    if config.validation_depth != "passive":
        raise ValueError("PHP2Scope v1 supports Passive mode only. Safe active validation is shown in the wizard roadmap but is not implemented in this build.")
    target = normalize_target(config.target_url)
    if config.access_mode not in {"url_only", "authenticated", "server_evidence"}:
        raise ValueError("Unknown access mode.")
    modules = [m for m in config.modules if m in MODULE_LABELS]
    if not modules:
        raise ValueError("Select at least one discovery module.")
    result = ScanResult(
        scan_id=uuid.uuid4().hex[:12], created_utc=datetime.now(timezone.utc).isoformat(),
        target_url=target, access_mode=config.access_mode, validation_depth="passive", modules=modules,
    )
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,application/xml,text/plain,*/*;q=0.5"})
    if config.access_mode == "authenticated":
        # These are in-memory request headers only; never copy them to result or report.
        if config.auth_header.strip(): session.headers["Authorization"] = config.auth_header.strip()
        if config.cookie_header.strip(): session.headers["Cookie"] = config.cookie_header.strip()
    try:
        # Baseline GET is the only arbitrary page request in v1. No discovered links are fetched.
        homepage = _safe_http(session, target, "GET", config.timeout_seconds)
        result.http_observations.append({k: v for k, v in homepage.items() if k != "body_text"})
        if homepage.get("error"):
            result.errors.append(f"Baseline GET failed: {homepage['error']}")
        body = homepage.get("body_text", "")
        base_origin = origin_of(target)
        # Inventory module requests only two fixed public metadata paths; discovered URLs are never fetched.
        if "inventory" in modules:
            for path in ("/robots.txt", "/sitemap.xml"):
                # Preserve the target origin's exact scheme, hostname and port.
                bp = urlparse(target)
                public_url = urlunparse((bp.scheme, bp.netloc, path, "", "", ""))
                time.sleep(0.15)
                doc = _safe_http(session, public_url, "GET", config.timeout_seconds)
                result.http_observations.append({k: v for k, v in doc.items() if k != "body_text"})
                if doc.get("error"):
                    # Errors on these optional public documents are not scan failures.
                    continue
                if path == "/robots.txt" and doc.get("status_code") == 200:
                    directives = [ln.strip() for ln in doc.get("body_text", "").splitlines() if re.match(r"(?i)^(?:Disallow|Allow|Sitemap):", ln.strip())]
                    result.evidence_notes.append(f"robots.txt directives observed: {len(directives)}; raw file contents not copied into report.")
                    for line in directives[:100]:
                        if line.lower().startswith("sitemap:"):
                            u = line.split(":", 1)[1].strip()
                            if u and _is_same_origin(u, base_origin):
                                result.evidence_notes.append("Same-origin sitemap reference found in robots.txt.")
                if path == "/sitemap.xml" and doc.get("status_code") == 200:
                    sitemap_urls = _extract_sitemap_urls(doc.get("body_text", ""), target)
                    result.evidence_notes.append(f"Same-origin sitemap URLs discovered: {len(sitemap_urls)}; URLs were inventoried, not requested.")
                    for u in sitemap_urls[:100]:
                        p = urlparse(u)
                        rec = _endpoint_record(u, "GET", "sitemap.xml (not fetched)", [k for k, _ in parse_qsl(p.query, keep_blank_values=True)])
                        if not any(e["method"] == rec["method"] and e["path"] == rec["path"] for e in result.endpoint_inventory):
                            result.endpoint_inventory.append(rec)
        # HEAD to baseline URL is bounded and safe; it is used only for a metadata comparison.
        if "headers" in modules:
            time.sleep(0.15)
            head = _safe_http(session, target, "HEAD", config.timeout_seconds)
            result.http_observations.append({k: v for k, v in head.items() if k != "body_text"})
            findings, notes = _analyze_http([dict(homepage, url=target), head])
            result.evidence_notes.extend(notes)
        else:
            findings, notes = [], []
        if "php" in modules:
            tech, header_version, clues = _php_indicators([homepage], body)
            result.technology_findings.extend(tech)
            result.evidence_notes.extend(clues)
            observed_version = header_version
            version_source = "http_fingerprint" if header_version else "unknown"
            # HTML metadata generators can mention PHP but do not prove runtime version.
            if observed_version:
                result.version_assessment = assess_php_version(observed_version, version_source)
        if "cms" in modules:
            for f in _cms_framework_findings(body, [homepage]):
                if f not in result.technology_findings:
                    result.technology_findings.append(f)
            parser = _PageParser()
            try: parser.feed(body[:MAX_RESPONSE_BYTES])
            except Exception: pass
            for meta in parser.meta:
                if meta.get("name", "").lower() == "generator" and meta.get("content"):
                    content = meta["content"][:160]
                    result.technology_findings.append({"technology": "Generator metadata", "evidence": f"meta generator={content}", "confidence": "low"})
        if "headers" in modules:
            result.evidence_notes.extend([f"HTTP finding: {f['evidence']}" for f in findings])
            if homepage.get("headers"):
                safe_names = ("server", "x-powered-by", "content-type", "content-security-policy", "strict-transport-security", "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy", "cache-control")
                observed_names = {k.lower() for k in homepage["headers"]}
                missing = [n for n in safe_names if n not in observed_names and n in {"content-security-policy", "strict-transport-security", "x-content-type-options", "x-frame-options", "referrer-policy"}]
                result.evidence_notes.append("Common hardening headers not observed on baseline response: " + (", ".join(missing) if missing else "none of the checked headers were missing"))
        if "inventory" in modules:
            eps, pars, title_parts = _extract_endpoint_inventory(body, target)
            result.endpoint_inventory.extend(eps)
            result.parameter_inventory.extend(pars)
            result.summary["page_title"] = " ".join(title_parts)[:200] or "Not observed"
        # If manually supplied evidence exists, it takes precedence over a header-only guess for version assessment.
        if config.server_evidence.strip():
            version = extract_php_version(config.server_evidence)
            result.version_assessment = assess_php_version(version, "server_evidence")
            if not version:
                result.evidence_notes.append("Server-side evidence was supplied, but no explicit PHP version could be extracted. Review evidence manually; secrets/raw pasted content are not stored in this report.")
            else:
                result.evidence_notes.append(f"Server-side evidence supplied by operator; extracted PHP version {version}. Verify that this package matches the web-serving runtime and that any vendor backport applies.")
        elif "php" in modules and not result.version_assessment:
            result.version_assessment = assess_php_version(None, "unknown")
        result.summary.update({
            "http_requests": len(result.http_observations),
            "successful_http_responses": sum(1 for o in result.http_observations if o.get("status_code") is not None),
            "technology_count": len(result.technology_findings),
            "endpoint_count": len(result.endpoint_inventory),
            "parameter_count": len(result.parameter_inventory),
            "response_errors": sum(1 for o in result.http_observations if o.get("error")),
            "assessment_limit": "Passive GET/HEAD only; no forms submitted, no parameter payloads, no exploitability test.",
        })
        # Ensure no credentials leak into any result field by construction.
        return result
    finally:
        session.close()
