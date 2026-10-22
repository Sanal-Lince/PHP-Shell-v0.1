# PHP2Scope v0.3

PHP2Scope is a local-first, wizard-driven **passive** black-box assessment prototype for PHP runtime exposure to CVE-2026-109618 and CVE-2026-109619. It provides both a browser UI and a terminal wizard using the same Python engine, and exports DOCX/PDF evidence reports.

> **Safety and scope:** v0.3 performs bounded, normal HTTP GET/HEAD requests only. It does not submit forms, fuzz parameters, send exploit payloads, try code execution, or automatically fetch discovered links. Use it only on systems where you have authorization. The browser UI binds to `127.0.0.1` only.

## Included features

- Access modes: website URL only, authenticated web application (optional Authorization/Cookie header), or URL plus server-side version/package evidence.
- Validation-depth selector: Passive is implemented. Safe active is shown as a future mode and is not enabled in this v1 build.
- Modules: PHP version/runtime fingerprinting; CMS/framework clues; HTTP headers, error signatures and GET-vs-HEAD comparison; candidate endpoint/parameter inventory; evidence and report export. The inventory module is what enables the fixed `robots.txt` and `sitemap.xml` requests.
- Conservative version triage for both CVEs; low-confidence HTTP banners are differentiated from operator-supplied server evidence.
- DOCX and PDF reports include findings, source URLs, limitations and remediation guidance.
- Authentication headers are never written to results or reports. Response bodies are used transiently for parsing and are not placed in the result object. Scan result objects live in memory in the web app and are cleared on restart/cache rotation. Generated report files persist under `~/.local/share/php2scope/reports/`; treat them as sensitive and delete them when no longer needed.
- Unit tests for version rules, version parsing, URL credential rejection and inventory extraction.

## Requirements

- Python 3.10+
- Network access to the authorized target from the scanning machine
- Python packages in `requirements.txt`

## Install on Garuda / Arch / Kali Linux

Use a virtual environment to avoid modifying the distro-managed Python installation.

```bash
cd PHP2Scope_v0.1
python -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt
```

On Fish shell, to activate the environment in the current shell use:

```fish
source .venv/bin/activate.fish
```

Activation is optional; the commands below use `.venv/bin/python` directly.

## Start the browser wizard

```bash
.venv/bin/python run_web.py
```

Open `http://127.0.0.1:8765` in your browser. Do not expose the development server to a public network. The UI requires an explicit authorization checkbox before it scans.

## Start the terminal wizard

```bash
.venv/bin/python run_cli.py
```

The CLI asks for the target, access type, enabled discovery modules and explicit authorization. Auth header values are entered with hidden terminal input. Reports are saved under `php2scope_reports/` in the current working directory.

## Run tests

```bash
.venv/bin/python -m unittest discover -s tests -v
```

## How version results are interpreted

- PHP 8.5 before 8.5.12, 8.4 before 8.4.27, 8.3 before 8.3.36, and 8.2 before 8.2.35 are classified as **potentially affected upstream versions**.
- Versions at/above the corresponding fixed release are reported as **at or above upstream fixed version**.
- PHP 8.1 and older get a vendor/backport review result, not a categorical statement based on a banner alone. PHP's advisory notes minimal source backports for PHP 7.4, 8.0 and 8.1, and vendors may distribute backported fixes.
- A major/minor version without a patch number is inconclusive.
- A PHP-looking header is low-confidence evidence because headers can be hidden, rewritten, stale or unrelated to the web-serving runtime. A supplied `php -v` may describe CLI PHP rather than PHP-FPM/mod_php serving the target.

If you deselect the reporting module, that scan will not offer report downloads. The built-in advisory matrix was verified on **22 October 2026** against these sources:

1. PHP Security Advisory: https://www.php.net/archive/2026.php
2. Google Cloud: https://cloud.google.com/blog/products/identity-security/responding-to-core-php-vulnerabilities-cve-2026-109618-cve-2026-109619
3. Canadian Centre for Cyber Security: https://www.cyber.gc.ca/en/alerts-advisories/al26-026-critical-vulnerabilities-impacting-php-cve-2026-109618-cve-2026-109619

## Current limitations

- Passive-only in v1; safe active validation is a planned stage, not implemented.
- No exploitability proof and no arbitrary parameter tests.
- Does not follow redirects automatically; a redirect to a different host is recorded, not followed.
- Inventory is based on the baseline HTML and public sitemap information; candidate endpoints and parameters are not requested or submitted.
- CMS/framework detection is heuristic and can produce false positives/negatives.
- A web-facing PHP version may not be discoverable from HTTP. Use authenticated asset inventory or server-side package evidence where available.
- Vendor package names and backport status require vendor-specific checks; compare distribution security advisories rather than relying only on an upstream version string.

## Project structure

```text
php2scope/
├── php2scope/
│   ├── core.py          # shared HTTP fingerprinting, inventory and CVE version logic
│   ├── reports.py       # DOCX/PDF exports
│   ├── cli.py           # interactive terminal wizard
│   └── webapp.py        # local browser wizard and report endpoints
├── tests/
├── run_web.py
├── run_cli.py
└── requirements.txt
```
