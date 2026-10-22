# Security notes

- Only scan assets you own or are explicitly authorized to assess.
- The web server binds to loopback (`127.0.0.1`) by default; do not bind it to a public interface without a security review.
- Do not paste credentials into the target URL. Prefer a low-privilege, short-lived testing account. Auth headers are request-only and are not included in the report, but avoid using production admin tokens.
- Result bodies are not persisted. Reports may still include target paths, headers, fingerprinting results, and endpoint names; handle and store them as security-sensitive evidence.
- Requests verify TLS certificates, do not follow redirects, cap response bodies at 1 MB and use request timeouts. The scan sends one baseline GET, GET requests to `/robots.txt` and `/sitemap.xml`, and one HEAD request when the corresponding modules require it. Discovered links/forms are inventory-only and are not fetched/submitted.
- Do not use version assessment as a substitute for patch verification. Confirm the exact package build and vendor backport status.
