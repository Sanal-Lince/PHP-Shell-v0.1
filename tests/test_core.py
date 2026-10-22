import unittest
from php2scope.core import assess_php_version, extract_php_version, normalize_target, _extract_endpoint_inventory

class VersionAssessmentTests(unittest.TestCase):
    def test_vulnerable_84(self):
        self.assertEqual(assess_php_version("8.4.26", "server_evidence")["status"], "potentially_affected")
    def test_fixed_84(self):
        self.assertEqual(assess_php_version("8.4.27", "server_evidence")["status"], "upstream_fixed_version")
    def test_old_branch_requires_backport_review(self):
        self.assertEqual(assess_php_version("8.1.34", "server_evidence")["status"], "vendor_backport_review")
    def test_patch_unknown(self):
        self.assertEqual(assess_php_version("8.4", "server_evidence")["status"], "inconclusive")
    def test_banner_unknown(self):
        self.assertEqual(assess_php_version(None)["status"], "not_determined")
    def test_extract_package_string(self):
        self.assertEqual(extract_php_version("ea-php84 8.4.26-1.el9"), "8.4.26")
    def test_reject_credentials_in_url(self):
        with self.assertRaises(ValueError): normalize_target("https://user:pass@example.com")
    def test_reject_invalid_port(self):
        with self.assertRaises(ValueError): normalize_target("https://example.com:bogus/")
    def test_inventory_no_fetch(self):
        html = '<title>Test</title><a href="/search?q=hi">Search</a><form action="/upload" method="POST"><input name="avatar" type="file"></form>'
        ep, params, title = _extract_endpoint_inventory(html, "https://example.com/")
        self.assertTrue(any(x["path"] == "/upload" and x["method"] == "POST" for x in ep))
        self.assertTrue(any(x["parameter"] == "avatar" and x["tested"] is False for x in params))
        self.assertTrue(any(x["parameter"] == "q" for x in params))
        self.assertEqual(title, ["Test"])

if __name__ == "__main__": unittest.main()
