"""Offline integration tests; only contact an ephemeral local mock HTTP server."""
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

from php2scope.core import ScanConfig, run_assessment

class MockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/robots.txt":
            body = b"User-agent: *\nAllow: /\n"
            ctype = "text/plain"
        elif self.path == "/sitemap.xml":
            body = f"<urlset><url><loc>http://127.0.0.1:{self.server.server_port}/catalog?tag=blue</loc></url></urlset>".encode()
            ctype = "application/xml"
        else:
            body = (b'<!doctype html><html><head><title>Mock</title><meta name="generator" content="WordPress 6.9">'
                    b'</head><body><a href="/find?q=term">Find</a><form action="/upload" method="POST">'
                    b'<input name="avatar" type="file"></form></body></html>')
            ctype = "text/html"
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Powered-By", "PHP/8.4.26")
        self.send_header("Set-Cookie", "PHPSESSID=fake-secret-cookie; Path=/; HttpOnly")
        self.end_headers()
        self.wfile.write(body)
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("X-Powered-By", "PHP/8.4.26")
        self.end_headers()
    def log_message(self, *args):
        pass

class LocalIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), MockHandler)
        cls.thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join(timeout=2)
        cls.server.server_close()

    def test_passive_scan_inventory_and_no_secret_leak(self):
        result = run_assessment(ScanConfig(
            target_url=f"http://127.0.0.1:{self.server.server_port}/", access_mode="authenticated",
            auth_header="Bearer test-secret-token", cookie_header="session=also-secret",
            scope_confirmed=True,
        )).to_dict()
        self.assertEqual(result["version_assessment"]["status"], "potentially_affected")
        self.assertTrue(any(x["technology"] == "WordPress" for x in result["technology_findings"]))
        self.assertTrue(any(x.get("parameter") == "avatar" and x.get("tested") is False for x in result["parameter_inventory"]))
        serialized = str(result)
        self.assertNotIn("test-secret-token", serialized)
        self.assertNotIn("also-secret", serialized)
        self.assertNotIn("fake-secret-cookie", serialized)
        self.assertNotIn("body_text", serialized)
        self.assertTrue(all(o.get("method") in {"GET", "HEAD"} for o in result["http_observations"]))

    def test_inventory_module_controls_public_metadata_requests(self):
        result = run_assessment(ScanConfig(
            target_url=f"http://127.0.0.1:{self.server.server_port}/", modules=["php"], scope_confirmed=True,
        )).to_dict()
        self.assertEqual(result["summary"]["http_requests"], 1)
        self.assertEqual([o["url"] for o in result["http_observations"]], [f"http://127.0.0.1:{self.server.server_port}/"])

if __name__ == "__main__":
    unittest.main()
