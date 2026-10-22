import gzip
import shutil
import tempfile
import unittest
from pathlib import Path

import helpers
from checks import logs

POSITIVE = {
    "DR-001": '1.2.3.4 - - [x] "POST /a.php HTTP/1.1" 500 0 "-" "-"',
    "DR-002": '1.2.3.4 - - [x] "POST /a HTTP/1.1" 200 1 "multipart/form-data; boundary=z"',
    "DR-003": "PHP Fatal error:  Allowed memory size of 134217728 bytes exhausted (tried to allocate 1 bytes)",
    "DR-004": "PHP Fatal error:  Out of memory (allocated 2097152) (tried to allocate 1 bytes)",
    "DR-005": "WARNING: [pool www] child 99 exited on signal 11 (SIGSEGV - core dumped) after 1 seconds from start",
    "DR-006": "[core:notice] [pid 1] AH00052: child pid 99 exit signal Segmentation fault (11)",
    "DR-007": "kernel: php-fpm8.4[99]: segfault at 0 ip 0 sp 0 error 4",
    "DR-008": "PHP Fatal error:  Maximum execution time of 30 seconds exceeded in /a.php on line 1",
    "DR-009": "body=...PHP_SESSION_UPLOAD_PROGRESS=x",
    "DR-010": "PHP Deprecated:  Directive 'x' is deprecated in Unknown on line 0",
    "DR-011": '1.2.3.4 - - [x] "GET /wp-content/uploads/a.php HTTP/1.1" 200 1 "-" "-"',
    "DR-012": '1.2.3.4 - - [x] "GET /?file=/usr/local/lib/php/pearcmd.php HTTP/1.1" 200 1',
}
NEGATIVE = {
    "DR-001": '1.2.3.4 - - [x] "GET /a.php HTTP/1.1" 500 0',
    "DR-005": "WARNING: [pool www] child 99 exited with code 0 after 1 seconds from start",
    "DR-006": "AH00052: child pid 99 exit signal Terminated (15)",
    "DR-007": "kernel: bash[1]: segfault at 0",
    "DR-011": '1.2.3.4 - - [x] "GET /wp-content/uploads/a.jpg HTTP/1.1" 200 1',
    "DR-011b": '1.2.3.4 - - [x] "GET /wp-content/uploads/a.php HTTP/1.1" 404 1',
}


class Rules(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules = {r["id"]: r for r in helpers.settings()["_rules"]["rules"]}

    def test_every_rule_has_positive_case(self):
        self.assertEqual(set(POSITIVE), set(self.rules))

    def test_positive(self):
        for rid, line in POSITIVE.items():
            with self.subTest(rid=rid):
                self.assertTrue(self.rules[rid]["_re"].search(line))

    def test_negative(self):
        for rid, line in NEGATIVE.items():
            with self.subTest(rid=rid):
                self.assertFalse(self.rules[rid[:6]]["_re"].search(line))

    def test_masking(self):
        m = logs.mask('x PHPSESSID=deadbeef; y Authorization: Bearer abc.def')
        self.assertNotIn("deadbeef", m)
        self.assertNotIn("abc.def", m)


class Scan(unittest.TestCase):
    def test_fixture_scan_and_thresholds(self):
        with tempfile.TemporaryDirectory() as t:
            for f in (helpers.FIX / "logs").iterdir():
                shutil.copy(f, t)
            with open(Path(t, "error.log"), "rb") as src, gzip.open(Path(t, "error.log.1.gz"), "wb") as dst:
                dst.write(src.read())
            s = helpers.settings(log_sources=[
                {"name": "a", "type": "access", "paths": [f"{t}/access.log"]},
                {"name": "e", "type": "error", "paths": [f"{t}/error.log*"]},
                {"name": "f", "type": "fpm", "paths": [f"{t}/php8.3-fpm.log"]},
                {"name": "k", "type": "system", "paths": [f"{t}/kern.log"]},
                {"name": "missing", "type": "waf", "paths": [f"{t}/nope*.log"]},
            ])
            res = logs.scan(s)
            self.assertEqual(res["DR-003"]["hits"], 2)
            self.assertEqual(res["DR-006"]["hits"], 2)
            self.assertEqual(res["DR-005"]["hits"], 1)
            self.assertEqual(res["DR-007"]["hits"], 1)
            self.assertEqual(res["DR-010"]["hits"], 2)
            self.assertIn("missing", res["_missing_sources"])
            f = helpers.by_id(logs.to_findings(res, s))
            self.assertEqual(f["DR-005"].status, "ALERT")
            self.assertEqual(f["DR-011"].status, "ALERT")
            self.assertEqual(f["DR-001"].status, "INFO")
            self.assertEqual(f["DR-002"].status, "INFO")
            self.assertNotIn("abcdef123456", str(f["DR-002"].evidence))
            self.assertEqual(f["LOG-GAPS"].status, "INFO")

    def test_no_logs(self):
        s = helpers.settings(log_sources=[{"name": "x", "type": "access", "paths": ["/nonexistent/*.log"]}])
        f = helpers.by_id(logs.to_findings(logs.scan(s), s))
        self.assertEqual(f["LOG-NODATA"].status, "UNKNOWN")

    def test_line_limit(self):
        with tempfile.TemporaryDirectory() as t:
            Path(t, "fpm.log").write_text("\n".join([POSITIVE["DR-005"]] * 11) + "\n")
            s = helpers.settings(max_lines_per_file=3, log_sources=[{"name": "f", "type": "fpm", "paths": [f"{t}/fpm.log"]}])
            res = logs.scan(s)
            self.assertEqual(res["DR-005"]["hits"], 3)
            self.assertTrue(res["_truncated"])


if __name__ == "__main__":
    unittest.main()
