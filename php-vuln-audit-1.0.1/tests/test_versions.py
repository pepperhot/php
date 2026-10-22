import unittest

import helpers  # noqa: F401
from core.versions import branch_from_package, deb_compare, detect_origin, upstream_of


class DebCompare(unittest.TestCase):
    CASES = [
        ("8.3.6-0ubuntu0.24.04.13", "8.3.6-0ubuntu0.24.04.12", 1),
        ("8.3.6-0ubuntu0.24.04.12", "8.3.6-0ubuntu0.24.04.13", -1),
        ("8.4.27-1~deb13u1", "8.4.27-1", -1),
        ("8.4.27-1~deb13u1", "8.4.24-1~deb13u1", 1),
        ("1.0~rc1", "1.0", -1),
        ("2:93ubuntu2", "93ubuntu3", 1),
        ("8.4.27-1+0~20261021.1+debian13~1.gbp+deb.sury.org+1", "8.4.27", 1),
        ("7.4.3-4ubuntu2.29+esm5", "7.4.3-4ubuntu2.29", 1),
        ("8.2.35-1~deb12u1", "8.2.35-1~deb12u1", 0),
        ("1.10", "1.9", 1),
        ("1.0a", "1.0", 1),
    ]

    def test_cases(self):
        for a, b, exp in self.CASES:
            with self.subTest(a=a, b=b):
                self.assertEqual(deb_compare(a, b), exp)
                self.assertEqual(deb_compare(b, a), -exp)

    def test_matches_dpkg_when_available(self):
        import shutil
        import subprocess
        if not shutil.which("dpkg"):
            self.skipTest("dpkg absent")
        for a, b, _ in self.CASES:
            gt = subprocess.run(["dpkg", "--compare-versions", a, "gt", b]).returncode == 0
            eq = subprocess.run(["dpkg", "--compare-versions", a, "eq", b]).returncode == 0
            self.assertEqual(deb_compare(a, b), 0 if eq else 1 if gt else -1, f"{a} vs {b}")


class Helpers(unittest.TestCase):
    def test_upstream(self):
        self.assertEqual(upstream_of("8.3.6-0ubuntu0.24.04.13"), (8, 3, 6))
        self.assertEqual(upstream_of("2:93ubuntu2"), None)
        self.assertEqual(upstream_of("5.5.9+dfsg-1ubuntu4.29+esm18"), (5, 5, 9))

    def test_branch_from_package(self):
        self.assertEqual(branch_from_package("php8.3-fpm"), "8.3")
        self.assertEqual(branch_from_package("libapache2-mod-php8.4"), "8.4")
        self.assertEqual(branch_from_package("php8.3"), "8.3")
        self.assertIsNone(branch_from_package("php-common"))
        self.assertIsNone(branch_from_package("php5"))

    def test_origin(self):
        self.assertEqual(detect_origin("8.4.27-1+0~x+deb.sury.org+1"), "sury")
        self.assertEqual(detect_origin("8.3.6-0ubuntu0.24.04.13"), "ubuntu")
        self.assertEqual(detect_origin("8.4.27-1~deb13u1"), "debian")
        self.assertEqual(detect_origin("8.4.26-1", "debian"), "debian")
        self.assertEqual(detect_origin("8.4.26", "alpine"), "unknown")


if __name__ == "__main__":
    unittest.main()
