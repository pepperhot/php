import os
import tempfile
import unittest
from pathlib import Path

import helpers
from checks import binaries, external, mitigations, packages, runtime
from core.collect import collect_php_conf, collect_stale_processes, norm_bool, parse_fpm_pool_text, parse_ini_text
from core.engine import overall, run_checks
from checks import select


class Packages(unittest.TestCase):
    def setUp(self):
        self.s = helpers.settings()
        self.adv = self.s["_advisories"][0]

    def test_ubuntu_noble_vulnerable(self):
        f = helpers.by_id(packages.run(helpers.inventory("inv_ubuntu_noble_vulnerable.json"), self.s, self.adv))
        self.assertEqual(f["PKG-php8.3"].status, "VULNERABLE")
        self.assertEqual(f["PKG-php8.3"].evidence["fixed_version"], "8.3.6-0ubuntu0.24.04.13")
        self.assertNotIn("PKG-php-defaults", f)

    def test_ubuntu_noble_fixed_despite_upstream_number(self):
        f = helpers.by_id(packages.run(helpers.inventory("inv_ubuntu_noble_fixed.json"), self.s, self.adv))
        self.assertEqual(f["PKG-php8.3"].status, "FIXED")
        self.assertEqual(f["PKG-php8.3"].evidence["basis"], "table distribution")

    def test_sury_mixed(self):
        f = helpers.by_id(packages.run(helpers.inventory("inv_debian_trixie_mixed.json"), self.s, self.adv))
        self.assertEqual(f["PKG-php8.4"].status, "FIXED")
        self.assertEqual(f["PKG-php8.5"].status, "VULNERABLE")
        self.assertEqual(f["PKG-php7.4"].status, "UNKNOWN")

    def test_unknown_release_backport_via_changelog(self):
        inv = helpers.inventory("inv_ubuntu_noble_fixed.json")
        inv["os"].update(version_id="25.10", codename="questing")
        for p in inv["packages"]:
            if p["source"] == "php8.3":
                p["version"] = p["source_version"] = "8.3.6-0ubuntu9.1"
        f = helpers.by_id(packages.run(inv, self.s, self.adv))
        self.assertEqual(f["PKG-php8.3"].status, "LIKELY_FIXED")
        inv["changelog_cves"] = {"php8.3": []}
        f = helpers.by_id(packages.run(inv, self.s, self.adv))
        self.assertEqual(f["PKG-php8.3"].status, "VULNERABLE")

    def test_eol_debian_without_backport(self):
        inv = helpers.inventory("inv_ubuntu_noble_fixed.json")
        inv["os"] = {"id": "debian", "version_id": "11", "codename": "bullseye"}
        inv["packages"] = [{"name": "php7.4-fpm", "version": "7.4.33-1+deb11u5", "source": "php7.4", "source_version": "7.4.33-1+deb11u5"}]
        inv["changelog_cves"] = {}
        f = helpers.by_id(packages.run(inv, self.s, self.adv))
        self.assertEqual(f["PKG-php7.4"].status, "VULNERABLE")


class Binaries(unittest.TestCase):
    def test_manual_and_embedded(self):
        s = helpers.settings()
        f = helpers.by_id(binaries.run(helpers.inventory("inv_debian_trixie_mixed.json"), s, s["_advisories"][0]))
        self.assertEqual(f["BIN-/usr/local/bin/php"].status, "VULNERABLE")
        self.assertEqual(f["BIN-/usr/local/bin/php"].severity, "high")
        self.assertEqual(f["BIN-/opt/bitnami/php/sbin/php-fpm"].status, "UNKNOWN")
        self.assertEqual(f["BIN-/opt/bitnami/php/sbin/php-fpm"].severity, "critical")

    def test_packaged_binary_is_info(self):
        s = helpers.settings()
        f = helpers.by_id(binaries.run(helpers.inventory("inv_ubuntu_noble_vulnerable.json"), s, s["_advisories"][0]))
        self.assertEqual(f["BIN-/usr/sbin/php-fpm8.3"].status, "INFO")


class Runtime(unittest.TestCase):
    def test_stale_and_modphp(self):
        s = helpers.settings()
        adv = s["_advisories"][0]
        f = helpers.by_id(runtime.run(helpers.inventory("inv_ubuntu_noble_vulnerable.json"), s, adv))
        self.assertEqual(f["RUN-STALE"].status, "VULNERABLE")
        f = helpers.by_id(runtime.run(helpers.inventory("inv_debian_trixie_mixed.json"), s, adv))
        self.assertEqual(f["RUN-PROC-SKIP"].status, "UNKNOWN")
        self.assertEqual(f["RUN-MODPHP"].status, "WARN")


class Mitigations(unittest.TestCase):
    def setUp(self):
        self.s = helpers.settings()
        self.adv = self.s["_advisories"][0]

    def test_fpm_pool_precedence(self):
        f = helpers.by_id(mitigations.run(helpers.inventory("inv_ubuntu_noble_vulnerable.json"), self.s, self.adv))
        up = f["MIT-8.3-fpm:www-MIT-UPLOAD-PROGRESS"]
        self.assertEqual((up.status, up.evidence["set_by"]), ("INFO", "php_admin"))
        mem = f["MIT-8.3-fpm:www-MIT-MEMORY-LIMIT"]
        self.assertEqual((mem.status, mem.evidence["set_by"]), ("WARN", "php_value (surchargeable)"))
        self.assertEqual(f["MIT-8.3-fpm:www-MIT-POST-MAX-SIZE"].status, "WARN")
        self.assertNotIn("MIT-8.3-fpm:www-MIT-FATAL-BACKTRACES", f)

    def test_85_only_directive_and_overrides(self):
        f = helpers.by_id(mitigations.run(helpers.inventory("inv_debian_trixie_mixed.json"), self.s, self.adv))
        self.assertEqual(f["MIT-8.5-apache2-MIT-FATAL-BACKTRACES"].status, "WARN")
        self.assertEqual(f["MIT-8.5-apache2-MIT-UPLOAD-PROGRESS"].status, "INFO")
        self.assertNotIn("MIT-8.4-apache2-MIT-FATAL-BACKTRACES", f)
        self.assertEqual(f["MIT-8.4-apache2-MIT-UPLOAD-PROGRESS"].status, "INFO")
        self.assertNotIn("MIT-8.4-apache2-MIT-MEMORY-LIMIT", f)
        self.assertEqual(f["MIT-APACHE-OVERRIDES"].status, "WARN")


class External(unittest.TestCase):
    def test_containers_and_http(self):
        s = helpers.settings()
        f = helpers.by_id(external.run(helpers.inventory("inv_debian_trixie_mixed.json"), s, s["_advisories"][0]))
        self.assertEqual(f["EXT-container:app"].status, "FIXED")
        self.assertEqual(f["EXT-container:legacy"].status, "VULNERABLE")
        self.assertEqual(f["EXT-http:https://example.test/"].status, "UNKNOWN")


class Engine(unittest.TestCase):
    def test_overall_and_resilience(self):
        s = helpers.settings(enabled=False)
        findings, failures = run_checks(helpers.inventory("inv_ubuntu_noble_fixed.json"), s, select())
        self.assertEqual(failures, [])
        self.assertEqual(overall(findings), "OK")
        findings, _ = run_checks(helpers.inventory("inv_ubuntu_noble_vulnerable.json"), s, select())
        self.assertEqual(overall(findings), "VULNERABLE")
        broken = helpers.inventory("inv_ubuntu_noble_fixed.json")
        broken["packages"] = [{"name": "php8.3-cli"}]
        findings, failures = run_checks(broken, s, select(["PKG"]))
        self.assertEqual(failures, ["PKG"])
        self.assertEqual(overall(findings), "INCOMPLETE")


class Parsers(unittest.TestCase):
    def test_ini(self):
        v = parse_ini_text('[PHP]\n; c\nmemory_limit = 256M ; note\nerror_log = "/var/log/a;b.log" ; x\nsession.upload_progress.enabled=Off\n')
        self.assertEqual(v["memory_limit"], "256M")
        self.assertEqual(v["error_log"], "/var/log/a;b.log")
        self.assertEqual(norm_bool(v["session.upload_progress.enabled"]), "0")

    def test_pool(self):
        pools = parse_fpm_pool_text("[www]\nuser = www-data\nphp_admin_flag[session.upload_progress.enabled] = off\nphp_value[memory_limit] = 512M\n[api]\nphp_admin_value[memory_limit] = -1\n", "x.conf")
        self.assertEqual([p["pool"] for p in pools], ["www", "api"])
        self.assertEqual(pools[0]["admin"]["session.upload_progress.enabled"], "0")
        self.assertEqual(pools[0]["user"]["memory_limit"], "512M")
        self.assertEqual(pools[1]["admin"]["memory_limit"], "-1")

    def test_conf_tree_and_conf_d_order(self):
        with tempfile.TemporaryDirectory() as t:
            fpm = Path(t, "8.4", "fpm")
            (fpm / "conf.d").mkdir(parents=True)
            (fpm / "pool.d").mkdir()
            (fpm / "php.ini").write_text("session.upload_progress.enabled = On\n")
            (fpm / "conf.d" / "99-php2shell.ini").write_text("session.upload_progress.enabled = Off\n")
            (fpm / "pool.d" / "www.conf").write_text("[www]\npm.max_requests = 1\n")
            ini, pools = collect_php_conf(t)
            self.assertEqual(ini["8.4"]["fpm"]["values"]["session.upload_progress.enabled"], "Off")
            self.assertEqual(pools["8.4"][0]["settings"]["pm.max_requests"], "1")

    def test_stale_proc(self):
        with tempfile.TemporaryDirectory() as t:
            for pid, maps in (("10", "7f00-7f01 r-xp 0 08:01 1 /usr/lib/apache2/modules/libphp8.4.so (deleted)\n"), ("11", "7f00-7f01 r-xp 0 08:01 1 /usr/lib/libc.so.6 (deleted)\n")):
                os.makedirs(f"{t}/{pid}")
                Path(t, pid, "maps").write_text(maps)
                Path(t, pid, "comm").write_text("apache2\n")
            res = collect_stale_processes(t)
            self.assertEqual(res["scanned"], 2)
            self.assertEqual([m["pid"] for m in res["matches"]], [10])


if __name__ == "__main__":
    unittest.main()
