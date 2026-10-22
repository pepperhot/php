import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import helpers
from remediation import planner


class Planner(unittest.TestCase):
    def setUp(self):
        self.s = helpers.settings()
        self.adv = self.s["_advisories"][0]

    def test_plan_never_executes_commands(self):
        with mock.patch("subprocess.run", side_effect=AssertionError("exécution interdite")), mock.patch("os.system", side_effect=AssertionError):
            plan = planner.build_plan(helpers.inventory("inv_ubuntu_noble_vulnerable.json"), self.s, self.adv)
            script = planner.to_script(plan)
        self.assertTrue(plan["supported"])
        self.assertIn('--i-have-reviewed', script)
        self.assertIn("check_ge php8.3-fpm 8.3.6-0ubuntu0.24.04.13", script)
        self.assertIn("systemctl restart php8.3-fpm.service", script)
        self.assertNotRegex(script, r"(?m)^\s+apt(-get)? (dist-|full-)?upgrade")
        self.assertNotIn("php-common", script.split("S3")[1].split("S4")[0])
        s5 = script.split("# --- S5")[1]
        self.assertLess(s5.index("check_ge php8.3-fpm"), s5.index("changelog.Debian.gz"))
        self.assertIn("exit 1; else echo 'OK : aucun processus obsolète'", s5)

    def test_script_syntax_and_guard(self):
        if not shutil.which("bash"):
            self.skipTest("bash absent")
        plan = planner.build_plan(helpers.inventory("inv_ubuntu_noble_vulnerable.json"), self.s, self.adv)
        with tempfile.TemporaryDirectory() as t:
            paths = planner.write(plan, t, "p")
            sh = [p for p in paths if p.suffix == ".sh"][0]
            self.assertEqual(oct(sh.stat().st_mode)[-3:], "600")
            self.assertEqual(subprocess.run(["bash", "-n", str(sh)]).returncode, 0)
            r = subprocess.run(["bash", str(sh)], capture_output=True, text=True)
            self.assertEqual(r.returncode, 64)

    def test_eol_without_reference_blocks(self):
        plan = planner.build_plan(helpers.inventory("inv_debian_trixie_mixed.json"), self.s, self.adv)
        script = planner.to_script(plan)
        self.assertIn("À CONFIRMER php7.4", script)
        self.assertIn("check_ge php8.5-fpm 8.5.12", script)

    def test_unsupported_os_and_no_packages(self):
        inv = helpers.inventory("inv_ubuntu_noble_fixed.json")
        inv["os"]["id"] = "alpine"
        self.assertFalse(planner.build_plan(inv, self.s, self.adv)["supported"])
        inv = helpers.inventory("inv_ubuntu_noble_fixed.json")
        inv["packages"] = []
        plan = planner.build_plan(inv, self.s, self.adv)
        self.assertFalse(plan["supported"])
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual([p.suffix for p in planner.write(plan, t, "p")], [".md"])


class Cli(unittest.TestCase):
    def test_cli(self):
        import phpaudit
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(phpaudit.main(["validate"]), 0)
            inv = str(helpers.FIX / "inv_ubuntu_noble_vulnerable.json")
            self.assertEqual(phpaudit.main(["audit", "--inventory", inv, "--skip-logs", "--output-dir", t]), 1)
            self.assertEqual(len(list(Path(t).glob("audit_*.json"))), 1)
            self.assertEqual(phpaudit.main(["plan", "--inventory", inv, "--output-dir", t]), 0)
            self.assertEqual(phpaudit.main(["--env", "nope", "validate"]), 4)
            self.assertEqual(phpaudit.main(["audit", "--inventory", inv, "--checks", "ZZZ", "--output-dir", t]), 4)


if __name__ == "__main__":
    unittest.main()
