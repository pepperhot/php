import json
import shutil
import subprocess
import unittest

import helpers
from core.collect import norm_bool, parse_fpm_pool_text, parse_ini_text

ANX = helpers.ROOT / "annexes"
WAF = ["aws-waf-php2shell-phase-test.json", "aws-waf-taille-corps-phase-test.json"]
SCRIPTS = ["01_inventaire.sh", "02_verifier_correctif.sh", "03_detection_lecture_seule.sh", "ssm-audit-flotte.sh"]


class Waf(unittest.TestCase):
    def test_json_is_test_phase(self):
        for f in WAF:
            rule = json.loads((ANX / f).read_text(encoding="utf-8"))
            self.assertEqual(rule["Action"], {"Count": {}}, f)
            self.assertTrue(rule["VisibilityConfig"]["CloudWatchMetricsEnabled"])

    def test_against_wafv2_api_model(self):
        try:
            import botocore.session
            from botocore.validate import ParamValidator
        except ImportError:
            self.skipTest("botocore absent")
        shape = botocore.session.get_session().get_service_model("wafv2").shape_for("Rule")
        for f in WAF:
            r = ParamValidator().validate(json.loads((ANX / f).read_text()), shape)
            self.assertFalse(r.has_errors(), r.generate_report())


class Scripts(unittest.TestCase):
    def test_bash_syntax(self):
        if not shutil.which("bash"):
            self.skipTest("bash absent")
        for f in SCRIPTS:
            self.assertEqual(subprocess.run(["bash", "-n", str(ANX / f)]).returncode, 0, f)

    def test_shellcheck(self):
        if not shutil.which("shellcheck"):
            self.skipTest("shellcheck absent")
        r = subprocess.run(["shellcheck", "-S", "warning", *[str(ANX / f) for f in SCRIPTS]], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)

    def test_verify_references_match_advisory(self):
        text = (ANX / "02_verifier_correctif.sh").read_text(encoding="utf-8")
        adv = json.loads((helpers.ROOT / "data/advisories/php2shell-2026-10.json").read_text(encoding="utf-8"))
        for fx in adv["distro_fixes"]:
            ver = {"trixie": "13", "bookworm": "12"}.get(fx["release"], fx["release"])
            self.assertIn(f'[{fx["distro"]}:{ver}:{fx["source_package"]}]="{fx["fixed_version"]}"', text)
        for b, info in adv["upstream"]["branches"].items():
            self.assertIn(f'[{b}]="{info["fixed"]}"', text)


class Snippets(unittest.TestCase):
    def test_active_directives(self):
        ini = parse_ini_text((ANX / "mitigation-php.ini").read_text(encoding="utf-8"))
        self.assertEqual(norm_bool(ini["session.upload_progress.enabled"]), "0")
        self.assertNotIn("fatal_error_backtraces", ini)
        pool = parse_fpm_pool_text("[www]\n" + (ANX / "mitigation-php-fpm-pool.conf").read_text(encoding="utf-8"))[0]
        self.assertEqual(pool["admin"], {"session.upload_progress.enabled": "0"})
        apache = (ANX / "mitigation-apache-modphp.conf").read_text(encoding="utf-8")
        active = [ln.strip() for ln in apache.splitlines() if ln.strip() and not ln.strip().startswith("#")]
        self.assertEqual(active, ["<IfModule php_module>", "php_admin_flag session.upload_progress.enabled off", "</IfModule>"])


if __name__ == "__main__":
    unittest.main()
