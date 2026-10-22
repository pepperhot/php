import copy
import json
import tempfile
import unittest
from pathlib import Path

import helpers  # noqa: F401
from core.config import ROOT, ConfigError, load_advisory, load_rules, load_settings
from core.schema import validate, validate_builtin


def _write(tmp, name, data):
    p = Path(tmp) / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


class Settings(unittest.TestCase):
    def setUp(self):
        self.raw = json.loads((ROOT / "config/settings.json").read_text())
        self.schema = json.loads((ROOT / "config/settings.schema.json").read_text())

    def test_default_valid_and_audit_mode(self):
        s = load_settings()
        self.assertEqual(s["mode"], "audit")
        self.assertTrue(s["_advisories"])

    def test_mode_other_than_audit_rejected(self):
        bad = copy.deepcopy(self.raw)
        bad["mode"] = "remediate"
        self.assertTrue(validate_builtin(bad, self.schema))
        self.assertTrue(validate(bad, self.schema))

    def test_unknown_key_rejected(self):
        bad = copy.deepcopy(self.raw)
        bad["auto_patch"] = True
        self.assertTrue(validate_builtin(bad, self.schema))

    def test_bad_types_rejected(self):
        bad = copy.deepcopy(self.raw)
        bad["collect"]["command_timeout_seconds"] = 0
        bad["detection"]["log_sources"][0]["type"] = "random"
        errs = validate_builtin(bad, self.schema)
        self.assertEqual(len(errs), 2, errs)

    def test_builtin_agrees_with_jsonschema(self):
        try:
            import jsonschema  # noqa: F401
        except ImportError:
            self.skipTest("jsonschema absent")
        for mutate in (lambda d: d, lambda d: d.update(mode="x"), lambda d: d.pop("collect")):
            d = copy.deepcopy(self.raw)
            mutate(d)
            self.assertEqual(bool(validate_builtin(d, self.schema)), bool(validate(d, self.schema)))

    def test_unknown_environment(self):
        with self.assertRaises(ConfigError):
            load_settings(environment="nope")


class Rules(unittest.TestCase):
    def test_bad_regex(self):
        data = json.loads((ROOT / "config/detection_rules.json").read_text())
        data["rules"][0]["pattern"] = "([unclosed"
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(ConfigError):
                load_rules(_write(t, "r.json", data))

    def test_duplicate_ids(self):
        data = json.loads((ROOT / "config/detection_rules.json").read_text())
        data["rules"].append(copy.deepcopy(data["rules"][0]))
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(ConfigError):
                load_rules(_write(t, "r.json", data))


class Advisory(unittest.TestCase):
    def setUp(self):
        self.data = json.loads((ROOT / "data/advisories/php2shell-2026-10.json").read_text())

    def test_reference_values(self):
        b = self.data["upstream"]["branches"]
        self.assertEqual({k: v["fixed"] for k, v in b.items()}, {"8.2": "8.2.35", "8.3": "8.3.36", "8.4": "8.4.27", "8.5": "8.5.12"})
        self.assertEqual({c["id"] for c in self.data["cves"]}, {"CVE-2026-109618", "CVE-2026-109619"})

    def test_every_source_dated(self):
        for s in self.data["sources"] + self.data["distro_fixes"]:
            self.assertRegex(s["verified_on"], r"^\d{4}-\d{2}-\d{2}$")

    def test_fixed_version_outside_branch_rejected(self):
        bad = copy.deepcopy(self.data)
        bad["upstream"]["branches"]["8.3"]["fixed"] = "8.4.27"
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(ConfigError):
                load_advisory(_write(t, "a.json", bad))

    def test_distro_fix_requires_https_source(self):
        bad = copy.deepcopy(self.data)
        bad["distro_fixes"][0]["source_url"] = "http://insecure"
        with tempfile.TemporaryDirectory() as t:
            with self.assertRaises(ConfigError):
                load_advisory(_write(t, "a.json", bad))


if __name__ == "__main__":
    unittest.main()
