import json
import tempfile
import unittest
from pathlib import Path

import helpers
from checks import select
from core import report
from core.engine import EXIT_CODES, run_checks


class Reports(unittest.TestCase):
    def _rep(self, inv_name):
        s = helpers.settings(enabled=False)
        inv = helpers.inventory(inv_name)
        findings, failures = run_checks(inv, s, select())
        return report.build(inv, findings, s, failures)

    def test_json_structure_and_roundtrip(self):
        rep = self._rep("inv_ubuntu_noble_vulnerable.json")
        self.assertEqual(rep["summary"]["overall"], "VULNERABLE")
        self.assertEqual(rep["meta"]["mode"], "audit")
        self.assertTrue(all(s["verified_on"] for s in rep["sources"]))
        with tempfile.TemporaryDirectory() as t:
            jp, mp = report.write(rep, t, "r")
            again = json.loads(Path(jp).read_text(encoding="utf-8"))
            self.assertEqual(again["summary"], rep["summary"])
            md = Path(mp).read_text(encoding="utf-8")
        self.assertIn("## Verdict : **VULNERABLE**", md)
        self.assertIn("`PKG-php8.3`", md)
        self.assertIn("security-tracker.debian.org", md)
        self.assertIn("ne remplace pas le correctif", md)

    def test_priority_table_lists_only_actionable(self):
        md = report.to_markdown(self._rep("inv_ubuntu_noble_fixed.json"))
        prio = md.split("## Constats prioritaires")[1].split("## Détail")[0]
        self.assertIn("Aucun constat prioritaire", prio)

    def test_pipe_escaping(self):
        rep = self._rep("inv_ubuntu_noble_fixed.json")
        rep["findings"].insert(0, {**rep["findings"][0], "status": "WARN", "title": "a|b", "id": "X"})
        self.assertIn("a\\|b", report.to_markdown(rep))

    def test_exit_codes(self):
        self.assertEqual(EXIT_CODES[self._rep("inv_ubuntu_noble_vulnerable.json")["summary"]["overall"]], 1)
        self.assertEqual(EXIT_CODES[self._rep("inv_ubuntu_noble_fixed.json")["summary"]["overall"]], 0)


if __name__ == "__main__":
    unittest.main()
