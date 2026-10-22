#!/usr/bin/env python3
import argparse
import json
import logging
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from checks import REGISTRY, select  # noqa: E402
from core import collect, report  # noqa: E402
from core.config import ConfigError, load_settings  # noqa: E402
from core.engine import EXIT_CODES, run_checks  # noqa: E402
from remediation import planner  # noqa: E402

log = logging.getLogger("php_audit")


def _settings(a):
    s = load_settings(a.config, a.env)
    logging.basicConfig(level=getattr(logging, a.log_level or s.get("log_level", "INFO")), format="%(asctime)s %(levelname)s %(name)s: %(message)s", stream=sys.stderr)
    return s


def _inventory(a, s):
    if getattr(a, "inventory", None):
        with open(a.inventory, encoding="utf-8") as f:
            return json.load(f)
    log.info("collecte sans modification de la configuration système")
    return collect.collect(s)


def cmd_validate(a):
    s = _settings(a)
    print(f"OK : configuration valide ({len(s['_advisories'])} avis, {len(s['_rules']['rules'])} règles, environnement {s['environment']})")
    return 0


def cmd_collect(a):
    s = _settings(a)
    inv = collect.collect(s)
    out = a.output or str(ROOT / "data/inventory" / f"{inv['hostname']}.json")
    collect.save_inventory(inv, out)
    print(out)
    return 0


def cmd_audit(a):
    s = _settings(a)
    inv = _inventory(a, s)
    if a.skip_logs:
        s["detection"]["enabled"] = False
    findings, failures = run_checks(inv, s, select(a.checks))
    rep = report.build(inv, findings, s, failures)
    jp, mp = report.write(rep, a.output_dir or s["_reports_dir"])
    print(f"Verdict : {rep['summary']['overall']}\nJSON : {jp}\nMarkdown : {mp}")
    return EXIT_CODES[rep["summary"]["overall"]]


def cmd_plan(a):
    s = _settings(a)
    inv = _inventory(a, s)
    adv = s["_advisories"][0]
    plan = planner.build_plan(inv, s, adv)
    stem = f"plan_{inv.get('hostname', 'host')}_{s['environment']}"
    for p in planner.write(plan, a.output_dir or s["_reports_dir"], stem):
        print(p)
    return 0 if plan["supported"] else 3


def cmd_list(a):
    for c in REGISTRY.values():
        print(f"{c.id}\t{c.title}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="phpaudit", description="Audit des vulnérabilités PHP sans modification de la configuration système (écrit uniquement reports/ et data/inventory/).")
    p.add_argument("--config", help="chemin de settings.json")
    p.add_argument("--env", help="environnement (clé de settings.environments)")
    p.add_argument("--log-level", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("validate", help="valider configuration, avis et règles").set_defaults(fn=cmd_validate)
    sp = sub.add_parser("collect", help="collecter l'inventaire (aucune modification système)")
    sp.add_argument("-o", "--output")
    sp.set_defaults(fn=cmd_collect)
    sp = sub.add_parser("audit", help="collecter (ou charger) puis évaluer et produire les rapports")
    sp.add_argument("--inventory", help="inventaire JSON existant (analyse hors ligne)")
    sp.add_argument("--checks", nargs="*", help="sous-ensemble de contrôles (ex : PKG RUN)")
    sp.add_argument("--skip-logs", action="store_true")
    sp.add_argument("--output-dir")
    sp.set_defaults(fn=cmd_audit)
    sp = sub.add_parser("plan", help="générer un plan de remédiation à relire (aucune exécution)")
    sp.add_argument("--inventory")
    sp.add_argument("--output-dir")
    sp.set_defaults(fn=cmd_plan)
    sub.add_parser("list-checks").set_defaults(fn=cmd_list)
    a = p.parse_args(argv)
    try:
        return a.fn(a)
    except ConfigError as e:
        print(f"Erreur de configuration : {e}", file=sys.stderr)
        return 4
    except KeyError as e:
        print(f"Erreur : {e}", file=sys.stderr)
        return 4


if __name__ == "__main__":
    sys.exit(main())
