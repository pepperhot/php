import json
import re
from pathlib import Path

from core.schema import validate

ROOT = Path(__file__).resolve().parent.parent


class ConfigError(Exception):
    pass


def _load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise ConfigError(f"Fichier introuvable : {path}") from None
    except json.JSONDecodeError as e:
        raise ConfigError(f"JSON invalide dans {path} : {e}") from e


def _resolve(p, base=ROOT):
    p = Path(p)
    return p if p.is_absolute() else base / p


def load_validated(path, schema_path):
    data = _load_json(path)
    errors = validate(data, _load_json(schema_path))
    if errors:
        raise ConfigError(f"{path} invalide :\n  - " + "\n  - ".join(errors))
    return data


def load_rules(path):
    rules = load_validated(path, ROOT / "config/detection_rules.schema.json")
    seen = set()
    for r in rules["rules"]:
        if r["id"] in seen:
            raise ConfigError(f"Règle dupliquée : {r['id']}")
        seen.add(r["id"])
        try:
            r["_re"] = re.compile(r["pattern"])
        except re.error as e:
            raise ConfigError(f"Regex invalide pour {r['id']} : {e}") from e
    return rules


def load_advisory(path):
    adv = load_validated(path, ROOT / "data/advisories/advisory.schema.json")
    for branch, info in adv["upstream"]["branches"].items():
        if not re.match(r"^\d+\.\d+$", branch) or not re.match(r"^\d+\.\d+\.\d+$", info.get("fixed", "")):
            raise ConfigError(f"{path} : branche ou version corrigée invalide ({branch})")
        if not info["fixed"].startswith(branch + "."):
            raise ConfigError(f"{path} : {info['fixed']} n'appartient pas à la branche {branch}")
    return adv


def load_settings(path=None, environment=None):
    path = _resolve(path or "config/settings.json")
    settings = load_validated(path, ROOT / "config/settings.schema.json")
    if environment:
        settings["environment"] = environment
    if settings["environment"] not in settings["environments"]:
        raise ConfigError(f"Environnement inconnu : {settings['environment']}")
    settings["_advisories"] = [load_advisory(_resolve(a)) for a in settings["advisories"]]
    settings["_rules"] = load_rules(_resolve(settings["detection_rules"]))
    settings["_reports_dir"] = _resolve(settings["reports_dir"])
    return settings
