import json
import shlex
from datetime import datetime, timezone
from pathlib import Path

from checks.packages import _PHP_SOURCE, _match_distro_fix
from core.versions import detect_origin

PLATFORMS = Path(__file__).resolve().parent / "platforms"
_GUARD = """#!/usr/bin/env bash
# Plan de remédiation généré par php-vuln-audit — NE PAS exécuter sans relecture.
# Aucune étape n'est lancée par l'outil d'audit. Chaque étape demande confirmation.
set -euo pipefail
if [[ "${1:-}" != "--i-have-reviewed" ]]; then
  echo "Refus : relire ce script puis lancer avec --i-have-reviewed" >&2; exit 64
fi
[[ $EUID -eq 0 ]] || { echo "Exécuter en root" >&2; exit 65; }
confirm() { read -r -p "[$1] $2 — exécuter ? (oui/non) " a; [[ "$a" == "oui" ]]; }
check_ge() { local p="$1" want="$2" got="$3"
  if [[ -z "$got" || "$got" == "(none)" ]]; then echo "KO $p : aucune version"; return 1; fi
  if dpkg --compare-versions "$got" ge "$want"; then echo "OK $p $got >= $want"; else echo "KO $p $got < $want"; return 1; fi; }
"""


def load_platform(os_id):
    for f in PLATFORMS.glob("*.json"):
        p = json.loads(f.read_text(encoding="utf-8"))
        if os_id in p["applies_to_os"]:
            return p
    return None


def _context(inv, adv):
    os_info = inv.get("os", {})
    core = [p for p in inv.get("packages", []) if _PHP_SOURCE.match(p["source"])]
    pkgs = sorted({p["name"] for p in core})
    services = [s["unit"] for s in inv.get("services", []) if s.get("active") == "active" and (s["unit"].startswith("php") or s["unit"].startswith("apache2"))]
    dirs = [d for d in ("/etc/php", "/etc/apache2", "/etc/nginx") if Path(d).exists()] or ["/etc/php"]
    checks_pre, checks_post, blocked = [], [], set()
    for p in sorted(core, key=lambda x: x["name"]):
        src = p["source"]
        origin = detect_origin(p["source_version"], os_info.get("id"))
        fx = _match_distro_fix(adv, origin, os_info, src) if origin in ("debian", "ubuntu") else None
        want = fx["fixed_version"] if fx else adv["upstream"]["branches"].get(src[3:], {}).get("fixed")
        if not want:
            if src not in blocked:
                blocked.add(src)
                checks_pre.append(f"echo 'À CONFIRMER {src} : aucune version corrigée de référence (branche non maintenue ou origine inconnue)'; exit 1")
            continue
        q = shlex.quote(p["name"])
        checks_pre.append(f"check_ge {q} {shlex.quote(want)} \"$(apt-cache policy {q} | awk '/Candidate:/{{print $2}}')\"")
        checks_post.append(f"check_ge {q} {shlex.quote(want)} \"$(dpkg-query -W -f='${{Version}}' {q})\"")
    return {"binary_packages": " ".join(shlex.quote(x) for x in pkgs), "services": services, "backup_dirs": " ".join(dirs), "timestamp": datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"), "candidate_checks": checks_pre, "candidate_post_checks": checks_post, "has_packages": bool(pkgs)}


def build_plan(inv, settings, adv):
    env = settings["environments"][settings["environment"]]
    os_id = inv.get("os", {}).get("id")
    plat = load_platform(os_id)
    if plat is None:
        return {"supported": False, "reason": f"Aucune procédure pour l'OS '{os_id}'."}
    ctx = _context(inv, adv)
    if not ctx["has_packages"]:
        return {"supported": False, "reason": "Aucun paquet PHP dpkg : installation manuelle, embarquée ou conteneur. Voir PLAN_REMEDIATION.md §Cas particuliers."}
    steps = []
    for s in plat["steps"]:
        if s.get("requires") == "services" and not ctx["services"]:
            continue
        cmds = [c.format(**ctx) for c in s.get("commands", [])]
        if "commands_per_service" in s:
            cmds += [s["commands_per_service"].format(service=shlex.quote(sv)) for sv in ctx["services"]]
        if s.get("prepend"):
            cmds = ctx[s["prepend"]] + cmds
        if s.get("append"):
            cmds += ctx[s["append"]]
        steps.append({"id": s["id"], "title": s["title"], "purpose": s["purpose"], "expected": s["expected"], "commands": cmds})
    return {"supported": True, "platform": plat["platform"], "environment": settings["environment"], "script_allowed": env["allow_remediation_script"], "steps": steps, "rollback": plat["rollback"]}


def to_script(plan):
    out = [_GUARD]
    for s in plan["steps"]:
        out.append(f"\n# --- {s['id']} : {s['title']}\n# Objectif : {s['purpose']}\n# Attendu : {s['expected']}")
        out.append(f"if confirm {shlex.quote(s['id'])} {shlex.quote(s['title'])}; then")
        out += [f"  {c}" for c in s["commands"]]
        out.append(f"else echo 'Étape {s['id']} ignorée — arrêt.'; exit 1; fi")
    out.append("\necho 'Plan terminé. Lancer un nouvel audit : python3 phpaudit.py audit'")
    return "\n".join(out) + "\n"


def to_markdown(plan):
    if not plan["supported"]:
        return f"# Plan de remédiation\n\nNon généré : {plan['reason']}\n"
    L = [f"# Plan de remédiation ({plan['platform']}, environnement `{plan['environment']}`)", "", "> Généré pour relecture. L'outil n'exécute aucune commande. Valider d'abord en préproduction.", ""]
    for s in plan["steps"]:
        L += [f"## {s['id']} — {s['title']}", f"- Objectif : {s['purpose']}", f"- Résultat attendu : {s['expected']}", "```bash", *s["commands"], "```", ""]
    L += ["## Retour arrière", ""] + [f"- {r}" for r in plan["rollback"]]
    return "\n".join(L) + "\n"


def write(plan, out_dir, stem):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    md = out_dir / f"{stem}.md"
    md.write_text(to_markdown(plan), encoding="utf-8")
    paths = [md]
    if plan.get("supported") and plan.get("script_allowed"):
        sh = out_dir / f"{stem}.sh"
        sh.write_text(to_script(plan), encoding="utf-8")
        sh.chmod(0o600)
        paths.append(sh)
    return paths
