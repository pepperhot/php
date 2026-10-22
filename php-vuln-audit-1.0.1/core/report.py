import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from core.engine import overall

TOOL_VERSION = "1.0.1"
ICON = {"VULNERABLE": "🔴", "ALERT": "🟠", "UNKNOWN": "⚪", "WARN": "🟡", "LIKELY_FIXED": "🟢", "FIXED": "🟢", "INFO": "ℹ️"}


def build(inventory, findings, settings, failures=()):
    advs = settings["_advisories"]
    return {
        "meta": {
            "tool_version": TOOL_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "mode": settings["mode"],
            "environment": settings["environment"],
            "host": inventory.get("hostname"),
            "os": inventory.get("os"),
            "inventory_collected_at": inventory.get("collected_at"),
            "advisories": [{"id": a["id"], "verified_on": a["verified_on"]} for a in advs],
            "rules_verified_on": settings["_rules"]["verified_on"],
        },
        "summary": {
            "overall": overall(findings),
            "by_status": dict(Counter(f.status for f in findings)),
            "failed_checks": list(failures),
        },
        "findings": [f.to_dict() for f in findings],
        "data_gaps": inventory.get("errors", []),
        "sources": [s for a in advs for s in a["sources"]],
        "disclaimer": "Collecte sans modification de la configuration système (seuls les rapports et l'inventaire sont écrits). Une mitigation ne remplace pas le correctif. Une version corrigée ne nettoie pas un serveur déjà compromis.",
    }


def _md_escape(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def to_markdown(rep):
    m, s = rep["meta"], rep["summary"]
    L = [
        f"# Rapport d'audit PHP — {m['host']}",
        "",
        f"- Généré : {m['generated_at']} (outil {m['tool_version']}, mode `{m['mode']}`, environnement `{m['environment']}`)",
        f"- Système : {(m.get('os') or {}).get('pretty', 'inconnu')}",
        f"- Inventaire collecté : {m['inventory_collected_at']}",
        "- Avis : " + ", ".join(f"{a['id']} (vérifié le {a['verified_on']})" for a in m["advisories"]),
        "",
        f"## Verdict : **{s['overall']}**",
        "",
        "| Statut | Nombre |",
        "|---|---|",
    ]
    L += [f"| {ICON.get(k, '')} {k} | {v} |" for k, v in sorted(s["by_status"].items())]
    if s["failed_checks"]:
        L += ["", f"> Contrôles en échec : {', '.join(s['failed_checks'])}"]
    L += ["", "## Constats prioritaires", "", "| Statut | Sévérité | ID | Composant | Constat | Action |", "|---|---|---|---|---|---|"]
    prio = [f for f in rep["findings"] if f["status"] in ("VULNERABLE", "ALERT", "UNKNOWN", "WARN", "LIKELY_FIXED")]
    for f in prio:
        L.append(f"| {ICON[f['status']]} {f['status']} | {f['severity']} | `{f['id']}` | {_md_escape(f['component'])} | {_md_escape(f['title'])} | {_md_escape(f['recommendation'])} |")
    if not prio:
        L.append("| — | — | — | — | Aucun constat prioritaire | — |")
    L += ["", "## Détail des constats", ""]
    for f in rep["findings"]:
        L.append(f"### {ICON[f['status']]} `{f['id']}` — {f['title']}")
        L.append(f"- Statut / sévérité : **{f['status']}** / {f['severity']} — contrôle `{f['check']}`")
        if f["cves"]:
            L.append(f"- CVE : {', '.join(f['cves'])}")
        if f["detail"]:
            L.append(f"- Détail : {f['detail']}")
        if f["recommendation"]:
            L.append(f"- Action : {f['recommendation']}")
        if f["evidence"]:
            L.append("- Preuves :")
            L.append("```json")
            L.append(json.dumps(f["evidence"], ensure_ascii=False, indent=2, default=str)[:4000])
            L.append("```")
        for r in f["references"]:
            L.append(f"- Réf. : {r}")
        L.append("")
    L += ["## Données manquantes / erreurs de collecte", ""]
    L += [f"- {e}" for e in rep["data_gaps"]] or ["- Aucune"]
    L += ["", "## Sources", ""]
    L += [f"- [{x['publisher']} — {x['title']}]({x['url']}) — vérifié le {x['verified_on']}" for x in rep["sources"]]
    L += ["", f"> {rep['disclaimer']}", ""]
    return "\n".join(L)


def write(rep, out_dir, stem=None):
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = stem or f"audit_{rep['meta']['host']}_{rep['meta']['generated_at'].replace(':', '').replace('+0000', 'Z')}"
    jp, mp = out_dir / f"{stem}.json", out_dir / f"{stem}.md"
    jp.write_text(json.dumps(rep, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    mp.write_text(to_markdown(rep), encoding="utf-8")
    return jp, mp
