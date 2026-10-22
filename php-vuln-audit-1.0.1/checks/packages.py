import re
from datetime import date, timedelta

from checks.common import all_cves, eval_upstream, is_eol, refs
from core.engine import Finding
from core.versions import branch_from_package, deb_compare, detect_origin

ID = "PKG"
TITLE = "Version des paquets PHP (dpkg)"
_PHP_SOURCE = re.compile(r"^php\d+(\.\d+)?$")


def _match_distro_fix(adv, origin, os_info, source):
    rel = {os_info.get("codename"), os_info.get("version_id")} - {None, ""}
    for fx in adv["distro_fixes"]:
        if fx["distro"] == origin and fx["release"] in rel and fx["source_package"] == source:
            return fx
    return None


def run(inv, settings, adv):
    cves = all_cves(adv)
    out = []
    sources = {}
    for p in inv.get("packages", []):
        if _PHP_SOURCE.match(p["source"]):
            sources.setdefault(p["source"], {"version": p["source_version"], "binaries": []})["binaries"].append(p["name"])
    if not inv.get("packages"):
        out.append(Finding(ID, "PKG-NONE", "Aucun paquet PHP dpkg détecté", "INFO", "info", "dpkg", detail="PHP absent, compilé manuellement, embarqué (Bitnami, FrankenPHP) ou en conteneur : voir contrôles BIN/EXT."))
    os_info = inv.get("os", {})
    changelogs = inv.get("changelog_cves", {})
    for src, data in sorted(sources.items()):
        ver = data["version"]
        branch = branch_from_package(src)
        origin = detect_origin(ver, os_info.get("id"))
        cl = changelogs.get(src, [])
        cl_all = all(c in cl for c in cves)
        ev = {"source_package": src, "version": ver, "origin": origin, "binaries": sorted(data["binaries"]), "changelog_cves": cl, "os": f"{os_info.get('id')} {os_info.get('version_id')} {os_info.get('codename')}".strip()}
        fx = _match_distro_fix(adv, origin, os_info, src) if origin in ("debian", "ubuntu") else None
        fid = f"PKG-{src}"
        if fx:
            ok = deb_compare(ver, fx["fixed_version"]) >= 0
            ev.update({"fixed_version": fx["fixed_version"], "distro_advisory": fx["advisory"], "basis": "table distribution"})
            note = f" Note : {fx['note']}" if fx.get("note") else ""
            if ok:
                out.append(Finding(ID, fid, f"{src} corrigé ({fx['advisory']})", "FIXED", "info", src, detail=f"{ver} >= {fx['fixed_version']}.{note}", recommendation="Vérifier qu'aucun processus n'exécute l'ancienne version (contrôle RUN).", cves=cves, evidence=ev, references=[fx["source_url"]]))
            else:
                out.append(Finding(ID, fid, f"{src} vulnérable", "VULNERABLE", "critical", src, detail=f"{ver} < {fx['fixed_version']} ({fx['advisory']}).{note}", recommendation=f"Installer {fx['fixed_version']} ou supérieur depuis le dépôt sécurité {origin}, puis redémarrer les services PHP.", cves=cves, evidence=ev, references=[fx["source_url"]]))
            continue
        status, fixed = eval_upstream(ver, adv)
        if status == "FIXED":
            ev["basis"] = "version upstream"
            out.append(Finding(ID, fid, f"{src} corrigé (upstream {fixed})", "FIXED", "info", src, detail=f"Version upstream >= {fixed}.", recommendation="Vérifier le contrôle RUN.", cves=cves, evidence=ev, references=refs(adv, "php-advisory")))
        elif status == "VULNERABLE":
            if origin in ("debian", "ubuntu") and cl_all:
                out.append(Finding(ID, fid, f"{src} probablement corrigé (backport)", "LIKELY_FIXED", "medium", src, detail="Version upstream < version corrigée mais le changelog Debian cite les deux CVE. Release absente de la table de correctifs : à confirmer via l'avis de la distribution.", recommendation="Confirmer l'avis distribution (USN/DSA/DLA) et mettre à jour data/advisories.", cves=cves, evidence=ev))
            else:
                out.append(Finding(ID, fid, f"{src} vulnérable", "VULNERABLE", "critical", src, detail=f"Version upstream < {fixed}, aucune preuve de backport (origine {origin}).", recommendation=f"Mettre à jour vers {fixed}+ (ou paquet distribution corrigé) puis redémarrer les services.", cves=cves, evidence=ev, references=refs(adv, "php-advisory")))
        elif status == "EOL" or is_eol(branch, adv):
            if cl_all:
                out.append(Finding(ID, fid, f"{src} : backport présent sur branche non maintenue", "LIKELY_FIXED", "high", src, detail="Changelog cite les deux CVE. Branche sans support upstream : les futures failles ne seront pas corrigées par le projet PHP.", recommendation="Planifier la migration vers 8.4 ou 8.5.", cves=cves, evidence=ev))
            elif origin == "sury":
                out.append(Finding(ID, fid, f"{src} : backport Sury à confirmer", "UNKNOWN", "high", src, detail="Sury annonce des backports EOL ; chaîne de version corrigée non publiée et CVE absentes du changelog local.", recommendation="Lire /usr/share/doc/<paquet>/changelog.Debian.gz ; à défaut traiter comme vulnérable et migrer.", cves=cves, evidence=ev))
            else:
                out.append(Finding(ID, fid, f"{src} : branche non maintenue sans correctif identifié", "VULNERABLE", "critical", src, detail=adv["upstream"].get("eol_note", ""), recommendation="Migrer vers une branche maintenue ou appliquer un backport fournisseur vérifié ; isoler en attendant.", cves=cves, evidence=ev, references=refs(adv, "php-advisory", "certeu")))
        else:
            out.append(Finding(ID, fid, f"{src} : statut indéterminé", "UNKNOWN", "high", src, detail="Version non interprétable ou branche absente de l'avis.", recommendation="Vérification manuelle.", cves=cves, evidence=ev))
        info = adv["upstream"]["branches"].get(branch or "")
        horizon = (date.today() + timedelta(days=180)).isoformat()
        if info and info.get("security_support_until", "9999") <= horizon:
            out.append(Finding(ID, f"PKG-{src}-EOLSOON", f"Branche {branch} : fin de support {info['security_support_until']}", "INFO", "low", src, recommendation="Planifier la migration vers 8.4/8.5.", references=["https://www.php.net/supported-versions.php"]))
    return out
