from checks.common import all_cves, eval_upstream, refs
from core.engine import Finding

ID = "BIN"
TITLE = "Binaires PHP (CLI, FPM, compilés, embarqués)"

WEB_SAPIS = {"fpm-fcgi", "cgi-fcgi", "apache2handler", "litespeed", "frankenphp"}


def run(inv, settings, adv):
    cves = all_cves(adv)
    out = []
    for b in inv.get("binaries", []):
        comp = b["realpath"]
        ev = {k: b.get(k) for k in ("path", "realpath", "version", "sapi", "owner_package")}
        if not b.get("version"):
            out.append(Finding(ID, f"BIN-{comp}", f"Version illisible : {comp}", "UNKNOWN", "medium", comp, detail=b.get("error", ""), recommendation="Exécuter manuellement '<binaire> -v'.", evidence=ev))
            continue
        exposure = "web" if (b.get("sapi") in WEB_SAPIS or "fpm" in comp) else "cli"
        ev["exposure"] = exposure
        if b.get("owner_package"):
            out.append(Finding(ID, f"BIN-{comp}", f"{comp} : PHP {b['version']} ({b.get('sapi')})", "INFO", "info", comp, detail=f"Binaire fourni par le paquet {b['owner_package']} : statut évalué par le contrôle PKG (les backports conservent le numéro upstream).", evidence=ev))
            continue
        status, fixed = eval_upstream(b["version"], adv)
        ev["fixed_upstream"] = fixed
        sev_v = "critical" if exposure == "web" else "high"
        if status == "FIXED":
            out.append(Finding(ID, f"BIN-{comp}", f"{comp} hors paquet : corrigé", "FIXED", "info", comp, detail=f"{b['version']} >= {fixed}.", cves=cves, evidence=ev))
        elif status == "VULNERABLE":
            out.append(Finding(ID, f"BIN-{comp}", f"{comp} hors paquet : vulnérable", "VULNERABLE", sev_v, comp, detail=f"Installation manuelle/embarquée {b['version']} < {fixed}. 'apt upgrade' ne la met pas à jour.", recommendation=f"Recompiler depuis {fixed}+ ou mettre à jour la pile fournisseur (Bitnami, FrankenPHP...), puis redémarrer.", cves=cves, evidence=ev, references=refs(adv, "php-advisory")))
        else:
            out.append(Finding(ID, f"BIN-{comp}", f"{comp} hors paquet : branche non maintenue ou inconnue", "UNKNOWN", sev_v, comp, detail="Impossible de savoir si un backport source a été appliqué à ce build.", recommendation="Vérifier la provenance du build ; sinon traiter comme vulnérable et migrer.", cves=cves, evidence=ev, references=list(adv["upstream"].get("source_backports", {}).values())))
    return out
