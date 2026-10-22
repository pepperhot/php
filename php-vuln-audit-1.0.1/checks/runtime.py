from checks.common import all_cves, refs
from core.engine import Finding

ID = "RUN"
TITLE = "Processus et services en cours d'exécution"


def run(inv, settings, adv):
    cves = all_cves(adv)
    out = []
    sp = inv.get("stale_processes")
    if sp is None:
        out.append(Finding(ID, "RUN-PROC-SKIP", "Scan /proc désactivé", "UNKNOWN", "low", "processus", recommendation="Activer collect.scan_proc_maps ou lancer 'needrestart -b -r l'."))
    else:
        if sp["matches"]:
            out.append(Finding(ID, "RUN-STALE", f"{len(sp['matches'])} processus exécutent encore une bibliothèque/binaire PHP supprimé", "VULNERABLE", "critical", "processus", detail="Le paquet a été mis à jour mais l'ancien code reste chargé en mémoire.", recommendation="Redémarrage complet (stop/start) des services PHP-FPM / Apache concernés ; 'reload' et 'graceful' ne suffisent pas pour mod_php.", cves=cves, evidence={"matches": sp["matches"][:50]}))
        else:
            out.append(Finding(ID, "RUN-STALE", "Aucun processus PHP avec code supprimé en mémoire", "INFO", "info", "processus", evidence={"scanned": sp["scanned"], "unreadable": sp["unreadable"]}))
        if sp["unreadable"] and sp["scanned"] == 0:
            out.append(Finding(ID, "RUN-PROC-PERM", "Aucun /proc/*/maps lisible", "UNKNOWN", "medium", "processus", recommendation="Relancer en root pour fiabiliser ce contrôle."))
    active = [s for s in inv.get("services", []) if s.get("active") == "active"]
    if active:
        out.append(Finding(ID, "RUN-SERVICES", "Services web/PHP actifs", "INFO", "info", "systemd", evidence={"services": active}))
    ap = inv.get("apache", {})
    if ap.get("php_modules_enabled"):
        out.append(Finding(ID, "RUN-MODPHP", "Apache mod_php actif : SAPI le plus exposé", "WARN", "high", "apache2", detail=f"Modules : {', '.join(ap['php_modules_enabled'])} ; MPM : {ap.get('mpm')}. L'avis PHP considère mod_php comme le plus à risque (exploitation avant tout code applicatif).", recommendation="Corriger en priorité ; à moyen terme migrer vers PHP-FPM (isolation par pool, utilisateur dédié).", cves=cves, evidence=ap, references=refs(adv, "php-advisory")))
    return out
