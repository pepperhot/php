from checks.common import all_cves, eval_upstream
from core.engine import Finding

ID = "EXT"
TITLE = "Conteneurs et sondes HTTP"


def run(inv, settings, adv):
    cves = all_cves(adv)
    out = []
    cont = inv.get("containers") or {}
    for c in cont.get("items", []):
        comp = f"container:{c.get('name') or c.get('id')}"
        if not c.get("php_version"):
            out.append(Finding(ID, f"EXT-{comp}", f"{comp} ({c.get('image')}) : version PHP non sondée", "UNKNOWN", "medium", comp, recommendation="docker exec <id> php -v (ou SBOM / scanner d'image), puis reconstruire depuis une image corrigée.", evidence=c))
            continue
        st, fixed = eval_upstream(c["php_version"], adv)
        status = {"FIXED": "FIXED", "VULNERABLE": "VULNERABLE"}.get(st, "UNKNOWN")
        out.append(Finding(ID, f"EXT-{comp}", f"{comp} : PHP {c['php_version']}", status, "info" if status == "FIXED" else "critical" if status == "VULNERABLE" else "high", comp, detail="Image dérivée d'une distribution : un backport peut conserver le numéro upstream." if status != "FIXED" else "", recommendation="Reconstruire avec --pull depuis une image corrigée et recréer le conteneur." if status != "FIXED" else "", cves=cves, evidence={**c, "fixed_upstream": fixed}))
    for p in inv.get("http_probes", []):
        comp = f"http:{p['url']}"
        xpb = p.get("x_powered_by") or ""
        if "error" in p or not xpb.startswith("PHP/"):
            out.append(Finding(ID, f"EXT-{comp}", f"{p['url']} : version PHP non exposée", "INFO", "info", comp, detail=p.get("error", "En-tête X-Powered-By absent (expose_php=Off) : normal."), evidence=p))
            continue
        ver = xpb.split("/", 1)[1]
        st, fixed = eval_upstream(ver, adv)
        status = "FIXED" if st == "FIXED" else "UNKNOWN"
        out.append(Finding(ID, f"EXT-{comp}", f"{p['url']} annonce PHP {ver}", status, "info" if status == "FIXED" else "medium", comp, detail="" if status == "FIXED" else "En-tête non fiable : les paquets distribution backportent sans changer le numéro. Croiser avec le contrôle PKG.", cves=cves, evidence={**p, "fixed_upstream": fixed}))
    return out
