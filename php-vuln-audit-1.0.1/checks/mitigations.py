from checks import packages
from checks.common import parse_size, refs
from core.collect import norm_bool
from core.engine import Finding
from core.versions import branch_from_package

ID = "MIT"
TITLE = "Mesures compensatoires (php.ini, pools FPM, Apache)"
WEB_SAPIS = ("fpm", "apache2", "cgi")


def _branch_status(inv, settings, adv):
    st = {}
    for f in packages.run(inv, settings, adv):
        src = f.evidence.get("source_package")
        b = branch_from_package(src) if src else None
        if b and f.status in ("FIXED", "LIKELY_FIXED", "VULNERABLE", "UNKNOWN"):
            st[b] = f.status
    return st


def _ok(m, value):
    if m["directive"] in ("session.upload_progress.enabled", "fatal_error_backtraces"):
        return norm_bool(value) == m["recommended"]
    if m["directive"] == "memory_limit":
        return str(value).strip() == "-1"
    if m["directive"] == "post_max_size":
        size = parse_size(value)
        return size is not None and size != -1 and 0 < size <= m["recommended_max_bytes"]
    return None


def _applies(m, branch):
    return m["branches"] == "*" or m["branches"] == branch


def _contexts(inv):
    for branch, sapis in sorted(inv.get("ini", {}).items()):
        pools = inv.get("fpm_pools", {}).get(branch, [])
        for sapi in WEB_SAPIS:
            if sapi not in sapis:
                continue
            base = sapis[sapi]["values"]
            if sapi == "fpm" and pools:
                for p in pools:
                    eff, src = {}, {}
                    for k in set(base) | set(p["user"]) | set(p["admin"]):
                        if k in p["admin"]:
                            eff[k], src[k] = p["admin"][k], "php_admin"
                        elif k in p["user"]:
                            eff[k], src[k] = p["user"][k], "php_value (surchargeable)"
                        else:
                            eff[k], src[k] = base[k], "php.ini"
                    yield branch, f"fpm:{p['pool']}", eff, src, p
            else:
                yield branch, sapi, base, {k: "php.ini" for k in base}, None


def run(inv, settings, adv):
    out = []
    bstat = _branch_status(inv, settings, adv)
    for branch, ctx, values, origin, pool in _contexts(inv):
        patched = bstat.get(branch) in ("FIXED",)
        for m in adv["mitigations"]:
            if not _applies(m, branch):
                continue
            val = values.get(m["directive"], m.get("default", ""))
            src = origin.get(m["directive"], "défaut PHP")
            ok = _ok(m, val)
            fid = f"MIT-{branch}-{ctx}-{m['id']}"
            ev = {"branch": branch, "context": ctx, "directive": m["directive"], "value": val, "set_by": src, "package_status": bstat.get(branch, "inconnu")}
            title = f"PHP {branch} {ctx} : {m['directive']} = {val}"
            if ok:
                weak = "surchargeable" in src and not patched
                out.append(Finding(ID, fid, title, "WARN" if weak else "INFO", "low" if weak else "info", ctx, detail=m["scope"], recommendation="Valeur posée par php_value (modifiable par l'application) : utiliser php_admin_value/php_admin_flag." if "surchargeable" in src else "", cves=m["cves"], evidence=ev))
            elif patched:
                if m["id"] == "MIT-UPLOAD-PROGRESS":
                    out.append(Finding(ID, fid, title, "INFO", "low", ctx, detail="Version corrigée. L'avis PHP recommande de désactiver upload progress même après correctif si la fonction est inutilisée.", recommendation="php_admin_flag[session.upload_progress.enabled] = off si inutilisé.", cves=m["cves"], evidence=ev, references=refs(adv, "ghsa-619")))
            else:
                out.append(Finding(ID, fid, title, "WARN", "medium", ctx, detail=f"Mitigation absente sur une branche non confirmée corrigée. {m['scope']}", recommendation="Mitigation temporaire uniquement, ne remplace pas la mise à jour. Tester en préproduction.", cves=m["cves"], evidence=ev, references=refs(adv, "php-advisory", "certfr-ale")))
        if pool is not None:
            mr = pool["settings"].get("pm.max_requests", "0")
            out.append(Finding(ID, f"MIT-{branch}-{ctx}-MAXREQ", f"PHP {branch} {ctx} : pm.max_requests = {mr}", "INFO", "info", ctx, detail="pm.max_requests=1 supprime la réutilisation de worker (CVE-2026-109619) au prix des performances.", evidence={"user": pool["settings"].get("user"), "listen": pool["settings"].get("listen")}))
    ap = inv.get("apache", {})
    if ap.get("php_modules_enabled") and (ap.get("htaccess_php_overrides") or ap.get("conf_php_overrides")):
        out.append(Finding(ID, "MIT-APACHE-OVERRIDES", "Surcharges php_value/php_flag détectées (Apache)", "WARN", "medium", "apache2", detail=f".htaccess concernés : {ap.get('htaccess_php_overrides')} / scannés : {ap.get('htaccess_scanned')}{' (tronqué)' if ap.get('htaccess_truncated') else ''} ; directives dans la conf : {ap.get('conf_php_overrides')}. Sous mod_php ces directives s'appliquent avant l'initialisation de la requête (chemin diagnostics INI de CVE-2026-109619) et peuvent réactiver session.upload_progress.", recommendation="Imposer les mitigations via php_admin_flag/php_admin_value dans la conf Apache ; supprimer les directives obsolètes ; AllowOverride restrictif.", cves=["CVE-2026-109619"], evidence=ap, references=refs(adv, "ghsa-619")))
    return out
