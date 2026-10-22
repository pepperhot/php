import glob
import gzip
import os
import re
import time

from core.engine import Finding

ID = "LOG"
TITLE = "Recherche d'indicateurs dans les journaux"
_MASK = [
    (re.compile(r"(PHPSESSID=)[^;\s\"]+"), r"\1***"),
    (re.compile(r"(Authorization:\s*\S+\s+)\S+", re.I), r"\1***"),
]


def mask(line, limit=300):
    for rx, rep in _MASK:
        line = rx.sub(rep, line)
    return line[:limit]


def _open(path):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, encoding="utf-8", errors="replace")


def scan_lines(lines, rules, source_type, results, max_samples, max_lines, fname):
    applicable = [r for r in rules if source_type in r["applies_to"]]
    n = 0
    for n, line in enumerate(lines, 1):
        if n > max_lines:
            results["_truncated"].append(fname)
            break
        for r in applicable:
            if r["_re"].search(line):
                res = results.setdefault(r["id"], {"hits": 0, "samples": [], "files": set()})
                res["hits"] += 1
                res["files"].add(fname)
                if len(res["samples"]) < max_samples:
                    res["samples"].append(mask(line.rstrip("\n")))
    return n


def scan(settings):
    det = settings["detection"]
    rules = settings["_rules"]["rules"]
    max_age = det.get("max_file_age_days", 14) * 86400
    now = time.time()
    results = {"_truncated": [], "_files": [], "_unreadable": [], "_missing_sources": []}
    for src in det["log_sources"]:
        files = sorted({f for p in src["paths"] for f in glob.glob(p)})
        if not files:
            results["_missing_sources"].append(src["name"])
            continue
        for f in files:
            try:
                if now - os.path.getmtime(f) > max_age:
                    continue
                with _open(f) as fh:
                    lines = scan_lines(fh, rules, src["type"], results, det.get("max_samples_per_rule", 5), det.get("max_lines_per_file", 2000000), f)
                results["_files"].append({"file": f, "source": src["name"], "lines": lines})
            except (OSError, EOFError) as e:
                results["_unreadable"].append(f"{f}: {e.__class__.__name__}")
    return results


def to_findings(results, settings):
    det = settings["detection"]
    thr = {"low": 50, "medium": 5, "high": 1, **det.get("min_hits_to_flag", {})}
    by_id = {r["id"]: r for r in settings["_rules"]["rules"]}
    out = []
    for rid, res in sorted((k, v) for k, v in results.items() if not k.startswith("_")):
        r = by_id[rid]
        flagged = res["hits"] >= thr[r["severity"]]
        out.append(Finding(ID, rid, f"{r['title']} : {res['hits']} occurrence(s)", "ALERT" if flagged else "INFO", r["severity"] if flagged else "info", "journaux", detail=f"{r['rationale']} Faux positifs : {r['false_positives']}", recommendation="Corréler (horodatage, IP source, worker) avec les autres règles avant toute conclusion. Un indicateur seul ne prouve pas une exploitation." if flagged else "", cves=r["cves"], evidence={"hits": res["hits"], "threshold": thr[r["severity"]], "files": sorted(res["files"])[:20], "samples": res["samples"]}))
    gaps = []
    if results["_missing_sources"]:
        gaps.append(f"sources absentes : {', '.join(results['_missing_sources'])}")
    if results["_unreadable"]:
        gaps.append(f"illisibles : {len(results['_unreadable'])}")
    if results["_truncated"]:
        gaps.append(f"tronqués : {len(results['_truncated'])}")
    if not results["_files"]:
        out.append(Finding(ID, "LOG-NODATA", "Aucun journal analysé", "UNKNOWN", "medium", "journaux", detail="; ".join(gaps), recommendation="Vérifier detection.log_sources, les droits de lecture et la rétention."))
    elif gaps:
        out.append(Finding(ID, "LOG-GAPS", "Couverture des journaux partielle", "INFO", "low", "journaux", detail="; ".join(gaps), evidence={"unreadable": results["_unreadable"][:20], "truncated": results["_truncated"][:20]}))
    out.append(Finding(ID, "LOG-LIMITS", "Limites de la détection par journaux", "INFO", "info", "journaux", detail="Les formats combined n'enregistrent ni Content-Type, ni corps, ni taille de requête ; une exploitation réussie peut ne laisser aucune trace PHP. Absence d'alerte ≠ absence de compromission.", evidence={"files_scanned": len(results["_files"])}))
    return out


def run(inv, settings, adv):
    if not settings["detection"].get("enabled", True):
        return [Finding(ID, "LOG-OFF", "Détection désactivée", "INFO", "info", "journaux")]
    return to_findings(scan(settings), settings)
