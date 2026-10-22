import glob
import gzip
import json
import logging
import os
import re
import socket
import subprocess
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("php_audit.collect")

SAPI_DIRS = ("cli", "fpm", "apache2", "cgi")
_PHP_V_RE = re.compile(r"^PHP (\d+\.\d+\.\d+\S*) \(([^)]+)\)")
_POOL_DIRECTIVE_RE = re.compile(r"^(php_admin_value|php_admin_flag|php_value|php_flag)\[([^\]]+)\]\s*=\s*(.*)$")
_TRUE = {"1", "on", "true", "yes"}
_FALSE = {"0", "off", "false", "no", "none", ""}


def norm_bool(v):
    s = str(v).strip().strip('"').strip("'").lower()
    if s in _TRUE:
        return "1"
    if s in _FALSE:
        return "0"
    return str(v).strip().strip('"').strip("'")


def run(cmd, timeout):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return None, "", f"commande introuvable : {cmd[0]}"
    except subprocess.TimeoutExpired:
        return None, "", f"délai dépassé : {' '.join(cmd)}"
    except OSError as e:
        return None, "", str(e)


def parse_ini_text(text, into=None):
    values = {} if into is None else into
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in ";#[":
            continue
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if v.startswith('"'):
            end = v.find('"', 1)
            v = v[1:end] if end > 0 else v[1:]
        else:
            v = v.split(";", 1)[0].strip()
        values[k.strip()] = v
    return values


def read_ini_chain(sapi_dir):
    values, files = {}, []
    main = Path(sapi_dir) / "php.ini"
    chain = ([main] if main.is_file() else []) + sorted(Path(sapi_dir, "conf.d").glob("*.ini"))
    for f in chain:
        try:
            parse_ini_text(f.read_text(encoding="utf-8", errors="replace"), values)
            files.append(str(f))
        except OSError as e:
            log.warning("lecture impossible %s : %s", f, e)
    return values, files


def parse_fpm_pool_text(text, filename=""):
    pools, cur = [], None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line[0] in ";#":
            continue
        m = re.match(r"^\[([^\]]+)\]$", line)
        if m:
            cur = {"file": filename, "pool": m.group(1), "admin": {}, "user": {}, "settings": {}}
            pools.append(cur)
            continue
        if cur is None:
            continue
        m = _POOL_DIRECTIVE_RE.match(line)
        if m:
            kind, key, val = m.groups()
            val = val.split(";", 1)[0].strip().strip('"')
            target = cur["admin"] if kind.startswith("php_admin") else cur["user"]
            target[key.strip()] = norm_bool(val) if kind.endswith("flag") else val
            continue
        if "=" in line:
            k, v = line.split("=", 1)
            cur["settings"][k.strip()] = v.split(";", 1)[0].strip()
    return pools


def collect_os():
    info = {}
    try:
        for line in Path("/etc/os-release").read_text().splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                info[k] = v.strip('"')
    except OSError:
        pass
    return {
        "id": info.get("ID", "unknown"),
        "version_id": info.get("VERSION_ID", ""),
        "codename": info.get("VERSION_CODENAME", ""),
        "pretty": info.get("PRETTY_NAME", ""),
    }


def collect_packages(timeout, errors):
    fmt = "${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Abbrev}\n"
    rc, out, err = run(["dpkg-query", "-W", "-f", fmt, "php*", "libapache2-mod-php*"], timeout)
    if rc is None:
        errors.append(f"dpkg-query : {err.strip()}")
        return []
    pkgs = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 5 or not parts[4].startswith("ii"):
            continue
        pkgs.append({"name": parts[0].split(":")[0], "version": parts[1], "source": parts[2] or parts[0], "source_version": parts[3] or parts[1]})
    return pkgs


def collect_changelog_cves(packages, cve_ids):
    found = {}
    for p in packages:
        src = p["source"]
        if src in found:
            continue
        cl = Path("/usr/share/doc", p["name"], "changelog.Debian.gz")
        if not cl.is_file():
            continue
        try:
            with gzip.open(cl, "rt", encoding="utf-8", errors="replace") as f:
                text = f.read()
            found[src] = sorted(c for c in cve_ids if c in text)
        except OSError:
            continue
    return found


def collect_binaries(globs, timeout, errors):
    seen, out = set(), []
    for pattern in globs:
        for path in sorted(glob.glob(pattern)):
            real = os.path.realpath(path)
            if real in seen or not os.access(real, os.X_OK) or not os.path.isfile(real):
                continue
            seen.add(real)
            entry = {"path": path, "realpath": real, "version": None, "sapi": None, "owner_package": None}
            rc, so, se = run([real, "-v"], timeout)
            m = _PHP_V_RE.match(so.strip()) if so else None
            if m:
                entry["version"], entry["sapi"] = m.group(1), m.group(2)
            else:
                entry["error"] = (se or so or "sortie illisible").strip()[:200]
            rc, so, _ = run(["dpkg", "-S", real], timeout)
            if rc == 0 and so:
                entry["owner_package"] = so.split(":", 1)[0].strip()
            out.append(entry)
    return out


def collect_php_conf(root):
    ini, pools = {}, {}
    for vdir in sorted(Path(root).glob("*")):
        if not vdir.is_dir() or not re.match(r"^\d+\.\d+$", vdir.name):
            continue
        ini[vdir.name] = {}
        for sapi in SAPI_DIRS:
            d = vdir / sapi
            if d.is_dir():
                values, files = read_ini_chain(d)
                ini[vdir.name][sapi] = {"values": values, "files": files}
        pool_list = []
        for f in sorted((vdir / "fpm" / "pool.d").glob("*.conf")):
            try:
                pool_list += parse_fpm_pool_text(f.read_text(encoding="utf-8", errors="replace"), str(f))
            except OSError:
                continue
        if pool_list:
            pools[vdir.name] = pool_list
    return ini, pools


_PHP_OVERRIDE_RE = re.compile(r"^\s*php_(admin_)?(value|flag)\s", re.M)


def collect_apache(root, web_roots, max_htaccess):
    r = Path(root)
    res = {"present": r.is_dir(), "php_modules_enabled": [], "mpm": None, "conf_php_overrides": 0, "htaccess_php_overrides": 0, "htaccess_scanned": 0, "htaccess_truncated": False}
    if not r.is_dir():
        return res
    res["php_modules_enabled"] = sorted(p.stem for p in (r / "mods-enabled").glob("php*.load"))
    mpm = sorted(p.stem for p in (r / "mods-enabled").glob("mpm_*.load"))
    res["mpm"] = mpm[0] if mpm else None
    for sub in ("apache2.conf", "conf-enabled", "sites-enabled"):
        target = r / sub
        files = [target] if target.is_file() else sorted(target.glob("*")) if target.is_dir() else []
        for f in files:
            try:
                res["conf_php_overrides"] += len(_PHP_OVERRIDE_RE.findall(f.read_text(errors="replace")))
            except OSError:
                continue
    for wr in web_roots:
        for dirpath, _, filenames in os.walk(wr):
            if ".htaccess" not in filenames:
                continue
            if res["htaccess_scanned"] >= max_htaccess:
                res["htaccess_truncated"] = True
                return res
            res["htaccess_scanned"] += 1
            try:
                if _PHP_OVERRIDE_RE.search(Path(dirpath, ".htaccess").read_text(errors="replace")):
                    res["htaccess_php_overrides"] += 1
            except OSError:
                continue
    return res


def collect_services(patterns, timeout, errors):
    rc, out, err = run(["systemctl", "list-units", "--type=service", "--all", "--no-legend", "--plain", *patterns], timeout)
    if rc is None:
        errors.append(f"systemctl : {err.strip()}")
        return []
    services = []
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4:
            services.append({"unit": parts[0], "load": parts[1], "active": parts[2], "sub": parts[3]})
    return services


_STALE_RE = re.compile(r"(php|libphp|apache2|httpd|frankenphp|lsphp)")


def collect_stale_processes(proc="/proc"):
    res = {"scanned": 0, "unreadable": 0, "matches": []}
    for pid_dir in glob.glob(f"{proc}/[0-9]*"):
        pid = os.path.basename(pid_dir)
        try:
            with open(f"{pid_dir}/maps", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except (PermissionError, ProcessLookupError):
            res["unreadable"] += 1
            continue
        except OSError:
            continue
        res["scanned"] += 1
        paths = sorted({ln.split(None, 5)[5].strip() for ln in lines if ln.rstrip().endswith("(deleted)") and len(ln.split(None, 5)) == 6 and _STALE_RE.search(ln)})
        if paths:
            try:
                comm = Path(pid_dir, "comm").read_text().strip()
            except OSError:
                comm = "?"
            res["matches"].append({"pid": int(pid), "comm": comm, "paths": paths})
    return res


def collect_containers(cfg, timeout, errors):
    if not cfg.get("enabled"):
        return {"enabled": False, "items": []}
    rc, out, err = run(["docker", "ps", "--format", "{{.ID}}\t{{.Image}}\t{{.Names}}"], timeout)
    if rc != 0:
        errors.append(f"docker ps : {(err or out).strip()[:200]}")
        return {"enabled": True, "items": []}
    items = []
    for line in out.splitlines():
        cid, image, name = (line.split("\t") + ["", "", ""])[:3]
        item = {"id": cid, "image": image, "name": name, "php_version": None}
        if cfg.get("exec_version_probe"):
            rc2, so, _ = run(["docker", "exec", cid, "php", "-r", "echo PHP_VERSION;"], timeout)
            if rc2 == 0:
                item["php_version"] = so.strip()
        items.append(item)
    return {"enabled": True, "items": items}


def collect_http(urls, timeout):
    out = []
    for u in urls:
        try:
            req = urllib.request.Request(u, method="HEAD")
            with urllib.request.urlopen(req, timeout=timeout) as r:
                out.append({"url": u, "status": r.status, "x_powered_by": r.headers.get("X-Powered-By"), "server": r.headers.get("Server")})
        except Exception as e:
            out.append({"url": u, "error": str(e)[:200]})
    return out


def collect(settings):
    c = settings["collect"]
    t = c["command_timeout_seconds"]
    errors = []
    cve_ids = sorted({cve["id"] for a in settings["_advisories"] for cve in a["cves"]})
    packages = collect_packages(t, errors)
    ini, pools = collect_php_conf(c["php_conf_root"])
    inv = {
        "schema_version": 1,
        "collected_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "hostname": socket.gethostname(),
        "euid": os.geteuid() if hasattr(os, "geteuid") else None,
        "os": collect_os(),
        "packages": packages,
        "changelog_cves": collect_changelog_cves(packages, cve_ids),
        "binaries": collect_binaries(c["php_binary_globs"], t, errors),
        "ini": ini,
        "fpm_pools": pools,
        "apache": collect_apache(c.get("apache_conf_root", "/etc/apache2"), c.get("web_roots", []), c.get("max_htaccess_files", 5000)),
        "services": collect_services(c.get("systemd_units", []), t, errors),
        "stale_processes": collect_stale_processes() if c.get("scan_proc_maps", True) else None,
        "containers": collect_containers(c.get("containers", {}), t, errors),
        "http_probes": collect_http(c.get("http_probes", []), t),
        "errors": errors,
    }
    if inv["euid"] not in (0, None):
        inv["errors"].append("Exécution non-root : /proc/*/maps et certains journaux peuvent être illisibles (résultats partiels).")
    return inv


def save_inventory(inv, path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(inv, f, ensure_ascii=False, indent=2)
