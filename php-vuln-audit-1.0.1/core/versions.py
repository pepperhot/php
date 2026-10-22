import re

_UPSTREAM_RE = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")


def _order(c):
    if c == "~":
        return -1
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    return ord(c) + 256


def _cmp_fragment(a, b):
    i = j = 0
    while i < len(a) or j < len(b):
        first_diff = 0
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) and not a[i].isdigit() else 0
            bc = _order(b[j]) if j < len(b) and not b[j].isdigit() else 0
            if ac != bc:
                return ac - bc
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if first_diff:
            return first_diff
    return 0


def _split(v):
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if "-" in v:
        upstream, revision = v.rsplit("-", 1)
    else:
        upstream, revision = v, "0"
    return epoch, upstream, revision


def deb_compare(a, b):
    ea, ua, ra = _split(a)
    eb, ub, rb = _split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    r = _cmp_fragment(ua, ub)
    if r == 0:
        r = _cmp_fragment(ra, rb)
    return (r > 0) - (r < 0)


def upstream_of(version):
    if not version:
        return None
    _, up, _ = _split(version)
    m = _UPSTREAM_RE.match(up)
    if not m:
        return None
    return tuple(int(x) for x in m.groups(default="0"))


def branch_of(version):
    t = upstream_of(version)
    return f"{t[0]}.{t[1]}" if t else None


def parse_triplet(s):
    m = _UPSTREAM_RE.match(s or "")
    return tuple(int(x) for x in m.groups(default="0")) if m else None


def branch_tuple(branch):
    a, b = branch.split(".")[:2]
    return int(a), int(b)


def branch_from_package(name):
    m = re.match(r"^(?:libapache2-mod-)?php(\d+)\.?(\d+)?", name or "")
    if not m:
        return None
    major, minor = m.group(1), m.group(2)
    if minor is None:
        if len(major) == 2:
            return f"{major[0]}.{major[1]}"
        return None
    return f"{major}.{minor}"


def detect_origin(version, os_id=None):
    v = version or ""
    if "deb.sury.org" in v:
        return "sury"
    if "ubuntu" in v:
        return "ubuntu"
    if re.search(r"[~+]deb\d+u\d+", v):
        return "debian"
    if os_id in ("debian", "ubuntu"):
        return os_id
    return "unknown"
