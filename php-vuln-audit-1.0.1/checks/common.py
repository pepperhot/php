from core.versions import branch_tuple, parse_triplet

SIZE_UNITS = {"k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}


def all_cves(adv):
    return [c["id"] for c in adv["cves"]]


def refs(adv, *ids):
    by_id = {s["id"]: s["url"] for s in adv["sources"]}
    return [by_id[i] for i in ids if i in by_id]


def is_eol(branch, adv):
    if not branch:
        return False
    return branch_tuple(branch) < branch_tuple(adv["upstream"]["min_supported_branch"])


def eval_upstream(version, adv):
    t = parse_triplet(version)
    if not t:
        return "UNKNOWN", None
    branch = f"{t[0]}.{t[1]}"
    info = adv["upstream"]["branches"].get(branch)
    if info:
        return ("FIXED" if t >= parse_triplet(info["fixed"]) else "VULNERABLE"), info["fixed"]
    if is_eol(branch, adv):
        return "EOL", None
    return "UNKNOWN", None


def parse_size(v):
    s = str(v).strip().lower()
    if s in ("-1", ""):
        return -1
    mult = SIZE_UNITS.get(s[-1], 1)
    num = s[:-1] if s[-1] in SIZE_UNITS else s
    try:
        return int(float(num) * mult)
    except ValueError:
        return None
