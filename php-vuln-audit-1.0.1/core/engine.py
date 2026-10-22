import logging
from dataclasses import asdict, dataclass, field

log = logging.getLogger("php_audit.engine")

STATUSES = ("VULNERABLE", "ALERT", "UNKNOWN", "WARN", "LIKELY_FIXED", "FIXED", "INFO")
SEVERITIES = ("critical", "high", "medium", "low", "info")


@dataclass
class Finding:
    check: str
    id: str
    title: str
    status: str
    severity: str
    component: str
    detail: str = ""
    recommendation: str = ""
    cves: list = field(default_factory=list)
    evidence: dict = field(default_factory=dict)
    references: list = field(default_factory=list)

    def __post_init__(self):
        if self.status not in STATUSES:
            raise ValueError(f"statut invalide {self.status}")
        if self.severity not in SEVERITIES:
            raise ValueError(f"sévérité invalide {self.severity}")

    def to_dict(self):
        return asdict(self)


EXIT_CODES = {"OK": 0, "VULNERABLE": 1, "ALERT": 2, "INCOMPLETE": 3}


def overall(findings):
    st = {f.status for f in findings}
    if "VULNERABLE" in st:
        return "VULNERABLE"
    if "ALERT" in st:
        return "ALERT"
    if "UNKNOWN" in st:
        return "INCOMPLETE"
    return "OK"


def run_checks(inventory, settings, checks):
    findings, failures = [], []
    for adv in settings["_advisories"]:
        for chk in checks:
            try:
                findings += chk.run(inventory, settings, adv)
            except Exception as e:
                log.exception("échec du contrôle %s", chk.id)
                failures.append(chk.id)
                findings.append(Finding(chk.id, f"{chk.id}-ERR", f"Contrôle {chk.id} en échec", "UNKNOWN", "medium", "outil", detail=str(e), recommendation="Corriger l'erreur puis relancer l'audit."))
    order = {s: i for i, s in enumerate(STATUSES)}
    sev = {s: i for i, s in enumerate(SEVERITIES)}
    findings.sort(key=lambda f: (order[f.status], sev[f.severity], f.id))
    return findings, failures
