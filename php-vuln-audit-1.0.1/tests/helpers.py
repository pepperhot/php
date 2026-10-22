import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT))

from core.config import load_settings  # noqa: E402

_BASE = None


def settings(**detection_overrides):
    global _BASE
    if _BASE is None:
        _BASE = load_settings()
    s = copy.deepcopy({k: v for k, v in _BASE.items() if k != "_rules"})
    s["_rules"] = _BASE["_rules"]
    s["detection"].update(detection_overrides)
    return s


def inventory(name):
    return json.loads((FIX / name).read_text(encoding="utf-8"))


def by_id(findings):
    return {f.id: f for f in findings}
