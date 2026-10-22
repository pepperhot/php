from types import SimpleNamespace

from checks import binaries, external, logs, mitigations, packages, runtime

_MODULES = (packages, binaries, runtime, mitigations, external, logs)

REGISTRY = {m.ID: SimpleNamespace(id=m.ID, title=m.TITLE, run=m.run) for m in _MODULES}


def select(ids=None):
    if not ids:
        return list(REGISTRY.values())
    unknown = set(ids) - set(REGISTRY)
    if unknown:
        raise KeyError(f"Contrôles inconnus : {', '.join(sorted(unknown))}")
    return [REGISTRY[i] for i in ids]
