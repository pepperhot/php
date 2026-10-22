import re

_TYPES = {
    "object": dict,
    "array": list,
    "string": str,
    "boolean": bool,
    "null": type(None),
}


def _is_type(value, t):
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, _TYPES[t])


def validate_builtin(data, schema, path="$"):
    errors = []
    t = schema.get("type")
    if t and not _is_type(data, t):
        return [f"{path}: type attendu {t}, obtenu {type(data).__name__}"]
    if "enum" in schema and data not in schema["enum"]:
        errors.append(f"{path}: valeur {data!r} hors de {schema['enum']}")
    if isinstance(data, str):
        if "pattern" in schema and not re.search(schema["pattern"], data):
            errors.append(f"{path}: {data!r} ne respecte pas {schema['pattern']}")
        if "minLength" in schema and len(data) < schema["minLength"]:
            errors.append(f"{path}: longueur < {schema['minLength']}")
    if _is_type(data, "number"):
        if "minimum" in schema and data < schema["minimum"]:
            errors.append(f"{path}: {data} < {schema['minimum']}")
        if "maximum" in schema and data > schema["maximum"]:
            errors.append(f"{path}: {data} > {schema['maximum']}")
    if isinstance(data, dict):
        for k in schema.get("required", []):
            if k not in data:
                errors.append(f"{path}: clé requise manquante '{k}'")
        props = schema.get("properties", {})
        addl = schema.get("additionalProperties", True)
        for k, v in data.items():
            if k in props:
                errors += validate_builtin(v, props[k], f"{path}.{k}")
            elif addl is False:
                errors.append(f"{path}: clé inattendue '{k}'")
            elif isinstance(addl, dict):
                errors += validate_builtin(v, addl, f"{path}.{k}")
    if isinstance(data, list):
        if "minItems" in schema and len(data) < schema["minItems"]:
            errors.append(f"{path}: moins de {schema['minItems']} élément(s)")
        if "items" in schema:
            for i, item in enumerate(data):
                errors += validate_builtin(item, schema["items"], f"{path}[{i}]")
    return errors


def validate(data, schema):
    try:
        import jsonschema
    except ImportError:
        return validate_builtin(data, schema)
    v = jsonschema.Draft202012Validator(schema)
    return [f"$.{'.'.join(str(p) for p in e.absolute_path)}: {e.message}" for e in v.iter_errors(data)]
