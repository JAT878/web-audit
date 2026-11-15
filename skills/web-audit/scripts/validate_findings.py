#!/usr/bin/env python3
"""Validate findings.json against schema/findings.schema.json plus audit-quality rules. Stdlib only."""
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA = os.path.join(HERE, "..", "schema", "findings.schema.json")
UNREDACTED = [
    (re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}"), "JWT"),
    (re.compile(r"(?:sk|rk)_live_[a-zA-Z0-9]{10,}"), "Stripe secret key"),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key"),
    (re.compile(r"(?i)(?:password|passwd|secret|api[_-]?key|client[_-]?secret)[\"']?\s*[:=]\s*[\"']?(?!\*{4})[^\s\"'&,<*]{8,}"), "secret-looking value"),
    (re.compile(r"(?i)\bBearer\s+(?!<|\*)[a-zA-Z0-9\-_\.=]{20,}"), "bearer token"),
    (re.compile(r"(?i)\bCookie:[ \t]*(?![ \t<])[^\n]*?=(?!\*{4})[^\n;*]{16,}"), "cookie value"),
]


def check_value(val, spec, path, errs):
    if "enum" in spec and val not in spec["enum"]:
        errs.append(f"{path}: '{val}' not in {spec['enum']}")
        return
    t = spec.get("type")
    types = {"string": str, "integer": int, "array": list, "object": dict}
    if t and not isinstance(val, types[t]):
        errs.append(f"{path}: expected {t}")
        return
    if t == "string":
        if "pattern" in spec and not re.search(spec["pattern"], val):
            errs.append(f"{path}: '{val}' does not match {spec['pattern']}")
        if "maxLength" in spec and len(val) > spec["maxLength"]:
            errs.append(f"{path}: longer than {spec['maxLength']} chars")
    if t == "object":
        for r in spec.get("required", []):
            if r not in val or val[r] in ("", None):
                errs.append(f"{path}: missing '{r}'")
        for k, sub in spec.get("properties", {}).items():
            if k in val:
                check_value(val[k], sub, f"{path}.{k}", errs)
    if t == "array" and "items" in spec:
        for i, item in enumerate(val):
            check_value(item, spec["items"], f"{path}[{i}]", errs)


def schema_errors(doc, schema):
    """Use jsonschema if installed (full Draft 2020-12 support); otherwise the builtin subset checker."""
    try:
        import jsonschema
    except ImportError:
        errs = []
        check_value(doc, schema, "$", errs)
        return errs, "builtin"
    v = jsonschema.Draft202012Validator(schema)
    errs = []
    for e in sorted(v.iter_errors(doc), key=lambda e: list(e.absolute_path)):
        loc = "$" + "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in e.absolute_path)
        errs.append(f"{loc}: {e.message}")
    return errs, "jsonschema"


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: validate_findings.py findings.json")
    with open(SCHEMA, encoding="utf-8") as f:
        schema = json.load(f)
    with open(sys.argv[1], encoding="utf-8") as f:
        doc = json.load(f)
    warns = []
    errs, engine = schema_errors(doc, schema)
    ids = set()
    counts = {}
    for i, fd in enumerate(doc.get("findings", [])):
        p = f"findings[{i}] ({fd.get('id', '?')})"
        if fd.get("id") in ids:
            errs.append(f"{p}: duplicate id")
        ids.add(fd.get("id"))
        st = fd.get("status")
        counts[st] = counts.get(st, 0) + 1
        if st == "verified":
            rep = fd.get("reproduction") or {}
            if not rep.get("steps") and not rep.get("curl"):
                errs.append(f"{p}: verified findings need reproduction.steps or reproduction.curl")
            if not fd.get("impact"):
                errs.append(f"{p}: verified findings need impact")
            if not fd.get("remediation"):
                errs.append(f"{p}: verified findings need remediation")
            if not (fd.get("verification") or {}).get("by"):
                warns.append(f"{p}: verification.by not set (who/what independently verified it?)")
        if st == "rejected" and not fd.get("rejection_reason"):
            errs.append(f"{p}: rejected findings need rejection_reason")
        ev, rep = fd.get("evidence") or {}, fd.get("reproduction") or {}
        blob = "\n".join(str(v) for v in [fd.get("description"), *ev.values(), rep.get("curl"), *(rep.get("steps") or [])] if v)
        for rx, label in UNREDACTED:
            if rx.search(blob):
                errs.append(f"{p}: evidence appears to contain an unredacted {label} — redact to the first 4 chars + ****")
    if counts.get("candidate"):
        warns.append(f"{counts['candidate']} finding(s) still 'candidate' — verify or reject them before the final report")
    for w in warns:
        print("WARN:", w)
    if errs:
        print("FAIL")
        for e in errs:
            print("  -", e)
        sys.exit(1)
    print(f"OK ({engine}) — {len(ids)} findings valid ({', '.join(f'{v} {k}' for k, v in sorted(counts.items()))})")


if __name__ == "__main__":
    main()
