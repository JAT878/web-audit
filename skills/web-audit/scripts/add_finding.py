#!/usr/bin/env python3
"""Add or update a finding (manual finding, or verification result) in findings.json.

  add_finding.py --out OUT --json '{"id": "XSS-reflected-search", ...}'
  add_finding.py --out OUT --update HDR-missing-csp --set status=verified --set verification.by=subagent
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import now_iso, redact  # noqa: E402


def set_path(d, dotted, value):
    keys = dotted.split(".")
    for k in keys[:-1]:
        d = d.setdefault(k, {})
    try:
        value = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        pass
    d[keys[-1]] = value


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--json", help="full finding object")
    ap.add_argument("--update", help="id of an existing finding to modify")
    ap.add_argument("--set", action="append", default=[], help="dotted.key=value (value may be JSON)")
    ap.add_argument("--target", help="target URL if findings.json does not exist yet")
    a = ap.parse_args()
    path = os.path.join(a.out, "findings.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    else:
        doc = {"target": a.target or "", "generated_at": now_iso(), "findings": []}
    if a.json:
        fd = json.loads(a.json)
        fd.setdefault("source", "manual")
        fd.setdefault("status", "candidate")
        ev = fd.get("evidence") or {}
        for k in ("request", "response_excerpt", "notes"):
            if isinstance(ev.get(k), str):
                ev[k] = redact(ev[k])
        doc["findings"] = [x for x in doc["findings"] if x["id"] != fd["id"]] + [fd]
        print(f"Saved {fd['id']}")
    elif a.update:
        match = [x for x in doc["findings"] if x["id"] == a.update]
        if not match:
            sys.exit(f"No finding with id {a.update}")
        for kv in a.set:
            k, v = kv.split("=", 1)
            set_path(match[0], k, v)
        if any(kv.startswith("status=") for kv in a.set):
            match[0].setdefault("verification", {})["at"] = now_iso()
        print(f"Updated {a.update}")
    else:
        sys.exit("Pass --json or --update")
    doc["generated_at"] = now_iso()
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)


if __name__ == "__main__":
    main()
