#!/usr/bin/env python3
"""Coverage ledger + gap critic (Component 1/4 accountability, no network).

Black-box coverage is only ever what you discovered, so "no findings" can hide a run that
barely tested anything. This reconstructs, from artifacts that already exist, a ledger of every
discovered surface unit and whether it was actually exercised — then flags the gaps a coverage
critic should chase before the report is trusted:

  recon*.json      -> what EXISTS (endpoint_templates, params)         [discoverable surface]
  requests.jsonl   -> what was HIT, and by which actor                 [actual coverage]
  findings.json    -> what was FOUND, and by which detector            [outcomes]

Deterministic (the critic's mechanical half). The coverage-critic agent
(references/agents/coverage-critic.md) reads the gaps and decides whether to send a hunter back.
"""
import argparse
import json
import os
import re
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import load_scope_or_exit  # noqa: E402

_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


def templatize(url: str) -> str:
    path = urlsplit(url).path or "/"
    segs = ["{id}" if (s.isdigit() or _UUID.match(s)) else s for s in path.split("/")]
    return "/".join(segs) or "/"


def has_query(url: str) -> bool:
    return bool(urlsplit(url).query)


def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def main():
    ap = argparse.ArgumentParser(description="Build a coverage ledger and flag coverage gaps (no network).")
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    scope = load_scope_or_exit(a.scope)
    out = a.out

    # --- discoverable surface: merge endpoint_templates from every recon*.json
    units: dict = {}
    param_templates: set = set()
    for name in sorted(os.listdir(out)) if os.path.isdir(out) else []:
        if not (name.startswith("recon") and name.endswith(".json")):
            continue
        rec = load_json(os.path.join(out, name)) or {}
        for t in rec.get("endpoint_templates", []):
            tpl = t.get("template")
            if not tpl:
                continue
            u = units.setdefault(tpl, {"template": tpl, "asset": t.get("asset"),
                                       "id_shape": t.get("id_shape", "none"),
                                       "requested_by": set(), "sources": set(),
                                       "findings": [], "has_params": False})
            u["asset"] = u["asset"] or t.get("asset")
            if t.get("id_shape") and t["id_shape"] != "none":
                u["id_shape"] = t["id_shape"]
            for ex in t.get("example_urls", []):
                if has_query(ex):
                    u["has_params"] = True
        for up in rec.get("urls_with_params", []):
            param_templates.add(templatize(up))

    # --- actual coverage: who hit what (requests.jsonl)
    log = os.path.join(out, "requests.jsonl")
    if os.path.exists(log):
        for line in open(log, encoding="utf-8"):
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            tpl = templatize(e.get("url", ""))
            u = units.setdefault(tpl, {"template": tpl, "asset": None, "id_shape": "none",
                                       "requested_by": set(), "sources": set(),
                                       "findings": [], "has_params": False})
            if e.get("session"):
                u["requested_by"].add(e["session"])

    # --- outcomes: findings per template
    fdoc = load_json(os.path.join(out, "findings.json")) or {}
    checks_run = set()
    for f in fdoc.get("findings", []):
        checks_run.add(f.get("source", "?"))
        tpl = templatize(f.get("url", ""))
        u = units.get(tpl)
        if u is not None:
            u["findings"].append(f.get("id"))
            u["sources"].add(f.get("source", "?"))

    for tpl in param_templates:
        if tpl in units:
            units[tpl]["has_params"] = True

    # --- classify + gaps (the critic's deterministic half)
    ledger, gaps = [], []
    for tpl, u in sorted(units.items()):
        ctxs = u["requested_by"]
        asset_bearing = bool(u["asset"])
        is_admin = "admin" in tpl.lower() or "manage" in tpl.lower()
        if u["findings"]:
            status = "finding"
        elif len([c for c in ctxs if c]) >= 2 and asset_bearing:
            status = "authz-tested"
        elif ctxs:
            status = "tested"
        else:
            status = "untested"
        ledger.append({"template": tpl, "asset": u["asset"], "id_shape": u["id_shape"],
                       "requested_by": sorted(ctxs), "checks": sorted(u["sources"]),
                       "findings": u["findings"], "status": status})
        # gap rules
        if status == "untested":
            gaps.append({"template": tpl, "gap": "discovered but never requested", "priority": "high" if asset_bearing or is_admin else "medium"})
        elif asset_bearing and u["id_shape"] == "sequential" and len([c for c in ctxs if c and c != "anonymous"]) < 2:
            gaps.append({"template": tpl, "gap": "sequential-id object not tested across two users (IDOR unchecked)", "priority": "high"})
        elif is_admin and "anonymous" not in ctxs and not any(c in ctxs for c in ("user_a", "user_b")):
            gaps.append({"template": tpl, "gap": "admin/privileged endpoint not exercised as a lower-privilege actor (function-level authz unchecked)", "priority": "high"})
        if u["has_params"] and not (u["sources"] & {"param_probe", "api_checks"}) and status != "untested":
            gaps.append({"template": tpl, "gap": "endpoint carries parameters that were not probed", "priority": "medium"})

    by_status: dict = {}
    for row in ledger:
        by_status[row["status"]] = by_status.get(row["status"], 0) + 1
    doc = {"target": scope.target, "units": ledger,
           "gaps": sorted(gaps, key=lambda g: (g["priority"] != "high", g["template"])),
           "summary": {"total_units": len(ledger), "by_status": by_status,
                       "checks_run": sorted(c for c in checks_run if c and c != "?"),
                       "open_gaps": len(gaps)}}
    path = os.path.join(out, "coverage-ledger.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    os.replace(tmp, path)

    s = doc["summary"]
    print(f"Coverage: {s['total_units']} units ({', '.join(f'{k}={v}' for k, v in sorted(by_status.items()))}) "
          f"-> {path}")
    if gaps:
        print(f"  {len(gaps)} coverage gap(s) for the critic to weigh:")
        for g in gaps[:15]:
            print(f"    [{g['priority']}] {g['template']}: {g['gap']}")
    else:
        print("  no coverage gaps flagged.")


if __name__ == "__main__":
    main()
