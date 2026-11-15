#!/usr/bin/env python3
"""Render report.md from scope.json + findings.json."""
import argparse
import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import now_iso  # noqa: E402

ORDER = ["critical", "high", "medium", "low", "info"]


def fence(text):
    return "```\n" + (text or "").replace("```", "'''") + "\n```"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True)
    ap.add_argument("--findings", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--include-candidates", action="store_true", help="draft report: show unverified candidates too")
    a = ap.parse_args()
    with open(a.scope, encoding="utf-8") as f:
        scope = json.load(f)
    with open(a.findings, encoding="utf-8") as f:
        doc = json.load(f)
    fs = doc["findings"]
    shown_status = {"verified"} | ({"candidate"} if a.include_candidates else set())
    shown = sorted([x for x in fs if x["status"] in shown_status], key=lambda x: (ORDER.index(x["severity"]), x["id"]))
    rejected = [x for x in fs if x["status"] == "rejected"]
    pending = [x for x in fs if x["status"] == "candidate"]
    c = Counter(x["severity"] for x in shown)
    auth = scope.get("authorization", {})

    L = [f"# Web security assessment — {scope['target']}", ""]
    if scope.get("environment") == "production":
        L += ["> **Tested against PRODUCTION.**", ""]
    if a.include_candidates and pending:
        L += ["> **DRAFT** — includes unverified candidate findings.", ""]
    L += ["| | |", "|---|---|",
          f"| Target | {scope['target']} |",
          f"| Hosts in scope | {', '.join(scope['allowed_hosts'])} |",
          f"| Environment | {scope.get('environment')} |",
          f"| Mode | {scope.get('mode')} (black-box{' + authenticated' if scope.get('mode') in ('auth', 'both') else ''}) |",
          f"| Authorised by | {auth.get('authorized_by', '')} — {auth.get('reference', '')} |",
          f"| Test window | {auth.get('window', auth.get('date', ''))} |",
          f"| Report generated | {now_iso()} |", ""]
    L += ["## Summary", ""]
    L += ["| Severity | Count |", "|---|---|"] + [f"| {s.title()} | {c.get(s, 0)} |" for s in ORDER] + [""]
    top = [x for x in shown if x["severity"] in ("critical", "high")][:5]
    if top:
        L += ["**Fix first:**", ""] + [f"- **{x['title']}** ({x['severity']}) — {x.get('impact', '')}" for x in top] + [""]
    elif shown:
        L += ["No critical or high severity issues were verified.", ""]
    else:
        L += ["No issues were verified within the tested scope.", ""]

    L += ["## Findings", ""]
    for i, x in enumerate(shown, 1):
        L += [f"### {i}. {x['title']}", "",
              f"**Severity:** {x['severity'].title()} · **Confidence:** {x['confidence']} · **Status:** {x['status']} · "
              f"**Category:** {x['category']} · **Context:** {x['auth_context']}" + (f" · **{x['cwe']}**" if x.get("cwe") else ""), "",
              f"**URL:** `{x['method']} {x['url']}`", "", x["description"], ""]
        if x.get("impact"):
            L += [f"**Impact:** {x['impact']}", ""]
        ev = x.get("evidence") or {}
        L += ["**Evidence**", "", fence(ev.get("request", ""))]
        if ev.get("response_status") is not None:
            L += [f"Response status: `{ev['response_status']}`"]
        if ev.get("notes"):
            L += ["", ev["notes"]]
        if ev.get("response_excerpt"):
            L += ["", fence(ev["response_excerpt"])]
        rep = x.get("reproduction") or {}
        if rep.get("steps") or rep.get("curl"):
            L += ["", "**Reproduce**", ""] + [f"{n}. {s}" for n, s in enumerate(rep.get("steps", []), 1)]
            if rep.get("curl"):
                L += ["", fence(rep["curl"])]
        if x.get("remediation"):
            L += ["", f"**Fix:** {x['remediation']}"]
        L += [""]

    if rejected:
        L += ["## Appendix A — Ruled out", "", "| Candidate | Reason |", "|---|---|"]
        L += [f"| {x['title']} (`{x['id']}`) | {x.get('rejection_reason', '')} |" for x in rejected] + [""]
    if pending and not a.include_candidates:
        L += ["## Appendix B — Not yet verified", "", f"{len(pending)} candidate(s) were not verified and are excluded above: "
              + ", ".join(f"`{x['id']}`" for x in pending), ""]
    L += ["## Method", "",
          "Black-box testing of the running application: reconnaissance and crawling, configuration checks (TLS, headers, cookies, CORS), "
          "sensitive-file discovery, unauthenticated and cross-user/cross-role access-control replay, and manual checks. "
          "All candidate findings were independently re-tested before inclusion. Requests were rate limited "
          f"to {scope.get('max_rps', 3)}/s and {'included' if scope.get('allow_state_changing') else 'excluded'} state-changing methods. "
          "A full request log is kept in requests.jsonl.", ""]
    with open(a.out, "w", encoding="utf-8") as f:
        f.write("\n".join(L))
    print(f"Report: {len(shown)} findings ({', '.join(f'{c[s]} {s}' for s in ORDER if c.get(s))}) -> {a.out}")


if __name__ == "__main__":
    main()
