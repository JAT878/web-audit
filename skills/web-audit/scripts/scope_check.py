#!/usr/bin/env python3
"""Validate a scope.json (and optional sessions.json) before any testing."""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Scope, ScopeError  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("scope")
    ap.add_argument("--sessions")
    a = ap.parse_args()
    try:
        s = Scope(a.scope)
    except ScopeError as e:
        print(f"FAIL\n{e}")
        sys.exit(1)
    warn = []
    if s.environment == "production":
        warn.append("Target is PRODUCTION — keep max_rps <= 2 and flag this in the report.")
    if not s.excluded_paths:
        warn.append("excluded_paths is empty — add logout, delete, payment and email-sending paths.")
    elif not any("logout" in p or "signout" in p or "sign-out" in p for p in s.excluded_paths):
        warn.append("No logout path in excluded_paths — crawling it will kill authenticated sessions.")
    if s.mode in ("auth", "both"):
        if not a.sessions:
            warn.append("Auth mode: pass --sessions to check session material (need user_a and user_b for IDOR tests).")
        else:
            with open(a.sessions, encoding="utf-8") as f:
                sess = json.load(f)
            for n in ("user_a", "user_b"):
                if n not in sess:
                    warn.append(f"sessions.json has no '{n}' — horizontal access-control tests will be skipped.")
                elif not sess[n].get("identity_markers"):
                    warn.append(f"{n} has no identity_markers — IDOR detection will rely on body similarity only.")
    print("OK — scope is valid")
    print(f"  target: {s.target}\n  hosts: {', '.join(sorted(s.allowed_hosts))}\n  env: {s.environment}  mode: {s.mode}"
          f"  max_rps: {s.max_rps}  state-changing: {s.allow_state_changing}")
    print(f"  authorised by: {s.raw['authorization'].get('authorized_by')} ({s.raw['authorization'].get('reference')})")
    for w in warn:
        print(f"WARN: {w}")


if __name__ == "__main__":
    main()
