#!/usr/bin/env python3
"""Phase C: session-security checks — fixation / no rotation, cookie scope & lifetime, logout note.

Read-only OBSERVATION only (GET). Nothing here changes target state and the logout endpoint is never
hit. It emits candidate findings for a human to confirm.

Checks:
  1. Session fixation / no rotation (CWE-384) — issue two FRESH anonymous requests and compare the
     Set-Cookie session-cookie VALUE. If every visitor is handed the same session id (or the value
     never changes), that is a fixation / no-rotation indicator.
  2. Cookie scope / lifetime — a session cookie scoped to too broad a Domain, or given an unusually
     long Max-Age / Expires.
  3. Logout invalidation — logout is excluded from automated testing, so this only NOTES whether a
     logout endpoint exists, for manual review.
"""
import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (Client, Findings, asset_of, cap_fields, describe_request, excerpt,  # noqa: E402
                    id_shape_of, load_scope_or_exit, load_sessions, shash, slug)

# Canonical session-cookie names (lowercased).
CANON = {"phpsessid", "jsessionid", "connect.sid", "laravel_session", "asp.net_sessionid",
         "sessionid", "session", "sid", "sess", "ci_session", "_session_id", "rack.session",
         "symfony", "express.sid"}
LOGOUT = re.compile(r"(logout|sign-?out|log-?out|/signoff\b)", re.I)
LONG_LIFETIME = 7 * 24 * 3600  # a session cookie living longer than a week is worth flagging


def _set_cookies(resp):
    if resp is None:
        return []
    try:
        return [c for c in resp.raw.headers.getlist("Set-Cookie") if c]
    except AttributeError:
        v = resp.headers.get("Set-Cookie")
        return [v] if v else []


def _parse_cookie(sc):
    """Parse one Set-Cookie header into (name, value, attrs) with attribute names case-folded."""
    parts = [p for p in sc.split(";")]
    name, _, value = parts[0].strip().partition("=")
    attrs = {}
    for seg in parts[1:]:
        seg = seg.strip()
        if not seg:
            continue
        k, _, v = seg.partition("=")
        attrs[k.strip().lower()] = v.strip()
    return name.strip(), value.strip(), attrs


def is_session_name(name, auth_names):
    n = (name or "").lower()
    if n in auth_names or n in CANON:
        return True
    return "sess" in n or "sid" in n


def auth_cookie_names(sessions):
    names = set()
    for entry in sessions.values():
        if not isinstance(entry, dict):
            continue
        for k in (entry.get("cookies") or {}):
            names.add(k.lower())
        for part in (entry.get("cookie_header") or "").split(";"):
            if "=" in part:
                names.add(part.strip().split("=", 1)[0].lower())
    return names


def long_lifetime(attrs):
    """Return a human string if the cookie persists beyond LONG_LIFETIME, else None."""
    if "max-age" in attrs:
        try:
            ma = int(attrs["max-age"])
            if ma > LONG_LIFETIME:
                return f"Max-Age={ma}s (~{ma // 86400}d)"
        except ValueError:
            pass
    if "expires" in attrs:
        try:
            exp = parsedate_to_datetime(attrs["expires"])
            if exp is not None:
                if exp.tzinfo is None:
                    exp = exp.replace(tzinfo=timezone.utc)
                days = (exp - datetime.now(timezone.utc)).total_seconds() / 86400
                if days > 7:
                    return f"Expires in ~{int(days)}d"
        except (TypeError, ValueError):
            pass
    return None


def logout_endpoints(out_dir, scope):
    found = set()
    for ex in scope.excluded_paths:
        if LOGOUT.search(ex):
            found.add(ex)
    if os.path.isdir(out_dir):
        for fname in sorted(os.listdir(out_dir)):
            if not (fname.startswith("recon") and fname.endswith(".json")):
                continue
            try:
                with open(os.path.join(out_dir, fname), encoding="utf-8") as f:
                    recon = json.load(f)
            except Exception:  # noqa: BLE001
                continue
            pool = [p.get("url", "") for p in recon.get("pages", [])]
            pool += [e for e in recon.get("js_endpoints", []) if isinstance(e, str)]
            pool += (recon.get("browser_crawl", {}) or {}).get("links", [])
            for u in pool:
                if isinstance(u, str) and LOGOUT.search(u):
                    found.add(urlsplit(u).path or u)
    return sorted(found)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sessions")
    ap.add_argument("--session", help="learn the auth cookie name(s) from this session")
    a = ap.parse_args()
    scope = load_scope_or_exit(a.scope)
    sessions = load_sessions(a.sessions)
    auth_names = auth_cookie_names(sessions)
    # Fresh anonymous client (strips server-set cookies before each request → every GET is a new visitor).
    client = Client(scope, a.out, "anonymous")
    F = Findings(a.out, scope.target)
    new_ids = []
    logouts = logout_endpoints(a.out, scope)
    logout_note = ("Logout endpoint(s) exist (" + ", ".join(logouts) + ") but are excluded from automated "
                   "testing — verify by hand that logout invalidates the server-side session.") if logouts else \
                  "No logout endpoint was observed; confirm one exists and invalidates the session server-side."

    fixation_hits, scope_hits = 0, 0
    try:
        # Two fresh anonymous requests to the entry point.
        r1 = client.get(scope.target + "/", allow_redirects=False)
        r2 = client.get(scope.target + "/", allow_redirects=False)

        def session_cookies(resp):
            out = {}
            for sc in _set_cookies(resp):
                name, value, attrs = _parse_cookie(sc)
                if name and is_session_name(name, auth_names):
                    out[name] = (value, attrs)
            return out

        c1 = session_cookies(r1)
        c2 = session_cookies(r2)
        sample_resp = r1 if r1 is not None else r2

        # --- Check 1: fixation / no rotation -----------------------------------------------------
        for name, (v1, attrs1) in c1.items():
            v2 = c2.get(name, (None, {}))[0]
            if v1 and v2 is not None and v1 == v2:
                canonical = name.lower() in CANON or name.lower() in auth_names
                sev = "high" if canonical else "medium"
                fid = f"SESSFIX-{slug(name)}"
                F.add(id=fid,
                      title=f"Session cookie '{name}' is not rotated (fixation risk)",
                      severity=sev, confidence="tentative", category="session-management",
                      auth_context="anonymous", url=scope.target + "/", method="GET",
                      description=(f"Two fresh anonymous requests were both handed the SAME value for the "
                                   f"session-looking cookie '{name}'. The server appears to issue a fixed session id "
                                   f"to every visitor and not rotate it, which enables session fixation: an attacker "
                                   f"who plants a known session id can hijack the victim's session once they log in "
                                   f"(CWE-384). " + logout_note),
                      impact="An attacker who fixes a victim's session id can take over the authenticated session.",
                      evidence={"request": describe_request(sample_resp),
                                "response_status": sample_resp.status_code if sample_resp is not None else None,
                                "response_excerpt": excerpt(f"request1 {name}={v1[:4]}…  request2 {name}={v2[:4]}…  "
                                                            f"identical={v1 == v2}", 200),
                                "notes": f"cookie '{name}' identical across two fresh anonymous requests; canonical session name={canonical}."},
                      remediation=("Issue a fresh, high-entropy session id and rotate it on every login / privilege "
                                   "change; set HttpOnly, Secure and SameSite; invalidate the old id."),
                      cwe="CWE-384", source="session_checks",
                      **cap_fields(grants=["session:fixate"], chain_role="session",
                                   assets=[asset_of(scope.target + "/")], id_shape=id_shape_of(scope.target + "/")))
                fixation_hits += 1
                if fid not in new_ids:
                    new_ids.append(fid)

            # --- Check 2: cookie scope / lifetime ------------------------------------------------
            problems = []
            dom = attrs1.get("domain", "")
            host = urlsplit(scope.target).hostname or ""
            if dom:
                d = dom.lstrip(".").lower()
                if dom.startswith(".") or (d and host and d != host and host.endswith("." + d)):
                    problems.append(f"Domain={dom} is broader than the host {host}")
            ll = long_lifetime(attrs1)
            if ll:
                problems.append(f"long lifetime ({ll}) on a session cookie")
            if problems:
                fid = f"SESSCOOKIE-{slug(name)}"
                F.add(id=fid,
                      title=f"Session cookie '{name}' has weak scope/lifetime",
                      severity="low", confidence="tentative", category="session-management",
                      auth_context="anonymous", url=scope.target + "/", method="GET",
                      description=("The session-looking cookie '" + name + "' is set with: " + "; ".join(problems) +
                                   ". A broad Domain exposes the cookie to sibling subdomains; a long lifetime widens "
                                   "the window for stolen-cookie reuse."),
                      impact="Broader cookie scope or a longer lifetime increases the blast radius of session theft.",
                      evidence={"request": describe_request(sample_resp),
                                "response_status": sample_resp.status_code if sample_resp is not None else None,
                                "response_excerpt": excerpt("attributes: " + json.dumps(attrs1), 200),
                                "notes": "; ".join(problems)},
                      remediation=("Scope session cookies to the exact host, keep them short-lived (ideally browser-session "
                                   "or a short Max-Age), and set HttpOnly/Secure/SameSite."),
                      cwe="CWE-1275", source="session_checks",
                      **cap_fields(chain_role="session",
                                   assets=[asset_of(scope.target + "/")], id_shape=id_shape_of(scope.target + "/")))
                scope_hits += 1
                if fid not in new_ids:
                    new_ids.append(fid)
    finally:
        F.save()
        print(f"Session checks: {client.count} requests; {fixation_hits} fixation/no-rotation, "
              f"{scope_hits} cookie scope/lifetime indicator(s); {F.added} new candidate findings -> {F.path}")
        print("  logout: " + logout_note)
        if new_ids:
            print("  new: " + ", ".join(new_ids[:15]))


if __name__ == "__main__":
    main()
