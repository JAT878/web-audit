#!/usr/bin/env python3
"""Phase C: authentication-surface probing — user enumeration and reset-token leakage.

Read-only OBSERVATION only. For auth-related endpoints found in recon (forgot/reset/password,
login, register, account) this looks at how the server *responds* — it never brute forces, never
POSTs, never consumes a reset token, and sends at most a couple of GETs per endpoint (through the
scope rate limit). It emits candidate findings for a human to confirm.

Checks:
  1. User enumeration (CWE-204) — a forgot/login/register endpoint that answers differently for a
     known account vs a clearly-nonexistent one (status, body wording, or a notable length delta).
  2. Reset-token-in-response / predictable reset (CWE-640) — a forgot/reset response that hands a
     reset token or reset link straight back in the body.
  3. Forced-browsing note — a short manual-review note when recon shows obvious auth-only endpoints
     (authz_replay already tests anonymous access; this does NOT duplicate those findings).

Safety: /forgot-style endpoints can trigger emails, so an identity value is only ever sent to a
clearly-nonexistent test address OR to an account already under test (never an arbitrary real user);
excluded paths are respected; requests are GET only.
"""
import argparse
import json
import os
import re
import sys
import uuid
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (Client, Findings, asset_of, cap_fields, describe_request, excerpt,  # noqa: E402
                    id_shape_of, load_scope_or_exit, load_sessions, shash, slug)

FORGOT = re.compile(r"(forgot|reset|recover|lost.?password|password.?reset|/password\b)", re.I)
LOGIN = re.compile(r"(login|sign-?in|log-?in|/auth(?:enticate)?\b)", re.I)
REGISTER = re.compile(r"(register|sign-?up|create-?account|/join\b)", re.I)
IDENT_PARAM = re.compile(r"(email|e-?mail|user(name)?|login|account|mail|identifier)", re.I)
EMAIL = re.compile(r"[^@\s\"'<>]+@[^@\s\"'<>]+\.[^@\s\"'<>]+")
# Phrases a server uses to say "no such account" — an enumeration oracle when only one side shows it.
NEG = re.compile(r"(no account|not found|no such|does ?n[o']?t exist|unknown|not registered|"
                 r"isn[']?t registered|no user|invalid (?:user|email|account))", re.I)
# A reset token / link handed back in the response body.
RESET_LEAK = re.compile(r"(reset[_-]?token|reset[_-]?url|reset[_-]?link|/reset\?token=|"
                        r"[\"']token[\"']\s*:\s*[\"'][^\"']{6,}|token=[A-Za-z0-9._%-]{8,})", re.I)
# Well-known auth paths probed in addition to recon — recon's JS/link miner only surfaces endpoints
# under a fixed prefix set, so standard forgot/login/register URLs are often missing from it. These
# are GET-only, in-scope, and the known-vs-unknown differential suppresses false positives on paths
# that do not exist (they return the app's generic/soft-404 response identically for both).
COMMON_AUTH_PATHS = ("/forgot", "/forgot-password", "/forgotpassword", "/password/forgot",
                     "/account/forgot", "/recover", "/recover-account", "/users/password/new",
                     "/login", "/signin", "/register", "/signup", "/account")


def _recon_files(out_dir):
    if not os.path.isdir(out_dir):
        return []
    return [f for f in sorted(os.listdir(out_dir)) if f.startswith("recon") and f.endswith(".json")]


def _abs(scope, url):
    if url.startswith("/"):
        return scope.target + url
    return url


def gather_auth_endpoints(out_dir, scope):
    """Return (enum_targets, auth_only). enum_targets: {base_url: param_name} for forgot/login/
    register endpoints that take an identity parameter. auth_only: set of recon paths that redirect
    to login (obvious auth-only surface, for the forced-browsing note)."""
    enum_targets, auth_only = {}, set()
    candidates = set()
    for fname in _recon_files(out_dir):
        try:
            with open(os.path.join(out_dir, fname), encoding="utf-8") as f:
                recon = json.load(f)
        except Exception:  # noqa: BLE001
            continue
        for pg in recon.get("pages", []):
            if pg.get("url"):
                candidates.add(pg["url"])
        for ep in recon.get("js_endpoints", []):
            if isinstance(ep, str) and ep.startswith("/"):
                candidates.add(_abs(scope, ep))
        for u in recon.get("urls_with_params", []):
            if isinstance(u, str):
                candidates.add(_abs(scope, u))
        for form in recon.get("forms", []):
            if (form.get("method", "GET") or "GET").upper() != "GET":
                continue
            action = form.get("action_abs") or form.get("page")
            if not action:
                continue
            names = [i.get("name") for i in form.get("inputs", []) if i.get("name")]
            ident = next((n for n in names if IDENT_PARAM.fullmatch(n or "") or IDENT_PARAM.search(n or "")), None)
            if ident:
                candidates.add(action + ("?" if "?" not in action else "&") + ident + "=")
        for t in recon.get("endpoint_templates", []):
            tmpl = t.get("template") if isinstance(t, dict) else t
            if isinstance(tmpl, str) and tmpl.startswith("/"):
                candidates.add(_abs(scope, tmpl))
        for rd in recon.get("redirects_to_login", []):
            if isinstance(rd, dict) and rd.get("url"):
                auth_only.add(urlsplit(rd["url"]).path or rd["url"])

    # Merge well-known auth paths (recon's miner may not surface them).
    for p in COMMON_AUTH_PATHS:
        candidates.add(scope.target + p)

    for url in candidates:
        parts = urlsplit(url)
        path = parts.path or "/"
        is_forgot = bool(FORGOT.search(path))
        is_auth = bool(LOGIN.search(path) or REGISTER.search(path))
        if not (is_forgot or is_auth):
            continue
        # pick the identity parameter: an identity-looking query key, else default to 'email'
        param = None
        for k, _ in parse_qsl(parts.query, keep_blank_values=True):
            if IDENT_PARAM.search(k):
                param = k
                break
        # login/register endpoints are only usable as a GET oracle if they already expose an
        # identity parameter in recon; forgot endpoints default to 'email'.
        if param is None:
            if is_forgot:
                param = "email"
            else:
                continue
        base = urlunsplit((parts.scheme, parts.netloc, path, "", ""))
        enum_targets.setdefault(base, param)
    return enum_targets, auth_only


def known_emails(sessions, prefer):
    """Email identity markers for accounts already under test (safe to probe). Prefer --session."""
    out, seen = [], set()

    def add_from(entry):
        for m in (entry.get("identity_markers") or []):
            for e in EMAIL.findall(str(m)):
                if e.lower() not in seen:
                    seen.add(e.lower())
                    out.append(e)

    if prefer and prefer in sessions:
        add_from(sessions[prefer])
    for name, entry in sessions.items():
        if name != prefer and isinstance(entry, dict):
            add_from(entry)
    return out


def build_url(base, param, value):
    parts = urlsplit(base)
    q = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != param]
    q.append((param, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), ""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sessions")
    ap.add_argument("--session", help="source known account(s) under test from this session")
    ap.add_argument("--max-endpoints", type=int, default=12, help="cap auth endpoints probed")
    a = ap.parse_args()
    scope = load_scope_or_exit(a.scope)
    sessions = load_sessions(a.sessions)
    # Enumeration/reset are pre-auth oracles — probe anonymously.
    client = Client(scope, a.out, "anonymous")
    F = Findings(a.out, scope.target)

    enum_targets, auth_only = gather_auth_endpoints(a.out, scope)
    knowns = known_emails(sessions, a.session)
    unknown = f"audit-nouser-{uuid.uuid4().hex[:8]}@example.invalid"
    enum_hits, leak_hits = 0, 0
    probed = 0
    new_ids = []

    try:
        if not knowns:
            # Without a known-good account we cannot safely build an enumeration oracle.
            pass
        else:
            known = knowns[0]
            for base, param in sorted(enum_targets.items())[:a.max_endpoints]:
                if not scope.in_scope(base) or scope.excluded(base) or scope.state_changing_path(base):
                    continue
                probed += 1
                ku = build_url(base, param, known)
                uu = build_url(base, param, unknown)
                kr = client.get(ku, allow_redirects=False)
                ur = client.get(uu, allow_redirects=False)
                if kr is None or ur is None:
                    continue
                kb, ub = kr.text or "", ur.text or ""
                caveat = ("Caveat: a forgot/reset endpoint may send an email; this probe only used an "
                          "account already under test and a reserved .invalid non-existent address, and "
                          "sent GET only (no token was consumed).")

                # --- Check 1: user enumeration -------------------------------------------------
                status_diff = kr.status_code != ur.status_code
                neg_diff = bool(NEG.search(kb)) != bool(NEG.search(ub))
                lens = sorted((len(kb), len(ub)))
                len_diff = lens[1] > 0 and (lens[1] - lens[0]) >= 12 and (lens[1] - lens[0]) / lens[1] >= 0.15
                if status_diff or neg_diff or len_diff:
                    enum_hits += 1
                    why = []
                    if status_diff:
                        why.append(f"status {kr.status_code} vs {ur.status_code}")
                    if neg_diff:
                        why.append("only one response carries a 'no such account' message")
                    if len_diff:
                        why.append(f"body length {len(kb)} vs {len(ub)} bytes")
                    fid = f"AUTHENUM-{slug(urlsplit(base).path)}-{shash(base + param)}"
                    F.add(id=fid,
                          title=f"User enumeration via {urlsplit(base).path} (parameter '{param}')",
                          severity="medium", confidence="tentative", category="authentication",
                          auth_context="anonymous", url=ku, method="GET",
                          description=(f"The endpoint responds differently for a known account vs a clearly "
                                       f"non-existent one ({'; '.join(why)}). This lets an attacker confirm which "
                                       f"email addresses / usernames have accounts. OBSERVED only — not brute forced. "
                                       + caveat),
                          impact="An attacker can enumerate valid accounts to seed credential-stuffing, phishing, or targeted resets.",
                          evidence={"request": describe_request(kr),
                                    "response_status": kr.status_code,
                                    "response_excerpt": excerpt(f"known -> {kb[:200]}\nunknown -> {ub[:200]}", 500),
                                    "notes": f"unknown address used: {unknown}; distinguishers: {'; '.join(why)}"},
                          remediation=("Return an identical response (status, body, timing) whether or not the "
                                       "account exists; rate-limit and log these requests."),
                          cwe="CWE-204", source="auth_probe",
                          **cap_fields(grants=["knowledge:usernames"], requires=["none"],
                                       chain_role="disclosure",
                                       assets=[asset_of(ku)], id_shape=id_shape_of(ku)))
                    if fid not in new_ids:
                        new_ids.append(fid)

                # --- Check 2: reset-token / reset-link leaked in the response body -------------
                if FORGOT.search(urlsplit(base).path) and RESET_LEAK.search(kb):
                    leak_hits += 1
                    m = RESET_LEAK.search(kb)
                    i = max(0, m.start() - 40)
                    fid = f"AUTHRESET-{slug(urlsplit(base).path)}-{shash(base + param)}"
                    F.add(id=fid,
                          title=f"Password-reset token returned in response body ({urlsplit(base).path})",
                          severity="high", confidence="tentative", category="authentication",
                          auth_context="anonymous", url=ku, method="GET",
                          description=(f"The forgot/reset endpoint returns a reset token or reset link directly in the "
                                       f"response body (matched '{m.group(0)[:30]}'). Anyone who can request a reset for "
                                       f"an account — combined with the enumeration oracle above — can then take over the "
                                       f"account without access to its mailbox (CWE-640). OBSERVED only; the token was NOT "
                                       f"used. " + caveat),
                          impact="Full account takeover: the reset secret is disclosed to the requester instead of only the account owner's inbox.",
                          evidence={"request": describe_request(kr),
                                    "response_status": kr.status_code,
                                    "response_excerpt": excerpt(kb[i:i + 240], 300),
                                    "notes": "Reset token/link present in body; value redacted in evidence."},
                          remediation=("Never return the reset token or link in the HTTP response; deliver it only out-of-band "
                                       "(email/SMS). Use high-entropy, single-use, short-lived tokens."),
                          cwe="CWE-640", source="auth_probe",
                          **cap_fields(grants=["identity:assume-user"], requires=["knowledge:usernames"],
                                       chain_role="privilege",
                                       assets=[asset_of(ku)], id_shape=id_shape_of(ku)))
                    if fid not in new_ids:
                        new_ids.append(fid)

        # --- Check 3: forced-browsing note (do NOT duplicate authz_replay's anonymous-access work)
        if auth_only:
            sample = sorted(auth_only)[:8]
            fid = "AUTHFORCEDBROWSE-manual-review"
            F.add(id=fid,
                  title="Auth-only endpoints present — manual forced-browsing review",
                  severity="info", confidence="tentative", category="broken-access-control",
                  auth_context="anonymous", url=scope.target + (sample[0] if sample else "/"),
                  method="GET",
                  description=("Recon found endpoints that redirect anonymous users to login. authz_replay already "
                               "tests whether these are actually reachable without authentication; this is only a "
                               "reminder to review them by hand for forced browsing. No access attempt was made here."),
                  evidence={"request": "(no request — manual review note)",
                            "notes": "auth-only paths: " + ", ".join(sample)},
                  remediation="Enforce authorization server-side on every sensitive endpoint, not just via UI redirects.",
                  source="auth_probe",
                  **cap_fields(chain_role="standalone"))
            if fid not in new_ids:
                new_ids.append(fid)
    finally:
        F.save()
        print(f"Auth probe: {client.count} requests, {probed} auth endpoint(s) probed; "
              f"{enum_hits} enumeration, {leak_hits} reset-token-leak indicator(s); "
              f"{F.added} new candidate findings -> {F.path}")
        if not enum_targets:
            print("  No forgot/login/register endpoints found in recon — run recon.py first, "
                  "or the app may expose them only via POST.")
        elif not knowns:
            print("  No known account under test (pass --sessions/--session with an email identity_marker) "
                  "— enumeration/reset oracle skipped for safety.")
        if new_ids:
            print("  new: " + ", ".join(new_ids[:15]))


if __name__ == "__main__":
    main()
