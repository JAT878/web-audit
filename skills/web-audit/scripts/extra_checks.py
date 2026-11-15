#!/usr/bin/env python3
"""Phase 2-3 extras: GraphQL introspection and JWT weaknesses. Read-only (GET) by default.

GraphQL: tries common endpoints (plus any '/graphql' paths found by recon) with an introspection
query sent as GET. If allow_state_changing is true it also tries POST (introspection is a read,
but POST is still blocked by default to keep the "GET only" promise simple).

JWT: decodes (never verifies or forges) tokens found in session material and Set-Cookie headers,
and flags alg=none, missing/long expiry, and sensitive-looking claims.
"""
import argparse
import base64
import json
import os
import re
import sys
import time
from urllib.parse import quote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Client, Findings, describe_request, excerpt, load_scope_or_exit, load_sessions, shash  # noqa: E402

GQL_PATHS = ["/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql", "/query", "/gql"]
INTROSPECTION = "{__schema{queryType{name} types{name}}}"
JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]{5,}\.eyJ[a-zA-Z0-9_-]{5,}\.[a-zA-Z0-9_-]*")
SENSITIVE_CLAIMS = re.compile(r"(?i)^(password|pwd|secret|ssn|dob|credit|card|pan|cvv|api_?key|private)")
LONG_EXPIRY_DAYS = 7


# ---------------------------------------------------------------- GraphQL
def graphql_candidates(out_dir, scope):
    paths = list(GQL_PATHS)
    for fname in sorted(os.listdir(out_dir)):
        if fname.startswith("recon") and fname.endswith(".json"):
            with open(os.path.join(out_dir, fname), encoding="utf-8") as f:
                recon = json.load(f)
            for ep in recon.get("js_endpoints", []):
                if "graphql" in ep.lower() and ep.startswith("/") and ep.split("?")[0] not in paths:
                    paths.append(ep.split("?")[0])
    return [scope.target + p for p in paths]


def check_graphql(scope, c, F, out_dir):
    for url in graphql_candidates(out_dir, scope):
        if scope.excluded(url):
            continue
        r = c.get(url + "?query=" + quote(INTROSPECTION))
        if (r is None or '"__schema"' not in (r.text or "")) and scope.allow_state_changing:
            r = c.request("POST", url, json={"query": INTROSPECTION})
        if r is None or r.status_code != 200 or '"__schema"' not in (r.text or ""):
            continue
        try:
            types = [t["name"] for t in r.json()["data"]["__schema"]["types"] if not t["name"].startswith("__")]
        except (ValueError, KeyError, TypeError):
            types = []
        sev = "medium" if scope.environment == "production" else "low"
        F.add(id=f"GQL-introspection-{shash(url)}", title="GraphQL introspection enabled", severity=sev,
              confidence="confirmed", category="information-disclosure", auth_context=c.name if c.name != "anonymous" else "anonymous",
              url=url, method=r.request.method,
              description=f"The GraphQL endpoint returns its full schema ({len(types)} types) to an introspection query.",
              impact="Attackers get a complete map of queries, mutations and fields — including ones the UI never uses — which speeds up finding access-control gaps.",
              evidence={"request": describe_request(r), "response_status": 200,
                        "response_excerpt": excerpt(", ".join(types[:40]), 600), "notes": f"{len(types)} non-builtin types"},
              remediation="Disable introspection outside development (most GraphQL servers have a flag), and enforce authorization per resolver.",
              cwe="CWE-200", source="extra_checks")
        return url  # one endpoint is enough evidence
    return None


# ---------------------------------------------------------------- JWT
def b64json(part):
    part += "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part))


def decode_jwt(token):
    try:
        h, p, sig = token.split(".")
        return b64json(h), b64json(p), sig
    except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def collect_tokens(scope, c, sessions):
    """Return [(token, where_found, context)] from sessions.json and Set-Cookie on the start page."""
    found = []
    for name, entry in sessions.items():
        blobs = list((entry.get("cookies") or {}).items()) + list((entry.get("headers") or {}).items())
        if entry.get("cookie_header"):
            blobs.append(("Cookie", entry["cookie_header"]))
        for k, v in blobs:
            for t in JWT_RE.findall(str(v)):
                found.append((t, f"{name} {k}", name))
    r = c.get(scope.target + "/")
    if r is not None:
        try:
            raw = r.raw.headers.getlist("Set-Cookie")
        except AttributeError:
            raw = [r.headers.get("Set-Cookie", "")]
        for sc in raw:
            for t in JWT_RE.findall(sc or ""):
                found.append((t, f"Set-Cookie {sc.split('=', 1)[0]}", "anonymous"))
    seen, out = set(), []
    for t, w, ctx in found:
        if t not in seen:
            seen.add(t)
            out.append((t, w, ctx))
    return out


def check_jwts(scope, c, F, sessions):
    tokens = collect_tokens(scope, c, sessions)
    now = time.time()
    for token, where, ctx in tokens:
        d = decode_jwt(token)
        if not d:
            continue
        header, payload, sig = d
        alg = str(header.get("alg", "")).lower()
        tid = shash(token[:40])
        red = token[:12] + "****"
        ctx = ctx if ctx in ("anonymous", "user_a", "user_b", "admin") else "user_a"
        common = dict(confidence="confirmed", auth_context=ctx, url=scope.target, method="GET", source="extra_checks",
                      evidence={"request": f"Token from {where}: {red}",
                                "notes": "Decoded header: " + json.dumps(header) + "; claim names: " + ", ".join(sorted(payload))})
        if alg == "none" or not sig:
            F.add(id=f"JWT-alg-none-{tid}", title="JWT uses alg 'none' / is unsigned", severity="critical",
                  category="authentication",
                  description=f"A token found in {where} declares alg '{header.get('alg')}' or has an empty signature.",
                  impact="If the server accepts unsigned tokens, anyone can forge a token for any user.",
                  remediation="Reject 'none' and pin the expected algorithm server-side; always verify signatures.",
                  cwe="CWE-347", **common)
        exp = payload.get("exp")
        if exp is None:
            F.add(id=f"JWT-no-expiry-{tid}", title="JWT has no expiry (exp claim missing)", severity="medium",
                  category="session-management",
                  description=f"The token from {where} has no 'exp' claim.",
                  impact="A stolen token works forever unless the server tracks revocation.",
                  remediation="Issue short-lived access tokens (minutes to hours) with refresh tokens, and set 'exp'.",
                  cwe="CWE-613", **common)
        elif isinstance(exp, (int, float)) and (exp - payload.get("iat", now)) / 86400 > LONG_EXPIRY_DAYS:
            days = round((exp - payload.get("iat", now)) / 86400)
            F.add(id=f"JWT-long-expiry-{tid}", title=f"JWT is valid for ~{days} days", severity="low",
                  category="session-management",
                  description=f"The token from {where} has a lifetime of about {days} days.",
                  impact="Long-lived tokens extend the window in which a stolen token is useful.",
                  remediation="Shorten access-token lifetime and use refresh-token rotation.",
                  cwe="CWE-613", **common)
        sens = [k for k in payload if SENSITIVE_CLAIMS.search(k)]
        if sens:
            F.add(id=f"JWT-sensitive-claims-{tid}", title="JWT contains sensitive-looking claims", severity="medium",
                  category="sensitive-data-exposure",
                  description=f"Claims {sens} are present in a token from {where}. JWT payloads are only base64-encoded, not encrypted.",
                  impact="Anyone holding the token (or seeing it in logs/browser storage) can read these values.",
                  remediation="Keep only identifiers in tokens; look sensitive data up server-side.",
                  cwe="CWE-312", **common)
    return len(tokens)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sessions")
    ap.add_argument("--session", help="also try GraphQL introspection as this session")
    a = ap.parse_args()
    scope = load_scope_or_exit(a.scope)
    sessions = load_sessions(a.sessions)
    F = Findings(a.out, scope.target)
    c = Client(scope, a.out, "anonymous")
    gql = check_graphql(scope, c, F, a.out)
    if not gql and a.session and a.session in sessions:
        gql = check_graphql(scope, Client(scope, a.out, a.session, sessions[a.session]), F, a.out)
    n = check_jwts(scope, c, F, sessions)
    F.save()
    print(f"Extra checks: GraphQL {'introspection found at ' + gql if gql else 'none found'}; "
          f"{n} JWT(s) analysed; {F.added} new candidate findings -> {F.path}")


if __name__ == "__main__":
    main()
