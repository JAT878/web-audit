#!/usr/bin/env python3
"""Phase 2: parameter probing for reflected-input (XSS) and SQL-error indicators.

For every GET parameter found in recon (page query strings, JS endpoints, and GET forms), send ONE
benign marker and look at the response. This is detection, not exploitation:
  * the marker contains harmless characters (a quote and an inert <zq> tag), never a working payload;
  * one request per parameter, through the scope rate limit, GET only;
  * it reports an *indicator* for a human to confirm — it does not attempt to run script or extract data.
"""
import argparse
import json
import os
import re
import sys
import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Client, Findings, describe_request, excerpt, load_scope_or_exit, load_sessions, shash  # noqa: E402

SQL_ERROR = re.compile(
    r"(SQLSTATE\[|You have an error in your SQL syntax|ORA-\d{5}|PG::\w+Error|psycopg2\.|"
    r"Unclosed quotation mark|Microsoft OLE DB|SQLiteException|sqlite3\.OperationalError|"
    r"org\.hibernate\.|System\.Data\.SqlClient|MySqlException|Npgsql\.|Warning: mysqli?)", re.I)
HTML_CTX = re.compile(r"text/html", re.I)


def gather_params(out_dir, scope):
    """Return {url_without_query: {param_names}} plus GET-form targets."""
    targets = {}
    for fname in sorted(os.listdir(out_dir)):
        if not (fname.startswith("recon") and fname.endswith(".json")):
            continue
        with open(os.path.join(out_dir, fname), encoding="utf-8") as f:
            recon = json.load(f)
        for pg in recon.get("pages", []):
            qs = urlparse(pg["url"]).query
            if qs:
                base = pg["url"].split("?")[0]
                targets.setdefault(base, set()).update(parse_qs(qs).keys())
        for ep in recon.get("js_endpoints", []):
            if ep.startswith("/") and "?" in ep:
                base = scope.target + ep.split("?")[0]
                targets.setdefault(base, set()).update(parse_qs(ep.split("?", 1)[1]).keys())
        for form in recon.get("forms", []):
            if form.get("method", "GET").upper() != "GET":
                continue
            action = form.get("action_abs") or form.get("page")
            names = {i["name"] for i in form.get("inputs", []) if i.get("name")}
            if action and names:
                targets.setdefault(action.split("?")[0], set()).update(names)
    return targets


def build_url(base, param, marker, existing):
    params = {k: v[0] if isinstance(v, list) else v for k, v in existing.items()}
    params[param] = marker
    u = urlparse(base)
    return urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(params), ""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sessions")
    ap.add_argument("--session", help="probe as this session as well as anonymously")
    ap.add_argument("--max-params", type=int, default=120, help="cap total parameters probed")
    a = ap.parse_args()
    scope = load_scope_or_exit(a.scope)
    sessions = load_sessions(a.sessions)
    clients = [Client(scope, a.out, "anonymous")]
    if a.session and a.session in sessions:
        clients.append(Client(scope, a.out, a.session, sessions[a.session]))

    targets = gather_params(a.out, scope)
    probed = 0
    xss_hits, sqli_hits = 0, 0
    F = Findings(a.out, scope.target)

    for base, params in targets.items():
        if not scope.in_scope(base) or scope.excluded(base):
            continue
        existing = {}  # keep other params empty; probe one at a time
        for param in sorted(params):
            if probed >= a.max_params:
                break
            probed += 1
            tag = "zq" + uuid.uuid4().hex[:6]
            marker = f"{tag}'\"<{tag}>"
            url = build_url(base, param, marker, existing)
            for c in clients:
                r = c.get(url, allow_redirects=False)
                if r is None:
                    continue
                body = r.text or ""
                ctype = r.headers.get("Content-Type", "")
                # Reflected-input indicator: our inert tag comes back verbatim in an HTML response.
                if f"<{tag}>" in body and HTML_CTX.search(ctype):
                    xss_hits += 1
                    i = body.find(f"<{tag}>")
                    F.add(id=f"XSS-reflected-{shash(base + param)}",
                          title=f"Input reflected unescaped in HTML (parameter '{param}')",
                          severity="medium", confidence="tentative", category="injection",
                          auth_context=c.name if c.name != "anonymous" else "anonymous",
                          url=url, method="GET",
                          description=f"The value of '{param}' is returned in the HTML response without encoding "
                                      f"(the inert marker <{tag}> appears verbatim). This is an indicator of reflected XSS; "
                                      "confirm the exact context and whether a CSP would block execution.",
                          impact="If the value is rendered as HTML, an attacker could run script in a victim's browser.",
                          evidence={"request": describe_request(r), "response_status": r.status_code,
                                    "response_excerpt": excerpt(body[max(0, i - 80):i + 120], 300),
                                    "notes": f"Content-Type: {ctype}"},
                          remediation="Context-encode output (HTML/attribute/JS) and add a Content-Security-Policy. Validate input server-side.",
                          cwe="CWE-79", source="param_probe")
                    break  # one indicator per parameter is enough
                if SQL_ERROR.search(body):
                    sqli_hits += 1
                    m = SQL_ERROR.search(body)
                    i = max(0, m.start() - 80)
                    F.add(id=f"SQLI-error-{shash(base + param)}",
                          title=f"Database error triggered by parameter '{param}'",
                          severity="high", confidence="tentative", category="injection",
                          auth_context=c.name if c.name != "anonymous" else "anonymous",
                          url=url, method="GET",
                          description=f"Sending a single quote in '{param}' produced a database error "
                                      f"(matched '{m.group(0)[:40]}'). This is a strong indicator of SQL injection. "
                                      "Do NOT run extraction payloads — confirm safely or hand to a developer.",
                          impact="SQL injection can expose or modify the entire database.",
                          evidence={"request": describe_request(r), "response_status": r.status_code,
                                    "response_excerpt": excerpt(body[i:i + 200], 300)},
                          remediation="Use parameterised queries / prepared statements everywhere; never build SQL by string concatenation.",
                          cwe="CWE-89", source="param_probe")
                    break
    F.save()
    print(f"Param probe: {probed} parameters across {len(targets)} URLs; "
          f"{xss_hits} reflected-input, {sqli_hits} SQL-error indicator(s); {F.added} new candidate findings -> {F.path}")
    if probed == 0:
        print("  No GET parameters found in recon — run recon.py first, or the app may use path/body params only.")


if __name__ == "__main__":
    main()
