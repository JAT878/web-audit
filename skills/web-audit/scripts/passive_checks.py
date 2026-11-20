#!/usr/bin/env python3
"""Phase 2: low-impact configuration checks — TLS, headers, cookies, CORS, disclosure, errors."""
import argparse
import json
import os
import re
import socket
import ssl
import sys
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (Client, Findings, asset_of, cap_fields, describe_request, excerpt,  # noqa: E402
                    id_shape_of, load_scope_or_exit, load_sessions, shash)

SESSION_COOKIE = re.compile(r"(?i)(sess|sid|auth|token|jwt|login|remember|\.aspnetcore|laravel_session|phpsessid|jsessionid|connect\.sid)")
STACK_TRACE = re.compile(
    r"(Traceback \(most recent call last\)|at [\w\.$]+\([\w]+\.java:\d+\)|System\.\w+Exception|"
    r"Stack trace:|Fatal error: |Warning: .* on line \d+|Uncaught (?:Exception|Error)|"
    r"SQLSTATE\[|You have an error in your SQL syntax|ORA-\d{5}|PG::|psycopg2\.|"
    r"Microsoft OLE DB|Unclosed quotation mark|Whoops, looks like something went wrong|"
    r"Ignition|Server Error in '/' Application|DEBUG = True|Werkzeug Debugger|"
    r"node_modules/|at Object\.<anonymous>|ActiveRecord::|django\.core)", re.I)
VERSION_RE = re.compile(r"\d+\.\d+")


def html_pages(out_dir, scope, limit=12):
    urls = [scope.target + "/"]
    p = os.path.join(out_dir, "recon.json")
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            recon = json.load(f)
        for pg in recon.get("pages", []):
            if pg["status"] == 200 and "html" in pg.get("type", "") and pg["url"] not in urls:
                urls.append(pg["url"])
    return urls[:limit]


def json_endpoints(out_dir, scope, limit=10):
    out = []
    for fname in sorted(os.listdir(out_dir)):
        if fname.startswith("recon") and fname.endswith(".json"):
            with open(os.path.join(out_dir, fname), encoding="utf-8") as f:
                recon = json.load(f)
            for pg in recon.get("pages", []):
                if "json" in pg.get("type", "") and pg["url"] not in out:
                    out.append(pg["url"])
            for ep in recon.get("js_endpoints", []):
                if ep.startswith("/") and "{" not in ep and "$" not in ep:
                    u = scope.target + ep
                    if u not in out:
                        out.append(u)
    return out[:limit]


def set_cookies(resp):
    try:
        return resp.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        v = resp.headers.get("Set-Cookie")
        return [v] if v else []


def tls_checks(scope, client, F):
    p = urlparse(scope.target)
    if p.scheme != "https":
        F.add(id="CRYPTO-no-https", title="Site served over plain HTTP", severity="high", confidence="confirmed",
              category="cryptographic-failure", auth_context="anonymous", url=scope.target,
              description="The target is served over HTTP, so credentials and session cookies travel in clear text.",
              impact="Network attackers can read or modify traffic, including logins.",
              evidence={"request": f"GET {scope.target}"}, remediation="Serve the site only over HTTPS and redirect HTTP to HTTPS.",
              cwe="CWE-319", source="passive_checks")
        return
    host, port = p.hostname, p.port or 443
    proxied = bool(os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy"))
    client.limiter.wait()
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ss:
                cert = ss.getpeercert()
                proto = ss.version()
        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (exp - datetime.now(timezone.utc)).days
        if days < 21:
            F.add(id="CRYPTO-cert-expiring", title=f"TLS certificate expires in {days} days", severity="medium" if days < 7 else "low",
                  confidence="confirmed", category="cryptographic-failure", auth_context="anonymous", url=scope.target,
                  description=f"Certificate notAfter is {cert['notAfter']}.", impact="Expired certificates break access and train users to click through warnings.",
                  evidence={"request": f"TLS handshake {host}:{port}", "notes": f"negotiated {proto}"},
                  remediation="Renew the certificate and automate renewal.", cwe="CWE-298", source="passive_checks")
    except ssl.SSLCertVerificationError as e:
        F.add(id="CRYPTO-invalid-cert", title="TLS certificate fails validation", severity="high", confidence="firm",
              category="cryptographic-failure", auth_context="anonymous", url=scope.target,
              description=f"Certificate validation failed: {e.verify_message if hasattr(e, 'verify_message') else e}",
              impact="Users cannot distinguish the real site from an interception attack.",
              evidence={"request": f"TLS handshake {host}:{port}"}, remediation="Install a valid certificate chain for this hostname.",
              cwe="CWE-295", source="passive_checks")
    except (OSError, ValueError) as e:
        print(f"  TLS handshake check skipped ({e}){' — direct connections may be blocked by a proxy' if proxied else ''}")
        return
    # Legacy protocol support
    for ver_name, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        client.limiter.wait()
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = ver
            ctx.maximum_version = ver
            try:
                ctx.set_ciphers("ALL:@SECLEVEL=0")
            except ssl.SSLError:
                pass
            with socket.create_connection((host, port), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=host):
                    F.add(id=f"CRYPTO-legacy-{ver_name.lower().replace('.', '')}", title=f"{ver_name} is enabled",
                          severity="medium", confidence="confirmed", category="cryptographic-failure", auth_context="anonymous",
                          url=scope.target, description=f"The server accepted a {ver_name} handshake.",
                          impact="Deprecated protocol versions have known weaknesses and fail compliance baselines (PCI DSS, ISO 27001 controls).",
                          evidence={"request": f"TLS handshake {host}:{port} limited to {ver_name}"},
                          remediation="Disable TLS 1.0 and 1.1; allow TLS 1.2+ only.", cwe="CWE-327", source="passive_checks")
        except (ssl.SSLError, OSError, ValueError):
            pass  # rejected or not supported locally


def https_redirect(scope, client, F):
    p = urlparse(scope.target)
    if p.scheme != "https":
        return
    http_url = "http://" + p.netloc + "/"
    r = client.get(http_url)
    if r is None:
        return
    loc = r.headers.get("Location", "")
    if not (r.is_redirect and loc.startswith("https://")):
        F.add(id="CRYPTO-no-https-redirect", title="HTTP does not redirect to HTTPS", severity="low", confidence="confirmed",
              category="cryptographic-failure", auth_context="anonymous", url=http_url,
              description=f"Plain HTTP returned {r.status_code} without redirecting to HTTPS.",
              impact="Users typing the bare domain may use an unencrypted connection.",
              evidence={"request": describe_request(r), "response_status": r.status_code, "notes": f"Location: {loc or '(none)'}"},
              remediation="Redirect all HTTP requests to HTTPS (301) and enable HSTS.", cwe="CWE-319", source="passive_checks")


def header_checks(scope, client, F, pages):
    missing = {"csp": [], "hsts": [], "frame": [], "nosniff": [], "referrer": []}
    sample = {}
    disclosure = {}
    cookie_issues = {}
    https = scope.target.startswith("https")
    for url in pages:
        r = client.get(url)
        if r is None or "html" not in r.headers.get("Content-Type", ""):
            continue
        h = {k.lower(): v for k, v in r.headers.items()}
        csp = h.get("content-security-policy", "")
        if not csp:
            missing["csp"].append(url)
        if https and "strict-transport-security" not in h:
            missing["hsts"].append(url)
        if "x-frame-options" not in h and "frame-ancestors" not in csp:
            missing["frame"].append(url)
        if h.get("x-content-type-options", "").lower() != "nosniff":
            missing["nosniff"].append(url)
        if "referrer-policy" not in h:
            missing["referrer"].append(url)
        sample.setdefault("resp", r)
        for k in ("server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"):
            if k in h and VERSION_RE.search(h[k]):
                disclosure[k] = (h[k], r)
        for sc in set_cookies(r):
            # Parse cookie attributes by splitting on ';' and comparing attribute NAMES
            # case-insensitively, so 'a=b;Secure;HttpOnly' is not a false positive and a
            # cookie VALUE containing 'httponly' is not a false negative (C3).
            parts = sc.split(";")
            name = parts[0].split("=", 1)[0].strip()
            attrs = {}
            for seg in parts[1:]:
                seg = seg.strip()
                if not seg:
                    continue
                an, _, av = seg.partition("=")
                attrs[an.strip().lower()] = av.strip()
            probs = []
            if https and "secure" not in attrs:
                probs.append("Secure")
            if "httponly" not in attrs:
                probs.append("HttpOnly")
            if "samesite" not in attrs:
                probs.append("SameSite")
            elif attrs.get("samesite", "").lower() == "none" and "secure" not in attrs:
                probs.append("SameSite=None without Secure")
            if probs:
                cookie_issues.setdefault(name, (set(), r, sc))[0].update(probs)

    r0 = sample.get("resp")
    if r0 is None:
        print("  No HTML pages returned — header checks skipped")
        return
    defs = {
        "csp": ("HDR-missing-csp", "Content-Security-Policy header missing", "low",
                "No CSP means any XSS bug can load and run arbitrary script.", "Add a restrictive Content-Security-Policy (start with default-src 'self'; object-src 'none'; frame-ancestors 'self').", "CWE-1021"),
        "hsts": ("HDR-missing-hsts", "Strict-Transport-Security header missing", "low",
                 "Browsers will not force HTTPS, enabling SSL-stripping on first visit.", "Add Strict-Transport-Security: max-age=31536000; includeSubDomains.", "CWE-319"),
        "frame": ("HDR-clickjacking", "Pages can be framed (no X-Frame-Options / frame-ancestors)", "low",
                  "Pages can be embedded in an attacker site to trick users into clicks (clickjacking).", "Add X-Frame-Options: DENY or CSP frame-ancestors 'self'.", "CWE-1021"),
        "nosniff": ("HDR-missing-nosniff", "X-Content-Type-Options: nosniff missing", "info",
                    "Browsers may MIME-sniff responses into executable types.", "Add X-Content-Type-Options: nosniff.", "CWE-693"),
        "referrer": ("HDR-missing-referrer-policy", "Referrer-Policy header missing", "info",
                     "Full URLs (which may contain tokens) can leak to third parties via Referer.", "Add Referrer-Policy: strict-origin-when-cross-origin.", "CWE-200"),
    }
    for key, urls in missing.items():
        if not urls:
            continue
        fid, title, sev, impact, fix, cwe = defs[key]
        F.add(id=fid, title=title, severity=sev, confidence="firm", category="clickjacking" if key == "frame" else "security-misconfiguration",
              auth_context="anonymous", url=urls[0], description=f"Missing on {len(urls)} HTML page(s): " + ", ".join(urls[:5]),
              impact=impact, evidence={"request": f"GET {urls[0]}", "response_status": r0.status_code,
                                       "notes": "Response headers: " + ", ".join(sorted(r0.headers.keys()))},
              remediation=fix, cwe=cwe, source="passive_checks")
    for k, (val, r) in disclosure.items():
        F.add(id=f"INFO-version-{k.replace('x-', '')}", title=f"Version disclosed in {k} header", severity="low", confidence="confirmed",
              category="information-disclosure", auth_context="anonymous", url=r.url,
              description=f"{k}: {val}", impact="Exact versions let attackers match known CVEs quickly. Check whether this version is still supported.",
              evidence={"request": describe_request(r), "response_status": r.status_code, "notes": f"{k}: {val}"},
              remediation=f"Remove or genericise the {k} header; keep the component patched.", cwe="CWE-200", source="passive_checks",
              **cap_fields(chain_role="disclosure"))  # fingerprint only — no chain grant
    for name, (probs, r, raw) in cookie_issues.items():
        is_sess = bool(SESSION_COOKIE.search(name))
        sev = "medium" if is_sess and ("HttpOnly" in probs or "Secure" in probs) else "low"
        if not is_sess and probs == {"SameSite"}:
            sev = "info"
        raw_red = name + "=****" + (";" + raw.split(";", 1)[1] if ";" in raw else "")
        F.add(id=f"SESS-cookie-flags-{name.lower().replace('.', '').replace('_', '-')[:30]}",
              title=f"Cookie '{name}' missing {', '.join(sorted(probs))}", severity=sev, confidence="confirmed",
              category="session-management", auth_context="anonymous", url=r.url,
              description=f"Set-Cookie for '{name}' lacks: {', '.join(sorted(probs))}." + (" This looks like a session cookie." if is_sess else ""),
              impact="Missing HttpOnly lets XSS steal the cookie; missing Secure sends it over HTTP; missing SameSite weakens CSRF defence.",
              evidence={"request": describe_request(r), "response_status": r.status_code, "notes": "Set-Cookie: " + raw_red},
              remediation="Set Secure; HttpOnly; SameSite=Lax (or Strict) on session cookies.", cwe="CWE-1004" if "HttpOnly" in probs else "CWE-614",
              source="passive_checks")


def cors_checks(scope, client, F, urls):
    host = urlparse(scope.target).hostname
    origins = ["https://evil.example", "null", f"https://{host}.evil.example"]
    for url in urls:
        for o in origins:
            r = client.get(url, headers={"Origin": o})
            if r is None:
                continue
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
            # Only reflected-origin or null-origin WITH credentials is exploitable. 'ACAO: *'
            # with credentials is forbidden by browsers, so it is NOT reported (C2).
            if acao == o and acac:
                F.add(id=f"CORS-reflect-{'null' if o == 'null' else 'origin'}-{shash(url)}",
                      title=f"CORS allows {'null' if o == 'null' else 'arbitrary'} origin with credentials",
                      severity="high", confidence="firm", category="cors", auth_context=client.name, url=url,
                      description=f"Origin '{o}' is reflected in Access-Control-Allow-Origin and credentials are allowed.",
                      impact="Any website can read this endpoint's responses using the victim's session.",
                      evidence={"request": describe_request(r), "response_status": r.status_code,
                                "notes": f"Access-Control-Allow-Origin: {acao}; Access-Control-Allow-Credentials: {r.headers.get('Access-Control-Allow-Credentials', '')}"},
                      remediation="Use an explicit allow-list of trusted origins; never reflect Origin or allow 'null' with credentials.",
                      cwe="CWE-942", source="passive_checks",
                      **cap_fields(chain_role="standalone"))  # browser-forced victim action — not a clean chain link
                break


def error_checks(scope, client, F):
    probes = [
        (scope.target + f"/zz-not-found-{uuid.uuid4().hex[:8]}", "random 404 path"),
        (scope.target + "/?id=%27%22%3C", "quote characters in a query parameter"),
        (scope.target + "/%ff", "invalid URL encoding"),
        (scope.target + f"/zz-{uuid.uuid4().hex[:6]}.php", "non-existent .php file"),
        (scope.target + f"/zz-{uuid.uuid4().hex[:6]}.aspx", "non-existent .aspx file"),
    ]
    for url, why in probes:
        r = client.get(url)
        if r is None:
            continue
        m = STACK_TRACE.search(r.text or "")
        if m:
            i = max(0, m.start() - 150)
            F.add(id=f"INFO-verbose-error-{shash(why)}", title="Verbose error / stack trace returned",
                  severity="medium", confidence="firm", category="information-disclosure", auth_context="anonymous", url=url,
                  description=f"Sending {why} produced a detailed error (matched '{m.group(0)[:60]}').",
                  impact="Stack traces reveal file paths, frameworks, queries and sometimes secrets; they help attackers craft exploits.",
                  evidence={"request": describe_request(r), "response_status": r.status_code, "response_excerpt": excerpt(r.text[i:i + 700])},
                  remediation="Disable debug mode / detailed errors in this environment and return generic error pages.",
                  cwe="CWE-209", source="passive_checks",
                  **cap_fields(grants=["knowledge:internal-host"], chain_role="disclosure",
                               assets=[asset_of(url)], id_shape=id_shape_of(url)))


def dirlist_checks(scope, client, F):
    for d in ("/uploads/", "/images/", "/assets/", "/static/", "/files/", "/backup/", "/media/", "/tmp/"):
        r = client.get(scope.target + d)
        if r is not None and r.status_code == 200 and re.search(r"<title>Index of /|Directory listing for|\[To Parent Directory\]", r.text or "", re.I):
            F.add(id=f"MISCONF-dir-listing-{d.strip('/')}", title=f"Directory listing enabled at {d}", severity="medium",
                  confidence="confirmed", category="security-misconfiguration", auth_context="anonymous", url=r.url,
                  description=f"{d} returns an auto-generated directory index.",
                  impact="Attackers can browse and download files that were never meant to be linked (uploads, backups).",
                  evidence={"request": describe_request(r), "response_status": 200, "response_excerpt": excerpt(r.text, 400)},
                  remediation="Disable directory indexes (Options -Indexes / autoindex off / directoryBrowse disabled).",
                  cwe="CWE-548", source="passive_checks")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sessions")
    ap.add_argument("--session", help="also run header/cookie/CORS checks as this session")
    ap.add_argument("--skip-tls", action="store_true")
    a = ap.parse_args()
    scope = load_scope_or_exit(a.scope)
    sessions = load_sessions(a.sessions)
    c = Client(scope, a.out, "anonymous")
    F = Findings(a.out, scope.target)
    clients = [c]
    try:
        pages = html_pages(a.out, scope)
        if not a.skip_tls:
            tls_checks(scope, c, F)
        https_redirect(scope, c, F)
        header_checks(scope, c, F, pages)
        cors_targets = [scope.target + "/"] + json_endpoints(a.out, scope)
        cors_checks(scope, c, F, cors_targets)
        if a.session:
            cs = Client(scope, a.out, a.session, sessions.get(a.session))
            clients.append(cs)
            cors_checks(scope, cs, F, cors_targets)
        error_checks(scope, c, F)
        dirlist_checks(scope, c, F)
    finally:
        F.save()
        reqs = sum(cl.count for cl in clients)
        print(f"Passive checks: {reqs} requests, {F.added} new candidate findings -> {F.path}")


if __name__ == "__main__":
    main()
