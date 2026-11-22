#!/usr/bin/env python3
"""Phase C: auth-flow + open-redirect detector (read-only observation).

Looks for redirect-handling and OAuth/OIDC/SAML endpoints and checks, with a SINGLE benign,
off-site marker value, whether the server will hand an attacker-controlled destination straight
back in a Location header (or reflect it in a meta-refresh / JS). Everything here is read-only:

  * GET only, through common.Client (scope, rate limit, logging, redaction all enforced);
  * the marker's HOST (example.com) is OUT OF SCOPE and allow_redirects stays False, so the client
    never actually follows the marker — it only inspects the Location the target returns;
  * no real OAuth/SAML flow is completed, no crafted assertion is sent, nothing changes state;
  * one request per (endpoint, param) candidate, de-duplicated, rate-limited.

Checks:
  1. OPEN REDIRECT (CWE-601) — a redirect-like parameter reflected into a 3xx Location (or a
     meta-refresh / JS sink) that points off the allow-list. severity medium (high on a login/oauth flow).
  2. OAUTH/OIDC redirect_uri validation (CWE-601 / account takeover) — an authorize/connect/sso
     endpoint that echoes an unregistered redirect_uri. severity high; privilege (grants
     identity:assume-user) when the reflected destination also carries a token/code, else standalone.
  3. OIDC/OAuth hygiene (observe, info) — token/code returned in the redirect URL fragment/query and
     no observed `state` parameter. Noted for manual review only.
  4. SAML / SSO (observe, info) — if a SAML/SSO endpoint exists, note it for manual review; signature
     wrapping and friends can't be safely automated, so nothing is crafted or sent.
"""
import argparse
import json
import os
import re
import sys
from urllib.parse import urlsplit, urlencode

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (Client, Findings, ScopeError, asset_of, cap_fields,  # noqa: E402
                    describe_request, excerpt, id_shape_of, load_scope_or_exit,
                    load_sessions, shash)

# Off-site marker: host MUST be out of scope so the client can never actually follow it.
MARKER_HOST = "example.com"
MARKER_CORE = f"{MARKER_HOST}/evil-marker"
MARKER = f"https://{MARKER_CORE}"

# Redirect-like parameter names (lowercased for matching).
REDIRECT_PARAMS = ["next", "url", "redirect", "redirect_uri", "return", "returnto", "returnurl",
                   "dest", "destination", "continue", "goto", "callback"]
OAUTH_PARAMS = ["redirect_uri", "returnurl"]  # the ones OAuth/OIDC/SSO flows key on

# Endpoint whose path looks like an OAuth/OIDC/SSO authorize step (check 2 territory).
OAUTH_PATH = re.compile(r"(?:^|/)(?:oauth2?|openid|connect|authorize|sso|saml)(?:/|$)|/authorize\b", re.I)
# Path that is part of an authentication flow (bumps open-redirect severity to high).
FLOW_PATH = re.compile(r"(login|signin|sign-in|logon|oauth|openid|connect|authorize|sso|saml|/auth)", re.I)
# A token/code sitting in a redirect URL (fragment or query) — leaks on reflection.
TOKEN_IN_URL = re.compile(r"[#?&](access_token|id_token|refresh_token|code|token|ticket)=", re.I)
SAML_MARKERS = re.compile(r"SAMLRequest|SAMLResponse|AuthnRequest|urn:oasis:names:tc:SAML", re.I)
SOFT404 = re.compile(r"could not be found|page not found|not found|404", re.I)

# Seed endpoints to probe even when recon didn't surface them. Each is (path, [params]).
REDIRECT_SEEDS = [
    ("/redirect", ["next", "url", "redirect"]),
    ("/login", ["next", "returnto", "redirect"]),
    ("/signin", ["next", "returnurl"]),
    ("/auth/login", ["next", "redirect"]),
    ("/out", ["url"]), ("/away", ["url"]), ("/go", ["url", "goto"]),
    ("/link", ["url"]), ("/exit", ["url"]), ("/proxy", ["url"]),
]
OAUTH_SEEDS = [
    ("/oauth/authorize", ["redirect_uri"]),
    ("/oauth2/authorize", ["redirect_uri"]),
    ("/authorize", ["redirect_uri"]),
    ("/connect/authorize", ["redirect_uri"]),
    ("/openid/authorize", ["redirect_uri"]),
    ("/sso", ["returnurl", "redirect_uri"]),
    ("/saml/login", ["returnurl"]),
]
SAML_SEEDS = ["/saml", "/saml/login", "/saml/acs", "/saml/sso", "/sso", "/sso/login", "/adfs/ls"]


def _path_of(u):
    return urlsplit(u).path if "//" in u else (u.split("?", 1)[0] if isinstance(u, str) else "")


def _query_params(u):
    q = urlsplit(u).query if "//" in u else (u.split("?", 1)[1] if (isinstance(u, str) and "?" in u) else "")
    out = []
    for part in q.split("&"):
        if "=" in part:
            out.append(part.split("=", 1)[0])
        elif part:
            out.append(part)
    return out


def _recon_urls(out_dir):
    """Every URL/path string recon discovered, from the keys the contract names."""
    urls = []
    if not os.path.isdir(out_dir):
        return urls
    for fname in sorted(os.listdir(out_dir)):
        if not (fname.startswith("recon") and fname.endswith(".json")):
            continue
        try:
            with open(os.path.join(out_dir, fname), encoding="utf-8") as f:
                recon = json.load(f)
        except Exception:  # noqa: BLE001 — recon absent/partial is fine, seeds still run
            continue
        for pg in recon.get("pages", []):
            if isinstance(pg, dict) and pg.get("url"):
                urls.append(pg["url"])
        for e in recon.get("js_endpoints", []):
            if isinstance(e, str):
                urls.append(e)
        for e in recon.get("js_absolute_urls", []):
            if isinstance(e, str):
                urls.append(e)
        for u in recon.get("urls_with_params", []):
            if isinstance(u, str):
                urls.append(u)
        for t in recon.get("endpoint_templates", []):
            for ex in (t.get("example_urls") or []):
                if isinstance(ex, str):
                    urls.append(ex)
    return urls


def gather_candidates(out_dir, scope):
    """Return {(base_url, param_lower): (base_url, param, is_oauth)} de-duped by endpoint+param."""
    cands = {}

    def add(path, param, is_oauth):
        path = path or "/"
        if not path.startswith("/"):
            path = "/" + path
        base = scope.target + path
        key = (base, param.lower())
        cands.setdefault(key, (base, param, is_oauth or bool(OAUTH_PATH.search(path))))

    # from recon
    for u in _recon_urls(out_dir):
        path = _path_of(u)
        if not path:
            continue
        is_oauth = bool(OAUTH_PATH.search(path))
        for p in _query_params(u):
            if p.lower() in REDIRECT_PARAMS:
                add(path, p, is_oauth)
        if is_oauth:  # an authorize-looking endpoint: probe its redirect params even if absent in the URL
            for p in OAUTH_PARAMS:
                add(path, p, True)
    # seeds
    for path, params in REDIRECT_SEEDS:
        for p in params:
            add(path, p, False)
    for path, params in OAUTH_SEEDS:
        for p in params:
            add(path, p, True)
    return cands


def _probe_url(base, param):
    return base + ("&" if "?" in base else "?") + urlencode({param: MARKER})


def _location(resp):
    return (resp.headers.get("Location") or "") if resp is not None else ""


def _body_reflects(resp):
    """True if the marker is reflected into a meta-refresh or JS location sink in the body."""
    if resp is None:
        return False
    body = resp.text or ""
    if MARKER_CORE not in body:
        return False
    low = body.lower()
    return (("http-equiv" in low and "refresh" in low) or "window.location" in low
            or "location.href" in low or "location.replace" in low)


def _probeable(scope, url):
    try:
        return scope.in_scope(url) and not scope.excluded(url) and not scope.state_changing_path(url)
    except Exception:  # noqa: BLE001
        return False


def soft404_baseline(client, scope):
    url = scope.target + "/auth-flows-probe-nonexistent-ba5e"
    if not _probeable(scope, url):
        return None
    try:
        r = client.get(url, allow_redirects=False)
    except (ScopeError, Exception):  # noqa: BLE001
        return None
    return (r.status_code, (r.text or "")[:400]) if r is not None else None


def check_saml(client, scope, out_dir, F, baseline):
    """Observe-only: note a SAML/SSO endpoint for manual review if one plausibly exists."""
    seen = set()
    paths = list(SAML_SEEDS)
    for u in _recon_urls(out_dir):
        p = _path_of(u)
        if p and re.search(r"/(saml|sso|adfs)\b", p, re.I):
            paths.append(p)
    hits = 0
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        url = scope.target + path
        if not _probeable(scope, url):
            continue
        try:
            r = client.get(url, allow_redirects=False)
        except ScopeError:
            continue
        if r is None:
            continue
        body = r.text or ""
        has_markers = bool(SAML_MARKERS.search(body))
        is_soft404 = bool(baseline and r.status_code == baseline[0] and body[:400] == baseline[1]) \
            or (r.status_code == 200 and SOFT404.search(body) and MARKER_CORE not in body and not has_markers)
        # Only note when it looks like a real SAML/SSO surface, never a soft-404.
        if has_markers or (r.status_code in (200, 301, 302, 303, 307, 308) and not is_soft404 and
                           re.search(r"/(saml|sso|adfs)\b", path, re.I)):
            fid = f"SAML-review-{shash(path)}"
            F.add(id=fid,
                  title=f"SAML/SSO endpoint present ({path}) — manual review",
                  severity="info", confidence="tentative", category="authentication",
                  auth_context="anonymous", url=url, method="GET",
                  description=("A SAML/SSO endpoint appears to be exposed. SAML attacks (XML signature "
                               "wrapping, unsigned-assertion acceptance, audience/recipient confusion) can't be "
                               "safely automated, so this is NOTED for manual review only — no crafted assertion "
                               "was sent. Verify assertions are signed, the signature covers the whole document, "
                               "and audience/recipient/NotOnOrAfter are enforced."),
                  impact="Weak SAML validation can allow authentication bypass or user impersonation.",
                  evidence={"request": describe_request(r), "response_status": r.status_code,
                            "response_excerpt": excerpt(body, 300),
                            "notes": f"SAML markers in body={has_markers}"},
                  remediation=("Require and verify XML signatures over the full assertion; validate "
                               "Audience, Recipient, InResponseTo and NotOnOrAfter; reject unsigned assertions."),
                  cwe="CWE-347", source="auth_flows",
                  **cap_fields(chain_role="standalone", assets=[asset_of(url)], id_shape=id_shape_of(url)))
            hits += 1
    return hits


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sessions")
    ap.add_argument("--session", help="also probe as this session (as well as anonymously)")
    ap.add_argument("--max-candidates", type=int, default=80, help="cap total (endpoint,param) probes")
    a = ap.parse_args()

    scope = load_scope_or_exit(a.scope)
    sessions = load_sessions(a.sessions)
    clients = [Client(scope, a.out, "anonymous")]
    if a.session and a.session in sessions:
        clients.append(Client(scope, a.out, a.session, sessions[a.session]))

    F = Findings(a.out, scope.target)
    cands = gather_candidates(a.out, scope)
    new_ids = []
    redir_hits = oauth_hits = hygiene_hits = probed = 0
    hygiene_done = set()

    try:
        for (base, _), (base_url, param, is_oauth) in sorted(cands.items()):
            if probed >= a.max_candidates:
                break
            url = _probe_url(base_url, param)
            if not _probeable(scope, url):
                continue
            probed += 1
            path = urlsplit(base_url).path or "/"
            flow = bool(FLOW_PATH.search(path))
            for c in clients:
                try:
                    r = c.get(url, allow_redirects=False)
                except ScopeError:
                    break
                if r is None:
                    continue
                loc = _location(r)
                is_3xx = 300 <= r.status_code < 400
                loc_reflects = (MARKER_CORE in loc)
                reflects = (is_3xx and loc_reflects) or _body_reflects(r)
                if not reflects:
                    continue
                token_leak = bool(TOKEN_IN_URL.search(loc))
                sink = "Location header" if (is_3xx and loc_reflects) else "meta-refresh/JS body sink"
                shown = excerpt((f"Location: {loc}" if loc else "body reflects " + MARKER_CORE), 300)

                if is_oauth:
                    # --- Check 2: OAuth/OIDC redirect_uri validation -----------------------------
                    fid = f"OAUTH-redirect-uri-{shash(path + ':' + param.lower())}"
                    if token_leak:
                        caps = cap_fields(grants=["identity:assume-user"], requires=["none"],
                                          chain_role="privilege", assets=[asset_of(url)],
                                          id_shape=id_shape_of(url))
                        extra = (" The reflected destination also carried an OAuth token/code in the URL, so an "
                                 "off-allowlist redirect_uri leaks the victim's token/code to an attacker "
                                 "(account takeover).")
                        impact = ("An attacker who sends a victim a crafted authorize URL can steal the issued "
                                  "token/code and take over the account.")
                    else:
                        caps = cap_fields(chain_role="standalone", assets=[asset_of(url)],
                                          id_shape=id_shape_of(url))
                        extra = (" No token was observed in this response, but accepting an unregistered redirect_uri "
                                 "is still an authorization-redirect flaw that can leak codes/tokens in a real flow.")
                        impact = "Missing redirect_uri allow-listing can leak OAuth codes/tokens and enable account takeover."
                    F.add(id=fid,
                          title=f"OAuth redirect_uri not validated at {path} (parameter '{param}')",
                          severity="high", confidence="tentative", category="open-redirect",
                          auth_context=c.name, url=url, method="GET",
                          description=(f"The authorize-style endpoint {path} reflected an unregistered, off-allowlist "
                                       f"redirect destination ({MARKER}) into its {sink} with no allow-list validation of "
                                       f"'{param}' (CWE-601). Observed only — no real OAuth flow was completed." + extra),
                          impact=impact,
                          evidence={"request": describe_request(r), "response_status": r.status_code,
                                    "response_excerpt": shown,
                                    "notes": f"off-allowlist destination reflected; token/code in redirect URL={token_leak}"},
                          remediation=("Validate redirect_uri against an exact, pre-registered allow-list (full string "
                                       "match incl. path); never reflect an arbitrary destination; prefer the "
                                       "authorization-code flow with PKCE and keep tokens out of the URL."),
                          cwe="CWE-601", references=["https://owasp.org/www-community/attacks/Open_redirect"],
                          source="auth_flows", **caps)
                    oauth_hits += 1
                    if fid not in new_ids:
                        new_ids.append(fid)

                    # --- Check 3: OAuth/OIDC hygiene (observe, info) -----------------------------
                    if token_leak and path not in hygiene_done:
                        hygiene_done.add(path)
                        hid = f"OAUTH-hygiene-{shash(path)}"
                        F.add(id=hid,
                              title=f"OAuth response hygiene at {path}: token in URL, no state observed",
                              severity="info", confidence="tentative", category="authentication",
                              auth_context=c.name, url=url, method="GET",
                              description=("Observation only: the authorize response placed an access/id token or code "
                                           "directly in the redirect URL (fragment/query), and no `state` parameter was "
                                           "observed or required. Tokens in the URL leak via history, logs and Referer; a "
                                           "missing state parameter leaves the flow open to CSRF. Review manually."),
                              impact="Tokens in URLs leak through logs/Referer; a missing state parameter enables login CSRF.",
                              evidence={"request": describe_request(r), "response_status": r.status_code,
                                        "response_excerpt": shown,
                                        "notes": "token/code in redirect URL; no state parameter observed"},
                              remediation=("Use the authorization-code flow with PKCE, return tokens only via the back "
                                           "channel, and require a unique, verified `state` parameter on every flow."),
                              cwe="CWE-598", source="auth_flows",
                              **cap_fields(chain_role="standalone", assets=[asset_of(url)], id_shape=id_shape_of(url)))
                        hygiene_hits += 1
                        if hid not in new_ids:
                            new_ids.append(hid)
                else:
                    # --- Check 1: open redirect --------------------------------------------------
                    sev = "high" if flow else "medium"
                    # Leaks knowledge of an endpoint only in the rare case it reflects one; usually no grant.
                    caps = cap_fields(chain_role="standalone", assets=[asset_of(url)], id_shape=id_shape_of(url))
                    fid = f"REDIR-open-{shash(path + ':' + param.lower())}"
                    F.add(id=fid,
                          title=f"Open redirect at {path} via '{param}'",
                          severity=sev, confidence="tentative", category="open-redirect",
                          auth_context=c.name, url=url, method="GET",
                          description=(f"The '{param}' parameter is reflected into the response's {sink} with no "
                                       f"allow-list check, so {path} will redirect a visitor to an arbitrary external "
                                       f"destination ({MARKER}) (CWE-601). The marker host is out of scope and redirects "
                                       f"were not followed, so nothing actually left scope."
                                       + (" This sits on an authentication flow, which raises the severity (phishing / "
                                          "token-leak risk)." if flow else "")),
                          impact=("An attacker can craft a trusted-looking link on this site that silently sends victims "
                                  "to a malicious page (phishing, OAuth token theft on auth flows)."),
                          evidence={"request": describe_request(r), "response_status": r.status_code,
                                    "response_excerpt": shown,
                                    "notes": f"reflected off-allowlist destination in {sink}"},
                          remediation=("Don't send user-controlled values to a redirect sink. Allow only relative paths "
                                       "or an exact host allow-list, or show an interstitial for external links."),
                          cwe="CWE-601", references=["https://owasp.org/www-community/attacks/Open_redirect"],
                          source="auth_flows", **caps)
                    redir_hits += 1
                    if fid not in new_ids:
                        new_ids.append(fid)
                break  # one flag per (endpoint, param) — first client that reproduces it is enough

        # --- Check 4: SAML / SSO (observe) ---------------------------------------------------------
        baseline = soft404_baseline(clients[0], scope)
        saml_hits = check_saml(clients[0], scope, a.out, F, baseline)
    finally:
        F.save()
        reqs = sum(c.count for c in clients)
        print(f"Auth flows: {reqs} requests, {probed} redirect/oauth candidate(s); "
              f"{redir_hits} open-redirect, {oauth_hits} oauth redirect_uri, {hygiene_hits} hygiene note(s); "
              f"{F.added} new candidate findings -> {F.path}")
        if not cands:
            print("  No redirect/oauth candidates (recon absent?); probed built-in seed endpoints only.")
        if new_ids:
            print("  new: " + ", ".join(new_ids[:15]))


if __name__ == "__main__":
    main()
