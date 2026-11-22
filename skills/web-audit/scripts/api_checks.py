#!/usr/bin/env python3
"""Phase C: deep API / web-service security checks. Read-only (GET only) by default.

Reads recon.json / recon-<session>.json from the out dir for candidate API endpoints
(endpoint_templates, js_endpoints, js_absolute_urls, browser_crawl.api_urls, page URLs) and
focuses on JSON / API endpoints (path under /api, a /graphql path, or a JSON content type).

It emits *candidate* findings for the API-specific weaknesses that the generic authz replay does
not cover in depth:

  1. BOLA / object-level authz (CWE-639) — templated object endpoints with an id requested as
     another actor (user_b) and anonymously; flagged when a 2xx JSON body returns an object that
     belongs to someone other than the requester.
  2. BFLA / broken function-level authz (CWE-285) — admin / privileged endpoints reachable by a
     normal user or anonymously.
  3. Excessive data exposure (CWE-213) — authenticated JSON that carries sensitive keys the UI
     hides (password_hash, role, is_admin, ssn, secret, token, other users' emails, ...).
  4. GraphQL field-level-authz hygiene (observe only) — one introspection GET; notes
     privileged-looking types. Does NOT duplicate extra_checks' GQL-introspection finding.
  5. API inventory — old versioned siblings (/api/v1 beside /v2) and debug endpoints. Low severity.

Everything goes through common.Client (scope, rate limit, logging, redaction). GET only; excluded
paths and the state-changing deny-list are enforced by common. Baselines against a nonexistent id
avoid soft-404 false positives. BOLA findings are de-duped by templated path.
"""
import argparse
import difflib
import glob
import json
import os
import re
import sys
from urllib.parse import urljoin, urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (  # noqa: E402
    Client, Findings, ScopeError, TargetDistress, asset_of, cap_fields,
    describe_request, excerpt, id_shape_of, load_scope_or_exit, load_sessions,
    redact, shash,
)

# -- id detection / templating -------------------------------------------------------------
_NUM = r"\d{1,12}"
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_HEX24 = r"[0-9a-f]{24}"
ID_TOKEN = re.compile(r"(?i)(?<![0-9a-z])(" + _UUID + "|" + _HEX24 + "|" + _NUM + r")(?![0-9a-z])")

# Privileged / function-level paths (BFLA candidates).
PRIVILEGED_RE = re.compile(r"(?i)(?:^|/)(?:admin|administrator|manage|management|internal|"
                           r"backoffice|back-office|console|superuser|sysadmin|staff|moderat)")
# Debug / diagnostic endpoints (inventory).
DEBUG_RE = re.compile(r"(?i)(?:^|/)(?:debug|trace|actuator|_debug|__debug|phpinfo|server-status|"
                      r"swagger|openapi|metrics|healthz?/debug|console|test-?api)\b")
# Version marker in a path, e.g. /api/v2/...  -> ("/api", "2", rest)
VERSION_RE = re.compile(r"(?i)(?P<pre>/(?:api|rest|graphql)?)?/v(?P<ver>\d{1,3})(?=/|$)")

# Sensitive JSON keys the UI should not expose (excessive data exposure).
SENSITIVE_KEYS = {
    "password", "passwd", "pwd", "password_hash", "passwordhash", "pw_hash",
    "hash", "salt", "secret", "client_secret", "api_key", "apikey", "private_key",
    "token", "access_token", "refresh_token", "session", "ssn", "social_security",
    "is_admin", "isadmin", "admin", "role", "roles", "scope", "scopes", "permissions",
    "credit", "credit_card", "card_number", "cvv", "cost_price", "internal_notes",
}
# Keys that specifically hand over a secret / credential primitive.
SECRET_KEYS = {"password", "passwd", "pwd", "password_hash", "passwordhash", "pw_hash",
               "hash", "salt", "secret", "client_secret", "api_key", "apikey",
               "private_key", "token", "access_token", "refresh_token", "cvv"}
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")

GQL_PATHS = ["/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql", "/query", "/gql"]
INTROSPECTION = "{__schema{queryType{name} types{name fields{name}}}}"
# Type names that suggest privileged data a resolver must guard.
PRIV_TYPE_RE = re.compile(r"(?i)(admin|secret|credential|password|internal|billing|payment|"
                          r"invoice|audit|permission|role|setting|config|user)")


def load_json(path):
    if path and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as f:
                return json.load(f)
        except (ValueError, OSError):
            return None
    return None


def ok(r):
    return r is not None and 200 <= r.status_code < 300


def is_json_response(r):
    if r is None:
        return False
    ct = r.headers.get("Content-Type", "").lower()
    if "json" in ct or "graphql" in ct:
        return True
    if "html" in ct:
        return False
    s = (r.text or "").lstrip()[:1]
    return s in ("{", "[")


def parse_json(r):
    if r is None:
        return None
    try:
        return json.loads(r.text or "")
    except (ValueError, TypeError):
        return None


def norm_body(text):
    # Drop long digit runs / hashes so baseline similarity is about shape, not the id value.
    return re.sub(r"[0-9a-f]{8,}|\d{2,}", "#", (text or "")[:6000])


def similarity(a, b):
    return difflib.SequenceMatcher(None, norm_body(a), norm_body(b)).ratio()


def resolve(target, ep):
    ep = (ep or "").strip()
    if not ep or ep.startswith(("#", "data:", "mailto:", "javascript:", "//")):
        return None
    if ep.startswith(("http://", "https://")):
        return ep
    return urljoin(target.rstrip("/") + "/", ep.lstrip("/"))


def templatize(url):
    """Grouping key: path with ids collapsed to {id} (+ sorted query-param names)."""
    parts = urlsplit(url)
    path = ID_TOKEN.sub("{id}", parts.path) or "/"
    qkeys = sorted({kv.split("=", 1)[0] for kv in parts.query.split("&") if kv})
    return path + ("?" + ",".join(qkeys) if qkeys else "")


def path_of(url):
    return urlsplit(url).path or "/"


def markers_in(text, markers):
    t = (text or "").lower()
    return [m for m in (markers or []) if m and m.lower() in t]


# -- candidate collection ------------------------------------------------------------------
def collect_templates(out_dir, target, scope):
    """Merge every recon*.json into {template_key: {path, id_shape, asset, urls}} for API-ish
    endpoints. urls is a set of concrete, resolved, in-scope example URLs."""
    merged = {}

    def add(raw):
        u = resolve(target, raw)
        if not u or not scope.in_scope(u) or scope.excluded(u):
            return
        key = templatize(u)
        g = merged.setdefault(key, {"path": path_of(u).rstrip("/") or "/", "urls": set(),
                                    "id_shape": "none", "asset": None})
        g["urls"].add(u)
        sh = id_shape_of(u)
        if sh != "none" and (g["id_shape"] == "none" or sh == "uuid"):
            g["id_shape"] = sh
        if g["asset"] is None:
            g["asset"] = asset_of(u)

    for fname in sorted(glob.glob(os.path.join(out_dir, "recon*.json"))):
        doc = load_json(fname)
        if not isinstance(doc, dict):
            continue
        for t in doc.get("endpoint_templates", []):
            for ex in t.get("example_urls", []) or [t.get("template")]:
                add(ex)
        for ep in doc.get("js_endpoints", []) + doc.get("js_absolute_urls", []):
            add(ep)
        for ep in (doc.get("browser_crawl", {}) or {}).get("api_urls", []):
            add(ep)
        for p in doc.get("pages", []):
            add(p.get("url"))
    return merged


def is_api_ish(tmpl_key, g):
    p = (g["path"] or "").lower()
    return p.startswith("/api") or "graphql" in p or "gql" in p


def extract_ids(urls):
    ids = set()
    for u in urls:
        for m in ID_TOKEN.finditer(path_of(u)):
            ids.add(m.group(1))
    return ids


def id_pool(template_urls, idmap, id_shape):
    """Candidate ids for an object template: ids from the id-map + ids seen in recon +
    a few sequential neighbours. Capped small and rate-limited by the Client."""
    pool = []
    seen = set()

    def push(v):
        v = str(v)
        if v and v not in seen:
            seen.add(v)
            pool.append(v)

    if idmap:
        for actor in ("user_a", "user_b", "admin"):
            for v in (idmap.get(actor) or []):
                push(v)
    for v in extract_ids(template_urls):
        push(v)
    if id_shape == "sequential":
        for base in list(pool):
            if base.isdigit():
                n = int(base)
                for d in (1, -1, 2):
                    if n + d > 0:
                        push(n + d)
    return pool[:6]


def owner_hint(data):
    """Pull an owner/identity string out of a JSON object for the evidence note."""
    if isinstance(data, dict):
        for k in ("owner", "email", "user", "username", "user_email", "customer"):
            v = data.get(k)
            if isinstance(v, str):
                return v
    return ""


# -- BOLA ----------------------------------------------------------------------------------
def check_bola(F, clients, templates, idmap, union_markers, baseline_cache):
    """clients: list of (actor_name, Client, own_markers). First actor should be anonymous."""
    new = []
    for key, g in templates.items():
        if not is_api_ish(key, g):
            continue
        if "{id}" not in key and g["id_shape"] == "none":
            continue  # not an object endpoint
        # Build a URL template with {id} in the PATH only (never touch host/port digits).
        tmpl_url = None
        for u in sorted(g["urls"]):
            parts = urlsplit(u)
            tpath = ID_TOKEN.sub("{id}", parts.path)
            if "{id}" in tpath:
                tmpl_url = f"{parts.scheme}://{parts.netloc}{tpath}"
                break
        if not tmpl_url:
            continue
        ids = id_pool(g["urls"], idmap, g["id_shape"])
        if not ids:
            continue
        # Baseline: a nonexistent id (soft-404 guard), fetched once anonymously.
        anon = clients[0][1]
        bogus = "999999999" if g["id_shape"] != "uuid" else "00000000-0000-4000-8000-000000000000"
        base = baseline_cache.get(tmpl_url)
        if base is None:
            try:
                br = anon.get(tmpl_url.replace("{id}", bogus))
            except (ScopeError, TargetDistress):
                br = None
            base = {"ok": ok(br), "body": (br.text if br is not None else "")}
            baseline_cache[tmpl_url] = base

        leak = {"cross_user": False, "anon": False, "ids": [], "owners": set(),
                "rep": None, "rep_url": None}
        for actor_name, client, own_m in clients:
            if client is None:
                continue
            for oid in ids:
                u = tmpl_url.replace("{id}", str(oid))
                try:
                    r = client.get(u)
                except (ScopeError, TargetDistress):
                    continue
                if not ok(r) or not is_json_response(r):
                    continue
                body = r.text or ""
                # Soft-404 guard: a real object must differ from the nonexistent-id baseline.
                if base["ok"] and similarity(body, base["body"]) >= 0.95:
                    continue
                data = parse_json(r)
                if data in (None, [], {}):
                    continue
                foreign = [m for m in union_markers if m.lower() in body.lower()
                           and m not in (own_m or [])]
                # anonymous: any real object is an unauth object read; authed actor: needs a
                # foreign identity in the body (another user's object).
                if actor_name == "anonymous":
                    leak["anon"] = True
                elif foreign:
                    leak["cross_user"] = True
                else:
                    continue
                if u not in leak["ids"]:
                    leak["ids"].append(u)
                oh = owner_hint(data)
                if oh:
                    leak["owners"].add(oh)
                if leak["rep"] is None:
                    leak["rep"], leak["rep_url"] = r, u
        if not (leak["cross_user"] or leak["anon"]):
            continue
        new.append(emit_bola(F, tmpl_url, g, leak))
    return new


def emit_bola(F, tmpl_url, g, leak):
    path_key = templatize(tmpl_url)
    fid = f"API-bola-{shash('GET ' + path_key)}"
    shape = g["id_shape"]
    asset = g["asset"]
    ctx = "cross-user" if leak["cross_user"] else "anonymous"
    enum = " IDs look sequential, so records are enumerable at scale." if shape == "sequential" else ""
    owners = ", ".join(sorted(leak["owners"]))[:200]
    ex = "; ".join(leak["ids"][:5]) + (f" (+{len(leak['ids']) - 5} more)" if len(leak["ids"]) > 5 else "")
    how = ("Another user's object was returned to a different authenticated user"
           if leak["cross_user"] else "Object was returned to an unauthenticated request")
    desc = (f"{how}. The JSON API endpoint {path_key} returns objects by id with no owner/authz "
            f"check.{enum} Example URL(s): {ex}." + (f" Owner(s) in the leaked bodies: {owners}." if owners else ""))
    rep = leak["rep"]
    # requires knowledge:user-ids UNLESS ids are sequential (then they are guessable).
    req = None if shape == "sequential" else ["knowledge:user-ids"]
    F.add(id=fid, title="BOLA / IDOR — object-level authorization missing on a JSON API",
          severity="high", confidence="firm", category="broken-access-control",
          auth_context=ctx, url=leak["rep_url"], method="GET", description=desc,
          impact="Any user (or anyone at all, when anonymous) can read other users' records by "
                 "changing the object id in the URL." + enum,
          evidence={"request": redact(describe_request(rep)) if rep is not None else "",
                    "response_status": rep.status_code if rep is not None else None,
                    "response_excerpt": excerpt(rep.text if rep is not None else "", 500),
                    "example_urls": leak["ids"],
                    "notes": f"template {path_key}; id_shape {shape}; owners {owners or 'n/a'}"},
          remediation="Enforce per-object authorization on the server: verify the authenticated "
                      "caller owns or may access the requested object before returning it. Do not "
                      "rely on unguessable ids.",
          cwe="CWE-639", source="api_checks",
          **cap_fields(grants=["read:any-user"], requires=req, assets=[asset] if asset else None,
                       id_shape=shape, chain_role="authz"))
    return fid


# -- BFLA ----------------------------------------------------------------------------------
def check_bfla(F, clients, templates, shell_cache):
    new = []
    for key, g in templates.items():
        path = g["path"]
        if not PRIVILEGED_RE.search(path):
            continue
        if "{id}" in key:
            continue  # object endpoints handled by BOLA
        # Prefer a concrete URL; fall back to the path.
        url = sorted(g["urls"])[0] if g["urls"] else None
        if not url:
            continue
        anon_reach = False
        user_reach = False
        rep = None
        rep_actor = None
        for actor_name, client, _ in clients:
            if client is None:
                continue
            try:
                r = client.get(url)
            except (ScopeError, TargetDistress):
                continue
            if not ok(r):
                continue
            # Must not be the generic soft-404/SPA shell served to unknown paths.
            shell = shell_cache.get("body")
            if shell and "html" in r.headers.get("Content-Type", "").lower() \
                    and similarity(r.text, shell) >= 0.9:
                continue
            if actor_name == "anonymous":
                anon_reach = True
            else:
                user_reach = True
            if rep is None:
                rep, rep_actor = r, actor_name
        if not (anon_reach or user_reach):
            continue
        new.append(emit_bfla(F, key, g, url, anon_reach, rep, rep_actor))
    return new


def emit_bfla(F, key, g, url, anon_reach, rep, rep_actor):
    fid = f"API-bfla-{shash('GET ' + key)}"
    asset = g["asset"]
    if anon_reach:
        ctx, req, who = "anonymous", ["none"], "an unauthenticated request"
    else:
        ctx, req, who = "cross-role", ["identity:user"], "a normal (non-admin) user"
    desc = (f"The privileged endpoint {key} returns a 2xx response to {who}. No function-level "
            f"authorization is enforced. URL: {url}.")
    F.add(id=fid, title="Broken function-level authorization — admin/privileged endpoint reachable",
          severity="high", confidence="firm", category="broken-access-control",
          auth_context=ctx, url=url, method="GET", description=desc,
          impact="Callers without the admin role can invoke privileged functionality or read "
                 "administrative data (here, the full user/role listing).",
          evidence={"request": redact(describe_request(rep)) if rep is not None else "",
                    "response_status": rep.status_code if rep is not None else None,
                    "response_excerpt": excerpt(rep.text if rep is not None else "", 500),
                    "notes": f"reachable as {rep_actor}; template {key}"},
          remediation="Enforce a server-side role/permission check on every privileged route; deny "
                      "by default and require the admin role explicitly.",
          cwe="CWE-285", source="api_checks",
          **cap_fields(grants=["read:admin"], requires=req, assets=[asset] if asset else None,
                       id_shape=g["id_shape"], chain_role="privilege"))
    return fid


# -- excessive data exposure ---------------------------------------------------------------
def walk_keys(obj):
    """Yield (key, value) for every key in a nested JSON structure."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield str(k), v
            yield from walk_keys(v)
    elif isinstance(obj, list):
        for item in obj:
            yield from walk_keys(item)


def check_data_exposure(F, clients, templates, union_markers, skip_paths):
    new = []
    seen = set()
    for key, g in templates.items():
        if not is_api_ish(key, g) or "{id}" in key:
            # EDE focuses on non-object JSON endpoints (e.g. /api/me); object leaks are BOLA.
            if "{id}" in key:
                continue
        if g["path"] in skip_paths or key in seen:
            continue
        url = sorted(g["urls"])[0] if g["urls"] else None
        if not url:
            continue
        for actor_name, client, own_m in clients:
            if client is None or actor_name == "anonymous":
                # EDE is about what an *authenticated* response over-shares; still allow anon if
                # it is the only actor available.
                if any(c is not None and n != "anonymous" for n, c, _ in clients):
                    continue
            try:
                r = client.get(url)
            except (ScopeError, TargetDistress):
                continue
            if not ok(r) or not is_json_response(r):
                continue
            data = parse_json(r)
            if data is None:
                continue
            found = sorted({k.lower() for k, _ in walk_keys(data) if k.lower() in SENSITIVE_KEYS})
            body = r.text or ""
            foreign_emails = sorted({e for e in EMAIL_RE.findall(body)
                                     if e not in (own_m or [])})
            if not found and not foreign_emails:
                continue
            seen.add(key)
            new.append(emit_data_exposure(F, key, url, actor_name, found, foreign_emails, r))
            break
    return new


def emit_data_exposure(F, key, url, actor_name, found, foreign_emails, r):
    fid = f"API-excessive-data-{shash('GET ' + key)}"
    secret_leak = any(k in SECRET_KEYS for k in found)
    ctx = actor_name if actor_name in ("user_a", "user_b", "admin", "anonymous") else "user_a"
    grants = []
    if secret_leak:
        grants.append("knowledge:secret")
    if foreign_emails:
        grants.append("knowledge:user-ids")
    sev = "high" if secret_leak else "medium"
    keys_txt = ", ".join(found) if found else "n/a"
    extra = (f" It also returns {len(foreign_emails)} other identifier(s) (e.g. email) "
             "the caller should not see." if foreign_emails else "")
    desc = (f"The JSON response from {key} includes sensitive field(s) the UI never shows: "
            f"{keys_txt}.{extra} Clients should receive only the fields they need.")
    F.add(id=fid, title="Excessive data exposure — API returns sensitive fields",
          severity=sev, confidence="firm", category="sensitive-data-exposure",
          auth_context=ctx, url=url, method="GET", description=desc,
          impact=("The response leaks a credential/secret value (e.g. a password hash) to any "
                  "client that can reach the endpoint." if secret_leak
                  else "The response discloses internal fields (roles, flags, other users' "
                       "identifiers) that widen the attack surface."),
          evidence={"request": redact(describe_request(r)),
                    "response_status": r.status_code,
                    "response_excerpt": excerpt(r.text, 500),
                    "notes": f"sensitive keys: {keys_txt}; foreign identifiers: {len(foreign_emails)}"},
          remediation="Return a minimal, explicit DTO per endpoint. Never serialize password "
                      "hashes, secrets, internal flags or other users' identifiers; filter at the "
                      "serialization layer, not the UI.",
          cwe="CWE-213", source="api_checks",
          **cap_fields(grants=grants or None, requires=None, chain_role="disclosure",
                       assets=[asset_of(url)] if asset_of(url) else None, id_shape=id_shape_of(url)))
    return fid


# -- GraphQL field hygiene (observe only) --------------------------------------------------
def check_graphql(F, scope, clients, templates):
    paths = list(GQL_PATHS)
    for key, g in templates.items():
        if "graphql" in g["path"].lower() or "gql" in g["path"].lower():
            if g["path"] not in paths:
                paths.append(g["path"])
    from urllib.parse import quote
    for actor_name, client, _ in clients:
        if client is None:
            continue
        for p in paths:
            url = scope.target + p
            if scope.excluded(url) or not scope.in_scope(url):
                continue
            try:
                r = client.get(url + "?query=" + quote(INTROSPECTION))
            except (ScopeError, TargetDistress):
                continue
            if r is None or r.status_code != 200 or '"__schema"' not in (r.text or ""):
                continue
            data = parse_json(r) or {}
            try:
                types = data["data"]["__schema"]["types"]
            except (KeyError, TypeError):
                types = []
            priv = sorted({t["name"] for t in types if isinstance(t, dict)
                           and not str(t.get("name", "")).startswith("__")
                           and PRIV_TYPE_RE.search(str(t.get("name", "")))})
            if not priv:
                return []  # schema present but nothing privilege-shaped: extra_checks covers it
            fid = f"API-graphql-authz-{shash(url)}"
            F.add(id=fid, title="GraphQL schema exposes privileged types — field-level authz review needed",
                  severity="low", confidence="firm", category="information-disclosure",
                  auth_context=actor_name if actor_name in ("anonymous", "user_a", "user_b", "admin") else "anonymous",
                  url=url, method="GET",
                  description=("Introspection reveals privileged-looking type(s): "
                               + ", ".join(priv[:20])
                               + ". Confirm every field on these types enforces authorization in its "
                                 "resolver (introspection alone does not prove a gap — observation only)."),
                  impact="If resolvers trust the schema for access control, these types may be "
                         "queryable by unauthorized callers.",
                  evidence={"request": describe_request(r), "response_status": 200,
                            "response_excerpt": excerpt(", ".join(priv), 500),
                            "notes": "observation only; one introspection GET; no deep/batched queries run"},
                  remediation="Enforce authorization in each resolver (not just at the schema edge) "
                              "and disable introspection in production.",
                  cwe="CWE-285", source="api_checks",
                  **cap_fields(chain_role="disclosure"))
            return [fid]
    return []


# -- API inventory (versioned siblings + debug) --------------------------------------------
def check_inventory(F, clients, templates):
    new = []
    # Versioned siblings: same base path family seen at >= 2 versions.
    families = {}
    for key, g in templates.items():
        m = VERSION_RE.search(g["path"])
        if not m:
            continue
        fam = (g["path"][:m.start()], g["path"][m.end():])
        families.setdefault(fam, set()).add(int(m.group("ver")))
    for (pre, rest), vers in families.items():
        if len(vers) < 2:
            continue
        old = sorted(vers)[:-1]
        fid = f"API-version-sibling-{shash(pre + '|' + rest)}"
        example = f"{pre}/v{sorted(vers)[0]}{rest}"
        new.append(fid)
        F.add(id=fid, title="Old API version still reachable alongside a newer one",
              severity="low", confidence="firm", category="security-misconfiguration",
              auth_context="anonymous", url=example, method="GET",
              description=(f"Multiple API versions are exposed for {pre}…{rest}: "
                           f"v{', v'.join(str(v) for v in sorted(vers))}. Older versions "
                           f"(v{', v'.join(str(v) for v in old)}) often miss fixes present in the latest."),
              impact="Deprecated versions widen the attack surface and may lack authorization or "
                     "input-validation fixes shipped in the current version.",
              evidence={"request": f"GET {example}", "notes": f"versions seen: {sorted(vers)}"},
              remediation="Retire or gate deprecated API versions; keep a single supported surface.",
              cwe="CWE-1059", source="api_checks",
              **cap_fields(chain_role="standalone"))
    # Debug endpoints that are actually reachable.
    anon = clients[0][1]
    for key, g in templates.items():
        if not DEBUG_RE.search(g["path"]) or "{id}" in key:
            continue
        url = sorted(g["urls"])[0] if g["urls"] else None
        if not url:
            continue
        try:
            r = anon.get(url)
        except (ScopeError, TargetDistress):
            continue
        if not ok(r):
            continue
        fid = f"API-debug-endpoint-{shash('GET ' + key)}"
        new.append(fid)
        F.add(id=fid, title="Debug / diagnostic endpoint reachable", severity="low",
              confidence="firm", category="security-misconfiguration",
              auth_context="anonymous", url=url, method="GET",
              description=f"A debug/diagnostic endpoint responds 2xx: {key}.",
              impact="Debug endpoints can leak internals (config, stack traces, metrics) or enable "
                     "actions never meant for production.",
              evidence={"request": redact(describe_request(r)), "response_status": r.status_code,
                        "response_excerpt": excerpt(r.text, 300), "notes": f"template {key}"},
              remediation="Remove or restrict debug/diagnostic endpoints in production.",
              cwe="CWE-489", source="api_checks", **cap_fields(chain_role="disclosure"))
    return new


# -- main ----------------------------------------------------------------------------------
def build_clients(scope, out_dir, sessions, session_names, other, admin):
    """Return [(actor_name, Client|None, own_markers)] with anonymous first."""
    clients = [("anonymous", Client(scope, out_dir, "anonymous"), [])]
    wanted = []
    for n in (session_names or []):
        wanted.append(n)
    for n in (other, admin):
        if n:
            wanted.append(n)
    seen = set()
    for name in wanted:
        if not name or name in seen or name not in sessions:
            continue
        seen.add(name)
        entry = sessions.get(name)
        markers = (entry or {}).get("identity_markers", [])
        clients.append((name, Client(scope, out_dir, name, entry), markers))
    return clients


def main():
    ap = argparse.ArgumentParser(description="Deep API security checks (read-only, GET only).")
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sessions")
    ap.add_argument("--session", action="append", default=[],
                    help="session name(s) to drive authed checks (repeatable); also accepts user_a")
    ap.add_argument("--other", help="a second user session for cross-user BOLA tests (e.g. user_b)")
    ap.add_argument("--admin", help="an admin session name (used as an extra actor)")
    ap.add_argument("--id-map", help="JSON with templates + per-user id lists (reused for BOLA ids)")
    a = ap.parse_args()

    scope = load_scope_or_exit(a.scope)
    sessions = load_sessions(a.sessions)
    F = Findings(a.out, scope.target)

    # id-map: explicit path, else tests/ids.json convention next to the out dir isn't assumed;
    # fall back to <out>/ids.json if present.
    idmap = load_json(a.id_map) if a.id_map else load_json(os.path.join(a.out, "ids.json"))

    # Default the primary session to user_a when sessions exist and none was named.
    session_names = list(a.session)
    if not session_names and "user_a" in sessions:
        session_names = ["user_a"]
    other = a.other or ("user_b" if "user_b" in sessions and "user_b" not in session_names else None)

    clients = build_clients(scope, a.out, sessions, session_names, other, a.admin)
    union_markers = sorted({m for _, _, mk in clients for m in (mk or [])})

    templates = collect_templates(a.out, scope.target, scope)
    if not templates:
        print("API checks: no recon*.json candidates found — run recon.py first. 0 requests, 0 new candidate findings.")
        F.save()
        return

    new_ids = []
    baseline_cache = {}
    shell_cache = {}
    try:
        # Establish the soft-404 / SPA shell served to an unknown path (BFLA guard).
        import random
        import string
        rnd = "/zz-nope-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=14))
        try:
            sh = clients[0][1].get(scope.target + rnd)
            if ok(sh) and "html" in sh.headers.get("Content-Type", "").lower():
                shell_cache["body"] = sh.text
        except (ScopeError, TargetDistress):
            pass

        new_ids += check_bola(F, clients, templates, idmap, union_markers, baseline_cache)
        new_ids += check_bfla(F, clients, templates, shell_cache)
        new_ids += check_data_exposure(F, clients, templates, union_markers,
                                       skip_paths={t["path"] for k, t in templates.items()
                                                   if PRIVILEGED_RE.search(t["path"])})
        new_ids += check_graphql(F, scope, clients, templates)
        new_ids += check_inventory(F, clients, templates)
    except TargetDistress as e:
        print(f"TargetDistress: {e}")
    finally:
        F.save()

    reqs = sum(c.count for _, c, _ in clients if c is not None)
    new_ids = [i for i in new_ids if i]
    print(f"API checks: {reqs} requests, {F.added} new candidate findings -> {F.path}")
    for fid in new_ids[:15]:
        print(f"  + {fid}")


if __name__ == "__main__":
    main()
