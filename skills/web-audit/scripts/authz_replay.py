#!/usr/bin/env python3
"""Phases 2-3: access-control replay.

Requests endpoints that one identity can see as another identity (other user, anonymous, lower
role) and flags responses that leak the owner's data. GET only — safe to run by default.

Endpoint sources (combined):
  * recon-<owner>.json pages returning 200 that were NOT public in the anonymous recon.json
  * recon.json / recon-<owner>.json js_endpoints, js_absolute_urls and browser_crawl api_urls
  * <out>/endpoints.txt (HAR GET endpoints) when present
  * --endpoints file (one URL per line)
  * --id-map ids.json  (templates with {id} + per-user ID lists)  -> cross-user ID swaps
  * --admin: pages in recon-<admin>.json that the owner never saw  -> function-level checks

Findings are grouped by (method + templated path), so one IDOR on /orders/{id} is a single
finding listing example URLs. Before replay each actor's session is probed with a liveness
canary; a dead session produces a loud WARNING instead of silently "denied everywhere".
"""
import argparse
import difflib
import json
import os
import random
import re
import string
import sys
from urllib.parse import urljoin, urlsplit, urlparse, parse_qsl

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (  # noqa: E402
    Client, Findings, ScopeError, TargetDistress, asset_of, cap_fields,
    describe_request, excerpt, load_scope_or_exit, load_sessions, redact, shash,
)

# -- id detection: numeric (sequential), UUID, 24-hex (Mongo ObjectId) ---------------------
_NUM = r"\d{1,12}"
_UUID = r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
_HEX24 = r"[0-9a-f]{24}"
ID_TOKEN = re.compile(r"(?i)(?<![0-9a-z])(" + _UUID + "|" + _HEX24 + "|" + _NUM + r")(?![0-9a-z])")
VOLATILE = re.compile(r"[0-9a-f]{16,}|\d{6,}|(?i:csrf[^\"'<>]{0,40}[\"'][^\"']+[\"'])|nonce=\"[^\"]+\"")

# -- denial detection (A4): only structural login/forbidden signals count as "denied" -------
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
H1_RE = re.compile(r"<h1[^>]*>(.*?)</h1>", re.I | re.S)
PWD_RE = re.compile(r"type=[\"']password[\"']", re.I)
DENIAL_KW = re.compile(
    r"(?i)(sign[\s-]?in|log[\s-]?in|unauthori[sz]ed|forbidden|access denied|"
    r"not authenticated|permission denied|authentication required|please (?:log|sign) ?in)")
_JSON_ERR_KEYS = ("error", "errors", "message", "detail", "title", "reason")


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


def norm(text):
    return VOLATILE.sub("~", (text or "")[:8000])


def similarity(a, b):
    return difflib.SequenceMatcher(None, norm(a), norm(b)).ratio()


def markers_in(text, markers):
    t = (text or "").lower()
    return [m for m in (markers or []) if m and m.lower() in t]


def _first_group(rx, text):
    m = rx.search(text or "")
    return (m.group(1) if m else "")


def is_htmlish(r):
    if r is None:
        return False
    ct = r.headers.get("Content-Type", "").lower()
    if "html" in ct:
        return True
    if ct and ("json" in ct or "javascript" in ct or "css" in ct or "image" in ct
               or "font" in ct or "octet" in ct or "pdf" in ct):
        return False
    return (r.text or "").lstrip()[:1] == "<"


def is_checkable_type(r):
    """A8: only HTML or JSON responses are candidates for the anon-access check."""
    if r is None:
        return False
    ct = r.headers.get("Content-Type", "").lower()
    if "html" in ct or "json" in ct:
        return True
    if not ct:  # no content-type — fall back to a cheap sniff
        s = (r.text or "").lstrip()[:1]
        return s in ("<", "{", "[")
    return False


def _json_denial(data):
    if isinstance(data, dict):
        for k in _JSON_ERR_KEYS:
            v = data.get(k)
            if isinstance(v, str) and DENIAL_KW.search(v):
                return True
        err = data.get("error")
        if isinstance(err, str) and re.search(r"(?i)auth|forbid|denied|login|permission|token|unauthenti", err):
            return True
    return False


def denial_signal(r, owner_markers=None):
    """A4: decide 'denied' by markers FIRST, then only via login/forbidden signals in
    <title>/<h1>/password-input/JSON error keys — never anywhere in the body. A page that
    merely has a 'Log in' nav link is NOT a denial."""
    if r is None:
        return True
    if r.status_code in (401, 403, 404) or r.is_redirect:
        return True
    body = r.text or ""
    # Owner's own content present => this is a leak, not a denial.
    if owner_markers and markers_in(body, owner_markers):
        return False
    ct = r.headers.get("Content-Type", "").lower()
    if "json" in ct:
        try:
            return _json_denial(json.loads(body))
        except ValueError:
            return False
    # HTML / unknown: structural signals only.
    if PWD_RE.search(body) and len(body) < 20000:  # a login form, not a stray field
        return True
    hay = _first_group(TITLE_RE, body) + " \n " + _first_group(H1_RE, body)
    return bool(DENIAL_KW.search(hay))


# -- id shape / templating (A5, A10) -------------------------------------------------------
def id_shape(url, from_idmap=False):
    if re.search("(?i)" + _UUID, url) or re.search("(?i)" + _HEX24, url):
        return "uuid"
    parts = urlsplit(url)
    for seg in parts.path.split("/"):
        if re.fullmatch(_NUM, seg):
            return "sequential"
    for _, v in parse_qsl(parts.query):
        if re.fullmatch(_NUM, v):
            return "sequential"
    return "none"


def has_id(url, from_idmap=False):
    """A5: an id in the path OR a query-string value, or any id-map-derived URL."""
    if from_idmap:
        return True
    parts = urlsplit(url)
    if ID_TOKEN.search(parts.path):
        return True
    for _, v in parse_qsl(parts.query):
        if ID_TOKEN.fullmatch(v):
            return True
    return False


def templatize(url):
    """A10 grouping key: method is always GET, so key on the path with ids -> {id}
    plus the sorted set of query parameter names."""
    parts = urlsplit(url)
    path = ID_TOKEN.sub("{id}", parts.path) or "/"
    qkeys = sorted({k for k, _ in parse_qsl(parts.query)})
    return path + ("?" + ",".join(qkeys) if qkeys else "")


# -- candidate sources (A6) ----------------------------------------------------------------
def _resolve(target, ep):
    ep = (ep or "").strip()
    if not ep or ep.startswith(("#", "data:", "mailto:", "javascript:")):
        return None
    if ep.startswith(("http://", "https://")):
        return ep
    if ep.startswith("//"):
        return None  # protocol-relative to some other host; skip
    return urljoin(target.rstrip("/") + "/", ep.lstrip("/"))


def candidate_urls(out_dir, target, owner, extra_file, scope):
    anon = load_json(os.path.join(out_dir, "recon.json")) or {}
    public = {p["url"] for p in anon.get("pages", []) if p.get("status") == 200}
    urls = []
    own = load_json(os.path.join(out_dir, f"recon-{owner}.json")) if owner else None
    if own:
        for p in own.get("pages", []):
            if p.get("status") == 200 and p["url"] not in public and not p["url"].endswith((".xml", "robots.txt")):
                urls.append(p["url"])
    # A6: JS-mined endpoints + browser-crawl XHR/fetch URLs from both recon files.
    for doc in (anon, own or {}):
        for ep in doc.get("js_endpoints", []) + doc.get("js_absolute_urls", []):
            r = _resolve(target, ep)
            if r:
                urls.append(r)
        for ep in (doc.get("browser_crawl", {}) or {}).get("api_urls", []):
            r = _resolve(target, ep)
            if r:
                urls.append(r)
    # A6: HAR GET endpoints.
    ep_txt = os.path.join(out_dir, "endpoints.txt")
    if os.path.exists(ep_txt):
        with open(ep_txt, encoding="utf-8") as f:
            for line in f:
                r = _resolve(target, line)
                if r:
                    urls.append(r)
    if extra_file:
        with open(extra_file, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    r = _resolve(target, line)
                    if r:
                        urls.append(r)
    seen, out = set(), []
    for u in urls:
        if u in seen:
            continue
        seen.add(u)
        if scope.in_scope(u) and not scope.excluded(u):
            out.append(u)
    return out, public


# -- grouping + finding emission (A10 + capabilities) --------------------------------------
def _new_group(kind, owner, other):
    return {"kind": kind, "owner": owner, "other": other, "urls": [], "matched": set(),
            "sim": 0.0, "confirmed": False, "has_id": False, "id_shape": "none",
            "asset": None, "rep_owner": None, "rep_other": None, "sens": False}


def record(groups, kind, url, owner_name, other_name, r_owner, r_other, matched, sim, from_idmap, sens):
    key = (kind, templatize(url))
    g = groups.get(key)
    if g is None:
        g = _new_group(kind, owner_name, other_name)
        groups[key] = g
    if url not in g["urls"] and len(g["urls"]) < 8:
        g["urls"].append(url)
    g["matched"].update(matched or [])
    g["sim"] = max(g["sim"], sim or 0.0)
    g["sens"] = g["sens"] or sens
    g["has_id"] = g["has_id"] or has_id(url, from_idmap)
    sh = id_shape(url, from_idmap)
    if g["id_shape"] == "none" or (sh == "sequential"):
        g["id_shape"] = sh
    if g["asset"] is None:
        g["asset"] = asset_of(url)
    # Keep the most convincing representative pair (one that matched markers wins).
    if matched or g["rep_other"] is None:
        g["rep_owner"] = r_owner
        g["rep_other"] = r_other
    g["confirmed"] = g["confirmed"] or bool(matched)


def emit(F, key, g):
    kind = g["kind"]
    ident = shash("GET " + key[1])  # key = (kind, templated_path); stable per method+path
    urls = g["urls"]
    rep = urls[0]
    matched = sorted(g["matched"])
    sim = g["sim"]
    shape = g["id_shape"]
    asset = g["asset"]
    assets = [asset] if asset else []
    how = ("identity markers found: " + ", ".join(matched)) if matched else f"body similarity {sim:.0%}"
    ex = "; ".join(urls[:5]) + (f" (+{len(urls) - 5} more)" if len(urls) > 5 else "")
    confidence = "confirmed" if g["confirmed"] else "tentative"
    rep_o, rep_x = g["rep_owner"], g["rep_other"]

    if kind == "anon":
        fid = f"AUTHZ-unauth-access-{ident}"
        title = "Authenticated content reachable without logging in"
        ctx = "anonymous"
        admin = asset == "admin" or "/admin" in key[1].lower()
        desc = (f"{rep} returns {g['owner']}'s content to an anonymous request ({how}). "
                f"Example URL(s): {ex}.")
        impact = "Anyone on the internet can read this data without an account."
        sev = "high" if (matched or g["sens"]) else "medium"
        cwe = "CWE-306"
        caps = cap_fields(grants=["read:admin"] if admin else ["read:any-user"],
                          requires=["none"], assets=assets, id_shape=shape, chain_role="authz")
    elif kind == "cross-user":
        fid = f"AUTHZ-idor-{ident}"
        title = "Insecure direct object reference — another user's data is readable"
        ctx = "cross-user"
        enum = " IDs look sequential, so this is enumerable." if shape == "sequential" else ""
        desc = (f"{g['other']} requested objects belonging to {g['owner']} and received them ({how})."
                f"{enum} Example URL(s): {ex}.")
        impact = "Any logged-in user can read other users' records by changing the identifier." + enum
        sev = "high" if matched else "medium"
        cwe = "CWE-639"
        # requires knowledge:user-ids UNLESS the ids are sequential (enumerable).
        req = None if shape == "sequential" else ["knowledge:user-ids"]
        caps = cap_fields(grants=["read:any-user"], requires=req, assets=assets,
                          id_shape=shape, chain_role="authz")
    else:  # cross-role
        fid = f"AUTHZ-function-level-{ident}"
        title = "Admin/privileged function reachable by a normal user"
        ctx = "cross-role"
        desc = (f"{g['other']} (lower privilege) received the same response as {g['owner']} ({how}). "
                f"Example URL(s): {ex}.")
        impact = "Normal users can reach privileged functionality or data."
        sev = "high"
        cwe = "CWE-285"
        caps = cap_fields(grants=["read:admin"], requires=["identity:user"], assets=assets,
                          id_shape=shape, chain_role="privilege")

    notes = (f"grouped {len(urls)} URL(s) under {templatize(rep)}; "
             f"owner status {rep_o.status_code if rep_o is not None else 'n/a'}, "
             f"replay status {rep_x.status_code if rep_x is not None else 'n/a'}; similarity {sim:.2f}")
    F.add(id=fid, title=title, severity=sev, confidence=confidence, category="broken-access-control",
          auth_context=ctx, url=rep, method="GET", description=desc, impact=impact,
          evidence={"request": redact(describe_request(rep_x)) if rep_x is not None else "",
                    "response_status": rep_x.status_code if rep_x is not None else None,
                    "response_excerpt": excerpt(rep_x.text if rep_x is not None else "", 500),
                    "example_urls": urls, "notes": notes},
          remediation=("Enforce authorization on the server for every request: check the authenticated "
                       "user owns (or may access) the requested object/function. Do not rely on hidden "
                       "links or unguessable IDs."),
          cwe=cwe, source="authz_replay", **caps)
    return fid


# -- liveness (A1) -------------------------------------------------------------------------
def actor_canaries(out_dir, actor, entry, idmap, owner_candidates, public):
    """Ordered list of (url, expected_marker|None) to probe this actor's session."""
    if entry and entry.get("check_url"):
        return [(entry["check_url"], entry.get("check_marker"))]
    out = []
    if idmap:
        for tpl in idmap.get("templates", []):
            for oid in (idmap.get(actor, []) or [])[:1]:
                out.append((tpl.replace("{id}", str(oid)), None))
    rec = load_json(os.path.join(out_dir, f"recon-{actor}.json")) or {}
    for p in rec.get("pages", []):
        if p.get("status") == 200 and p["url"] not in public:
            out.append((p["url"], None))
        if len(out) >= 3:
            break
    for u in owner_candidates:
        out.append((u, None))
        if len(out) >= 3:
            break
    # de-dup, cap at 3 probes
    seen, res = set(), []
    for u, m in out:
        if u not in seen:
            seen.add(u)
            res.append((u, m))
    return res[:3]


def check_liveness(client, canaries, amarkers):
    """Return (alive, detail). alive is None when no canary could be constructed."""
    if client is None or not canaries:
        return None, "no canary available"
    first = canaries[0][0]
    for url, cmark in canaries:
        try:
            r = client.get(url)
        except ScopeError:
            continue
        if denial_signal(r):
            continue
        if cmark:
            if cmark.lower() in (r.text or "").lower():
                return True, url
            continue
        if amarkers:
            if markers_in(r.text, amarkers):
                return True, url
            continue
        return True, url  # 200, non-denial, nothing to assert
    return False, first


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sessions")
    ap.add_argument("--owner", default="user_a")
    ap.add_argument("--other", default="user_b")
    ap.add_argument("--admin")
    ap.add_argument("--endpoints", help="extra URLs to test, one per line")
    ap.add_argument("--id-map", help="JSON with templates and per-user id lists")
    ap.add_argument("--anon-only", action="store_true", help="only replay authenticated endpoints anonymously")
    ap.add_argument("--threshold", type=float, default=0.92, help="similarity treated as 'same response' when no identity markers")
    a = ap.parse_args()

    scope = load_scope_or_exit(a.scope)
    sessions = load_sessions(a.sessions)
    F = Findings(a.out, scope.target)
    anon = Client(scope, a.out, "anonymous")
    results = []
    groups = {}
    stats = {}  # actor -> {"req": n, "deny": n}
    liveness = {}
    dead = set()

    def bump(actor, r):
        s = stats.setdefault(actor, {"req": 0, "deny": 0})
        s["req"] += 1
        if denial_signal(r):
            s["deny"] += 1

    def safe_get(client, actor, url):
        if client is None:
            return None
        try:
            r = client.get(url)
        except ScopeError:
            return None
        bump(actor, r)
        return r

    have_owner = a.owner in sessions
    have_other = a.other in sessions and not a.anon_only
    if not have_owner and not a.endpoints:
        sys.exit(f"Need a '{a.owner}' session in --sessions (or --endpoints to test anonymously).")
    owner_c = Client(scope, a.out, a.owner, sessions.get(a.owner)) if have_owner else None
    other_c = Client(scope, a.out, a.other, sessions.get(a.other)) if have_other else None
    m_owner = (sessions.get(a.owner) or {}).get("identity_markers", [])
    m_other = (sessions.get(a.other) or {}).get("identity_markers", [])

    urls, public = candidate_urls(a.out, scope.target, a.owner if have_owner else None, a.endpoints, scope)
    idmap = load_json(a.id_map)
    if not urls and not idmap:
        print(f"No candidate URLs. Run recon.py --session {a.owner} first, or pass --endpoints / --id-map.")

    try:
        # ---- A8: establish the SPA/soft-404 shell as anonymous ----
        rand = "/zz-notfound-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        shell_text = None
        try:
            sh = anon.get(urljoin(scope.target.rstrip("/") + "/", rand.lstrip("/")))
            if ok(sh) and is_htmlish(sh):
                shell_text = sh.text
        except ScopeError:
            pass

        # ---- A1: liveness probes before replay ----
        for actor, client, mk in ((a.owner, owner_c, m_owner), (a.other, other_c, m_other)):
            if client is None:
                continue
            can = actor_canaries(a.out, actor, sessions.get(actor), idmap, urls, public)
            alive, detail = check_liveness(client, can, mk)
            liveness[actor] = {"alive": alive, "canary": detail}
            if alive is False:
                dead.add(actor)
                print(f"WARNING: {actor} session looks DEAD — liveness canary {detail} returned "
                      f"login/denied. Its authz results are unreliable; NOT reporting them as 'secure'.")

        tested = set()

        def test(url, owner_name, oc, om, other_name, xc, xm, from_idmap=False):
            if scope.excluded(url) or not scope.in_scope(url) or (url, owner_name) in tested:
                return
            tested.add((url, owner_name))
            ro = safe_get(oc, owner_name, url) if oc else None
            if oc and not ok(ro):
                return
            row = {"url": url, "owner": owner_name, "owner_status": ro.status_code if ro is not None else None}
            sens = has_id(url, from_idmap) or "json" in ((ro.headers.get("Content-Type", "")) if ro is not None else "")
            # ---- anonymous replay ----
            rn = safe_get(anon, "anonymous", url)
            row["anon_status"] = rn.status_code if rn is not None else None
            if ok(rn) and url not in public and is_checkable_type(rn) and not denial_signal(rn, om):
                shell_hit = (shell_text is not None and is_htmlish(rn)
                             and similarity(rn.text, shell_text) >= 0.90)
                if not shell_hit:
                    matched = markers_in(rn.text, om)
                    sim = similarity(ro.text, rn.text) if ro is not None else 0.0
                    if matched or (ro is not None and sim >= a.threshold):
                        record(groups, "anon", url, owner_name, "anonymous",
                               ro if ro is not None else rn, rn, matched, sim, from_idmap, sens)
                        row["anon_flag"] = True
            # ---- cross-user replay ----
            if xc is not None and not row.get("anon_flag"):
                rx = safe_get(xc, other_name, url)
                row["other_status"] = rx.status_code if rx is not None else None
                if ok(rx) and not denial_signal(rx, om):
                    matched = [m for m in markers_in(rx.text, om) if m not in markers_in(rx.text, xm)]
                    sim = similarity(ro.text, rx.text) if ro is not None else 0.0
                    # A3: similarity fallback stays ON even when owner markers are configured
                    # (missing markers lower confidence, they don't drop the result). Require an
                    # id-bearing URL for the similarity-only path so identical soft-404/shell
                    # pages don't masquerade as IDOR.
                    if matched or (ro is not None and sim >= a.threshold and has_id(url, from_idmap)):
                        record(groups, "cross-user", url, owner_name, other_name,
                               ro, rx, matched, sim, from_idmap, sens)
                        row["cross_user_flag"] = True
            results.append(row)

        for u in urls:
            test(u, a.owner, owner_c, m_owner, a.other, other_c, m_other, from_idmap=False)

        if idmap:
            pairs = [(a.owner, owner_c, m_owner, a.other, other_c, m_other)]
            if other_c is not None and owner_c is not None:
                pairs.append((a.other, other_c, m_other, a.owner, owner_c, m_owner))
            for tpl in idmap.get("templates", []):
                for own_name, oc, om, oth_name, xc, xm in pairs:
                    for oid in idmap.get(own_name, []):
                        test(tpl.replace("{id}", str(oid)), own_name, oc, om, oth_name, xc, xm, from_idmap=True)

        # ---- vertical / function-level (admin reachable by a normal user) ----
        if a.admin and a.admin in sessions and owner_c is not None:
            adm = load_json(os.path.join(a.out, f"recon-{a.admin}.json")) or {}
            own = load_json(os.path.join(a.out, f"recon-{a.owner}.json")) or {}
            own_urls = {p["url"] for p in own.get("pages", [])}
            admin_c = Client(scope, a.out, a.admin, sessions[a.admin])
            # liveness for the admin actor too
            can = actor_canaries(a.out, a.admin, sessions.get(a.admin), idmap, urls, public)
            alive, detail = check_liveness(admin_c, can, (sessions.get(a.admin) or {}).get("identity_markers", []))
            liveness[a.admin] = {"alive": alive, "canary": detail}
            if alive is False:
                dead.add(a.admin)
                print(f"WARNING: {a.admin} session looks DEAD — liveness canary {detail} denied.")
            for p in adm.get("pages", []):
                u = p["url"]
                if p.get("status") != 200 or u in own_urls or u in public:
                    continue
                if scope.excluded(u) or not scope.in_scope(u):
                    continue
                ra = safe_get(admin_c, a.admin, u)
                ru = safe_get(owner_c, a.owner, u)
                if ok(ra) and ok(ru) and not denial_signal(ru):
                    sim = similarity(ra.text, ru.text)
                    if sim >= a.threshold:
                        record(groups, "cross-role", u, a.admin, a.owner, ra, ru, [], sim, False, True)
                        results.append({"url": u, "admin_status": ra.status_code,
                                        "user_status": ru.status_code, "cross_role_flag": True})
        elif a.admin:
            print(f"Admin checks skipped: need '{a.admin}' in sessions and recon-{a.admin}.json")

        # ---- emit grouped findings ----
        new_ids = [emit(F, key, g) for key, g in groups.items()]
    except TargetDistress as e:
        print(f"TargetDistress: {e}")
        new_ids = [emit(F, key, g) for key, g in groups.items()]  # salvage what we found
    finally:
        # ---- S7: always persist results + findings, even on interrupt/distress ----
        meta = {
            "liveness": liveness,
            "denial_rates": {k: {"denied_pct": round(100 * v["deny"] / v["req"]) if v["req"] else 0,
                                 "n": v["req"]} for k, v in stats.items()},
            "dead_sessions": sorted(dead),
        }
        try:
            with open(os.path.join(a.out, "authz-results.json"), "w", encoding="utf-8") as f:
                json.dump({"meta": meta, "tests": results}, f, indent=2)
        except OSError:
            pass
        F.save()

    flagged = sum(1 for r in results if any(k.endswith("_flag") for k in r))
    print(f"Authz replay: {len(results)} endpoint tests, {flagged} flagged, "
          f"{F.added} new candidate findings -> {F.path}")
    for actor, v in stats.items():
        if actor == "anonymous" or not v["req"]:
            continue
        rate = v["deny"] / v["req"]
        tail = " — session may be dead" if (rate >= 0.99 and v["req"] >= 2 and actor in dead) else ""
        if rate >= 0.5 or actor in dead:
            print(f"  {actor} denied {rate:.0%} (n={v['req']}){tail}")
    for fid in [i for i in locals().get("new_ids", []) if i][:15]:
        print(f"  + {fid}")
    if have_owner and not m_owner:
        print(f"Tip: add identity_markers for {a.owner} in sessions.json — IDOR detection is much more reliable with them.")


if __name__ == "__main__":
    main()
