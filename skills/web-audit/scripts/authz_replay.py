#!/usr/bin/env python3
"""Phases 2-3: access-control replay.

Requests endpoints that one identity can see as another identity (other user, anonymous, lower
role) and flags responses that leak the owner's data. GET only — safe to run by default.

Endpoint sources (combined):
  * recon-<owner>.json pages returning 200 that were NOT public in the anonymous recon.json
  * --endpoints file (one URL per line)
  * --id-map ids.json  (templates with {id} + per-user ID lists)  -> cross-user ID swaps
  * --admin: pages in recon-<admin>.json that the owner never saw  -> function-level checks
"""
import argparse
import difflib
import json
import os
import re
import sys
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Client, Findings, describe_request, excerpt, load_scope_or_exit, load_sessions, shash  # noqa: E402

ID_IN_PATH = re.compile(r"/(\d{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(/|$|\?)", re.I)
VOLATILE = re.compile(r"[0-9a-f]{16,}|\d{6,}|(?i:csrf[^\"'<>]{0,40}[\"'][^\"']+[\"'])|nonce=\"[^\"]+\"")
LOGIN_HINT = re.compile(r"(?i)(type=[\"']password[\"']|sign in|log in|login|unauthori[sz]ed|forbidden|access denied|not authenticated)")


def load_json(path):
    if path and os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return None


def ok(r):
    return r is not None and 200 <= r.status_code < 300


def norm(text):
    return VOLATILE.sub("~", (text or "")[:8000])


def similarity(a, b):
    return difflib.SequenceMatcher(None, norm(a), norm(b)).ratio()


def markers_in(text, markers):
    t = (text or "").lower()
    return [m for m in markers if m and m.lower() in t]


def looks_like_denial(r):
    if r is None:
        return True
    if r.status_code in (401, 403, 404) or r.is_redirect:
        return True
    return bool(LOGIN_HINT.search((r.text or "")[:3000])) and len(r.text or "") < 15000


def candidate_urls(out_dir, owner, extra_file):
    anon = load_json(os.path.join(out_dir, "recon.json")) or {}
    public = {p["url"] for p in anon.get("pages", []) if p["status"] == 200}
    urls = []
    own = load_json(os.path.join(out_dir, f"recon-{owner}.json")) if owner else None
    if own:
        for p in own.get("pages", []):
            if p["status"] == 200 and p["url"] not in public and not p["url"].endswith((".xml", "robots.txt")):
                urls.append(p["url"])
    if extra_file:
        with open(extra_file, encoding="utf-8") as f:
            urls += [l.strip() for l in f if l.strip() and not l.startswith("#")]
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out, public


def add_finding(F, kind, url, owner, other, r_owner, r_other, matched, sim, sens):
    has_id = bool(ID_IN_PATH.search(urlparse(url).path))
    if kind == "anon":
        fid = f"AUTHZ-unauth-access-{shash(url)}"
        title = "Authenticated content reachable without logging in"
        ctx = "anonymous"
        desc = (f"{url} returns {owner}'s content to an anonymous request "
                f"({'identity markers found: ' + ', '.join(matched) if matched else f'body similarity {sim:.0%}'}).")
        impact = "Anyone on the internet can read this data without an account."
        sev = "high" if (matched or sens) else "medium"
        cwe = "CWE-306"
        cat = "broken-access-control"
    elif kind == "cross-user":
        fid = f"AUTHZ-idor-{shash(url)}"
        title = "Insecure direct object reference — another user's data is readable"
        ctx = "cross-user"
        desc = (f"{other} requested {url} (an object belonging to {owner}) and received it "
                f"({'identity markers found: ' + ', '.join(matched) if matched else f'body similarity {sim:.0%}'}).")
        impact = "Any logged-in user can read other users' records by changing the identifier" + (" — IDs look sequential, so this is enumerable." if has_id and re.search(r"/\d+", url) else ".")
        sev = "high" if matched else "medium"
        cwe = "CWE-639"
        cat = "broken-access-control"
    else:  # cross-role
        fid = f"AUTHZ-function-level-{shash(url)}"
        title = "Admin/privileged function reachable by a normal user"
        ctx = "cross-role"
        desc = f"{other} (lower privilege) received the same response as {owner} for {url} (similarity {sim:.0%})."
        impact = "Normal users can reach privileged functionality or data."
        sev = "high"
        cwe = "CWE-285"
        cat = "broken-access-control"
    F.add(id=fid, title=title, severity=sev, confidence="confirmed" if matched else "tentative", category=cat,
          auth_context=ctx, url=url, method="GET", description=desc, impact=impact,
          evidence={"request": describe_request(r_other), "response_status": r_other.status_code,
                    "response_excerpt": excerpt(r_other.text, 500),
                    "notes": f"Owner ({owner}) status {r_owner.status_code}, len {len(r_owner.content)}; "
                             f"replay ({other}) status {r_other.status_code}, len {len(r_other.content)}; similarity {sim:.2f}"},
          remediation="Enforce authorization on the server for every request: check the authenticated user owns (or may access) the requested object/function. Do not rely on hidden links or unguessable IDs.",
          cwe=cwe, source="authz_replay")


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

    have_owner = a.owner in sessions
    have_other = a.other in sessions and not a.anon_only
    if not have_owner and not a.endpoints:
        sys.exit(f"Need a '{a.owner}' session in --sessions (or --endpoints to test anonymously).")
    owner_c = Client(scope, a.out, a.owner, sessions.get(a.owner)) if have_owner else None
    other_c = Client(scope, a.out, a.other, sessions.get(a.other)) if have_other else None
    m_owner = (sessions.get(a.owner) or {}).get("identity_markers", [])
    m_other = (sessions.get(a.other) or {}).get("identity_markers", [])

    urls, public = candidate_urls(a.out, a.owner if have_owner else None, a.endpoints)
    if not urls and not a.id_map:
        print(f"No candidate URLs. Run recon.py --session {a.owner} first, or pass --endpoints / --id-map.")

    tested = set()

    def test(url, owner_name, oc, om, other_name, xc, xm):
        if scope.excluded(url) or not scope.in_scope(url) or (url, owner_name) in tested:
            return
        tested.add((url, owner_name))
        ro = oc.get(url) if oc else None
        if oc and not ok(ro):
            return
        row = {"url": url, "owner": owner_name, "owner_status": ro.status_code if ro is not None else None}
        sens = bool(ID_IN_PATH.search(urlparse(url).path)) or "json" in ((ro.headers.get("Content-Type", "")) if ro is not None else "")
        # anonymous replay
        rn = anon.get(url)
        row["anon_status"] = rn.status_code if rn is not None else None
        if ok(rn) and url not in public and not looks_like_denial(rn):
            matched = markers_in(rn.text, om)
            sim = similarity(ro.text, rn.text) if ro is not None else 0.0
            if matched or (ro is not None and sim >= a.threshold):
                add_finding(F, "anon", url, owner_name, "anonymous", ro if ro is not None else rn, rn, matched, sim, sens)
                row["anon_flag"] = True
        # cross-user replay
        if xc is not None and not row.get("anon_flag"):  # anonymous leak already covers it
            rx = xc.get(url)
            row["other_status"] = rx.status_code if rx is not None else None
            if ok(rx) and not looks_like_denial(rx):
                matched = [m for m in markers_in(rx.text, om) if m not in markers_in(rx.text, xm)]
                sim = similarity(ro.text, rx.text)
                if matched or (not om and sim >= max(a.threshold, 0.98) and ID_IN_PATH.search(urlparse(url).path)):
                    add_finding(F, "cross-user", url, owner_name, other_name, ro, rx, matched, sim, sens)
                    row["cross_user_flag"] = True
        results.append(row)

    for u in urls:
        test(u, a.owner, owner_c, m_owner, a.other, other_c, m_other)

    idmap = load_json(a.id_map)
    if idmap:
        pairs = [(a.owner, owner_c, m_owner, a.other, other_c, m_other)]
        if other_c is not None and owner_c is not None:
            pairs.append((a.other, other_c, m_other, a.owner, owner_c, m_owner))
        for tpl in idmap.get("templates", []):
            for own_name, oc, om, oth_name, xc, xm in pairs:
                for oid in idmap.get(own_name, []):
                    test(tpl.replace("{id}", str(oid)), own_name, oc, om, oth_name, xc, xm)

    if a.admin and a.admin in sessions and owner_c is not None:
        adm = load_json(os.path.join(a.out, f"recon-{a.admin}.json")) or {}
        own = load_json(os.path.join(a.out, f"recon-{a.owner}.json")) or {}
        own_urls = {p["url"] for p in own.get("pages", [])}
        admin_c = Client(scope, a.out, a.admin, sessions[a.admin])
        for p in adm.get("pages", []):
            u = p["url"]
            if p["status"] != 200 or u in own_urls or u in public or scope.excluded(u):
                continue
            ra = admin_c.get(u)
            ru = owner_c.get(u)
            if ok(ra) and ok(ru) and not looks_like_denial(ru):
                sim = similarity(ra.text, ru.text)
                if sim >= a.threshold:
                    add_finding(F, "cross-role", u, a.admin, a.owner, ra, ru, [], sim, True)
                    results.append({"url": u, "admin_status": ra.status_code, "user_status": ru.status_code, "cross_role_flag": True})
    elif a.admin:
        print(f"Admin checks skipped: need '{a.admin}' in sessions and recon-{a.admin}.json")

    with open(os.path.join(a.out, "authz-results.json"), "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    F.save()
    flagged = sum(1 for r in results if any(k.endswith("_flag") for k in r))
    print(f"Authz replay: {len(results)} endpoint tests, {flagged} flagged, {F.added} new candidate findings -> {F.path}")
    if have_owner and not m_owner:
        print(f"Tip: add identity_markers for {a.owner} in sessions.json — IDOR detection is much more reliable with them.")


if __name__ == "__main__":
    main()
