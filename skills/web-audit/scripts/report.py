#!/usr/bin/env python3
"""Render a chain-first, engagement-grade report.md from scope.json + findings.json (+ chains.json).

The report leads with attack chains (correlated kill-chains), then engagement details, then the
findings themselves, with rejected candidates and methodology in appendices. Everything emitted is
passed through common.redact / redact_url, and the finished report is re-scanned for unredacted
secrets before it is written — if any remain, nothing is written and the script exits non-zero.
"""
import argparse
import json
import os
import re
import sys
from collections import Counter, OrderedDict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import now_iso, redact, redact_url  # noqa: E402

ORDER = ["critical", "high", "medium", "low", "info"]
FULL = {"critical", "high", "medium"}  # rendered in full; low/info collapse to a table

# -- redaction gate (mask-aware; mirrors validate_findings.redaction_failures) -------
# Catches the shapes common.redact does not neutralise on its own (curl -b/-u, cookie
# name=value, bearer/JWT), plus a redact() diff gate for text that carries no "****" marker.
MASK = "****"
SENSITIVE_COOKIE = re.compile(
    r"(?i)\b(session|sid|token|auth|jwt|refresh|access)[a-z0-9_.\-]*=([^\s;&\"'`]{8,})")
CURL_COOKIE = re.compile(r"(?i)(?:^|\s)(?:-b|--cookie)[ =]\s*['\"]?(?P<v>[^\s'\"]{8,})")
CURL_USERPASS = re.compile(r"(?i)(?:^|\s)(?:-u|--user)[ =]\s*['\"]?(?P<v>\S+:\S+)")
AUTH_HEADER = re.compile(r"(?i)\bauthorization\b\s*[:=]\s*['\"]?\w+\s+(?P<v>\S{12,})")
BEARER = re.compile(r"(?i)\bbearer\s+(?P<v>\S{12,})")
JWT = re.compile(r"\beyJ[a-zA-Z0-9_-]{6,}\.[a-zA-Z0-9_-]{6,}\.[a-zA-Z0-9_-]*")
QUERY_TOKEN = re.compile(
    r"(?i)[?&](token|code|key|sig|signature|auth|session|sessionid|jwt|access_token|"
    r"refresh_token|id_token|api_key|apikey|secret|otp)=(?P<v>[^\s&\"'`*]{6,})")


def _unmasked(m):
    return MASK not in (m.group("v") or "")


def redaction_failures(text, is_url=False):
    if not text or not isinstance(text, str):
        return []
    out = []
    if MASK not in text:
        if redact(text) != text:
            out.append("secret/credential")
        if is_url and redact_url(text) != text:
            out.append("query token")
    if JWT.search(text):
        out.append("JWT")
    for rx, label in ((CURL_COOKIE, "curl cookie"), (CURL_USERPASS, "curl -u"),
                      (AUTH_HEADER, "auth header"), (BEARER, "bearer")):
        m = rx.search(text)
        if m and _unmasked(m):
            out.append(label)
    for rx, label in ((SENSITIVE_COOKIE, "cookie value"), (QUERY_TOKEN, "query token")):
        if any(MASK not in (m.group(2) or "") for m in rx.finditer(text)):
            out.append(label)
    return out


# -- helpers ------------------------------------------------------------------------
def R(text):
    """Redact any string before it is emitted (secrets masked by construction)."""
    return redact("" if text is None else str(text))


def RU(url):
    return redact_url("" if url is None else str(url))


def fence(text):
    return "```\n" + R(text).replace("```", "'''") + "\n```"


def cell(text):
    """Escape a value for a markdown table cell (| and newlines)."""
    return R(text).replace("\\", "\\\\").replace("|", "\\|").replace("\r", " ").replace("\n", "<br>")


def group_key(fid):
    """Collapse per-instance ids to a template key so one bug isn't repeated.
    Strips a trailing -<6+ hex hash> or -<digits> (e.g. AUTHZ-idor-9f3a1c -> AUTHZ-idor)."""
    fid = fid or ""
    k = re.sub(r"-[0-9a-f]{6,}$", "", fid)
    k = re.sub(r"-\d+$", "", k)
    return k or fid


def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def sev_rank(s):
    return ORDER.index(s) if s in ORDER else len(ORDER)


# -- main ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scope", required=True)
    ap.add_argument("--findings", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--chains", help="chains.json (default: chains.json beside findings.json, if present)")
    ap.add_argument("--authz", help="authz-results.json for the coverage line (default: beside findings.json)")
    ap.add_argument("--include-candidates", action="store_true",
                    help="draft report: include unverified candidates (clearly marked DRAFT)")
    a = ap.parse_args()

    scope = load_json(a.scope)
    if scope is None:
        sys.exit(f"ERROR: cannot read scope file: {a.scope}")
    doc = load_json(a.findings)
    if doc is None or not isinstance(doc.get("findings"), list):
        sys.exit(f"ERROR: cannot read findings file (or no 'findings' array): {a.findings}")
    fs = doc["findings"]

    base_dir = os.path.dirname(os.path.abspath(a.findings))
    chains_path = a.chains or os.path.join(base_dir, "chains.json")
    chains_doc = load_json(chains_path) if os.path.exists(chains_path) else None
    chains = (chains_doc or {}).get("chains", []) if isinstance(chains_doc, dict) else []
    authz_path = a.authz or os.path.join(base_dir, "authz-results.json")
    authz = load_json(authz_path) if os.path.exists(authz_path) else None

    # -- partition findings
    shown_status = {"verified"} | ({"candidate"} if a.include_candidates else set())
    shown = sorted([x for x in fs if x.get("status") in shown_status],
                   key=lambda x: (sev_rank(x.get("severity")), x.get("id", "")))
    rejected = [x for x in fs if x.get("status") == "rejected"]
    pending = [x for x in fs if x.get("status") == "candidate"]
    by_id = {x.get("id"): x for x in fs}
    counts_all = Counter(x.get("status", "?") for x in fs)
    sev_counts = Counter(x.get("severity", "info") for x in shown)
    draft = a.include_candidates and pending

    # -- chain -> finding membership + severity
    chains_sorted = sorted(chains, key=lambda c: sev_rank(c.get("severity", "info")))
    member_of = {}
    for ch in chains_sorted:
        for step in ch.get("kill_chain", []) or []:
            fid = (step or {}).get("finding")
            if fid:
                member_of.setdefault(fid, []).append(ch.get("id"))
    crit_chains = [c for c in chains_sorted if c.get("severity") in ("critical", "high")]

    L = [f"# Web security assessment — {R(scope.get('target', 'target'))}", ""]
    if scope.get("environment") == "production":
        L += ["> \u26a0\ufe0f **TESTED AGAINST PRODUCTION** — findings reflect the live system.", ""]
    if draft:
        L += ["> **DRAFT** — includes unverified candidate findings; not for distribution.", ""]

    # == 1. Executive summary (lead with chains) ====================================
    L += ["## Executive summary", ""]
    if chains_sorted:
        worst = chains_sorted[0]
        nphrase = f"{len(crit_chains)} critical attack chain(s)" if crit_chains else f"{len(chains_sorted)} attack chain(s)"
        L += [f"**{nphrase}** were identified by correlating individual findings. "
              f"The worst: **{R(worst.get('title', worst.get('id', 'chain')))}** "
              f"({R(worst.get('severity', '?'))}) — {R(worst.get('combined_impact', 'see below'))}", ""]
    else:
        L += ["No multi-step attack chains were correlated across the findings "
              + ("(candidates only — run correlation after verification)." if not shown else "(findings stand alone).") , ""]
    L += [f"Findings by severity ({'candidates + verified' if a.include_candidates else 'verified'}):", "",
          "| Severity | Count |", "|---|---|"] + \
         [f"| {s.title()} | {sev_counts.get(s, 0)} |" for s in ORDER] + [""]
    top = [x for x in shown if x.get("severity") in ("critical", "high")][:5]
    if top:
        L += ["**Fix first:**", ""] + [f"- **{R(x.get('title', x.get('id')))}** "
                                       f"({R(x.get('severity'))}) — {R(x.get('impact', ''))}" for x in top] + [""]
    elif not shown:
        L += ["No issues were verified within the tested scope.", ""]

    # == 2. Engagement details ======================================================
    auth = scope.get("authorization", {}) or {}
    actors = []
    sess_env = scope.get("mode", "")
    if sess_env in ("auth", "both"):
        actors = ["anonymous", "user_a", "user_b"]
    elif sess_env == "unauth":
        actors = ["anonymous"]
    L += ["## Engagement details", "", "| | |", "|---|---|",
          f"| Target | {R(scope.get('target', ''))} |",
          f"| Hosts in scope | {R(', '.join(scope.get('allowed_hosts', [])))} |",
          f"| Environment | {R(scope.get('environment', '?'))}"
          + (" \u26a0\ufe0f PRODUCTION" if scope.get("environment") == "production" else "") + " |",
          f"| Mode | {R(sess_env)}"
          + (" (black-box + authenticated)" if sess_env in ("auth", "both") else " (black-box, unauthenticated)") + " |",
          f"| Actors tested | {R(', '.join(actors) or 'anonymous')} |",
          f"| Authorised by | {R(auth.get('authorized_by', ''))} |",
          f"| Authorisation reference | {R(auth.get('reference', ''))} |",
          f"| Test window | {R(auth.get('window', auth.get('date', 'not recorded')))} |",
          f"| Max request rate | {R(scope.get('max_rps', 3))}/s"
          + (", state-changing methods enabled" if scope.get("allow_state_changing") else ", read-only") + " |",
          f"| Report generated | {now_iso()} |", ""]
    # Coverage line
    if isinstance(authz, list) and authz:
        per_actor = Counter()
        flagged = 0
        for row in authz:
            owner = row.get("owner") or ("admin" if "admin_status" in row else "anonymous")
            per_actor[owner] += 1
            if any(k.endswith("_flag") for k in row):
                flagged += 1
        cov = ", ".join(f"{n} as {R(act)}" for act, n in per_actor.items())
        L += [f"**Coverage:** access-control replay tested {len(authz)} endpoint(s) ({cov}); "
              f"{flagged} flagged for review. Passive, exposed-file, injection-indicator and JWT checks "
              "ran across the crawled surface (see requests.jsonl for the full request log).", ""]
    else:
        L += ["**Coverage:** reconnaissance/crawl, passive configuration checks, exposed-file discovery, "
              "injection indicators and JWT inspection ran across the in-scope surface; see requests.jsonl "
              "for the full request log.", ""]
    L += ["This assessment was authorised; all testing stayed within the scope above and used a request-rate "
          "limit. Methodology is summarised in Appendix B.", ""]

    # == 3. Attack chains ===========================================================
    if chains_sorted:
        L += ["## Attack chains", "",
              "Individual findings were correlated into the multi-step attack paths below. "
              "A chain is more severe than its parts because each step enables the next.", ""]
        for n, ch in enumerate(chains_sorted, 1):
            L += [f"### Chain {n}: {R(ch.get('title', ch.get('id', 'chain')))} "
                  f"(`{R(ch.get('id', ''))}`)", "",
                  f"**Combined severity:** {R(ch.get('severity', '?'))} · "
                  f"**Status:** {R(ch.get('status', '?'))} · **Confidence:** {R(ch.get('confidence', '?'))}"
                  + (f" · **Pattern:** {R(ch.get('pattern'))}" if ch.get("pattern") else ""), ""]
            if ch.get("preconditions"):
                L += [f"**Preconditions:** {R(ch.get('preconditions'))}", ""]
            L += ["**Kill chain:**", ""]
            for step in ch.get("kill_chain", []) or []:
                step = step or {}
                fid = step.get("finding", "")
                ftitle = (by_id.get(fid, {}) or {}).get("title", fid)
                missing = "" if fid in by_id else " *(finding not in findings.json)*"
                L += [f"{step.get('step', '?')}. **{R(step.get('phase', '?'))}** \u2192 "
                      f"{R(ftitle)} (`{R(fid)}`){missing}"
                      + (f" — {R(step.get('narrative'))}" if step.get("narrative") else "")]
            L += ["", f"**Combined impact:** {R(ch.get('combined_impact', 'n/a'))}", "",
                  f"**Remediation priority (cheapest cut):** {R(ch.get('remediation_priority', 'n/a'))}", ""]
            ver = ch.get("verification") or {}
            if ver.get("executed"):
                L += ["**Executed proof:** this chain was run end-to-end."
                      + (f" Actor path: {R(' \u2192 '.join(ver.get('actor_path', [])))}." if ver.get("actor_path") else "")
                      + (f" {R(ver.get('notes'))}" if ver.get("notes") else ""), ""]
                for s in ver.get("steps", []) or []:
                    L += [f"- {R(s)}"]
                if ver.get("steps"):
                    L += [""]
            else:
                L += ["*Not yet executed end-to-end; steps are correlated from individual findings.*", ""]

    # == 4. Findings ================================================================
    L += ["## Findings", ""]
    if not shown:
        L += ["_No findings to report at the selected status._", ""]
    # group the full-detail findings by template key so one bug isn't repeated
    full = [x for x in shown if x.get("severity") in FULL]
    low = [x for x in shown if x.get("severity") not in FULL]
    groups = OrderedDict()
    for x in full:
        groups.setdefault(group_key(x.get("id", "")), []).append(x)

    idx = 0
    for key, members in groups.items():
        members = sorted(members, key=lambda x: (sev_rank(x.get("severity")), x.get("id", "")))
        rep = members[0]
        idx += 1
        x = rep
        chain_tags = member_of.get(x.get("id"), [])
        head = f"### {idx}. {R(x.get('title', x.get('id')))}"
        L += [head, "",
              f"**Severity:** {R(x.get('severity', '?')).title()} · **Confidence:** {R(x.get('confidence', '?'))} · "
              f"**Status:** {R(x.get('status', '?'))} · **Category:** {R(x.get('category', '?'))} · "
              f"**Context:** {R(x.get('auth_context', '?'))}" + (f" · **{R(x.get('cwe'))}**" if x.get("cwe") else ""), ""]
        if chain_tags:
            L += [f"**Part of:** {', '.join('`' + R(c) + '`' for c in chain_tags)}", ""]
        L += [f"**URL:** `{R(x.get('method', 'GET'))} {RU(x.get('url', ''))}`", "",
              R(x.get("description", "")), ""]
        if x.get("impact"):
            L += [f"**Impact:** {R(x.get('impact'))}", ""]
        ev = x.get("evidence") or {}
        if ev.get("request") or ev.get("response_excerpt") or ev.get("notes"):
            L += ["**Evidence**", ""]
            if ev.get("request"):
                L += [fence(ev.get("request"))]
            if ev.get("response_status") not in (None, ""):
                L += [f"Response status: `{R(ev.get('response_status'))}`"]
            if ev.get("notes"):
                L += ["", R(ev.get("notes"))]
            if ev.get("response_excerpt"):
                L += ["", fence(ev.get("response_excerpt"))]
        rep_r = x.get("reproduction") or {}
        if rep_r.get("steps") or rep_r.get("curl"):
            L += ["", "**Reproduce**", ""] + [f"{n}. {R(s)}" for n, s in enumerate(rep_r.get("steps", []) or [], 1)]
            if rep_r.get("curl"):
                L += ["", fence(rep_r.get("curl"))]
        if x.get("remediation"):
            L += ["", f"**Fix:** {R(x.get('remediation'))}"]
        if len(members) > 1:
            others = ", ".join(f"`{RU(m.get('url', m.get('id')))}`" for m in members[1:])
            L += ["", f"**Also affects ({len(members) - 1} more instance(s) of the same issue):** {others}"]
        L += [""]

    # low/info collapse into ONE table
    if low:
        L += ["### Lower-severity findings", "", "| Severity | Title | URL | Fix |", "|---|---|---|---|"]
        for x in sorted(low, key=lambda x: (sev_rank(x.get("severity")), x.get("id", ""))):
            L += [f"| {cell(x.get('severity', ''))} | {cell(x.get('title', x.get('id')))} | "
                  f"`{cell(RU(x.get('url', '')))}` | {cell(x.get('remediation', '—'))} |"]
        L += [""]

    # == 5. Appendix A — rejected ===================================================
    if rejected:
        L += ["## Appendix A — Ruled out", "",
              "Candidates investigated and dismissed (kept for transparency).", "",
              "| Candidate | Severity | Reason |", "|---|---|---|"]
        L += [f"| {cell(x.get('title', ''))} (`{cell(x.get('id', ''))}`) | {cell(x.get('severity', ''))} | "
              f"{cell(x.get('rejection_reason', ''))} |" for x in rejected] + [""]
    if pending and not a.include_candidates:
        L += ["> {} candidate(s) were not verified and are excluded above: ".format(len(pending))
              + ", ".join(f"`{R(x.get('id'))}`" for x in pending), ""]

    # == 6. Appendix B — methodology ================================================
    n_verified = counts_all.get("verified", 0)
    L += ["## Appendix B — Methodology", ""]
    method = ("Black-box testing of the running application: reconnaissance and crawling; configuration checks "
              "(TLS, security headers, cookies, CORS); sensitive-file discovery; injection indicators; JWT/token "
              "inspection; and unauthenticated plus cross-user/cross-role access-control replay. ")
    if a.include_candidates:
        method += ("This DRAFT includes unverified candidate findings; each candidate is a hypothesis that "
                   "still requires independent reproduction before it is treated as confirmed. ")
    elif n_verified == 0:
        method += ("No candidate reached independent verification in this engagement; nothing is reported as "
                   "confirmed. ")
    else:
        method += ("Every finding reported above was independently re-tested with a fresh request before "
                   "inclusion; candidates that did not reproduce or lacked real impact were rejected (Appendix A). ")
    method += (f"Requests were rate-limited to {R(scope.get('max_rps', 3))}/s and "
               f"{'included' if scope.get('allow_state_changing') else 'excluded'} state-changing methods. "
               "A full request log is kept in requests.jsonl.")
    L += [method, ""]

    report = "\n".join(L)

    # -- GATE: refuse to write if anything we emit is unredacted --------------------
    # Fields are redacted by construction via R()/RU(); this is the safety net that also
    # catches shapes common.redact cannot mask on its own (curl -b/-u, cookie name=value).
    leaks = redaction_failures(report)
    if leaks:
        print("REFUSING to write report: unredacted secrets detected -> " + "; ".join(sorted(set(leaks))),
              file=sys.stderr)
        sys.exit(2)

    with open(a.out, "w", encoding="utf-8") as f:
        f.write(report)

    # -- agent-friendly tail: top-3 one-liners + status counts ---------------------
    print(f"Report written -> {a.out}")
    print("Counts: {} verified, {} rejected, {} candidate".format(
        counts_all.get("verified", 0), counts_all.get("rejected", 0), counts_all.get("candidate", 0)))
    print("Top 3:")
    tops = []
    for ch in crit_chains[:3]:
        tops.append(f"[chain] {ch.get('title', ch.get('id'))} ({ch.get('severity')})")
    for x in shown:
        if len(tops) >= 3:
            break
        if x.get("severity") in ("critical", "high"):
            tops.append(f"[finding] {x.get('title', x.get('id'))} ({x.get('severity')})")
    if not tops:
        tops = [f"[finding] {x.get('title', x.get('id'))} ({x.get('severity')})" for x in shown[:3]]
    for t in tops[:3] or ["(nothing of high severity)"]:
        print("  -", redact(t))


if __name__ == "__main__":
    main()
