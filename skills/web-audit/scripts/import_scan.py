#!/usr/bin/env python3
"""Ingest OTHER scanners' output into our findings.json schema (as `candidate`, source-tagged)
and/or endpoint lists, so correlation (Component 4) and the report (Component 5) run over the
UNION of what every tool found — breadth borrowed, not rebuilt.

This script performs NO network I/O. It is a pure file transformation: read a third-party
report, normalise each item to our finding shape, keep only IN-SCOPE items, and merge into
findings.json via common.Findings (dedupe by id, lock+atomic save).

Usage:
  import_scan.py --scope <scope.json> --out <dir> --format {zap|nuclei|burp|har|generic} --input <file>

Formats:
  zap      ZAP JSON report        site[].alerts[] (riskcode/name/desc/solution/instances[].uri)
  nuclei   nuclei JSONL           one object/line (info.name, info.severity, matched-at, template-id)
  burp     Burp XML export        issues/issue (name, severity, host+path, issueDetail)
  har      browser HAR            -> <out>/endpoints.txt + har-endpoints.json (in-scope, secrets redacted)
  generic  JSON array             [{title, severity, url, description}]

Every imported finding is status "candidate", confidence "tentative" (external, unverified),
source set to the tool name, chain_role "standalone" (correlation treats it as standalone until
an analyst adds capability fields). Out-of-scope items are dropped and counted.
"""
import argparse
import json
import os
import sys
from urllib.parse import urlparse, urlunparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import (  # noqa: E402
    Findings, cap_fields, excerpt, load_scope_or_exit, redact, redact_url, shash, slug,
)

SEVERITIES = {"critical", "high", "medium", "low", "info"}
CATEGORIES = {
    "broken-access-control", "authentication", "session-management", "cryptographic-failure",
    "injection", "security-misconfiguration", "sensitive-data-exposure", "information-disclosure",
    "cors", "csrf", "clickjacking", "open-redirect", "vulnerable-component", "business-logic", "other",
}
STATIC = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2",
          ".ttf", ".css", ".mp4", ".mp3", ".map")


class ImportError_(Exception):
    """Raised on malformed input; main turns it into a clean error + non-zero exit."""


# ---------------------------------------------------------------- normalisation helpers
def safe_url(u: str) -> str:
    """common.redact_url masks sensitive query values, but its urlencode step percent-encodes the
    '****' mask into '%2A%2A%2A%2A'. Restore the literal mask so the value reads as redacted (and
    the validator recognises it as masked rather than flagging it)."""
    return redact_url(u).replace("%2A%2A%2A%2A", "****")


def norm_severity(value) -> str:
    """Map a tool's severity (string or ZAP riskcode int) to our enum; default 'info'."""
    if value is None:
        return "info"
    s = str(value).strip().lower()
    if s in SEVERITIES:
        return s
    zap_risk = {"3": "high", "2": "medium", "1": "low", "0": "info"}  # ZAP riskcode
    if s in zap_risk:
        return zap_risk[s]
    aliases = {
        "informational": "info", "information": "info", "none": "info", "unknown": "info",
        "warning": "low", "moderate": "medium", "severe": "high", "important": "high",
        "crit": "critical", "blocker": "critical",
    }
    return aliases.get(s, "info")


# Best-effort keyword -> our category enum. Anything unmatched falls back to "other".
_CATEGORY_HINTS = (
    ("idor", "broken-access-control"), ("bola", "broken-access-control"),
    ("access control", "broken-access-control"), ("authorization", "broken-access-control"),
    ("authoriz", "broken-access-control"), ("privilege", "broken-access-control"),
    ("sql inj", "injection"), ("sqli", "injection"), ("command inj", "injection"),
    ("injection", "injection"), ("xss", "injection"), ("cross site scripting", "injection"),
    ("cross-site scripting", "injection"),
    ("csrf", "csrf"), ("cross site request", "csrf"), ("cross-site request", "csrf"),
    ("clickjack", "clickjacking"), ("frame options", "clickjacking"),
    ("open redirect", "open-redirect"),
    ("cors", "cors"), ("cross origin", "cors"), ("cross-origin", "cors"),
    ("session", "session-management"), ("cookie", "session-management"),
    ("authentication", "authentication"), ("login", "authentication"),
    ("password", "authentication"), ("credential", "authentication"),
    ("enumerat", "authentication"), ("brute", "authentication"),
    ("tls", "cryptographic-failure"), ("ssl", "cryptographic-failure"),
    ("cipher", "cryptographic-failure"), ("certificate", "cryptographic-failure"),
    ("crypto", "cryptographic-failure"), ("weak hash", "cryptographic-failure"),
    ("outdated", "vulnerable-component"), ("vulnerable", "vulnerable-component"),
    ("known cve", "vulnerable-component"), ("component with", "vulnerable-component"),
    ("sensitive data", "sensitive-data-exposure"), ("data exposure", "sensitive-data-exposure"),
    ("information disclosure", "information-disclosure"), ("info leak", "information-disclosure"),
    ("version disclosure", "information-disclosure"), ("stack trace", "information-disclosure"),
    ("directory listing", "information-disclosure"), ("exposure", "information-disclosure"),
    ("header", "security-misconfiguration"), ("misconfig", "security-misconfiguration"),
    ("default", "security-misconfiguration"), ("security policy", "security-misconfiguration"),
    ("business logic", "business-logic"),
)


def map_category(*texts) -> str:
    blob = " ".join(t for t in texts if t).lower()
    for needle, cat in _CATEGORY_HINTS:
        if needle in blob:
            return cat
    return "other"


def mk_id(prefix: str, title: str, *salt) -> str:
    """Build an id matching ^[A-Z]+-[a-z0-9_-]+$ : PREFIX-<slug>-<shorthash>."""
    return f"{prefix}-{slug(title or 'finding', 40)}-{shash('|'.join(str(s) for s in salt))}"


def make_finding(prefix, source, title, severity, url, description,
                 remediation=None, cwe=None, *, cat_hints=()):
    """Assemble a normalised candidate finding dict (url already confirmed in-scope)."""
    title = (title or "Imported finding").strip()[:200]
    f = {
        "id": mk_id(prefix, title, url, title),
        "title": title,
        "severity": norm_severity(severity),
        "confidence": "tentative",          # external, unverified
        "status": "candidate",
        "category": map_category(title, description, *cat_hints),
        "auth_context": "anonymous",
        "url": safe_url(url),
        "method": "GET",
        "description": excerpt(description or f"Imported from {source}; unverified.", 1500),
        "evidence": {
            "request": f"GET {safe_url(url)}",
            "notes": f"Imported from {source} (external scanner); candidate, not yet verified.",
        },
        "source": source,
    }
    if remediation:
        f["remediation"] = excerpt(remediation, 800)
    if cwe:
        f["cwe"] = cwe
    # chain_role only — imports carry NO capability grants/requires until an analyst adds them.
    f.update(cap_fields(chain_role="standalone"))
    return f


def clean_cwe(value):
    if value in (None, ""):
        return None
    s = str(value).strip().upper()
    if s.startswith("CWE-") and s[4:].isdigit():
        return s
    if s.isdigit():
        return f"CWE-{s}"
    return None


# ---------------------------------------------------------------- per-format parsers
def load_json(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise ImportError_(f"input file not found: {path}")
    except json.JSONDecodeError as e:
        raise ImportError_(f"input is not valid JSON ({path}): line {e.lineno}, column {e.colno}: {e.msg}")
    except OSError as e:
        raise ImportError_(f"cannot read input ({path}): {e.strerror or e}")


def parse_zap(path, scope):
    doc = load_json(path)
    if not isinstance(doc, dict) or not isinstance(doc.get("site"), list):
        raise ImportError_("ZAP report must be an object with a 'site' array")
    findings, skipped = [], 0
    for site in doc["site"]:
        if not isinstance(site, dict):
            continue
        for alert in site.get("alerts", []) or []:
            if not isinstance(alert, dict):
                continue
            uris = [i.get("uri") for i in (alert.get("instances") or []) if isinstance(i, dict) and i.get("uri")]
            if not uris:
                # fall back to the site name so a finding without instances still has a URL
                nm = site.get("@name") or site.get("name")
                if nm:
                    uris = [nm]
            in_scope_uri = next((u for u in uris if scope.in_scope(u)), None)
            if in_scope_uri is None:
                skipped += 1
                continue
            findings.append(make_finding(
                "ZAP", "zap", alert.get("name") or alert.get("alert"),
                alert.get("riskcode"), in_scope_uri,
                alert.get("desc") or alert.get("description"),
                remediation=alert.get("solution"), cwe=clean_cwe(alert.get("cweid")),
            ))
    return findings, skipped


def parse_nuclei(path, scope):
    try:
        with open(path, encoding="utf-8") as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        raise ImportError_(f"input file not found: {path}")
    except OSError as e:
        raise ImportError_(f"cannot read input ({path}): {e.strerror or e}")
    findings, skipped = [], 0
    for n, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            raise ImportError_(f"nuclei JSONL line {n} is not valid JSON: {e.msg}")
        if not isinstance(obj, dict):
            raise ImportError_(f"nuclei JSONL line {n} is not a JSON object")
        info = obj.get("info") or {}
        url = obj.get("matched-at") or obj.get("matched_at") or obj.get("host")
        if not url:
            skipped += 1
            continue
        if "://" not in url:                       # matched-at is often host:port
            url = "http://" + url
        if not scope.in_scope(url):
            skipped += 1
            continue
        tid = obj.get("template-id") or obj.get("templateID") or ""
        findings.append(make_finding(
            "NUCLEI", "nuclei", info.get("name") or tid, info.get("severity"), url,
            info.get("description"), remediation=info.get("remediation"),
            cwe=_first_cwe(info.get("classification")), cat_hints=(tid,),
        ))
    return findings, skipped


def _first_cwe(classification):
    if isinstance(classification, dict):
        ids = classification.get("cwe-id") or classification.get("cwe_id")
        if isinstance(ids, list) and ids:
            return clean_cwe(ids[0])
        return clean_cwe(ids)
    return None


def parse_burp(path, scope):
    import xml.etree.ElementTree as ET
    try:
        tree = ET.parse(path)
    except FileNotFoundError:
        raise ImportError_(f"input file not found: {path}")
    except ET.ParseError as e:
        raise ImportError_(f"Burp XML is not well-formed ({path}): {e}")
    except OSError as e:
        raise ImportError_(f"cannot read input ({path}): {e.strerror or e}")
    root = tree.getroot()
    issues = root.findall(".//issue")
    if not issues:
        raise ImportError_("Burp XML has no <issue> elements (expected issues/issue)")
    findings, skipped = [], 0
    for issue in issues:
        host_el = issue.find("host")
        host = (host_el.text or "").strip() if host_el is not None else ""
        if not host and host_el is not None:
            host = (host_el.get("ip") or "").strip()
        path_txt = _text(issue, "path")
        url = host.rstrip("/") + path_txt if host else path_txt
        if not url or not scope.in_scope(url):
            skipped += 1
            continue
        findings.append(make_finding(
            "BURP", "burp", _text(issue, "name"), _text(issue, "severity"), url,
            _text(issue, "issueDetail") or _text(issue, "issueBackground"),
            remediation=_text(issue, "remediationDetail") or _text(issue, "remediationBackground"),
        ))
    return findings, skipped


def _text(el, tag):
    child = el.find(tag)
    return (child.text or "").strip() if child is not None and child.text else ""


def parse_generic(path, scope):
    doc = load_json(path)
    if not isinstance(doc, list):
        raise ImportError_("generic format must be a JSON array of {title, severity, url, description}")
    findings, skipped = [], 0
    for i, item in enumerate(doc):
        if not isinstance(item, dict):
            raise ImportError_(f"generic[{i}] is not an object")
        url = item.get("url")
        if not url or not scope.in_scope(url):
            skipped += 1
            continue
        findings.append(make_finding(
            "GEN", "generic", item.get("title"), item.get("severity"), url,
            item.get("description"), remediation=item.get("remediation"),
            cwe=clean_cwe(item.get("cwe")),
        ))
    return findings, skipped


# ---------------------------------------------------------------- HAR (endpoints, not findings)
def _strip(url):
    u = urlparse(url)
    return urlunparse((u.scheme, u.netloc, u.path, "", u.query, ""))


def do_har(path, scope, out, include_static=False):
    """Mirror har_import.py, but REDACT secrets in query strings on the way out."""
    har = load_json(path)
    if not isinstance(har, dict):
        raise ImportError_("HAR file must be a JSON object with log.entries")
    entries = (har.get("log") or {}).get("entries", [])
    rows, get_urls, seen = [], [], set()
    off_scope = 0
    for e in entries:
        req = (e or {}).get("request", {}) or {}
        url = req.get("url", "")
        method = (req.get("method") or "GET").upper()
        if not url:
            continue
        if not scope.in_scope(url):
            off_scope += 1
            continue
        if scope.excluded(url):
            continue
        if not include_static and urlparse(url).path.lower().endswith(STATIC):
            continue
        ctype = ""
        for h in (e.get("response", {}) or {}).get("headers", []) or []:
            if (h.get("name") or "").lower() == "content-type":
                ctype = (h.get("value") or "").split(";")[0]
        has_body = bool((req.get("postData") or {}).get("text"))
        safe = safe_url(_strip(url))                   # secret-safe: mask token/session/etc
        rows.append({"method": method, "url": safe, "response_content_type": ctype,
                     "status": (e.get("response", {}) or {}).get("status"),
                     "has_request_body": has_body})
        if method == "GET" and safe not in seen:
            seen.add(safe)
            get_urls.append(safe)
    uniq, keys = [], set()
    for r in rows:
        k = (r["method"], r["url"])
        if k not in keys:
            keys.add(k)
            uniq.append(r)
    os.makedirs(out, exist_ok=True)
    ep_path = os.path.join(out, "endpoints.txt")
    with open(ep_path, "w", encoding="utf-8") as f:
        f.write("\n".join(get_urls) + ("\n" if get_urls else ""))
    with open(os.path.join(out, "har-endpoints.json"), "w", encoding="utf-8") as f:
        json.dump(uniq, f, indent=2)
    methods = sorted({r["method"] for r in uniq})
    print(f"Imported {len(uniq)} in-scope requests from har ({off_scope} out-of-scope skipped); "
          f"{len(get_urls)} unique GET -> {ep_path}; methods: {', '.join(methods) or 'none'}")
    non_get = [r for r in uniq if r["method"] != "GET"]
    if non_get:
        print(f"  Note: {len(non_get)} non-GET request(s) listed in har-endpoints.json for manual review "
              "(not replayed automatically in read-only mode).")


PARSERS = {"zap": parse_zap, "nuclei": parse_nuclei, "burp": parse_burp, "generic": parse_generic}


def main():
    ap = argparse.ArgumentParser(description="Ingest third-party scanner output into findings.json")
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--format", required=True, choices=["zap", "nuclei", "burp", "har", "generic"])
    ap.add_argument("--input", required=True, help="the third-party report / HAR file to import")
    ap.add_argument("--include-static", action="store_true", help="HAR only: keep images/css/fonts")
    a = ap.parse_args()
    scope = load_scope_or_exit(a.scope)
    os.makedirs(a.out, exist_ok=True)

    if a.format == "har":
        try:
            do_har(a.input, scope, a.out, a.include_static)
        except ImportError_ as e:
            sys.exit(f"ERROR: {e}")
        return

    try:
        findings, skipped = PARSERS[a.format](a.input, scope)
    except ImportError_ as e:
        sys.exit(f"ERROR: {e}")

    F = Findings(a.out, scope.target)
    try:
        for f in findings:
            F.add(**f)
    finally:
        F.save()
    print(f"Imported {F.added} candidate findings from {a.format} ({skipped} out-of-scope skipped)")
    for f in findings[:15]:
        print(f"  {f['id']} | {f['severity']} | {f['category']} | {f['title'][:60]}")


if __name__ == "__main__":
    main()
