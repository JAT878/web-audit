#!/usr/bin/env python3
"""Validate findings.json (and optionally chains.json) against schema + audit-quality rules.

Modes:
  validate_findings.py <findings.json>                 schema + quality checks (warns on candidates)
  validate_findings.py <findings.json> --final         also FAIL if any candidate remains
  validate_findings.py <findings.json> --summary        one line per finding (id|sev|status|title|url)
  validate_findings.py <findings.json> --chains c.json   also validate c.json against the chain schema

Stdlib only (jsonschema used when installed, with a builtin fallback for both schemas).
"""
import argparse
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA = os.path.join(HERE, "..", "schema", "findings.schema.json")
CHAIN_SCHEMA = os.path.join(HERE, "..", "schema", "chains.schema.json")

sys.path.insert(0, HERE)
from common import redact, redact_url  # noqa: E402

# ---------------------------------------------------------------- redaction scan
# Primary gate: common.redact / redact_url — if they would change an *un-masked* string,
# it holds something unredacted. common.redact is deliberately NOT idempotent (it re-shapes
# already-"****"-masked text and even re-pads "key: ****" -> "key: ********"), so the diff
# gate is skipped for any field that already carries a "****" marker; for those, the explicit
# patterns below still catch a second, unmasked secret sitting next to a redacted one.
MASK = "****"
SENSITIVE_COOKIE = re.compile(
    r"(?i)\b(session|sid|token|auth|jwt|refresh|access)[a-z0-9_.\-]*=(?P<v>[^\s;&\"'`]{8,})")
CURL_COOKIE = re.compile(r"(?i)(?:^|\s)(?:-b|--cookie)[ =]\s*['\"]?(?P<v>[^\s'\"]{8,})")
CURL_USERPASS = re.compile(r"(?i)(?:^|\s)(?:-u|--user)[ =]\s*['\"]?(?P<v>\S+:\S+)")
AUTH_HEADER = re.compile(r"(?i)\bauthorization\b\s*[:=]\s*['\"]?\w+\s+(?P<v>\S{12,})")
BEARER = re.compile(r"(?i)\bbearer\s+(?P<v>\S{12,})")
JWT = re.compile(r"\beyJ[a-zA-Z0-9_-]{6,}\.[a-zA-Z0-9_-]{6,}\.[a-zA-Z0-9_-]*")
QUERY_TOKEN = re.compile(
    r"(?i)[?&](token|code|key|sig|signature|auth|session|sessionid|jwt|access_token|"
    r"refresh_token|id_token|api_key|apikey|secret|otp)=(?P<v>[^\s&\"'`*]{6,})")
KEYVAL = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|"
    r"client[_-]?secret|refresh[_-]?token|access[_-]?token|apikey)[\"']?\s*[:=]\s*['\"]?"
    r"(?P<v>[^\s\"'&,<;]{8,})")
EMAIL = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")


def _unmasked(m):
    return MASK not in (m.group("v") or "")


def redaction_failures(text, is_url=False):
    """Return human-readable labels for unredacted secrets in `text` (mask-aware)."""
    if not text or not isinstance(text, str):
        return []
    out = []
    if MASK not in text:  # no masking marker: the common.redact diff gate is meaningful
        if redact(text) != text:
            out.append("secret/credential (common.redact would mask it)")
        if is_url and redact_url(text) != text:
            out.append("token-like value in URL query")
    # explicit shapes common.redact does not neutralise on its own / 2nd secret beside a mask
    for rx, label in ((JWT, "JWT (eyJ...)"),):
        if rx.search(text):
            out.append(label)
    for rx, label in ((CURL_COOKIE, "curl -b/--cookie value"),
                      (CURL_USERPASS, "curl -u user:pass"),
                      (AUTH_HEADER, "Authorization header credential"),
                      (BEARER, "bearer token"),
                      (KEYVAL, "secret-looking name=value")):
        m = rx.search(text)
        if m and _unmasked(m):
            out.append(label)
    for rx, label in ((SENSITIVE_COOKIE, "cookie value"), (QUERY_TOKEN, "token-like query param")):
        for m in rx.finditer(text):
            if _unmasked(m):
                out.append(f"{label} ('{m.group(1)}')")
                break
    seen, uniq = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            uniq.append(x)
    return uniq


def finding_strings(fd):
    """Yield (field-path, string, is_url) for the fields that may carry a secret."""
    for k in ("title", "description", "impact", "remediation", "rejection_reason"):
        if isinstance(fd.get(k), str):
            yield k, fd[k], False
    if isinstance(fd.get("url"), str):
        yield "url", fd["url"], True
    rep = fd.get("reproduction") or {}
    if isinstance(rep.get("curl"), str):
        yield "reproduction.curl", rep["curl"], False
    for i, s in enumerate(rep.get("steps") or []):
        if isinstance(s, str):
            yield f"reproduction.steps[{i}]", s, False
    ev = fd.get("evidence") or {}
    for k, v in ev.items():
        if isinstance(v, str):
            yield f"evidence.{k}", v, False
    ver = fd.get("verification") or {}
    if isinstance(ver.get("result_notes"), str):
        yield "verification.result_notes", ver["result_notes"], False


# ---------------------------------------------------------------- builtin schema checker
def check_value(val, spec, path, errs):
    if "enum" in spec and val not in spec["enum"]:
        errs.append(f"{path}: '{val}' not in {spec['enum']}")
        return
    t = spec.get("type")
    types = {"string": str, "integer": int, "array": list, "object": dict, "boolean": bool, "number": (int, float)}
    if t and t in types and not isinstance(val, types[t]):
        errs.append(f"{path}: expected {t}")
        return
    if t == "string":
        if "pattern" in spec and not re.search(spec["pattern"], val):
            errs.append(f"{path}: '{val}' does not match {spec['pattern']}")
        if "maxLength" in spec and len(val) > spec["maxLength"]:
            errs.append(f"{path}: longer than {spec['maxLength']} chars")
    if t == "object":
        for r in spec.get("required", []):
            if r not in val or val[r] in ("", None):
                errs.append(f"{path}: missing '{r}'")
        for k, sub in spec.get("properties", {}).items():
            if k in val:
                check_value(val[k], sub, f"{path}.{k}", errs)
    if t == "array":
        if "minItems" in spec and len(val) < spec["minItems"]:
            errs.append(f"{path}: needs at least {spec['minItems']} item(s)")
        if "items" in spec:
            for i, item in enumerate(val):
                check_value(item, spec["items"], f"{path}[{i}]", errs)


def _trunc(msg, n=120):
    msg = str(msg).replace("\n", " ")
    return msg if len(msg) <= n else msg[:n - 1] + "…"


def schema_errors(doc, schema):
    """jsonschema when available (full Draft 2020-12), else the builtin subset checker.
    Error messages are truncated to 120 chars so a huge offending value is never dumped."""
    try:
        import jsonschema
    except ImportError:
        errs = []
        check_value(doc, schema, "$", errs)
        return [_trunc(e) for e in errs], "builtin"
    v = jsonschema.Draft202012Validator(schema)
    errs = []
    for e in sorted(v.iter_errors(doc), key=lambda e: list(e.absolute_path)):
        loc = "$" + "".join(f"[{p}]" if isinstance(p, int) else f".{p}" for p in e.absolute_path)
        errs.append(f"{loc}: {_trunc(e.message)}")
    return errs, "jsonschema"


# ---------------------------------------------------------------- loaders (P6: clean errors)
def load_json_or_exit(path, what):
    if not path or not os.path.exists(path):
        sys.exit(f"ERROR: {what} not found: {path}")
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        sys.exit(f"ERROR: {what} is not valid JSON ({path}): line {e.lineno}, column {e.colno}: {e.msg}")
    except OSError as e:
        sys.exit(f"ERROR: cannot read {what} ({path}): {e.strerror or e}")


# ---------------------------------------------------------------- chains validation
CHAIN_PHASES = {"information-disclosure", "authorization-weakness", "privilege-boundary-failure",
                "session-weakness", "injection", "business-logic"}
CHAIN_STATUS = {"candidate", "verified", "rejected"}
CHAIN_CONF = {"tentative", "firm", "confirmed"}
SEVERITIES = {"critical", "high", "medium", "low", "info"}


def check_chains_builtin(doc):
    """Structural checks when schema/chains.schema.json is not present."""
    errs = []
    if not isinstance(doc, dict):
        return ["$: chains document must be an object"]
    chains = doc.get("chains")
    if not isinstance(chains, list):
        return ["$.chains: required array of chains"]
    for i, ch in enumerate(chains):
        p = f"chains[{i}] ({ch.get('id', '?') if isinstance(ch, dict) else '?'})"
        if not isinstance(ch, dict):
            errs.append(f"{p}: chain must be an object")
            continue
        cid = ch.get("id")
        if not cid or not re.match(r"^CHAIN-[a-z0-9-]+$", cid or ""):
            errs.append(f"{p}: id must match ^CHAIN-[a-z0-9-]+$")
        if not ch.get("title"):
            errs.append(f"{p}: missing title")
        if ch.get("status") not in CHAIN_STATUS:
            errs.append(f"{p}: status must be one of {sorted(CHAIN_STATUS)}")
        if ch.get("confidence") not in CHAIN_CONF:
            errs.append(f"{p}: confidence must be one of {sorted(CHAIN_CONF)}")
        if ch.get("severity") not in SEVERITIES:
            errs.append(f"{p}: severity must be one of {sorted(SEVERITIES)}")
        kc = ch.get("kill_chain")
        if not isinstance(kc, list) or len(kc) < 2:
            errs.append(f"{p}: kill_chain must be an ordered array of >=2 steps")
            kc = kc if isinstance(kc, list) else []
        for j, step in enumerate(kc):
            sp = f"{p}.kill_chain[{j}]"
            if not isinstance(step, dict):
                errs.append(f"{sp}: step must be an object")
                continue
            if step.get("phase") not in CHAIN_PHASES:
                errs.append(f"{sp}: phase must be one of {sorted(CHAIN_PHASES)}")
            if not step.get("finding"):
                errs.append(f"{sp}: missing finding id")
    return errs


def validate_chains(chains_path, finding_ids):
    doc = load_json_or_exit(chains_path, "chains file")
    errs = []
    engine = "builtin"
    if os.path.exists(CHAIN_SCHEMA):
        try:
            with open(CHAIN_SCHEMA, encoding="utf-8") as f:
                schema = json.load(f)
            errs, engine = schema_errors(doc, schema)
        except (OSError, json.JSONDecodeError):
            errs = check_chains_builtin(doc)
    else:
        errs = check_chains_builtin(doc)
    # cross-checks that the schema alone can't express
    chains = doc.get("chains", []) if isinstance(doc, dict) else []
    for i, ch in enumerate(chains if isinstance(chains, list) else []):
        if not isinstance(ch, dict):
            continue
        p = f"chains[{i}] ({ch.get('id', '?')})"
        for j, step in enumerate(ch.get("kill_chain", []) or []):
            if isinstance(step, dict):
                fid = step.get("finding")
                if fid and fid not in finding_ids:
                    errs.append(f"{p}.kill_chain[{j}]: finding '{fid}' is not present in findings.json")
        if ch.get("status") == "verified" and not (ch.get("verification") or {}).get("executed"):
            errs.append(f"{p}: status 'verified' requires verification.executed = true")
    n = len(chains) if isinstance(chains, list) else 0
    if errs:
        print("CHAINS FAIL")
        for e in errs:
            print("  -", e)
        return False
    print(f"CHAINS OK ({engine}) — {n} chain(s) valid")
    return True


# ---------------------------------------------------------------- summary mode
def print_summary(findings):
    for fd in findings:
        print(" | ".join([
            str(fd.get("id", "?")),
            str(fd.get("severity", "?")),
            str(fd.get("status", "?")),
            (fd.get("title", "") or "").replace("\n", " ")[:80],
            redact_url(fd.get("url", "") or ""),
        ]))


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("findings", help="path to findings.json")
    ap.add_argument("--final", action="store_true", help="fail (non-zero) if any finding is still 'candidate'")
    ap.add_argument("--summary", action="store_true", help="print one line per finding and exit")
    ap.add_argument("--chains", metavar="chains.json", help="also validate a chains.json file")
    a = ap.parse_args()

    doc = load_json_or_exit(a.findings, "findings file")
    if not isinstance(doc, dict) or not isinstance(doc.get("findings"), list):
        sys.exit("ERROR: findings file must be an object with a 'findings' array")
    findings = doc["findings"]

    if a.summary:
        print_summary(findings)
        return

    schema = load_json_or_exit(SCHEMA, "findings schema")
    warns, errs = [], []
    errs_schema, engine = schema_errors(doc, schema)
    errs += errs_schema

    ids, counts = set(), {}
    redaction_fail = []
    for i, fd in enumerate(findings):
        p = f"findings[{i}] ({fd.get('id', '?')})"
        if fd.get("id") in ids:
            errs.append(f"{p}: duplicate id")
        ids.add(fd.get("id"))
        st = fd.get("status")
        counts[st] = counts.get(st, 0) + 1

        if st == "verified":
            ev = fd.get("evidence") or {}
            rep = fd.get("reproduction") or {}
            # P3/4.2: verified findings need request evidence AND a status or excerpt.
            if not (ev.get("request") or "").strip():
                errs.append(f"{p}: verified findings need non-empty evidence.request")
            if ev.get("response_status") in (None, "") and not (ev.get("response_excerpt") or "").strip():
                errs.append(f"{p}: verified findings need evidence.response_status or evidence.response_excerpt")
            if not rep.get("steps") and not rep.get("curl"):
                errs.append(f"{p}: verified findings need reproduction.steps or reproduction.curl")
            if not fd.get("impact"):
                errs.append(f"{p}: verified findings need impact")
            if not fd.get("remediation"):
                errs.append(f"{p}: verified findings need remediation")
            if not (fd.get("verification") or {}).get("by"):
                warns.append(f"{p}: verification.by not set (who/what independently verified it?)")
        if st == "rejected" and not fd.get("rejection_reason"):
            errs.append(f"{p}: rejected findings need rejection_reason")

        # R3: redaction scan across the finding's secret-bearing string fields.
        for fname, sval, is_url in finding_strings(fd):
            for label in redaction_failures(sval, is_url):
                redaction_fail.append(f"{p}.{fname}: unredacted {label}")
            # PII: emails are a warning, not a failure.
            for em in EMAIL.findall(sval):
                warns.append(f"{p}.{fname}: possible PII (email {em[:2]}***) — confirm it belongs in the report")

    if redaction_fail:
        errs += redaction_fail

    if counts.get("candidate"):
        msg = f"{counts['candidate']} finding(s) still 'candidate'"
        if a.final:
            errs.append(f"{msg} — --final requires every finding verified or rejected")
        else:
            warns.append(f"{msg} — verify or reject them before the final report")

    # de-dup warnings
    seen, uniq = set(), []
    for w in warns:
        if w not in seen:
            seen.add(w)
            uniq.append(w)
    for w in uniq:
        print("WARN:", w)

    ok = True
    if errs:
        print("FAIL")
        for e in errs:
            print("  -", e)
        ok = False
    else:
        print(f"OK ({engine}) — {len(ids)} findings valid ({', '.join(f'{v} {k}' for k, v in sorted(counts.items()))})")

    if a.chains:
        if not validate_chains(a.chains, ids):
            ok = False

    if not ok:
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:  # e.g. piping --summary into `head`
        try:
            sys.stdout.close()
        finally:
            os._exit(0)
