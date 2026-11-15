"""Shared helpers: scope enforcement, rate-limited HTTP client, findings store, redaction."""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    import requests
except ImportError:  # pragma: no cover
    sys.exit("This skill needs 'requests': pip install requests")

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
DEFAULT_UA = "Mozilla/5.0 (compatible; web-audit/1.0)"


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# ---------------------------------------------------------------- scope
class ScopeError(Exception):
    pass


class Scope:
    REQUIRED = ["target", "allowed_hosts", "environment", "authorization", "mode"]

    def __init__(self, path: str):
        with open(path, encoding="utf-8") as f:
            self.raw = json.load(f)
        self.path = path
        problems = self.problems()
        if problems:
            raise ScopeError("Scope file is not valid:\n  - " + "\n  - ".join(problems))
        r = self.raw
        self.target = r["target"].rstrip("/")
        self.allowed_hosts = {h.lower() for h in r["allowed_hosts"]}
        self.environment = r["environment"]
        self.mode = r["mode"]
        self.max_rps = float(r.get("max_rps", 3))
        self.allow_state_changing = bool(r.get("allow_state_changing", False))
        self.excluded_paths = [p.rstrip("/") or "/" for p in r.get("excluded_paths", [])]
        self.ua = DEFAULT_UA + (f" {r['user_agent_tag']}" if r.get("user_agent_tag") else "")

    def problems(self) -> list[str]:
        r, out = self.raw, []
        for k in self.REQUIRED:
            if not r.get(k):
                out.append(f"missing '{k}'")
        auth = r.get("authorization") or {}
        if isinstance(auth, dict):
            for k in ("authorized_by", "reference"):
                if not auth.get(k):
                    out.append(f"authorization.{k} is required (who approved this test, and a ticket/email reference)")
        else:
            out.append("authorization must be an object")
        if r.get("mode") and r["mode"] not in ("unauth", "auth", "both"):
            out.append("mode must be unauth, auth or both")
        if r.get("environment") and r["environment"] not in ("staging", "production", "development", "test"):
            out.append("environment must be staging, production, development or test")
        t = r.get("target", "")
        if t:
            p = urlparse(t)
            if p.scheme not in ("http", "https") or not p.hostname:
                out.append("target must be an absolute http(s) URL")
            elif p.hostname.lower() not in {h.lower() for h in r.get("allowed_hosts", [])}:
                out.append("target host must be listed in allowed_hosts")
        try:
            rps = float(r.get("max_rps", 3))
            if rps <= 0 or rps > 20:
                out.append("max_rps must be between 0 and 20")
            if r.get("environment") == "production" and rps > 5:
                out.append("max_rps above 5 against production is not allowed by this skill")
        except (TypeError, ValueError):
            out.append("max_rps must be a number")
        return out

    def in_scope(self, url: str) -> bool:
        p = urlparse(url)
        return p.scheme in ("http", "https") and (p.hostname or "").lower() in self.allowed_hosts

    def excluded(self, url: str) -> bool:
        path = urlparse(url).path or "/"
        for ex in self.excluded_paths:
            if ex == "/":
                continue
            if path == ex or path.startswith(ex + "/") or path.startswith(ex + "?") or path.rstrip("/") == ex:
                return True
        return False

    def check(self, url: str, method: str) -> None:
        if not self.in_scope(url):
            raise ScopeError(f"Out of scope host: {url}")
        if self.excluded(url):
            raise ScopeError(f"Excluded path: {url}")
        if method.upper() not in SAFE_METHODS and not self.allow_state_changing:
            raise ScopeError(f"{method} blocked: allow_state_changing is false")


# ---------------------------------------------------------------- sessions
def load_sessions(path: str | None) -> dict:
    if not path:
        return {}
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def apply_session(sess: requests.Session, entry: dict | None) -> None:
    if not entry:
        return
    for k, v in (entry.get("cookies") or {}).items():
        sess.cookies.set(k, v)
    if entry.get("cookie_header"):
        for part in entry["cookie_header"].split(";"):
            if "=" in part:
                k, v = part.strip().split("=", 1)
                sess.cookies.set(k, v)
    for k, v in (entry.get("headers") or {}).items():
        sess.headers[k] = v
    if entry.get("storage_state") and os.path.exists(entry["storage_state"]):
        with open(entry["storage_state"], encoding="utf-8") as f:
            state = json.load(f)
        for c in state.get("cookies", []):
            sess.cookies.set(c["name"], c["value"], domain=c.get("domain"), path=c.get("path", "/"))


# ---------------------------------------------------------------- http
class _RateLimiter:
    def __init__(self, rps: float):
        self.interval = 1.0 / rps
        self.lock = threading.Lock()
        self.last = 0.0

    def wait(self):
        with self.lock:
            delta = time.monotonic() - self.last
            if delta < self.interval:
                time.sleep(self.interval - delta)
            self.last = time.monotonic()


_LIMITERS: dict[float, _RateLimiter] = {}


class Client:
    """Rate-limited, scope-enforcing HTTP client that logs every request."""

    def __init__(self, scope: Scope, out_dir: str, session_name: str = "anonymous",
                 session_entry: dict | None = None, timeout: float = 15.0):
        self.scope = scope
        self.out_dir = out_dir
        self.name = session_name
        self.timeout = timeout
        os.makedirs(out_dir, exist_ok=True)
        self.log_path = os.path.join(out_dir, "requests.jsonl")
        self.s = requests.Session()
        self.s.headers["User-Agent"] = scope.ua
        apply_session(self.s, session_entry)
        self.limiter = _LIMITERS.setdefault(scope.max_rps, _RateLimiter(scope.max_rps))
        self.errors_5xx = 0
        self.count = 0

    def request(self, method: str, url: str, allow_redirects: bool = False, **kw):
        self.scope.check(url, method)
        self.limiter.wait()
        t0 = time.monotonic()
        err = None
        resp = None
        try:
            resp = self.s.request(method, url, timeout=self.timeout, allow_redirects=False, **kw)
        except requests.RequestException as e:
            err = str(e)
        dt = round((time.monotonic() - t0) * 1000)
        self.count += 1
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": now_iso(), "session": self.name, "method": method, "url": url,
                                "status": resp.status_code if resp is not None else None,
                                "ms": dt, "len": len(resp.content) if resp is not None else None,
                                "error": err}) + "\n")
        if resp is not None and resp.status_code >= 500:
            self.errors_5xx += 1
            if self.errors_5xx >= 10:
                raise SystemExit("Stopping: 10+ server errors — possible impact on the target. Check with the user before continuing.")
        if err:
            return None
        # Follow redirects manually so every hop is scope-checked.
        hops = 0
        while allow_redirects and resp is not None and resp.is_redirect and hops < 5:
            nxt = requests.compat.urljoin(resp.url, resp.headers.get("Location", ""))
            if not self.scope.in_scope(nxt) or self.scope.excluded(nxt):
                resp.offscope_redirect = nxt  # type: ignore[attr-defined]
                return resp
            hops += 1
            resp = self.request("GET", nxt, allow_redirects=False)
        return resp

    def get(self, url: str, **kw):
        return self.request("GET", url, **kw)


def describe_request(resp) -> str:
    if resp is None:
        return ""
    r = resp.request
    hdrs = {k: v for k, v in r.headers.items() if k.lower() in ("origin", "content-type", "x-forwarded-host", "accept")}
    if "Cookie" in r.headers or "cookie" in r.headers:
        hdrs["Cookie"] = "<cookies redacted>"
    if "Authorization" in r.headers:
        hdrs["Authorization"] = "<redacted>"
    h = "".join(f"\n{k}: {v}" for k, v in hdrs.items())
    return f"{r.method} {r.url}{h}"


def excerpt(text: str, limit: int = 600) -> str:
    text = redact(text or "")
    return text if len(text) <= limit else text[:limit] + "…[truncated]"


SECRET_PATTERNS = [
    re.compile(r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|auth)[\"']?\s*[:=]\s*[\"']?)([^\s\"'&,<]{4})([^\s\"'&,<]*)"),
    re.compile(r"(eyJ[a-zA-Z0-9_-]{4})[a-zA-Z0-9_-]{6,}\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*"),
    re.compile(r"((?:sk|rk)_(?:live|test)_[a-zA-Z0-9]{4})[a-zA-Z0-9]+"),
    re.compile(r"(AKIA[0-9A-Z]{4})[0-9A-Z]{12}"),
]


def redact(text: str) -> str:
    def _kv(m):
        return m.group(1) + m.group(2) + "****"
    text = SECRET_PATTERNS[0].sub(_kv, text)
    for p in SECRET_PATTERNS[1:]:
        text = p.sub(lambda m: m.group(1) + "****", text)
    return text


# ---------------------------------------------------------------- findings
class Findings:
    def __init__(self, out_dir: str, target: str):
        self.path = os.path.join(out_dir, "findings.json")
        if os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as f:
                self.doc = json.load(f)
        else:
            self.doc = {"target": target, "generated_at": now_iso(), "findings": []}
        self.added = 0

    def add(self, **f) -> None:
        f.setdefault("status", "candidate")
        f.setdefault("confidence", "firm")
        f.setdefault("method", "GET")
        ids = {x["id"]: i for i, x in enumerate(self.doc["findings"])}
        if f["id"] in ids:
            existing = self.doc["findings"][ids[f["id"]]]
            if existing.get("status") != "candidate":
                return  # never overwrite verified/rejected work
            self.doc["findings"][ids[f["id"]]] = f
        else:
            self.doc["findings"].append(f)
            self.added += 1

    def save(self) -> None:
        self.doc["generated_at"] = now_iso()
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(self.doc, f, indent=2)


def slug(text: str, n: int = 40) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:n].strip("-") or "x"


def load_scope_or_exit(path: str) -> Scope:
    try:
        return Scope(path)
    except ScopeError as e:
        sys.exit(str(e))
    except FileNotFoundError:
        sys.exit(f"Scope file not found: {path}. Complete Phase 0 first (references/scope-template.md).")


def shash(text: str, n: int = 6) -> str:
    """Stable short hash for finding ids (Python's hash() is randomised per run)."""
    import hashlib
    return hashlib.sha1(text.encode()).hexdigest()[:n]
