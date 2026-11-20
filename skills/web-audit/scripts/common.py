"""Shared core: scope enforcement, rate-limited HTTP client, findings store, redaction,
capability vocabulary for attack-chain correlation.

This module is the single dependency every script imports. Public API (stable):
  now_iso, ScopeError, TargetDistress, Scope, load_scope_or_exit,
  load_sessions, apply_session, Client, describe_request, excerpt,
  redact, redact_url, Findings, slug, shash,
  GRANTS, REQUIRES, ASSET_HINTS, cap_fields
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
import posixpath
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit, urlparse, unquote, parse_qsl, urlencode

try:
    import requests
    import urllib3
except ImportError:  # pragma: no cover
    sys.exit("This skill needs 'requests': pip install requests")

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
DEFAULT_UA = "Mozilla/5.0 (compatible; web-audit/1.0)"


def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


# ================================================================ capability vocab
# Shared, deliberately small controlled vocabulary so correlate.py can match
# one finding's GRANTS against another's REQUIRES. Scripts attach these via cap_fields().
GRANTS = {
    "knowledge:user-ids", "knowledge:usernames", "knowledge:schema",
    "knowledge:internal-host", "knowledge:secret", "knowledge:endpoint",
    "read:other-user", "read:any-user", "read:admin",
    "write:other-user", "write:admin",
    "session:fixate", "session:steal", "token:forge", "token:no-expiry",
    "identity:assume-user", "identity:assume-admin", "exec:code",
}
REQUIRES = {
    "none", "identity:user", "identity:admin",
    "knowledge:user-ids", "knowledge:usernames", "knowledge:schema",
    "knowledge:endpoint", "holds:token",
}
ASSET_HINTS = (  # (regex on path, asset class) — recon/correlate normalise with this
    (re.compile(r"/orders?\b", re.I), "order"),
    (re.compile(r"/invoices?\b", re.I), "invoice"),
    (re.compile(r"/users?\b", re.I), "user"),
    (re.compile(r"/accounts?\b", re.I), "account"),
    (re.compile(r"/files?\b|/attachments?\b|/documents?\b", re.I), "file"),
    (re.compile(r"/reports?\b", re.I), "report"),
    (re.compile(r"/admin\b", re.I), "admin"),
)
_CHAIN_ROLES = {"disclosure", "authz", "privilege", "session", "injection", "standalone"}


def cap_fields(grants=None, requires=None, assets=None, id_shape=None, chain_role=None) -> dict:
    """Validate + assemble the capability fields for a finding. Unknown tokens are dropped
    (with a note) rather than raising, so a detector can never crash the pipeline on a typo."""
    out: dict = {}
    g = [x for x in (grants or []) if x in GRANTS]
    r = [x for x in (requires or []) if x in REQUIRES]
    if g:
        out["grants"] = sorted(set(g))
    if r:
        out["requires"] = sorted(set(r))
    if assets:
        out["assets"] = sorted({a for a in assets if a})
    if id_shape in ("sequential", "uuid", "slug", "none"):
        out["id_shape"] = id_shape
    if chain_role in _CHAIN_ROLES:
        out["chain_role"] = chain_role
    return out


def asset_of(url: str) -> str | None:
    path = urlsplit(url).path if "//" in url else url
    for rx, name in ASSET_HINTS:
        if rx.search(path or ""):
            return name
    return None


_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_SEQ = re.compile(r"/\d{1,12}(?:/|$|\?)")


def id_shape_of(url: str) -> str:
    if _UUID.search(url):
        return "uuid"
    if _SEQ.search(url):
        return "sequential"
    return "none"


# ================================================================ errors
class ScopeError(Exception):
    pass


class TargetDistress(Exception):
    """Raised when the target shows signs of impact (consecutive 5xx / errors).
    Scripts should catch this in a try/finally that saves findings, then exit non-zero."""


# ================================================================ scope
def _host_port(url: str):
    """Return (host, port, error). Parses with urllib3 — the SAME parser urllib3/requests
    use to open the socket — so the scope check can't disagree with where the request goes
    (closes the backslash/userinfo host-confusion bypass)."""
    if url is None:
        return None, None, "empty url"
    for bad in ("\\", "\n", "\r", "\t", "\x00", " "):
        if bad in url:
            return None, None, f"illegal character in URL"
    try:
        u = urllib3.util.parse_url(url)
    except Exception as e:  # noqa: BLE001
        return None, None, f"unparseable URL: {e}"
    if u.auth:  # userinfo (user:pass@host) — never allowed; can smuggle creds off-scope
        return None, None, "URL contains userinfo"
    if u.scheme not in ("http", "https"):
        return None, None, f"non-http scheme: {u.scheme}"
    host = (u.host or "").rstrip(".").lower()
    if not host:
        return None, None, "no host"
    port = u.port or (443 if u.scheme == "https" else 80)
    return host, port, None


class Scope:
    REQUIRED = ["target", "allowed_hosts", "environment", "authorization", "mode"]
    # Path segments that may change state; blocked for GET too unless allow_state_changing.
    DENY_SEGMENTS = re.compile(
        r"(?:^|/)(logout|signout|sign-out|delete|remove|destroy|cancel|unsubscribe|"
        r"impersonate|reset|revoke|disable|enable|approve|deactivate|purge|drop)(?:/|$|\.)",
        re.I,
    )

    def __init__(self, path: str):
        with open(path, encoding="utf-8") as f:
            self.raw = json.load(f)
        self.path = path
        problems = self.problems()
        if problems:
            raise ScopeError("Scope file is not valid:\n  - " + "\n  - ".join(problems))
        r = self.raw
        self.target = r["target"].rstrip("/")
        self.allowed_hosts = {h.split(":")[0].lower() for h in r["allowed_hosts"]}
        self.environment = r["environment"]
        self.mode = r["mode"]
        self.max_rps = float(r.get("max_rps", 3))
        self.allow_state_changing = bool(r.get("allow_state_changing", False))
        # Rules of engagement flags (read now; active behaviour lands in later phases).
        self.allow_token_forge = bool(r.get("allow_token_forge", False))
        self.allow_active_exploit = bool(r.get("allow_active_exploit", False))
        self.max_chain_hops = int(r.get("max_chain_hops", 6))
        # Ports: explicit list, else the target's port plus 80/443. Closes "any port on host".
        tp = urlparse(self.target).port or (443 if self.target.startswith("https") else 80)
        explicit = set()
        for h in r["allowed_hosts"]:
            if ":" in h:
                try:
                    explicit.add(int(h.split(":", 1)[1]))
                except ValueError:
                    pass
        self.allowed_ports = set(r.get("allowed_ports") or []) | explicit | {tp, 80, 443}
        # Excluded paths, normalised once. "/" means "everything".
        self.exclude_all = any((p or "").strip() == "/" for p in r.get("excluded_paths", []))
        self.excluded_paths = sorted({self._norm(p) for p in r.get("excluded_paths", []) if (p or "").strip() != "/"})
        self.ua = DEFAULT_UA + (f" {r['user_agent_tag']}" if r.get("user_agent_tag") else "")

    # -- validation
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
            elif p.hostname.lower() not in {h.split(":")[0].lower() for h in r.get("allowed_hosts", [])}:
                out.append("target host must be listed in allowed_hosts")
        try:
            rps = float(r.get("max_rps", 3))
            if rps <= 0 or rps > 20:
                out.append("max_rps must be between 0 and 20")
            if r.get("environment") == "production" and rps > 2:
                out.append("max_rps above 2 against production is not allowed by this skill")
        except (TypeError, ValueError):
            out.append("max_rps must be a number")
        return out

    # -- path normalisation (unquote, collapse //, strip ;params, resolve .., casefold)
    @staticmethod
    def _norm(path_or_url: str) -> str:
        path = urlsplit(path_or_url).path if "//" in path_or_url else path_or_url
        path = unquote(path or "/")
        path = path.split(";", 1)[0]
        path = re.sub(r"/{2,}", "/", path)
        if not path.startswith("/"):
            path = "/" + path
        path = posixpath.normpath(path)
        return (path if path != "." else "/").lower()

    # -- decisions
    def in_scope(self, url: str) -> bool:
        host, port, err = _host_port(url)
        if err:
            return False
        return host in self.allowed_hosts and port in self.allowed_ports

    def excluded(self, url: str) -> bool:
        if self.exclude_all:
            return True
        np = self._norm(url)
        for ex in self.excluded_paths:
            if np == ex or np.startswith(ex.rstrip("/") + "/"):
                return True
        return False

    def state_changing_path(self, url: str) -> bool:
        return bool(self.DENY_SEGMENTS.search(self._norm(url)))

    def check(self, url: str, method: str) -> None:
        host, port, err = _host_port(url)
        if err:
            raise ScopeError(f"Rejected URL ({err}): {url}")
        if host not in self.allowed_hosts:
            raise ScopeError(f"Out of scope host: {host} ({url})")
        if port not in self.allowed_ports:
            raise ScopeError(f"Out of scope port: {port} (allowed: {sorted(self.allowed_ports)})")
        if self.excluded(url):
            raise ScopeError(f"Excluded path: {url}")
        m = method.upper()
        if m not in SAFE_METHODS and not self.allow_state_changing:
            raise ScopeError(f"{method} blocked: allow_state_changing is false")
        # Block state-changing GETs (e.g. /logout, /orders/5/delete) unless explicitly allowed.
        if not self.allow_state_changing and self.state_changing_path(url):
            raise ScopeError(f"State-changing path blocked (read-only mode): {url}")


def load_scope_or_exit(path: str) -> Scope:
    try:
        return Scope(path)
    except ScopeError as e:
        sys.exit(str(e))
    except FileNotFoundError:
        sys.exit(f"Scope file not found: {path}. Complete Phase 0 first (references/scope-template.md).")


# ================================================================ sessions
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


# ================================================================ http
class _RateLimiter:
    """Cross-process token bucket via a lock file, so N scripts sharing max_rps stay under it."""

    def __init__(self, rps: float, out_dir: str):
        self.interval = 1.0 / rps
        self.lock = threading.Lock()
        self.last = 0.0
        self.stamp = os.path.join(out_dir, ".ratelimit")

    def wait(self):
        with self.lock:
            try:
                import fcntl
                with open(self.stamp, "a+", encoding="utf-8") as f:
                    fcntl.flock(f, fcntl.LOCK_EX)
                    f.seek(0)
                    raw = f.read().strip()
                    last = float(raw) if raw else 0.0
                    delta = time.time() - last
                    if delta < self.interval:
                        time.sleep(self.interval - delta)
                    f.seek(0)
                    f.truncate()
                    f.write(str(time.time()))
                    fcntl.flock(f, fcntl.LOCK_UN)
                    return
            except Exception:  # noqa: BLE001 — no fcntl (non-POSIX) or FS issue: fall back to in-process
                pass
            delta = time.monotonic() - self.last
            if delta < self.interval:
                time.sleep(self.interval - delta)
            self.last = time.monotonic()


_LIMITERS: dict[tuple, _RateLimiter] = {}
MAX_BODY = 262144  # 256 KB cap — never pull a full heapdump/backup into memory


class Client:
    """Rate-limited, scope-enforcing HTTP client that logs every request (URL redacted)."""

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
        # Anonymous client must not accumulate server-set cookies (could mask unauth-access bugs).
        self._strip_cookies = session_entry is None and session_name == "anonymous"
        apply_session(self.s, session_entry)
        self.limiter = _LIMITERS.setdefault((scope.max_rps, out_dir), _RateLimiter(scope.max_rps, out_dir))
        self.errors_5xx = 0
        self._consec = 0
        self.count = 0

    def request(self, method: str, url: str, allow_redirects: bool = False, **kw):
        self.scope.check(url, method)
        self.limiter.wait()
        if self._strip_cookies:
            self.s.cookies.clear()
        t0 = time.monotonic()
        err = None
        resp = None
        kw.setdefault("stream", True)
        try:
            resp = self.s.request(method, url, timeout=self.timeout, allow_redirects=False, **kw)
            body = resp.content[:MAX_BODY] if resp is not None else b""
            resp._content = body  # cap in-memory body
        except requests.RequestException as e:
            err = str(e)
        dt = round((time.monotonic() - t0) * 1000)
        self.count += 1
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": now_iso(), "session": self.name, "method": method,
                                "url": redact_url(url),
                                "status": resp.status_code if resp is not None else None,
                                "ms": dt, "len": len(resp.content) if resp is not None else None,
                                "error": err}) + "\n")
        # Circuit breaker: consecutive 5xx or transport errors suggest impact.
        if err is not None or (resp is not None and resp.status_code >= 500):
            self._consec += 1
            if resp is not None and resp.status_code >= 500:
                self.errors_5xx += 1
        else:
            self._consec = 0
        if self._consec >= 8:
            raise TargetDistress(
                f"Stopping: {self._consec} consecutive errors — possible impact on the target. "
                "Findings so far are saved; check with the user before continuing.")
        if err:
            return None
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


# ================================================================ redaction
SECRET_PATTERNS = [
    re.compile(r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|refresh[_-]?token|session[_-]?id|auth)[\"']?\s*[:=]\s*[\"']?)([^\s\"'&,<]{0,4})([^\s\"'&,<]*)"),
    re.compile(r"(?i)(authorization:\s*\w+\s+)([A-Za-z0-9._\-]{6,})"),
    re.compile(r"(?i)(bearer\s+)([A-Za-z0-9._\-]{8,})"),
    re.compile(r"(?i)(set-cookie:\s*[^=;\s]+=)([^;\s]{4,})"),
    re.compile(r"(?i)(cookie:\s*)([^\r\n]+)"),
    re.compile(r"(eyJ[a-zA-Z0-9_-]{4})[a-zA-Z0-9_-]{6,}\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]*"),
    re.compile(r"((?:sk|rk)_(?:live|test)_[a-zA-Z0-9]{4})[a-zA-Z0-9]+"),
    re.compile(r"(AKIA[0-9A-Z]{4})[0-9A-Z]{12}"),
]
SENSITIVE_PARAMS = {
    "token", "code", "key", "sig", "signature", "auth", "session", "sessionid",
    "password", "passwd", "pwd", "jwt", "access_token", "refresh_token", "id_token",
    "api_key", "apikey", "secret", "otp", "x-amz-signature", "x-amz-credential",
}


def redact(text: str) -> str:
    text = text or ""
    text = SECRET_PATTERNS[0].sub(lambda m: m.group(1) + m.group(2) + "****", text)
    for p in SECRET_PATTERNS[1:5]:
        text = p.sub(lambda m: m.group(1) + "****", text)
    for p in SECRET_PATTERNS[5:]:
        text = p.sub(lambda m: m.group(1) + "****", text)
    return text


def redact_url(url: str) -> str:
    """Mask sensitive query-parameter values in a URL before it is logged or shown as evidence."""
    try:
        parts = urlsplit(url)
    except Exception:  # noqa: BLE001
        return redact(url)
    if not parts.query:
        return url
    q = [(k, "****" if k.lower() in SENSITIVE_PARAMS else v)
         for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(q), parts.fragment))


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
    return f"{r.method} {redact_url(r.url)}{h}"


def excerpt(text: str, limit: int = 600) -> str:
    text = redact(text or "")
    return text if len(text) <= limit else text[:limit] + "…[truncated]"


# ================================================================ findings
class Findings:
    """Concurrency-safe findings store. Scripts run in parallel, so save() takes a file lock,
    re-reads what is on disk, merges, and atomically replaces — no writer clobbers another."""

    def __init__(self, out_dir: str, target: str):
        self.path = os.path.join(out_dir, "findings.json")
        self.target = target
        if os.path.exists(self.path):
            with open(self.path, encoding="utf-8") as f:
                self.doc = json.load(f)
        else:
            self.doc = {"target": target, "generated_at": now_iso(), "findings": []}
        self.added = 0

    @staticmethod
    def _apply(doc: dict, f: dict) -> bool:
        idx = {x["id"]: i for i, x in enumerate(doc["findings"])}
        if f["id"] in idx:
            existing = doc["findings"][idx[f["id"]]]
            if existing.get("status") != "candidate":
                return False  # never overwrite verified/rejected work
            doc["findings"][idx[f["id"]]] = f
            return False
        doc["findings"].append(f)
        return True

    def add(self, **f) -> None:
        f.setdefault("status", "candidate")
        f.setdefault("confidence", "firm")
        f.setdefault("method", "GET")
        if self._apply(self.doc, f):
            self.added += 1

    def save(self) -> None:
        lock = self.path + ".lock"
        try:
            import fcntl
            lf = open(lock, "w", encoding="utf-8")
            fcntl.flock(lf, fcntl.LOCK_EX)
        except Exception:  # noqa: BLE001
            lf = None
        try:
            if os.path.exists(self.path):
                with open(self.path, encoding="utf-8") as f:
                    base = json.load(f)
            else:
                base = {"target": self.target, "findings": []}
            base.setdefault("findings", [])
            for f in self.doc["findings"]:
                self._apply(base, f)
            base["target"] = base.get("target") or self.target
            base["generated_at"] = now_iso()
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(base, f, indent=2)
            os.replace(tmp, self.path)
            self.doc = base
        finally:
            if lf is not None:
                try:
                    import fcntl
                    fcntl.flock(lf, fcntl.LOCK_UN)
                finally:
                    lf.close()


# ================================================================ misc helpers
def slug(text: str, n: int = 40) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return s[:n].strip("-") or "x"


def shash(text: str, n: int = 6) -> str:
    """Stable short hash for finding ids (Python's hash() is randomised per run)."""
    import hashlib
    return hashlib.sha1(text.encode()).hexdigest()[:n]
