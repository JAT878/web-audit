#!/usr/bin/env python3
"""Phase 1 recon: crawl in-scope pages, mine JS for endpoints, fingerprint tech, list forms."""
import argparse
import json
import os
import re
import sys
from collections import deque
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, urldefrag

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402
from common import Client, load_scope_or_exit, load_sessions, now_iso  # noqa: E402

STATIC_EXT = re.compile(r"\.(png|jpe?g|gif|svg|ico|webp|woff2?|ttf|eot|css|mp4|mp3|pdf|zip|map)(\?|$)", re.I)
JS_ENDPOINT = re.compile(r"""["'`](\/(?:api|v[0-9]|graphql|rest|auth|admin|internal|user|users|account|orders?|invoices?|files?)[a-zA-Z0-9_\-\/{}\.:$?=&]*)["'`]""")
JS_ABS_URL = re.compile(r"""["'`](https?://[a-zA-Z0-9\.\-:]+/[a-zA-Z0-9_\-\/{}\.:$?=&]*)["'`]""")
FINGERPRINT_COOKIES = {
    "PHPSESSID": "PHP", "laravel_session": "Laravel", "XSRF-TOKEN": "Laravel/Angular CSRF",
    "ASP.NET_SessionId": "ASP.NET", ".AspNetCore.": "ASP.NET Core", "JSESSIONID": "Java servlet",
    "connect.sid": "Express", "csrftoken": "Django", "sessionid": "Django", "wordpress_": "WordPress",
    "wp-settings": "WordPress", "_rails": "Rails", "ci_session": "CodeIgniter", "__cf_bm": "Cloudflare",
    "AWSALB": "AWS ALB", "ARRAffinity": "Azure App Service",
}


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links, self.scripts, self.forms, self.meta = [], [], [], {}
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag in ("link", "iframe", "frame") and a.get("href" if tag == "link" else "src"):
            if tag != "link" or a.get("rel", "") in ("alternate", "next", "prev"):
                self.links.append(a.get("href") or a.get("src"))
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "meta" and a.get("name"):
            self.meta[a["name"].lower()] = a.get("content", "")
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "GET").upper(), "inputs": []}
        elif tag in ("input", "select", "textarea") and self._form is not None:
            self._form["inputs"].append({"name": a.get("name"), "type": a.get("type", tag),
                                         "autocomplete": a.get("autocomplete")})

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


def parse_html(html: str) -> dict:
    """Extract links, scripts, forms and meta. Uses BeautifulSoup (+lxml) if installed — more tolerant of
    broken markup — otherwise the stdlib parser."""
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        p = PageParser()
        try:
            p.feed(html)
        except Exception:
            pass
        return {"links": p.links, "scripts": p.scripts, "forms": p.forms, "meta": p.meta}
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        soup = BeautifulSoup(html, "html.parser")
    links = [a["href"] for a in soup.find_all("a", href=True)]
    links += [f["src"] for f in soup.find_all(["iframe", "frame"], src=True)]
    links += [l["href"] for l in soup.find_all("link", href=True)
              if set(l.get("rel") or []) & {"alternate", "next", "prev"}]
    scripts = [t["src"] for t in soup.find_all("script", src=True)]
    meta = {m["name"].lower(): m.get("content", "") for m in soup.find_all("meta", attrs={"name": True})}
    forms = []
    for f in soup.find_all("form"):
        forms.append({"action": f.get("action", ""), "method": (f.get("method") or "GET").upper(),
                      "inputs": [{"name": i.get("name"), "type": i.get("type", i.name), "autocomplete": i.get("autocomplete")}
                                 for i in f.find_all(["input", "select", "textarea"])]})
    return {"links": links, "scripts": scripts, "forms": forms, "meta": meta}


def norm(url: str) -> str:
    url, _ = urldefrag(url)
    return url


# -- endpoint templating ------------------------------------------------------
_SEG_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_SEG_NUM = re.compile(r"^\d{1,12}$")


def path_of(u: str) -> str:
    """Path portion of an absolute URL or a bare path/endpoint string (query/fragment stripped)."""
    if u.startswith("/"):
        return u.split("#", 1)[0].split("?", 1)[0]
    pp = urlparse(u).path or "/"
    return pp


def templatize(path: str) -> str:
    """Collapse numeric / UUID path segments to {id}: /orders/1001 -> /orders/{id}."""
    segs = path.split("/")
    out = []
    for s in segs:
        if s and (_SEG_NUM.match(s) or _SEG_UUID.match(s)):
            out.append("{id}")
        else:
            out.append(s)
    t = "/".join(out)
    return t or "/"


def build_endpoint_templates(urls):
    """Group discovered endpoint URLs/paths by their collapsed template. asset + id_shape come
    from the frozen common.asset_of / common.id_shape_of. Returns a list sorted by count desc."""
    groups = {}
    for raw in urls:
        if not raw:
            continue
        p = path_of(raw)
        if not p:
            continue
        tmpl = templatize(p)
        g = groups.get(tmpl)
        if g is None:
            g = {"template": tmpl, "asset": common.asset_of(p), "id_shape": common.id_shape_of(p),
                 "count": 0, "example_urls": []}
            groups[tmpl] = g
        g["count"] += 1
        # Promote id_shape from "none" if a later concrete URL reveals one (uuid > sequential > none).
        sh = common.id_shape_of(p)
        if sh != "none" and (g["id_shape"] == "none" or (sh == "uuid" and g["id_shape"] == "sequential")):
            g["id_shape"] = sh
        if g["asset"] is None and common.asset_of(p):
            g["asset"] = common.asset_of(p)
        if raw not in g["example_urls"] and len(g["example_urls"]) < 3:
            g["example_urls"].append(raw)
    return sorted(groups.values(), key=lambda x: (-x["count"], x["template"]))


def dedup_forms(forms):
    """Collapse identical forms by (action, method, sorted input names) with a page_count (AUDIT T2)."""
    groups, order = {}, []
    for f in forms:
        names = tuple(sorted((i.get("name") or "") for i in f.get("inputs", [])))
        key = (f.get("action_abs") or f.get("action") or "", f.get("method", "GET"), names)
        g = groups.get(key)
        if g is None:
            g = {"action": f.get("action", ""), "action_abs": f.get("action_abs"),
                 "method": f.get("method", "GET"), "inputs": f.get("inputs", []), "pages": []}
            groups[key] = g
            order.append(key)
        pg = f.get("page")
        if pg and pg not in g["pages"]:
            g["pages"].append(pg)
    out = []
    for key in order:
        g = groups[key]
        g["page_count"] = len(g["pages"]) or 1
        g["pages"] = g["pages"][:10]
        out.append(g)
    return out


def compute_auth_surface_diff(out_dir, name, templates, param_urls):
    """If an anonymous recon.json exists, return templates/URLs that only appear authenticated."""
    anon_path = os.path.join(out_dir, "recon.json")
    if not os.path.exists(anon_path):
        return None
    try:
        with open(anon_path, encoding="utf-8") as f:
            anon = json.load(f)
    except Exception:
        return None
    anon_tmpls = {t.get("template") for t in anon.get("endpoint_templates", [])}
    anon_paths = {path_of(p.get("url", "")) for p in anon.get("pages", [])}
    anon_params = set(anon.get("urls_with_params", []))
    only = sorted({t["template"] for t in templates
                   if t["template"] not in anon_tmpls and t["template"] not in anon_paths})
    only_params = sorted(set(param_urls) - anon_params)
    return {"only_when_authenticated": only, "only_when_authenticated_params": only_params, "session": name}


def write_summary(out_dir, out, auth_diff):
    """Concise human/agent-readable recon summary (AUDIT T1). Target ~150 lines."""
    L = []
    a = L.append
    a(f"# Recon summary — {out['target']}")
    a("")
    a(f"- session: {out['session']}")
    a(f"- generated: {out['generated_at']}")
    st = out["stats"]
    a(f"- pages crawled: {st['pages']}  |  requests: {st['requests']}")
    a(f"- forms (deduped): {len(out['forms'])}  |  scripts: {len(out['scripts'])}  |  "
      f"JS endpoints: {len(out['js_endpoints'])}")
    a("")
    # status histogram
    hist = {}
    for p in out["pages"]:
        hist[p["status"]] = hist.get(p["status"], 0) + 1
    a("## Status histogram")
    for code in sorted(hist):
        a(f"- {code}: {hist[code]}")
    a("")
    # tech
    a("## Technology fingerprint")
    if out["technology"]:
        for t in out["technology"]:
            a(f"- {t}")
    else:
        a("- (none detected)")
    a("")
    # endpoint templates
    a("## Endpoint templates")
    a("(asset / id_shape; `*` flags sequential ids — enumerable)")
    for t in out["endpoint_templates"][:80]:
        flag = " *" if t["id_shape"] == "sequential" else ""
        asset = t["asset"] or "-"
        a(f"- `{t['template']}` x{t['count']} [{asset} / {t['id_shape']}]{flag}")
    a("")
    # sensitive-object paths
    sens = [t for t in out["endpoint_templates"] if t["asset"]]
    a("## Sensitive-object paths (asset-bearing)")
    if sens:
        for t in sens[:40]:
            flag = " *sequential" if t["id_shape"] == "sequential" else ""
            a(f"- `{t['template']}` -> {t['asset']}{flag}")
    else:
        a("- (none)")
    a("")
    # params
    a("## URLs carrying parameters")
    if out["urls_with_params"]:
        for u in out["urls_with_params"][:40]:
            a(f"- {u}")
    else:
        a("- (none)")
    a("")
    # off-scope hosts
    a("## Off-scope hosts (host:count)")
    hosts = {}
    for u in out["offscope_links"]:
        h = urlparse(u).netloc or "?"
        hosts[h] = hosts.get(h, 0) + 1
    if hosts:
        for h in sorted(hosts, key=lambda x: -hosts[x])[:40]:
            a(f"- {h}:{hosts[h]}")
    else:
        a("- (none)")
    a("")
    # auth diff
    if auth_diff:
        a(f"## Auth surface diff (only when authenticated as {auth_diff['session']})")
        rows = auth_diff["only_when_authenticated"] + [f"{u} (param)" for u in auth_diff.get("only_when_authenticated_params", [])]
        if rows:
            for u in rows[:40]:
                a(f"- {u}")
        else:
            a("- (no new surface vs anonymous)")
        a("")
    with open(os.path.join(out_dir, "recon-summary.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")


def browser_crawl(scope, start_urls, session_entry, max_pages):
    """Optional JS-rendering pass. Renders pages in a headless browser and records the links and the
    XHR/fetch URLs that only appear after JavaScript runs. Returns (links, api_urls, ok, reason).
    Never raises — if Playwright or a browser is missing, it reports why and the caller falls back."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return set(), set(), False, "playwright not installed (pip install playwright && python3 -m playwright install chromium)"
    links, api = set(), set()
    try:
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(headless=True)
            except Exception:
                browser = p.chromium.launch(headless=True, executable_path="/usr/bin/google-chrome")
            ctx = browser.new_context()
            from common import apply_session
            if session_entry and session_entry.get("storage_state") and os.path.exists(session_entry["storage_state"]):
                ctx = browser.new_context(storage_state=session_entry["storage_state"])
            page = ctx.new_page()
            page.on("request", lambda req: api.add(req.url) if req.resource_type in ("xhr", "fetch") else None)
            visited = set()
            queue = list(start_urls)
            while queue and len(visited) < max_pages:
                url = queue.pop(0)
                if url in visited or not scope.in_scope(url) or scope.excluded(url):
                    continue
                visited.add(url)
                try:
                    page.goto(url, wait_until="networkidle", timeout=15000)
                except Exception:
                    continue
                for a_tag in page.query_selector_all("a[href]"):
                    href = a_tag.get_attribute("href")
                    if href:
                        full = urljoin(url, href)
                        links.add(full)
                        if scope.in_scope(full) and full not in visited:
                            queue.append(norm(full))
            browser.close()
    except Exception as e:
        return links, api, False, f"browser crawl error: {str(e)[:120]}"
    return links, api, True, f"rendered {len(links)} link(s), {len(api)} XHR/fetch URL(s)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--sessions")
    ap.add_argument("--session", help="session name from sessions.json to crawl as")
    ap.add_argument("--max-pages", type=int, default=150)
    ap.add_argument("--max-js", type=int, default=40)
    ap.add_argument("--seed", action="append", default=[], help="extra start URLs")
    ap.add_argument("--browser", action="store_true", help="also do a JS-rendering crawl (needs Playwright); falls back to the normal crawl if unavailable")
    a = ap.parse_args()

    scope = load_scope_or_exit(a.scope)
    sessions = load_sessions(a.sessions)
    name = a.session or "anonymous"
    if a.session and a.session not in sessions:
        sys.exit(f"Session '{a.session}' not in sessions file")
    c = Client(scope, a.out, name, sessions.get(a.session) if a.session else None)

    start = [scope.target + "/"] + a.seed
    for extra in ("/robots.txt", "/sitemap.xml"):
        start.append(scope.target + extra)

    seen, queue = set(), deque(start)
    pages, forms, scripts, offscope, robots, sitemap = [], [], set(), set(), [], []
    headers_seen, cookies_seen, tech = {}, set(), set()
    redirects_to_login = []

    while queue and len(pages) < a.max_pages:
        url = norm(queue.popleft())
        if url in seen:
            continue
        seen.add(url)
        if not scope.in_scope(url):
            offscope.add(url)
            continue
        if scope.excluded(url) or STATIC_EXT.search(urlparse(url).path):
            continue
        r = c.get(url)
        if r is None:
            continue
        loc = r.headers.get("Location")
        pages.append({"url": url, "status": r.status_code, "type": r.headers.get("Content-Type", ""),
                      "len": len(r.content), "location": loc})
        for k in ("Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "Via", "X-Drupal-Cache"):
            if k in r.headers:
                headers_seen[k] = r.headers[k]
        for ck in r.cookies:
            cookies_seen.add(ck.name)
        if loc:
            nxt = urljoin(url, loc)
            if re.search(r"login|signin|sign-in|auth|sso|oauth", nxt, re.I):
                redirects_to_login.append({"url": url, "to": nxt})
            queue.append(nxt)
            continue
        if url.endswith("/robots.txt") and r.status_code == 200:
            for line in r.text.splitlines():
                m = re.match(r"(?i)\s*(dis)?allow:\s*(\S+)", line)
                if m:
                    robots.append(m.group(2))
                    if "*" not in m.group(2):
                        queue.append(urljoin(scope.target + "/", m.group(2)))
                m = re.match(r"(?i)\s*sitemap:\s*(\S+)", line)
                if m:
                    queue.append(m.group(1))
            continue
        if "xml" in r.headers.get("Content-Type", "") or url.endswith(".xml"):
            if r.status_code == 200:
                for loc_url in re.findall(r"<loc>\s*([^<\s]+)\s*</loc>", r.text)[:500]:
                    sitemap.append(loc_url)
                    queue.append(loc_url)
            continue
        if "html" not in r.headers.get("Content-Type", ""):
            continue
        p = parse_html(r.text)
        gen = p["meta"].get("generator")
        if gen:
            tech.add(f"generator: {gen}")
        for f in p["forms"]:
            f["page"] = url
            f["action_abs"] = urljoin(url, f["action"]) if f["action"] else url
            forms.append(f)
        for s in p["scripts"]:
            scripts.add(urljoin(url, s))
        for l in p["links"]:
            if l.startswith(("mailto:", "tel:", "javascript:", "data:")):
                continue
            queue.append(urljoin(url, l))

    # JS mining
    endpoints, abs_urls = set(), set()
    for js in list(sorted(scripts))[: a.max_js]:
        if not scope.in_scope(js):
            offscope.add(js)
            continue
        r = c.get(js)
        if r is None or r.status_code != 200:
            continue
        for m in JS_ENDPOINT.findall(r.text):
            endpoints.add(m)
        for m in JS_ABS_URL.findall(r.text):
            abs_urls.add(m)
        if "sourceMappingURL=" in r.text[-500:]:
            endpoints.add("[sourcemap] " + js + " references a source map")

    browser_note = None
    browser_links, browser_api = [], []
    if a.browser:
        b_links, b_api, ok, reason = browser_crawl(scope, [p["url"] for p in pages][:a.max_pages] or start,
                                                   sessions.get(a.session) if a.session else None, a.max_pages)
        browser_note = reason
        if ok:
            new_pages = {urlparse(u).path for u in b_links if scope.in_scope(u)} - {urlparse(p["url"]).path for p in pages}
            browser_links = sorted(u for u in b_links if scope.in_scope(u))
            browser_api = sorted(b_api)
            for ep in b_api:
                if scope.in_scope(ep):
                    rel = ep[len(scope.target):] if ep.startswith(scope.target) else ep
                    endpoints.add(rel if rel.startswith("/") else ep)
            print(f"Browser crawl: {reason}; {len(new_pages)} path(s) the static crawl missed")
        else:
            print(f"Browser crawl skipped: {reason} — using static crawl results only")

    for name_c in cookies_seen:
        for k, v in FINGERPRINT_COOKIES.items():
            if name_c.startswith(k):
                tech.add(v)
    for k, v in headers_seen.items():
        tech.add(f"{k}: {v}")

    # -- endpoint templates: collapse numeric/UUID path segments, asset + id_shape via common
    sorted_endpoints = sorted(endpoints)
    template_sources = (
        [p["url"] for p in pages]
        + list(sitemap)
        + [u for u in abs_urls if scope.in_scope(u)]
        + [e for e in sorted_endpoints if e.startswith("/")]
        + [f.get("action_abs") for f in forms if f.get("action_abs")]
        + list(browser_api) + list(browser_links)
    )
    endpoint_templates = build_endpoint_templates(template_sources)

    # -- URLs carrying query parameters (across pages, JS endpoints and absolute URLs)
    param_pool = [p["url"] for p in pages] + sorted_endpoints + sorted(abs_urls) + list(browser_api)
    from common import redact_url
    urls_with_params = sorted({redact_url(u) for u in param_pool if isinstance(u, str) and "?" in u})

    # -- deduplicate forms by (action, method, sorted input names) with a page_count (AUDIT T2)
    deduped_forms = dedup_forms(forms)

    out = {
        "browser_crawl": {"used": bool(a.browser), "note": browser_note,
                          "links": browser_links[:500], "api_urls": browser_api[:500]},
        "generated_at": now_iso(), "session": name, "target": scope.target,
        "pages": pages, "forms": deduped_forms, "scripts": sorted(scripts),
        "endpoint_templates": endpoint_templates,
        "urls_with_params": urls_with_params,
        "js_endpoints": sorted_endpoints, "js_absolute_urls": sorted(abs_urls),
        "robots_entries": robots, "sitemap_urls": sitemap[:500],
        "technology": sorted(tech), "cookies_seen": sorted(cookies_seen),
        "redirects_to_login": redirects_to_login, "offscope_links": sorted(offscope)[:300],
        "stats": {"requests": c.count, "pages": len(pages), "forms_raw": len(forms)},
    }

    # -- anonymous-vs-authenticated surface diff (session runs only, if anon recon.json exists)
    auth_diff = None
    if name != "anonymous":
        auth_diff = compute_auth_surface_diff(a.out, name, endpoint_templates, urls_with_params)
        if auth_diff is not None:
            out["auth_surface_diff"] = auth_diff

    fname = "recon.json" if name == "anonymous" else f"recon-{name}.json"
    with open(os.path.join(a.out, fname), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)

    # -- concise recon-summary.md (AUDIT T1) — what the agent reads instead of the full JSON
    write_summary(a.out, out, auth_diff)

    print(f"Recon ({name}): {len(pages)} pages, {len(deduped_forms)} forms ({len(forms)} raw), "
          f"{len(scripts)} scripts, {len(endpoints)} JS endpoints, {len(endpoint_templates)} templates, "
          f"{len(redirects_to_login)} login redirects -> {fname}")
    if auth_diff is not None:
        print(f"Auth surface diff vs anonymous: {len(auth_diff['only_when_authenticated'])} new template(s)")
    if tech:
        print("Tech: " + "; ".join(sorted(tech)))


if __name__ == "__main__":
    main()
