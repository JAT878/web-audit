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

    out = {
        "browser_crawl": {"used": bool(a.browser), "note": browser_note,
                          "links": browser_links[:500], "api_urls": browser_api[:500]},
        "generated_at": now_iso(), "session": name, "target": scope.target,
        "pages": pages, "forms": forms, "scripts": sorted(scripts),
        "js_endpoints": sorted(endpoints), "js_absolute_urls": sorted(abs_urls),
        "robots_entries": robots, "sitemap_urls": sitemap[:500],
        "technology": sorted(tech), "cookies_seen": sorted(cookies_seen),
        "redirects_to_login": redirects_to_login, "offscope_links": sorted(offscope)[:300],
        "stats": {"requests": c.count, "pages": len(pages)},
    }
    fname = "recon.json" if name == "anonymous" else f"recon-{name}.json"
    with open(os.path.join(a.out, fname), "w", encoding="utf-8") as f:
        json.dump(out, f, indent=2)
    print(f"Recon ({name}): {len(pages)} pages, {len(forms)} forms, {len(scripts)} scripts, "
          f"{len(endpoints)} JS endpoints, {len(redirects_to_login)} login redirects -> {fname}")
    if tech:
        print("Tech: " + "; ".join(sorted(tech)))


if __name__ == "__main__":
    main()
