#!/usr/bin/env python3
"""Turn a browser HAR capture into inputs for the other phases.

You click through the app in your browser (DevTools > Network > export HAR). This reads that file and
writes, for the in-scope requests only:
  * endpoints.txt   — unique GET URLs, for `authz_replay.py --endpoints` and re-checking
  * har-endpoints.json — richer detail (method, content-type, has-body) for your review

It captures the real API calls the app makes, including ones fired by JavaScript that the crawler
misses. It does NOT replay anything itself — it just extracts targets. Secrets in the HAR stay in the
HAR; only URLs and metadata are written out.
"""
import argparse
import json
import os
import sys
from urllib.parse import urlparse, urlunparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import load_scope_or_exit  # noqa: E402

STATIC = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".woff", ".woff2",
          ".ttf", ".css", ".mp4", ".mp3", ".map")


def strip(url):
    u = urlparse(url)
    return urlunparse((u.scheme, u.netloc, u.path, "", u.query, ""))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--har", required=True)
    ap.add_argument("--include-static", action="store_true", help="keep images/css/fonts (off by default)")
    a = ap.parse_args()
    scope = load_scope_or_exit(a.scope)
    with open(a.har, encoding="utf-8") as f:
        har = json.load(f)

    entries = har.get("log", {}).get("entries", [])
    rows = []
    get_urls, seen = [], set()
    off_scope = 0
    for e in entries:
        req = e.get("request", {})
        url = req.get("url", "")
        method = req.get("method", "GET").upper()
        if not url:
            continue
        if not scope.in_scope(url):
            off_scope += 1
            continue
        if scope.excluded(url):
            continue
        path = urlparse(url).path.lower()
        if not a.include_static and path.endswith(STATIC):
            continue
        ctype = ""
        for h in e.get("response", {}).get("headers", []):
            if h.get("name", "").lower() == "content-type":
                ctype = h.get("value", "").split(";")[0]
        has_body = bool(req.get("postData", {}).get("text"))
        rows.append({"method": method, "url": strip(url), "response_content_type": ctype,
                     "status": e.get("response", {}).get("status"), "has_request_body": has_body})
        if method == "GET":
            s = strip(url)
            if s not in seen:
                seen.add(s)
                get_urls.append(s)

    # de-dup rows by (method, url)
    uniq, keys = [], set()
    for r in rows:
        k = (r["method"], r["url"])
        if k not in keys:
            keys.add(k)
            uniq.append(r)

    ep_path = os.path.join(a.out, "endpoints.txt")
    with open(ep_path, "w", encoding="utf-8") as f:
        f.write("\n".join(get_urls) + ("\n" if get_urls else ""))
    with open(os.path.join(a.out, "har-endpoints.json"), "w", encoding="utf-8") as f:
        json.dump(uniq, f, indent=2)

    methods = sorted({r["method"] for r in uniq})
    print(f"HAR import: {len(entries)} entries -> {len(uniq)} in-scope requests "
          f"({len(get_urls)} unique GET), methods: {', '.join(methods)}; {off_scope} off-scope skipped")
    print(f"  Wrote {ep_path} (feed to: authz_replay.py --endpoints {ep_path})")
    non_get = [r for r in uniq if r["method"] != "GET"]
    if non_get:
        print(f"  Note: {len(non_get)} non-GET request(s) captured — these are listed in har-endpoints.json for "
              "manual review. authz_replay only replays GETs unless the scope allows state-changing requests.")


if __name__ == "__main__":
    main()
