#!/usr/bin/env python3
"""Capture an authenticated session with Playwright and save it to sessions.json.

Manual (recommended; works with MFA/SSO):
  capture_session.py --scope scope.json --out OUT --name user_a --login-url https://site/login --manual

Automated form login (no MFA):
  capture_session.py ... --name user_a --login-url URL --username u --password-env AUDIT_PASS_A \
      [--user-selector 'input[name=email]'] [--pass-selector 'input[type=password]'] [--submit-selector 'button[type=submit]']

Add --marker 'alice@example.com' (repeatable) for identity markers used by authz_replay.
Also records the cookies before and after login so you can check session-ID rotation.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import load_scope_or_exit, now_iso  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--name", required=True)
    ap.add_argument("--login-url", required=True)
    ap.add_argument("--manual", action="store_true")
    ap.add_argument("--username")
    ap.add_argument("--password-env", help="env var holding the password (keeps it out of shell history)")
    ap.add_argument("--user-selector", default="input[type=email], input[name*=user i], input[name*=email i], input[id*=user i]")
    ap.add_argument("--pass-selector", default="input[type=password]")
    ap.add_argument("--submit-selector", default="button[type=submit], input[type=submit]")
    ap.add_argument("--success-selector", help="element that only appears when logged in")
    ap.add_argument("--marker", action="append", default=[])
    ap.add_argument("--timeout", type=int, default=300, help="seconds to wait for manual login")
    a = ap.parse_args()

    scope = load_scope_or_exit(a.scope)
    if not scope.in_scope(a.login_url):
        print("Note: login URL is off-scope (e.g. an SSO provider). The browser will visit it for login only; no tests run there.")
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        sys.exit("Playwright missing: pip install playwright && python3 -m playwright install chromium")

    os.makedirs(a.out, exist_ok=True)
    state_path = os.path.join(a.out, f"state-{a.name}.json")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not a.manual)
        ctx = browser.new_context(user_agent=None)
        page = ctx.new_page()
        page.goto(a.login_url, wait_until="domcontentloaded")
        before = {c["name"]: c["value"] for c in ctx.cookies()}
        if a.manual:
            print(f"Log in as {a.name} in the opened browser window.")
            if a.success_selector:
                page.wait_for_selector(a.success_selector, timeout=a.timeout * 1000)
            else:
                input("Press Enter here once you are fully logged in... ")
        else:
            pw = os.environ.get(a.password_env or "", "")
            if not (a.username and pw):
                sys.exit("Automated login needs --username and --password-env (env var with the password).")
            page.fill(a.user_selector, a.username)
            if not page.is_visible(a.pass_selector):  # two-step login forms
                page.click(a.submit_selector)
                page.wait_for_selector(a.pass_selector, timeout=15000)
            page.fill(a.pass_selector, pw)
            page.click(a.submit_selector)
            page.wait_for_load_state("networkidle")
            if a.success_selector:
                page.wait_for_selector(a.success_selector, timeout=20000)
        ctx.storage_state(path=state_path)
        after_all = ctx.cookies()
        browser.close()

    after = {c["name"]: c["value"] for c in after_all}
    cookies = {c["name"]: c["value"] for c in after_all if scope.in_scope("https://" + c["domain"].lstrip("."))}
    unchanged = [n for n in before if n in after and before[n] == after[n] and any(k in n.lower() for k in ("sess", "sid", "auth"))]

    sess_path = os.path.join(a.out, "sessions.json")
    sessions = {}
    if os.path.exists(sess_path):
        with open(sess_path, encoding="utf-8") as f:
            sessions = json.load(f)
    sessions[a.name] = {"cookies": cookies, "headers": {}, "storage_state": state_path,
                        "identity_markers": a.marker, "captured_at": now_iso(),
                        "pre_login_cookie_names": sorted(before), "session_ids_not_rotated": unchanged}
    with open(sess_path, "w", encoding="utf-8") as f:
        json.dump(sessions, f, indent=2)
    os.chmod(sess_path, 0o600)
    print(f"Saved session '{a.name}' ({len(cookies)} in-scope cookies) -> {sess_path}")
    if unchanged:
        print(f"WARN: session cookie(s) {unchanged} kept the same value across login — check for session fixation (CWE-384).")
    if not cookies:
        print("WARN: no in-scope cookies captured. If the app uses bearer tokens in localStorage, copy the token into "
              "sessions.json as headers.Authorization, or check the storage_state file's 'origins' section.")


if __name__ == "__main__":
    main()
