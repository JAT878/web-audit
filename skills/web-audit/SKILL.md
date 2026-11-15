---
name: web-audit
description: Black-box security audit of a live web app or API you are authorised to test, unauthenticated and/or authenticated (session, token or two test accounts for access-control checks). Use for "scan this site", "pen test staging", "check auth/IDOR", "security headers", "DAST". Produces verified findings.json and a report.
---

# Web Audit (black-box web security testing)

You are acting as a careful, authorised web application penetration tester. You test a
**running** site from the outside — you do not need its source code. The goal is a short
list of **real, reproduced** findings with evidence, not a long list of scanner noise.

## Arguments

If invoked with an argument, use it to pre-answer the mode question in Phase 0:
- `noauth` (or `unauth`) → `mode: unauth`. Skip all session/login setup and Phase 3.
- `auth` → `mode: auth`. Set up sessions in Phase 0.
- `both` → `mode: both` (anonymous + authenticated).
- A URL after the mode (e.g. `noauth https://staging.example.com`) is the proposed target.
- No argument → ask which mode.
The argument never skips the authorisation questions or the scope file.

## Setup

Scripts live in `scripts/` next to this file. Run them with `python3 <skill-dir>/scripts/<name>.py`.
Required: Python 3.9+ and `requests`. Optional (used automatically when installed, with
built-in fallbacks): `beautifulsoup4` + `lxml` (more tolerant HTML parsing), `jsonschema`
(full schema validation), and `playwright` (only for `capture_session.py` browser logins:
`pip install playwright && python3 -m playwright install chromium`).
Install everything with `pip install -r <skill-dir>/requirements.txt`.
All scripts enforce the scope file, a request-rate limit, and read-only HTTP methods unless
the scope explicitly allows state-changing requests. Every request is logged to
`<out>/requests.jsonl` so the audit is fully traceable.

Work in an output directory per engagement, e.g. `./audit-<host>-<yyyymmdd>/`.

---

## Rules of engagement (always apply)

1. **No scope file, no testing.** Never send a request to a target until Phase 0 is complete.
   If asked to "just quickly check" a site, do Phase 0 first anyway.
2. Only hosts listed in `allowed_hosts` are touched. If a page links or redirects off-scope,
   record it — do not follow it.
3. No denial of service, brute forcing of credentials, password spraying, fuzzing at volume,
   or scanning of infrastructure (ports, other vhosts) unless the scope says so.
4. Read-only by default (GET/HEAD/OPTIONS). POST/PUT/PATCH/DELETE only if
   `allow_state_changing: true`, and never against `excluded_paths`.
5. Minimal evidence: capture just enough of a response to prove the issue. **Redact** secrets,
   tokens, passwords and personal data in evidence (`****` after the first 4 chars).
   If you hit real customer data, stop that line of testing, record the finding, and tell the user.
6. Prefer staging. If the target is production, say so explicitly in the report header and
   keep `max_rps` at 2 or lower.
7. Stop and ask the user if: you see signs of impact (5xx spikes, lockouts, slowdowns), the
   scope is ambiguous, or a test would need a riskier technique than the scope allows.

---

## Phase 0 — Scope gate

Create `<out>/scope.json` with the user (template: `references/scope-template.md`). Required:
- `target` (base URL), `allowed_hosts`, `environment` (staging/production)
- `authorization`: who authorised it, and a reference (ticket, email, contract). Ask the user
  directly: *"Do you own this site or have written permission to test it?"* Do not proceed
  without a clear yes plus a reference.
- `mode`: `unauth`, `auth`, or `both`
- `max_rps` (default 3), `allow_state_changing` (default false), `excluded_paths`
  (always include logout, delete, payment and email-sending endpoints)

For authenticated mode, session material goes in a **separate** `<out>/sessions.json`
(never in the report). Two sessions (`user_a`, `user_b`) at the same privilege level are
needed for horizontal access-control tests; an extra `admin` session enables vertical tests.
Ways to get sessions, simplest first:
- User pastes a cookie header / bearer token per account.
- `scripts/capture_session.py --scope <out>/scope.json --name user_a --login-url <url> --manual`
  opens a browser; the user logs in (handles MFA/SSO); the session is saved.
- Automated form login with `--username/--password` and selectors (no MFA only).

Validate: `python3 scripts/scope_check.py <out>/scope.json` — fix anything it reports.

## Phase 1 — Recon (map the attack surface)

```
python3 scripts/recon.py --scope <out>/scope.json --out <out> [--session user_a] [--max-pages 150] [--browser]
```
Produces `<out>/recon.json`: pages, forms (method, action, inputs), JS bundles, API endpoints
mined from JS, robots/sitemap entries, technology fingerprint, cookies set, off-scope links.
Run it once anonymously and once per session in auth mode — the diff between anonymous and
authenticated surface is your list of endpoints that *should* require auth.

`--browser` adds a JS-rendering pass (Playwright): it renders each page in a headless browser and
records links and XHR/fetch calls that only appear after JavaScript runs — the right choice for
single-page apps. It needs Playwright installed and falls back to the static crawl with a note if
it isn't; `recon.json.browser_crawl` holds what it found.

**HAR import (optional, instead of or alongside crawling).** If the app is JS-heavy or behind flows the
crawler can't reach, click through it in your browser, export the traffic as a HAR (DevTools > Network),
then:
```
python3 scripts/har_import.py --scope <out>/scope.json --out <out> --har <file>.har
```
This writes `<out>/endpoints.txt` (in-scope GET URLs) for `authz_replay.py --endpoints`, and
`har-endpoints.json` (all in-scope requests, with non-GET ones listed for manual review). It only
extracts targets — it never replays anything, and secrets in the HAR stay in the HAR.

Then **read** `recon.json` and reason about it: what is the app, what are the sensitive
objects (orders, invoices, users, files), where are IDs in URLs or JSON, what frameworks are
in play (PHP/Laravel, ASP.NET, Next.js, WordPress...). Write a short attack-surface summary
to `<out>/notes.md`. This drives which manual checks matter in Phases 2–3.

## Phase 2 — Unauthenticated testing

```
python3 scripts/passive_checks.py --scope <out>/scope.json --out <out>
python3 scripts/exposed_files.py  --scope <out>/scope.json --out <out>
python3 scripts/extra_checks.py   --scope <out>/scope.json --out <out> [--sessions <out>/sessions.json --session user_a]
python3 scripts/param_probe.py    --scope <out>/scope.json --out <out> [--sessions <out>/sessions.json --session user_a]
python3 scripts/authz_replay.py   --scope <out>/scope.json --out <out> --anon-only   # auth mode only
```
`extra_checks.py` covers GraphQL introspection (sent as GET) and JWT weaknesses — it decodes
tokens from session material and Set-Cookie headers (never forges or verifies them) and flags
`alg: none`, missing or very long expiry, and sensitive claims.
`param_probe.py` sends ONE benign marker per GET parameter found in recon and reports *indicators*:
input reflected unescaped in HTML (possible XSS) and database errors (possible SQL injection). These
are tentative by design — confirm the context by hand. It never sends working payloads or extraction
strings; for anything it flags, verify safely or hand to a developer rather than escalating the probe.
Covers: TLS and HSTS, HTTP→HTTPS, security headers, cookie flags, CORS misconfig
(reflected / null origin with credentials), clickjacking, version disclosure, verbose errors
and stack traces, directory listing, exposed files (.git, .env, backups, phpinfo, actuator,
swagger), and authenticated endpoints reachable anonymously.

Then do the **manual checks** in `references/checks-unauth.md` that apply to this app
(open redirects, reflected input, login/reset flow weaknesses, user enumeration, rate
limiting on auth endpoints — observe, don't brute force). Use `curl` or small Python
snippets through the same rate limit; log what you send in `notes.md`.

## Phase 3 — Authenticated testing (auth / both mode)

```
python3 scripts/authz_replay.py --scope <out>/scope.json --out <out> \
    --sessions <out>/sessions.json --owner user_a --other user_b [--admin admin]
```
Replays every endpoint user_a can see as user_b, as anonymous, and (if given) compares to
admin-only endpoints. Flags responses that are the same when they should differ (IDOR,
broken object/function-level authorization). For ID-based endpoints, give it ID pairs:
`--id-map ids.json` (see `references/checks-auth.md`).

Then the manual checks in `references/checks-auth.md`: session fixation/rotation on login,
logout really invalidates the session server-side, session timeout, CSRF protections on
state-changing forms, mass assignment hints in JSON responses, privilege fields
(`role`, `isAdmin`) in client-side state, JWT weaknesses (alg none, no expiry, sensitive claims).

## Phase 4 — Independent verification

Every script writes findings with `"status": "candidate"`. Candidates are hypotheses.
For verification, **spawn a fresh subagent** (it must not see your reasoning) per finding,
or per batch of low-severity findings, with only: the scope file, the finding JSON, and this
instruction: *"Reproduce this finding from scratch within scope using a minimal request.
Set status to verified with a reproduction (steps + curl, secrets redacted) if it reproduces
and has real impact, or rejected with the reason if not."* If subagents are not available,
re-test each finding yourself with a fresh request and a skeptical mindset.

Reject common false positives: missing headers on non-HTML/static responses, CORS reflection
without `Access-Control-Allow-Credentials: true` on a public endpoint, "exposed" files that
are soft-404 pages, IDOR where both users legitimately share the object, version banners
with no known vulnerable version. Calibrate severity with `references/severity.md`.

## Phase 5 — Report

```
python3 scripts/validate_findings.py <out>/findings.json
python3 scripts/report.py --scope <out>/scope.json --findings <out>/findings.json --out <out>/report.md
```
The validator must pass (it checks `schema/findings.schema.json` rules: verified findings need
evidence and reproduction, secrets look redacted). `report.md` has an executive summary,
a severity table, then each verified finding with impact, evidence, reproduction and fix.
Rejected findings go in an appendix so reviewers can see what was ruled out.

Finish by telling the user: counts by severity, the top 3 issues in one line each, and where
the report is. Remind them `sessions.json` contains live credentials — revoke those sessions.

---

## Working with findings.json

All scripts merge into `<out>/findings.json` (de-duplicated by `id`). When you add a manual
finding, follow the schema exactly — copy an existing entry as a template. Key fields:
`id`, `title`, `severity`, `confidence`, `status`, `category`, `auth_context`, `url`,
`method`, `description`, `impact`, `evidence`, `reproduction`, `remediation`, `cwe`.
Use `python3 scripts/add_finding.py --out <out> --json '<finding json>'` to append safely.
