# web-audit: repository audit and improvement plan

**Date:** 2026-11-15 · **Scope:** the whole repo (`skills/web-audit/**`, `README.md`) · **Code changes made:** none. This document is the only output.

**Method:** four independent review passes ran in parallel, then their results were merged and de-duplicated:

1. Token economics and output format
2. Safety and correctness of the scanning scripts
3. Authorization, sessions and the findings/report pipeline
4. An end-to-end run against `tests/vuln_app.py`, plus a coverage-gap analysis against OWASP Top 10 2021 and OWASP API Top 10 2023

Each finding is labelled **CONFIRMED** (reproduced with a test) or **SUSPECTED** (found by reading the code). The most severe finding, S1, was also reproduced a second time on its own.

---

## 1. Executive summary

The skill is well designed and its scripts are cheap on tokens. On the bundled test app it finds **15 of 16 planted vulnerabilities with no outright false positives**. The one miss is a JS-only page, which needs Playwright. The overall structure is sound: a scope gate, a shared client, a findings store, verification by a separate subagent, and a report.

However, it **does not yet keep its main safety promise**: "never leaves scope, read-only, hides secrets". Its access-control engine also has several ways to **miss real IDORs without any warning**. Neither problem shows up on the friendly test app, and there are no automated tests to catch them.

| Area | Verdict | Most important item |
|---|---|---|
| Scope safety | 🔴 Broken | A backslash in a URL makes the scope check and the HTTP library disagree on the host, so **session cookies and the Bearer token are sent to an off-scope host** (S1) |
| Read-only guarantee | 🔴 Weak | `/Logout`, `/log%6Fut`, `/orders/5/logout` and `/x/delete` all get past `excluded_paths`; the Playwright crawl has no scope or method guard at all |
| Secret handling | 🟠 Partial | Tokens in query strings go unredacted into `requests.jsonl`, findings, report and `endpoints.txt`; the validator's redaction check has many bypasses |
| AuthZ accuracy | 🟠 Unreliable | An expired session, a "Log in" link in the page header, or configured identity markers each make real IDORs disappear, with exit code 0 |
| Pipeline integrity | 🟠 | When scripts run at the same time, findings are lost to a write race (2 of 16 survived); a `ScopeError` or JWT parse error crashes a script before it saves |
| Docs vs CLI | 🟠 | 4 commands documented in SKILL.md fail if copied exactly |
| Token economics | 🟢 Mostly good | SKILL.md is about 2.8k tokens and stdout is about 500 tokens per run. The real costs are reading `recon.json`/`findings.json` in full, `curl` output, and one verification subagent per finding |
| Output format | 🟡 | The report is long (606 lines for 24 findings), has duplicate "Fix first" entries, and claims findings were re-tested when none were |
| Coverage | 🟡 | Large passive gaps (cache-control, CSP quality, source maps, tokens in URLs, open redirect) and no API endpoint authorization testing |
| Tests / CI | 🔴 None | No automated tests or CI; the self-test is a manual list of steps |

**Fix first:** S1, S2/S3 (scope and read-only), A1–A4 (silent authZ misses), R1 (redaction), P1/P2 (lost findings), D1–D4 (broken docs). After that, add the golden end-to-end test so these stay fixed.

---

## 2. Repository map

| Component | Lines | Role |
|---|---|---|
| `SKILL.md` | 189 | Agent instructions: arguments, rules of engagement, Phases 0–5 |
| `references/*.md` | 184 | Scope template, severity, manual unauthenticated and authenticated checklists |
| `schema/findings.schema.json` | 67 | Findings contract |
| `scripts/common.py` | 290 | `Scope`, rate-limited `Client`, `Findings` store, `redact()` |
| `scripts/recon.py` | 287 | Crawl, JS endpoint mining, optional Playwright pass |
| `scripts/passive_checks.py` | 324 | TLS, headers, cookies, CORS, errors, directory listing |
| `scripts/exposed_files.py` | 138 | About 50 sensitive paths, with a soft-404 baseline |
| `scripts/extra_checks.py` | 181 | GraphQL introspection, JWT decoding |
| `scripts/param_probe.py` | 143 | One reflection/SQL-error marker per GET parameter |
| `scripts/authz_replay.py` | 229 | Horizontal, anonymous and vertical replay |
| `scripts/capture_session.py`, `har_import.py` | 201 | Session capture, HAR → endpoints |
| `scripts/add_finding.py`, `validate_findings.py`, `report.py` | 283 | Findings pipeline |
| `tests/` | 168 | Deliberately vulnerable app, plus manual self-test instructions |

---

## 3. Safety findings (the tool's core promise)

| ID | Sev | Status | Location | Issue | Fix |
|---|---|---|---|---|---|
| **S1** | Critical | CONFIRMED ×2 | `common.py:84-86` | `in_scope()` reads the host with `urllib.parse.urlparse`, but `requests`/urllib3 read it differently. For `http://evil:8091\@target/x`, urlparse returns `target` while urllib3 connects to `evil`. In testing, a link or `Location:` header on the target made `recon --session` send the **session cookie and `Authorization: Bearer`** to the off-scope host. | Check scope on the **prepared** URL (`urllib3.util.parse_url(Request(...).prepare().url)`). Reject URLs containing `\`, userinfo (`@` in netloc) or control characters. Check again inside `Client.request` right before sending. |
| **S2** | High | CONFIRMED | `common.py:88-95` | `excluded_paths` is case-sensitive, compares the raw encoded path, and does no normalisation. `/Logout`, `//logout`, `/log%6Fut`, `/x/../logout` all get through; recon actually followed `/Logout`. `startswith(ex+"?")` can never match, so excluded paths with a query are never honoured. `"/"` is silently ignored. | Normalise first: unquote, collapse `//`, `posixpath.normpath`, strip `;params`, case-fold. Support query-aware patterns. Make `/` exclude everything. |
| **S3** | High | CONFIRMED | `common.py` + `authz_replay` + `har_import` | No deny-list for GETs that change state. Prefix matching misses `/orders/5/logout`, `/logout.php`, `/api/items/3/delete`. har_import put these in `endpoints.txt`, and authz_replay would request each one 3 times. | Add a default segment regex, overridable in scope, that applies to every script: `logout\|signout\|delete\|remove\|destroy\|cancel\|unsubscribe\|impersonate\|reset\|revoke\|disable\|approve`. |
| **S4** | Critical | SUSPECTED (Playwright not installed) | `recon.py:91-133` | In the `--browser` crawl, only the top-level `page.goto` is checked against scope. Subresources, XHR/fetch, iframes and redirects, **including POST/DELETE requests from the page's own JS**, go out with no scope check, rate limit, method guard or log. The browser also ignores `cookies`/`cookie_header`/`headers` session entries, so an "authenticated" crawl runs anonymously. | Add a `ctx.route("**/*")` handler that calls `scope.check(url, method)`, aborts anything that fails, aborts non-GET when `allow_state_changing` is false, waits on the shared limiter, and logs to `requests.jsonl`. Inject cookies and headers through `add_cookies` and `extra_http_headers`. |
| **S5** | High | CONFIRMED | `common.py:86` | Any port on an allowed host counts as in scope (`target:22` passes), which is the infrastructure scanning that Rule 3 forbids. `allowed_hosts: ["host:8443"]` never matches anything. | Match on `(scheme, host, effective port)`, with an optional `allowed_ports`. |
| **S6** | High | CONFIRMED | `common.py:148,165` | The rate limiter is per process, so scripts run in parallel peaked at **20 req/s against `max_rps=10`**. The raw-socket TLS probes skip the limiter and the log. | Use a token bucket shared across processes through a file lock in `<out>/.ratelimit`. Log TLS handshakes. |
| **S7** | Medium | SUSPECTED | `common.py:186-189` | The "stops if the site returns errors" circuit breaker (promised in the README) counts 5xx responses cumulatively for each Client, ignores timeouts and connection errors, resets for every script, and raises `SystemExit`, so **findings collected so far are never saved**. | Use a windowed or consecutive error count that includes `RequestException` and latency spikes, shared through the out dir. Raise a custom exception that `main()` catches so it can save and exit. |
| **S8** | High | CONFIRMED | `common.py:184`, `exposed_files.py:116` | Every response body is downloaded in full (`len(resp.content)`). A real `/actuator/heapdump` or `backup.zip` can be hundreds of MB, costing target bandwidth and holding sensitive data in memory. | Use `stream=True`, read at most about 256 KB, then close. |
| **S9** | Medium | CONFIRMED | `capture_session.py:75` | `state-<name>.json` (all cookies, including SSO IdP cookies, plus localStorage tokens) is written world-readable (0644). `sessions.json` is chmod'ed only after it is written. | Create both files with `os.open(…, 0o600)` and make the out dir `0700`. |
| **S10** | Medium | CONFIRMED | SKILL.md:76, `capture_session.py` | The documented `--password` flag doesn't exist, but argparse's abbreviation matching treats it as `--password-env`, which **puts the password in argv and shell history**. | `ArgumentParser(allow_abbrev=False)` in every script, and correct SKILL.md. |
| **S11** | Medium | — | SKILL.md (missing rule) | Nothing stops the agent from `cat`-ing `sessions.json`, `state-*.json` or the HAR, which pulls live credentials into the model's context. The manual checks also tell it to use plain `curl`, which skips the scope check, rate limit and log. | Add a rule: "Never read session/state/HAR files; validate with `scope_check --sessions`." Replace `curl` with `scripts/req.py` (§8.3). |

### Redaction

| ID | Sev | Status | Issue | Fix |
|---|---|---|---|---|
| **R1** | High | CONFIRMED | `requests.jsonl` and `describe_request()` record the full URL, so `/reset?token=SECRET…` was stored in plain text. `redact()` misses `Authorization: Bearer <opaque>`, `Cookie:`/`Set-Cookie:` pairs, `{"session_id":…}`, `?code=`, and custom headers such as `X-API-Key`. | Add a query-parameter redactor with a sensitive-name list (`token\|code\|key\|sig\|session\|auth\|password\|jwt`), applied to every URL that is logged or used as evidence. Add `Bearer\s+\S+`, cookie-pair and session-key patterns. Redact any header that carries session material. |
| **R2** | High | CONFIRMED | `har_import.py:26-28` writes query strings verbatim, so `access_token=…` and `X-Amz-Signature=…` ended up in `endpoints.txt` and `har-endpoints.json`. Neither file is gitignored. Replaying user_a's token as user_b then **creates false IDORs**. | Remove token-like parameters and gitignore both files. |
| **R3** | High | CONFIRMED | `validate_findings.py:10-17,93` only scans evidence fields. These passed validation: `curl -b session=…`, `-u admin:pw`, `Authorization: Token …`, a token in `url`, `refresh`/`access_token` JSON keys, short cookies, emails and SSNs. `add_finding.py:46-48` never redacts `reproduction`. | Scan **every** string field. Add the patterns above. Redact `reproduction` and `url` in `add_finding`. Warn on PII, since Rule 5 requires PII to be redacted. |
| **R4** | Medium | CONFIRMED | IDOR evidence includes owners' email addresses and street addresses in full. | Mask identity markers and emails in excerpts. |

---

## 4. Correctness findings

### 4.1 Access-control engine (`authz_replay.py`)

How it decides now: a response counts as "denied" if the status is 401/403/404, it is any redirect, or it matches `LOGIN_HINT` with a body under 15 KB. Otherwise it compares identity markers, falling back to `difflib` similarity on the first 8 KB.

| ID | Sev | Status | Issue | Effect | Fix |
|---|---|---|---|---|---|
| **A1** | High | CONFIRMED | No check that sessions are still alive (`:53-58,162,179`). | An expired user_b session gives **0 IDORs, exit 0, no warning**. A dead owner session or a network error is skipped silently. | Add a `check_url`+`check_marker` canary to each sessions.json entry, probed before, during (every N requests) and after the run, aborting on failure. Print the denial rate per identity ("user_b denied 100% → session dead?"). Record skipped and errored rows. |
| **A2** | High | CONFIRMED | `capture_session.py:62-75` doesn't check that login succeeded. | A wrong password saves an anonymous session as `user_a`, and every authz test after that is silently empty. | Require a success selector or URL change, and run the canary before saving. |
| **A3** | High | CONFIRMED | `:182 not om and …`: once markers are configured, the similarity fallback is switched off. | Markers that don't appear on the page (such as a display name) hide real IDORs. JSON APIs that return only IDs are affected. | Always fall back to similarity, and lower the confidence instead of dropping the result. |
| **A4** | High | CONFIRMED | `:26,58`: denial is detected by "login/sign in/forbidden" appearing anywhere in the first 3 KB. | A leaking page with a "Log in" link in the nav, which is typical for anonymous visitors, counts as denied. JSON keys like `unauthorized_count` trigger it too. | Check markers first. Look for denial words only in `<title>`, `<h1>`, password inputs or JSON error keys. Compare against a known-denied baseline for each identity. |
| **A5** | High | CONFIRMED | `ID_IN_PATH` (`:24`) only looks at the path, and only for digits or UUIDs. | `/api/orders?id=1001` was missed. Mongo ObjectIDs, ULIDs and slugs are never treated as IDs, while years like `/2024/` are. | Treat id-map-derived URLs as ID-bearing. Look for IDs in the query string. Add hex-24 and ULID. |
| **A6** | High | CONFIRMED | `candidate_urls` (`:61-78`) reads only recon `pages`. | `/api/me`, `/api/orders/`, `/api/admin/users` (mined from JS) are **never replayed**, so APIs, the main IDOR surface, get no coverage. This contradicts "replays every endpoint user_a can see". | Add `js_endpoints`, `browser_crawl.api_urls`, and GETs from the HAR. |
| **A7** | High | CONFIRMED | Vertical test (`:203-207`): `own_urls` includes every page the user visited, whatever its status. | An admin page the user **can** reach (the worst case) is left out of the test. JS-mined admin APIs and anonymous access to admin pages are not tested either. | Choose candidates where the user's status was not 200, plus user-reachable pages matching `/admin`-style patterns, plus `js_endpoints`. Apply S3. |
| **A8** | High | CONFIRMED | Unauthenticated-access check (`:169-173,90`). | SPA shells (every route returns `index.html`), `/help` and `/static/app.js` were reported as "authenticated content reachable anonymously", with high severity when the path contains an ID. | Detect the SPA shell by fetching a random nonexistent path. Skip non-HTML/JSON content types. Without markers, report at most low/tentative. |
| **A9** | Medium | CONFIRMED | Similarity uses only the first 8 KB, with no `<head>`/`<script>` stripping. | Pages with large inline heads always score 1.00. | Compare visible text, or for JSON compare keys plus value hashes. |
| **A10** | Low | CONFIRMED | The finding ID is `shash(url)`. | One bug becomes N findings (3 IDORs for `/orders/{id}`), which inflates the report. | Group by id-map template or by the normalised path. |

### 4.2 Scanning scripts

| ID | Sev | Status | Location | Issue | Fix |
|---|---|---|---|---|---|
| C1 | High | CONFIRMED | `passive_checks.py:40-54`, `recon.py:231` | URLs aren't filtered against `excluded()`, so `Client` raises `ScopeError`, the script crashes, and **no findings are saved**. | `Client.request` should log the URL as skipped and return `None`. |
| C2 | Medium | CONFIRMED | `passive_checks.py:243` | `ACAO: *` with `ACAC: true` is reported **high**, but browsers refuse that combination. Prefix/suffix origin tricks are missed. `auth_context` is hard-coded to `anonymous`. | Remove the `*` branch, add origin variants, take the context from `client.name`. |
| C3 | Medium | CONFIRMED | `passive_checks.py:175-182` | Cookie flags are matched as substrings: `a=b;Secure;HttpOnly` gives a false positive, and a value containing `httponly` gives a false negative. | Parse the attributes into a set. |
| C4 | Medium | CONFIRMED | `param_probe.py:40,44` | `parse_qs` drops blank values, so `/find?q=` is never probed. | `keep_blank_values=True`. |
| C5 | Medium | SUSPECTED | `param_probe.py:116,134` | `break` exits the client loop (the session client is skipped after an anonymous hit). An XSS hit skips the SQL check. Other parameters are dropped. No baseline, so a page that always contains "mysql" gives a false SQLi. Anonymous and session results share an ID and collide. Attribute-context reflection is missed. | Restructure the loops, fetch a baseline response, keep the other parameters, put the context in the ID. |
| C6 | Medium | CONFIRMED | `extra_checks.py:141` | A JWT with `iat` as a string (`TypeError`) or a header that isn't a dict crashes the script before it saves. Unknown session names are silently relabelled `user_a`. | Check types and use a try/except per token. |
| C7 | Medium | CONFIRMED (e2e) | `extra_checks.py` | `alg: none` is reported **critical/confirmed** even though the server never accepted a forged token. | Start it as tentative/medium. It is critical only after acceptance is shown, which requires scope permission. |
| C8 | Medium | SUSPECTED | `exposed_files.py` | Some signatures are the path itself (`/telescope`, `/horizon`, `/swagger-ui.html`), so soft-404 pages that echo the path match. `quick_ratio()` is too loose. Binary content can pass the printable check. | Use content-specific signatures and `ratio()`. |
| C9 | Low | SUSPECTED | `passive_checks.py` | HSTS `max-age=0` passes. `XFO: ALLOWALL` passes. `https_redirect` keeps the wrong port. `--session` runs only the CORS check, despite the docs. `STACK_TRACE` matches `node_modules/` in normal SPA pages. | Fix each one. |
| C10 | Low | SUSPECTED | `recon.py`, `scope_check.py:27` | Query-string variants are crawled without limit (crawl trap). The browser's `visited` set isn't normalised. The "logout" check in scope_check is case-sensitive. `browser_crawl.used` is `true` even when Playwright is missing. | Fix each one. |
| C11 | Medium | CONFIRMED | `common.py` (anonymous client) | The "anonymous" client keeps server-set cookies (PHPSESSID, guest_token), so anonymous evidence carries cookies, which can hide unauthenticated-access bugs. | Use a fresh cookie jar for each anonymous request, or a strict policy that drops session-looking cookies. |

### 4.3 Pipeline integrity

| ID | Sev | Status | Issue | Fix |
|---|---|---|---|---|
| **P1** | High | CONFIRMED | `Findings` (`common.py:243-270`) reads the file at the start and writes it in full at the end: last writer wins, and the write isn't atomic. **Only 2 of 16 findings survived** when 3 scripts ran in parallel. Phase 4 subagents running `add_finding.py` hit the same race. | Use `flock`, re-read, merge, then write a temp file and `os.replace`. Have verifier subagents **return** their verdicts and let the parent apply them. |
| **P2** | High | CONFIRMED | `validate_findings` exits 0 when every finding is still a candidate (it only warns), yet SKILL.md treats "validator must pass" as the gate. | Add a `--final` flag that fails on any `candidate`. Use it in Phase 5. |
| P3 | Medium | CONFIRMED | With jsonschema installed, a verified finding with `evidence.request: ""` passes, but the built-in checker fails it. The two engines disagree. | Add an explicit check for non-empty evidence. |
| P4 | Medium | CONFIRMED | `report.py` renders even when the validator fails (a raw Bearer token ended up in the report). A `\|` or newline in a field breaks tables. A missing field causes `KeyError`. | Run the redaction scan inside report.py and refuse to render on failure. Escape table cells. Use `.get()`. |
| P5 | Low | CONFIRMED | Re-running a script replaces candidate fields wholesale (verifier notes are lost). `add_finding --json` overwrites verified entries. A missing `id` causes a traceback. | Merge instead of replace. Require `--force` to overwrite a non-candidate. |
| P6 | Low | CONFIRMED | `validate_findings` on a missing file prints a raw traceback. | Print a clean error. |

---

## 5. Docs vs CLI: commands that fail

| ID | Location | Problem (all CONFIRMED) | Fix |
|---|---|---|---|
| **D1** | SKILL.md:83 | `recon.py … [--session user_a]` exits 1 because it also needs `--sessions <file>`. The error text is misleading. | Document `--sessions <out>/sessions.json --session user_a`. |
| **D2** | SKILL.md:74 | `capture_session.py` is shown without the required `--out` (argparse returns 2). | Add `--out <out>`. |
| **D3** | SKILL.md:74-75, `capture_session.py:61` | `--manual` without `--success-selector` calls `input()`. The agent's shell has no TTY, so it raises EOFError or hangs. | Always pass `--success-selector`, or have the script poll. |
| **D4** | SKILL.md:117 | `authz_replay.py --anon-only` (in Phase 2, labelled "auth mode only") always exits 1. Even when fixed, it can never flag anything without an owner response, and Phase 3 already does the anonymous replay. | Delete the line. |
| D5 | SKILL.md:85 | It says recon writes `recon.json`; session runs actually write `recon-<name>.json`. | Name both. |
| D6 | SKILL.md:51 vs `common.py:78` | Production `max_rps` is "≤ 2" in the docs and ≤ 5 in code. | Choose one value and enforce it. |
| D7 | SKILL.md:174 | It promises an "executive summary"; report.py has no such section. | Implement it (§8.6) or change the text. |
| D8 | `har_import.py:196` | Says authz_replay may replay non-GET requests; it only ever sends GET. | Correct the text. |
| D9 | SKILL.md | Undocumented flags: `recon --seed` (the README's "add hidden pages" depends on it), `scope_check --sessions`, `report --include-candidates`, `exposed_files --extra`, `add_finding --update/--set` (needed in Phase 4). | Add one line each (about 60 tokens). |
| D10 | stdout | Request counts are too low (passive says 30, actually sent 40; exposed says 52, actually sent 56). | Count from the Client, not the loop. |
| D11 | `tests/README.md` | Skips `validate_findings` and writes to `/tmp/selftest`. | Include the whole pipeline. |
| D12 | CLI | `scope_check` takes the scope as a positional argument while every other script uses `--scope`. `--session` means something different in each script. Unknown session names exit in recon but are silently ignored in param_probe and extra_checks. | Make conventions consistent in a shared `argparse` helper. |

---

## 6. Token economics and output format

### 6.1 Measurements (self-test, 145 requests, about 17 s)

| Item | Size | ≈ Tokens | Read by the model? |
|---|---|---|---|
| SKILL.md | 11.3 KB | 2,825 | Always |
| All script stdout | 1.9–2.5 KB | about 500 | Always |
| `findings.json` (24 findings) | 25.5 KB | 6.4k (about 240 per finding) | Yes, repeatedly |
| `report.md` draft | 21 KB, 606 lines | 5.3k | Yes |
| `requests.jsonl` | 23.5 KB | 5.9k | Should never be read |
| `recon.json` (self-test) | 2.6 KB | 650 | Yes |
| `recon.json` (estimate for a real site with 150 pages) | 100–200 KB | **25–60k per file**, × 2–3 in auth mode | Yes, and **silently truncated** past the Read tool's 2,000-line default |

**What costs the most**, in order:
1. One Phase 4 subagent per finding (about 170k tokens on the self-test)
2. Reading the full `recon*.json` files on a real site
3. Unbounded `curl -i` output in the manual checks (5–25k tokens per page)
4. Re-reading `findings.json` after each script

SKILL.md itself is already lean.

### 6.2 Proposals that don't reduce capability

| # | Proposal | Saves | Capability risk |
|---|---|---|---|
| T1 | **`recon-summary.md`** written by recon.py (about 2.5k tokens). Contents: counts, status histogram, tech, forms de-duplicated by (action, method, inputs) with page counts, URLs with parameters, JS endpoints grouped by templated prefix (`/api/orders/{n}`), sensitive-object paths, off-scope hosts as host:count, and **the anonymous-vs-session diff**, which SKILL.md currently asks the model to work out from two JSON files. SKILL.md changes to "read the summary; grep/jq the JSON for detail." | 20–100k per audit | Low: the full JSON still exists |
| T2 | De-duplicate forms inside `recon.json` (a header form repeated on 150 pages is about 49 KB). | 10–40k | None |
| T3 | **`findings_summary.py`** (or `validate_findings --summary`): one line per finding, `id\|sev\|status\|title\|url`, about 25 tokens instead of about 240. Scripts also print the IDs of new findings (capped at 15). | about 90% of findings reads; about 40k on a 60-finding audit | None |
| T4 | **`scripts/req.py`** in place of `curl`: `req.py --scope --out [--session] METHOD URL [-H] [--grep RE] [--max-body 1500]`. Prints status, headers and a redacted, truncated body, and is scoped, rate-limited and logged. | 5–25k per manual request | None; it also fixes S11 |
| T5 | **Batched Phase 4** (§8.5): what has to stay independent is the verifier versus the parent, not one finding versus another. Group into about 6 batches; one subagent per AUTHZ template; at most 3 critical/high per batch. | about 65% (170k → 60k on the self-test) | Low |
| T6 | **Fixed one-line verifier return:** `ID \| verified\|rejected \| sev \| ≤20-word reason \| redacted curl`. The parent applies it, which also fixes P1. | about 10k back into the parent | None |
| T7 | Move auth-only material (SKILL.md:69-76, 87-88, 136-150; about 430 tokens) into `references/auth-setup.md`, loaded only in auth/both mode. | about 390 per noauth run | Low |
| T8 | Shorten Setup (about 120), the browser/HAR text (about 200), the Phase 2 prose (about 125, keeping "never escalate the probe" word for word), the duplicated reference headings (about 100) and the key-field list (about 40). | about 585 | None |
| T9 | `validate_findings.py:162`: cut jsonschema error messages to 120 characters (it currently echoes whole 2,000+ character excerpts). | variable | None |
| T10 | Have report.py print the top-3 one-liners plus the counts of verified, rejected and still-pending findings, so the model can write the final message without reading the report. | about 5k | None |

**Net effect on SKILL.md:** about −700 tokens in noauth mode and about −330 in auth mode, after adding the new safety rules and the D-fixes (about +150). Adding a frontmatter clause, *"Not for source-code review"* (about 6 tokens), avoids triggering instead of `security-review`.

### 6.3 Output flagged as too long or in the wrong format

| # | Output | Problem | Proposal |
|---|---|---|---|
| F1 | `report.md` | 606 lines for 24 findings. Every low or info finding gets a full block of about 25 lines. | Show low and info findings as **one table** (title \| URL \| fix). Expected to cut 30–50%. |
| F2 | `report.md` | One root cause becomes several findings (3 IDORs for `/orders/{id}`, 3 JWT findings, and the stack trace and SQLi indicator from the same `?id='`). 24 could be about 15. | Group findings by template or root cause, listing affected URLs under one finding. |
| F3 | `report.md` "Fix first" | The same IDOR appears twice with no URL. | Include URL or ID, or merge grouped findings. |
| F4 | `report.md` Method | It always says "all candidates independently re-tested", even with 0 verified, with `--include-candidates`, or in unauth-only runs. "Appendix B" exists with no Appendix A. | Make the text depend on mode and status. Number appendices correctly. |
| F5 | `report.md` | No executive summary (D7) and no **coverage** section, so "No issues verified" can hide a run with zero coverage. | Add a 3–5 line summary and a coverage block: endpoints tested per identity, whether sessions were alive, scripts run and skipped. |
| F6 | Script stdout | Too short to act on: counts with no IDs, which forces a read of `findings.json`. | T3. |
| F7 | Final message to the user | Good overall. Missing: the unverified count, the production flag, and the session warning, which applies only in auth mode and doesn't mention `state-*.json` or the HAR. | Adjust SKILL.md:178-179. |

---

## 7. Coverage gaps

"Auto" means a script checks it, "Manual" means it is only in `references/checks-*.md`, and "No" means it isn't covered. Every proposed check is read-only and low-volume.

| Check | OWASP | Covered | Priority | Approach |
|---|---|---|---|---|
| Function-level authorization on JS-mined admin/API routes | API5 / A01 | Manual | **High** | A6/A7 |
| BOLA on JSON APIs (template derivation) | API1 | Partial | **High** | Derive id templates from `js_endpoints` and IDs in JSON |
| Open redirect | A01 | Manual | **High** | One marker in `next/url/redirect/return*` parameters; read `Location` |
| Cache-Control on authenticated pages | A04 / API8 | No | **High** | Passive over the session recon (no extra requests) |
| CSP quality (`unsafe-inline/eval`, wildcards, missing `object-src`/`base-uri`) | A05 | Presence only | **High** | Header parsing |
| Sensitive data in URLs (token/session/password/email in the query string) | A04 | No | **High** | Passive over recon and the request log; shares code with R1 |
| Exposed source maps | A05 | Manual | **High** | Look for `sourceMappingURL`, then one HEAD request per bundle |
| CSRF token on forms, plus SameSite | A01 | Manual | Medium | Passive form heuristic (recon already has forms) |
| Password autocomplete / login form posting over HTTP | A07 | Data collected, nothing flags it | Medium | One rule over recon forms |
| Session fixation / static session ID | A07 | Manual | Medium | Compare Set-Cookie between two anonymous clients. vuln_app's fixed PHPSESSID went undetected |
| SRI on third-party scripts | A08 | No | Medium | Passive |
| Mixed content | A02 | No | Medium | Passive |
| OPTIONS `Allow` / TRACE | A05 | Manual | Medium | OPTIONS automatically; TRACE only if scope allows |
| Verbose JSON API errors | A05 / API8 | HTML on `/` only | Medium | Extend the regex to JSON and param_probe responses |
| Excessive data exposure (`role`, `isAdmin`, `password_hash` in JSON) | API3 | Manual | Medium | Passive key scan of authenticated JSON |
| Host / X-Forwarded-Host reflection | A05 | Manual (reset flow only) | Medium | One GET with a changed header |
| Known-vulnerable versions | A06 | Banners only | Medium | Map banner and lockfile versions to known CVEs; offline list or manual |
| Cookie scope (`Domain` too broad, long session `Max-Age`) | A07 | No | Low–Med | Passive |
| SSRF-shaped parameters (`url`, `callback`, `webhook`) | A10 / API7 | No | Low–Med | **Flag for manual review only.** Never send internal targets |
| Permissions-Policy / COOP / CORP | A05 | No | Low | Passive |
| Rate-limit headers (`Retry-After`, `X-RateLimit-*`) | API4 | Manual | Low | Record passively |
| WebSocket endpoints | — | No | Low | List in recon; Origin testing stays manual |
| SSTI indicator | A03 | Manual | Low | Optional second marker in param_probe |
| security.txt missing | Hygiene | Present → info only | Low | Report when absent |
| Subdomain/vhost enumeration | — | Excluded by design | — | Correct as is |

Other misses in vuln_app that aren't in its README list: the login form posts over HTTP with no CSRF token; `/reports/latest` also leaks cross-user (it was only flagged as anonymous access); the `invoice-1001.pdf` link in the directory listing wasn't followed.

---

## 8. Proposed architecture

The changes stay within the current design (stdlib + `requests`, separate scripts, a JSON findings store). The idea is to push safety down into one place so that no script, and not the agent's ad-hoc requests either, can get around it.

```
                ┌──────────────────────── common/ (shared core) ────────────────────────┐
 scope.json ──► │ SafeURL      parse once from the PREPARED url; reject \ userinfo ctl;  │
                │              normalise path; (scheme,host,port) match; deny-list      │
 sessions.json─►│ Session      load + canary(check_url, check_marker) + liveness stats  │
                │ Client       SafeURL check per hop · shared file-lock rate limiter ·  │
                │              windowed circuit breaker (5xx+timeouts) · stream+cap ·   │
                │              redacted jsonl log · ScopeError→skip (never crash) ·     │
                │              optional response cache keyed (identity,url)             │
                │ Redactor     one implementation: URL params, headers, cookies, JWT,   │
                │              key=value, PII masking — used by log, evidence, report,  │
                │              har_import, validator                                     │
                │ FindingStore flock + atomic replace; merge-not-replace; group_key     │
                │ cli.py       shared argparse (allow_abbrev=False, --scope/--out/      │
                │              --sessions/--session semantics)                           │
                └────────────────────────────────────────────────────────────────────────┘
   recon.py ──► recon-<id>.json + recon-summary.md (incl. anon↔auth diff, id templates)
   browser crawl ─► ctx.route() → SafeURL + method guard + limiter + log
   checks (passive/exposed/extra/param) ─► FindingStore   (print: new IDs, capped)
   authz_replay ─► candidates = pages ∪ js_endpoints ∪ har GETs ∪ id-map templates
                   decision = markers → visible-text/JSON similarity → denial baseline
                   + liveness gate + SPA-shell baseline; group by template
   req.py ─────► the only sanctioned ad-hoc request path (manual checks, Phase 4)
   findings_summary.py ─► 1 line/finding for the model
   validate_findings --final ─► all fields redaction scan, no candidates
   report.py ─► refuses on validation failure; exec summary, coverage, grouped,
                low/info table; prints top-3 + counts
```

### 8.1 SafeURL (fixes S1, S2, S3, S5)
- Build the request once with `requests.Request(...).prepare()`, then parse the host with `urllib3.util.parse_url`, the same parser that opens the socket.
- Reject `\`, userinfo, control characters and non-http(s) schemes.
- Compare `(scheme, host.rstrip('.').lower() via IDNA, port or default)` against the allow-list.
- Normalise the path (unquote → `normpath` → collapse `//` → strip `;params` → case-fold), then match against `excluded_paths` (prefix, plus optional query-aware patterns) and the default deny regex for state-changing GETs.
- The Client calls this on **every** hop, and the Playwright route handler calls the same function.

### 8.2 Client hardening (S6, S7, S8, C1, C11, R1)
- Rate limiting with a file-lock token bucket at `<out>/.ratelimit`, shared by every process and the browser.
- A circuit breaker using a sliding window (for example ≥5 5xx/timeouts in 30 s, or 3 in a row) persisted in the out dir. It raises `TargetDistress`, which `main()` catches, saves findings, and exits non-zero with a clear message.
- `stream=True`, read at most 256 KB, record the true `Content-Length`.
- `ScopeError` is logged as `skipped` and the request returns `None`.
- Anonymous identity uses a strict cookie policy.
- Log lines pass through the Redactor.
- An optional on-disk cache keyed by `(identity, url)` removes the repeat fetches seen in testing (`/` fetched 7×).

### 8.3 `req.py` (S11, T4)
The only way manual checks and verifiers send requests. It goes through the same Client (scope, limiter, log), redacts output, and caps the body. SKILL.md swaps every `curl` mention for it and adds a rule never to read `sessions.json`, `state-*.json` or HAR files.

### 8.4 AuthZ engine (A1–A10)
1. **Liveness gate:** check each identity's canary before, during and after the run, and abort on failure. Print denial rates per identity. Write `coverage` to `authz-results.json`.
2. **Candidates:** recon pages ∪ `js_endpoints` ∪ browser API URLs ∪ HAR GETs ∪ expanded id-map templates, minus the deny-list.
3. **Decision order:** owner markers in the response → visible-text/JSON-structure similarity (head, script and style stripped) → denial check against a **per-identity denied baseline** (taken from a known-protected URL) instead of keyword matching.
4. **Baselines:** fetch a random nonexistent path to detect the SPA shell; compare against the site-root anonymous response.
5. **Vertical:** candidates where the user's status ≠ 200, plus admin-pattern paths and admin `js_endpoints`; also replay admin pages anonymously.
6. **IDs:** detect them in the path and query; numeric, UUID, hex-24 and ULID; years excluded.
7. **Grouping:** `group_key = method + templated path`. One finding lists N example URLs.

### 8.5 Phase 4 verification protocol (T5, T6, P1)
- **Brief** (about 180 tokens, with no parent reasoning): scope path; the sessions path only if `auth_context ≠ anonymous`; the finding JSON (or group); `req.py` usage; the false-positive list and severity table (which currently go to the wrong agent); and the rules of engagement in brief.
- **Batches:**
  - A: config/headers/cookies/TLS/version
  - B: exposed files and directory listing
  - C: JWT and GraphQL
  - D: one per AUTHZ template
  - E: XSS and SQLi indicators, one each
  - At most 3 critical/high findings per batch.
- **Return:** exactly one line per finding. The **parent** applies the results with `add_finding --update`, so verifiers never write `findings.json` in parallel.

### 8.6 Report v2 (F1–F7, P4, D7)

The report checks redaction and validity first and won't render if they fail. Its layout:

1. Header, with the production banner when it applies.
2. Executive summary in 3–5 lines.
3. Coverage: identities and whether they were alive, endpoints tested, scripts run.
4. Severity table.
5. "Fix first" list, with URLs.
6. Critical, high and medium findings in full, grouped by root cause.
7. Low and info findings as one table.
8. Appendix A: rejected findings, collapsed by group, with escaped cells.
9. Appendix B: methodology, worded according to the mode.

After writing the report, report.py prints the top-3 findings and the counts, ready for the final message.

### 8.7 SKILL.md v2 (T7, T8, D1–D12, S11)
- Fix every command; generate the command blocks from a single source if possible (§9.2).
- Move auth setup and Phase 3 detail to `references/auth-setup.md`.
- New rules: use `req.py` instead of `curl`; never read credential files; Phase 5 uses `validate_findings --final`.
- Phase 1 tells the model to read `recon-summary.md`; Phase 2/3 use `findings_summary.py` after each script.
- Final message: counts (verified, rejected, unverified), production flag, top 3, report path, and, in auth mode, revoke the sessions and delete `sessions.json`, `state-*.json` and the HAR.

---

## 9. Testing and CI (currently none)

### 9.1 Test suite to add (pytest; tests run against `vuln_app.py` on a free port)

| # | Test | Would have caught |
|---|---|---|
| 1 | **Golden end-to-end:** run the full pipeline, assert the expected finding IDs and categories. Also run a **clean** variant of the app (correct headers, cookies, authZ) and assert zero findings | FP/FN regressions, C2, A8 |
| 2 | **Docs vs CLI:** parse every `python3 scripts/…` line in SKILL.md and tests/README.md, check each flag against argparse | D1–D4, D9, S10 |
| 3 | **Scope:** backslash/userinfo/port/IDN/trailing-dot URLs, off-scope redirect, case/encoding/`..` exclusions, deny-list, POST blocked, `max_rps` timing across 3 processes | S1–S3, S5, S6 |
| 4 | **Redaction canaries:** plant tokens in the query string, header, cookie, JWT, `.env` and an email; grep **every** artifact (`requests.jsonl`, `findings.json`, `report.md`, `endpoints.txt`) for the raw values | R1–R4 |
| 5 | **AuthZ edge cases:** expired session → abort; "Log in" nav on a leaking page → flagged; markers not shown → still flagged; query-string IDs; SPA shell → not flagged; shared object → tentative; JS-mined API replayed | A1–A8 |
| 6 | **Soft-404 apps:** catch-all 200, 302-to-home, 403-everywhere → zero exposed-file hits | C8 |
| 7 | **Concurrency:** 3 scripts in parallel → every finding kept | P1 |
| 8 | **Validator fixtures:** verified finding without reproduction fails; secret anywhere fails; candidate under `--final` fails; missing file gives a clean error | P2, P3, P6, R3 |
| 9 | **Robustness:** malformed JWTs, ScopeError in the middle of a script, 5xx storm → findings saved and clean exit | C1, C6, S7 |
| 10 | **Fallbacks:** without bs4, jsonschema or Playwright → graceful degradation, accurate flags | C10 |

### 9.2 CI
- A GitHub Actions workflow running the matrix on Python 3.9 and 3.12; Playwright only in a separate optional job (which exercises S4's route guard).
- Add a lint step (ruff) and a check that SKILL.md command blocks match `--help` output.

---

## 10. Roadmap

| Phase | Items | Effort | Outcome |
|---|---|---|---|
| **P0: safety and trust** (do first) | S1, S2, S3, S4, S5, R1, R2, S9, S10, S11 (req.py + rule), C1, P1 | about 2–3 days | Keeps the "scope / read-only / secrets" promise |
| **P0: silent false negatives** | A1, A2, A3, A4, P2 | about 1–2 days | No more empty reports with exit 0 |
| **P0: docs** | D1–D8 | about 2 h | Every documented command runs as written |
| **P1: tests and CI** | §9 tests 1–5 and 7–8, workflow | about 2 days | Keeps P0 fixed |
| **P1: accuracy** | A5–A10, C2–C7, C11, S6, S7, S8, R3, R4, P3–P5 | about 3 days | Fewer FPs and FNs; API authZ coverage |
| **P1: tokens and format** | T1, T3, T5, T6, F1–F5, T10 | about 2 days | About 65% less verification cost, 20–100k fewer recon tokens, shorter report |
| **P2: coverage** | §7 High items, then Medium | about 3–4 days | Passive and API gaps closed |
| **P2: polish** | T2, T7–T9, D9–D12, C8–C10, response cache, CLI consistency | about 2 days | Leaner SKILL.md, fewer requests |

---

## Appendix: end-to-end run on the self-test (as documented, `max_rps=10`)

| Step | Exit | Requests | Note |
|---|---|---|---|
| scope_check | 0 | 0 | |
| recon `--session user_a` (as in SKILL.md) | **1** | 0 | D1 |
| recon (anonymous) / (with `--sessions`) | 0 / 0 | 10 / 13 | writes `recon-user_a.json` (D5) |
| passive_checks | 0 | 40 | stdout says 30 (D10) |
| exposed_files | 0 | 56 | stdout says 52; no FPs against a catch-all 200 |
| extra_checks / param_probe | 0 / 0 | 2 / 2 | |
| authz_replay `--anon-only` (as in SKILL.md) | **1** | 0 | D4 |
| authz_replay (full, with id-map) | 0 | 14 | 3 IDOR findings for 1 bug (A10) |
| validate_findings | **0** | 0 | passes with 0 verified findings (P2) |
| report (default / `--include-candidates`) | 0 / 0 | 0 | "0 findings" with a "re-tested" claim (F4) / 606 lines (F1) |

Detected: `.env`, `.git`, IDOR, unauthenticated report, CORS with credentials, stack trace, directory listing, cookie flags, version headers, missing headers, plain HTTP, GraphQL introspection, three JWT issues, XSS indicator, SQLi indicator. Missed: the `/js-only` page (needs Playwright).
