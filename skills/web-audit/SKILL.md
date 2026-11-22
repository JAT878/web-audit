---
name: web-audit
description: Black-box security audit of a live web app or API you are authorised to test, unauthenticated and/or authenticated (session, token or two test accounts for access-control checks). Use for "scan this site", "pen test staging", "check auth/IDOR", "security headers", "DAST". Produces verified findings.json, correlated attack chains.json and a chain-first report.
---

# Web Audit — AI web application pentesting framework

You run a careful, authorised black-box penetration test of a **running** site (no source
needed) and produce a short list of **real, reproduced** findings plus the **attack chains**
that connect them — not scanner noise. The intelligence is the reasoning on top of the checks,
above all **attack-chain correlation**: individually-medium findings that chain into account
takeover are the headline.

A **five-component methodology** (WHAT is assessed) delivered by a **multi-agent architecture**
(WHO does it), mapped to execution phases:

| Component | Phase(s) | Owning agent(s) |
|---|---|---|
| 0 Engagement & authorization | Phase 0 | Orchestrator |
| 1 Recon & attack-surface | Phase 1 | Recon |
| 2 AuthN / AuthZ / session | Phases 2–3 | Auth |
| 3 API & business-logic | Phases 2–3 | API (+ optional Logic) |
| 4 Validation & attack-chain correlation | Phase 4 + **4.5** | Validation + Risk + Orchestrator |
| 5 Professional chain-first report | Phase 5 | Reporting + Review |

**Read-only by default, authorization-gated, prove-don't-exploit** is the non-negotiable core.
This build (A+B) adds correlation and orchestration but **no new active behaviour**: chain
EXECUTION is a later phase, so chains stay `confidence: tentative` unless manually confirmed.

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
built-in fallbacks): `beautifulsoup4` + `lxml` (tolerant HTML parsing), `jsonschema` (full
schema validation), and `playwright` (only for `capture_session.py` browser logins:
`pip install playwright && python3 -m playwright install chromium`).
Install everything with `pip install -r <skill-dir>/requirements.txt`.
Every script enforces the scope file, a request-rate limit, read-only HTTP methods (unless the
scope explicitly allows state-changing requests), and secret redaction. Every request is logged
to `<out>/requests.jsonl` so the audit is fully traceable. Work in an output directory per
engagement, e.g. `./audit-<host>-<yyyymmdd>/`.

---

## Orchestration (multi-agent)

**The running session is the ORCHESTRATOR.** It plans and scopes the engagement, enforces
permissions, allocates tasks, runs risk **control** (stop/go circuit breaker), performs
correlation synthesis, and is the **sole writer** of `findings.json` and `chains.json` (this
kills the write race by construction). It fans out to specialist **subagents**, each given only
a scoped brief, who return **compact structured results** (one line per finding/chain + evidence
refs — never transcripts) that the orchestrator applies.

Briefs to paste when spawning live in `references/agents/<name>.md`:

| Agent | Spawn when | Returns |
|---|---|---|
| **Recon** | first — others depend on it | surface map, auth-diff, capability-tagged endpoints |
| **Auth** | after recon (auth/both mode) | capability-tagged candidate findings |
| **API** | after recon, when APIs/specs exist | candidate findings |
| **Logic** *(optional)* | only when recon shows real workflows (cart/checkout/state machine) | candidate findings |
| **Validation** | per finding/chain, **siloed, in parallel** | `verified\|rejected` + one redacted repro line |
| **Risk** | after validation | severity + combined chain impact + cheapest cut |
| **Reporting** | after scoring | `report.md` |
| **Review** | after the draft | `pass` or a fix-list |

Sequence: Recon → parallel {Auth, API, (Logic)} → **correlate (Phase 4.5)** → parallel siloed
Validation → Risk → Reporting → Review (loop back on fail). Risk *control* runs throughout:
on `TargetDistress`, 5xx spikes, latency or scope edges, pause/stop/re-plan.

**Graceful degradation:** if no subagent capability is available, the orchestrator **runs every
role itself, serially, in one context** — same methodology, same report. The multi-agent layer
is an accelerator and a context-hygiene mechanism, never a requirement.

---

## Rules of engagement (always apply)

1. **No scope file, no testing.** Never send a request to a target until Phase 0 is complete,
   even for a "quick check".
2. Only hosts in `allowed_hosts` are touched. Record off-scope links/redirects; never follow them.
3. No denial of service, credential brute force, password spraying, volume fuzzing, or infra
   scanning unless the scope says so.
4. Read-only by default (GET/HEAD/OPTIONS). POST/PUT/PATCH/DELETE only if
   `allow_state_changing: true`, never against `excluded_paths`.
5. Minimal, **redacted** evidence (`****` after the first 4 chars). On real customer data, stop
   that line of testing, record the finding, and tell the user.
6. Prefer staging. If the target is production, say so in the report header and keep `max_rps` at
   **2 or lower** (the scope validator rejects `max_rps` > 2 against production).
7. Stop and ask if you see impact (5xx spikes, lockouts, slowdowns), the scope is ambiguous, or a
   test needs a riskier technique than the scope allows.
8. **Never `cat`/Read `sessions.json`, `state-*.json`, or HAR files** — they hold live
   credentials. Validate session material only with `scope_check.py --sessions` (below). Keep
   session material out of the report.
9. **RoE flags** (scope, default safe): `allow_state_changing` (false), `allow_token_forge`
   (false), `allow_active_exploit` (false), `max_chain_hops` (6). This A+B build never turns on
   active behaviour; those flags gate later phases only.

---

## Phase 0 — Scope gate (Component 0, Orchestrator)

Create `<out>/scope.json` with the user (template: `references/scope-template.md`). Required:
- `target` (base URL), `allowed_hosts`, `environment` (staging/production/development/test)
- `authorization`: `authorized_by` + `reference` (ticket/email/contract). Ask directly: *"Do you
  own this site or have written permission to test it?"* Do not proceed without a clear yes + reference.
- `mode`: `unauth`, `auth`, or `both`
- `max_rps` (default 3; ≤2 for production), `allow_state_changing` (default false),
  `excluded_paths` (always include logout, delete, payment and email-sending endpoints)

For authenticated mode, session material goes in a **separate** `<out>/sessions.json` (never in
the report). Two sessions (`user_a`, `user_b`) at the same privilege enable horizontal
access-control tests; an extra `admin` session enables vertical tests. Ways to get sessions,
simplest first:
- User pastes a cookie header / bearer token per account.
- Browser login (handles MFA/SSO), **`--out` and `--success-selector` are required with `--manual`**:
  ```
  python3 scripts/capture_session.py --scope <out>/scope.json --out <out> --name user_a \
      --login-url <url> --manual --success-selector "<element only present when logged in>"
  ```
- Automated form login with `--username`/`--password-env` and selectors (no MFA only).

Validate scope and session material together:
```
python3 scripts/scope_check.py <out>/scope.json [--sessions <out>/sessions.json]
```
`--sessions` checks the session file's shape without printing its secrets. Fix anything it reports.

## Phase 1 — Recon (Component 1, Recon agent)

```
python3 scripts/recon.py --scope <out>/scope.json --out <out> [--max-pages 150] [--seed <url>] [--browser]
# per session (auth/both): REQUIRES --sessions AND --session; writes recon-<name>.json
python3 scripts/recon.py --scope <out>/scope.json --out <out> --sessions <out>/sessions.json --session user_a
```
The anonymous run writes `<out>/recon.json`; **a session run writes `<out>/recon-<name>.json`**
(e.g. `recon-user_a.json`), so the anonymous map is preserved for the **auth-diff** —
endpoints that appear only when logged in are your authorization-test target list.
Flags: `--seed <url>` adds extra start URLs (repeatable); `--max-pages`/`--max-js` cap the crawl;
`--browser` adds a Playwright JS-render pass for SPAs (records post-JS links + XHR/fetch; falls
back to the static crawl with a note; results under `recon.json.browser_crawl`).
Recon also writes a token-cheap `<out>/recon-summary.md` — read that, not the full JSON.

**HAR import (optional).** For JS-heavy or flow-gated apps, click through in your browser, export
the traffic (DevTools → Network → HAR), then:
```
python3 scripts/har_import.py --scope <out>/scope.json --out <out> --har <file>.har
```
Writes `<out>/endpoints.txt` (in-scope GET URLs for `authz_replay.py --endpoints`) and
`har-endpoints.json`. It only extracts targets — never replays; secrets in the HAR stay there.
Ingest external scanners (ZAP/nuclei/Burp) with `import_scan.py` if present — breadth borrowed.

Then **reason** about the surface: what is the app, the sensitive objects (orders, invoices,
users, files), where IDs live in URLs/JSON, which frameworks. Note `id_shape` (sequential IDs are
a free `knowledge:*` grant for chains). Write a short attack-surface summary to `<out>/notes.md`.

## Phase 2 — Unauthenticated testing (Components 1–3)

```
python3 scripts/passive_checks.py --scope <out>/scope.json --out <out> [--session user_a] [--skip-tls]
python3 scripts/exposed_files.py  --scope <out>/scope.json --out <out> [--extra <paths.txt>]
python3 scripts/extra_checks.py   --scope <out>/scope.json --out <out> [--sessions <out>/sessions.json --session user_a]
python3 scripts/param_probe.py    --scope <out>/scope.json --out <out> [--sessions <out>/sessions.json --session user_a]
python3 scripts/auth_probe.py     --scope <out>/scope.json --out <out> [--sessions <out>/sessions.json --session user_a]
python3 scripts/session_checks.py --scope <out>/scope.json --out <out> [--sessions <out>/sessions.json --session user_a]
python3 scripts/auth_flows.py     --scope <out>/scope.json --out <out> [--sessions <out>/sessions.json --session user_a]
```
`auth_flows.py`: open redirects (one benign off-site marker, `allow_redirects=False`) and
OAuth/OIDC `redirect_uri` / missing-`state` weaknesses (observe only — never completes a flow).
`auth_probe.py`: user enumeration (known vs unknown account) and reset-token-in-response / weak
reset flows (observe only — never POSTs, never consumes a reset token). `session_checks.py`:
session fixation / no rotation (same session id for every visitor), cookie scope/lifetime; notes
logout endpoints for manual testing (never hits them).
`passive_checks.py`: TLS/HSTS, HTTP→HTTPS, security headers, cookie flags, CORS misconfig
(reflected/null origin with credentials), clickjacking, version disclosure, verbose errors/stack
traces, directory listing, and authenticated endpoints reachable anonymously.
`exposed_files.py`: `.git`, `.env`, backups, phpinfo, actuator, swagger (soft-404 aware).
`extra_checks.py`: GraphQL introspection (sent as GET) and JWT weaknesses — decodes tokens from
session material and Set-Cookie (**never forges or verifies**) and flags `alg: none`, missing/
overlong expiry, sensitive claims.
`param_probe.py`: sends ONE benign marker per GET parameter and reports *indicators* — input
reflected unescaped (possible XSS) and database errors (possible SQLi). Tentative by design:
confirm context by hand; it never sends working payloads.

Then do the **manual checks** in `references/checks-unauth.md` that apply (open redirects,
reflected input, login/reset-flow weaknesses, user enumeration, auth-endpoint rate limiting —
observe, don't brute force). Use `curl` / small Python through the same rate limit; log in `notes.md`.

## Phase 3 — Authenticated testing (auth / both mode; Components 2–3)

```
python3 scripts/authz_replay.py --scope <out>/scope.json --out <out> \
    --sessions <out>/sessions.json --owner user_a --other user_b [--admin admin] \
    [--id-map <out>/ids.json] [--endpoints <out>/endpoints.txt] [--threshold 0.92]
python3 scripts/api_checks.py --scope <out>/scope.json --out <out> \
    --sessions <out>/sessions.json --session user_a --other user_b [--admin admin] [--id-map <out>/ids.json]
```
`api_checks.py` (Component 3 — deep API security): BOLA (object-level authz on JSON APIs),
BFLA / broken function-level authz (admin endpoints reachable by a normal user or anon), excessive
data exposure (sensitive fields in JSON responses), and GraphQL field-authz hygiene. Reads the API
surface recon mined; GET-only; emits the capability fields that feed correlation.

`authz_replay.py` replays every endpoint `user_a` can see as `user_b`, as anonymous, and (if given) compares to
admin-only endpoints — flagging responses that are the same when they should differ (IDOR, broken
object/function-level authorization). For ID-based endpoints give `--id-map ids.json` (templates
+ per-user id lists; see `references/checks-auth.md`). `--endpoints` adds URLs (one per line,
e.g. from `har_import.py`). `--threshold` tunes similarity when no identity markers exist.

Then the manual checks in `references/checks-auth.md`: session fixation/rotation on login, logout
really invalidating server-side, timeout, CSRF on state-changing forms, mass-assignment hints,
privilege fields (`role`, `isAdmin`) in client state, JWT weaknesses.

## Phase 4 — Independent verification (Component 4a, Validation agents)

Every script writes `"status": "candidate"` — candidates are hypotheses. **Spawn a fresh, siloed
Validation subagent per finding** (or per batch of low-severity ones) using
`references/agents/validation.md`. Each agent sees ONLY the scope file and its one finding —
never your reasoning, never sibling agents' work — and reproduces from scratch with a minimal
request, returning `verified` (with a redacted one-line repro traceable to a `requests.jsonl`
line) or `rejected` (with reason). If subagents aren't available, retest each yourself, fresh
and skeptical.

Reject common false positives: missing headers on non-HTML/static responses; CORS reflection
without `Access-Control-Allow-Credentials: true`; soft-404 "exposed" files; IDOR where both users
legitimately share the object; version banners with no known-vulnerable version. Calibrate
severity with `references/severity.md`. **Nothing reaches the report without a reproducible
evidence artifact.**

## Phase 4.5 — Correlation (Component 4, Orchestrator)

Attack-chain correlation is the centrepiece and needs the global view, so the orchestrator runs it.

```
python3 scripts/correlate.py --findings <out>/findings.json --out <out> --recon <out>/recon.json
```
`correlate.py` is deterministic (no network): it reads the capability fields on each finding
(`grants`/`requires`/`assets`/`id_shape`/`chain_role`), builds the attacker-state graph (edge
**A→B when a grant of A satisfies a require of B on the same asset**; sequential `id_shape`
injects an implicit `knowledge:*` grant from anonymous), matches the pattern library, and writes
**candidate chains** to `<out>/chains.json` (high recall).

Then apply the **four-stage method in `references/attack-chains.md`** to prune/confirm:
1. information disclosure (what we learned for free → `knowledge:*`),
2. authorization weakness (does that knowledge make an authz gap practical?),
3. privilege boundary failure (once a user, what makes us another user / admin?),
4. combined-impact assessment — rate on the **worst outcome from the lowest privilege in the
   chain**, then name the **cheapest cut** (the single fix that breaks it earliest).
Prune anti-patterns (different-asset steps, contradictory identities, a finding used twice,
useless knowledge). Write combined impact and `remediation_priority` into each chain.

Regression: pass `--baseline <prev chains.json>` to tag each chain `new` vs `still-live` and
report chains that no longer reproduce (retest intelligence across runs).

## Phase 4.6 — Chain execution (optional; verifies chains end-to-end)

```
python3 scripts/chain_exec.py --scope <out>/scope.json --out <out> \
    --chains <out>/chains.json --findings <out>/findings.json [--sessions <out>/sessions.json] [--chain CHAIN-id]
```
Walks each chain's steps in order across the real actor sessions, carrying extracted artifacts
between them, and promotes a chain to `confidence: confirmed` only when it reproduces end-to-end.
**Read-only by default.** The one active capability — forging an `alg:none` `role=admin` token to
*observe* whether an admin endpoint accepts it — runs **only** when the scope sets
`allow_token_forge: true` (default false), never persists, and counts as confirmed only via a
baseline differential (endpoint denies without the token, accepts with it). With the flag off, the
forge step is skipped and the chain stays `tentative`. This is the prove-don't-exploit line: keep
`allow_token_forge` off unless the engagement explicitly authorises it.

## Phase 5 — Chain-first report (Component 5, Reporting → Review)

Gate, then render:
```
python3 scripts/validate_findings.py <out>/findings.json --final    # body gate: verified need evidence+repro+impact+remediation, secrets redacted
python3 scripts/validate_findings.py <out>/findings.json --chains <out>/chains.json   # chain integrity: every kill_chain finding exists, shape valid
python3 scripts/report.py --scope <out>/scope.json --findings <out>/findings.json --out <out>/report.md
```
`validate_findings.py` modes: plain (schema + redaction checks), `--summary` (counts by status/
severity, no gate), `--final` (strict pre-report gate), `--chains <file>` (validate `chains.json`
against the chain shape and finding-id integrity). `report.py` reads `<out>/chains.json`
automatically when present and leads with chains; add `--include-candidates` for an **internal
draft only** (never the final deliverable).

The report is chain-first: executive summary (chains + business risk), engagement details (scope,
environment, actors + liveness, dates, authorization reference, methodology, **coverage** —
endpoints tested per actor), attack chains (kill-chain diagram, combined impact, redacted proof,
cheapest cut), findings tagged with their chains (low/info collapse to a table), a remediation
plan ordered by chain-breaking value, and appendices (methodology, rejected findings, evidence
index). Then spawn a **Review** subagent (`references/agents/review.md`) as the QA gate; loop back
to Reporting on a fix-list. Nothing ships unreviewed.

Finish by telling the user: counts by severity, the top chains in one line each, and where the
report is. Remind them `sessions.json` holds live credentials — revoke those sessions.

---

## Working with findings.json and chains.json

All scripts merge into `<out>/findings.json` (deduped by `id`; the merge is lock-protected and
parallel-safe). For a manual finding, follow `schema/findings.schema.json` — copy an existing
entry as a template. Core fields: `id`, `title`, `severity`, `confidence`, `status`, `category`,
`auth_context`, `url`, `method`, `description`, `impact`, `evidence`, `reproduction`,
`remediation`, `cwe`, `source`. **Optional capability fields** (additive, drive correlation):
`grants`, `requires`, `assets`, `id_shape`, `chain_role` — use only the controlled vocab (set by
`common.cap_fields(...)`, which drops unknown tokens). Append safely with:
```
python3 scripts/add_finding.py --out <out> --json '<finding json>'
```
`chains.json` is written only by the orchestrator (via `correlate.py` + your synthesis); its
canonical shape and the `kill_chain` phase enum live in `references/attack-chains.md`.

## Self-test

`tests/` holds a deliberately-vulnerable app and checks. Run `python3 tests/test_core.py` (unit
tests for the frozen core) and `bash tests/run_selftest.sh` (end-to-end pipeline against the
bundled app) before relying on changes.
