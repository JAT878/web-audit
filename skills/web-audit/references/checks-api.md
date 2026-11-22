# API security checks (manual reference)

Companion to `scripts/api_checks.py`. The script runs the read-only, automatable subset of the
**OWASP API Security Top 10 (2023)**; this page says what it covers, what stays manual, and how to
widen coverage safely.

## What `api_checks.py` does

Read-only, **GET only**, every request through `common.Client` (scope, rate limit, redaction,
logging). It reads `recon.json` / `recon-<session>.json` from the out dir for candidate endpoints
(`endpoint_templates`, `js_endpoints`, `js_absolute_urls`, `browser_crawl.api_urls`, page URLs) and
focuses on JSON / API endpoints (path under `/api`, a `/graphql` path, or a JSON content type).

```
python3 scripts/api_checks.py --scope scope.json --out OUT \
    --sessions sessions.json --session user_a --other user_b --admin admin --id-map ids.json
```

It emits **candidate** findings for:

| # | Check | Detector | Finding id prefix | CWE |
|---|-------|----------|-------------------|-----|
| 1 | BOLA / object-level authz | object endpoints (`/api/orders/{id}`) requested as `user_b` and anonymously; flags a 2xx JSON body that belongs to another user. Baselined against a nonexistent id. De-duped by templated path. | `API-bola-*` | 639 |
| 2 | BFLA / function-level authz | privileged paths (`/api/admin/*`, `/manage`, `/internal`, …) that return 2xx to anonymous or a normal user | `API-bfla-*` | 285 |
| 3 | Excessive data exposure | authenticated JSON carrying sensitive keys (`password_hash`, `role`, `is_admin`, `ssn`, `secret`, `token`, other users' emails, …) | `API-excessive-data-*` | 213 |
| 4 | GraphQL field-level-authz hygiene | one introspection GET; notes privileged-looking types (observation only, no deep/batched queries). Does **not** duplicate `extra_checks`' `GQL-introspection-*` finding. | `API-graphql-authz-*` | 285 |
| 5 | API inventory | old versioned siblings (`/api/v1` beside `/v2`) and reachable debug endpoints | `API-version-sibling-*`, `API-debug-endpoint-*` | 1059 / 489 |

BOLA ids come from `--id-map` (reused `ids.json`) when present, else ids seen in recon plus a few
sequential neighbours — rate-limited and capped. Capability fields (`grants`/`requires`/`assets`/
`id_shape`/`chain_role`) are attached via `common.cap_fields` so `correlate.py` can chain these into
attack paths (e.g. *enumerate user ids → BOLA read*, *BFLA → admin data*).

## OWASP API Top 10 (2023): automated vs manual

| API risk | Covered by script | Stays manual |
|----------|-------------------|--------------|
| API1 Broken object level authz (BOLA) | yes (check 1) | nested/second-order object refs, IDs in POST/PATCH bodies, GraphQL node ids |
| API2 Broken authentication | partial (`extra_checks` JWT, `auth_checks`) | credential stuffing, weak OTP, token refresh abuse |
| API3 Broken object **property** level authz | yes (excessive data exposure, check 3) | **mass assignment** (writing privileged fields) — needs a safe write test, out of read-only scope |
| API4 Unrestricted resource consumption | no | rate-limit / pagination-limit / large-payload testing (send volume) — do manually, with care |
| API5 Broken function level authz (BFLA) | yes (check 2) | state-changing admin actions (POST/DELETE) |
| API6 Unrestricted access to sensitive business flows | no | business-logic abuse (bulk purchase, referral farming) |
| API7 SSRF | no | SSRF-shaped params (`url=`, `callback=`, `webhook=`, `image_url=`) — probe manually |
| API8 Security misconfiguration | partial (inventory, CORS in `passive_checks`) | verbose errors, missing security headers on API responses |
| API9 Improper inventory management | partial (check 5) | shadow/undocumented hosts, staging APIs, deprecated docs |
| API10 Unsafe consumption of 3rd-party APIs | no | review server-side calls to upstream APIs |

**Injection in API params** (SQLi/NoSQLi/command/template) is handled by `param_probe.py`
(error-based, read-only); confirm by hand before reporting.

## Widening coverage with a schema

The detectors are only as good as the endpoint list from recon. Feed them more:

- **OpenAPI / Swagger**: if you have a spec, expand its `paths` into concrete URLs (one per
  operation, filling `{id}` from `ids.json`) and drop them into `recon*.json`'s
  `endpoint_templates`, or point recon at the discovered spec. Every documented GET then becomes a
  BOLA/BFLA/EDE candidate.
- **GraphQL**: supply the schema (SDL or an introspection JSON). Enumerate types with object ids
  and check each resolver enforces authz. The script only *observes* introspection — it never runs
  deep, batched or aliased queries.
- **`--id-map ids.json`**: the single biggest lever for BOLA. List real object ids per user so the
  script can do true cross-user swaps instead of guessing neighbours.
- **`--other` / `--admin`**: give a second user and an admin session so horizontal (cross-user) and
  vertical (cross-role) checks both run.

## Safety notes

- **Read-only, GET only.** No POST/PUT/PATCH/DELETE, no state changes. `common.Scope` also blocks
  state-changing GET paths (`/delete`, `/reset`, …) and honours `excluded_paths`.
- **No heavy GraphQL.** One introspection GET maximum; no deep/recursive/batched queries that could
  amplify load.
- **No mass-assignment or resource-consumption testing** here — both require writes or volume. Do
  them manually, only with `allow_state_changing` / explicit authorization, and never against
  production without sign-off.
- All findings are emitted as `status: "candidate"` — a human verifies (or rejects) them before the
  final report. Response excerpts are redacted via `common.redact`.
