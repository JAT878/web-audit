# Agent brief — API (Component 3: deep API security)

## Mandate
Spec-driven API testing: BOLA/BFLA, excessive data exposure, mass assignment (flag only),
GraphQL field-level authz, improper inventory (old `/v1` beside `/v2`, debug endpoints),
API hygiene (verbose JSON errors, CORS on APIs, verb/content-type confusion). Detail:
`references/checks-api.md`.

## Inputs you receive
- Scope path `<out>/scope.json`, out dir `<out>`, recon surface map (`recon.json` +
  `recon-<name>.json`), any API specs discovered (OpenAPI/Swagger/GraphQL schema), actor names.
- Sessions via `--sessions <out>/sessions.json --session <name>`. Never read session values.

## Scripts you run
```
python3 scripts/api_checks.py --scope <out>/scope.json --out <out> --sessions <out>/sessions.json ...   # if present
python3 scripts/extra_checks.py --scope <out>/scope.json --out <out> --session <name>   # GraphQL introspection (GET)
python3 scripts/authz_replay.py ... --endpoints <out>/endpoints.txt   # API authz matrix from specs/HAR
python3 scripts/param_probe.py --scope <out>/scope.json --out <out> [--session <name>]
```
Prefer coverage from the spec (exercise every operation × every actor), not guesswork.

## Capability fields to emit (CONTRACT vocab only)
- BOLA/IDOR on object endpoint → `grants:["read:any-user"]`, `requires:["knowledge:user-ids"]`
  (omit if sequential), `role:"authz"`, `assets=[asset_of(url)]`.
- Excessive data exposure (response leaks other users' PII/role) →
  `grants:["knowledge:user-ids","read:any-user"]`, `role:"disclosure"`.
- GraphQL introspection / swagger reachable → `grants:["knowledge:schema"]`, `requires:["none"]`,
  `role:"disclosure"`.
- Mass assignment (writable privileged field) → flag only; `write:*` grant, no write sent
  unless `allow_state_changing`. Always set `id_shape=id_shape_of(url)`.

## Rules of engagement
- Read-only by default; mass-assignment/writes only with `allow_state_changing` + approval.
- GraphQL batch/alias/depth: observe as resource-consumption indicators, do not abuse.
- Everything through `common.Client`. Findings `status:"candidate"`.

## EXACT return format
```
COVERAGE: operations=<n> actors=<n> tested=<n>
FINDINGS: <finding-id> | <severity> | <category> | grants=[..] requires=[..] role=<role> asset=<a> | ev: requests.jsonl#<line>
INVENTORY: <extra/old/debug endpoints found, one line>
```
One line per finding, evidence by `requests.jsonl` line ref. Under ~25 lines.
