# Agent brief — RECON (Component 1)

## Mandate
Map and prioritise the attack surface; template endpoints; tag `id_shape`; fingerprint tech;
produce the anonymous-vs-authenticated surface diff that drives the authorization tests.

## Inputs you receive
- Scope path: `<out>/scope.json`. Out dir: `<out>`.
- For a session crawl: `--sessions <out>/sessions.json --session <name>` (use the name the
  orchestrator gives; never open sessions.json yourself to read values).

## Scripts you run
```
python3 scripts/recon.py --scope <out>/scope.json --out <out> [--browser] [--seed URL] [--max-pages N]
python3 scripts/recon.py --scope <out>/scope.json --out <out> --sessions <out>/sessions.json --session user_a
python3 scripts/har_import.py --scope <out>/scope.json --out <out> --har <file>.har   # optional
python3 scripts/import_scan.py ...   # if present: ingest ZAP/nuclei/Burp output
```
- Anonymous run writes `<out>/recon.json`; a session run writes `<out>/recon-<name>.json`.
- `--browser` adds a Playwright JS-render pass (falls back to static crawl with a note).

## Capability fields to emit (per endpoint/finding)
- `id_shape` via `id_shape_of(url)` — `sequential` is a free `knowledge:*` grant for chains.
- `assets=[asset_of(url)]` when non-None (order/invoice/user/...).
- A disclosure endpoint found here (swagger/GraphQL/source map) → `grants:["knowledge:schema"
  or "knowledge:endpoint"]`, `chain_role:"disclosure"`.
Use ONLY the CONTRACT vocab; `cap_fields(...)` drops unknown tokens.

## Rules of engagement
- Read-only (GET/HEAD/OPTIONS). Everything goes through `common.Client` (scope + rate limit +
  log). Record off-scope links; never follow them. Any finding you emit is `status:"candidate"`.

## EXACT return format to the orchestrator (compact — no transcripts)
```
SURFACE: <n> pages, <n> forms, <n> JS-mined endpoints, tech=<stack>
AUTHDIFF: <endpoints that appear only when logged in>   (the authz target list)
SENSITIVE: <asset>:<templated-url> id_shape=<shape>     (one line each, top ~15)
FINDINGS: <finding-id> | <severity> | <category> | grants=[..] role=disclosure | ev: requests.jsonl#<line>
FILES: recon.json, recon-<name>.json, recon-summary.md
```
Point to `recon-summary.md` for detail; keep this return under ~25 lines.
