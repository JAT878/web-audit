# Agent brief — AUTH (Component 2: authN / authZ / session)

## Mandate
The highest-value area. Authentication bypass, the role×endpoint authorization matrix
(horizontal/vertical/tenant), session weaknesses, privilege escalation. Deep detail:
`references/checks-auth.md`.

## Inputs you receive
- Scope path `<out>/scope.json`, out dir `<out>`, the recon surface map (`<out>/recon.json`
  and `recon-<name>.json`), and the actor names to use (anon/user_a/user_b/admin).
- Session material via `--sessions <out>/sessions.json --session <name>` / `--owner/--other/
  --admin`. Never read session values directly.

## Scripts you run
```
python3 scripts/authz_replay.py --scope <out>/scope.json --out <out> \
    --sessions <out>/sessions.json --owner user_a --other user_b [--admin admin] \
    [--id-map <out>/ids.json] [--endpoints <out>/endpoints.txt] [--threshold 0.92]
python3 scripts/extra_checks.py --scope <out>/scope.json --out <out> --sessions <out>/sessions.json [--session user_a]
python3 scripts/auth_probe.py / session_checks.py ...   # if present (Component C)
```
`extra_checks.py` decodes JWTs from session material / Set-Cookie (decode-only; never forges)
and flags `alg:none`, missing/overlong `exp`, sensitive claims.

## Capability fields to emit (CONTRACT vocab only)
- IDOR cross-user read → `grants:["read:any-user"|"read:other-user"]`,
  `requires:["knowledge:user-ids"]` (omit if `id_shape` sequential), `chain_role:"authz"`.
- Authed endpoint reachable anonymously → `grants:["read:any-user"|"read:admin"]`,
  `requires:["none"]`, `role:"authz"`.
- User reaching admin fn → `grants:["read:admin"]`, `requires:["identity:user"]`, `role:"privilege"`.
- JWT `alg:none`/forgeable role → `grants:["identity:assume-admin"]`, `requires:["identity:user"]`,
  `role:"privilege"`. JWT no/long expiry → `grants:["token:no-expiry"]`, `role:"session"`.
- Session fixation / no rotation → `grants:["session:fixate"]`, `role:"session"`.
Always set `assets=[asset_of(url)]` and `id_shape=id_shape_of(url)`.

## Rules of engagement
- Read-only. No credential brute force / spraying. JWT decode-only unless `allow_token_forge`.
- Everything through `common.Client`. All findings `status:"candidate"`.

## EXACT return format
```
MATRIX: <actor>x<endpoint> tested=<n> gaps=<n>
FINDINGS: <finding-id> | <severity> | <category> | grants=[..] requires=[..] role=<role> asset=<a> | ev: requests.jsonl#<line>
NOTES: <one line per manual check done, e.g. "logout does not invalidate server-side">
```
One line per finding; reference the `requests.jsonl` line, not the body. Keep under ~25 lines.
