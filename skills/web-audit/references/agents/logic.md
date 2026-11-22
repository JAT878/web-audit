# Agent brief — LOGIC (Component 3, OPTIONAL)

Spawned only when recon shows **real business workflows** (carts, checkout, multi-step forms,
state machines, coupons, balances). Otherwise skip — business logic can't be fully scripted,
which is exactly why this is a reasoning agent and why it's optional.

## Mandate
Business-logic flaws: price/quantity/parameter tampering, workflow step-skipping,
replay/idempotency, negative amounts, coupon/limit abuse. Agent-led against the checklist
`references/checks-business-logic.md`.

## Inputs you receive
- Scope path `<out>/scope.json`, out dir `<out>`, recon surface map, the app/workflow model
  the orchestrator describes, actor names, session material via `--sessions ... --session`.

## How you work
- Walk each workflow as a legitimate actor through `common.Client`; reason about what the
  server fails to re-check. Use `curl`/small Python snippets through the SAME rate limit; log
  what you send in `<out>/notes.md`.
- State-changing steps need `allow_state_changing: true` AND they must not touch
  `excluded_paths` (logout/delete/payment/email). Prefer observation; prove, don't exploit.

## Capability fields to emit (CONTRACT vocab only)
- Tampering that yields another user's data/actions → `grants:["write:other-user"]` or
  `read:*`, `role:"authz"` or `"privilege"`, `assets=[asset_of(url)]`.
- Workflow skip reaching a privileged state → `grants:["identity:assume-admin"]` where apt,
  `requires:["identity:user"]`, `role:"privilege"`.
- Most logic flaws are `chain_role:"standalone"` unless they clearly compose.

## Rules of engagement
- Read-only by default; any state change is opt-in, scoped, approved, and never against
  excluded paths. Findings `status:"candidate"`.

## EXACT return format
```
WORKFLOWS: <name> steps=<n> tested=<n>
FINDINGS: <finding-id> | <severity> | business-logic | grants=[..] role=<role> asset=<a> | ev: requests.jsonl#<line>
NOTES: <one line per workflow observation>
```
One line per finding; evidence by `requests.jsonl` line. Under ~25 lines.
