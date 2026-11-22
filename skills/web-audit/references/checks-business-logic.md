# Business-logic checks (Logic agent reference)

Business logic cannot be fully scripted: the flaw is the gap between what the application *should*
enforce and what it actually re-checks on each request. This is **agent-led reasoning**, not a
scanner. You walk real workflows as a legitimate actor, then ask: *what does the server fail to
re-validate?* A scanner cannot know that a quantity should be positive, that step 3 requires step 2,
or that a coupon is single-use. You do.

## Ground rules (read first)
- **Read-only by default.** Observe and reason before you touch anything. A state change is opt-in:
  it is allowed ONLY when **all** of these hold — `allow_state_changing: true` in scope, the action is
  **harmless on a disposable test account**, the path is **not** in `excluded_paths` (logout / delete /
  payment / email / password), and the **user has approved** that specific step. Otherwise reason from
  observation and mark the finding's uncertainty honestly.
- **Everything over `common.Client`** (same scope, rate limit, redaction, logging). Small `curl` or
  Python snippets must honour the same rate limit. Log what you send in `<out>/notes.md`, one line per
  workflow observation, and cite evidence by `requests.jsonl` line.
- **Prove, don't exploit.** Demonstrate the boundary is missing with the *smallest* observation; never
  cause real loss, charges, spam, or data destruction. "Could" is enough when "did" would do harm.
- Findings are `status: "candidate"`, `category: "business-logic"`, `confidence` honest (usually
  `tentative` for reasoned-but-not-executed; `firm`/`confirmed` only when you safely observed it).

## Recording a finding
Emit via `add_finding.py` or the same `Findings.add(**...)` shape the scripts use. Attach capability
fields with `common.cap_fields(...)` **only when the flaw clearly composes** — most logic flaws are
standalone. Vocabulary is fixed (see base CONTRACT); `cap_fields` drops unknown tokens.

```python
F.add(id="LOGIC-price-tamper-<shash>", title="Order total trusts client-supplied unit price",
      severity="high", category="business-logic", auth_context="user_a",
      url=u, method="GET", description="...observed vs expected...",
      source="logic", evidence={"request": describe_request(r), "response_status": 200,
                                "response_excerpt": excerpt(r.text), "notes": "requests.jsonl#42"},
      **common.cap_fields(grants=["write:other-user"], requires=["identity:user"],
                          assets=[common.asset_of(u)], chain_role="standalone"))
```
Set `assets=[asset_of(url)]` when it returns non-None and `id_shape=id_shape_of(url)` where object ids
are involved. Default `chain_role="standalone"`; use `"authz"`/`"privilege"` only when the flaw grants
another actor's data/actions or crosses a role boundary.

---

## The checklist

For each: **look for** (where the flaw hides) · **test safely** (read-only first) · **record**
(capability hint when it composes).

### 1. Parameter / price tampering
- **Look for:** totals, prices, discounts, currency, tax, shipping, account/tenant ids, or role/flag
  fields that travel in the request (query, hidden form field, JSON body) and are *trusted* rather than
  recomputed server-side. Compare what the UI sends against what the server could derive itself.
- **Test safely:** first just *read* the request the app makes and the response. Reason about whether the
  server re-prices. Only re-send a modified value if state changes are approved and harmless (e.g. a
  search/quote endpoint that reflects a total without committing). Observe whether the altered value is
  honoured.
- **Record:** server trusts client price/amount → `grants:["write:other-user"]` if it affects another
  party's charge/record, else no grant; `role:"authz"` or `"standalone"`; `assets=[asset_of(url)]`.

### 2. Quantity / negative amounts
- **Look for:** quantity, amount, points, balance, transfer fields accepting `0`, negatives, huge
  values, or fractional where integers are expected. Negative quantity → credit/refund; oversized →
  overflow or free goods.
- **Test safely:** check client-side-only validation (does the server also reject it?). Prefer a
  read/quote path. A negative/zero that the server *accepts* but you do **not** commit is still strong
  evidence — capture the accepting response.
- **Record:** negative amount yields value/credit → `business-logic`, severity by impact; usually
  `standalone`.

### 3. Workflow step-skipping / out-of-order
- **Look for:** multi-step flows (cart → address → payment → confirm; KYC; onboarding; approval
  gates). Can you POST/GET a later step's endpoint directly, skip verification, or reach a
  "confirmed/approved" state without the prerequisite step?
- **Test safely:** request the later-step endpoint as a legitimate actor *without* doing the earlier
  step and observe the state. Read the resulting object. Do not finalise anything irreversible.
- **Record:** skip reaches a privileged/paid/approved state → `grants:["identity:assume-admin"]` where a
  role gate is bypassed, `requires:["identity:user"]`, `role:"privilege"`; otherwise `standalone`.

### 4. Replay / idempotency
- **Look for:** one-time actions reused — reuse a coupon, a reset/confirm token, a signed callback, an
  order-submit, a "redeem" more than once. Missing nonce / idempotency key / server-side single-use
  enforcement.
- **Test safely:** observe whether the token/action is marked consumed. Re-presenting a *read* of the
  same token (no second commit) can reveal it is still valid. A second state-changing replay only with
  approval and on a test account that absorbs no real effect.
- **Record:** reusable reset token → ties to the reset-token-leak chain; `grants:["identity:assume-user"]`
  where it yields account takeover, `requires:["knowledge:usernames"]`, `role:"privilege"`.

### 5. Coupon / limit / allowance abuse
- **Look for:** per-user/per-order caps, stacking rules, "one per customer", rate or spend limits,
  free-tier quotas enforced only in the UI or only client-side.
- **Test safely:** read the rule, then observe whether the server enforces it (e.g. apply the same
  coupon twice to a *quote* that doesn't commit; check the reflected discount). Stay within harmless,
  reversible observation.
- **Record:** limit bypassable → `business-logic`; `standalone` unless it grants another actor value.

### 6. Authorization within a workflow
- **Look for:** steps that check *authentication* but not *ownership/role at that step* — editing
  another user's cart/order mid-flow, approving your own request, acting on an object id that belongs to
  someone else once you're "inside" the workflow. This is the logic cousin of IDOR; confirm the missing
  *per-step* check.
- **Test safely:** as `user_a`, read a `user_b` object id reachable only through the workflow; confirm
  `user_b`'s `identity_markers` appear. Read-only.
- **Record:** cross-user action inside a flow → `grants:["read:other-user"]`/`["write:other-user"]`,
  `requires:["knowledge:user-ids"]` (omit when `id_shape:"sequential"`), `assets=[asset_of(url)]`,
  `role:"authz"`. Composes readily — set the right role so correlation can chain it.

### 7. Race conditions / TOCTOU — **note only, do not exploit**
- **Look for:** check-then-act gaps where concurrent requests could double-spend a balance, redeem a
  coupon twice, or over-draw a limit (classic TOCTOU on balance/stock/quota).
- **Test safely:** **do not** fire concurrent bursts against the target — that risks impact and trips the
  circuit breaker. Record it as a **reasoned/manual** candidate: describe the window and why it is
  plausible from the single-request behaviour you observed. Flag for manual, authorised load testing in
  a dedicated environment.
- **Record:** `severity` by plausible impact, `confidence:"tentative"`, `notes` stating it was reasoned,
  not executed; `standalone`.

---

## Return discipline
Follow the Logic agent's exact return format (`references/agents/logic.md`): one line per workflow
(`WORKFLOWS:`), one per finding (`FINDINGS: <id> | <sev> | business-logic | grants=[..] role=<role>
asset=<a> | ev: requests.jsonl#<line>`), one per observation (`NOTES:`). Keep it tight. If recon shows
no real workflows (no cart, checkout, state machine, balance, coupon), say so and skip — a reasoning
agent with nothing to reason about adds noise, not coverage.
