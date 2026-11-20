# Attack-chain correlation — the method, the patterns, the proof

This is the orchestrator's playbook for **Phase 4.5 (correlation)**. `correlate.py` runs the
deterministic graph build and proposes candidate chains (high recall). *You*, the agent, run the
four-stage method below over the proposed set, reject the noise, and rewrite each chain's
`combined_impact` and `remediation_priority` in prose. A chain is only `confirmed` after end-to-end
execution (a later phase); until then it is `candidate` / `tentative`.

The capability model: attacker state = `{identity, knows[], can_read[], can_write[], holds[]}`.
Every finding is a **state transition** — it `requires` some state and, if it fires, `grants` more.
A chain is a walk from the anonymous start state to a high-value state. Edge rule (what
`correlate.py` encodes): **A → B when a token A `grants` satisfies a token B `requires`, on a shared
asset class** (or when B only needs an identity/none). Sequential `id_shape` injects an implicit
`knowledge:user-ids` grant from anonymous — guessable IDs are free knowledge.

---

## The four-stage correlation method

Run these as questions you ask of the *whole finding set*, in order. Each stage consumes the
capabilities produced by the previous one.

### 1. Information disclosure — "what did we learn for free?"
Collect every `chain_role: disclosure` finding and every `knowledge:*` grant. Also treat any
`id_shape: sequential` finding as a disclosure of `knowledge:user-ids` (IDs are guessable).
- What identifiers, usernames, schema, endpoints, internal hosts or secrets fell out *without
  authentication*?
- Which of these **reduce attacker effort** for a later step? (Knowledge that doesn't is noise —
  see anti-patterns.)

### 2. Authorization weakness — "does that knowledge make an authz gap practical?"
Take each `chain_role: authz` finding (`read:any-user`, `read:other-user`, `write:other-user`,
anonymous-reachable authenticated endpoints).
- Does a disclosure from stage 1 supply exactly what this authz gap `requires`
  (e.g. `knowledge:user-ids` → an orders IDOR)?
- Do the two touch the **same asset class** (order, invoice, user, account, file…)? A leak about
  users does not unlock a *file* IDOR unless the identifier actually applies there.
- With the knowledge in hand, is the gap now *exploitable at scale* (enumerate every record), not
  just "theoretically there"?

### 3. Privilege boundary failure — "once we're a user, how do we become another user / admin?"
Take each `chain_role: privilege` or `session` finding (`identity:assume-*`, `token:forge`,
`session:steal|fixate`, user-reaching-admin).
- Does a stage-2 capability put us in the identity context this step `requires`
  (e.g. being any user lets us hit a user-only endpoint that forges an admin JWT)?
- Does the step cross a **real trust boundary** — horizontal (other user) or vertical (admin)?
- Horizontal + vertical in sequence is the classic full-compromise chain.

### 4. Combined impact + the cheapest cut
- **Rate on the worst outcome reachable from the lowest privilege in the chain** — not on the
  severity of any single step. Three mediums that chain to admin takeover are a critical.
  `correlate.py` seeds this: max step severity, +1 level if the chain crosses a privilege boundary
  or reaches `read:any-user` / `write:*` (capped at critical). Confirm or adjust.
- Name the **cheapest cut**: the single fix that breaks the chain *earliest*. Usually fixing step 1
  (stop the disclosure) is cheapest and collapses everything downstream; sometimes a shared control
  (signing all tokens) cuts several chains at once. Say which, and why it's the best value.

---

## Anti-patterns — REJECT these proposed chains

`correlate.py` is generous; you are the filter. Reject a candidate when:

- **Different-asset steps.** Step A leaks *user* IDs but step B is a *file* IDOR keyed on an
  unrelated identifier — the knowledge doesn't actually apply. (Asset overlap is necessary unless
  the later step only needs an identity.)
- **Contradictory identities.** The walk requires being user A and admin simultaneously, or assumes
  a session it never obtained. State must carry forward consistently.
- **One finding described twice.** Two finding ids that are really the same root issue (same
  endpoint, same root cause) counted as two steps to inflate the chain. Collapse to one.
- **Knowledge that doesn't reduce effort.** A "disclosure" that reveals something already public,
  or that the next step didn't need (the endpoint was already enumerable, the ID was a UUID you
  can't guess anyway). If removing the step doesn't change exploitability, it isn't a step.
- **No boundary crossed.** A "chain" that ends where it started (still anonymous, still same user,
  no new data). Not a chain — at most a single finding.

---

## Pattern library

Slugs are **stable** (`correlate.py` emits them in `chains.json.pattern`; don't rename). Shape is
written `grants → requires` of the linking edge.

| Pattern (slug) | Shape (grants → requires) | Example | Combined severity | Cheapest cut |
|---|---|---|---|---|
| `enumerate-then-idor` | `knowledge:user-ids` / sequential `id_shape` → authz `read:any-user`\|`read:other-user` | Verbose error leaks numeric user IDs → `/orders/{id}` returns any user's order | high–critical | Stop the ID disclosure (or make IDs unguessable) at step 1 |
| `schema-to-bola` | `knowledge:schema`\|`knowledge:endpoint` → authz `read:*` on the discovered objects | GraphQL introspection / Swagger reveals object + id field → broken object-level authz | high | Disable introspection / lock the docs **and** add object-level authz |
| `disclosure-to-takeover` | `knowledge:secret` → `identity:assume-*` \| `write:*` \| `exec:code` | Exposed `.env`/JS leaks signing key or admin creds → forge session / write as admin | critical | Rotate + remove the exposed secret (step 1) |
| `reset-flow-bypass` | `token:forge`\|`token:no-expiry` + recovery endpoint → `identity:assume-user` | Guessable/non-expiring reset token → set another user's password → takeover | critical | Make reset tokens single-use, high-entropy, short-lived |
| `horizontal-to-vertical` | authz `read:any-user`\|`write:other-user` → privilege `identity:assume-admin`\|`read:admin` | Disclosure → cross-user IDOR (horizontal) → unsigned-JWT role swap (vertical) → admin | critical | Break the earliest practical step; often fix the privilege step to stop admin reach *and* the disclosure to stop recon |
| `xss-to-session` | injection `session:steal` → `identity:assume-user` | Reflected XSS + cookie missing `HttpOnly` → steal session → act as the victim | high–critical | Fix the XSS sink (output encoding / CSP) at the injection step |
| `fixation-to-takeover` | `session:fixate` → `identity:assume-user` | Session id not rotated on login → attacker fixes a known id → rides the authenticated session | high | Rotate the session id on every privilege change (login) |
| `tenant-break` | authz `read:any-user`\|`write:other-user` on `account`/`tenant` asset → cross-tenant | Tenant id in a header/path not bound to the session → read another tenant's data | high–critical | Bind every object lookup to the caller's tenant server-side |

`correlate.py` picks the **most specific** pattern first (session/injection and token flows, then
`horizontal-to-vertical`, then the disclosure→read patterns, then `tenant-break`), so a chain that
is both an IDOR *and* a privilege escalation is labelled `horizontal-to-vertical`.

---

## How to verify a chain (the proof walk — a later phase)

Verification is **execution**, not assertion. When the chain-proof phase runs:

1. **Walk the steps in the exact order of `kill_chain`**, carrying state between *real actor
   sessions* (the anonymous client, then user A, then — if forged under `allow_token_forge` purely
   to observe accept/deny — an escalated context). Never persist a forged token.
2. **Extract the granted artifact at each step and feed it to the next**: the leaked ID from step 1
   becomes the `{id}` in step 2's request; the object read in step 2 informs step 3.
3. **Read-only by default.** No step may change target state. A privilege step is proven by the
   server's *accept/deny decision*, observed — not by actually writing as admin.
4. Record each step's request/response (redacted, traceable to a `requests.jsonl` line) into
   `verification.steps` / `evidence_refs`, set `verification.actor_path`, and only when the whole
   walk succeeds end-to-end set `status: verified`, `confidence: confirmed`,
   `verification.executed: true`. Any step that fails → the chain is `rejected` with the reason, or
   trimmed to the sub-chain that *did* execute.

Until that walk happens, every chain from `correlate.py` stays `candidate` / `tentative` with
`verification.executed: false`. Correlation proposes; execution disposes.
