# web-audit → AI Web Application Pentesting Framework

**Design proposal for review — 2026-11-20. No code has been changed.**

This reframes web-audit from a black-box scanner into a **five-component AI pentesting framework**,
with **attack-chain correlation as the centrepiece**. It supersedes the earlier attack-chains design
note (now folded in as Component 4) and builds on `AUDIT.md` (the correctness/safety audit).

---

## 0. Verdict on the framing

The five-component structure is **right**. It's the standard professional-pentest spine (it maps
almost one-to-one onto OWASP WSTG and PTES), and the current skill already does fragments of all five.
Adopting it as the organizing frame is an improvement over "a scanner that also finds chains."

Three caveats shape the whole design, so they're stated up front:

1. **"Comprehensive" must mean reasoning, not raw-check breadth.** Burp/ZAP/nuclei already own
   signature coverage and always will. If web-audit re-implements them it becomes a worse scanner. Its
   edge is the **intelligence layer**: correlate, validate, assess impact, chain, report. So the
   framework is positioned as an **orchestrator that can ingest/drive other tools** (import a ZAP or
   nuclei or HAR run as raw signal) and then do the part only an AI can. Breadth is borrowed; judgement
   is the product.
2. **A pentest framework is not an exploitation framework.** The skill's value *and* its licence to run
   against real systems come from being read-only by default, authorization-gated, and
   **prove-don't-exploit**. That stays the non-negotiable core. Active steps (token forging, state
   changes, chain execution) are opt-in, per-scope, and demonstrate *acceptance* rather than cause
   damage. We build the thing that finds and proves the route — not Metasploit.
3. **There is a Component 0.** Engagement setup, authorization, and rules of engagement are what make
   this a *professional* framework rather than a scanner. It's named explicitly below.

Everything else here assumes those three hold. If you disagree with any, it changes the build.

---

## 1. The framework at a glance

```
┌──────────────────────────────────────────────────────────────────────────────┐
│  COMPONENT 0 · Engagement & authorization   (scope gate, RoE, actors)          │
├──────────────────────────────────────────────────────────────────────────────┤
│  1 · Recon &        2 · AuthN / AuthZ      3 · API &            (detection)     │
│      attack-surface      assessment            business-logic                   │
│      mapping                                   assessment                        │
│         │                   │                      │                             │
│         └───────────────────┴──────────────────────┘                            │
│                              ▼  atomic, correlatable findings                    │
│  4 · Validation & ATTACK-CHAIN CORRELATION   ◄── the brain / centrepiece         │
│         │  verify each finding · build capability graph · assemble & prove chains │
│                              ▼                                                    │
│  5 · Professional penetration-testing reports                                    │
└──────────────────────────────────────────────────────────────────────────────┘
          cross-cutting: safe scoped HTTP client · redaction · evidence log · tool ingest
```

| # | Component | Today | OWASP WSTG area | Biggest gap to close |
|---|---|---|---|---|
| 0 | Engagement & authorization | Phase 0 scope gate (solid) | WSTG-INFO pre-engagement | Formalize actors/RoE; make it the framework's contract |
| 1 | Recon & attack-surface mapping | `recon.py` (crawl, JS mining, browser, HAR) | WSTG-INFO | Asset/endpoint templating, `id_shape`, tool ingest |
| 2 | AuthN / AuthZ assessment | `authz_replay`, `extra_checks`, manual refs | WSTG-ATHN / ATHZ / SESS | Auth-bypass & session modules; authz accuracy (AUDIT A1–A10) |
| 3 | API & business-logic | partial (JS endpoints, GraphQL) | WSTG-APIT / BUSL | The weakest area today — needs a real module |
| 4 | Validation & attack-chain correlation | Phase 4 verify (siloed, per-finding) | WSTG-analysis | Correlation doesn't exist yet — **the core of this proposal** |
| 5 | Professional reports | `report.py` (functional, verbose) | reporting | Chain-first, exec-ready, remediation-prioritized |

Cross-cutting (shared by all): the scoped rate-limited HTTP client, one redaction implementation,
the evidence log, and the findings/chains data model — the parts `AUDIT.md` says to harden first.

---

## 2. Positioning principle: the brain, not another scanner

The division of labour that makes this an *AI* framework rather than a tool collection:

- **Deterministic helpers (scripts)** do what must be exact and cheap: send scoped requests, parse,
  pattern-match grants→requires, execute a declared chain step, validate schema. No judgement.
- **The agent/session** does what only it can: read the app for what it *is*, decide what to probe,
  judge whether a finding is real, correlate findings into chains, write business impact, pick the
  cheapest fix. **This is where "AI pentesting" actually lives.**
- **External tools** are borrowed for breadth: ingest ZAP/nuclei/Burp/HAR exports as additional raw
  findings and endpoints, normalized into the same data model, then run Components 4–5 over the union.
  We never try to out-signature them.

So "comprehensive" = comprehensive *methodology and reasoning*, with breadth outsourced. That's
defensible against real tools; re-implementing their signatures is not.

---

## 3. Component 0 — Engagement & authorization

The contract layer. Mostly exists (Phase 0) and is good; formalize it:

- `scope.json`: target, `allowed_hosts`, `allowed_ports`, environment, `max_rps`,
  `allow_state_changing`, `excluded_paths`, and the deny-list (AUDIT S3).
- **Authorization record** (who approved, reference) — already enforced; keep it a hard gate.
- **Actors**: `anonymous`, `user_a`, `user_b`, `admin`, each with a **liveness canary** (AUDIT A1) so
  the framework knows a session died instead of silently reporting "all denied."
- **Rules of engagement** as explicit flags the later components read:
  `allow_state_changing`, `allow_token_forge` (new, default off), `allow_active_exploit` (new, default
  off), `max_chain_hops`. Every active behaviour downstream checks a flag here. This is what keeps
  Caveat 2 enforceable in code, not just in prose.

---

## 4. Component 1 — Recon & attack-surface mapping

Extends `recon.py`. Goal: a surface map rich enough to *correlate* on, not just a URL list.

- Keep: crawl, JS endpoint mining, Playwright render, HAR import.
- **Add asset/endpoint templating**: collapse `/orders/1001`, `/orders/1002` → `order:{id}` and record
  **`id_shape`** (`sequential|uuid|slug`). Sequential IDs are a free `knowledge:*` grant for Component 4.
- **Add the anon-vs-authenticated surface diff** (AUDIT T1): endpoints that appear only when logged in
  are the ones that *should* require auth — the primary authz target list.
- **Tool ingest** (the breadth lever): `import_scan.py` normalizes ZAP/nuclei/Burp/HAR output into
  findings + endpoints in our schema, tagged `source: zap|nuclei|…`. The framework then validates and
  chains them like its own.
- Output: `recon-summary.md` (condensed, token-cheap — AUDIT T1) + full `recon.json`.

---

## 5. Component 2 — Authentication & authorization assessment

The highest-value detection area. Combines hardened `authz_replay.py` with new auth modules. Every
finding here emits the capability primitives (`grants`/`requires`/`assets`) that Component 4 needs.

- **AuthN / bypass** (new `auth_probe.py`): forced browsing to post-auth pages; user enumeration
  (response/timing delta); password-reset flow flaws (token in response, token not invalidated,
  host-header-poisoned reset links); predictable "remember me" tokens. *Observation-first; nothing is
  reset/changed against real accounts without approval.*
- **AuthZ** (`authz_replay.py`, AUDIT A1–A10): horizontal (IDOR), vertical (function-level), tenant
  boundary — **including JS-mined API endpoints** (AUDIT A6, today's biggest miss). Correct the silent
  false-negative logic (expired session, "Log in" link treated as deny, markers disabling similarity).
- **Session** (new `session_checks.py`): fixation / no rotation on login, logout not server-invalidating,
  lifetime, binding. Emits `session:*` grants that compose with XSS/disclosure.
- **Privilege escalation**: mass-assignable `role`/`isAdmin`; forgeable/weak JWT with a trusted claim;
  admin function reachable as a normal user.

Grant vocabulary (shared, tiny, defined once): `knowledge:user-ids|usernames|schema|secret|endpoint`,
`read:other-user|any-user|admin`, `write:*`, `session:fixate|steal`, `token:forge|no-expiry`,
`identity:assume-user|assume-admin`. Requires: `none|identity:user|identity:admin|knowledge:*|holds:token`.

---

## 6. Component 3 — API & business-logic assessment

Today's weakest area; given its own module because modern apps are mostly APIs and OWASP tracks it
separately (API Top 10 2023).

- **BOLA / BFLA** from the templated API surface (Component 1) — object- and function-level authz on
  JSON endpoints, using the same actor replay as Component 2.
- **Excessive data exposure**: responses carrying fields the UI hides (`role`, `password_hash`, other
  users' PII, cost prices) → a `knowledge:*` *and* `read:*` grant, a frequent chain starter.
- **Mass assignment**: flag writable privileged fields (read-only by default; write only with approval).
- **GraphQL**: introspection → `knowledge:schema`, which feeds targeted BOLA — a canonical two-step chain.
- **Business logic** (agent-led, can't be fully scripted): parameter tampering on price/quantity,
  workflow step-skipping, replay/idempotency, negative amounts. The framework gives the agent the
  surface + a checklist (`references/checks-business-logic.md`); the agent reasons and probes safely.
- **API hygiene**: verbose JSON errors, missing rate-limit signals, method/verb handling.

---

## 7. Component 4 — Validation & attack-chain correlation (the centrepiece)

Two stages: verify each finding is real (exists today, Phase 4), then **correlate verified findings
into attack chains** (new, Phase 4.5). This is the component the whole reframing exists for.

### 7.1 Capability model — findings as attacker state transitions

Every finding is reframed as an edge that moves an attacker between capability states. The attacker's
state is a small capability set:

```
{ identity: anonymous|user|admin,  knows: [ids/secrets/endpoints],
  can_read: [asset classes],  can_write: [...],  holds: [session|token|key] }
```

Correlation reduces to one rule: **an edge A→B exists when a `grant` of A satisfies a `require` of B,
on the same `asset` class.** Sequential `id_shape` injects an implicit `knowledge:*` grant from
anonymous, so IDOR-on-sequential-IDs chains even with no explicit disclosure step.

Schema additions (additive/optional, so old findings still validate): `grants`, `requires`, `assets`,
`id_shape`, `chain_role`. (Full enums in §5/§6.)

### 7.2 `chains.json` — the new artifact (sibling of `findings.json`)

```jsonc
{
  "chains": [{
    "id": "CHAIN-acct-takeover-orders",
    "title": "Any user's orders readable, then account takeover via forged role",
    "status": "candidate",            // candidate|verified|rejected (same lifecycle as findings)
    "confidence": "tentative",        // confirmed only after end-to-end execution (§7.5)
    "severity": "critical",           // from COMBINED impact, not max(step severities)
    "kill_chain": [
      { "step": 1, "phase": "information-disclosure", "finding": "INFO-verbose-error-userid",
        "grants": ["knowledge:user-ids"] },
      { "step": 2, "phase": "authorization-weakness", "finding": "AUTHZ-idor-orders",
        "requires": ["knowledge:user-ids"], "grants": ["read:any-user"] },
      { "step": 3, "phase": "privilege-boundary-failure", "finding": "JWT-alg-none-role",
        "requires": ["identity:user"], "grants": ["identity:assume-admin"] }
    ],
    "combined_impact": "Anonymous attacker enumerates user ids from the error page, reads any \
customer's orders, forges the unsigned JWT to become admin — full compromise, no credentials.",
    "remediation_priority": "Signing the JWT (step 3) breaks escalation; object-level authz (step 2) \
breaks the data exposure. Step 2 is the cheaper blast-radius cut.",
    "verification": { "executed": true, "actor_path": ["anonymous","user_b","forged-admin"],
                      "evidence_refs": ["requests.jsonl#L142-171"] }
  }]
}
```

Modelling choices: chains reference finding ids (never duplicate content); severity is **combined**
(three mediums chaining into cross-tenant takeover = critical); `remediation_priority` names the
**cheapest cut** (the single most useful line for an eng team, and only a chain view produces it).

### 7.3 The four-stage correlation method (your model, formalized)

Goes in `references/attack-chains.md` as the agent's Phase 4.5 method — exactly your sequence:

1. **Information disclosure** — what did we learn for free? (IDs, usernames, schema, secrets, hosts) →
   `knowledge:*` grants.
2. **Authorization weakness** — does any of that knowledge turn a theoretical authz gap into a
   practical one? (IDOR needs an ID; stage 1 supplied it.)
3. **Privilege boundary failure** — once acting as a user, what lets us become another user or admin?
   (forgeable token, mass-assignable role, unchecked admin endpoint, session fixation.)
4. **Combined impact assessment** — from the lowest privilege in the chain, what's the worst outcome
   and how many users/how much data? Rate the chain on that. Then name the cut.

Plus anti-patterns to reject (different-asset steps, contradictory identities, one finding described
twice, knowledge that doesn't reduce attacker effort).

### 7.4 Mechanical + reasoning split

- **`correlate.py`** (deterministic, no network): builds the capability graph, finds anonymous→
  boundary-crossing paths, matches them to the **pattern library**, writes candidate chains. High
  recall, low precision — it proposes.
- **The agent**: prunes graph-only nonsense, adds business-logic chains the vocabulary can't encode,
  writes combined impact + cheapest cut, decides what to execute.

### 7.5 Chain verification — proving composition (opt-in, safe)

A `--chain <id>` mode of `authz_replay.py` walks the steps in order, carrying state between the real
actor sessions: execute step, extract the granted artifact (declared regex/JSON-path), feed into the
next step, until the final step returns the high-value asset / crosses the boundary — one request per
step, redacted, logged. Read-only by default. Token forging is allowed only to *send* a probe and
observe the server's accept/deny (never persisted), and only under `allow_token_forge`. Only a
fully-executed chain reaches `confidence: confirmed`; otherwise `tentative` with a manual repro note.

### 7.6 Pattern library (`references/attack-chains.md`)

Named chain shapes so the correlator can recognise and label paths: enumerate-then-IDOR,
schema-to-BOLA, disclosure-to-takeover, reset-flow bypass, horizontal-to-vertical (role mass-assign),
XSS-to-session-theft, fixation-to-takeover, tenant-break. Each with shape, example, combined severity,
cheapest cut.

---

## 8. Component 5 — Professional penetration-testing reports

`report.py` becomes chain-first and engagement-grade:

1. **Executive summary** leads with chains and business risk: "2 critical attack chains; the worst
   lets an anonymous user read all customer data and become admin in 3 steps."
2. **Engagement details**: scope, environment (production banner — AUDIT D7), actors tested + liveness,
   dates, authorization reference, methodology/standard (WSTG/PTES), **coverage** (endpoints tested per
   actor — so "no issues" can't hide a zero-coverage run).
3. **Attack chains**: each as a kill-chain diagram (disclosure → authz → privilege → impact), combined
   impact, executed proof (redacted), and the **cheapest cut** as primary remediation.
4. **Findings**: individual findings, each tagged with the chains it belongs to; standalone findings
   follow; low/info collapse to a table (AUDIT F1).
5. **Remediation plan**: prioritized by chain-breaking value, not just per-finding severity.
6. **Appendices**: methodology, rejected findings (collapsed), evidence index.

Export beyond Markdown (HTML/PDF) is a later nicety. Combined-severity + "up one if chained" becomes a
first-class rule in `severity.md`. Validation gates rendering (AUDIT P4): no report if redaction/schema
checks fail.

---

## 9. Harnessing the session/agent (the intelligence-aware requirement)

The framework leans on whatever the host session provides, degrading gracefully:

- **Subagents as parallel explorers**: one per candidate chain (execution) or per finding batch
  (verification), each returning a one-line verdict the **parent** applies — preserving independence
  and dodging the `findings.json`/`chains.json` write race (AUDIT P1). No subagents → agent works
  serially.
- **Cross-run memory / regression**: prior `chains.json` as a `--baseline`; the framework reports
  "chain X now broken (step 2 fixed), chain Y still live" — retest intelligence, not just a fresh scan.
- **Actors as a state machine**: `user_a/user_b/admin` aren't only IDOR fodder — they're the identities
  the agent *moves between* while walking a chain.

Firm boundary throughout: **scripts = deterministic primitives + safe execution; agent = correlation,
judgement, impact, next-probe selection.** That's what makes the *agent* chain-aware rather than
hard-coding a fixed chain set.

---

## 10. Proposed file / module layout

```
skills/web-audit/
  SKILL.md                         # phases 0–5 mapped to the 5 components
  common/                          # (was common.py) shared core — AUDIT hardening lands here
    scope.py  client.py  redact.py  findings.py  capability.py(grants/requires enums)  cli.py
  scripts/
    recon.py  import_scan.py       # Component 1 (+ tool ingest)
    authz_replay.py  auth_probe.py  session_checks.py  extra_checks.py   # Component 2
    api_checks.py                  # Component 3 (business-logic is agent-led via refs)
    passive_checks.py  exposed_files.py  param_probe.py                  # Component 1/2 detection
    correlate.py                   # Component 4 (graph + candidate chains)
    validate_findings.py           # + --chains, --final gates
    report.py                      # Component 5
  references/
    attack-chains.md               # method + pattern library (Component 4)
    checks-auth.md  checks-api.md  checks-business-logic.md  checks-unauth.md
    severity.md  scope-template.md
  schema/ findings.schema.json  chains.schema.json
  tests/ …                         # golden e2e per component (AUDIT §9)
```

---

## 11. Sequencing & dependency on the audit

Correlation and chain execution sit on top of the findings pipeline, so AUDIT P0 items are
**prerequisites**, not optional — a wrong graph fabricates or misses chains, and chain execution is the
most attacker-like behaviour the skill has.

| Must land first (AUDIT) | Why |
|---|---|
| S1–S3, S7, R1–R4 (scope/safety/redaction) | Chain execution must be unbreakably in-scope and leak-free |
| A1–A8 (authz accuracy) | Wrong asset/endpoint labels → wrong edges |
| P1–P2 (findings integrity + validator gate) | Correlation consumes *verified* findings |
| Schema enrichment (§7.1) | No grants/requires/assets → nothing to correlate on |

Proposed phasing:

- **Phase A — Foundation** (with AUDIT P0): shared `common/`, capability vocab, scripts emit the new
  fields, recon templating + `id_shape`, actor canaries.
- **Phase B — Correlation brain** (no new network behaviour): `correlate.py`, `chains.json` + schema,
  `attack-chains.md`, Phase 4.5, chain-first `report.py`. *You can see chain output on the test app here.*
- **Phase C — Components 2 & 3 depth**: `auth_probe.py`, `session_checks.py`, `api_checks.py`, business-
  logic refs, tool ingest (`import_scan.py`).
- **Phase D — Chain execution**: `authz_replay --chain`, extractors, `allow_token_forge`, subagent
  fan-out, baseline/regression, confirmed-only-after-execution.

I'd recommend landing **A + B first** (the correlation brain, zero new active behaviour) so you can
evaluate chain quality before we add any execution.

---

## 12. Decisions I need from you

1. **Positioning (Caveat 1):** agree the framework *orchestrates + ingests* other scanners rather than
   re-implementing their checks? If yes, `import_scan.py` is in scope for Component 1.
2. **Exploitation boundary (Caveat 2):** keep read-only-by-default + prove-don't-exploit as the hard
   core, with active steps gated behind `allow_token_forge` / `allow_active_exploit`? Or do you want a
   fuller active-exploitation mode (changes the safety/legal posture materially)?
3. **Standard to speak:** map findings/chains to a public taxonomy (OWASP WSTG IDs + MITRE ATT&CK /
   CAPEC) so reports are portable, or keep our own vocabulary?
4. **Scope of this build:** A+B first (recommended), or commit to A–D up front?
5. **AUDIT relationship:** fold the AUDIT P0 prerequisites into this work as one programme, or land the
   AUDIT fixes as a separate pass first and layer the framework on after?

---

*Worked example maps to your four-stage model: verbose-error disclosure → orders IDOR → unsigned-JWT
privilege break → "anonymous to full compromise" combined impact (see the `CHAIN-acct-takeover-orders`
object in §7.2).*
