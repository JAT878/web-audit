# web-audit → AI Web Application Pentesting Framework

**Design proposal for review — 2026-11-20. No code has been changed.**

A five-component pentesting framework delivered by a **multi-agent architecture**: a central
orchestrator that plans, scopes, and controls risk, fanning out to specialist agents that all funnel
into one professional penetration-testing report. Attack-chain correlation is the intelligence
centrepiece. Builds on `AUDIT.md` (correctness/safety audit).

---

## 0. Two axes, kept separate

This design has two independent axes. Keeping them separate is what keeps it coherent:

- **Components (WHAT is assessed)** — the five-part methodology: recon, authN/authZ, API/logic,
  validation + correlation, reporting. Maps to OWASP WSTG / PTES.
- **Agents (WHO does it)** — the orchestrator + specialists that execute the methodology, so the work
  parallelizes and each agent reasons in a clean context.

A component is a body of testing; an agent is a worker. One agent can own one component (auth agent ↔
Component 2), but correlation and risk are cross-component roles. The mapping is in §2.

### Verdict on the framing (unchanged, still holds)

The five components are the right spine. Three caveats shape everything:

1. **"Comprehensive" = reasoning, not raw-check breadth.** Don't out-signature Burp/ZAP/nuclei —
   *ingest* them and do the AI part on top. Breadth is borrowed; judgement is the product.
2. **Pentest framework ≠ exploitation framework.** Read-only-by-default, authorization-gated,
   prove-don't-exploit is the non-negotiable core. Active steps are opt-in behind scope flags.
3. **There is a Component 0** — engagement, authorization, rules of engagement — owned by the
   orchestrator. It's what makes this professional rather than a scanner.

---

## 1. The framework at a glance

```
                       ┌───────────────────────────────────────────────┐
                       │     CENTRAL ORCHESTRATOR  (the only writer)     │
                       │  plan · scope · permissions · task allocation   │
                       │  risk CONTROL (stop/go) · state · correlation   │
                       └───────────────────────────────────────────────┘
          dispatch ▲ scoped briefs                 ▲ structured returns (compact)
   ┌────────┬──────────┬──────────┬───────────┬─────────────┬────────┬───────────┬────────┐
   ▼        ▼          ▼          ▼           ▼             ▼        ▼           ▼        │
 RECON    AUTH       API       LOGIC*     VALIDATION      RISK   REPORTING   REVIEW      │
 agent    agent      agent     agent       agent         agent    agent       agent      │
 C1       C2         C3        C3(opt)     C4a           C4/5     C5          QA gate     │
   └────────┴──────────┴──────────┴───────────┴─────────────┴────────┴───────────┴───────┘
                                        ▼
                         ONE professional pentest report
        * logic agent is optional — spawned only when the app has real business workflows

 cross-cutting (shared libs every agent uses): scoped rate-limited client · redaction ·
 evidence log · findings/chains data model · tool ingest
```

| # | Component | Owning agent(s) | OWASP WSTG | Biggest lift |
|---|---|---|---|---|
| 0 | Engagement & authorization | Orchestrator | pre-engagement | Formalize RoE/actors as the contract |
| 1 | Recon & attack-surface | Recon | INFO | Intelligence recon (§4) |
| 2 | AuthN / AuthZ | Auth | ATHN/ATHZ/SESS | Advanced auth (§5) + AUDIT A1–A10 |
| 3 | API & business-logic | API (+ optional Logic) | APIT/BUSL | Deep API testing (§6) — weakest today |
| 4 | Validation & attack-chain correlation | Validation + Risk + Orchestrator | analysis | Correlation (§7) — the centrepiece |
| 5 | Professional report | Reporting + Review | reporting | Chain-first, evidence-gated (§8) |

---

## 2. Agent roster

Each agent gets a **scoped brief** (only what it needs), uses the **shared scoped client**, and returns
a **compact structured result** the orchestrator applies. No agent writes shared state; no agent can
widen scope. Briefs live in `references/agents/<name>.md`.

| Agent | Mandate | Reads | Returns | Component |
|---|---|---|---|---|
| **Orchestrator** | Plan the engagement, enforce scope/permissions, allocate tasks, run risk **control** (circuit breaker, stop/go), own all shared-state writes, run correlation synthesis | scope, RoE, all returns | drives everything | 0, 4 |
| **Recon** | Map & prioritize the attack surface; template endpoints; tech→CVE; ingest external tool output | scope | surface map, capability-tagged endpoints, tech fingerprint | 1 |
| **Auth** | AuthN bypass, authZ matrix (horizontal/vertical/tenant), session, privesc | scope, surface map, actors | capability-tagged candidate findings | 2 |
| **API** | Spec-driven API testing: BOLA/BFLA, excessive data exposure, mass assignment, GraphQL | scope, surface map, API specs, actors | candidate findings | 3 |
| **Logic** *(optional)* | Business-logic flaws: price/quantity tampering, workflow skipping, replay, negative values | scope, surface map, app model | candidate findings | 3 |
| **Validation** | Independently reproduce each candidate from scratch; verify/reject with evidence; prove chains end-to-end | scope, one finding/chain (siloed) | verified\|rejected + evidence line | 4a |
| **Risk** | Calibrate severity, compute **combined** chain impact, score risk, choose the cheapest cut | verified findings + chains | severity/impact/priority per item | 4/5 |
| **Reporting** | Assemble the professional report from verified, scored material | everything verified | `report.md` | 5 |
| **Review** | QA gate: evidence-backing, redaction, consistency, false-positive sweep, scope adherence | draft report + evidence | pass / fix-list | 5 |

Design rules that make the roster safe and cheap:

- **Orchestrator is the sole writer** of `findings.json` / `chains.json` → kills the write race
  (AUDIT P1) by construction.
- **Validation agents are siloed** — each sees only its one finding + scope, never the detector's
  reasoning or siblings' work. This preserves the skill's existing "fresh, skeptical retest" property.
- **Risk *assessment* (Risk agent) ≠ risk *control* (Orchestrator).** The orchestrator decides whether
  it's safe to keep going (5xx spikes, latency, scope edges). The Risk agent scores findings for the
  report. Different jobs, deliberately split.
- **Correlation is an orchestrator synthesis step**, not a detector — it needs the global view of all
  findings. (Option: a dedicated Correlation agent; I'd keep it in the orchestrator for the global
  context unless it gets heavy.)
- **Context budget**: agents return compact structured results (one line per finding/chain + evidence
  refs), not transcripts — so the orchestrator's context stays small across a long engagement.

---

## 3. Execution flow (how the agents sequence)

```
Orchestrator: plan + scope gate + actor liveness
        │
   ┌────▼────┐  Recon agent  ── surface map ──┐   (must finish first; others depend on it)
   │         │                                 │
   │   parallel fan-out ───────────────────────┤
   │   Auth agent · API agent · (Logic agent)  │  → candidate findings (capability-tagged)
   └────┬────┘                                 │
        │  Orchestrator: correlate → candidate chains (correlate.py + reasoning)
        │
   parallel, SILOED: Validation agents ── verify findings + execute chains ── verified/rejected
        │
   Risk agent: severity + combined impact + cheapest cut
        │
   Reporting agent: assemble ── Review agent: QA gate ──(fix-list?)──┐
        │                                                            │
        ▼  (loop back on fail)  ◄───────────────────────────────────┘
   ONE professional pentest report
```

Risk control runs **throughout**: the orchestrator watches the shared circuit breaker (AUDIT S7) and
can pause/stop/re-plan any time. Degradation: **no subagent capability → the orchestrator runs every
role itself, serially** — same methodology, one context. The multi-agent layer is an accelerator and a
context-hygiene mechanism, never a requirement.

---

## 4. Component 1 — Intelligence reconnaissance *(Recon agent)*

Beyond crawling: turn raw surface into a **prioritized, templated, capability-annotated target list**.

- Crawl + JS endpoint mining + Playwright render + HAR import (today).
- **Spec discovery**: OpenAPI/Swagger, GraphQL schema (introspection), `.well-known/`, source maps
  (`.js.map` → original paths), JS comments/config blobs → endpoints the crawler never sees.
- **Content & parameter discovery**: low-volume, scoped path probing; parameter mining from JS;
  cert SAN names for other in-scope hostnames.
- **Asset/endpoint templating** + **`id_shape`** (`sequential|uuid|slug`) — sequential IDs are a free
  `knowledge:*` grant for correlation.
- **Auth-state surface diff**: anonymous vs each actor — the endpoints that appear only when logged in
  are the authorization-test target list (AUDIT T1).
- **Tech → version → CVE** fingerprinting (offline CVE list; the breadth we *do* keep, since it's cheap
  and feeds chains).
- **Tool ingest** (`import_scan.py`): normalize ZAP/nuclei/Burp/HAR output into our schema, tagged by
  source — breadth borrowed, not rebuilt.
- Output: `recon-summary.md` (token-cheap) + full `recon.json`.

---

## 5. Component 2 — Advanced authentication & authorization *(Auth agent)*

The highest-value area. Every finding emits capability primitives (`grants`/`requires`/`assets`).

**Authentication & bypass:**
- Forced browsing to post-auth pages; user enumeration (response/timing delta).
- **OAuth/OIDC/SAML flow flaws** (observe): `redirect_uri` validation, missing `state` (CSRF),
  token leakage via `Referer`, implicit-flow issues.
- **MFA/step-up**: presence and whether sensitive actions can skip it.
- Password-reset flaws: token in response body, token not invalidated after use, host-header-poisoned
  reset links. Default creds only with approval. *Observation-first; no real account is reset.*
- **JWT deep (offline/decode-only unless `allow_token_forge`)**: `alg:none`, RS256→HS256 confusion,
  `kid` injection, weak-secret indicators, missing/overlong `exp`, sensitive claims.

**Authorization — the matrix:**
- Build a **role × endpoint authorization matrix**: every actor (anon/user_a/user_b/admin) against
  every sensitive endpoint, horizontal + vertical + tenant boundary, **including JS-mined APIs**
  (AUDIT A6). Fix the silent false-negatives (expired session, "Log in" link read as deny, markers
  disabling similarity — AUDIT A1–A4).

**Session:** fixation / no rotation on login, logout not server-invalidating, lifetime, concurrency,
JWT revocation, cookie scope. Emits `session:*` grants that compose with XSS/disclosure.

---

## 6. Component 3 — Deep API & business-logic security *(API agent, optional Logic agent)*

Today's weakest area; modern apps are mostly APIs (OWASP API Top 10 2023).

**API (API agent) — spec-driven where possible:**
- Parse OpenAPI/GraphQL schema → exercise **every operation across every actor** (the API
  authorization matrix). This is the deep part: coverage comes from the spec, not guesswork.
- **BOLA/BFLA** on templated object/function endpoints; **excessive data exposure** (responses carrying
  fields the UI hides → a `knowledge:*` *and* `read:*` grant, a frequent chain starter);
  **mass assignment** (flag writable privileged fields; write only with approval).
- **Improper inventory**: old `/v1` beside `/v2`, debug/staging endpoints.
- **GraphQL**: introspection → `knowledge:schema`; field-level authz; (observe only) alias/batch abuse
  and nested-query depth as resource-consumption indicators.
- API hygiene: verbose JSON errors, CORS on APIs, verb/content-type confusion, rate-limit signals.

**Business logic (Logic agent, optional — spawned only when real workflows exist):**
- Price/quantity/parameter tampering, workflow step-skipping, replay/idempotency, negative amounts,
  coupon/limit abuse. Agent-led against a checklist (`references/checks-business-logic.md`); can't be
  fully scripted, which is exactly why it's a reasoning agent and why it's optional.

---

## 7. Component 4 — Validation & attack-chain correlation *(the centrepiece)*

Two stages: **evidence-based validation** of each finding, then **attack-chain correlation** across the
verified set. Correlation is orchestrator-run (global view); validation and chain-proof are the
Validation agents; scoring is the Risk agent.

### 7.1 Evidence-based validation *(Validation agents)*
- Every candidate is independently reproduced **from scratch** by a fresh, siloed agent: minimal
  request, captured request/response/diff, secrets redacted, **traceable to a `requests.jsonl` line**.
- Verdict is `verified` (with evidence) or `rejected` (with reason) against a false-positive catalog.
- **Rule: nothing reaches the report without a reproducible evidence artifact.** Confidence is earned,
  not asserted.

### 7.2 Capability model — findings as attacker state transitions
Attacker state = `{identity, knows[], can_read[], can_write[], holds[]}`. Correlation rule: **edge A→B
when a `grant` of A satisfies a `require` of B on the same `asset`.** Sequential `id_shape` injects an
implicit `knowledge:*` grant from anonymous. Schema adds `grants`, `requires`, `assets`, `id_shape`,
`chain_role` (additive/optional).

Grant vocab: `knowledge:user-ids|usernames|schema|secret|endpoint`, `read:other-user|any-user|admin`,
`write:*`, `session:fixate|steal`, `token:forge|no-expiry`, `identity:assume-user|assume-admin`.
Requires: `none|identity:user|identity:admin|knowledge:*|holds:token`.

### 7.3 The four-stage correlation method (your model)
In `references/attack-chains.md`, run by the orchestrator:
1. **Information disclosure** — what we learned for free → `knowledge:*`.
2. **Authorization weakness** — does that knowledge make an authz gap practical?
3. **Privilege boundary failure** — once a user, what makes us another user / admin?
4. **Combined impact assessment** — worst outcome from the lowest privilege in the chain; rate on
   *that*; then name the **cheapest cut** (the single fix that breaks the chain earliest).

Plus anti-patterns (different-asset steps, contradictory identities, one finding twice, useless
knowledge).

### 7.4 `chains.json`
Chains reference finding ids (never duplicate), carry the `candidate→verified→rejected` lifecycle,
**combined severity** (three mediums → critical if they chain to takeover), an executed `verification`
block, and `remediation_priority` (cheapest cut). Worked example `CHAIN-acct-takeover-orders`:
verbose-error disclosure → orders IDOR → unsigned-JWT privilege break → "anonymous to full compromise."

### 7.5 Mechanics + proof
- `correlate.py` (deterministic, no network): build graph, find anonymous→boundary paths, match the
  **pattern library**, emit candidate chains (high recall).
- Chain proof: `authz_replay.py --chain` walks steps in order carrying state between real actor
  sessions, extracting each granted artifact and feeding the next step. Read-only by default; forging a
  token only to *observe* the server's accept/deny under `allow_token_forge`, never persisted. Only a
  fully-executed chain → `confidence: confirmed`.
- Pattern library: enumerate-then-IDOR, schema-to-BOLA, disclosure-to-takeover, reset-flow bypass,
  horizontal-to-vertical, XSS-to-session, fixation-to-takeover, tenant-break.

---

## 8. Component 5 — Professional report *(Reporting agent → Review agent)*

Chain-first and engagement-grade; every agent funnels here.

1. **Executive summary** leads with chains and business risk.
2. **Engagement details**: scope, environment (production banner), actors + liveness, dates,
   authorization reference, methodology standard, **coverage** (endpoints tested per actor — so "no
   issues" can't hide zero coverage).
3. **Attack chains**: kill-chain diagram (disclosure → authz → privilege → impact), combined impact,
   executed proof (redacted), cheapest cut as primary remediation.
4. **Findings**: each tagged with its chains; standalone follow; low/info collapse to a table.
5. **Remediation plan**: prioritized by chain-breaking value.
6. **Appendices**: methodology, rejected findings, evidence index.

**Review agent** is the final QA gate: every claim evidence-backed and traceable, redaction clean
(gates rendering — AUDIT P4/R1–R4), severities consistent, no scope violations, false-positive sweep.
Returns pass or a fix-list; the orchestrator loops back on fail. Nothing ships unreviewed.

---

## 9. Harnessing a Claude session (the multi-agent runtime)

- **Agents = subagents** spawned by the orchestrator (the host session). Recon first; then Auth/API/
  Logic in parallel; then siloed Validation agents in parallel; then Risk → Reporting → Review.
- **Orchestrator owns state & scope**: passes each agent only its brief + the RoE flags it needs; no
  agent can widen scope or write shared files. This is the enforcement point for Caveat 2.
- **Independence where it matters**: Validation agents never see each other or the detectors' reasoning.
- **Cross-run memory**: prior `chains.json` as a `--baseline` → "chain X now broken, chain Y still
  live" (regression intelligence).
- **Graceful degradation**: no subagents → orchestrator runs all roles serially in one context. Same
  methodology, same report.

---

## 10. Proposed layout

```
skills/web-audit/
  SKILL.md                         # phases 0–5 + agent orchestration
  common/  scope.py client.py redact.py findings.py capability.py cli.py   # shared, AUDIT-hardened
  scripts/
    recon.py import_scan.py                                   # C1 (Recon agent)
    authz_replay.py auth_probe.py session_checks.py extra_checks.py   # C2 (Auth agent)
    api_checks.py                                             # C3 (API agent)
    passive_checks.py exposed_files.py param_probe.py         # shared detection
    correlate.py                                              # C4 (orchestrator)
    validate_findings.py report.py                            # C4a/C5
  references/
    attack-chains.md checks-auth.md checks-api.md checks-business-logic.md
    checks-unauth.md severity.md scope-template.md
    agents/ orchestrator.md recon.md auth.md api.md logic.md validation.md risk.md reporting.md review.md
  schema/ findings.schema.json chains.schema.json
  tests/ …
```

---

## 11. Sequencing & dependency on the audit

AUDIT P0 items are **prerequisites** — correlation and chain execution on unreliable findings fabricate
or miss chains, and chain execution is the most attacker-like behaviour here.

| Must land first (AUDIT) | Why |
|---|---|
| S1–S3, S7, R1–R4 | Every agent uses the scoped client; execution must be in-scope + leak-free |
| A1–A8 | Wrong asset/endpoint labels → wrong graph edges |
| P1–P2 | Correlation consumes verified findings; orchestrator-as-sole-writer resolves P1 |
| Schema enrichment (§7.2) | No capability primitives → nothing to correlate |

Phasing:
- **A — Foundation** (+AUDIT P0): shared `common/`, capability vocab, scripts emit new fields, recon
  templating + `id_shape`, actor canaries, orchestrator skeleton + state ownership.
- **B — Correlation brain + multi-agent core** (no new active behaviour): `correlate.py`, `chains.json`,
  `attack-chains.md`, orchestrator fan-out to Recon/Auth/API + Validation + Risk + Reporting + Review,
  chain-first report. *Evaluate chain quality + agent orchestration on the test app here.*
- **C — Component depth**: `auth_probe.py`, `session_checks.py`, `api_checks.py`, Logic agent,
  business-logic refs, tool ingest.
- **D — Chain execution + advanced**: `authz_replay --chain`, extractors, `allow_token_forge`,
  baseline/regression, OAuth/SAML, confirmed-only-after-execution.

Recommend **A + B first**: the orchestrator + specialist roster + correlation brain, zero new active
behaviour, so you see both the chain output *and* the multi-agent orchestration before any execution.

---

## 12. Decisions I need from you

1. **Positioning:** agree the framework orchestrates + ingests other scanners rather than
   re-implementing checks? (→ `import_scan.py` in C1.)
2. **Exploitation boundary:** keep read-only-default + prove-don't-exploit, active steps gated behind
   `allow_token_forge` / `allow_active_exploit`? Or a fuller active mode (changes safety/legal posture)?
3. **Correlation agent:** keep correlation inside the orchestrator (global context), or split it into a
   dedicated Correlation agent?
4. **Logic agent default:** auto-spawn it only when recon detects real workflows (carts, multi-step
   forms, state machines), or always offer it? (You leaned toward optional — I've made it conditional.)
5. **Standard to speak:** map findings/chains to OWASP WSTG IDs + MITRE ATT&CK / CAPEC for portable
   reports, or keep our own vocabulary?
6. **Build scope:** A+B first (recommended), or commit A–D up front?
7. **AUDIT relationship:** one programme (fold in P0 prerequisites), or land AUDIT fixes as a separate
   pass first?

---

*End of proposal. Supersedes the earlier attack-chains and framework notes.*
