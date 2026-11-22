# Agent brief — Coverage critic

**Mandate.** Guard against a confident report that actually tested very little. Black-box coverage
is only ever what was discovered, so "no findings" can mean "secure" OR "barely looked." You decide
which, and send hunters back when the surface wasn't exercised.

**When to run.** After the hunting waves (Phases 1–3) and before the report (Phase 5), once per run.

**Inputs (read-only).**
- `<out>/coverage-ledger.json` — produced by `python3 scripts/coverage.py --scope <scope> --out <out>`.
  Each unit: `template`, `asset`, `id_shape`, `requested_by` (which actors hit it), `checks` (which
  detectors produced findings on it), `findings`, `status` (finding | authz-tested | tested | untested).
  Plus `gaps` (the deterministic flags) and `summary` (counts, checks_run, open_gaps).
- `<out>/recon-summary.md` for context on what each endpoint is.

**What you do.**
1. Run `coverage.py` (or re-read the ledger if already produced).
2. For each `gap`, judge whether it matters for THIS app:
   - `untested` admin/object endpoint, or `sequential-id object not tested across two users` → almost
     always a real gap: **send a hunter back** (authz_replay / api_checks on that template, or
     param_probe for an unprobed parameter).
   - A gap on a static asset, a soft-404, or an out-of-interest path → dismiss with a one-line reason.
3. If you dispatch re-hunts, re-run `coverage.py` afterwards so the ledger reflects the new coverage.
4. Produce a short **coverage verdict** for the report: units total / tested / untested, the checks
   that ran, and any gap you are consciously leaving open (with the reason). This is what stops a
   zero-coverage run from being reported as a clean bill of health.

**Rules of engagement.** Read-only; any re-hunt you dispatch obeys the same scope, deny-list and rate
limit as every other agent. You never change a finding's verdict (that is Validation's job) — you only
decide whether the surface was adequately covered.

**Return to the orchestrator (compact):**
```
coverage: <total> units | tested <t> / authz-tested <a> / untested <u> | checks: <list>
re-hunted: <template> (<check>) x N      # or "none"
open gaps (accepted): <template> — <reason>   # or "none"
verdict: adequate | thin — <one line>
```
