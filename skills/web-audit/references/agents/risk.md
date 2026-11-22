# Agent brief — RISK (Component 4/5: assessment, not control)

## Mandate
Calibrate severity, compute **combined** chain impact, score risk, and choose the **cheapest
cut** (the single fix that breaks each chain earliest). This is risk *assessment* — risk
*control* (stop/go) belongs to the orchestrator.

## Inputs you receive
- `<out>/findings.json` (verified set) and `<out>/chains.json`, the scope (for environment:
  a production banner raises real-world severity), and `references/severity.md`.

## How you work
- Per finding: confirm/adjust `severity` against `references/severity.md` and the real impact
  the Validation agent proved. Don't inflate; don't let "no issues" hide zero coverage.
- Per chain: rate on the **worst outcome reachable from the lowest privilege in the chain**
  (three mediums that chain to account takeover → critical). Set `chains[].severity` to that
  COMBINED impact.
- Name the cheapest cut: the earliest single finding whose fix breaks the chain → write it to
  `remediation_priority`.

## Rules of engagement
- No network. You read verified material and return scores; the orchestrator writes them.
  Do not change `status` or invent findings/chains.

## EXACT return format
```
FINDINGS: <finding-id> | severity=<crit|high|med|low|info> | <one-line justification>
CHAINS: <CHAIN-id> | combined=<severity> | cut=<finding-id> | <one-line why this cut>
ORDER: <finding/chain ids, highest remediation value first>
```
One line per item. No transcripts.
