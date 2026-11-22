#!/usr/bin/env python3
"""Attack-chain correlation (Phase B, Component 4) — the centrepiece.

Deterministic, NO network. Reads findings.json, builds a capability graph where each
finding is a node carrying its grants/requires/assets/id_shape/chain_role, draws an edge
A->B when a token A *grants* satisfies a token B *requires* (on a shared asset class, or
when B only needs an identity/none), finds anonymous->high-value paths, matches them
against a stable pattern library, and emits candidate chains in the canonical chains.json
shape for the agent to verify in Phase 4.5.

Design doc: DESIGN-framework.md s7. Vocabulary + chains.json shape: scratchpad/CONTRACT.md.

Usage:
  python3 correlate.py --findings <out>/findings.json --out <out> [--recon <out>/recon.json]

High recall by design: this *proposes* chains (status candidate, confidence tentative,
verification.executed false); the agent disposes. combined_impact / remediation_priority
are STUBS the agent rewrites in prose during Phase 4.5.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402
from common import now_iso, slug, shash, asset_of, id_shape_of  # noqa: E402

# ------------------------------------------------------------------ severity ladder
SEV_ORDER = ["info", "low", "medium", "high", "critical"]


def sev_index(s: str) -> int:
    try:
        return SEV_ORDER.index(s)
    except ValueError:
        return 0


def bump(s: str, n: int = 1) -> str:
    return SEV_ORDER[min(len(SEV_ORDER) - 1, max(0, sev_index(s) + n))]


# ------------------------------------------------------------------ high-value grants (targets)
TARGET_GRANTS = {
    "read:any-user", "read:admin", "write:admin", "write:other-user",
    "identity:assume-admin", "identity:assume-user", "knowledge:secret", "exec:code",
}
# Grants that justify a severity bump when reached anywhere in the chain.
SEVERE_GRANTS = {
    "read:any-user", "write:admin", "write:other-user", "exec:code",
    "identity:assume-admin", "identity:assume-user", "knowledge:secret",
}

# ------------------------------------------------------------------ grant -> requires satisfaction
# A requirement token is "satisfied" by a grant token either directly (same token, e.g.
# knowledge:user-ids) or through a small, explicit hierarchy: reading/writing as a user,
# stealing/forging a session, or assuming an identity all establish an identity context;
# assuming/writing as admin establishes an admin context; session/token grants hold a token.
_IDENTITY_USER_GRANTS = {
    "identity:assume-user", "identity:assume-admin",
    "read:other-user", "read:any-user", "read:admin",
    "write:other-user", "write:admin",
    "session:steal", "session:fixate", "token:forge",
}
# token:no-expiry means an existing token is long-lived — it does NOT, on its own, make the
# attacker a user, so it must not establish identity:user (prevents nonsense token->token edges).
_IDENTITY_ADMIN_GRANTS = {"identity:assume-admin", "read:admin", "write:admin"}
_TOKEN_GRANTS = {"session:steal", "session:fixate", "token:forge", "token:no-expiry"}
_IDENTITY_OR_NONE = {"none", "identity:user", "identity:admin"}


def satisfies(req: str, grants: set) -> bool:
    if req == "none":
        return True
    if req in grants:  # direct match (covers every knowledge:* token)
        return True
    if req == "identity:user":
        return bool(grants & _IDENTITY_USER_GRANTS)
    if req == "identity:admin":
        return bool(grants & _IDENTITY_ADMIN_GRANTS)
    if req == "holds:token":
        return bool(grants & _TOKEN_GRANTS)
    return False


# ------------------------------------------------------------------ chain_role -> kill_chain phase
ROLE_PHASE = {
    "disclosure": "information-disclosure",
    "authz": "authorization-weakness",
    "privilege": "privilege-boundary-failure",
    "session": "session-weakness",
    "injection": "injection",
    "standalone": "business-logic",
}


class Node:
    __slots__ = ("id", "title", "severity", "grants", "requires", "assets",
                 "id_shape", "chain_role", "auth_context", "category", "url")

    def __init__(self, f: dict):
        self.id = f.get("id", "")
        self.title = f.get("title", self.id)
        self.severity = f.get("severity", "info")
        self.grants = set(f.get("grants") or [])
        self.requires = list(f.get("requires") or [])
        self.assets = set(f.get("assets") or [])
        self.id_shape = f.get("id_shape")
        self.chain_role = f.get("chain_role")
        self.auth_context = f.get("auth_context")
        self.category = f.get("category")
        self.url = f.get("url", "")

    # Sequential IDs are guessable: a finding exposing them hands the anonymous attacker
    # knowledge:user-ids for free, exactly like a disclosure.
    def effective_grants(self) -> set:
        g = set(self.grants)
        if self.id_shape == "sequential":
            g.add("knowledge:user-ids")
        return g

    def is_entry(self) -> bool:
        return ("none" in self.requires or not self.requires
                or self.chain_role == "disclosure"
                or self.auth_context == "anonymous")

    def is_target(self) -> bool:
        return bool(self.effective_grants() & TARGET_GRANTS)


def enrich(f: dict) -> None:
    """Deterministic, offline backfill of asset/id_shape from the finding URL when a
    detector left them off — pure heuristics from common.py, never network."""
    url = f.get("url") or ""
    if url:
        if not f.get("assets"):
            a = asset_of(url)
            if a:
                f["assets"] = [a]
        if not f.get("id_shape"):
            shp = id_shape_of(url)
            if shp and shp != "none":
                f["id_shape"] = shp


def has_edge(a: Node, b: Node):
    """Return the set of satisfied (non-none) requirement tokens for edge a->b, or None."""
    a_grants = a.effective_grants()
    b_req = b.requires or ["none"]
    satisfied = {r for r in b_req if r != "none" and satisfies(r, a_grants)}
    if not satisfied:
        return None
    only_identity_or_none = all(r in _IDENTITY_OR_NONE for r in b_req)
    # Asset gate: knowledge that only needs identity is asset-agnostic; an asset-less
    # disclosure (or target) is treated as global knowledge; otherwise require overlap.
    asset_ok = (only_identity_or_none or not a.assets or not b.assets
                or bool(a.assets & b.assets))
    return satisfied if asset_ok else None


def find_paths(nodes, edges, max_len=4):
    """All simple paths entry->...->target, each terminating at a target node (len>=2)."""
    entries = [n.id for n in nodes.values() if n.is_entry()]
    targets = {n.id for n in nodes.values() if n.is_target()}
    paths = []

    def dfs(path):
        if len(path) >= 2 and path[-1] in targets:
            paths.append(list(path))
        if len(path) >= max_len:
            return
        for nxt in edges.get(path[-1], ()):
            if nxt not in path:  # simple path, no cycles
                path.append(nxt)
                dfs(path)
                path.pop()

    for e in entries:
        dfs([e])
    return paths


def dedupe(paths, nodes, cap=12):
    """Keep DISTINCT attack chains without flooding. (1) one representative per node-set;
    (2) drop any chain whose node-set is a strict subset of another's; (3) because many
    entries can reach the same terminal privilege (every 'become a user' finding reaches a
    forgeable-admin token), collapse by (terminal, entry chain_role) and keep the longest
    representative of each — so distinct attack *narratives* survive (enumerate→reset→forge,
    IDOR→forge, BFLA→forge, fixation→forge, xss→forge) but near-duplicates don't."""
    uniq = {tuple(p): p for p in paths}
    by_set: dict = {}
    for key in uniq:
        fs = frozenset(key)
        if fs not in by_set or (len(key), key) < (len(by_set[fs]), tuple(by_set[fs])):
            by_set[fs] = uniq[key]
    sets = list(by_set.keys())
    kept = [p for fs, p in by_set.items() if not any(fs < other for other in sets)]

    def entry_role(p):
        n = nodes.get(p[0])
        return getattr(n, "chain_role", None) or "other"
    groups: dict = {}
    for p in kept:
        gk = (p[-1], entry_role(p))
        cur = groups.get(gk)
        if cur is None or (len(p), tuple(p)) > (len(cur), tuple(cur)):
            groups[gk] = p
    return sorted(groups.values(), key=lambda p: (-len(p), tuple(p)))[:cap]


# ------------------------------------------------------------------ pattern library
# Slugs are STABLE (referenced in chains.json `pattern` and documented in
# references/attack-chains.md). Matched first-wins, most specific first.
def match_pattern(chain):
    all_grants = set().union(*[n.effective_grants() for n in chain]) if chain else set()
    has_authz = any(n.chain_role == "authz"
                    or (n.effective_grants() & {"read:any-user", "read:other-user",
                                                "write:other-user"}) for n in chain)
    has_priv = any(n.chain_role == "privilege"
                   or (n.effective_grants() & {"identity:assume-admin", "read:admin",
                                               "write:admin"}) for n in chain)

    if "session:steal" in all_grants:
        return "xss-to-session"
    if "session:fixate" in all_grants:
        return "fixation-to-takeover"
    if (all_grants & {"token:forge", "token:no-expiry"}) and \
            (all_grants & {"identity:assume-user", "identity:assume-admin"}):
        return "reset-flow-bypass"
    if has_authz and has_priv:
        return "horizontal-to-vertical"
    if "knowledge:secret" in all_grants and \
            (all_grants & {"identity:assume-admin", "identity:assume-user",
                           "write:admin", "write:other-user", "exec:code"}):
        return "disclosure-to-takeover"
    if (all_grants & {"knowledge:schema", "knowledge:endpoint"}) and \
            (all_grants & {"read:any-user", "read:other-user", "read:admin"}):
        return "schema-to-bola"
    if (all_grants & {"knowledge:user-ids", "knowledge:usernames"}) and \
            (all_grants & {"read:any-user", "read:other-user"}):
        return "enumerate-then-idor"
    if (all_grants & {"read:any-user", "write:other-user"}) and \
            any("account" in n.assets or "tenant" in n.assets for n in chain):
        return "tenant-break"
    return None


PATTERN_TITLE = {
    "enumerate-then-idor": "Leaked identifiers enable cross-user object access (IDOR)",
    "schema-to-bola": "Exposed schema enables broken object-level authorization",
    "disclosure-to-takeover": "Leaked secret enables account/system takeover",
    "reset-flow-bypass": "Token weakness bypasses the recovery flow to seize an account",
    "horizontal-to-vertical": "Cross-user access escalates to administrative control",
    "xss-to-session": "Reflected XSS enables session theft and account takeover",
    "fixation-to-takeover": "Session fixation enables account takeover",
    "tenant-break": "Cross-tenant access breaks isolation boundaries",
}


def phase_for(node: Node) -> str:
    return ROLE_PHASE.get(node.chain_role or "", "business-logic")


def step_narrative(node: Node, satisfied, idx) -> str:
    g = ", ".join(sorted(node.effective_grants())) or "no new capability"
    if idx == 0:
        pre = ("Reachable anonymously" if node.auth_context == "anonymous"
               or "none" in node.requires or not node.requires else "Starting point")
        return f"{pre}: {node.title}. Grants {g}."
    used = ", ".join(sorted(satisfied)) if satisfied else "the prior step's access"
    return f"Using {used} from the previous step: {node.title}. Grants {g}."


def build_chain(path, nodes, seen_ids):
    chain = [nodes[i] for i in path]
    # per-step satisfied-requirements (for narratives)
    sats = [set()]
    for a, b in zip(chain, chain[1:]):
        sats.append(has_edge(a, b) or set())

    pattern = match_pattern(chain)

    # Combined severity: max step severity, +1 if a privilege boundary is crossed OR a
    # severe grant (read:any-user / write:*) is reached. Cap at critical.
    max_sev = max((n.severity for n in chain), key=sev_index) if chain else "info"
    all_grants = set().union(*[n.effective_grants() for n in chain])
    crosses_priv = any(n.chain_role == "privilege" for n in chain)
    reaches_severe = bool(all_grants & SEVERE_GRANTS)
    combined_sev = bump(max_sev, 1) if (crosses_priv or reaches_severe) else max_sev

    kill_chain = []
    for idx, n in enumerate(chain):
        step = {
            "step": idx + 1,
            "phase": phase_for(n),
            "finding": n.id,
            "grants": sorted(n.effective_grants()),
            "requires": [r for r in n.requires if r != "none"],
            "narrative": step_narrative(n, sats[idx], idx),
        }
        kill_chain.append(step)

    entry = chain[0]
    terminal = chain[-1]
    entry_ctx = entry.auth_context or ("anonymous" if entry.is_entry() else "a low-privilege user")
    term_grants = ", ".join(sorted(terminal.effective_grants() & TARGET_GRANTS)) \
        or ", ".join(sorted(terminal.effective_grants())) or "elevated access"

    # Stable id: CHAIN-<pattern-or-grant>-<hash-of-path>.
    base = pattern or (slug(term_grants, 24) or "chain")
    cid = f"CHAIN-{slug(base, 40)}-{shash('>'.join(path))}"
    while cid in seen_ids:  # collision guard (deterministic)
        cid = f"CHAIN-{slug(base, 40)}-{shash(cid)}"
    seen_ids.add(cid)

    title = PATTERN_TITLE.get(pattern) or \
        f"{len(chain)}-step chain from {entry_ctx} to {term_grants}"

    # STUBS — the agent rewrites these in prose during Phase 4.5.
    combined_impact = (
        f"STUB (agent rewrites in Phase 4.5): starting from {entry_ctx}, an attacker chains "
        f"{len(chain)} findings ({' -> '.join(p for p in path)}) to reach {term_grants}. "
        f"Rate on the worst outcome from the lowest privilege in the chain."
    )
    remediation_priority = (
        f"STUB (cheapest cut): fix the earliest step {entry.id} ({entry.title}) — breaking "
        f"step 1 collapses the whole chain at lowest cost. Agent to confirm the single "
        f"highest-value cut in Phase 4.5."
    )
    preconditions = (
        f"Attacker begins as {entry_ctx}. "
        + ("No prior credentials required." if entry.is_entry() and entry.auth_context in (None, "anonymous")
           else "Requires the starting context above.")
    )

    out = {
        "id": cid,
        "title": title,
        "status": "candidate",
        "confidence": "tentative",
        "severity": combined_sev,
        "kill_chain": kill_chain,
        "combined_impact": combined_impact,
        "preconditions": preconditions,
        "remediation_priority": remediation_priority,
        "verification": {"executed": False, "actor_path": [], "steps": [],
                         "evidence_refs": [], "notes": ""},
    }
    if pattern:
        out["pattern"] = pattern
    return out


def main():
    ap = argparse.ArgumentParser(description="Deterministic attack-chain correlation (no network).")
    ap.add_argument("--findings", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--recon", help="optional recon.json for asset/id_shape context")
    a = ap.parse_args()

    try:
        with open(a.findings, encoding="utf-8") as f:
            doc = json.load(f)
    except FileNotFoundError:
        sys.exit(f"findings.json not found: {a.findings}")
    except json.JSONDecodeError as e:
        sys.exit(f"findings.json is not valid JSON: {e}")

    target = doc.get("target", "")
    raw = list(doc.get("findings") or [])

    # Optional recon context: a {url: {asset|assets, id_shape}} map backfills missing fields.
    recon_map = {}
    if a.recon and os.path.exists(a.recon):
        try:
            with open(a.recon, encoding="utf-8") as f:
                rec = json.load(f)
            for ep in (rec.get("endpoints") or rec.get("urls") or []):
                if isinstance(ep, dict) and ep.get("url"):
                    recon_map[ep["url"]] = ep
        except (json.JSONDecodeError, OSError):
            pass  # recon is best-effort context only

    # Build nodes (consider only candidate/verified findings — rejected ones don't chain).
    nodes = {}
    cap_count = 0
    for f in raw:
        if f.get("status") == "rejected":
            continue
        if not f.get("id"):
            continue
        hint = recon_map.get(f.get("url"))
        if hint:
            if not f.get("assets"):
                av = hint.get("assets") or ([hint["asset"]] if hint.get("asset") else None)
                if av:
                    f["assets"] = av
            if not f.get("id_shape") and hint.get("id_shape"):
                f["id_shape"] = hint["id_shape"]
        enrich(f)
        n = Node(f)
        if n.grants or n.requires or n.id_shape == "sequential":
            cap_count += 1
        nodes[n.id] = n

    out_path = os.path.join(a.out, "chains.json")
    os.makedirs(a.out, exist_ok=True)

    if cap_count == 0:
        _write(out_path, target, [])
        print("0 candidate chains: no findings carry capability fields "
              "(grants/requires/id_shape). Nothing to correlate. -> " + out_path)
        return

    # Edges: adjacency id -> [ids].
    edges = {}
    node_list = list(nodes.values())
    for a_node in node_list:
        for b_node in node_list:
            if a_node.id == b_node.id:
                continue
            if has_edge(a_node, b_node) is not None:
                edges.setdefault(a_node.id, []).append(b_node.id)
    for k in edges:
        edges[k].sort()

    paths = find_paths(nodes, edges, max_len=4)
    paths = dedupe(paths, nodes)

    seen_ids = set()
    chains = [build_chain(p, nodes, seen_ids) for p in paths]
    chains.sort(key=lambda c: (-sev_index(c["severity"]), c["id"]))

    _write(out_path, target, chains)

    print(f"{len(chains)} candidate chain(s) -> {out_path}")
    for c in chains[:15]:
        print(f"  {c['id']} | {c['severity']} | {len(c['kill_chain'])} steps | "
              f"{c.get('pattern', 'no-pattern')}")


def _write(path, target, chains):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"target": target, "generated_at": now_iso(), "chains": chains}, f, indent=2)


if __name__ == "__main__":
    main()
