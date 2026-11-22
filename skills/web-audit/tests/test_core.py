#!/usr/bin/env python3
"""Unit tests for the FROZEN scripts/common.py core: scope enforcement, path
normalisation, the state-changing deny-list, redaction, and the concurrency-safe
Findings merge. Pure stdlib (unittest) so it runs with `python3 tests/test_core.py`
and is also collected by pytest if present. No network.
"""
import json
import os
import sys
import tempfile
import unittest

# Import the frozen core by putting scripts/ on the path.
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "scripts"))
import common  # noqa: E402


def _scope(**over):
    """Build a Scope from a minimal valid scope dict written to a temp file."""
    base = {
        "target": "http://target.example:8088",
        "allowed_hosts": ["target.example"],
        "environment": "test",
        "authorization": {"authorized_by": "owner", "reference": "ticket-1"},
        "mode": "both",
        "max_rps": 5,
        "excluded_paths": [],
    }
    base.update(over)
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(base, f)
    return common.Scope(path)


class TestScopeRejection(unittest.TestCase):
    def setUp(self):
        self.s = _scope()

    def test_backslash_host_confusion(self):
        # urllib3 parses the real socket host; backslash is an illegal char → rejected.
        with self.assertRaises(common.ScopeError):
            self.s.check("http://target.example\\@evil.com/x", "GET")
        self.assertFalse(self.s.in_scope("http://target.example\\@evil.com/x"))

    def test_userinfo_rejected(self):
        # user:pass@host can smuggle creds / confuse the host — never allowed.
        with self.assertRaises(common.ScopeError):
            self.s.check("http://user:pass@target.example/x", "GET")
        self.assertFalse(self.s.in_scope("http://user:pass@target.example/x"))

    def test_bad_port_rejected(self):
        # allowed_ports = {8088, 80, 443}; 9999 is not allowed.
        with self.assertRaises(common.ScopeError):
            self.s.check("http://target.example:9999/x", "GET")
        self.assertFalse(self.s.in_scope("http://target.example:9999/x"))

    def test_off_host_rejected(self):
        with self.assertRaises(common.ScopeError):
            self.s.check("http://evil.example:8088/x", "GET")
        self.assertFalse(self.s.in_scope("http://evil.example:8088/x"))

    def test_in_scope_accepts_target(self):
        self.assertTrue(self.s.in_scope("http://target.example:8088/orders/1"))
        self.s.check("http://target.example:8088/orders/1", "GET")  # must not raise


class TestExcludedPathNormalisation(unittest.TestCase):
    def setUp(self):
        self.s = _scope(excluded_paths=["/admin"])

    def test_variants_all_excluded(self):
        base = "http://target.example:8088"
        for variant in (
            "/admin",          # exact
            "/ADMIN",          # case
            "/admin/",         # trailing slash
            "/admin/users",    # subtree
            "/%61dmin",        # percent-encoded 'a'
            "/foo/../admin",   # dot-segment resolution
            "//admin",         # doubled slash
            "/admin;jsessionid=x",  # matrix param
        ):
            with self.subTest(variant=variant):
                self.assertTrue(self.s.excluded(base + variant),
                                f"{variant} should be excluded")

    def test_unrelated_not_excluded(self):
        self.assertFalse(self.s.excluded("http://target.example:8088/administrators-public"))
        self.assertFalse(self.s.excluded("http://target.example:8088/public"))


class TestDenyListStateChanging(unittest.TestCase):
    def setUp(self):
        self.s = _scope()  # allow_state_changing defaults to False

    def test_logout_get_blocked(self):
        self.assertTrue(self.s.state_changing_path("http://target.example:8088/logout"))
        with self.assertRaises(common.ScopeError):
            self.s.check("http://target.example:8088/logout", "GET")

    def test_nested_delete_get_blocked(self):
        self.assertTrue(self.s.state_changing_path("http://target.example:8088/x/delete"))
        with self.assertRaises(common.ScopeError):
            self.s.check("http://target.example:8088/x/delete", "GET")

    def test_benign_get_allowed(self):
        self.s.check("http://target.example:8088/orders/1", "GET")  # must not raise

    def test_allowed_when_flag_set(self):
        s = _scope(allow_state_changing=True)
        # With the flag on, the deny-list no longer blocks it.
        s.check("http://target.example:8088/x/delete", "GET")  # must not raise


class TestRedaction(unittest.TestCase):
    def test_redact_cookie(self):
        out = common.redact("Cookie: session=supersecretvalue123")
        self.assertIn("****", out)
        self.assertNotIn("supersecretvalue123", out)

    def test_redact_bearer(self):
        out = common.redact("Authorization: Bearer abcdef0123456789token")
        self.assertIn("****", out)
        self.assertNotIn("abcdef0123456789token", out)

    def test_redact_url_token_param(self):
        out = common.redact_url("http://target.example:8088/cb?token=secretTOKENvalue&page=2")
        # urlencode escapes the mask, so accept either literal or percent-encoded ****.
        self.assertTrue("token=****" in out or "token=%2A%2A%2A%2A" in out, out)
        self.assertNotIn("secretTOKENvalue", out)
        self.assertIn("page=2", out)  # non-sensitive params preserved

    def test_redact_set_cookie(self):
        out = common.redact("Set-Cookie: sid=deadbeefdeadbeef; Path=/")
        self.assertIn("****", out)
        self.assertNotIn("deadbeefdeadbeef", out)


class TestFindingsConcurrentMerge(unittest.TestCase):
    def test_two_instances_both_survive(self):
        """Simulate concurrency sequentially: two Findings objects on the same out dir,
        each constructed before either saves, each adds a different id, both save —
        assert both ids are present (save() re-reads + merges under a lock)."""
        with tempfile.TemporaryDirectory() as d:
            target = "http://target.example:8088"
            f1 = common.Findings(d, target)
            f2 = common.Findings(d, target)  # both see an empty store at construction
            f1.add(id="HDR-missing-csp", title="a", severity="low",
                   confidence="firm", status="candidate", category="security-misconfiguration",
                   auth_context="anonymous", url=target + "/", description="x",
                   evidence={"request": "GET /"}, source="passive_checks")
            f2.add(id="AUTHZ-idor-orders", title="b", severity="high",
                   confidence="firm", status="candidate", category="broken-access-control",
                   auth_context="cross-user", url=target + "/orders/1", description="y",
                   evidence={"request": "GET /orders/1"}, source="authz_replay")
            f1.save()
            f2.save()  # must merge onto f1's already-written record, not clobber it
            with open(os.path.join(d, "findings.json"), encoding="utf-8") as fh:
                doc = json.load(fh)
            ids = {x["id"] for x in doc["findings"]}
            self.assertIn("HDR-missing-csp", ids)
            self.assertIn("AUTHZ-idor-orders", ids)
            self.assertEqual(len(doc["findings"]), 2)


class TestCapabilityFields(unittest.TestCase):
    def test_cap_fields_drops_unknown_tokens(self):
        out = common.cap_fields(grants=["read:any-user", "bogus:grant"],
                                requires=["knowledge:user-ids", "nope"],
                                assets=["order"], id_shape="sequential", chain_role="authz")
        self.assertEqual(out["grants"], ["read:any-user"])
        self.assertEqual(out["requires"], ["knowledge:user-ids"])
        self.assertEqual(out["assets"], ["order"])
        self.assertEqual(out["id_shape"], "sequential")
        self.assertEqual(out["chain_role"], "authz")

    def test_id_shape_of(self):
        self.assertEqual(common.id_shape_of("http://h/orders/42"), "sequential")
        self.assertEqual(common.id_shape_of(
            "http://h/orders/3fa85f64-5717-4562-b3fc-2c963f66afa6"), "uuid")
        self.assertEqual(common.id_shape_of("http://h/orders/mine"), "none")


if __name__ == "__main__":
    unittest.main(verbosity=2)
