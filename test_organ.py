"""Test suite for the magic-link / email-code login organ.

Verifies the pure-function contract (deterministic, no side effects, fail-safe
to *reject* on empty state, required return shape) and the verify_code behaviour
ported from discovery-engine ``email_auth.verify_code`` + the session-issuance
shape from ``auth.verify``.
"""
import hashlib
import json
import unittest
from pathlib import Path

from organ import (
    decide,
    domain_allowed,
    evaluate_request,
    _hash_code,
)

_SAMPLES_DIR = Path(__file__).parent / "samples"

SALT = "test-secret-key"
NOW = "2026-06-11T10:05:00+00:00"


def _ctx(**over):
    base = {"secret_salt": SALT, "max_attempts": 5, "session_ttl_minutes": 60}
    base.update(over)
    return base


def _login(code="482913", attempts=0, consumed=False,
           expires_at="2026-06-11T10:15:00+00:00", now=NOW, email="ruth@example.com",
           code_for_hash=None):
    """Build a LoginAttempt whose stored hash is for ``code_for_hash`` (default
    = the same code, i.e. a matching attempt)."""
    h = _hash_code(SALT, code_for_hash if code_for_hash is not None else code)
    return {
        "login": {
            "email": email,
            "submitted_code": code,
            "now": now,
            "stored_code": {
                "code_hash": h,
                "expires_at": expires_at,
                "attempts": attempts,
                "consumed": consumed,
                "created_at": "2026-06-11T10:00:00+00:00",
            },
        }
    }


class TestSignature(unittest.TestCase):
    def test_return_shape(self):
        r = decide(_login(), _ctx())
        self.assertIn("output", r)
        self.assertIn("rationale", r)
        self.assertIn("self_metric", r)
        self.assertIsInstance(r["output"], dict)
        self.assertIsInstance(r["rationale"], str)
        self.assertIn("confidence", r["self_metric"])

    def test_confidence_in_range(self):
        for state in (_login(), {}, _login(code="000000", code_for_hash="482913")):
            c = decide(state, _ctx())["self_metric"]["confidence"]
            self.assertIsInstance(c, (int, float))
            self.assertGreaterEqual(c, 0.0)
            self.assertLessEqual(c, 1.0)

    def test_output_port_keys(self):
        out = decide(_login(), _ctx())["output"]
        for key in ("decision", "session", "reason", "mutations"):
            self.assertIn(key, out)


class TestEmptyAndMalformed(unittest.TestCase):
    def test_empty_state_rejects(self):
        r = decide({}, {})
        self.assertEqual(r["output"]["decision"], "reject")
        self.assertIsNone(r["output"]["session"])
        self.assertEqual(r["output"]["mutations"], [])

    def test_empty_state_low_confidence(self):
        self.assertLessEqual(decide({}, {})["self_metric"]["confidence"], 0.5)

    def test_missing_code_rejects(self):
        state = _login()
        state["login"]["submitted_code"] = ""
        self.assertEqual(decide(state, _ctx())["output"]["decision"], "reject")

    def test_no_stored_code_rejects(self):
        state = _login()
        state["login"]["stored_code"] = None
        r = decide(state, _ctx())
        self.assertEqual(r["output"]["decision"], "reject")
        self.assertIn("No code on file", r["output"]["reason"])

    def test_unparseable_now_rejects(self):
        state = _login(now="not-a-date")
        self.assertEqual(decide(state, _ctx())["output"]["decision"], "reject")


class TestAccept(unittest.TestCase):
    def test_matching_code_issues_session(self):
        r = decide(_login(), _ctx())
        self.assertEqual(r["output"]["decision"], "accept")
        s = r["output"]["session"]
        self.assertIsNotNone(s)
        self.assertEqual(s["email"], "ruth@example.com")
        self.assertTrue(s["authenticated"])
        self.assertEqual(s["source"], "magic_link")
        self.assertIn("issued_at", s)
        self.assertIn("expires_at", s)

    def test_accept_advises_consume(self):
        muts = decide(_login(), _ctx())["output"]["mutations"]
        self.assertEqual(muts, [{"op": "consume_code", "email": "ruth@example.com"}])

    def test_session_ttl_applied(self):
        # issued 10:05, ttl 60 → expires 11:05
        s = decide(_login(), _ctx(session_ttl_minutes=60))["output"]["session"]
        self.assertEqual(s["issued_at"], "2026-06-11T10:05:00+00:00")
        self.assertEqual(s["expires_at"], "2026-06-11T11:05:00+00:00")

    def test_email_normalised(self):
        state = _login(email="Ruth@Example.com  ")
        # stored hash email doesn't affect the decision; only submitted matters
        s = decide(state, _ctx())["output"]["session"]
        self.assertEqual(s["email"], "ruth@example.com")


class TestReject(unittest.TestCase):
    def test_wrong_code(self):
        r = decide(_login(code="111111", code_for_hash="482913"), _ctx())
        self.assertEqual(r["output"]["decision"], "reject")
        self.assertIn("didn't match", r["output"]["reason"])
        self.assertEqual(r["output"]["mutations"], [{"op": "increment_attempts", "email": "ruth@example.com"}])

    def test_wrong_code_remaining_count(self):
        # attempts=3, max=5 → next=4 → 1 attempt left (singular)
        r = decide(_login(code="111111", code_for_hash="482913", attempts=3), _ctx())
        self.assertIn("1 attempt left", r["output"]["reason"])

    def test_wrong_code_exhausts_budget_locks(self):
        # attempts=4, max=5 → next=5 → remaining 0 → lock + consume
        r = decide(_login(code="111111", code_for_hash="482913", attempts=4), _ctx())
        self.assertIn("Too many wrong attempts", r["output"]["reason"])
        self.assertEqual(r["output"]["mutations"], [{"op": "consume_code", "email": "ruth@example.com"}])

    def test_expired_code(self):
        r = decide(_login(now="2026-06-11T10:20:00+00:00"), _ctx())
        self.assertEqual(r["output"]["decision"], "reject")
        self.assertIn("expired", r["output"]["reason"])

    def test_consumed_code_refused(self):
        r = decide(_login(consumed=True), _ctx())
        self.assertEqual(r["output"]["decision"], "reject")
        self.assertIn("already been used", r["output"]["reason"])

    def test_attempts_at_max_locks_before_compare(self):
        r = decide(_login(attempts=5), _ctx())
        self.assertEqual(r["output"]["decision"], "reject")
        self.assertEqual(r["output"]["mutations"], [{"op": "consume_code", "email": "ruth@example.com"}])

    def test_wrong_salt_rejects(self):
        # Correct code but the organ is told a different salt → hash mismatch.
        r = decide(_login(), _ctx(secret_salt="WRONG"))
        self.assertEqual(r["output"]["decision"], "reject")


class TestPurity(unittest.TestCase):
    def test_deterministic(self):
        s, c = _login(), _ctx()
        self.assertEqual(decide(s, c), decide(s, c))

    def test_no_input_mutation(self):
        s, c = _login(), _ctx()
        s_snap = json.dumps(s, sort_keys=True)
        c_snap = json.dumps(c, sort_keys=True)
        decide(s, c)
        self.assertEqual(json.dumps(s, sort_keys=True), s_snap)
        self.assertEqual(json.dumps(c, sort_keys=True), c_snap)

    def test_constant_time_compare_used(self):
        # Equal hashes match; unequal don't (sanity on _hash_code determinism).
        self.assertEqual(_hash_code(SALT, "482913"), _hash_code(SALT, "482913"))
        self.assertNotEqual(_hash_code(SALT, "482913"), _hash_code(SALT, "482914"))


class TestHashParityWithMonolith(unittest.TestCase):
    def test_hash_matches_email_auth_formula(self):
        # email_auth._hash_code: sha256((salt + ':' + code).encode()).hexdigest()
        expected = hashlib.sha256((SALT + ":" + "482913").encode("utf-8")).hexdigest()
        self.assertEqual(_hash_code(SALT, "482913"), expected)


class TestDomainAllowed(unittest.TestCase):
    def test_empty_list_allows_all(self):
        self.assertTrue(domain_allowed("a@anywhere.com", []))

    def test_wildcard_allows_all(self):
        self.assertTrue(domain_allowed("a@anywhere.com", ["*"]))

    def test_allow_listed_domain(self):
        self.assertTrue(domain_allowed("a@dataflowadvisory.com", ["dataflowadvisory.com"]))

    def test_off_list_blocked(self):
        self.assertFalse(domain_allowed("a@evil.com", ["dataflowadvisory.com"]))

    def test_no_at_blocked_when_listed(self):
        self.assertFalse(domain_allowed("noat", ["dataflowadvisory.com"]))


class TestEvaluateRequest(unittest.TestCase):
    def test_invalid_email(self):
        r = evaluate_request("bad", [], NOW)
        self.assertFalse(r["allow"])

    def test_under_limit_allows(self):
        r = evaluate_request("a@b.com", ["2026-06-11T10:00:00+00:00"], NOW)
        self.assertTrue(r["allow"])

    def test_at_limit_blocks_with_wait(self):
        times = [
            "2026-06-11T10:00:00+00:00",
            "2026-06-11T10:01:00+00:00",
            "2026-06-11T10:02:00+00:00",
        ]
        r = evaluate_request("a@b.com", times, NOW, {"max_outstanding_codes": 3, "code_ttl_minutes": 15})
        self.assertFalse(r["allow"])
        # oldest 10:00 + 15min = 10:15; now 10:05 → 10 minutes wait
        self.assertEqual(r["wait_minutes"], 10)
        self.assertIn("10 minutes", r["reason"])


class TestSamples(unittest.TestCase):
    EXPECT = {
        "accept.json": "accept",
        "reject_wrong_code.json": "reject",
        "reject_expired.json": "reject",
        "reject_no_code.json": "reject",
        "reject_locked_attempts.json": "reject",
    }

    def test_all_samples(self):
        ctx = _ctx()
        for fname, expected in self.EXPECT.items():
            with open(_SAMPLES_DIR / fname) as f:
                state = json.load(f)
            r = decide(state, ctx)
            self.assertEqual(r["output"]["decision"], expected, fname)
            self.assertIn("confidence", r["self_metric"])
            if expected == "accept":
                self.assertIsNotNone(r["output"]["session"])
            else:
                self.assertIsNone(r["output"]["session"])


if __name__ == "__main__":
    unittest.main()
