"""acceptance_basis: the absence of criteria is a named state, and nobody may paper over it (backlog 150)."""
import hashlib
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import acceptance_basis as ab  # noqa: E402


def code(fn, *a, **k):
    try:
        fn(*a, **k)
    except ab.Refusal as e:
        return e.code
    return None


class T(unittest.TestCase):
    def test_none_stated_refuses_a_merchant_declarer(self):
        self.assertEqual(code(ab.acceptance_block, "none_stated", declarer="merchant"), "self_authored_acceptance_refused")

    def test_none_stated_refuses_a_payer_declarer(self):
        self.assertEqual(code(ab.acceptance_block, "none_stated", declarer="payer"), "self_authored_acceptance_refused")
        self.assertEqual(code(ab.acceptance_block, "none_stated", accepted=True), "self_authored_acceptance_refused")

    def test_none_stated_keeps_settlement_claim(self):
        self.assertTrue(ab.acceptance_block("none_stated")["settlement_claim_unaffected"])

    def test_accepted_is_null_not_false(self):
        self.assertIsNone(ab.acceptance_block("none_stated")["accepted"])

    def test_predicate_after_delivery_refused(self):
        p = {"predicate_id": "sha256-matches-declared-output", "stated_at": "2026-10-26T07:00:00Z"}
        self.assertEqual(code(ab.acceptance_block, "recomputable_property", predicate=p,
                              delivered_at="2026-10-26T06:00:00Z"), "predicate_stated_after_delivery")

    def test_predicate_expression_is_never_evaluated(self):
        marker = os.path.join(tempfile.mkdtemp(), "pwned")
        p = {"predicate_id": "sha256-matches-declared-output", "stated_at": "2026-10-26T05:00:00Z",
             "expression": "__import__('os').system('touch %s')" % marker}
        b = ab.acceptance_block("recomputable_property", predicate=p, delivered_at="2026-10-26T06:00:00Z")
        self.assertEqual(b["predicate"]["expression"], p["expression"])
        self.assertFalse(os.path.exists(marker))

    def test_unknown_predicate_id_refused(self):
        p = {"predicate_id": "vibes", "stated_at": "2026-10-26T05:00:00Z"}
        self.assertEqual(code(ab.acceptance_block, "recomputable_property", predicate=p,
                              delivered_at="2026-10-26T06:00:00Z"), "predicate_not_implemented")

    def test_recomputable_verdict_reproduces_for_a_third_party(self):
        data = b"deliverable"
        commit = hashlib.sha256(data).hexdigest()
        p = {"predicate_id": "sha256-matches-declared-output", "stated_at": "2026-10-26T05:00:00Z"}
        self.assertTrue(ab.recompute(p, data, commit))
        self.assertFalse(ab.recompute(p, b"other", commit))

    def test_recomputable_with_declarer_refused(self):
        p = {"predicate_id": "sha256-matches-declared-output", "stated_at": "2026-10-26T05:00:00Z"}
        self.assertEqual(code(ab.acceptance_block, "recomputable_property", declarer="x", predicate=p,
                              delivered_at="2026-10-26T06:00:00Z"), "declarer_not_permitted")

    def test_missing_basis_is_refused(self):
        self.assertEqual(code(ab.acceptance_block), "acceptance_basis_required")
        self.assertEqual(code(ab.acceptance_block, "trust_me"), "unknown_acceptance_basis")

    def test_committed_criteria_need_a_matching_hash(self):
        self.assertEqual(code(ab.acceptance_block, "criteria_committed_at_payment"), "criteria_hash_missing")
        self.assertEqual(code(ab.acceptance_block, "criteria_committed_at_payment", criteria_sha256="0" * 64,
                              criteria_bytes=b"x"), "criteria_hash_mismatch")
        h = hashlib.sha256(b"x").hexdigest()
        self.assertEqual(ab.acceptance_block("criteria_committed_at_payment", criteria_sha256=h,
                                             criteria_bytes=b"x")["criteria_sha256"], h)

    def test_our_three_jobs_each_carry_committed_criteria(self):
        jobs = json.load(open(os.path.join(ROOT, "jobs.json")))["jobs"]
        self.assertGreaterEqual(len(jobs), 3)
        for j in jobs:
            c = ab.classify_job(j)
            self.assertEqual(c["basis"], "criteria_committed_at_payment", j["id"])
            self.assertEqual(c["criteria_sha256"], ab.criteria_digest(j["acceptance"]))

    def test_a_job_without_criteria_classifies_none_stated(self):
        self.assertEqual(ab.classify_job({"id": "j", "acceptance": []})["basis"], "none_stated")
        self.assertEqual(ab.classify_job({"id": "j"})["accepted"], None)

    def test_no_network_or_eval_in_source(self):
        src = open(os.path.join(ROOT, "acceptance_basis.py")).read()
        for bad in ("urllib", "socket", "eval(", "exec(", "subprocess"):
            self.assertNotIn(bad, src)


if __name__ == "__main__":
    unittest.main()
