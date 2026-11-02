"""The verification ladder (vegachiefofstaff), the dated counting rule (vegachiefofstaff, merktop) and the control
claims (jarvismuse), as laws. Nothing opens a socket; the snapshot tests drive two real commits in a temp repo.

No 64-hex run stands as a single literal (the secret gate): digests are built here.
"""
import datetime
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "vendor"))

import jobs_feed  # noqa: E402
import settle  # noqa: E402
import snapshots  # noqa: E402
import validate  # noqa: E402
import verification_tier as vt  # noqa: E402

NOW = jobs_feed.moment("2026-10-04T06:00:00Z")


def board():
    return jobs_feed.read_jobs(json.load(open(os.path.join(ROOT, "jobs.json"))))


def block(seed="AB"):
    return (seed * 32)[:64]


def git(cwd, *a):
    return subprocess.run(("git", "-C", cwd) + a, check=True, capture_output=True, text=True).stdout


class FeedTier(unittest.TestCase):
    def test_1_feed_declares_a_tier_from_the_closed_set(self):
        feed, _ = jobs_feed.build(board(), [], 0, NOW)
        self.assertIn(feed["verification_tier"], vt.LADDER)
        self.assertEqual(feed["verification_tier_ladder"], list(vt.LADDER))

    def test_2_no_index_means_live_editable_file(self):
        feed, _ = jobs_feed.build(board(), [], 0, NOW)
        self.assertEqual(feed["verification_tier"], vt.LIVE)

    def test_3_a_jobs_feed_never_claims_the_rail_even_with_receipts(self):
        receipts = [{"confirmed": True, "block_hash": block()}]
        feed, _ = jobs_feed.build(board(), receipts, 1, NOW)
        self.assertNotEqual(feed["verification_tier"], vt.APPEND_ONLY_RAIL)

    def test_4_checker_downgrades_a_claimed_tier_it_cannot_evidence(self):
        feed, _ = jobs_feed.build(board(), [], 0, NOW)
        feed["verification_tier"] = vt.RETAINED          # claimed, no snapshots index supplied
        verdict = jobs_feed.check(feed, board(), [], 0, NOW)
        self.assertFalse(verdict["ok"])
        self.assertTrue(any("tier_not_evidenced" in s for s in verdict["stale_fields"]), verdict["stale_fields"])

    def test_5_unknown_tier_is_stale(self):
        feed, _ = jobs_feed.build(board(), [], 0, NOW)
        feed["verification_tier"] = "gold"
        verdict = jobs_feed.check(feed, board(), [], 0, NOW)
        self.assertTrue(any("verification_tier" in s for s in verdict["stale_fields"]))

    def test_6_honest_feed_still_matches_the_board(self):
        feed, _ = jobs_feed.build(board(), [], 0, NOW)
        self.assertTrue(jobs_feed.check(feed, board(), [], 0, NOW)["ok"])

    def test_7_rule_is_dated_before_anything_it_counts(self):
        feed, _ = jobs_feed.build(board(), [], 0, NOW)
        rule = feed["distinct_external_counterparties_rule"]
        self.assertEqual(vt.rule_problems(rule, "2026-10-06T00:00:00Z"), [])
        late = dict(rule, stated_at="2026-12-01T00:00:00Z")
        self.assertEqual(vt.rule_problems(late, "2026-10-06T00:00:00Z")[0][0], "rule_dated_after_what_it_counts")

    def test_8_a_rule_dated_after_the_first_receipt_makes_the_feed_stale(self):
        feed, _ = jobs_feed.build(board(), [], 0, NOW)
        feed["distinct_external_counterparties_rule"]["stated_at"] = "2026-12-01T00:00:00Z"
        receipts = [{"confirmed": True, "block_hash": block(), "settled_at": "2026-10-06T00:00:00Z"}]
        stale = jobs_feed.check(feed, board(), receipts, 1, NOW)["stale_fields"]
        self.assertTrue(any("rule_dated_after_what_it_counts" in s for s in stale), stale)

    def test_9_an_inference_without_method_or_control_test_is_refused(self):
        rule = {"stated_at": "2026-10-01T00:00:00Z", "counts": "x", "excludes": [], "method_is_an_inference": True}
        self.assertEqual(vt.rule_problems(rule, None)[0][0], "inference_without_method")
        rule.update(method="funding-graph clustering", control_test="a planted cluster is found")
        self.assertEqual(vt.rule_problems(rule, None), [])


class ReceiptTier(unittest.TestCase):
    def test_10_settle_writes_the_rail_tier_and_validate_accepts_it(self):
        j = {"id": "job-1", "claimed_by": "s", "price_raw": "250000000000000000000000000000", "claim_url": "https://x.invalid/1"}
        r = settle.build_receipt(j, "job-1", "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
                                 block(), "https://node.invalid", "https://x.invalid/d",
                                 datetime.datetime(2026, 10, 5, tzinfo=datetime.timezone.utc), "receipt-001")
        self.assertEqual(r["verification_tier"], vt.APPEND_ONLY_RAIL)
        self.assertEqual(validate.check_receipts({"receipts": [r]}), [])

    def test_11_a_receipt_cannot_claim_the_rail_without_a_confirmed_block(self):
        r = {"id": "receipt-001", "job_id": "job-1", "paid_to": "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
             "amount_raw": "1", "amount_xno": "0.000000000000000000000000000001", "block_hash": block(),
             "settled_at": "2026-10-05T00:00:00Z", "delivery_url": "https://x.invalid/d",
             "verification_tier": vt.APPEND_ONLY_RAIL}          # no `confirmed`
        errs = validate.check_receipts({"receipts": [r]})
        self.assertTrue(any("tier_not_evidenced" in e for e in errs), errs)

    def test_12_unknown_receipt_tier_is_an_error(self):
        r = {"id": "receipt-001", "job_id": "job-1", "paid_to": "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3",
             "amount_raw": "1", "amount_xno": "0.000000000000000000000000000001", "block_hash": block(),
             "settled_at": "2026-10-05T00:00:00Z", "delivery_url": "https://x.invalid/d", "verification_tier": "gold"}
        self.assertTrue(any("verification_tier" in e for e in validate.check_receipts({"receipts": [r]})))


class SnapshotIndex(unittest.TestCase):
    def repo(self):
        d = tempfile.mkdtemp()
        git(d, "init", "-q")
        git(d, "config", "user.email", "t@invalid")
        git(d, "config", "user.name", "t")
        os.makedirs(os.path.join(d, "feed"))
        for n, stamp in enumerate(("2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z")):
            with open(os.path.join(d, "feed", "jobs.json"), "w") as fh:
                json.dump({"generated_at": stamp, "n": n}, fh)
            git(d, "add", "-A")
            git(d, "commit", "-q", "-m", "v%d" % n)
        return d

    def test_13_rows_are_derived_from_git_and_pin_commit_shas(self):
        d = self.repo()
        doc = snapshots.build(d, ("feed/jobs.json",))
        self.assertEqual(len(doc["snapshots"]), 2)
        head = git(d, "rev-parse", "HEAD").strip()
        self.assertIn(head, doc["snapshots"][1]["permalink"])
        self.assertEqual(doc["snapshots"][0]["superseded_at"], doc["snapshots"][1]["generated_at"])
        self.assertIsNone(doc["snapshots"][1]["superseded_at"])
        self.assertEqual(vt.snapshot_problems(doc, "feed/jobs.json", ["2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z"]), [])
        self.assertEqual(vt.evidenced_tier("feed/jobs.json", index=doc)["tier"], vt.RETAINED)

    def test_14_a_dropped_row_fails_the_append_only_check(self):
        d = self.repo()
        doc = snapshots.build(d, ("feed/jobs.json",))
        thin = {"snapshots": doc["snapshots"][1:]}
        self.assertIn("snapshot_row_removed", [c for c, _ in vt.append_only_problems(doc, thin)])
        with self.assertRaises(vt.Refusal):               # a rebuild that lost history refuses to write
            git(d, "reset", "-q", "--hard", "HEAD~1")
            snapshots.build(d, ("feed/jobs.json",), previous=doc)

    def test_15_a_retimed_row_fails(self):
        d = self.repo()
        doc = snapshots.build(d, ("feed/jobs.json",))
        moved = json.loads(json.dumps(doc))
        moved["snapshots"][0]["generated_at"] = "2026-10-01T00:00:09Z"
        self.assertIn("snapshot_row_retimed", [c for c, _ in vt.append_only_problems(doc, moved)])

    def test_16_a_gap_in_history_is_named(self):
        d = self.repo()
        doc = snapshots.build(d, ("feed/jobs.json",))
        doc["snapshots"].pop(0)
        doc["snapshots"][0]["superseded_at"] = None
        self.assertEqual(vt.snapshot_problems(doc, "feed/jobs.json", ["2026-10-01T00:00:00Z", "2026-10-02T00:00:00Z"])[0][0],
                         "snapshot_index_gap")

    def test_17_a_branch_permalink_is_refused(self):
        d = self.repo()
        doc = snapshots.build(d, ("feed/jobs.json",))
        doc["snapshots"][0]["permalink"] = "https://raw.githubusercontent.com/o/r/main/feed/jobs.json"
        self.assertIn("snapshot_permalink_is_a_branch", [c for c, _ in vt.snapshot_problems(doc, "feed/jobs.json")])

    def test_18_feed_with_an_index_evidences_retained_and_check_agrees(self):
        d = self.repo()
        doc = snapshots.build(d, ("feed/jobs.json",))
        feed, _ = jobs_feed.build(board(), [], 0, NOW, snapshots=doc)
        self.assertEqual(feed["verification_tier"], vt.RETAINED)
        self.assertTrue(jobs_feed.check(feed, board(), [], 0, NOW, snapshots=doc)["ok"])


class ControlClaims(unittest.TestCase):
    def test_19_controls_must_be_present_and_must_not_agree(self):
        good = [{"id": "c1", "control": True, "expected_verdict": "refuted", "verdict": False},
                {"id": "c2", "control": True, "expected_verdict": "unproven", "verdict_is": "unproven", "verdict": False}]
        self.assertEqual(vt.control_problems(good, lambda c: False), [])
        self.assertEqual({c for c, _ in vt.control_problems([], lambda c: False)}, {"controls_absent"})
        self.assertEqual(vt.control_problems(good, lambda c: True)[0][0], "controls_agree_with_the_real_claims")

    def test_21_committed_verdict_carries_controls_in_the_same_array(self):
        import verdict
        art = json.load(open(os.path.join(ROOT, "feed", "verdict.json")))
        ctl = [c for c in art["claims"] if c.get("control")]
        self.assertEqual({c["expected_verdict"] for c in ctl}, {"refuted", "unproven"})
        self.assertTrue(verdict.check(art)["ok"])
        self.assertEqual(art["claims_false_or_unproven"], 0)       # controls never inflate the headline
        flipped = json.loads(json.dumps(art))
        for c in flipped["claims"]:
            if c["id"] == "control-false-001":
                c["verdict"] = True
        res = verdict.check(flipped)
        self.assertFalse(res["ok"])

    def test_22_removing_the_controls_fails_the_check(self):
        import verdict
        art = json.load(open(os.path.join(ROOT, "feed", "verdict.json")))
        art["claims"] = [c for c in art["claims"] if not c.get("control")]
        self.assertIn("controls_absent", [m["id"] for m in verdict.check(art)["mismatches"]])

    def test_20_module_self_test(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "verification_tier.py"), "--self-test"],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout)


if __name__ == "__main__":
    unittest.main()
