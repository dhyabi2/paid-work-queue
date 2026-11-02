import json, os, sys, tempfile, unittest
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
import open_tasks  # noqa: E402

H = "A" * 64


def feed(*jobs, receipts=()):
    return {"feed_url": "u", "generated_at": "t", "jobs": list(jobs), "receipts": list(receipts)}


def job(i, state, raw="50000000000000000000000000000"):
    return {"id": i, "title": "t" + i, "acceptance": ["a"], "price_xno": "0.05", "price_raw": raw,
            "expires": "e", "state": state, "claimed_by": "x" if state != "open" else None, "claim_url": None}


class OpenTasks(unittest.TestCase):
    def test_only_open_jobs_count_and_filled_ones_are_marked_not_dropped(self):
        v = open_tasks.view(feed(job("1", "open"), job("2", "claimed")))
        self.assertEqual(v["open_count"], 1)
        self.assertEqual([t["status"] for t in v["tasks"]], ["open", "filled"])
        self.assertEqual(v["open_total_raw"], "50000000000000000000000000000")

    def test_paid_needs_a_64_hex_block_hash(self):
        bad = open_tasks.view(feed(job("1", "settled"), receipts=[{"job_id": "1", "block_hash": "nothex"}]))
        self.assertEqual(bad["tasks"][0]["status"], "filled")
        good = open_tasks.view(feed(job("1", "settled"), receipts=[{"job_id": "1", "block_hash": H}]))
        self.assertEqual(good["tasks"][0]["status"], "paid")
        self.assertEqual(good["tasks"][0]["payout_block"], H)

    def test_invents_no_job(self):
        self.assertEqual(open_tasks.view(feed())["tasks"], [])

    def test_committed_view_matches_committed_feed(self):
        self.assertEqual(open_tasks.main(["check", "--feed", os.path.join(ROOT, "feed", "jobs.json"),
                                          "--out", os.path.join(ROOT, "feed")]), 0)


if __name__ == "__main__":
    unittest.main()
