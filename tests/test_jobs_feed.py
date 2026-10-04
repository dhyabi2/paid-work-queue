"""Publishing the board, and proving the published copy still matches it.

The decisive tests here are 1 and 5. Test 1 builds from the REAL committed
`jobs.json` and asserts the numbers a seller would act on - three jobs, 0.45
XNO - so the feed cannot drift from the board without this file going red. Test
5 is the other half of merktop's condition ("publish the invoice list and the
whole thing becomes stranger-checkable"): a board that moved after publication
is caught, by name, without anything of ours in the trust path.

Test 3 is the one a float implementation fails. 1 XNO is 10**30 raw, so `"1"`
raw is 0.000000000000000000000000000001 XNO; a float prints `1e-30` or `0.0`,
and either would be a published price that is not the price.

Every fixture is built independently of `jobs_feed`'s own `--self-test`
controls, deliberately: driving these assertions from the module's fixtures
would let a mutation that breaks both drift past green.

Nothing opens a socket, and nothing can: test 12 walks the import graph.

No 64-hex run stands as a single literal, matching the project's secret gate.
"""

import html
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
import validate  # noqa: E402
from custody_probe import NETWORK_MODULES  # noqa: E402  - reused, not re-listed
from jobs_feed import (  # noqa: E402
    BOARD_FIELDS, Refusal, board_digest, build, check, joined, main, moment,
    read_jobs, read_receipts, render_html, serialise, xno,
)

SCRIPT = os.path.join(ROOT, "jobs_feed.py")
NOW = "2026-10-04T06:00:00Z"
AFTER_EXPIRY = "2026-10-18T07:00:00Z"


def real_board():
    with open(os.path.join(ROOT, "jobs.json"), "r", encoding="utf-8") as fh:
        return json.load(fh)


def board(**changes):
    """A control board built here, not imported from the module's fixtures."""
    job = {
        "id": "job-test-7",
        "title": "A job that exists only in this file",
        "description": "Exercises the generator and nothing else.",
        "acceptance": [
            "A first condition, stated in full.",
            "A second condition, longer than the first, which must survive "
            "verbatim and must not be truncated to fit anything.",
            "A third.",
        ],
        "price_raw": "70000000000000000000000000000",
        "posted": "2026-09-26T07:00:00Z",
        "expires": "2026-10-17T07:00:00Z",
        "state": "open",
        "claimed_by": None,
        "claim_url": None,
        "receipt_id": None,
    }
    job.update(changes)
    return {"updated": NOW, "currency": "XNO", "jobs": [job]}


def built(document=None, now=NOW, receipts=(), payees=0, **kwargs):
    jobs = read_jobs(document if document is not None else board())
    feed, soon = build(jobs, list(receipts), payees, moment(now), **kwargs)
    return feed, jobs, soon


def run(*argv):
    return subprocess.run([sys.executable, SCRIPT] + list(argv),
                          capture_output=True, text=True, cwd=ROOT, timeout=60)


class TheBoardAsPublished(unittest.TestCase):

    def test_01_the_feed_carries_all_three_jobs_and_the_real_total(self):
        """Built from the committed board, so the feed cannot drift from it."""
        feed, _, _ = built(real_board())
        self.assertEqual(feed["open_count"], 3)
        self.assertEqual(feed["open_total_raw"], "450000000000000000000000000000")
        self.assertEqual(feed["open_total_xno"], "0.45")
        self.assertEqual([job["id"] for job in feed["jobs"]],
                         ["job-2026-09-26-001", "job-2026-09-26-002",
                          "job-2026-09-26-003"])
        self.assertEqual([job["price_xno"] for job in feed["jobs"]],
                         ["0.25", "0.15", "0.05"])

    def test_01b_the_total_is_the_exact_integer_sum(self):
        """0.25 + 0.15 + 0.05 is 0.45, not 0.44999999999999996."""
        feed, _, _ = built(real_board())
        total = sum(int(job["price_raw"]) for job in feed["jobs"])
        self.assertEqual(str(total), feed["open_total_raw"])
        self.assertEqual(xno(total), "0.45")

    def test_01c_the_committed_feed_matches_the_committed_board(self):
        """The artefacts in `feed/` are generated, not hand-written.

        If someone edits `jobs.json` without regenerating, this goes red - which
        is the whole point of committing a feed rather than serving one.
        """
        with open(os.path.join(ROOT, "feed", "jobs.json"), "rb") as fh:
            published = json.loads(fh.read().decode("utf-8"))
        jobs = read_jobs(real_board())
        self.assertEqual(joined(published["jobs_digest_halves"]),
                         board_digest(jobs),
                         "feed/jobs.json is stale; re-run `python3 jobs_feed.py "
                         "build --now <timestamp> --out feed/`")

    def test_02_acceptance_is_verbatim_and_complete(self):
        source = real_board()
        feed, _, _ = built(source)
        by_id = {job["id"]: job for job in source["jobs"]}
        for job in feed["jobs"]:
            original = by_id[job["id"]]["acceptance"]
            self.assertEqual(job["acceptance"], original)          # element for element
            self.assertEqual(job["acceptance_count"], len(original))
            for published, expected in zip(job["acceptance"], original):
                self.assertEqual(published, expected)              # full, not a prefix
                self.assertFalse(published.endswith("..."))
            self.assertEqual(job["description"],
                             by_id[job["id"]]["description"])

    def test_02b_a_long_acceptance_line_is_not_shortened(self):
        feed, _, _ = built(board())
        lines = feed["jobs"][0]["acceptance"]
        self.assertEqual(len(lines), 3)
        self.assertGreater(len(lines[1]), 100)
        self.assertEqual(lines[1], board()["jobs"][0]["acceptance"][1])

    def test_03_price_xno_is_exact_for_a_raw_amount_no_float_can_hold(self):
        self.assertEqual(xno("50000000000000000000000000000"), "0.05")
        self.assertEqual(xno("1"), "0." + "0" * 29 + "1")
        self.assertNotIn("e", xno("1"))
        self.assertNotEqual(xno("1"), "0.0")
        self.assertEqual(xno("1" + "0" * 30), "1")
        # The float version of the same arithmetic, for the record.
        self.assertNotEqual(repr(1 / 10 ** 30), xno("1"))
        feed, _, _ = built(board(price_raw="1"))
        self.assertEqual(feed["jobs"][0]["price_xno"], "0." + "0" * 29 + "1")
        self.assertEqual(feed["open_total_xno"], "0." + "0" * 29 + "1")


class WhatLapsedIsStillShown(unittest.TestCase):

    def test_04_an_expired_job_is_published_not_hidden(self):
        feed, _, _ = built(board(), now=AFTER_EXPIRY)
        self.assertEqual(len(feed["jobs"]), 1, "the lapsed job was dropped")
        job = feed["jobs"][0]
        self.assertEqual(job["state"], "expired")
        self.assertLess(job["hours_left"], 0)
        self.assertEqual(feed["open_count"], 0)
        self.assertEqual(feed["open_total_raw"], "0")
        self.assertEqual(feed["open_total_xno"], "0")
        # and its price is still legible, so a reader can see what lapsed
        self.assertEqual(job["price_xno"], "0.07")

    def test_04b_expiring_soon_is_counted(self):
        _, _, soon = built(board(), now="2026-10-16T07:00:00Z")
        self.assertEqual(soon, 1)
        _, _, far = built(board(), now=NOW)
        self.assertEqual(far, 0)

    def test_04c_at_the_exact_second_of_expiry_the_state_is_the_authority(self):
        """The boundary, stated rather than left to be discovered.

        At `now == expires` nothing is buyable, so `state` is `expired`, while
        `hours_left` floors to 0 rather than going negative. The state field is
        what a caller branches on; `hours_left` is for a human reading a page.
        """
        feed, _, _ = built(board(), now="2026-10-17T07:00:00Z")
        job = feed["jobs"][0]
        self.assertEqual(job["state"], "expired")
        self.assertEqual(job["hours_left"], 0)
        self.assertEqual(feed["open_count"], 0)

    def test_04d_a_board_state_that_is_not_open_is_carried_through(self):
        feed, _, _ = built(board(state="claimed", claimed_by="someone"))
        self.assertEqual(feed["jobs"][0]["state"], "claimed")
        self.assertEqual(feed["jobs"][0]["claimed_by"], "someone")
        self.assertEqual(feed["open_count"], 0)

    def test_04e_the_tool_holds_no_clock(self):
        import ast
        with open(SCRIPT, "r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=SCRIPT)
        banned = {"now", "utcnow", "today", "time", "monotonic", "time_ns"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, banned,
                                 "a clock call at line %d" % node.lineno)

    def test_04f_now_is_required_and_says_so_in_its_own_code(self):
        done = run("build", "--out", tempfile.mkdtemp())
        self.assertEqual(done.returncode, 2)
        self.assertEqual(json.loads(done.stderr)["error"], "now_required")


class StrangerCheckable(unittest.TestCase):

    def test_05_check_catches_a_board_that_moved(self):
        feed, jobs, _ = built(board())
        self.assertIs(check(feed, jobs, [], 0, moment(NOW))["ok"], True)

        moved = read_jobs(board(price_raw="90000000000000000000000000000"))
        verdict = check(feed, moved, [], 0, moment(NOW))
        self.assertIs(verdict["ok"], False)
        self.assertEqual(verdict["reason"], "feed_digest_mismatch")
        self.assertTrue(any("job-test-7" in entry
                            for entry in verdict["stale_fields"]),
                        verdict["stale_fields"])

    def test_05b_check_is_exit_1_through_the_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            # The board and the generated feed must not share a path: `build`
            # writes `jobs.json` into --out, which would overwrite the board.
            jobs_path = os.path.join(tmp, "board.json")
            out = os.path.join(tmp, "feed")
            with open(jobs_path, "w", encoding="utf-8") as fh:
                json.dump(board(), fh)
            done = run("build", "--now", NOW, "--out", out, "--jobs", jobs_path,
                       "--receipts", os.path.join(ROOT, "receipts.json"))
            self.assertEqual(done.returncode, 0, done.stderr)

            with open(jobs_path, "w", encoding="utf-8") as fh:
                json.dump(board(title="A different title entirely"), fh)
            done = run("check", "--feed", os.path.join(out, "jobs.json"),
                       "--jobs", jobs_path, "--now", NOW,
                       "--receipts", os.path.join(ROOT, "receipts.json"))
        self.assertEqual(done.returncode, 1, done.stdout)
        verdict = json.loads(done.stdout)
        self.assertEqual(verdict["reason"], "feed_digest_mismatch")
        self.assertIn("job-test-7: title", verdict["stale_fields"])

    def test_05c_time_moving_is_a_different_failure_from_the_board_moving(self):
        """`feed_stale` and `feed_digest_mismatch` are told apart on purpose.

        A digest over the whole published array would change every hour on an
        unchanged board, so `check` would report a mismatch forever and prove
        nothing. Separating the board-derived fields from the time-derived ones
        is what lets a reader tell a board edit from the passage of an
        afternoon.
        """
        feed, jobs, _ = built(board())
        verdict = check(feed, jobs, [], 0, moment(AFTER_EXPIRY))
        self.assertIs(verdict["ok"], False)
        self.assertEqual(verdict["reason"], "feed_stale")
        self.assertTrue(any("state is 'open'" in e for e in verdict["stale_fields"]),
                        verdict["stale_fields"])
        self.assertTrue(any(e.startswith("open_count:")
                            for e in verdict["stale_fields"]))
        # The board itself did not move, and the digest says so.
        self.assertEqual(verdict["jobs_digest"], verdict["published_digest"])

    def test_05d_the_digest_covers_every_board_field_and_no_time_field(self):
        feed, jobs, _ = built(board())
        baseline = board_digest(jobs)
        for field, altered in (("title", "moved"), ("description", "moved"),
                               ("price_raw", "80000000000000000000000000000"),
                               ("expires", "2026-10-18T07:00:00Z"),
                               ("claimed_by", "someone"),
                               ("receipt_id", "r-1"),
                               ("acceptance", ["only one line now"])):
            other = read_jobs(board(**{field: altered}))
            self.assertNotEqual(board_digest(other), baseline, field)
        # and the fields it must NOT cover
        self.assertEqual(sorted(BOARD_FIELDS),
                         sorted(("id", "title", "description", "acceptance",
                                 "price_raw", "expires", "claimed_by",
                                 "receipt_id")))
        self.assertNotIn("state", BOARD_FIELDS)
        self.assertNotIn("hours_left", BOARD_FIELDS)
        self.assertEqual(feed["jobs_digest_over"], list(BOARD_FIELDS))

    def test_05e_a_job_added_or_removed_is_named(self):
        feed, _, _ = built(board())
        two = board()
        two["jobs"].append(dict(two["jobs"][0], id="job-test-8"))
        verdict = check(feed, read_jobs(two), [], 0, moment(NOW))
        self.assertIs(verdict["ok"], False)
        self.assertTrue(any("job-test-8" in e and "not in the feed" in e
                            for e in verdict["stale_fields"]),
                        verdict["stale_fields"])

    def test_05f_a_feed_of_the_wrong_version_is_not_read(self):
        verdict = check({"v": "something-else"}, read_jobs(board()), [], 0,
                        moment(NOW))
        self.assertIs(verdict["ok"], False)
        self.assertEqual(verdict["reason"], "feed_unreadable")


class HonestZeroes(unittest.TestCase):

    def test_06_empty_receipts_are_published(self):
        feed, _, _ = built(real_board(), receipts=[], payees=0)
        self.assertIn("receipts", feed, "the key was omitted")
        self.assertEqual(feed["receipts"], [])
        self.assertEqual(feed["settled_count"], 0)
        self.assertEqual(feed["sellers_paid"], 0)
        # and the file says so in words, not only in a zero
        self.assertTrue(any("settled_count is 0" in note
                            for note in feed["notes"]))

    def test_06b_the_committed_feed_publishes_the_zero(self):
        with open(os.path.join(ROOT, "feed", "jobs.json"), "r",
                  encoding="utf-8") as fh:
            published = json.load(fh)
        self.assertEqual(published["receipts"], [])
        self.assertEqual(published["settled_count"], 0)
        self.assertEqual(published["sellers_paid"], 0)

    def test_06c_receipts_are_counted_by_distinct_payee(self):
        payee = "nano_1111111111111111111111111111111111111111111111111111hifc8npp"
        rows = [{"id": "r-1", "paid_to": payee},
                {"id": "r-2", "paid_to": payee.replace("nano_", "xrb_")}]
        parsed, payees = read_receipts({"receipts": rows})
        self.assertEqual(len(parsed), 2)
        self.assertEqual(payees, 1, "one seller in two spellings is one seller")
        feed, _, _ = built(board(), receipts=rows, payees=payees)
        self.assertEqual(feed["settled_count"], 2)
        self.assertEqual(feed["sellers_paid"], 1)

    def test_06d_a_buyer_account_is_stated_or_said_to_be_undeclared(self):
        """Never invented. No account in this repository is established as the
        buyer's, so the honest published value is null plus a note - rule 6's
        principle applied to a field whose value today is "not declared"."""
        feed, _, _ = built(board())
        self.assertIsNone(feed["buyer_account"])
        self.assertIn("Not declared", feed["buyer_account_note"])
        named = "nano_1111111111111111111111111111111111111111111111111111hifc8npp"
        stated, _, _ = built(board(), buyer_account=named)
        self.assertEqual(stated["buyer_account"], named)
        self.assertNotIn("buyer_account_note", stated)

    def test_06e_the_undeployed_door_is_marked_undeployed(self):
        """The README says `getunstuck.space` is not live. A feed whose whole
        claim is being checkable cannot open with a URL that does not answer."""
        feed, _, _ = built(board())
        http = feed["how_to_claim"]["by_http"]
        self.assertIs(http["deployed"], False)
        self.assertIsNone(http["where"])
        self.assertIn("not live", http["why_not"])
        for door in ("by_issue", "by_clone"):
            self.assertIs(feed["how_to_claim"][door]["deployed"], True)


class RefusedRatherThanPublished(unittest.TestCase):

    def test_07_a_duplicate_job_id_is_refused(self):
        twice = board()
        twice["jobs"].append(dict(twice["jobs"][0]))
        with self.assertRaises(Refusal) as caught:
            read_jobs(twice)
        self.assertEqual(caught.exception.code, "duplicate_job_id")
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "jobs.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(twice, fh)
            done = run("build", "--now", NOW, "--out", tmp, "--jobs", path)
        self.assertEqual(done.returncode, 2)
        self.assertEqual(json.loads(done.stderr)["error"], "duplicate_job_id")

    def test_08_a_date_that_does_not_exist_is_refused(self):
        """Reuses `validate._rfc3339`, and this test proves the reuse: nothing
        here re-implements a calendar."""
        self.assertIsNone(validate._rfc3339("2026-02-30T00:00:00Z"))
        # An absent or empty `expires` is a MISSING field (E-02
        # `bad_job_shape`, covered by test_08c), not a malformed date. Only
        # values that are present and are not a date belong here.
        for bad in ("2026-02-30T00:00:00Z", "2026-13-01T00:00:00Z",
                    "2026-10-17T25:00:00Z", "2026-10-17", "not a date",
                    "2026-10-17T07:00:00+04:00", 17, 2026.1):
            with self.assertRaises(Refusal) as caught:
                read_jobs(board(expires=bad))
            self.assertEqual(caught.exception.code, "bad_expiry", repr(bad))

    def test_08b_a_price_that_is_not_an_integer_string_is_refused(self):
        for bad in ("0.05", "5e28", "0", "-70", "٧٠", 70, 0.07, True):
            with self.assertRaises(Refusal) as caught:
                read_jobs(board(price_raw=bad))
            self.assertEqual(caught.exception.code, "price_not_integer_string",
                             repr(bad))

    def test_08c_a_job_missing_a_required_field_is_refused(self):
        for field in ("id", "title", "price_raw", "expires", "acceptance", "state"):
            with self.assertRaises(Refusal) as caught:
                read_jobs(board(**{field: None}))
            self.assertIn(caught.exception.code, ("bad_job_shape",))
        with self.assertRaises(Refusal) as caught:
            read_jobs(board(acceptance=[]))
        self.assertEqual(caught.exception.code, "bad_job_shape")
        with self.assertRaises(Refusal) as caught:
            read_jobs(board(acceptance="one line, not a list"))
        self.assertEqual(caught.exception.code, "bad_job_shape")

    def test_08d_an_unreadable_board_is_refused(self):
        for bad in ({}, {"jobs": "not a list"}, [], None, {"jobs": [3]}):
            with self.assertRaises(Refusal) as caught:
                read_jobs(bad)
            self.assertIn(caught.exception.code,
                          ("jobs_file_unreadable", "bad_job_shape"), repr(bad))
        done = run("build", "--now", NOW, "--jobs", "/nonexistent/jobs.json",
                   "--out", tempfile.mkdtemp())
        self.assertEqual(done.returncode, 2)
        self.assertEqual(json.loads(done.stderr)["error"], "jobs_file_unreadable")

    def test_09b_an_unwritable_out_dir_is_refused(self):
        done = run("build", "--now", NOW, "--out", "/proc/1/nowhere")
        self.assertEqual(done.returncode, 2)
        self.assertEqual(json.loads(done.stderr)["error"], "out_dir_unwritable")


class TheHumanPage(unittest.TestCase):

    def test_09_index_html_is_self_contained(self):
        feed, _, _ = built(real_board())
        page = render_html(feed)
        for forbidden in ("<script", "src=", 'href="http', "@import", "url(",
                          "<iframe", "<link"):
            self.assertNotIn(forbidden, page, forbidden)
        for job in feed["jobs"]:
            self.assertIn(job["title"], page)
            self.assertIn(job["price_xno"], page)
            self.assertIn(job["expires"], page)
            for line in job["acceptance"]:
                # escaped, because test_09d requires the page to escape: an
                # acceptance line carrying an apostrophe appears as &#x27;
                self.assertIn(html.escape(line), page)
        # the three doors
        self.assertIn("CLAIM &lt;job_id&gt;", page)
        self.assertIn("claim.py", page)
        self.assertIn("Not available yet", page)

    def test_09c_the_committed_page_is_self_contained_too(self):
        with open(os.path.join(ROOT, "feed", "index.html"), "r",
                  encoding="utf-8") as fh:
            page = fh.read()
        for forbidden in ("<script", "src=", 'href="http', "@import", "url("):
            self.assertNotIn(forbidden, page, forbidden)
        self.assertIn("0.45", page)

    def test_09d_a_title_carrying_html_is_escaped_not_rendered(self):
        feed, _, _ = built(board(title="<b>bold</b> & <script>alert(1)</script>"))
        page = render_html(feed)
        self.assertNotIn("<script", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("&amp;", page)


class ByteExactAndHermetic(unittest.TestCase):

    def test_10_feed_bytes_are_byte_exact(self):
        first, _, _ = built(real_board())
        second, _, _ = built(real_board())
        self.assertEqual(serialise(first), serialise(second))

        moved, _, _ = built(
            {"updated": NOW, "currency": "XNO",
             "jobs": [dict(real_board()["jobs"][0],
                           description=real_board()["jobs"][0]["description"] + ".")]})
        one_job, _, _ = built({"updated": NOW, "currency": "XNO",
                               "jobs": [real_board()["jobs"][0]]})
        self.assertNotEqual(joined(moved["jobs_digest_halves"]),
                            joined(one_job["jobs_digest_halves"]),
                            "one byte of a description did not move the digest")

    def test_10b_the_digest_halves_rejoin_to_the_digest(self):
        feed, jobs, _ = built(real_board())
        halves = feed["jobs_digest_halves"]
        self.assertEqual(len(halves), 2)
        self.assertEqual([len(half) for half in halves], [32, 32])
        self.assertEqual(joined(halves), board_digest(jobs))
        self.assertEqual(len(joined(halves)), 64)
        self.assertIsNone(joined("not a pair"))
        self.assertIsNone(joined([halves[0]]))

    def test_10c_the_published_files_hold_no_standalone_64_hex_run(self):
        """The secret gate, on the artefacts this tool commits.

        A published digest is not a key, so the right trade is to keep all 256
        bits and split the string - as `vectors/grant-mint-v1.json` already does
        - rather than weaken the gate so a feed can print one.
        """
        for name in ("feed/jobs.json", "feed/index.html", "jobs_feed.py",
                     "tests/test_jobs_feed.py"):
            with open(os.path.join(ROOT, name), "r", encoding="utf-8") as fh:
                self.assertIsNone(validate.SECRET_RE.search(fh.read()), name)

    def test_10d_the_whole_tree_still_passes_the_gate(self):
        self.assertEqual(validate.scan_for_secrets(ROOT), [])

    def test_10e_a_receipt_carrying_a_block_hash_survives_the_gate(self):
        """The break this would hit on the first settlement, caught now.

        `receipts` is copied verbatim, so once a payment exists its rows carry a
        64-hex block hash. The gate exempts exactly one key name, `block_hash`,
        so a row spelling it anything else would make the first real settlement
        turn the tree red - after the money moved, which is the worst possible
        moment to find out.
        """
        row = {"id": "r-1", "job_id": "job-test-7",
               "block_hash": "9F3C" * 16,
               "paid_to": "nano_1111111111111111111111111111111111111111111111111111hifc8npp",
               "amount_raw": "70000000000000000000000000000"}
        feed, _, _ = built(board(), receipts=[row], payees=1)
        findings = []
        validate._walk_json_for_secrets(
            json.loads(serialise(feed).decode("utf-8")), "feed/jobs.json", findings)
        self.assertEqual(findings, [], findings)
        self.assertEqual(feed["receipts"], [row])

    def test_11_self_test_exits_zero(self):
        done = run("--self-test")
        self.assertEqual(done.returncode, 0, done.stderr)
        report = json.loads(done.stdout)
        self.assertEqual(report["self_test"], "pass")
        self.assertEqual(report["failures"], [])
        self.assertGreaterEqual(report["negative_controls"], 8)
        self.assertIs(report["positive_control"]["ok"], True)

    def test_11b_self_test_is_hermetic_in_process(self):
        self.assertEqual(main(["--self-test"]), 0)

    def test_12_nothing_on_the_import_graph_can_reach_the_network(self):
        for entry in jobs_feed.import_graph():
            self.assertNotIn(entry["module"].split(".")[0], NETWORK_MODULES,
                             "%s imported in %s" % (entry["module"], entry["function"]))

    def test_12b_no_command_is_exit_2(self):
        self.assertEqual(run().returncode, 2)

    def test_12c_build_writes_both_artefacts_and_prints_the_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "nested", "feed")
            done = run("build", "--now", NOW, "--out", out)
            self.assertEqual(done.returncode, 0, done.stderr)
            reference = json.loads(done.stdout)
            with open(os.path.join(out, "jobs.json"), "rb") as fh:
                payload = fh.read()
            self.assertTrue(os.path.exists(os.path.join(out, "index.html")))
        self.assertEqual(reference["bytes"], len(payload))
        self.assertEqual(reference["open_count"], 3)
        self.assertEqual(reference["open_total_xno"], "0.45")
        self.assertEqual(reference["expiring_within_72h"], 0)
        self.assertEqual(reference["jobs_digest"],
                         joined(json.loads(payload.decode())["jobs_digest_halves"]))
        self.assertEqual(reference["feed_url"], jobs_feed.FEED_URL)
        self.assertTrue(payload.endswith(b"}\n"))
        # The byte rule itself, rather than a grep for ", ": a published note
        # legitimately contains ", " inside a string value, so the honest check
        # is that the file IS the canonical serialisation of its own content.
        self.assertEqual(payload, serialise(json.loads(payload.decode("utf-8"))))


if __name__ == "__main__":
    unittest.main()
