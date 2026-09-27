"""The fourteen tests named in the spec, plus the error paths around them.

No test touches the network. Every fixture is built in a temporary
directory, so a test can never pass or fail because of the live jobs.json.

Note on 64-hex literals: validate.py's secret gate fails any file holding
64 hex characters on their own, and it scans this repository including this
file. Block hashes here are therefore assembled with `_block()` rather than
written out, which is also why no seed or key can be pasted into a test
"just for a moment".
"""

import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import validate  # noqa: E402
from validate import (  # noqa: E402
    check_append_only, check_jobs, check_receipts, compute_stats,
    cross_check, run, scan_for_secrets,
)

BURN = "nano_1111111111111111111111111111111111111111111111111111hifc8npp"
SELLER = "nano_11131a3ia3a81w61k4id3i8iw5ri46b3871o4rdji8at5eg3t9izij86w3hz"
XNO = 10 ** 30


def _block(prefix="9F2C"):
    """A syntactically valid 64-uppercase-hex block hash, assembled not pasted."""
    return (prefix + "0123456789ABCDEF" * 4)[:64]


def job(**overrides):
    entry = {
        "id": "job-001",
        "title": "A job",
        "description": "Do the thing and publish it at a public URL.",
        "acceptance": ["the URL returns 200", "the output parses as JSON"],
        "price_xno": "0.25",
        "price_raw": str(25 * XNO // 100),
        "posted": "2026-09-26T06:00:00Z",
        "expires": "2026-10-03T06:00:00Z",
        "state": "open",
        "claimed_by": None,
        "claim_url": None,
        "receipt_id": None,
    }
    entry.update(overrides)
    return entry


def receipt(**overrides):
    entry = {
        "id": "receipt-001",
        "job_id": "job-001",
        "paid_to": SELLER,
        "amount_raw": str(25 * XNO // 100),
        "amount_xno": "0.25",
        "block_hash": _block(),
        "settled_at": "2026-09-26T09:14:02Z",
        "delivery_url": "https://example.invalid/delivery",
        "verify": "https://nanolooker.com/block/<hash>",
    }
    entry.update(overrides)
    return entry


def jobs_doc(*entries):
    return {"updated": "2026-09-26T06:00:00Z", "currency": "XNO", "jobs": list(entries)}


def receipts_doc(*entries):
    return {"receipts": list(entries)}


def settled_pair():
    """One open job, one settled job, and the settled job's receipt."""
    paid = job(id="job-002", state="settled", claimed_by="a-seller",
               claim_url="https://example.invalid/pr/1", receipt_id="receipt-001")
    return jobs_doc(job(), paid), receipts_doc(receipt(job_id="job-002"))


def joined(errors):
    return "\n".join(errors)


class TreeCase(unittest.TestCase):
    """Writes a jobs/receipts pair into a temp dir and runs validate end to end."""

    def tree(self, jobs, receipts, extra_files=None):
        root = tempfile.mkdtemp()
        with open(os.path.join(root, "jobs.json"), "w") as handle:
            json.dump(jobs, handle)
        with open(os.path.join(root, "receipts.json"), "w") as handle:
            json.dump(receipts, handle)
        for name, text in (extra_files or {}).items():
            with open(os.path.join(root, name), "w") as handle:
                handle.write(text)
        return root

    def run_tree(self, root, base_ref=None):
        out = io.StringIO()
        code = run(root, base_ref=base_ref, write_stats=True, out=out)
        return code, out.getvalue()


# --------------------------------------------------------------------------
# the fourteen numbered tests from the spec
# --------------------------------------------------------------------------

class SpecTests(TreeCase):

    def test_01_price_xno_and_price_raw_disagree_by_one_raw(self):
        off = job(price_raw=str(25 * XNO // 100 + 1))
        errors = check_jobs(jobs_doc(off))
        self.assertTrue(errors)
        message = joined(errors)
        self.assertIn("job-001", message)
        self.assertIn("0.25", message)
        self.assertIn(str(25 * XNO // 100 + 1), message)
        self.assertIn(str(25 * XNO // 100), message)
        code, _ = self.run_tree(self.tree(jobs_doc(off), receipts_doc()))
        self.assertEqual(code, 1)

    def test_02_settled_job_without_receipt_id(self):
        bad = job(state="settled", claimed_by="s", claim_url="u", receipt_id=None)
        errors = check_jobs(jobs_doc(bad))
        self.assertTrue(any("receipt_id" in e for e in errors))
        code, _ = self.run_tree(self.tree(jobs_doc(bad), receipts_doc()))
        self.assertEqual(code, 1)

    def test_03_settled_job_whose_receipt_has_no_block_hash(self):
        jobs, receipts = settled_pair()
        receipts["receipts"][0]["block_hash"] = None
        code, output = self.run_tree(self.tree(jobs, receipts))
        self.assertEqual(code, 1)
        self.assertIn("block_hash", output)
        self.assertIn("receipt-001", output)

    def test_04_block_hash_is_not_64_uppercase_hex(self):
        for bad_hash in (_block()[:63], _block().lower(), "not a hash", 12345):
            errors = check_receipts(receipts_doc(receipt(block_hash=bad_hash)))
            self.assertTrue(errors, bad_hash)
            self.assertIn("64 uppercase hex", joined(errors))

    def test_05_receipt_paid_to_fails_checksum_and_the_reason_is_reported(self):
        altered = SELLER[:-1] + ("a" if SELLER[-1] != "a" else "b")
        errors = check_receipts(receipts_doc(receipt(paid_to=altered)))
        self.assertIn("reason=bad_checksum", joined(errors))

        truncated = SELLER[:-1]
        errors = check_receipts(receipts_doc(receipt(paid_to=truncated)))
        self.assertIn("reason=bad_length", joined(errors))

        wrong_prefix = "nona_" + SELLER[5:]
        errors = check_receipts(receipts_doc(receipt(paid_to=wrong_prefix)))
        self.assertIn("reason=bad_prefix", joined(errors))

    def test_06_amount_raw_must_be_a_positive_integer_string(self):
        for bad_amount in ("0", "-1", "1.5", 250, None, "", "1e30"):
            errors = check_receipts(receipts_doc(receipt(amount_raw=bad_amount)))
            self.assertTrue(errors, bad_amount)
            self.assertIn("amount_raw", joined(errors))

    def test_07_editing_or_removing_an_existing_receipt_is_refused(self):
        old = receipts_doc(receipt())
        edited = receipts_doc(receipt(amount_raw=str(XNO), amount_xno="1"))
        errors = check_append_only(old, edited)
        self.assertTrue(errors)
        self.assertIn("append-only", joined(errors))
        self.assertIn("amount_raw", joined(errors))

        removed = receipts_doc()
        errors = check_append_only(old, removed)
        self.assertIn("was removed", joined(errors))

        appended = receipts_doc(receipt(), receipt(id="receipt-002", job_id="job-002",
                                                   block_hash=_block("1A2B")))
        self.assertEqual(check_append_only(old, appended), [])

    def test_07b_append_only_against_a_real_git_parent(self):
        jobs, receipts = settled_pair()
        root = self.tree(jobs, receipts)
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
        for command in (["git", "init", "-q", "-b", "main"], ["git", "add", "-A"],
                        ["git", "commit", "-qm", "seed"]):
            subprocess.run(command, cwd=root, check=True, env=env,
                           stdout=subprocess.DEVNULL)
        code, output = self.run_tree(root, base_ref="HEAD")
        self.assertEqual(code, 0, output)

        receipts["receipts"][0]["amount_xno"] = "1"
        receipts["receipts"][0]["amount_raw"] = str(XNO)
        with open(os.path.join(root, "receipts.json"), "w") as handle:
            json.dump(receipts, handle)
        code, output = self.run_tree(root, base_ref="HEAD")
        self.assertEqual(code, 1)
        self.assertIn("append-only", output)

    def test_08_duplicate_ids(self):
        errors = check_jobs(jobs_doc(job(), job()))
        self.assertIn("duplicate job id", joined(errors))
        errors = check_receipts(receipts_doc(receipt(), receipt()))
        self.assertIn("duplicate receipt id", joined(errors))

    def test_09_claimed_by_must_agree_with_state(self):
        errors = check_jobs(jobs_doc(job(state="claimed", claimed_by=None, claim_url="u")))
        self.assertIn("claimed_by", joined(errors))
        errors = check_jobs(jobs_doc(job(state="open", claimed_by="somebody")))
        self.assertIn("claimed by nobody", joined(errors))
        self.assertEqual(
            check_jobs(jobs_doc(job(state="claimed", claimed_by="somebody", claim_url="u"))), [])

    def test_10_state_outside_the_allowed_six(self):
        errors = check_jobs(jobs_doc(job(state="in_progress")))
        message = joined(errors)
        for state in ("open", "claimed", "delivered", "settled", "expired", "cancelled"):
            self.assertIn(state, message)

    def test_11_expires_must_follow_posted(self):
        errors = check_jobs(jobs_doc(job(expires="2026-09-25T06:00:00Z")))
        self.assertIn("does not come after", joined(errors))
        errors = check_jobs(jobs_doc(job(expires=job()["posted"])))
        self.assertIn("does not come after", joined(errors))

    def test_12_the_secret_gate_runs_first_and_stops_everything(self):
        seed = "DEADBEEF" * 8  # 64 hex characters, exactly what a Nano seed is
        jobs, receipts = settled_pair()
        jobs["jobs"][0]["price_raw"] = "1"  # a second, unrelated failure
        root = self.tree(jobs, receipts, {"notes.md": "scratch key %s\n" % seed})
        code, output = self.run_tree(root)
        self.assertEqual(code, 1)
        self.assertIn("SECRET GATE FAILED", output)
        self.assertIn("notes.md", output)
        # it ran first: the price failure was never reached
        self.assertNotIn("disagree", output)
        # and it did not write stats.json
        self.assertFalse(os.path.exists(os.path.join(root, "stats.json")))

    def test_12b_a_block_hash_field_is_the_one_permitted_64_hex_value(self):
        jobs, receipts = settled_pair()
        self.assertEqual(scan_for_secrets(self.tree(jobs, receipts)), [])
        # the same 64 hex characters under any other key are a finding
        receipts["receipts"][0]["verify"] = _block()
        findings = scan_for_secrets(self.tree(jobs, receipts))
        self.assertTrue(findings)
        self.assertIn("verify", joined(findings))

    def test_12c_a_longer_hex_run_cannot_slip_past_the_64_character_window(self):
        jobs, receipts = settled_pair()
        root = self.tree(jobs, receipts, {"notes.md": "ABCD" * 32})  # 128 hex
        self.assertTrue(scan_for_secrets(root))

    def test_13_a_clean_pair_exits_zero_and_prints_the_settled_count(self):
        jobs, receipts = settled_pair()
        root = self.tree(jobs, receipts)
        code, output = self.run_tree(root)
        self.assertEqual(code, 0, output)
        self.assertIn("jobs_settled=1", output)
        self.assertIn("jobs_open=1", output)
        with open(os.path.join(root, "stats.json")) as handle:
            stats = json.load(handle)
        self.assertEqual(stats["jobs_settled"], 1)
        self.assertEqual(stats["jobs_open"], 1)
        self.assertEqual(stats["sellers_paid"], 1)
        self.assertEqual(stats["first_settlement"], "2026-09-26T09:14:02Z")
        self.assertEqual(stats["last_settlement"], "2026-09-26T09:14:02Z")

    def test_14_paid_total_is_the_exact_integer_sum_rendered_through_raw_to_xno(self):
        # Two amounts whose sum is unrepresentable in binary floating point.
        first = receipt(job_id="job-002", amount_raw=str(XNO // 10), amount_xno="0.1")
        second = receipt(id="receipt-002", job_id="job-003", paid_to=BURN,
                         amount_raw=str(2 * XNO // 10), amount_xno="0.2",
                         block_hash=_block("1A2B"))
        stats = compute_stats(jobs_doc(), receipts_doc(first, second))
        self.assertEqual(stats["paid_xno_total"], "0.3")
        self.assertEqual(stats["sellers_paid"], 2)

        # one raw more than a float can distinguish from 0.1 XNO
        odd = receipt(amount_raw=str(XNO // 10 + 1), amount_xno="0.100000000000000000000000000001")
        stats = compute_stats(jobs_doc(), receipts_doc(odd))
        self.assertEqual(stats["paid_xno_total"], "0.100000000000000000000000000001")
        self.assertNotEqual(stats["paid_xno_total"], "0.1")


# --------------------------------------------------------------------------
# the error paths the numbered list does not name
# --------------------------------------------------------------------------

class ErrorPaths(TreeCase):

    def test_settled_job_pointing_at_a_receipt_that_does_not_exist(self):
        jobs, _ = settled_pair()
        errors = cross_check(jobs, receipts_doc())
        self.assertIn("not in receipts.json", joined(errors))

    def test_receipt_amount_must_equal_the_job_price(self):
        jobs, receipts = settled_pair()
        receipts["receipts"][0]["amount_raw"] = str(XNO)
        receipts["receipts"][0]["amount_xno"] = "1"
        errors = cross_check(jobs, receipts)
        self.assertIn("which is priced at", joined(errors))

    def test_receipt_naming_a_job_that_does_not_exist(self):
        errors = cross_check(jobs_doc(), receipts_doc(receipt()))
        self.assertIn("not in jobs.json", joined(errors))

    def test_two_receipts_cannot_claim_the_same_block(self):
        twice = receipts_doc(receipt(), receipt(id="receipt-002", job_id="job-002"))
        self.assertIn("more than one receipt", joined(check_receipts(twice)))

    def test_receipt_id_mismatch_between_job_and_receipt(self):
        jobs, receipts = settled_pair()
        receipts["receipts"][0]["job_id"] = "job-999"
        errors = cross_check(jobs, receipts)
        self.assertTrue(errors)

    def test_non_settled_job_may_not_carry_a_receipt_id(self):
        errors = check_jobs(jobs_doc(job(receipt_id="receipt-001")))
        self.assertIn("only a settled job carries one", joined(errors))

    def test_description_over_1200_characters(self):
        errors = check_jobs(jobs_doc(job(description="x" * 1201)))
        self.assertIn("the limit is 1200", joined(errors))

    def test_acceptance_must_be_a_non_empty_list_of_statements(self):
        self.assertIn("acceptance", joined(check_jobs(jobs_doc(job(acceptance=[])))))
        self.assertIn("acceptance", joined(check_jobs(jobs_doc(job(acceptance="one line")))))
        self.assertIn("acceptance", joined(check_jobs(jobs_doc(job(acceptance=["  "])))))

    def test_currency_must_be_xno(self):
        document = jobs_doc(job())
        document["currency"] = "USD"
        self.assertIn("currency", joined(check_jobs(document)))

    def test_malformed_timestamps(self):
        for bad in ("2026-09-26", "2026-09-26T06:00:00+00:00", "2026-13-01T00:00:00Z", None):
            self.assertTrue(check_jobs(jobs_doc(job(posted=bad))), bad)

    def test_impossible_calendar_dates(self):
        # A day that does not exist in that month is not a timestamp. The
        # pattern and the 1..31 range both pass it, so only a real calendar
        # check catches it.
        for bad in ("2026-02-31T00:00:00Z", "2026-02-29T00:00:00Z",
                    "2026-04-31T00:00:00Z", "2026-06-31T00:00:00Z"):
            self.assertIsNone(validate._rfc3339(bad), bad)
            self.assertTrue(check_jobs(jobs_doc(job(posted=bad))), bad)

    def test_real_dates_including_a_leap_day_are_accepted(self):
        for good in ("2024-02-29T00:00:00Z", "2026-01-31T23:59:59Z",
                     "2026-12-31T23:59:60Z"):
            self.assertIsNotNone(validate._rfc3339(good), good)

    def test_unreadable_and_malformed_files(self):
        root = tempfile.mkdtemp()
        code, output = self.run_tree(root)
        self.assertEqual(code, 1)
        self.assertIn("cannot be read", output)

        with open(os.path.join(root, "jobs.json"), "w") as handle:
            handle.write("{not json")
        with open(os.path.join(root, "receipts.json"), "w") as handle:
            handle.write("{}")
        code, output = self.run_tree(root)
        self.assertEqual(code, 1)
        self.assertIn("not valid JSON", output)

    def test_missing_base_ref_skips_the_append_only_check_and_says_so(self):
        jobs, receipts = settled_pair()
        code, output = self.run_tree(self.tree(jobs, receipts), base_ref="no-such-ref")
        self.assertEqual(code, 0, output)
        self.assertIn("append-only check skipped", output)

    def test_no_stats_written_when_anything_fails(self):
        root = self.tree(jobs_doc(job(state="bogus")), receipts_doc())
        code, _ = self.run_tree(root)
        self.assertEqual(code, 1)
        self.assertFalse(os.path.exists(os.path.join(root, "stats.json")))


# --------------------------------------------------------------------------
# the vendored codec, pinned to answers the swarm cannot influence
# --------------------------------------------------------------------------

class VendoredCodec(unittest.TestCase):

    def test_all_zero_public_key_is_the_canonical_burn_address(self):
        self.assertEqual(validate.nanoaddr.encode(bytes(32)), BURN)
        self.assertTrue(validate.nanoaddr.validate(BURN)["valid"])

    def test_every_single_character_change_breaks_a_valid_address(self):
        alphabet = validate.nanoaddr.ALPHABET
        body = SELLER[5:]
        for index, original in enumerate(body):
            for replacement in alphabet:
                if replacement == original:
                    continue
                candidate = "nano_" + body[:index] + replacement + body[index + 1:]
                self.assertFalse(
                    validate.nanoaddr.validate(candidate)["valid"],
                    "a one-character change at %d produced a valid address" % index,
                )

    def test_money_never_round_trips_through_a_float(self):
        from money import raw_to_xno, xno_to_raw
        one_raw_under = 10 ** 30 - 1
        self.assertEqual(xno_to_raw(raw_to_xno(one_raw_under)), one_raw_under)
        self.assertEqual(raw_to_xno(1), "0." + "0" * 29 + "1")


# --------------------------------------------------------------------------
# the live repository must itself be valid
# --------------------------------------------------------------------------

class LiveRepository(unittest.TestCase):

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def test_the_committed_jobs_and_receipts_pass(self):
        out = io.StringIO()
        self.assertEqual(run(self.root, write_stats=False, out=out), 0, out.getvalue())

    def test_the_repository_holds_no_standalone_64_hex_run(self):
        self.assertEqual(scan_for_secrets(self.root), [])

    def test_three_jobs_are_open(self):
        with open(os.path.join(self.root, "jobs.json")) as handle:
            jobs = json.load(handle)["jobs"]
        self.assertEqual(sum(1 for j in jobs if j["state"] == "open"), 3)
        self.assertTrue(any(int(j["price_raw"]) > 10 ** 29 for j in jobs),
                        "no job is priced above 0.1 XNO")


if __name__ == "__main__":
    unittest.main()


class SecretGateAndBlockHashInteraction(TreeCase):
    """The gate must not mask the block_hash format error with a key warning."""

    def test_a_lowercase_block_hash_is_reported_as_a_casing_error(self):
        jobs, receipts = settled_pair()
        receipts["receipts"][0]["block_hash"] = _block().lower()
        code, output = self.run_tree(self.tree(jobs, receipts))
        self.assertEqual(code, 1)
        self.assertIn("64 uppercase hex", output)
        self.assertNotIn("SECRET GATE", output)

    def test_a_non_hash_string_under_block_hash_still_trips_the_gate_if_it_is_a_key(self):
        jobs, receipts = settled_pair()
        # 65 hex characters: not a block hash, and the gate must still see it
        receipts["receipts"][0]["block_hash"] = "A" * 65
        code, output = self.run_tree(self.tree(jobs, receipts))
        self.assertEqual(code, 1)
        self.assertIn("SECRET GATE", output)

    def test_a_key_hidden_in_a_block_hash_field_is_still_refused(self):
        jobs, receipts = settled_pair()
        receipts["receipts"][0]["block_hash"] = "deadbeef" * 8
        code, output = self.run_tree(self.tree(jobs, receipts))
        self.assertEqual(code, 1, output)
