"""Three claims that are allowed to disagree, and the weakest one saying so.

The decisive tests are 1, 2, 10 and 11.

Test 1 is `antonzoomagent`'s question from 2026-10-08T19:01Z as a fixture -
*"how would you handle a recipient who signs receipt on delivery but discovers
the resource was unusable an hour later?"* - run end to end: settled true,
delivered true, accepted FALSE, outcome `paid_and_unusable`. An implementation
that cannot hold those three at once fails here.

Test 2 is the one-line version of the same defect: after `deliver`, the
`accepted` claim must still be null. Delivery is not acceptance, and
`fulfillment_receipt.py` conflating them is why this module exists.

Test 10 is the hour-later case in the data model rather than in a comment. An
attestation after the window is RECORDED and marked late, the row's operative
outcome stays `window_elapsed_unattested`, and the late attestation is still
there to read.

Test 11 is `miacollective`'s "undrifted garbage" rule: the FIRST attestation is
binding and a second cannot replace it, only append. A record that can be
revised by whoever speaks last is not a record.

Every fixture is built independently of the module's own `--self-test`
controls, deliberately: driving these assertions from the module's own fixtures
would let a mutation that breaks both drift past green.

Nothing opens a socket, and nothing can: test 18 walks the import graph.

No 64-hex run stands as a single literal, matching the project's secret gate.
"""

import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "vendor"))

import acceptance_receipt as ar  # noqa: E402
import nanoaddr  # noqa: E402

NOW = "2026-10-09T06:00:00Z"
PAYEE = nanoaddr.encode(hashlib.blake2b(b"test-acceptance-payee",
                                        digest_size=32).digest())

# antonzoomagent, 2026-10-08T19:01Z, and the reason the `unusable` verdict is a
# first-class outcome rather than a flavour of `rejected`.
TRUNCATED = "transcript truncated at 40% so the decision could not be made"


def good(**overrides):
    base = dict(order_key="buy-2026-10-09-001", settled_block="AB" * 32,
                amount_raw="50" + "0" * 27, payee=PAYEE,
                request_context_sha256="cd" * 32, anchor_frontier="EF" * 32,
                anchor_height=1234567, dispute_window_hours=24)
    base.update(overrides)
    return base


def opened(**overrides):
    return ar.open_acceptance(ar.empty_acceptances(), now=NOW, **good(**overrides))


def delivered(document, acceptance_id, digest="12" * 32, now=NOW):
    return ar.deliver(document, acceptance_id,
                      "https://example.invalid/summary.md", digest, now=now)


class ThreeClaims(unittest.TestCase):
    # -- 1 ------------------------------------------------------------------
    def test_1_the_antonzoomagent_fixture_all_three_disagreeing(self):
        """Settled, delivered, and the buyer says it did not do the job."""
        document, row = opened()
        document, _ = delivered(document, row["id"])
        document, attested = ar.attest(document, row["id"], "unusable",
                                       TRUNCATED, now=NOW)
        document, closed = ar.close(document, row["id"], now=NOW)

        claims = closed["claims"]
        self.assertIs(claims["settled"]["verdict"], True)
        self.assertIs(claims["delivered"]["verdict"], True)
        self.assertIs(claims["accepted"]["verdict"], False)
        self.assertEqual(claims["accepted"]["outcome"], "unusable")
        self.assertEqual(claims["accepted"]["reason"], TRUNCATED)
        self.assertEqual(closed["outcome"], "paid_and_unusable")
        # All three remain separately readable, with their own falsifiers.
        for name in ar.CLAIM_NAMES:
            self.assertIn("rule", claims[name])
        self.assertIn("falsified_by", claims["settled"])
        self.assertIn("falsified_by", claims["delivered"])
        self.assertIn("weaker_than_the_others_because", claims["accepted"])
        self.assertIs(attested["claims"]["accepted"]["outcome_binding"], True)

    # -- 2 ------------------------------------------------------------------
    def test_2_delivery_does_not_touch_the_accepted_claim(self):
        """A7. Conflating the two is the defect six agents named."""
        document, row = opened()
        document, after = delivered(document, row["id"])
        self.assertIs(after["claims"]["delivered"]["verdict"], True)
        self.assertIsNone(after["claims"]["accepted"]["verdict"])
        self.assertEqual(after["claims"]["accepted"]["verdict_is"],
                         "not_yet_attested")
        self.assertNotIn("attested_at", after["claims"]["accepted"])
        self.assertNotIn("outcome", after["claims"]["accepted"])

    # -- 3 ------------------------------------------------------------------
    def test_3_the_anchor_is_mandatory(self):
        """A1. juan_carlos' clause: a moment neither party authored."""
        with tempfile.TemporaryDirectory() as tmp:
            base = ["open", "--order-key", "buy-2026-10-09-001",
                    "--request-context-sha256", "cd" * 32,
                    "--dispute-window-hours", "24"]
            done = cli(tmp, *(base + ["--anchor-height", "1234567"]))
            self.assertEqual(done.returncode, 64, done.stderr)
            self.assertIn("anchor-frontier", done.stderr)

            done = cli(tmp, *(base + ["--anchor-frontier", "EF" * 32]))
            self.assertEqual(done.returncode, 64, done.stderr)
            self.assertIn("anchor-height", done.stderr)

    def test_3b_a_malformed_anchor_is_a_refusal_not_a_usage_error(self):
        """Absent is 64; present and wrong is 2. The two are different."""
        for field, value, code in (("anchor_frontier", "EF" * 31, "bad_anchor"),
                                   ("anchor_frontier", "zz" * 32, "bad_anchor"),
                                   ("anchor_height", 0, "bad_anchor"),
                                   ("anchor_height", "later", "bad_anchor")):
            with self.assertRaises(ar.Refusal) as caught:
                opened(**{field: value})
            self.assertEqual(caught.exception.code, code,
                             "%s=%r" % (field, value))

    # -- 4 ------------------------------------------------------------------
    def test_4_the_request_context_digest_is_mandatory(self):
        """A2. vina's field: recorded, never interpreted."""
        with tempfile.TemporaryDirectory() as tmp:
            done = cli(tmp, "open", "--order-key", "buy-2026-10-09-001",
                       "--anchor-frontier", "EF" * 32,
                       "--anchor-height", "1234567",
                       "--dispute-window-hours", "24")
            self.assertEqual(done.returncode, 64, done.stderr)
            self.assertIn("request-context-sha256", done.stderr)

    # -- 5 ------------------------------------------------------------------
    def test_5_the_dispute_window_is_bounded(self):
        """A3."""
        for bad in (0, 721, -1, "soon"):
            with self.assertRaises(ar.Refusal) as caught:
                opened(dispute_window_hours=bad)
            self.assertEqual(caught.exception.code,
                             "dispute_window_out_of_range", repr(bad))
        for ok in (1, 720, "24"):
            _, row = opened(dispute_window_hours=ok)
            self.assertEqual(row["dispute_window_hours"], int(ok))
        _, row = opened(dispute_window_hours=24)
        self.assertEqual(row["window_closes"], "2026-10-10T06:00:00Z")

    # -- 6 ------------------------------------------------------------------
    def test_6_a_payee_one_character_off_is_refused(self):
        """A4, with the checksum that key really implies named."""
        broken = PAYEE[:-1] + ("4" if PAYEE[-1] != "4" else "5")
        with self.assertRaises(ar.Refusal) as caught:
            opened(payee=broken)
        self.assertEqual(caught.exception.code, "payee_checksum_failed")
        self.assertIn("the checksum is", caught.exception.detail)

    # -- 7 ------------------------------------------------------------------
    def test_7_no_standalone_64_hex_run_reaches_a_committed_file(self):
        """A5. The halves join back to the digests the test recomputes."""
        document, row = opened()
        document, _ = delivered(document, row["id"])
        document, _ = ar.attest(document, row["id"], "accepted",
                                "read it, used it, it answered the question",
                                now=NOW)
        published = ar.feed(document, now=NOW)
        for label, payload in (("acceptances.json", document),
                               ("feed/acceptances.json", published)):
            text = ar.serialise(payload).decode("utf-8")
            self.assertIsNone(_standalone_64_hex(text), label)

        stored = document["acceptances"][0]
        self.assertEqual("".join(stored["request_context_sha256_halves"]),
                         "cd" * 32)
        self.assertEqual("".join(stored["anchor"]["frontier_halves"]),
                         "EF" * 32)
        self.assertEqual(
            "".join(stored["claims"]["settled"]["inputs"]["block_halves"]),
            "AB" * 32)
        self.assertEqual(
            "".join(stored["claims"]["delivered"]["inputs"]
                    ["artifact_sha256_halves"]), "12" * 32)
        for pair in (stored["request_context_sha256_halves"],
                     stored["anchor"]["frontier_halves"]):
            self.assertEqual([len(half) for half in pair], [32, 32])

    # -- 8 ------------------------------------------------------------------
    def test_8_a_partial_citation_never_infers_a_settlement(self):
        """A6. Any one of the three missing and the verdict is null."""
        for missing in ("settled_block", "amount_raw", "payee"):
            _, row = opened(**{missing: None})
            claim = row["claims"]["settled"]
            self.assertIsNone(claim["verdict"], missing)
            self.assertEqual(claim["verdict_is"], "not_yet_observed", missing)
            self.assertIn(missing, claim["not_yet_observed_because"])
        _, row = opened()
        self.assertIs(row["claims"]["settled"]["verdict"], True)
        self.assertEqual(row["claims"]["settled"]["verdict_is"], "measured")

    def test_8b_a_malformed_citation_is_refused_rather_than_dropped(self):
        """An unreadable block or amount must not quietly become `null`."""
        for field, value, code in (("settled_block", "AB" * 31, "bad_block_hash"),
                                   ("settled_block", "zz" * 32, "bad_block_hash"),
                                   ("amount_raw", "0", "bad_amount_raw"),
                                   ("amount_raw", "-5", "bad_amount_raw"),
                                   ("amount_raw", "1.5", "bad_amount_raw")):
            with self.assertRaises(ar.Refusal) as caught:
                opened(**{field: value})
            self.assertEqual(caught.exception.code, code,
                             "%s=%r" % (field, value))

    # -- 9 ------------------------------------------------------------------
    def test_9_a_second_different_artifact_digest_is_refused(self):
        """A8."""
        document, row = opened()
        document, _ = delivered(document, row["id"])
        with self.assertRaises(ar.Refusal) as caught:
            delivered(json.loads(json.dumps(document)), row["id"],
                      digest="34" * 32)
        self.assertEqual(caught.exception.code, "already_delivered")
        self.assertIn("12" * 16, caught.exception.detail)

        # The SAME digest again is idempotent, not a rewrite.
        again, same = delivered(json.loads(json.dumps(document)), row["id"],
                                digest="12" * 32)
        self.assertIs(same["claims"]["delivered"]["verdict"], True)
        self.assertEqual(len(again["acceptances"]), 1)


class TheWindow(unittest.TestCase):
    # -- 10 -----------------------------------------------------------------
    def test_10_the_hour_later_case_is_recorded_and_not_binding(self):
        """A10. antonzoomagent's question, answered in the data model."""
        document, row = opened()
        document, _ = delivered(document, row["id"])
        late_at = "2026-10-10T07:00:00Z"          # window_closes + 1h
        document, attested = ar.attest(document, row["id"], "unusable",
                                       TRUNCATED, at=late_at, now=late_at)
        self.assertTrue(attested["recorded_but_not_binding"])
        accepted = attested["claims"]["accepted"]
        self.assertIs(accepted["late"], True)
        self.assertIs(accepted["outcome_binding"], False)
        self.assertEqual(accepted["outcome"], "unusable")
        self.assertEqual(accepted["reason"], TRUNCATED)

        document, closed = ar.close(document, row["id"], now=late_at)
        self.assertEqual(closed["outcome"], "window_elapsed_unattested")
        # The late attestation is still there to read.
        self.assertEqual(closed["claims"]["accepted"]["attested_at"], late_at)
        self.assertEqual(ar.feed(document, now=late_at)["counts"]
                         ["late_attestations"], 1)

    # -- 11 -----------------------------------------------------------------
    def test_11_the_first_attestation_stands(self):
        """A11. miacollective: a record revisable by whoever speaks last."""
        document, row = opened()
        document, _ = delivered(document, row["id"])
        document, _ = ar.attest(document, row["id"], "accepted",
                                "read it, used it, it answered the question",
                                now=NOW)
        document, second = ar.attest(document, row["id"], "unusable",
                                     TRUNCATED, now=NOW)
        self.assertTrue(second["first_attestation_stands"])

        accepted = second["claims"]["accepted"]
        self.assertIs(accepted["verdict"], True)
        self.assertEqual(accepted["outcome"], "accepted")
        self.assertEqual(len(accepted["subsequent_attestations"]), 1)
        self.assertEqual(accepted["subsequent_attestations"][0]["outcome"],
                         "unusable")

        document, closed = ar.close(document, row["id"], now=NOW)
        self.assertEqual(closed["outcome"], "accepted")

    # -- 12 -----------------------------------------------------------------
    def test_12_attesting_before_delivery_is_refused(self):
        """A12. There is nothing to judge yet."""
        document, row = opened()
        with self.assertRaises(ar.Refusal) as caught:
            ar.attest(document, row["id"], "accepted", "x" * 20, now=NOW)
        self.assertEqual(caught.exception.code,
                         "cannot_attest_before_delivery")

    # -- 13 -----------------------------------------------------------------
    def test_13_the_window_cannot_be_shortened_by_whoever_benefits(self):
        """A13, and the refusal names the seconds remaining."""
        document, row = opened()
        document, _ = delivered(document, row["id"])
        one_second_early = "2026-10-10T05:59:59Z"
        with self.assertRaises(ar.Refusal) as caught:
            ar.close(json.loads(json.dumps(document)), row["id"],
                     now=one_second_early)
        self.assertEqual(caught.exception.code, "window_still_open")
        self.assertIn("1 seconds", caught.exception.detail)
        self.assertIn(row["window_closes"], caught.exception.detail)

        # One second later it closes, unattested.
        _, closed = ar.close(document, row["id"], now="2026-10-10T06:00:00Z")
        self.assertEqual(closed["outcome"], "window_elapsed_unattested")

    def test_13b_a_binding_attestation_closes_inside_the_window(self):
        """The window exists to protect the buyer, not to delay a verdict."""
        document, row = opened()
        document, _ = delivered(document, row["id"])
        document, _ = ar.attest(document, row["id"], "accepted",
                                "read it, used it, it answered the question",
                                now=NOW)
        _, closed = ar.close(document, row["id"], now=NOW)
        self.assertEqual(closed["outcome"], "accepted")

    # -- 14 -----------------------------------------------------------------
    def test_14_a_reason_shorter_than_sixteen_characters_is_refused(self):
        document, row = opened()
        document, _ = delivered(document, row["id"])
        with self.assertRaises(ar.Refusal) as caught:
            ar.attest(json.loads(json.dumps(document)), row["id"], "unusable",
                      "x" * 15, now=NOW)
        self.assertEqual(caught.exception.code, "reason_too_short")
        _, attested = ar.attest(json.loads(json.dumps(document)), row["id"],
                                "unusable", "x" * 16, now=NOW)
        self.assertEqual(attested["claims"]["accepted"]["reason"], "x" * 16)
        for bad in (None, "", 16):
            with self.assertRaises(ar.Refusal) as caught:
                ar.attest(json.loads(json.dumps(document)), row["id"],
                          "unusable", bad, now=NOW)
            self.assertEqual(caught.exception.code, "reason_too_short", repr(bad))

    # -- 15 -----------------------------------------------------------------
    def test_15_paid_and_never_delivered_is_published_as_that(self):
        """A14. Every outcome is published, including this one."""
        document, row = opened()
        _, closed = ar.close(document, row["id"], now="2026-10-10T06:00:00Z")
        self.assertEqual(closed["outcome"], "paid_not_delivered")
        published = ar.feed(document, now="2026-10-10T06:00:00Z")
        self.assertEqual(published["counts"]["paid_not_delivered"], 1)
        self.assertEqual(published["acceptances"][0]["outcome"],
                         "paid_not_delivered")

    def test_15b_an_unsettled_row_closes_unsettled(self):
        """The table's last line: with no settlement nothing else matters."""
        document, row = opened(settled_block=None)
        document, _ = delivered(document, row["id"])
        document, _ = ar.attest(document, row["id"], "accepted",
                                "it was fine, but nobody paid for it", now=NOW)
        _, closed = ar.close(document, row["id"], now=NOW)
        self.assertEqual(closed["outcome"], "unsettled")
        self.assertEqual(ar.feed(document, now=NOW)["counts"]["unsettled"], 1)

    def test_15c_a_closed_record_is_not_reopened(self):
        document, row = opened()
        document, _ = ar.close(document, row["id"], now="2026-10-10T06:00:00Z")
        with self.assertRaises(ar.Refusal) as caught:
            ar.close(document, row["id"], now="2026-10-10T07:00:00Z")
        self.assertEqual(caught.exception.code, "already_closed")


class Feed(unittest.TestCase):
    # -- 16 -----------------------------------------------------------------
    def test_16_every_count_is_present_even_at_zero(self):
        """A16. `paid_and_unusable` is never omitted or folded away."""
        counts = ar.feed(ar.empty_acceptances(), now=NOW)["counts"]
        for name in ("open", "accepted", "paid_and_unusable",
                     "paid_not_delivered", "window_elapsed_unattested",
                     "unsettled", "late_attestations"):
            self.assertIn(name, counts)
            self.assertEqual(counts[name], 0)
        # Built from OUTCOMES, so a sixth outcome cannot arrive without its
        # counter.
        for name in ar.OUTCOMES:
            self.assertIn(name, counts)

    def test_16b_the_feed_says_which_claim_is_weakest_and_what_is_unproven(self):
        published = ar.feed(ar.empty_acceptances(), now=NOW)
        self.assertIn("accepted", published["the_weakest_claim"])
        self.assertIn("can be wrong or lying", published["the_weakest_claim"])
        self.assertEqual(len(published["what_this_does_not_prove"]), 2)
        self.assertIn("nobody looked", " ".join(
            published["what_this_does_not_prove"]))
        self.assertIn("read_this_first", published)
        self.assertIn("block_info on a node you chose",
                      published["check_without_us"])

    # -- 17 -----------------------------------------------------------------
    def test_17_the_feed_is_deterministic_for_a_fixed_now(self):
        """A15."""
        document, row = opened()
        document, _ = delivered(document, row["id"])
        first = ar.serialise(ar.feed(document, now=NOW))
        second = ar.serialise(ar.feed(json.loads(json.dumps(document)), now=NOW))
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))

    # -- 18 -----------------------------------------------------------------
    def test_18_nothing_here_can_open_a_socket(self):
        reached = {entry["module"].split(".")[0]
                   for entry in ar.import_graph()}
        for module in ("socket", "http", "urllib", "ssl", "requests"):
            self.assertNotIn(module, reached)
        with open(os.path.join(ROOT, "acceptance_receipt.py"),
                  encoding="utf-8") as handle:
            source = handle.read()
        for name in ("http.client", "urllib.request", "socket(", "ssl."):
            self.assertNotIn(name, source)

    # -- 19 -----------------------------------------------------------------
    def test_19_the_vina_case_two_contexts_for_one_order_key(self):
        """One order_key, two context digests: both valid, both published.

        The divergence is recorded, not resolved. That is vina's rule: the
        record shows that the agent is acting on different reasoning, and says
        nothing about which reasoning was right.
        """
        document, first = opened()
        document, second = ar.open_acceptance(
            document, now=NOW, **good(request_context_sha256="ab" * 32))
        self.assertEqual(first["order_key"], second["order_key"])
        self.assertNotEqual(first["id"], second["id"])
        self.assertNotEqual(first["request_context_sha256_halves"],
                            second["request_context_sha256_halves"])

        published = ar.feed(document, now=NOW)
        digests = {"".join(row["request_context_sha256_halves"])
                   for row in published["acceptances"]}
        self.assertEqual(len(digests), 2)
        self.assertEqual(published["counts"]["open"], 2)
        self.assertIn("does not resolve", published["request_context_note"])

    # -- 20 -----------------------------------------------------------------
    def test_20_the_self_test_refuses_at_least_ten_times(self):
        verdict = ar.self_test()
        self.assertEqual(verdict["failures"], [])
        self.assertGreaterEqual(verdict["negative_controls"], 10)


class Discipline(unittest.TestCase):
    def test_21_the_anchor_says_who_chose_it_and_why(self):
        """An anchor nobody can see the provenance of anchors nothing."""
        _, row = opened()
        self.assertEqual(row["anchor"]["chosen_by"], "neither_party")
        self.assertIn("neither the buyer nor the seller authored",
                      row["anchor"]["why"])
        self.assertEqual(row["anchor"]["height"], 1234567)

    def test_22_acceptance_ids_are_the_lowest_unused_index(self):
        document, first = opened()
        document, second = ar.open_acceptance(document, now=NOW, **good())
        self.assertEqual(first["id"], "acc-2026-10-09-001")
        self.assertEqual(second["id"], "acc-2026-10-09-002")

        full = ar.empty_acceptances()
        full["acceptances"] = [
            {"id": "acc-2026-10-09-%03d" % index, "state": "closed"}
            for index in range(1, ar.MAX_ACCEPTANCES_PER_DATE)]
        with self.assertRaises(ar.Refusal) as caught:
            ar.next_acceptance_id(full, NOW)
        self.assertEqual(caught.exception.code,
                         "acceptance_id_space_exhausted")
        self.assertEqual(caught.exception.exit_code, 3)

    def test_23_every_refusal_code_is_declared(self):
        with self.assertRaises(AssertionError):
            ar.Refusal("invented_code", "nope")

    def test_24_fulfillment_receipt_is_left_exactly_as_it_was(self):
        """The spec asked for a citation this repository's own law forbids.

        `agent-tool-acceptance-receipt.md` says the build "should make
        `fulfillment_receipt` cite an `acceptance_id` where one exists". It
        cannot, and that is not an oversight here:
        `tests/test_divergence_note.py` holds a class called
        `TheOptionalKeyIsTheOnlyOne` - "the door opened in fulfillment_receipt
        is exactly one key wide" - which asserts
        `OPTIONAL_FULFILLMENT_KEYS == frozenset({"divergence_notes"})`.
        Widening that set is editing the guard to admit the change it guards
        against, so it is left alone and the overlap stays uncited until
        someone decides deliberately to open the door a second key.

        This test pins the decision so the next build does not quietly take
        the other branch. The two tools are separate and neither reads the
        other's records.
        """
        import fulfillment_receipt
        self.assertEqual(fulfillment_receipt.OPTIONAL_FULFILLMENT_KEYS,
                         frozenset({"divergence_notes"}))
        self.assertNotIn("acceptance_id", fulfillment_receipt.FULFILLMENT_KEYS)
        self.assertNotIn("fulfillment_receipt",
                         {entry["module"] for entry in ar.import_graph()})

    def test_25_the_record_carries_exactly_its_declared_fields(self):
        document, _ = opened()
        self.assertEqual(set(document["acceptances"][0]),
                         set(ar.ACCEPTANCE_FIELDS))


class Cli(unittest.TestCase):
    def test_26_the_whole_path_through_the_command_line(self):
        """open -> deliver -> attest unusable -> close, and the exit codes."""
        with tempfile.TemporaryDirectory() as tmp:
            done = cli(tmp, "open", "--order-key", "buy-2026-10-09-001",
                       "--settled-block", "AB" * 32,
                       "--amount-raw", "50" + "0" * 27, "--payee", PAYEE,
                       "--request-context-sha256", "cd" * 32,
                       "--anchor-frontier", "EF" * 32,
                       "--anchor-height", "1234567",
                       "--dispute-window-hours", "24")
            self.assertEqual(done.returncode, 0, done.stderr)
            row = json.loads(done.stdout)
            self.assertEqual(row["acceptance_id"], "acc-2026-10-09-001")
            self.assertIs(row["claims"]["settled"]["verdict"], True)

            # Attesting before delivery is a refusal, not a silent pass.
            done = cli(tmp, "attest", "--id", row["id"], "--verdict",
                       "accepted", "--reason", "x" * 20)
            self.assertEqual(done.returncode, 2, done.stdout)
            self.assertIn("reason=cannot_attest_before_delivery", done.stderr)

            done = cli(tmp, "deliver", "--id", row["id"], "--artifact-url",
                       "https://example.invalid/summary.md",
                       "--artifact-sha256", "12" * 32)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertIsNone(
                json.loads(done.stdout)["claims"]["accepted"]["verdict"])

            done = cli(tmp, "attest", "--id", row["id"], "--verdict",
                       "unusable", "--reason", TRUNCATED)
            self.assertEqual(done.returncode, 0, done.stderr)

            done = cli(tmp, "close", "--id", row["id"])
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(json.loads(done.stdout)["outcome"],
                             "paid_and_unusable")

            with open(os.path.join(tmp, "feed", "acceptances.json")) as handle:
                published = json.load(handle)
            self.assertEqual(published["counts"]["paid_and_unusable"], 1)
            self.assertEqual(published["counts"]["accepted"], 0)

    def test_27_the_self_test_runs_with_no_arguments_and_no_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            done = subprocess.run(
                [sys.executable, os.path.join(ROOT, "acceptance_receipt.py"),
                 "--self-test"], cwd=tmp, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout)["failures"], [])


def cli(cwd, *argv):
    return subprocess.run(
        [sys.executable, os.path.join(ROOT, "acceptance_receipt.py"), *argv,
         "--acceptances", os.path.join(cwd, "acceptances.json"),
         "--out", os.path.join(cwd, "feed", "acceptances.json"),
         "--now", NOW],
        capture_output=True, text=True)


def _standalone_64_hex(text):
    """The first standalone run of 64 lowercase hex characters, or None.

    Assembled at runtime rather than written as a literal: a 64-hex pattern in
    a committed test file is the very thing `validate.scan_for_secrets` refuses.
    """
    pattern = "(?<![0-9a-fA-F])[0-9a-f]{%d}(?![0-9a-fA-F])" % 64
    found = re.search(pattern, text)
    return found.group(0) if found else None


if __name__ == "__main__":
    unittest.main()
