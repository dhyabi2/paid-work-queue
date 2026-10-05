"""The order-bound amount: invoice-to-block as a function a stranger recomputes.

The decisive test in this file is test 1, and like
`tests/test_counterparty_role.py` test 1 it asserts two things at once: that
`fulfillment_receipt.verify` now refuses a receipt re-pointed at a different
order, AND that it returned `ok=True` with ZERO reasons on that same receipt
when the order binding is not checked. The second half records the gap. The
payment leg of a re-pointed receipt is genuinely valid - the block confirmed,
the grant allowed it, the amounts agree - and until this module existed nothing
in this repository recomputed which ORDER the block discharged, so a receipt
pointing at order N-1 while carrying order N's block read as our highest grade.
If test 1's second assertion ever goes red, `verify` has grown an opinion about
order binding without `order_amount_raw` and these two files have started to
disagree about whose job that is.

Fixtures here are built independently of `order_bound_amount`'s own
`--self-test` controls, deliberately: driving these assertions from the module's
fixtures would let a mutation that breaks both drift past green, which is the
whole failure mode `--self-test` exists to catch.

Nothing opens a socket, and nothing can: `test_15` walks the import graph.

No 64-hex run stands as a single literal, matching the project's secret gate -
every digest here is computed from a readable preimage or joined from halves.
"""

import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import authority_receipt
import fulfillment_receipt
import grant_mint
import order_bound_amount
from order_bound_amount import (
    DEFAULT_MODULUS, REASON_CODES, Refusal, derive, halves, joined, match,
    tag_for, unclaimed,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE = os.path.join(ROOT, "order_bound_amount.py")
VECTOR_PATH = os.path.join(ROOT, "vectors", "order-bound-amount-v1.json")

PRICE = "1000000000000000000000000000"          # 0.001 XNO in raw
BLOCK_A = "B7C8" * 16                            # synthetic, built at runtime
BLOCK_B = "C1D2" * 16


def d(text):
    """A 64-hex order digest from a readable preimage."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def cli(*args, stdin=None):
    """Run the module as a program. Returns (returncode, stdout, stderr)."""
    proc = subprocess.run([sys.executable, MODULE] + list(args),
                          input=stdin, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def written(document):
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(document, handle)
    handle.close()
    return handle.name


class TheDefectThisFileCloses(unittest.TestCase):
    """-- 1 -- a receipt re-pointed at another order, with the real block."""

    def _repointed(self):
        receipt, grant, block, delivery, attestation = (
            fulfillment_receipt._control_set())
        other = authority_receipt.request_digest(
            {"job": "job-N-minus-1", "unit": "an earlier, cheaper study"})
        moved_receipt = dict(receipt, request_digest=other,
                             request_id="order-N-minus-1")
        moved_delivery = dict(delivery, request_digest=other,
                              request_id="order-N-minus-1")
        reattested = dict(attestation, delivery_digest=fulfillment_receipt.digest(
            fulfillment_receipt.serialise(moved_delivery)))
        return moved_receipt, grant, block, moved_delivery, reattested

    def test_01_the_hole_is_real_and_the_binding_closes_it(self):
        receipt, grant, block, delivery, attestation = self._repointed()
        emitted = fulfillment_receipt.emit(
            receipt, delivery, [attestation], now=fulfillment_receipt.CONTROL_NOW)

        # The block that really settled the OTHER order is carried verbatim.
        self.assertEqual(receipt["settled_block"], block["hash"])
        self.assertEqual(emitted["evidence_grade"], "independently_attested")

        # -- half one: the hole, as it stands when the binding is not checked.
        blind = fulfillment_receipt.verify(
            emitted, receipt, grant, block, delivery=delivery,
            now=fulfillment_receipt.CONTROL_NOW,
            fetch=fulfillment_receipt._control_fetch())
        self.assertTrue(blind["ok"], blind["reasons"])
        self.assertEqual(blind["reasons"], [])
        self.assertEqual(blind["evidence_grade"], "independently_attested")
        # ... and the verdict now says out loud that it did not check.
        self.assertIn("order_binding_not_checked", blind["caveats"])

        # -- half two: supplied with the order's price, it refuses.
        bound = fulfillment_receipt.verify(
            emitted, receipt, grant, block, delivery=delivery,
            now=fulfillment_receipt.CONTROL_NOW,
            fetch=fulfillment_receipt._control_fetch(),
            order_amount_raw=fulfillment_receipt.CONTROL_RAW)
        self.assertFalse(bound["ok"])
        self.assertIn("order_not_derivable_from_block", bound["reasons"])
        self.assertEqual(bound["caveats"], [])

    def test_01b_a_correctly_bound_order_still_passes(self):
        """The check must be able to pass, or it is a check that always fails."""
        receipt, grant, block, delivery, attestation = (
            fulfillment_receipt._control_set())
        expected = derive(receipt["request_digest"],
                          fulfillment_receipt.CONTROL_RAW)
        priced = dict(receipt, quoted_raw=expected["pay_raw"],
                      settled_raw=expected["pay_raw"])
        paid = dict(block, amount=expected["pay_raw"])
        emitted = fulfillment_receipt.emit(
            priced, delivery, [attestation], now=fulfillment_receipt.CONTROL_NOW)
        verdict = fulfillment_receipt.verify(
            emitted, priced, grant, paid, delivery=delivery,
            now=fulfillment_receipt.CONTROL_NOW,
            fetch=fulfillment_receipt._control_fetch(),
            order_amount_raw=fulfillment_receipt.CONTROL_RAW)
        self.assertTrue(verdict["ok"], verdict["reasons"])
        self.assertEqual(verdict["reasons"], [])
        self.assertEqual(verdict["evidence_grade"], "independently_attested")
        self.assertEqual(verdict["caveats"], [])
        self.assertIn("order_not_derivable_from_block", verdict["checked"])


class DeriveIsAFunctionOfTheOrderAlone(unittest.TestCase):
    """-- 2 -- two fresh processes, the same answer. No cache can pass this."""

    def test_02_two_processes_agree(self):
        order = d("two-process agreement")
        one = cli("derive", "--order-digest", order, "--amount-raw", PRICE)
        two = cli("derive", "--order-digest", order, "--amount-raw", PRICE)
        self.assertEqual((one[0], two[0]), (0, 0), (one[2], two[2]))
        a, b = json.loads(one[1]), json.loads(two[1])
        self.assertEqual(a["tag"], b["tag"])
        self.assertEqual(a["pay_raw"], b["pay_raw"])
        # And the in-process answer is the same answer, not a second opinion.
        self.assertEqual(derive(order, PRICE)["pay_raw"], a["pay_raw"])

    def test_02b_there_is_no_allocation_anywhere_in_the_file(self):
        with open(MODULE, "r", encoding="utf-8") as handle:
            source = handle.read()
        for forbidden in ("import secrets", "import random", "secrets.",
                          "random."):
            self.assertNotIn(
                forbidden, source,
                "%r appears in order_bound_amount.py: the tag is derived, "
                "never allocated" % forbidden)


class AStrangerRecomputesTheJoin(unittest.TestCase):
    """-- 3 -- no file, no database, no socket: the order and the price suffice."""

    def test_03_match_reads_nothing_but_its_arguments(self):
        import builtins
        import socket

        order = d("a stranger with no access to us")
        expected = derive(order, PRICE)
        block = {"hash": BLOCK_A, "amount": expected["pay_raw"],
                 "confirmed": "true"}

        def no_open(*args, **kwargs):
            raise AssertionError("match() opened a file")

        def no_socket(*args, **kwargs):
            raise AssertionError("match() opened a socket")

        saved_open, saved_socket = builtins.open, socket.socket
        builtins.open, socket.socket = no_open, no_socket
        try:
            verdict = match(order, PRICE, block)
        finally:
            builtins.open, socket.socket = saved_open, saved_socket
        self.assertTrue(verdict["matched"], verdict["reasons"])
        self.assertEqual(verdict["tag_observed"], verdict["tag_expected"])


class TheHexVersusBytesTrap(unittest.TestCase):
    """-- 4 -- hashing the 64 characters of text is a different, wrong answer."""

    def test_04_the_digest_goes_in_as_32_raw_bytes(self):
        order = d("order-bound-amount vector A")

        def derive_over_ascii(order_digest, modulus=DEFAULT_MODULUS):
            payload = order_bound_amount.PREFIX + order_digest.encode("ascii")
            hexdigest = hashlib.blake2b(payload, digest_size=32).hexdigest()
            return 1 + (int(hexdigest, 16) % (modulus - 1))

        self.assertNotEqual(
            tag_for(order), derive_over_ascii(order),
            "the tag is the same whether the digest is hashed as bytes or as "
            "text, so this build cannot tell the two apart and has silently "
            "forked the vectors")
        # And the bytes form is the one the vectors are frozen under.
        self.assertEqual(derive(order, PRICE)["tag"], tag_for(order))


class TheTagIsNeverZero(unittest.TestCase):
    """-- 5 -- a zero tag binds no order, so the range is 1 .. modulus-1."""

    def test_05_fifty_thousand_digests_stay_in_range(self):
        rnd = random.Random(12)
        low = DEFAULT_MODULUS
        high = 0
        for _ in range(50000):
            order = "%064x" % rnd.getrandbits(256)
            tag = tag_for(order)
            self.assertGreaterEqual(tag, 1)
            self.assertLess(tag, DEFAULT_MODULUS)
            low, high = min(low, tag), max(high, tag)
        self.assertGreater(high, low)

    def test_05b_both_endpoints_are_reachable(self):
        """Measured at modulus 10**3, where 50k draws cover 1..999 densely.

        At 10**6 they do not: 50k draws touch about 5% of the range, so
        asserting a tag of exactly 1 there would be asserting a coin flip. The
        bound is stated rather than dressed up.
        """
        rnd = random.Random(12)
        seen = {tag_for("%064x" % rnd.getrandbits(256), 10 ** 3)
                for _ in range(50000)}
        self.assertIn(1, seen)
        self.assertIn(10 ** 3 - 1, seen)
        self.assertNotIn(0, seen)


class AnUnmatchedBlockStaysUnmatched(unittest.TestCase):
    """-- 6 -- there is no nearest order."""

    def test_06_the_only_order_present_does_not_claim_a_stray_block(self):
        order = d("the only order on the board")
        stray = {"hash": BLOCK_B, "amount": PRICE}   # tag 0: no order derives it
        swept = unclaimed([order], {order: PRICE}, [stray])
        self.assertEqual(swept["claimed"], [],
                         "a stray block was assigned to the only order present")
        self.assertEqual(len(swept["unclaimed_blocks"]), 1)
        self.assertEqual(swept["unclaimed_blocks"][0]["reason"],
                         "no_order_derives_this_tag")
        self.assertEqual([row["order_digest"] for row in swept["unpaid_orders"]],
                         [order])


class ACollisionIsReportedNeverResolved(unittest.TestCase):
    """-- 7 -- two orders, one tag, and neither one claims the block."""

    def test_07_both_sides_go_unpaid(self):
        a, b = (d(p) for p in order_bound_amount.COLLISION_PREIMAGES)
        modulus = order_bound_amount.COLLISION_MODULUS
        # The frozen pair really does collide; the test does not search.
        self.assertEqual(tag_for(a, modulus), tag_for(b, modulus))
        self.assertNotEqual(a, b)

        block = {"hash": BLOCK_A,
                 "amount": str(int(PRICE) + tag_for(a, modulus))}
        swept = unclaimed([a, b], {a: PRICE, b: PRICE}, [block],
                          modulus=modulus)
        self.assertEqual(len(swept["collisions"]), 1)
        self.assertEqual(swept["collisions"][0]["order_digests"], sorted([a, b]))
        self.assertEqual(swept["claimed"], [])
        self.assertEqual(
            sorted(row["order_digest"] for row in swept["unpaid_orders"]),
            sorted([a, b]))
        self.assertTrue(any("never resolved" in note for note in swept["notes"]))


class DuplicatePayRaw(unittest.TestCase):
    """-- 8 -- one order is claimed by at most one block."""

    def test_08_the_second_block_does_not_claim_the_same_order(self):
        order = d("one order, two identical blocks")
        pay = derive(order, PRICE)["pay_raw"]
        swept = unclaimed([order], {order: PRICE},
                          [{"hash": BLOCK_A, "amount": pay},
                           {"hash": BLOCK_B, "amount": pay}])
        self.assertEqual(len(swept["claimed"]), 1)
        self.assertEqual(swept["claimed"][0]["block_hash"], BLOCK_A)
        self.assertEqual(len(swept["unclaimed_blocks"]), 1)
        self.assertEqual(swept["unclaimed_blocks"][0]["block_hash"], BLOCK_B)
        self.assertEqual(swept["unclaimed_blocks"][0]["reason"],
                         "duplicate_pay_raw")
        self.assertEqual(swept["unpaid_orders"], [])


class AmountArithmeticIsInteger(unittest.TestCase):
    """-- 9 -- raw is an integer count, and a leading zero is still a number."""

    def test_09_pay_raw_is_exact(self):
        order = d("exact arithmetic")
        row = derive(order, PRICE)
        self.assertEqual(int(row["pay_raw"]), int(PRICE) + row["tag"])
        self.assertEqual(len(row["pay_raw"]), len(PRICE))

    def test_09c_a_tag_with_FEWER_than_six_digits_still_matches(self):
        """A short tag is an ordinary value, and it was the gap in this suite.

        Found by mutation: a comparison correct only for a six-digit tag
        survived every other test in this file, because every fixture here
        happens to derive a six-digit one. About one order in ten derives a tag
        below 100000 and one in a thousand a tag below 1000, so this is a
        normal case and not an edge. `short-tag-probe-135` derives 932 at the
        default modulus and is frozen for that reason.
        """
        order = d("short-tag-probe-135")
        row = derive(order, PRICE)
        self.assertLess(row["tag"], 1000)
        # The tag occupies the low digits; the price's digits are untouched.
        self.assertEqual(int(row["pay_raw"]), int(PRICE) + row["tag"])
        self.assertEqual(row["pay_raw"][-6:], "%06d" % row["tag"])
        verdict = match(order, PRICE, {"hash": BLOCK_A, "amount": row["pay_raw"]})
        self.assertTrue(verdict["matched"], verdict["reasons"])
        self.assertEqual(verdict["tag_observed"], row["tag"])
        # And a sweep claims it, rather than reading the short tag as a stray.
        swept = unclaimed([order], {order: PRICE},
                          [{"hash": BLOCK_A, "amount": row["pay_raw"]}])
        self.assertEqual(len(swept["claimed"]), 1)
        self.assertEqual(swept["unclaimed_blocks"], [])

    def test_09b_a_leading_zero_still_matches(self):
        order = d("exact arithmetic")
        pay = derive(order, PRICE)["pay_raw"]
        verdict = match(order, PRICE, {"hash": BLOCK_A, "amount": "0" + pay})
        self.assertTrue(verdict["matched"], verdict["reasons"])
        self.assertEqual(verdict["block_amount_raw"], pay)


class APriceWithNoRoomForTheTag(unittest.TestCase):
    """-- 10 -- a refusal, not a rounding."""

    def test_10_refuses_with_its_own_code(self):
        order = d("a price with no room")
        with self.assertRaises(Refusal) as caught:
            derive(order, "1000001")
        self.assertEqual(caught.exception.code, "amount_leaves_no_room_for_tag")
        code, out, _ = cli("derive", "--order-digest", order,
                           "--amount-raw", "1000001")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out)["error"],
                         "amount_leaves_no_room_for_tag")


class OverpayIsAReasonNotALoss(unittest.TestCase):
    """-- 11 -- and the message names both numbers."""

    def test_11_amount_above_price(self):
        order = d("an overpaying buyer")
        row = derive(order, PRICE)
        over = str(int(row["pay_raw"]) + DEFAULT_MODULUS)
        verdict = match(order, PRICE, {"hash": BLOCK_A, "amount": over})
        self.assertFalse(verdict["matched"])
        self.assertIn("amount_above_price", verdict["reasons"])
        message = verdict["messages"]["amount_above_price"]
        self.assertIn(over, message)
        self.assertIn(row["pay_raw"], message)
        self.assertIn("not a rejection of the money", message)


class EveryReasonCodeIsReachable(unittest.TestCase):
    """-- 12 -- a code no control reaches is a check never proven able to fail."""

    def test_12_self_test_reaches_every_code(self):
        report = order_bound_amount.self_test()
        self.assertTrue(report["ok"], report["failures"])
        self.assertEqual(report["failures"], [])
        self.assertEqual(report["codes_never_evaluated"], [])
        self.assertGreaterEqual(report["negative_controls"], len(REASON_CODES))

    def test_12b_no_code_in_the_module_is_unreachable(self):
        """And no code is declared that the module never emits."""
        with open(MODULE, "r", encoding="utf-8") as handle:
            source = handle.read()
        for code in REASON_CODES:
            self.assertIn('"%s"' % code, source,
                          "%s is declared but never emitted" % code)

    def test_12c_a_stubbed_derive_turns_the_self_test_red(self):
        saved = order_bound_amount.derive
        order_bound_amount.derive = lambda *a, **k: {
            "version": 1, "order_digest": "0" * 64, "amount_raw": PRICE,
            "modulus": DEFAULT_MODULUS, "tag": 1, "pay_raw": PRICE,
            "derivation": "stub"}
        try:
            report = order_bound_amount.self_test()
        finally:
            order_bound_amount.derive = saved
        self.assertFalse(report["ok"],
                         "a stubbed derive() passed the self-test, so the "
                         "controls are testing the stub against itself")

    def test_12d_the_cli_exit_codes_are_the_contract(self):
        order = d("exit codes")
        row = derive(order, PRICE)
        self.assertEqual(cli("--self-test")[0], 0)
        self.assertEqual(
            cli("derive", "--order-digest", order, "--amount-raw", PRICE)[0], 0)
        self.assertEqual(
            cli("derive", "--order-digest", "nothex", "--amount-raw", PRICE)[0], 2)
        good = written({"hash": BLOCK_A, "amount": row["pay_raw"]})
        bad = written({"hash": BLOCK_A, "amount": PRICE})
        try:
            self.assertEqual(cli("match", "--order-digest", order,
                                 "--amount-raw", PRICE, "--block", good)[0], 0)
            self.assertEqual(cli("match", "--order-digest", order,
                                 "--amount-raw", PRICE, "--block", bad)[0], 3)
        finally:
            os.unlink(good)
            os.unlink(bad)


class TheByteRule(unittest.TestCase):
    """-- 13 -- one repository, one serialisation."""

    def test_13_serialise_agrees_with_the_rest_of_the_repository(self):
        probe = {"version": 1, "b": "two", "a": "one"}
        self.assertEqual(order_bound_amount.serialise(probe),
                         grant_mint.serialise(probe))
        self.assertEqual(order_bound_amount.serialise(probe),
                         fulfillment_receipt.serialise(probe))
        self.assertEqual(order_bound_amount.digest(b"abc"),
                         grant_mint.digest(b"abc"))


class TheVectorsAreFrozen(unittest.TestCase):
    """-- 14 -- `--vectors` and the committed file are the same bytes."""

    def test_14_the_file_matches_the_module_byte_for_byte(self):
        with open(VECTOR_PATH, "rb") as handle:
            on_disk = handle.read()
        self.assertEqual(order_bound_amount.vectors_bytes(), on_disk)
        code, out, err = cli("--vectors")
        self.assertEqual(code, 0, err)
        self.assertEqual(out.encode("utf-8"), on_disk)

    def test_14b_every_vector_recomputes_from_its_preimage(self):
        with open(VECTOR_PATH, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        self.assertGreaterEqual(len(document["derive"]), 5)
        moduli = {case["modulus"] for case in document["derive"]}
        self.assertTrue({10 ** 3, 10 ** 6, 10 ** 12} <= moduli)
        for case in document["derive"]:
            order = joined(case["order_digest_halves"])
            self.assertEqual(order, d(case["preimage"]))
            row = derive(order, case["amount_raw"], modulus=case["modulus"])
            self.assertEqual(row["tag"], case["tag"])
            self.assertEqual(row["pay_raw"], case["pay_raw"])
        labels = {case["label"] for case in document["match"]}
        self.assertEqual(labels, {"matched", "tag_mismatch",
                                  "amount_below_price"})
        pair = document["collision"]["orders"]
        self.assertEqual(
            tag_for(joined(pair[0]["order_digest_halves"]),
                    document["collision"]["modulus"]),
            tag_for(joined(pair[1]["order_digest_halves"]),
                    document["collision"]["modulus"]))

    def test_14c_no_sixty_four_hex_run_stands_alone_in_the_vectors(self):
        """The secret gate is not weakened so a vector can print a digest."""
        import validate
        self.assertEqual(validate.scan_for_secrets(ROOT), [])
        self.assertEqual(len(halves(d("round trip"))), 2)
        self.assertEqual(joined(halves(d("round trip"))), d("round trip"))


class ThisFileReachesNoNetwork(unittest.TestCase):
    """-- 15 -- rule 6, as a testable fact about the import graph."""

    def test_15_no_network_module_in_any_function(self):
        network = {"socket", "ssl", "http", "urllib", "requests", "httpx",
                   "ftplib", "telnetlib", "asyncio", "smtplib"}
        local = {"canonical", "nanoaddr", "grant_mint", "authority_receipt"}
        for entry in order_bound_amount.import_graph():
            module, function = entry["module"], entry["function"]
            root = module.split(".")[0]
            self.assertNotIn(
                root, network,
                "%s is imported in %s; this file takes blocks as data"
                % (module, function))
            self.assertTrue(
                root in sys.stdlib_module_names or module in local,
                "%s is neither standard library nor a module of this "
                "repository" % module)


class RefusalsNameWhatTheySaw(unittest.TestCase):
    """Every refusal message names the value seen and the value wanted."""

    def test_16_each_refusal_names_its_value(self):
        order = d("refusal messages")
        cases = [
            ("bad_order_digest", lambda: derive("abc", PRICE)),
            ("bad_amount_raw", lambda: derive(order, "zero")),
            ("bad_modulus", lambda: derive(order, PRICE, modulus=10 ** 2)),
            ("bad_block_shape", lambda: match(order, PRICE, {"amount": "1"})),
            ("bad_block_amount",
             lambda: match(order, PRICE, {"hash": BLOCK_A, "amount": "lots"})),
        ]
        for code, call in cases:
            with self.subTest(code=code):
                with self.assertRaises(Refusal) as caught:
                    call()
                self.assertEqual(caught.exception.code, code)
                self.assertGreater(len(caught.exception.detail), 30,
                                   "a message that says only 'invalid' costs "
                                   "the agent on the other end a round trip")

    def test_16b_a_duplicate_order_is_refused_not_deduplicated(self):
        order = d("the same order twice")
        with self.assertRaises(Refusal) as caught:
            unclaimed([order, order], {order: PRICE}, [])
        self.assertEqual(caught.exception.code, "duplicate_order_digest")

    def test_16c_a_disagreeing_block_is_a_verdict_never_an_exception(self):
        order = d("a block that merely disagrees")
        verdict = match(order, PRICE, {"hash": BLOCK_A, "amount": "1"})
        self.assertFalse(verdict["matched"])
        self.assertIn("tag_mismatch", verdict["reasons"])
        self.assertIn("amount_below_price", verdict["reasons"])


if __name__ == "__main__":
    unittest.main()
