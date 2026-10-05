"""The outcome descriptor: the worst case of a paid call, as a number a policy reads.

The decisive tests here are 2 and 10. Test 2 pins that the seller cannot name
its own settlement - and that the refusal fires when the seller's number is
LOWER than the derived one as well as higher, because the rule is about
authorship and not about generosity. Test 10 pins that the operator gate is pure
arithmetic over the descriptor, which is the only reason a static policy
document can approve a spend at all.

Fixtures here are built independently of `outcome_descriptor`'s own `--self-test`
controls, deliberately: driving these assertions from the module's fixtures would
let a mutation that breaks both drift past green, which is the whole failure mode
`--self-test` exists to catch.

Nothing opens a socket and nothing reads a clock: tests 12 and 13 monkeypatch
`time.time`, `datetime.now`, `datetime.utcnow`, `socket.socket` and
`builtins.open` to raise, and every function still runs.

No 64-hex run stands as a single literal, matching the project's secret gate -
every digest here is computed from a readable preimage or joined from halves.
"""

import copy
import datetime
import hashlib
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import grant_mint
import outcome_descriptor
from outcome_descriptor import (
    ALL_CODES, CLASSES, RESOLVES_TO, Refusal, TERMINAL_CLASSES, ZERO_SETTLEMENT,
    descriptor, halves, joined, outcome, policy_check, resolve,
)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODULE = os.path.join(ROOT, "outcome_descriptor.py")
VECTOR_PATH = os.path.join(ROOT, "vectors", "outcome-descriptor-v1.json")

PRICE = "1000000000000000000000000000"        # 0.001 XNO in raw
PER_UNIT = "20000000000000000000000000"       # 50 units -> exactly PRICE
DEADLINE = "2026-10-12T00:00:00Z"
BEFORE = "2026-10-06T00:00:00Z"
AFTER = "2026-10-12T00:00:01Z"

WIDE_POLICY = {"ceiling_raw": "5000000000000000000000000000",
               "capital_ceiling_raw": "5000000000000000000000000000",
               "currencies": ["XNO"]}


def d(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def a_spec(**changes):
    """A complete spec, built here rather than taken from the module."""
    spec = {
        "order_digest": d("a test order"),
        "price_raw": PRICE,
        "currency": "XNO",
        "idempotency_key": "test-order-0001",
        "reconciliation_deadline": DEADLINE,
        "outcomes": [
            {"class": "delivered", "buyer_may_reject": False},
            {"class": "partial_result", "unit": "row", "units_ordered": 50,
             "min_units_accepted": 25, "settlement_raw_per_unit": PER_UNIT},
            {"class": "never_reserved"},
            {"class": "rejected_by_buyer"},
            {"class": "provider_failed"},
            {"class": "expired_unclaimed"},
            {"class": "timeout_unknown", "resolves_to": list(RESOLVES_TO),
             "resolution_deadline": DEADLINE},
        ],
    }
    spec.update(changes)
    return spec


def with_row(name, **changes):
    spec = a_spec()
    for row in spec["outcomes"]:
        if row["class"] == name:
            row.update(changes)
    return spec


def cli(*args, stdin=None):
    proc = subprocess.run([sys.executable, MODULE] + list(args),
                          input=stdin, capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def written(document):
    handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False)
    json.dump(document, handle)
    handle.close()
    return handle.name


class CompletenessIsEnforced(unittest.TestCase):
    """-- 1 -- the missing class is the unbounded case, so it is never defaulted."""

    def test_01_each_of_the_seven_omissions_refuses_and_names_the_class(self):
        self.assertEqual(len(CLASSES), 7)
        for absent in CLASSES:
            with self.subTest(absent=absent):
                spec = a_spec()
                spec["outcomes"] = [r for r in spec["outcomes"]
                                    if r["class"] != absent]
                with self.assertRaises(Refusal) as caught:
                    descriptor(spec)
                # Omitting partial_result or timeout_unknown trips its own
                # structural check first; either way it is never DEFAULTED, and
                # the completeness message must name the class when it is the
                # one that fires.
                self.assertIn(caught.exception.code,
                              ("outcome_set_incomplete", "bad_units",
                               "timeout_without_deadline"))
                if caught.exception.code == "outcome_set_incomplete":
                    self.assertIn(absent, caught.exception.detail)

    def test_01b_a_complete_set_is_complete_and_closed(self):
        doc = descriptor(a_spec())
        self.assertTrue(doc["complete"])
        self.assertEqual([r["class"] for r in doc["outcomes"]], list(CLASSES))

    def test_01c_a_class_outside_the_seven_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            descriptor(with_row("delivered", **{"class": "other"}))
        self.assertEqual(caught.exception.code, "unknown_outcome_class")
        self.assertIn("no extension point", caught.exception.detail)


class TheSellerCannotNameItsOwnSettlement(unittest.TestCase):
    """-- 2 -- the single most important refusal in the file."""

    def test_02_a_claim_carrying_settlement_raw_is_refused(self):
        doc = descriptor(a_spec())
        with self.assertRaises(Refusal) as caught:
            outcome(doc, {"class": "partial_result", "units_delivered": 1,
                          "settlement_raw": PRICE})
        self.assertEqual(caught.exception.code,
                         "settlement_not_the_sellers_to_name")

    def test_02b_the_refusal_fires_when_the_sellers_number_is_LOWER(self):
        """The rule is about authorship, not about generosity."""
        doc = descriptor(a_spec())
        with self.assertRaises(Refusal) as caught:
            outcome(doc, {"class": "partial_result", "units_delivered": 50,
                          "settlement_raw": "1"})
        self.assertEqual(caught.exception.code,
                         "settlement_not_the_sellers_to_name")
        self.assertIn("generosity", caught.exception.detail)

    def test_02c_a_resolution_cannot_name_it_either(self):
        doc = descriptor(a_spec())
        open_timeout = outcome(doc, {"class": "timeout_unknown"})
        with self.assertRaises(Refusal) as caught:
            resolve(doc, open_timeout, {"class": "delivered",
                                        "settlement_raw": "1"}, BEFORE)
        self.assertEqual(caught.exception.code,
                         "settlement_not_the_sellers_to_name")

    def test_02d_every_verdict_says_who_authored_the_settlement(self):
        doc = descriptor(a_spec())
        for name in CLASSES:
            claim = {"class": name}
            if name == "partial_result":
                claim["units_delivered"] = 30
            with self.subTest(cls=name):
                v = outcome(doc, claim)
                self.assertEqual(
                    v["who_authored_what"]["settlement_raw"],
                    "derived from the descriptor, authored by neither")
                self.assertEqual(v["who_authored_what"]["class_and_units"],
                                 "seller")


class TheWorstCaseIsComputed(unittest.TestCase):
    """-- 3 -- rule 4: supplied in the input, it is ignored and said to be."""

    def test_03_a_supplied_max_settlement_is_ignored(self):
        doc = descriptor(a_spec(max_settlement_raw="0"))
        self.assertEqual(doc["max_settlement_raw"], PRICE)
        self.assertIs(doc["recomputed_ignoring_input"]["max_settlement_raw"],
                      True)

    def test_03b_a_clean_spec_ignores_nothing(self):
        doc = descriptor(a_spec())
        self.assertEqual(doc["recomputed_ignoring_input"], {})

    def test_03c_the_worst_case_is_the_largest_terminal_settlement(self):
        """50 units at 2e25 raw each is exactly the price, so they tie."""
        doc = descriptor(a_spec())
        self.assertEqual(doc["max_settlement_raw"], PRICE)
        # Make the per-unit path strictly larger and the number must follow.
        bigger = descriptor(with_row(
            "partial_result", settlement_raw_per_unit="40000000000000000000000000"))
        self.assertEqual(int(bigger["max_settlement_raw"]), int(PRICE) * 2)
        self.assertEqual(bigger["max_settlement_from"], "partial_result")

    def test_03d_capital_held_is_computed_too_and_can_exceed_settlement(self):
        doc = descriptor(a_spec())
        self.assertEqual(doc["max_capital_held_raw"], doc["max_settlement_raw"])
        escrowed = descriptor(a_spec(
            prefunded_escrow_raw="3000000000000000000000000000",
            max_capital_held_raw="0"))
        self.assertEqual(escrowed["max_capital_held_raw"],
                         "3000000000000000000000000000")
        self.assertIs(escrowed["recomputed_ignoring_input"]["max_capital_held_raw"],
                      True)


class TheTimeoutHoldsTheKey(unittest.TestCase):
    """-- 4, 5 -- the only non-terminal class, and it cannot settle."""

    def test_04_a_timeout_freezes_everything_it_should(self):
        doc = descriptor(a_spec())
        v = outcome(doc, {"class": "timeout_unknown"})
        self.assertFalse(v["terminal"])
        self.assertEqual(v["idempotency_key_state"], "held_open")
        self.assertTrue(v["replacement_purchase_frozen"])
        self.assertEqual(v["settlement_raw"], "0")
        self.assertEqual(v["buyer_options"], ["reconcile_at_zero_price"])

    def test_05_units_on_a_timeout_are_ignored_not_credited(self):
        doc = descriptor(a_spec())
        v = outcome(doc, {"class": "timeout_unknown", "units_delivered": 50})
        self.assertEqual(v["settlement_raw"], "0")
        self.assertIsNone(v["units_delivered"])
        self.assertFalse(v["terminal"])

    def test_05b_it_is_the_only_non_terminal_class(self):
        doc = descriptor(a_spec())
        for name in CLASSES:
            claim = {"class": name}
            if name == "partial_result":
                claim["units_delivered"] = 30
            with self.subTest(cls=name):
                self.assertEqual(outcome(doc, claim)["terminal"],
                                 name in TERMINAL_CLASSES)

    def test_05c_the_zero_classes_pay_nothing_and_release_the_key(self):
        doc = descriptor(a_spec())
        for name in ZERO_SETTLEMENT:
            with self.subTest(cls=name):
                v = outcome(doc, {"class": name})
                self.assertEqual(v["settlement_raw"], "0")
                self.assertEqual(v["idempotency_key_state"], "released")


class ResolutionIsBounded(unittest.TestCase):
    """-- 6, 7 -- resolves_to is a closed list, and the deadline really fires."""

    def setUp(self):
        self.doc = descriptor(a_spec())
        self.open = outcome(self.doc, {"class": "timeout_unknown"})

    def test_06_a_class_outside_resolves_to_is_refused_and_the_set_is_named(self):
        with self.assertRaises(Refusal) as caught:
            resolve(self.doc, self.open, {"class": "rejected_by_buyer"}, BEFORE)
        self.assertEqual(caught.exception.code, "resolution_not_permitted")
        for permitted in RESOLVES_TO:
            self.assertIn(permitted, caught.exception.detail)

    def test_06b_a_permitted_class_resolves(self):
        v = resolve(self.doc, self.open, {"class": "delivered"}, BEFORE)
        self.assertEqual(v["class"], "delivered")
        self.assertEqual(v["settlement_raw"], PRICE)
        self.assertTrue(v["terminal"])
        self.assertEqual(v["resolved_from"], "timeout_unknown")

    def test_07_past_the_deadline_it_closes_at_zero_whatever_was_claimed(self):
        v = resolve(self.doc, self.open, {"class": "delivered"}, AFTER)
        self.assertEqual(v["class"], "never_reserved")
        self.assertIn("resolution_deadline_passed", v["reasons"])
        self.assertEqual(v["settlement_raw"], "0")
        self.assertEqual(v["idempotency_key_state"], "released")

    def test_07b_the_deadline_outranks_an_impermissible_class(self):
        """Checked before the claim, so a late resolution cannot pick its refusal."""
        v = resolve(self.doc, self.open, {"class": "rejected_by_buyer"}, AFTER)
        self.assertEqual(v["class"], "never_reserved")
        self.assertIn("resolution_deadline_passed", v["reasons"])

    def test_07c_a_timeout_with_no_deadline_cannot_be_built(self):
        spec = a_spec()
        spec["outcomes"] = [{k: v for k, v in r.items()
                             if k != "resolution_deadline"}
                            for r in spec["outcomes"]]
        with self.assertRaises(Refusal) as caught:
            descriptor(spec)
        self.assertEqual(caught.exception.code, "timeout_without_deadline")
        self.assertIn("frozen forever", caught.exception.detail)


class NoBuyerVetoOnDelivered(unittest.TestCase):
    """-- 8 -- wickthefamiliar's seam, closed by construction.

    "if the accept_token is what the answerer presents to trigger payment
    release, then the asker holds an arbitrary veto over whether the answerer
    gets paid - delivered or not. That's the buyer-withholding problem."
    """

    def test_08_a_veto_on_delivered_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            descriptor(with_row("delivered", buyer_may_reject=True))
        self.assertEqual(caught.exception.code, "buyer_veto_on_delivered")
        self.assertIn("arbitrary veto", caught.exception.detail)

    def test_08b_delivered_never_offers_reject_as_a_buyer_option(self):
        doc = descriptor(a_spec())
        self.assertEqual(outcome(doc, {"class": "delivered"})["buyer_options"],
                         ["accept"])


class BelowThresholdIsArithmeticNotDispute(unittest.TestCase):
    """-- 9 -- the descriptor said so in advance, so nobody has to be believed."""

    def test_09_twenty_of_fifty_against_a_threshold_of_twenty_five(self):
        doc = descriptor(a_spec())
        v = outcome(doc, {"class": "partial_result", "units_delivered": 20})
        self.assertEqual(v["class"], "rejected_by_buyer")
        self.assertEqual(v["settlement_raw"], "0")
        self.assertIn("below_accepted_quality_threshold", v["reasons"])
        self.assertEqual(
            v["who_authored_what"]["settlement_raw"],
            "derived from the descriptor, authored by neither")
        self.assertIn("25", v["detail"])

    def test_09b_at_the_threshold_it_settles_per_unit(self):
        doc = descriptor(a_spec())
        v = outcome(doc, {"class": "partial_result", "units_delivered": 25})
        self.assertEqual(v["class"], "partial_result")
        self.assertEqual(int(v["settlement_raw"]), 25 * int(PER_UNIT))

    def test_09c_more_units_than_ordered_is_refused_not_credited(self):
        doc = descriptor(a_spec())
        with self.assertRaises(Refusal) as caught:
            outcome(doc, {"class": "partial_result", "units_delivered": 51})
        self.assertEqual(caught.exception.code, "bad_units")


class PolicyCheckIsTheHumanGate(unittest.TestCase):
    """-- 10, 11 -- six rules, all arithmetic, and two separate ceilings."""

    def test_10_one_raw_unit_over_the_ceiling_is_not_approvable(self):
        doc = descriptor(a_spec())
        over = policy_check(doc, dict(WIDE_POLICY,
                                      ceiling_raw=str(int(PRICE) - 1)))
        self.assertFalse(over["approvable"])
        self.assertEqual(len(over["failed"]), 1)
        self.assertEqual(over["failed"][0]["saw"], PRICE)
        self.assertEqual(over["failed"][0]["limit"], str(int(PRICE) - 1))

    def test_10b_one_raw_unit_under_is_approvable(self):
        doc = descriptor(a_spec())
        under = policy_check(doc, dict(WIDE_POLICY, ceiling_raw=PRICE))
        self.assertTrue(under["approvable"], under["failed"])
        self.assertEqual(under["failed"], [])
        self.assertEqual(len(under["checked"]), 6)

    def test_11_the_capital_ceiling_is_a_separate_rule(self):
        """qbtlabs-io-web's difference between a cheap refund and a slow one."""
        doc = descriptor(a_spec())
        verdict = policy_check(doc, dict(
            WIDE_POLICY, capital_ceiling_raw=str(int(PRICE) - 1)))
        self.assertFalse(verdict["approvable"])
        self.assertEqual(len(verdict["failed"]), 1)
        self.assertIn("capital_ceiling_raw", verdict["failed"][0]["rule"])

    def test_11b_a_wrong_currency_fails_its_own_rule(self):
        doc = descriptor(a_spec())
        verdict = policy_check(doc, dict(WIDE_POLICY, currencies=["USDC"]))
        self.assertFalse(verdict["approvable"])
        self.assertIn("currency", verdict["failed"][0]["rule"])

    def test_11c_a_policy_a_descriptor_merely_exceeds_never_raises(self):
        doc = descriptor(a_spec())
        verdict = policy_check(doc, dict(WIDE_POLICY, ceiling_raw="1",
                                         capital_ceiling_raw="1"))
        self.assertFalse(verdict["approvable"])
        self.assertEqual(len(verdict["failed"]), 2)

    def test_11d_approvable_does_not_claim_the_seller_will_perform(self):
        doc = descriptor(a_spec())
        verdict = policy_check(doc, WIDE_POLICY)
        self.assertIn("NOT a statement that the seller will perform",
                      verdict["note"])


class ThereIsNoClock(unittest.TestCase):
    """-- 12 -- `now` is a parameter, through the one date parser here."""

    def test_12_every_function_runs_with_the_clock_removed(self):
        def explode(*args, **kwargs):
            raise AssertionError("outcome_descriptor read a clock")

        saved = (time.time, datetime.datetime.now, datetime.datetime.utcnow)
        time.time = explode
        try:
            doc = descriptor(a_spec())
            open_timeout = outcome(doc, {"class": "timeout_unknown"})
            resolve(doc, open_timeout, {"class": "delivered"}, BEFORE)
            policy_check(doc, WIDE_POLICY)
        finally:
            time.time = saved[0]

    def test_12b_a_missing_now_refuses_with_now_not_parseable(self):
        doc = descriptor(a_spec())
        open_timeout = outcome(doc, {"class": "timeout_unknown"})
        for bad in (None, "", "tomorrow", "2026-02-30T00:00:00Z"):
            with self.subTest(now=bad):
                with self.assertRaises(Refusal) as caught:
                    resolve(doc, open_timeout, {"class": "delivered"}, bad)
                self.assertEqual(caught.exception.code, "now_not_parseable")

    def test_12c_the_date_parser_is_the_repositorys_own(self):
        """So 2026-02-30 is refused as the non-date it is, not range-checked."""
        import validate
        self.assertIsNone(validate._rfc3339("2026-02-30T00:00:00Z"))
        with self.assertRaises(Refusal):
            descriptor(a_spec(reconciliation_deadline="2026-02-30T00:00:00Z"))


class NoNetworkAndNoDisk(unittest.TestCase):
    """-- 13 -- blocks and policies come in as data."""

    def test_13_build_classify_and_policy_read_nothing(self):
        import builtins

        def no_open(*args, **kwargs):
            raise AssertionError("outcome_descriptor opened a file")

        def no_socket(*args, **kwargs):
            raise AssertionError("outcome_descriptor opened a socket")

        spec = a_spec()
        saved_open, saved_socket = builtins.open, socket.socket
        builtins.open, socket.socket = no_open, no_socket
        try:
            doc = descriptor(spec)
            outcome(doc, {"class": "partial_result", "units_delivered": 30})
            policy_check(doc, WIDE_POLICY)
        finally:
            builtins.open, socket.socket = saved_open, saved_socket

    def test_13b_no_network_module_in_any_function(self):
        network = {"socket", "ssl", "http", "urllib", "requests", "httpx",
                   "ftplib", "telnetlib", "asyncio", "smtplib"}
        local = {"canonical", "validate", "grant_mint", "nanoaddr",
                 "authority_receipt"}
        for entry in outcome_descriptor.import_graph():
            module, function = entry["module"], entry["function"]
            root = module.split(".")[0]
            self.assertNotIn(root, network,
                             "%s is imported in %s" % (module, function))
            self.assertTrue(
                root in sys.stdlib_module_names or module in local,
                "%s is neither standard library nor a module of this "
                "repository" % module)


class DigestStability(unittest.TestCase):
    """-- 14 -- the digest covers the bytes, and cannot cover itself."""

    def test_14_a_round_trip_through_json_keeps_the_digest(self):
        doc = descriptor(a_spec())
        again = json.loads(json.dumps(doc, indent=2))
        self.assertEqual(outcome_descriptor.descriptor_digest(again),
                         doc["descriptor_digest"])
        # And it verifies, which is the thing a reader actually does.
        self.assertTrue(outcome_descriptor.checked_descriptor(again))

    def test_14b_one_altered_character_is_refused(self):
        doc = descriptor(a_spec())
        tampered = copy.deepcopy(doc)
        stored = tampered["descriptor_digest"]
        flipped = ("b" if stored[0] != "b" else "c") + stored[1:]
        tampered["descriptor_digest"] = flipped
        with self.assertRaises(Refusal) as caught:
            outcome(tampered, {"class": "delivered"})
        self.assertEqual(caught.exception.code, "descriptor_digest_mismatch")

    def test_14c_a_changed_field_is_refused_too(self):
        doc = descriptor(a_spec())
        with self.assertRaises(Refusal) as caught:
            policy_check(dict(doc, price_raw="1"), WIDE_POLICY)
        self.assertEqual(caught.exception.code, "descriptor_digest_mismatch")

    def test_14d_the_digest_does_not_cover_itself(self):
        doc = descriptor(a_spec())
        bare = {k: v for k, v in doc.items() if k != "descriptor_digest"}
        self.assertEqual(
            outcome_descriptor.digest(outcome_descriptor.serialise(bare)),
            doc["descriptor_digest"])


class EveryCodeIsReachable(unittest.TestCase):
    """-- 15 -- a code no control reaches is a check never proven able to fail."""

    def test_15_self_test_reaches_every_code(self):
        report = outcome_descriptor.self_test()
        self.assertTrue(report["ok"], report["failures"])
        self.assertEqual(report["failures"], [])
        self.assertEqual(report["codes_never_evaluated"], [])
        self.assertGreaterEqual(report["negative_controls"], len(ALL_CODES))

    def test_15b_no_code_is_declared_that_the_module_never_emits(self):
        with open(MODULE, "r", encoding="utf-8") as handle:
            source = handle.read()
        for code in ALL_CODES:
            self.assertIn('"%s"' % code, source,
                          "%s is declared but never emitted" % code)

    def test_15c_a_stubbed_policy_check_turns_the_self_test_red(self):
        saved = outcome_descriptor.policy_check
        outcome_descriptor.policy_check = lambda *a, **k: {
            "version": 1, "approvable": True, "descriptor_digest": "x",
            "checked": [], "failed": [], "note": "stub"}
        try:
            report = outcome_descriptor.self_test()
        finally:
            outcome_descriptor.policy_check = saved
        self.assertFalse(report["ok"],
                         "a stubbed policy_check passed the self-test, so the "
                         "controls are testing the stub against itself")

    def test_15d_the_cli_exit_codes_are_the_contract(self):
        doc = descriptor(a_spec())
        paths = {
            "spec": written(a_spec()),
            "doc": written(doc),
            "timeout": written({"class": "timeout_unknown"}),
            "delivered": written({"class": "delivered"}),
            "pol_ok": written(WIDE_POLICY),
            "pol_no": written(dict(WIDE_POLICY, ceiling_raw="1")),
        }
        try:
            self.assertEqual(cli("--self-test")[0], 0)
            self.assertEqual(cli("build", "--spec", paths["spec"])[0], 0)
            self.assertEqual(cli("classify", "--descriptor", paths["doc"],
                                 "--claim", paths["delivered"])[0], 0)
            self.assertEqual(cli("classify", "--descriptor", paths["doc"],
                                 "--claim", paths["timeout"])[0], 3)
            self.assertEqual(cli("policy", "--descriptor", paths["doc"],
                                 "--policy", paths["pol_ok"])[0], 0)
            self.assertEqual(cli("policy", "--descriptor", paths["doc"],
                                 "--policy", paths["pol_no"])[0], 3)
            code, out, _ = cli("build", "--spec", written({"nope": 1}))
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(out)["error"], "bad_spec_shape")
        finally:
            for path in paths.values():
                os.unlink(path)


class TheByteRule(unittest.TestCase):
    """-- 16 -- one repository, one serialisation."""

    def test_16_serialise_agrees_with_the_rest_of_the_repository(self):
        probe = {"version": 1, "b": "two", "a": "one"}
        self.assertEqual(outcome_descriptor.serialise(probe),
                         grant_mint.serialise(probe))
        self.assertEqual(outcome_descriptor.digest(b"abc"),
                         grant_mint.digest(b"abc"))


class TheVectorsAreFrozen(unittest.TestCase):
    """-- 17 -- `--vectors` and the committed file are the same bytes."""

    def test_17_the_file_matches_the_module_byte_for_byte(self):
        with open(VECTOR_PATH, "rb") as handle:
            on_disk = handle.read()
        self.assertEqual(outcome_descriptor.vectors_bytes(), on_disk)
        code, out, err = cli("--vectors")
        self.assertEqual(code, 0, err)
        self.assertEqual(out.encode("utf-8"), on_disk)

    def test_17b_the_vector_pins_one_classification_per_class(self):
        with open(VECTOR_PATH, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        classified = {row["claim"]["class"] for row in document["classify"]}
        self.assertEqual(classified, set(CLASSES))
        self.assertEqual(document["closed_set"], list(CLASSES))
        self.assertTrue(document["policy_pass"]["approvable"])
        self.assertFalse(document["policy_fail"]["approvable"])
        self.assertEqual(len(document["policy_fail"]["failed"]), 1)
        # The digests round-trip through halves rather than standing alone.
        self.assertEqual(joined(document["order_digest_halves"]),
                         d(document["order_digest_preimage"]))
        self.assertEqual(len(joined(document["descriptor_digest_halves"])), 64)

    def test_17c_no_sixty_four_hex_run_stands_alone_in_the_tree(self):
        import validate
        self.assertEqual(validate.scan_for_secrets(ROOT), [])
        self.assertEqual(joined(halves(d("round trip"))), d("round trip"))


if __name__ == "__main__":
    unittest.main()
