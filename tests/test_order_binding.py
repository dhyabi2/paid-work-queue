"""The binding of record is `(block_hash, order_id)`; the amount is a check.

Three of these tests are CONTROLS rather than assertions about behaviour, and
each one is red against a specific wrong implementation that would otherwise
pass every other test in this file:

  * test_05 is red against any offset derived from a counter, a timestamp, an
    incrementing id or `len(open_invoices)` - the ordering leak bosco-roteo
    named, which publishes a seller's order sequence in its public amounts;
  * test_09 is red against comparing addresses as strings instead of as
    decoded public keys, which refuses the same account spelled `xrb_`;
  * test_10 is red against an implementation that writes into the ledger it
    was handed, which loses a seller's book on a refused retry.

test_08 is the double-credit control and asserts the harder half: a second
credit of one block is refused EVEN WHEN the order_id is identical. An
implementation that treats that as idempotent passes a naive test and credits
a replayed payment twice.

Nothing opens a socket and nothing reads a clock; `created_utc` is passed in.
No 64-hex run stands as a literal here, matching the repository's secret gate -
every block hash is computed from a readable preimage.
"""

import hashlib
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "vendor"))

import nanoaddr  # noqa: E402
import order_binding  # noqa: E402
from order_binding import (  # noqa: E402
    REASON_CODES, BindingRefusal, assign, credit, publish_binding, tag_offset,
)

SECRET = b"a-seller-secret-of-at-least-16-bytes"
OTHER_SECRET = b"a-different-seller-secret-16-plus"
WIDTH = 10 ** 24
BASE = "1000000000000000000000000000"  # 0.001 XNO in raw
NOW = "2026-11-03T06:00:00Z"


def key_for(label):
    return hashlib.blake2b(label.encode("utf-8"), digest_size=32).digest()


def address(label, prefix="nano_"):
    return nanoaddr.encode(key_for(label), prefix)


def block_for(label):
    """A 64-hex block hash computed from a readable preimage, never a literal."""
    return hashlib.blake2b(label.encode("utf-8"), digest_size=32).hexdigest().upper()


PAYEE = address("order-binding-payee")
PAYER = address("order-binding-payer")


def expect_for(amount_raw=BASE, pay_to=PAYEE, network="nano:mainnet"):
    return {"network": network, "pay_to": pay_to, "amount_raw": amount_raw}


def info_for(amount_raw=BASE, link=PAYEE, confirmed=True, payer=PAYER):
    return {"confirmed": confirmed, "amount": amount_raw, "link_as_account": link,
            "block_account": payer}


def clean_ledger():
    return {"bindings": {}, "settled_orders": {}}


class OrderBindingTests(unittest.TestCase):

    # -- assign --------------------------------------------------------

    def test_01_assign_is_idempotent(self):
        first = assign("ord-1", BASE, [], secret=SECRET, tag_raw_width=WIDTH)
        second = assign("ord-1", BASE, [first], secret=SECRET, tag_raw_width=WIDTH)
        self.assertEqual(first["tagged_raw"], second["tagged_raw"])
        self.assertEqual(0, first["probe"])
        self.assertEqual(0, second["probe"])
        # Calling twice must not put two amounts in flight for one order.
        self.assertEqual(first["order_id"], second["order_id"])

    def test_02_collision_probes_to_a_different_amount(self):
        natural = assign("ord-2", BASE, [], secret=SECRET, tag_raw_width=WIDTH)
        seeded = [{"order_id": "ord-other", "tagged_raw": natural["tagged_raw"]}]
        probed = assign("ord-2", BASE, seeded, secret=SECRET, tag_raw_width=WIDTH)
        self.assertGreaterEqual(probed["probe"], 1)
        self.assertNotEqual(natural["tagged_raw"], probed["tagged_raw"])

    def test_03_max_attempts_exhausted_is_a_refusal(self):
        base_amount = assign("ord-3", BASE, [], secret=SECRET, tag_raw_width=WIDTH)["tagged_raw"]
        probe1 = str(int(BASE) + tag_offset("ord-3:1", secret=SECRET, tag_raw_width=WIDTH))
        seeded = [{"order_id": "a", "tagged_raw": base_amount},
                  {"order_id": "b", "tagged_raw": probe1}]
        with self.assertRaises(BindingRefusal) as caught:
            assign("ord-3", BASE, seeded, secret=SECRET, tag_raw_width=WIDTH, max_attempts=1)
        self.assertEqual("TAG_COLLISION", caught.exception.code)

    def test_04_tag_offset_is_deterministic_and_secret_dependent(self):
        a = tag_offset("ord-4", secret=SECRET, tag_raw_width=WIDTH)
        b = tag_offset("ord-4", secret=SECRET, tag_raw_width=WIDTH)
        self.assertEqual(a, b)
        self.assertNotEqual(a, tag_offset("ord-4", secret=OTHER_SECRET, tag_raw_width=WIDTH))

    def test_05_ordering_leak_control(self):
        """A monotone offset publishes the seller's order sequence. 199 steps,
        a fair coin: a counter scores 199 rises, a reversed counter 0."""
        offsets = [tag_offset("ord-%d" % n, secret=SECRET, tag_raw_width=WIDTH)
                   for n in range(200)]
        self.assertFalse(all(b >= a for a, b in zip(offsets, offsets[1:])),
                         "offsets are monotonically non-decreasing: the sequence leaks")
        rises = sum(1 for a, b in zip(offsets, offsets[1:]) if b > a)
        self.assertTrue(60 <= rises <= 140,
                        "adjacent rises %d outside [60, 140] - not order-independent" % rises)

    def test_06_assign_and_offset_refuse_bad_inputs(self):
        with self.assertRaises(BindingRefusal) as caught:
            tag_offset("ord-6", secret=b"fifteen-bytes!!", tag_raw_width=WIDTH)
        self.assertEqual("NO_SECRET", caught.exception.code)
        with self.assertRaises(BindingRefusal) as caught:
            tag_offset("", secret=SECRET, tag_raw_width=WIDTH)
        self.assertEqual("BAD_ORDER_ID", caught.exception.code)
        with self.assertRaises(ValueError):
            tag_offset("ord-6", secret=SECRET, tag_raw_width=100)
        with self.assertRaises(BindingRefusal) as caught:
            assign("ord-6", "0100", [], secret=SECRET, tag_raw_width=WIDTH)
        self.assertEqual("AMOUNT_MISMATCH", caught.exception.code)

    # -- credit --------------------------------------------------------

    def test_07_credit_writes_both_sides_of_the_binding(self):
        block = block_for("ord-7-block")
        out = credit(clean_ledger(), block_hash=block, order_id="ord-7",
                     block_info=info_for(), expect=expect_for(), created_utc=NOW)
        self.assertEqual("ord-7", out["ledger"]["bindings"][block]["order_id"])
        self.assertEqual(block, out["ledger"]["settled_orders"]["ord-7"])
        self.assertEqual(NOW, out["binding"]["credited_utc"])
        self.assertEqual("node reported confirmed", out["binding"]["confirmation_policy"])

    def test_08_double_credit_control(self):
        block = block_for("ord-8-block")
        first = credit(clean_ledger(), block_hash=block, order_id="ord-8",
                       block_info=info_for(), expect=expect_for(), created_utc=NOW)
        # The hard half: the SAME order_id is still refused. Credit is once.
        with self.assertRaises(BindingRefusal) as caught:
            credit(first["ledger"], block_hash=block, order_id="ord-8",
                   block_info=info_for(), expect=expect_for(), created_utc=NOW)
        self.assertEqual("BLOCK_ALREADY_CREDITED", caught.exception.code)
        # A different block against an already-settled order is also refused.
        with self.assertRaises(BindingRefusal) as caught:
            credit(first["ledger"], block_hash=block_for("ord-8-second-block"),
                   order_id="ord-8", block_info=info_for(), expect=expect_for(),
                   created_utc=NOW)
        self.assertEqual("ORDER_ALREADY_SETTLED", caught.exception.code)

    def test_09_prefix_control(self):
        """The same account spelled two ways is one account. A string compare
        refuses this and fails the test."""
        legacy = address("order-binding-payee", "xrb_")
        self.assertNotEqual(legacy, PAYEE)
        out = credit(clean_ledger(), block_hash=block_for("ord-9-block"), order_id="ord-9",
                     block_info=info_for(link=PAYEE), expect=expect_for(pay_to=legacy),
                     created_utc=NOW)
        self.assertEqual("ord-9", out["binding"]["order_id"])
        self.assertTrue(out["binding"]["pay_to"].startswith("nano_"))

    def test_10_immutability_control(self):
        ledger = clean_ledger()
        before = json.dumps(ledger, sort_keys=True)
        credit(ledger, block_hash=block_for("ord-10-block"), order_id="ord-10",
               block_info=info_for(), expect=expect_for(), created_utc=NOW)
        self.assertEqual(before, json.dumps(ledger, sort_keys=True),
                         "a successful credit mutated the ledger it was handed")
        with self.assertRaises(BindingRefusal):
            credit(ledger, block_hash=block_for("ord-10-block"), order_id="ord-10",
                   block_info=info_for(confirmed="false"), expect=expect_for(),
                   created_utc=NOW)
        self.assertEqual(before, json.dumps(ledger, sort_keys=True),
                         "a refused credit mutated the ledger it was handed")

    def test_11_each_refusal_has_its_own_code(self):
        cases = [
            ("NOT_CONFIRMED", dict(block_info=info_for(confirmed="false"), expect=expect_for())),
            ("AMOUNT_MISMATCH", dict(block_info=info_for(amount_raw=str(int(BASE) - 1)),
                                     expect=expect_for())),
            ("RECIPIENT_MISMATCH", dict(block_info=info_for(link=address("someone-else")),
                                        expect=expect_for())),
            ("NETWORK_MISMATCH", dict(block_info=info_for(), expect=expect_for(network="base"))),
        ]
        for code, kwargs in cases:
            with self.assertRaises(BindingRefusal) as caught:
                credit(clean_ledger(), block_hash=block_for("ord-11-%s" % code),
                       order_id="ord-11", created_utc=NOW, **kwargs)
            self.assertEqual(code, caught.exception.code)
        short = block_for("ord-11-short")[:63]
        with self.assertRaises(BindingRefusal) as caught:
            credit(clean_ledger(), block_hash=short, order_id="ord-11",
                   block_info=info_for(), expect=expect_for(), created_utc=NOW)
        self.assertEqual("BAD_BLOCK_HASH", caught.exception.code)

    def test_12_publish_binding_redacts_only_the_payer(self):
        out = credit(clean_ledger(), block_hash=block_for("ord-12-block"), order_id="ord-12",
                     block_info=info_for(), expect=expect_for(), created_utc=NOW)
        binding = out["binding"]
        public = publish_binding(binding, public=True)
        self.assertNotIn("from_account", public)
        self.assertIs(True, public["from_account_redacted"])
        for field in ("block_hash", "order_id", "amount_raw", "pay_to", "network", "credited_utc"):
            self.assertIn(field, public)
            self.assertEqual(binding[field], public[field])
        private = publish_binding(binding, public=False)
        self.assertEqual(PAYER, private["from_account"])
        self.assertNotIn("from_account_redacted", private)

    def test_13_the_amount_is_never_the_identifier(self):
        """Hand credit() an amount that is some OTHER open invoice's tagged_raw.
        The credit still goes to the order the caller named, because the tag is
        a hint and the binding of record is the recorded pair."""
        other = assign("ord-other", BASE, [], secret=SECRET, tag_raw_width=WIDTH)
        amount = other["tagged_raw"]
        self.assertNotEqual(BASE, amount)
        out = credit(clean_ledger(), block_hash=block_for("ord-13-block"), order_id="ord-13",
                     block_info=info_for(amount_raw=amount),
                     expect=expect_for(amount_raw=amount), created_utc=NOW)
        self.assertEqual("ord-13", out["binding"]["order_id"])
        self.assertEqual("ord-13", out["ledger"]["bindings"][block_for("ord-13-block")]["order_id"])
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "order_binding.py"), encoding="utf-8") as handle:
            source = handle.read()
        body = source.split("def credit(", 1)[1].split("\ndef ", 1)[0]
        self.assertNotIn("tagged_raw", body,
                         "credit() consults tagged_raw: the amount has become an identifier")

    # -- repository conventions ---------------------------------------

    def test_14_self_test_is_green_and_codes_are_declared(self):
        report = order_binding._self_test()
        self.assertTrue(report["ok"], report["failures"])
        self.assertEqual("(block_hash, order_id)", report["binding_of_record"])
        with self.assertRaises(AssertionError):
            BindingRefusal("NOT_A_REAL_CODE", "a typo'd code must not construct")
        for code in ("TAG_COLLISION", "BLOCK_ALREADY_CREDITED", "ORDER_ALREADY_SETTLED",
                     "AMOUNT_MISMATCH", "RECIPIENT_MISMATCH", "NETWORK_MISMATCH",
                     "NOT_CONFIRMED", "BAD_ORDER_ID", "BAD_BLOCK_HASH", "NO_SECRET"):
            self.assertIn(code, REASON_CODES)

    def test_15_nothing_opens_a_socket(self):
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "order_binding.py"), encoding="utf-8") as handle:
            source = handle.read()
        for forbidden in ("import socket", "urllib.request", "import requests", "http.client"):
            self.assertNotIn(forbidden, source)

    def test_16_the_old_module_points_here(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "order_bound_amount.py")
        with open(path, encoding="utf-8") as handle:
            head = handle.read()[:4000]
        self.assertIn("order_binding", head,
                      "a reader of order_bound_amount.py must be told where the "
                      "binding of record lives")


if __name__ == "__main__":
    unittest.main()
