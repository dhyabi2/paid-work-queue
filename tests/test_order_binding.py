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


def expect_for(order_id, amount_raw=BASE, pay_to=PAYEE, network="nano:mainnet"):
    """The seller's recorded terms FOR ONE ORDER: they name the order they belong to."""
    return {"order_id": order_id, "network": network, "pay_to": pay_to,
            "amount_raw": amount_raw}


def info_for(amount_raw=BASE, link=PAYEE, confirmed=True, payer=PAYER, subtype="send"):
    return {"confirmed": confirmed, "amount": amount_raw, "link_as_account": link,
            "block_account": payer, "subtype": subtype}


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
                     block_info=info_for(), expect=expect_for("ord-7"), created_utc=NOW)
        self.assertEqual("ord-7", out["ledger"]["bindings"][block]["order_id"])
        self.assertEqual(block, out["ledger"]["settled_orders"]["ord-7"])
        self.assertEqual(NOW, out["binding"]["credited_utc"])
        self.assertEqual("node reported confirmed", out["binding"]["confirmation_policy"])

    def test_08_double_credit_control(self):
        block = block_for("ord-8-block")
        first = credit(clean_ledger(), block_hash=block, order_id="ord-8",
                       block_info=info_for(), expect=expect_for("ord-8"), created_utc=NOW)
        # The hard half: the SAME order_id is still refused. Credit is once.
        with self.assertRaises(BindingRefusal) as caught:
            credit(first["ledger"], block_hash=block, order_id="ord-8",
                   block_info=info_for(), expect=expect_for("ord-8"), created_utc=NOW)
        self.assertEqual("BLOCK_ALREADY_CREDITED", caught.exception.code)
        # A different block against an already-settled order is also refused.
        with self.assertRaises(BindingRefusal) as caught:
            credit(first["ledger"], block_hash=block_for("ord-8-second-block"),
                   order_id="ord-8", block_info=info_for(), expect=expect_for("ord-8"),
                   created_utc=NOW)
        self.assertEqual("ORDER_ALREADY_SETTLED", caught.exception.code)

    def test_09_prefix_control(self):
        """The same account spelled two ways is one account. A string compare
        refuses this and fails the test."""
        legacy = address("order-binding-payee", "xrb_")
        self.assertNotEqual(legacy, PAYEE)
        out = credit(clean_ledger(), block_hash=block_for("ord-9-block"), order_id="ord-9",
                     block_info=info_for(link=PAYEE), expect=expect_for("ord-9", pay_to=legacy),
                     created_utc=NOW)
        self.assertEqual("ord-9", out["binding"]["order_id"])
        self.assertTrue(out["binding"]["pay_to"].startswith("nano_"))

    def test_10_immutability_control(self):
        ledger = clean_ledger()
        before = json.dumps(ledger, sort_keys=True)
        credit(ledger, block_hash=block_for("ord-10-block"), order_id="ord-10",
               block_info=info_for(), expect=expect_for("ord-10"), created_utc=NOW)
        self.assertEqual(before, json.dumps(ledger, sort_keys=True),
                         "a successful credit mutated the ledger it was handed")
        with self.assertRaises(BindingRefusal):
            credit(ledger, block_hash=block_for("ord-10-block"), order_id="ord-10",
                   block_info=info_for(confirmed="false"), expect=expect_for("ord-10"),
                   created_utc=NOW)
        self.assertEqual(before, json.dumps(ledger, sort_keys=True),
                         "a refused credit mutated the ledger it was handed")

    def test_11_each_refusal_has_its_own_code(self):
        cases = [
            ("NOT_CONFIRMED", dict(block_info=info_for(confirmed="false"), expect=expect_for("ord-11"))),
            ("AMOUNT_MISMATCH", dict(block_info=info_for(amount_raw=str(int(BASE) - 1)),
                                     expect=expect_for("ord-11"))),
            ("RECIPIENT_MISMATCH", dict(block_info=info_for(link=address("someone-else")),
                                        expect=expect_for("ord-11"))),
            ("NETWORK_MISMATCH", dict(block_info=info_for(), expect=expect_for("ord-11", network="base"))),
        ]
        for code, kwargs in cases:
            with self.assertRaises(BindingRefusal) as caught:
                credit(clean_ledger(), block_hash=block_for("ord-11-%s" % code),
                       order_id="ord-11", created_utc=NOW, **kwargs)
            self.assertEqual(code, caught.exception.code)
        short = block_for("ord-11-short")[:63]
        with self.assertRaises(BindingRefusal) as caught:
            credit(clean_ledger(), block_hash=short, order_id="ord-11",
                   block_info=info_for(), expect=expect_for("ord-11"), created_utc=NOW)
        self.assertEqual("BAD_BLOCK_HASH", caught.exception.code)

    def test_12_publish_binding_redacts_only_the_payer(self):
        out = credit(clean_ledger(), block_hash=block_for("ord-12-block"), order_id="ord-12",
                     block_info=info_for(), expect=expect_for("ord-12"), created_utc=NOW)
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
                     expect=expect_for("ord-13", amount_raw=amount), created_utc=NOW)
        self.assertEqual("ord-13", out["binding"]["order_id"])
        self.assertEqual("ord-13", out["ledger"]["bindings"][block_for("ord-13-block")]["order_id"])
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "order_binding.py"), encoding="utf-8") as handle:
            source = handle.read()
        body = source.split("def credit(", 1)[1].split("\ndef ", 1)[0]
        self.assertNotIn("tagged_raw", body,
                         "credit() consults tagged_raw: the amount has become an identifier")

    # -- break-review fixes: each of these is red on 9ec75f4 -------------

    def test_17_expect_must_belong_to_the_order(self):
        """Terms recorded for one order cannot be used to credit a block to a
        different order: that is crediting a block to whichever order suits."""
        block = block_for("ord-17-block")
        unnamed = expect_for("ord-17")
        del unnamed["order_id"]
        for terms in (unnamed, expect_for("ord-someone-else"), expect_for("")):
            with self.assertRaises(BindingRefusal) as caught:
                credit(clean_ledger(), block_hash=block, order_id="ord-17",
                       block_info=info_for(), expect=terms, created_utc=NOW)
            self.assertEqual("ORDER_UNKNOWN", caught.exception.code)

    def test_18_only_a_send_from_another_account_is_a_payment(self):
        block = block_for("ord-18-block")
        for subtype in ("receive", "change", "epoch", None):
            with self.assertRaises(BindingRefusal) as caught:
                credit(clean_ledger(), block_hash=block, order_id="ord-18",
                       block_info=info_for(subtype=subtype), expect=expect_for("ord-18"),
                       created_utc=NOW)
            self.assertEqual("NOT_A_SEND", caught.exception.code, subtype)
        # The payee paying itself, spelled either way, is not a payment.
        for payer in (PAYEE, address("order-binding-payee", "xrb_")):
            with self.assertRaises(BindingRefusal) as caught:
                credit(clean_ledger(), block_hash=block, order_id="ord-18",
                       block_info=info_for(payer=payer), expect=expect_for("ord-18"),
                       created_utc=NOW)
            self.assertEqual("SELF_SEND", caught.exception.code)

    def test_19_reprice_of_an_open_order_is_refused_not_ignored(self):
        first = assign("ord-19", BASE, [], secret=SECRET, tag_raw_width=WIDTH)
        repriced = str(int(BASE) * 2)
        with self.assertRaises(BindingRefusal) as caught:
            assign("ord-19", repriced, [first], secret=SECRET, tag_raw_width=WIDTH)
        self.assertEqual("AMOUNT_MISMATCH", caught.exception.code)
        # An open invoice recorded without base_raw is still checked by range.
        bare = {"order_id": "ord-19", "tagged_raw": first["tagged_raw"]}
        with self.assertRaises(BindingRefusal) as caught:
            assign("ord-19", repriced, [bare], secret=SECRET, tag_raw_width=WIDTH)
        self.assertEqual("AMOUNT_MISMATCH", caught.exception.code)
        # The same base is still idempotent.
        again = assign("ord-19", BASE, [first], secret=SECRET, tag_raw_width=WIDTH)
        self.assertEqual(first["tagged_raw"], again["tagged_raw"])

    def test_20_collision_compares_amounts_as_integers(self):
        natural = assign("ord-20", BASE, [], secret=SECRET, tag_raw_width=WIDTH)
        for spelling in ("0" + natural["tagged_raw"], " %s " % natural["tagged_raw"],
                         int(natural["tagged_raw"])):
            seeded = [{"order_id": "ord-other", "tagged_raw": spelling}]
            probed = assign("ord-20", BASE, seeded, secret=SECRET, tag_raw_width=WIDTH)
            self.assertGreaterEqual(probed["probe"], 1, repr(spelling))
            self.assertNotEqual(int(natural["tagged_raw"]), int(probed["tagged_raw"]))

    def test_21_malformed_ledger_is_a_refusal_not_a_crash(self):
        block = block_for("ord-21-block")
        ledgers = [
            [],
            {"bindings": [], "settled_orders": {}},
            {"bindings": {block: "not-a-dict"}, "settled_orders": {}},
            {"bindings": {"not-a-hash": {"order_id": "x"}}, "settled_orders": {}},
            {"bindings": {}, "settled_orders": {"x": 7}},
        ]
        # An absent or None side is an empty book, and the credit still writes.
        out = credit({"bindings": None}, block_hash=block, order_id="ord-21",
                     block_info=info_for(), expect=expect_for("ord-21"), created_utc=NOW)
        self.assertEqual(block, out["ledger"]["settled_orders"]["ord-21"])
        for ledger in ledgers:
            with self.assertRaises(BindingRefusal) as caught:
                credit(ledger, block_hash=block, order_id="ord-21", block_info=info_for(),
                       expect=expect_for("ord-21"), created_utc=NOW)
            self.assertEqual("BAD_LEDGER", caught.exception.code, repr(ledger))
        books = [
            {"bad": "shape"},
            ["not-a-dict"],
            [{"order_id": "ord-21", "tagged_raw": BASE, "probe": "x"}],
            [{"order_id": "other", "tagged_raw": "12abc"}],
        ]
        for book in books:
            with self.assertRaises(BindingRefusal) as caught:
                assign("ord-21", BASE, book, secret=SECRET, tag_raw_width=WIDTH)
            self.assertEqual("BAD_LEDGER", caught.exception.code, repr(book))

    def test_22_a_lowercase_key_in_the_ledger_still_blocks_double_credit(self):
        block = block_for("ord-22-block")
        cases = [
            {"bindings": {block.lower(): {"order_id": "ord-a"}},
             "settled_orders": {"ord-a": block.lower()}},
            # bindings lost, settled_orders still remembers the block
            {"bindings": {}, "settled_orders": {"ord-a": block.lower()}},
        ]
        for ledger in cases:
            with self.assertRaises(BindingRefusal) as caught:
                credit(ledger, block_hash=block, order_id="ord-b", block_info=info_for(),
                       expect=expect_for("ord-b"), created_utc=NOW)
            self.assertEqual("BLOCK_ALREADY_CREDITED", caught.exception.code)

    def test_23_an_order_in_bindings_alone_is_not_paid_twice(self):
        # settled_orders lost the order; bindings still binds it to a block.
        # Red on bc2424b: the order was credited again with a second block.
        first = block_for("ord-23-first")
        ledger = {"bindings": {first: {"order_id": "ord-23", "credited_utc": NOW}},
                  "settled_orders": {}}
        with self.assertRaises(BindingRefusal) as caught:
            credit(ledger, block_hash=block_for("ord-23-second"), order_id="ord-23",
                   block_info=info_for(), expect=expect_for("ord-23"), created_utc=NOW)
        self.assertEqual("ORDER_ALREADY_SETTLED", caught.exception.code)
        # The two sides contradicting each other is BAD_LEDGER, not a guess.
        other = block_for("ord-23-other")
        for book in (
            {"bindings": {first: {"order_id": "ord-23"}}, "settled_orders": {"ord-23": other}},
            {"bindings": {first: {"order_id": "ord-x"}}, "settled_orders": {"ord-y": first}},
            {"bindings": {first: {"credited_utc": NOW}}, "settled_orders": {}},
        ):
            with self.assertRaises(BindingRefusal) as caught:
                credit(book, block_hash=block_for("ord-23-new"), order_id="ord-23-new",
                       block_info=info_for(), expect=expect_for("ord-23-new"), created_utc=NOW)
            self.assertEqual("BAD_LEDGER", caught.exception.code, repr(book))

    def test_24_a_block_with_no_sending_account_fails_closed(self):
        # Red on bc2424b: a missing block_account skipped the self-send check.
        block = block_for("ord-24-block")
        with self.assertRaises(BindingRefusal) as caught:
            credit(clean_ledger(), block_hash=block, order_id="ord-24",
                   block_info=info_for(payer=None), expect=expect_for("ord-24"),
                   created_utc=NOW)
        self.assertEqual("SELF_SEND", caught.exception.code)
        # contents.account alone is read, and the payee there is still a self-send.
        info = info_for(payer=None)
        info["contents"] = {"account": PAYEE}
        with self.assertRaises(BindingRefusal) as caught:
            credit(clean_ledger(), block_hash=block, order_id="ord-24", block_info=info,
                   expect=expect_for("ord-24"), created_utc=NOW)
        self.assertEqual("SELF_SEND", caught.exception.code)

    def test_25_a_node_block_info_shape_is_credited(self):
        # The shape rpc.nano.to returned for block_info json_block true on a
        # state send (2026-11-06): block_account, amount, balance, height,
        # local_timestamp, successor, confirmed ("true"), subtype, balance_nano,
        # amount_nano at the top; the recipient ONLY in contents (type, account,
        # previous, representative, balance, link, link_as_account, signature,
        # work, balance_nano). Red on bc2424b: RECIPIENT_MISMATCH.
        block = block_for("ord-25-block")
        payee_key = key_for("order-binding-payee")

        def node_info(**contents_override):
            contents = {"type": "state", "account": PAYER, "previous": block_for("ord-25-prev"),
                        "representative": PAYER, "balance": "1",
                        "link": payee_key.hex().upper(), "link_as_account": PAYEE,
                        "signature": "00" * 64, "work": "0" * 16, "balance_nano": "0"}
            contents.update(contents_override)
            contents = {k: v for k, v in contents.items() if v is not None}
            return {"block_account": PAYER, "amount": BASE, "balance": "1", "height": "2",
                    "local_timestamp": "1791116182", "successor": "0" * 64,
                    "confirmed": "true", "contents": contents, "subtype": "send",
                    "balance_nano": "0", "amount_nano": "0.001"}

        for info in (node_info(), node_info(link=None), node_info(link_as_account=None),
                     node_info(link=payee_key.hex().lower())):
            result = credit(clean_ledger(), block_hash=block, order_id="ord-25",
                            block_info=info, expect=expect_for("ord-25"), created_utc=NOW)
            self.assertEqual("ord-25", result["ledger"]["bindings"][block]["order_id"])
            self.assertEqual(PAYER, result["binding"]["from_account"])
        refused = [
            node_info(link=None, link_as_account=None),          # no recipient at all
            node_info(link=key_for("someone-else").hex()),        # spellings disagree
            node_info(link="not-hex"),                            # link is not 64 hex
            dict(node_info(), contents=json.dumps(node_info()["contents"])),  # json_block false
        ]
        for info in refused:
            with self.assertRaises(BindingRefusal) as caught:
                credit(clean_ledger(), block_hash=block, order_id="ord-25", block_info=info,
                       expect=expect_for("ord-25"), created_utc=NOW)
            self.assertEqual("RECIPIENT_MISMATCH", caught.exception.code)

    def test_26_order_id_is_verbatim_and_case_twins_are_refused(self):
        # Red on bc18be8: "o1 " and "O1" were each credited a second block
        # after "o1" settled, and a book recording "O1" and "o1" was read.
        first = credit(clean_ledger(), block_hash=block_for("ord-26-a"), order_id="o1",
                       block_info=info_for(), expect=expect_for("o1"), created_utc=NOW)
        for bad in ("o1 ", " o1", "o1\n", "\t"):
            with self.assertRaises(BindingRefusal) as caught:
                credit(clean_ledger(), block_hash=block_for("ord-26-b"), order_id=bad,
                       block_info=info_for(), expect=expect_for(bad), created_utc=NOW)
            self.assertEqual("BAD_ORDER_ID", caught.exception.code, repr(bad))
            for call in (lambda: assign(bad, BASE, [], secret=SECRET, tag_raw_width=WIDTH),
                         lambda: tag_offset(bad, secret=SECRET, tag_raw_width=WIDTH)):
                with self.assertRaises(BindingRefusal) as caught:
                    call()
                self.assertEqual("BAD_ORDER_ID", caught.exception.code, repr(bad))
        with self.assertRaises(BindingRefusal) as caught:
            credit(first["ledger"], block_hash=block_for("ord-26-b"), order_id="O1",
                   block_info=info_for(), expect=expect_for("O1"), created_utc=NOW)
        self.assertEqual("ORDER_ALREADY_SETTLED", caught.exception.code)
        x, y = block_for("ord-26-x"), block_for("ord-26-y")
        twins = [
            {"bindings": {y: {"order_id": "o1"}}, "settled_orders": {"O1": x}},
            {"bindings": {x: {"order_id": "O1"}, y: {"order_id": "o1"}}, "settled_orders": {}},
            {"bindings": {}, "settled_orders": {"o1": x, "o1 ": y}},
        ]
        for ledger in twins:
            with self.assertRaises(BindingRefusal) as caught:
                credit(ledger, block_hash=block_for("ord-26-z"), order_id="other",
                       block_info=info_for(), expect=expect_for("other"), created_utc=NOW)
            self.assertEqual("BAD_LEDGER", caught.exception.code, repr(ledger))

    def test_27_amounts_are_strict_positive_raw(self):
        # Red on bc18be8: int(str(x)) accepted every one of these.
        for bad in ("+1000", "1_000", " 1000 ", "-1000", "0", "01000", "1000\n",
                    "\u0661\u0660\u0660\u0660", 1000, None):
            for kwargs in (dict(block_info=info_for(amount_raw=bad),
                                expect=expect_for("ord-27", amount_raw="1000")),
                           dict(block_info=info_for(amount_raw="1000"),
                                expect=expect_for("ord-27", amount_raw=bad))):
                with self.assertRaises(BindingRefusal) as caught:
                    credit(clean_ledger(), block_hash=block_for("ord-27"), order_id="ord-27",
                           created_utc=NOW, **kwargs)
                self.assertEqual("AMOUNT_MISMATCH", caught.exception.code, repr(bad))
        out = credit(clean_ledger(), block_hash=block_for("ord-27"), order_id="ord-27",
                     block_info=info_for(amount_raw="1000"),
                     expect=expect_for("ord-27", amount_raw="1000"), created_utc=NOW)
        self.assertEqual("1000", out["binding"]["amount_raw"])

    def test_28_bad_inputs_are_refusals_not_bare_exceptions(self):
        # Red on bc18be8: TypeError / ValueError escaped, outside REASON_CODES.
        self.assertIn("BAD_INPUT", REASON_CODES)
        block = block_for("ord-28")
        calls = [
            ("BAD_INPUT", dict(block_info=None, expect=expect_for("ord-28"), created_utc=NOW)),
            ("BAD_INPUT", dict(block_info=[], expect=expect_for("ord-28"), created_utc=NOW)),
            ("BAD_INPUT", dict(block_info=info_for(), expect="terms", created_utc=NOW)),
            ("BAD_INPUT", dict(block_info=info_for(), expect=expect_for("ord-28"))),
            ("BAD_INPUT", dict(block_info=info_for(), expect=expect_for("ord-28"),
                               created_utc="")),
        ]
        for code, kwargs in calls:
            with self.assertRaises(BindingRefusal) as caught:
                credit(clean_ledger(), block_hash=block, order_id="ord-28", **kwargs)
            self.assertEqual(code, caught.exception.code, repr(kwargs))
        cyclic = clean_ledger()
        cyclic["notes"] = [cyclic]
        for ledger in (dict(clean_ledger(), notes={1, 2}), dict(clean_ledger(), raw=b"x"),
                       cyclic):
            with self.assertRaises(BindingRefusal) as caught:
                credit(ledger, block_hash=block, order_id="ord-28", block_info=info_for(),
                       expect=expect_for("ord-28"), created_utc=NOW)
            self.assertEqual("BAD_LEDGER", caught.exception.code)

    def test_29_credit_states_that_block_info_is_trusted_for_the_hash(self):
        doc = credit.__doc__ or ""
        self.assertIn("does not echo the hash", doc)
        self.assertIn("byte-exact", doc)

    def test_30_an_amount_past_39_digits_is_a_refusal_not_a_valueerror(self):
        # Red on 1fc3118: a 5000-digit amount reached int() and CPython's
        # int/str digit limit raised a bare ValueError outside REASON_CODES.
        huge = "1" * 5000
        forty = "1" * 40
        for bad in (huge, forty):
            for kwargs in (dict(block_info=info_for(amount_raw=bad),
                                expect=expect_for("ord-30", amount_raw="1000")),
                           dict(block_info=info_for(amount_raw="1000"),
                                expect=expect_for("ord-30", amount_raw=bad))):
                with self.assertRaises(BindingRefusal) as caught:
                    credit(clean_ledger(), block_hash=block_for("ord-30"), order_id="ord-30",
                           created_utc=NOW, **kwargs)
                self.assertEqual("BAD_INPUT", caught.exception.code, len(bad))
            with self.assertRaises(BindingRefusal) as caught:
                assign("ord-30", bad, [], secret=SECRET, tag_raw_width=WIDTH)
            self.assertEqual("BAD_INPUT", caught.exception.code, len(bad))
            for invoice in ({"order_id": "other", "tagged_raw": bad},
                            {"order_id": "other", "tagged_raw": "0" * 4999 + "1"},
                            {"order_id": "ord-30", "tagged_raw": BASE, "base_raw": bad},
                            {"order_id": "ord-30", "tagged_raw": BASE, "probe": bad},
                            {"order_id": "other", "tagged_raw": int(forty)}):
                with self.assertRaises(BindingRefusal) as caught:
                    assign("ord-30", BASE, [invoice], secret=SECRET, tag_raw_width=WIDTH)
                self.assertEqual("BAD_LEDGER", caught.exception.code, repr(invoice)[:60])
        # 39 digits is the largest real raw amount (2**128 - 1) and still reads.
        top = str(2 ** 128 - 1)
        self.assertEqual(39, len(top))
        out = credit(clean_ledger(), block_hash=block_for("ord-30"), order_id="ord-30",
                     block_info=info_for(amount_raw=top),
                     expect=expect_for("ord-30", amount_raw=top), created_utc=NOW)
        self.assertEqual(top, out["binding"]["amount_raw"])

    def test_31_a_non_ascii_order_id_is_refused_not_normalised(self):
        # Red on 1fc3118: fullwidth, Cyrillic and folding-unsafe ids were
        # credited, so "\uff2f1" and "O1" (NFKC-equal) were two orders.
        for bad in ("\uff2f1", "\u041e1", "stra\u00dfe", "o\u0301", "\u0130d", "o1\u200b"):
            with self.assertRaises(BindingRefusal) as caught:
                credit(clean_ledger(), block_hash=block_for("ord-31"), order_id=bad,
                       block_info=info_for(), expect=expect_for(bad), created_utc=NOW)
            self.assertEqual("BAD_ORDER_ID", caught.exception.code, repr(bad))
            for call in (lambda: assign(bad, BASE, [], secret=SECRET, tag_raw_width=WIDTH),
                         lambda: tag_offset(bad, secret=SECRET, tag_raw_width=WIDTH)):
                with self.assertRaises(BindingRefusal) as caught:
                    call()
                self.assertEqual("BAD_ORDER_ID", caught.exception.code, repr(bad))
        # An old book that already records a non-ASCII id is still READ, and a
        # new ASCII id that folds equal to it is still refused as its twin.
        old = {"bindings": {}, "settled_orders": {"stra\u00dfe": block_for("ord-31-old")}}
        with self.assertRaises(BindingRefusal) as caught:
            credit(old, block_hash=block_for("ord-31-new"), order_id="STRASSE",
                   block_info=info_for(), expect=expect_for("STRASSE"), created_utc=NOW)
        self.assertEqual("ORDER_ALREADY_SETTLED", caught.exception.code)

    def test_32_a_non_str_key_is_a_refusal(self):
        # Red on 1fc3118: json.dumps() turned 1 into "1" on the copy, so
        # {1: x, "1": y} came back with one entry and the book was not the book.
        x, y = block_for("ord-32-x"), block_for("ord-32-y")
        ledgers = [
            {"bindings": {}, "settled_orders": {}, 1: "note", "1": "other note"},
            {"bindings": {x: {"order_id": "a", 7: "x"}}, "settled_orders": {"a": x}},
            {"bindings": {}, "settled_orders": {}, "notes": [{None: "n"}]},
            {"bindings": {}, "settled_orders": {}, True: "t"},
        ]
        for ledger in ledgers:
            with self.assertRaises(BindingRefusal) as caught:
                credit(ledger, block_hash=y, order_id="ord-32", block_info=info_for(),
                       expect=expect_for("ord-32"), created_utc=NOW)
            self.assertEqual("BAD_LEDGER", caught.exception.code, repr(ledger)[:60])
        for kwargs in (dict(block_info=dict(info_for(), **{"x": 1}) | {2: "x"},
                            expect=expect_for("ord-32")),
                       dict(block_info=info_for(), expect=dict(expect_for("ord-32"), **{}) | {b"k": 1}),
                       dict(block_info=dict(info_for(), contents={3: "c"}),
                            expect=expect_for("ord-32"))):
            with self.assertRaises(BindingRefusal) as caught:
                credit(clean_ledger(), block_hash=y, order_id="ord-32", created_utc=NOW, **kwargs)
            self.assertEqual("BAD_INPUT", caught.exception.code)
        with self.assertRaises(BindingRefusal) as caught:
            assign("ord-32", BASE, [{"order_id": "o", "tagged_raw": BASE, 5: "k"}],
                   secret=SECRET, tag_raw_width=WIDTH)
        self.assertEqual("BAD_LEDGER", caught.exception.code)

    def test_33_readme_carries_the_migration_note(self):
        with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "README.md"), encoding="utf-8") as f:
            readme = f.read()
        self.assertIn("Migrating a book that already holds fold-equal order ids", readme)

    def test_34_an_open_invoice_without_an_order_id_is_a_bad_ledger(self):
        # Red on fd2b715: taken.setdefault(amount, None) stored None, and
        # `holder is None` read it as FREE, so the amount in flight for the
        # unnamed invoice was quoted a second time at probe 0.
        secret, width = b"s" * 16, 10 ** 6
        t = assign("o2", "1000000", [], secret=secret, tag_raw_width=width)["tagged_raw"]
        for invoice in ({"tagged_raw": t}, {"order_id": None, "tagged_raw": t},
                        {"order_id": "", "tagged_raw": t}, {"order_id": 7, "tagged_raw": t}):
            with self.assertRaises(BindingRefusal) as caught:
                assign("o2", "1000000", [invoice], secret=secret, tag_raw_width=width)
            self.assertEqual("BAD_LEDGER", caught.exception.code, repr(invoice))
        # A named holder still forces a different amount.
        probed = assign("o2", "1000000", [{"order_id": "o9", "tagged_raw": t}],
                        secret=secret, tag_raw_width=width)
        self.assertNotEqual(t, probed["tagged_raw"])

    def test_35_assign_never_quotes_an_amount_past_the_raw_maximum(self):
        # Red on fd2b715: assign() returned a 61-digit (or 40-digit) amount that
        # the next assign() refused as BAD_LEDGER, blocking the seller; and a
        # wrong tag_raw_width raised a bare ValueError.
        top = 2 ** 128 - 1
        for base_raw, width in (("1000000", 10 ** 45), ("9" * 39, WIDTH),
                                (str(top - WIDTH + 2), WIDTH)):
            with self.assertRaises(BindingRefusal) as caught:
                assign("ord-35", base_raw, [], secret=SECRET, tag_raw_width=width)
            self.assertEqual("BAD_INPUT", caught.exception.code, (len(base_raw), width))
        for width in (None, True, 1.5, "1024", 0, -1, 100, 2 ** 128):
            with self.assertRaises(BindingRefusal) as caught:
                assign("ord-35", BASE, [], secret=SECRET, tag_raw_width=width)
            self.assertEqual("BAD_INPUT", caught.exception.code, repr(width))
        # The largest base whose whole tag space still fits is accepted, and
        # whatever it quotes reads back from the book.
        edge = str(top - WIDTH + 1)
        out = assign("ord-35", edge, [], secret=SECRET, tag_raw_width=WIDTH)
        self.assertLessEqual(int(out["tagged_raw"]), top)
        again = assign("ord-35b", BASE, [out], secret=SECRET, tag_raw_width=WIDTH)
        self.assertEqual("ord-35b", again["order_id"])

    def test_36_a_39_digit_amount_above_the_raw_maximum_is_refused(self):
        # Red on fd2b715: 39 digits passed the length cap even above 2**128 - 1.
        over = str(2 ** 128)
        self.assertEqual(39, len(over))
        for kwargs in (dict(block_info=info_for(amount_raw=over),
                            expect=expect_for("ord-36", amount_raw=over)),
                       dict(block_info=info_for(amount_raw="1000"),
                            expect=expect_for("ord-36", amount_raw=over))):
            with self.assertRaises(BindingRefusal) as caught:
                credit(clean_ledger(), block_hash=block_for("ord-36"), order_id="ord-36",
                       created_utc=NOW, **kwargs)
            self.assertEqual("BAD_INPUT", caught.exception.code)
        with self.assertRaises(BindingRefusal) as caught:
            assign("ord-36", over, [], secret=SECRET, tag_raw_width=WIDTH)
        self.assertEqual("BAD_INPUT", caught.exception.code)
        for invoice in ({"order_id": "other", "tagged_raw": over},
                        {"order_id": "other", "tagged_raw": 2 ** 128},
                        {"order_id": "ord-36", "tagged_raw": BASE, "base_raw": over}):
            with self.assertRaises(BindingRefusal) as caught:
                assign("ord-36", BASE, [invoice], secret=SECRET, tag_raw_width=WIDTH)
            self.assertEqual("BAD_LEDGER", caught.exception.code, repr(invoice))

    def test_37_an_order_id_with_a_control_character_is_refused(self):
        # Red on fd2b715: "o\x00" and friends are ASCII, so they were accepted.
        for bad in ("o\x00", "o\x001", "o\n1", "o\t1", "o\x7f", "o\x1b[0m"):
            calls = (
                lambda: credit(clean_ledger(), block_hash=block_for("ord-37"), order_id=bad,
                               block_info=info_for(), expect=expect_for(bad), created_utc=NOW),
                lambda: assign(bad, BASE, [], secret=SECRET, tag_raw_width=WIDTH),
                lambda: tag_offset(bad, secret=SECRET, tag_raw_width=WIDTH),
            )
            for call in calls:
                with self.assertRaises(BindingRefusal) as caught:
                    call()
                self.assertEqual("BAD_ORDER_ID", caught.exception.code, repr(bad))
        # Printable ASCII, inner space included, still reads.
        self.assertEqual("o 1~", assign("o 1~", BASE, [], secret=SECRET,
                                        tag_raw_width=WIDTH)["order_id"])

    def test_38_nan_or_infinity_in_the_ledger_is_a_bad_ledger(self):
        # Red on fd2b715: json.dumps() writes NaN/Infinity, which is not JSON,
        # so the copy passed and the book written was not plain JSON.
        for value in (float("nan"), float("inf"), float("-inf")):
            ledger = dict(clean_ledger(), notes={"rate": value})
            with self.assertRaises(BindingRefusal) as caught:
                credit(ledger, block_hash=block_for("ord-38"), order_id="ord-38",
                       block_info=info_for(), expect=expect_for("ord-38"), created_utc=NOW)
            self.assertEqual("BAD_LEDGER", caught.exception.code, repr(value))

    # -- repository conventions ---------------------------------------

    def test_14_self_test_is_green_and_codes_are_declared(self):
        report = order_binding._self_test()
        self.assertTrue(report["ok"], report["failures"])
        self.assertEqual("(block_hash, order_id)", report["binding_of_record"])
        with self.assertRaises(AssertionError):
            BindingRefusal("NOT_A_REAL_CODE", "a typo'd code must not construct")
        for code in ("TAG_COLLISION", "BLOCK_ALREADY_CREDITED", "ORDER_ALREADY_SETTLED",
                     "AMOUNT_MISMATCH", "RECIPIENT_MISMATCH", "NETWORK_MISMATCH",
                     "NOT_CONFIRMED", "BAD_ORDER_ID", "BAD_BLOCK_HASH", "NO_SECRET",
                     "ORDER_UNKNOWN", "NOT_A_SEND", "SELF_SEND", "BAD_LEDGER",
                     "BAD_INPUT"):
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
