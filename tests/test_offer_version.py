"""The fourth claim: was the accepted OFFER VERSION proven. saraofficinaip's three rows are tests 1-3, verbatim in shape.

saraofficinaip, 2026-10-25T00:32:09Z: "(A) invoice i7 references offer v7; v7 is explicitly preserved for buyer b1;
accepting i7 records v7 and succeeds. (B) v7 is explicitly withdrawn for b1 before acceptance; accepting i7 is
rejected. (C) a receipt references i7, but the invoice-to-offer record is missing; settlement may be observed, while
the accepted offer version stays unproven." Mapping: v7 = an offer's scope_digest, i7 = the buyer's order_key,
withdrawn = decline. A mocked receipt is enough: nothing here moves funds.

Every fixture is built in this file. No sockets. No 64-hex run stands as one literal.
"""
import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "vendor"))

import acceptance_receipt as ar  # noqa: E402
import nanoaddr  # noqa: E402
import seller_offer as so  # noqa: E402

NOW = "2026-10-25T06:00:00Z"
KEY = "b1-i7-fixture-order-key"
PAYEE = nanoaddr.encode(bytes(range(32)), "nano_")


def offers_doc(accept=True, decline=False):
    parsed = {"agent": "fixture-seller", "output": "markdown summary of the fixture endpoint response, under 1500 chars",
              "input": "GET https://example.invalid/home", "by": "2026-10-26T06:00:00Z", "price_xno": "0.05",
              "payout_address": PAYEE}
    doc, offer = so.propose(so.empty_offers(), parsed, source="issue", source_url="https://example.invalid/1", now=NOW)
    if decline:
        doc, offer = so.decline(doc, offer["id"], so.DECLINE_REASONS[0], now=NOW)
    elif accept:
        doc, offer = so.accept(doc, offer["id"], KEY, now=NOW)
    return doc, offer


def acceptance(offers=None, offer_id=None, key=KEY, settled=True):
    kw = dict(order_key=key, request_context_sha256="cd" * 32, anchor_frontier="EF" * 32, anchor_height=1,
              dispute_window_hours=24, now=NOW, offers=offers, offer_id=offer_id)
    if settled:
        kw.update(settled_block="AB" * 32, amount_raw="5" + "0" * 28, payee=PAYEE)
    return ar.open_acceptance(ar.empty_acceptances(), **kw)


class SarasRows(unittest.TestCase):
    def test_1_row_A_proven_and_digest_unchanged(self):
        doc, offer = offers_doc()
        _, row = acceptance(offers=doc)
        claim = row["claims"]["offer_version"]
        self.assertEqual(claim["verdict_is"], "proven")
        self.assertIs(claim["verdict"], True)
        self.assertEqual(claim["inputs"]["scope_digest_halves"], offer["scope_digest_halves"])
        self.assertEqual(claim["inputs"]["offer_state_at_accept"], "accepted")

    def test_2_row_B_withdrawn_before_accept_is_refuted_and_disputed(self):
        doc, offer = offers_doc(decline=True)
        with self.assertRaises(so.Refusal) as ctx:        # the accept itself is refused, as in sara's row B
            so.accept(doc, offer["id"], KEY, now=NOW)
        self.assertEqual(ctx.exception.code, "not_proposed")
        _, row = acceptance(offers=doc, offer_id=offer["id"])
        self.assertEqual(row["claims"]["offer_version"]["verdict_is"], "refuted_withdrawn_before_accept")
        self.assertEqual(row["outcome_if_closed_now"], "disputed")

    def test_3_row_C_orphan_key_is_unproven_and_settlement_is_untouched(self):
        doc, _ = offers_doc()
        _, row = acceptance(offers=doc, key="orphan-order-key-no-offer-row")
        self.assertEqual(row["claims"]["offer_version"]["verdict_is"], "unproven_no_offer_record")
        self.assertIs(row["claims"]["settled"]["verdict"], True)          # settlement observed, version unproven
        self.assertEqual(row["claims"]["settled"]["verdict_is"], "measured")
        self.assertNotEqual(row["outcome_if_closed_now"], "disputed")      # a thin record is not a dispute

    def test_4_no_offers_file_is_not_yet_resolved_never_proven(self):
        _, row = acceptance(offers=None)
        claim = row["claims"]["offer_version"]
        self.assertEqual(claim["verdict_is"], "not_yet_resolved")
        self.assertIsNone(claim["verdict"])

    def test_5_scope_rewritten_after_accept_is_refuted_digest_mismatch(self):
        doc, offer = offers_doc()
        tampered = copy.deepcopy(doc)
        tampered["offers"][0]["scope"]["output"] = "a different deliverable than the one that was digested at accept"
        _, row = acceptance(offers=tampered)
        self.assertEqual(row["claims"]["offer_version"]["verdict_is"], "refuted_digest_mismatch")
        self.assertEqual(row["outcome_if_closed_now"], "disputed")

    def test_6_two_offers_with_one_order_key_is_ambiguous(self):
        doc, _ = offers_doc()
        twin = copy.deepcopy(doc["offers"][0])
        twin["id"] = "offer-2026-10-25-002"
        doc["offers"].append(twin)
        _, row = acceptance(offers=doc)
        self.assertEqual(row["claims"]["offer_version"]["verdict_is"], "unproven_ambiguous")

    def test_7_missing_offers_file_refuses_and_leaves_the_state_file_alone(self):
        d = tempfile.mkdtemp()
        store = os.path.join(d, "acc.json")
        ar.write_json(store, ar.empty_acceptances())
        before = open(store, "rb").read()
        r = subprocess.run([sys.executable, os.path.join(ROOT, "acceptance_receipt.py"), "open",
                            "--acceptances", store, "--out", os.path.join(d, "feed.json"), "--now", NOW,
                            "--order-key", KEY, "--request-context-sha256", "cd" * 32, "--anchor-frontier", "EF" * 32,
                            "--anchor-height", "1", "--dispute-window-hours", "24",
                            "--offers", os.path.join(d, "does-not-exist.json")], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("reason=offers_file_unreadable", r.stderr)
        self.assertEqual(open(store, "rb").read(), before)
        self.assertFalse(os.path.exists(os.path.join(d, "feed.json")))

    def test_8_feed_counts_are_published_at_zero(self):
        feed = ar.feed(ar.empty_acceptances(), now=NOW)
        for name in ("offer_version_proven", "offer_version_unproven", "offer_version_refuted",
                     "offer_version_not_yet_resolved"):
            self.assertEqual(feed[name], 0)
        self.assertTrue(feed["offer_version_note"])

    def test_9_feed_counts_follow_the_rows(self):
        doc, _ = offers_doc()
        store = ar.empty_acceptances()
        ar.open_acceptance(store, order_key=KEY, request_context_sha256="cd" * 32, anchor_frontier="EF" * 32,
                           anchor_height=1, dispute_window_hours=24, now=NOW, offers=doc)
        ar.open_acceptance(store, order_key="orphan-order-key-no-offer-row", request_context_sha256="cd" * 32,
                           anchor_frontier="EF" * 32, anchor_height=1, dispute_window_hours=24, now=NOW, offers=doc)
        ar.open_acceptance(store, order_key="never-looked-order-key-x", request_context_sha256="cd" * 32,
                           anchor_frontier="EF" * 32, anchor_height=1, dispute_window_hours=24, now=NOW)
        feed = ar.feed(store, now=NOW)
        self.assertEqual((feed["offer_version_proven"], feed["offer_version_unproven"],
                          feed["offer_version_refuted"], feed["offer_version_not_yet_resolved"]), (1, 1, 0, 1))

    def test_10_closing_with_offers_looks_again_and_keeps_the_history(self):
        doc, _ = offers_doc()
        store = ar.empty_acceptances()
        _, row = ar.open_acceptance(store, order_key=KEY, request_context_sha256="cd" * 32, anchor_frontier="EF" * 32,
                                    anchor_height=1, dispute_window_hours=24, now=NOW,
                                    settled_block="AB" * 32, amount_raw="5" + "0" * 28, payee=PAYEE)
        self.assertEqual(row["claims"]["offer_version"]["verdict_is"], "not_yet_resolved")
        ar.deliver(store, row["id"], "https://example.invalid/o.md", "12" * 32, now=NOW)
        _, att = ar.attest(store, row["id"], "accepted", "the output matched the scope exactly", now=NOW, offers=doc)
        self.assertEqual(att["claims"]["offer_version"]["verdict_is"], "proven")
        self.assertEqual(att["claims"]["offer_version"]["history"][0]["verdict_is"], "not_yet_resolved")

    def test_11_a_refuted_version_makes_a_closed_settled_delivered_row_disputed_not_accepted(self):
        doc, _ = offers_doc()
        doc["offers"][0]["scope"]["by"] = "2030-01-01T00:00:00Z"            # rewritten after accept
        store = ar.empty_acceptances()
        _, row = ar.open_acceptance(store, order_key=KEY, request_context_sha256="cd" * 32, anchor_frontier="EF" * 32,
                                    anchor_height=1, dispute_window_hours=24, now=NOW, offers=doc,
                                    settled_block="AB" * 32, amount_raw="5" + "0" * 28, payee=PAYEE)
        ar.deliver(store, row["id"], "https://example.invalid/o.md", "12" * 32, now=NOW)
        ar.attest(store, row["id"], "accepted", "the output matched the scope exactly", now=NOW)
        _, closed = ar.close(store, row["id"], now=NOW)
        self.assertEqual(closed["outcome"], "disputed")

    def test_12_the_verdict_set_is_closed_and_prefixes_separate_thin_from_moved(self):
        self.assertEqual(set(ar.OFFER_VERDICTS), {"not_yet_resolved", "proven", "unproven_no_offer_record",
                                                  "unproven_ambiguous", "refuted_digest_mismatch",
                                                  "refuted_withdrawn_before_accept"})
        doc, _ = offers_doc()
        for offers in (None, doc):
            for key in (KEY, "orphan-order-key-no-offer-row"):
                self.assertIn(ar.offer_version_claim(offers, key)["verdict_is"], ar.OFFER_VERDICTS)


if __name__ == "__main__":
    unittest.main()
