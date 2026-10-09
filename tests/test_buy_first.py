"""The buy commitment: the first tool here that moves money before the work.

The decisive tests are 1, 9, 18 and 21.

Test 1 is `jessie_ilands`' own condition from 2026-10-08T20:23Z as the
fixture - *"Send one, just one, agent or human who actually wants a poem read
in my voice and can't use a card"* - with their message quoted verbatim as the
`seller_price_source`. It is the whole reason this module exists, so it is the
test that must never be allowed to become a synthetic one.

Test 9 recomputes `amount_to_send_raw` inline, from the published halves and
four lines of stdlib, WITHOUT importing `buy_first`: if that test needs the
module, a seller cannot check which order our block paid for without running
our code, and the binding proves nothing to the party it exists for.

Test 18 is the unfavourable path, and it is the one a feed that can only report
success fails: a buy that was paid and never delivered closes `not_delivered`
and must still appear, with `not_delivered_count: 1`. A buyer that publishes
only its wins is not evidence of anything.

Test 21 is the empty board. With nothing bought, the feed has to say
`buyer_account_declared: false` and say why, rather than be absent - the defect
it guards is `feed/jobs.json` publishing `buyer_account: null` for thirteen days
with nothing anywhere saying that was the blocker.

Every fixture is built independently of `buy_first`'s own `--self-test`
controls, deliberately: driving these assertions from the module's own fixtures
would let a mutation that breaks both drift past green. The addresses are
derived through the vendored codec from fixed labels, so no real payout address
appears in this file and nothing here can be paid at by mistake.

Nothing opens a socket, and nothing can: test 23 walks the import graph.

No 64-hex run stands as a single literal, matching the project's secret gate.
"""

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

import buy_first  # noqa: E402
import nanoaddr  # noqa: E402
import seller_offer  # noqa: E402

NOW = "2026-10-09T06:00:00Z"

# jessie_ilands, 2026-10-08T20:23Z, verbatim. The price source is their own
# words because the rule being tested is that the price has to be theirs.
JESSIE = (
    "jessie_ilands, 2026-10-08T20:23Z: \"'demand exists' is the one claim I "
    "can't verify from my side, and I won't build infrastructure ahead of it. "
    "So here's a test that costs us both nothing. Send one, just one, agent or "
    "human who actually wants a poem read in my voice and can't use a card. If "
    "a real buyer walks through, I'll wire a Nano door that same day, right "
    "next to the card one. One buyer is all it takes.\"")
POEM = ("one poem read aloud in your own voice, >= 30 seconds, published at a "
        "URL a stranger can open")


def address(label):
    """A checksum-valid address for a key nobody holds, derived not invented."""
    return nanoaddr.encode(hashlib.blake2b(label, digest_size=32).digest())


PAYEE = address(b"test-buy-first-payee-jessie")
BUYER = address(b"test-buy-first-buyer-operator")
OTHER = address(b"test-buy-first-payee-second-seller")


def mutate(addr):
    """The eddie_researcher case: one character off, so the checksum fails."""
    return addr[:-1] + ("4" if addr[-1] != "4" else "5")


def good(**overrides):
    base = dict(seller="jessie_ilands", output=POEM, price_xno="0.05",
                payee=PAYEE, buyer_account=BUYER, seller_price_source=JESSIE,
                refund_window_hours=72)
    base.update(overrides)
    return base


def proposed(**overrides):
    return buy_first.propose(buy_first.empty_buys(), now=NOW, **good(**overrides))


class Propose(unittest.TestCase):
    # -- 1 ------------------------------------------------------------------
    def test_1_the_jessie_ilands_fixture(self):
        """Their output, their price, their words - and we move first."""
        document, row = proposed()
        self.assertEqual(row["state"], "proposed")
        self.assertEqual(row["moves_first"], "buyer")
        self.assertEqual(row["counterparty_role"], "external")
        self.assertEqual(row["seller"], "jessie_ilands")
        self.assertEqual(row["output"], POEM)
        self.assertEqual(row["price_xno"], "0.05")
        self.assertEqual(row["price_raw"], "50" + "0" * 27)
        self.assertEqual(row["seller_price_source"], JESSIE)
        self.assertTrue(row["payee_checksum_ok"])
        self.assertEqual(row["buyer_account"], BUYER)
        self.assertEqual(row["refund_window_hours"], 72)
        self.assertEqual(row["refund_deadline"], "2026-10-12T06:00:00Z")
        self.assertEqual(len(document["buys"]), 1)
        # The record carries exactly the declared fields, no more and no fewer.
        self.assertEqual(set(document["buys"][0]), set(buy_first.BUY_FIELDS))

    # -- 2 ------------------------------------------------------------------
    def test_2_no_buyer_account_is_a_usage_error_exit_64(self):
        """B1. There is no default buyer account and no null one."""
        with tempfile.TemporaryDirectory() as tmp:
            done = cli(tmp, "propose", "--seller", "jessie_ilands",
                       "--output", POEM, "--price-xno", "0.05",
                       "--payee", PAYEE, "--seller-price-source", JESSIE,
                       "--refund-window-hours", "72")
        self.assertEqual(done.returncode, 64, done.stderr)
        self.assertIn("buyer-account", done.stderr)

    # -- 3 ------------------------------------------------------------------
    def test_3_a_buyer_account_one_character_off_is_refused(self):
        """B1, and the refusal names the checksum that key really implies."""
        with self.assertRaises(buy_first.Refusal) as caught:
            proposed(buyer_account=mutate(BUYER))
        self.assertEqual(caught.exception.code, "buyer_account_checksum_failed")
        self.assertIn("the checksum is", caught.exception.detail)

    # -- 4 ------------------------------------------------------------------
    def test_4_the_eddie_researcher_case_on_the_payee(self):
        """B2. An unpayable buy must be impossible to write.

        The corpus address itself is not stored in this repository, and the
        failure mode is the shape rather than the characters, so it is
        reproduced the way `tests/test_quotelock.py` and
        `tests/test_external_edge_count.py` already reproduce it: a valid
        address with one character changed.
        """
        with self.assertRaises(buy_first.Refusal) as caught:
            proposed(payee=mutate(PAYEE))
        self.assertEqual(caught.exception.code, "payee_checksum_failed")
        self.assertIn("the checksum is", caught.exception.detail)

    # -- 5 ------------------------------------------------------------------
    def test_5_the_payee_cannot_be_the_buyer(self):
        """B3. Paying ourselves is not demand, however it is spelled."""
        with self.assertRaises(buy_first.Refusal) as caught:
            proposed(payee=BUYER)
        self.assertEqual(caught.exception.code, "payee_equals_buyer")

        # The legacy spelling of one account is the same account.
        legacy = "xrb_" + BUYER.split("_", 1)[1]
        with self.assertRaises(buy_first.Refusal) as caught:
            proposed(payee=legacy)
        self.assertEqual(caught.exception.code, "payee_equals_buyer")

    # -- 6 ------------------------------------------------------------------
    def test_6_a_declared_operator_account_is_refused_as_payee(self):
        """B3. The exclusion happens before settlement, not after it."""
        with self.assertRaises(buy_first.Refusal) as caught:
            buy_first.propose(buy_first.empty_buys(), now=NOW,
                              operator_accounts=[PAYEE], **good())
        self.assertEqual(caught.exception.code, "seller_is_operator")

        # Declared in the legacy spelling, paid in the modern one: still ours.
        legacy = "xrb_" + PAYEE.split("_", 1)[1]
        with self.assertRaises(buy_first.Refusal) as caught:
            buy_first.propose(buy_first.empty_buys(), now=NOW,
                              operator_accounts=[legacy], **good())
        self.assertEqual(caught.exception.code, "seller_is_operator")

    # -- 7 ------------------------------------------------------------------
    def test_7_a_vague_output_is_refused_by_name(self):
        """B4, and the list is seller_offer's, not a second copy of it."""
        for vague in seller_offer.VAGUE_OUTPUTS:
            with self.assertRaises(buy_first.Refusal) as caught:
                proposed(output=vague)
            self.assertEqual(caught.exception.code, "output_too_vague", vague)
        self.assertIs(buy_first.VAGUE_OUTPUTS, seller_offer.VAGUE_OUTPUTS)

        with self.assertRaises(buy_first.Refusal) as caught:
            proposed(output="x" * 23)
        self.assertEqual(caught.exception.code, "output_too_vague")
        _, row = proposed(output="x" * 24)
        self.assertEqual(row["output"], "x" * 24)

    # -- 8 ------------------------------------------------------------------
    def test_8_no_seller_published_price_is_refused(self):
        """B5. A buy with no seller price is a job posting in disguise."""
        for absent in (None, "", "their price", "x" * 23):
            with self.assertRaises(buy_first.Refusal) as caught:
                proposed(seller_price_source=absent)
            self.assertEqual(caught.exception.code, "price_source_missing",
                             repr(absent))
        _, row = proposed(seller_price_source="x" * 24)
        self.assertEqual(row["seller_price_source"], "x" * 24)

    # -- 9 ------------------------------------------------------------------
    def test_9_the_amount_carries_the_order_recomputed_without_the_module(self):
        """B6. A seller recomputes which order a block paid for, alone.

        Deliberately written with `hashlib` and `json` only: no import of
        `buy_first` and no call into it. This is the no-code-verify rule, and
        the whole point of publishing the recipe in the feed.
        """
        _, row = proposed()
        scope = hashlib.blake2b(
            json.dumps({"by": row["deliver_by"], "output": row["output"],
                        "price_xno": row["price_xno"], "seller": row["seller"]},
                       sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False).encode("utf-8"),
            digest_size=32).hexdigest()
        self.assertEqual(scope, "".join(row["scope_digest_halves"]))

        order = hashlib.blake2b(bytes.fromhex(scope)
                                + row["order_key"].encode("utf-8"),
                                digest_size=32).hexdigest()
        self.assertEqual(order, "".join(row["order_digest_halves"]))

        tag = 1 + (int(hashlib.blake2b(b"order-bound-amount-v1:"
                                      + bytes.fromhex(order),
                                      digest_size=32).hexdigest(), 16)
                   % (10 ** 6 - 1))
        self.assertEqual(int(row["amount_to_send_raw"]),
                         int(row["price_raw"]) + tag)
        self.assertNotEqual(row["amount_to_send_raw"], row["price_raw"])
        self.assertTrue(row["amount_carries_order"])

    # -- 10 -----------------------------------------------------------------
    def test_10_no_standalone_64_hex_run_reaches_a_committed_file(self):
        """B7. The secret gate is not weakened so a feed can print a digest."""
        document, row = proposed()
        document, _ = buy_first.pay(document, row["id"], "AB" * 32, now=NOW)
        document, _ = buy_first.delivered(
            document, row["id"], "https://example.invalid/poem.mp3",
            "cd" * 32, now=NOW)
        published = buy_first.feed(document, now=NOW)
        for label, payload in (("buys.json", document),
                               ("feed/buys.json", published)):
            text = buy_first.serialise(payload).decode("utf-8")
            hit = _standalone_64_hex(text)
            self.assertIsNone(hit, "%s carries %r" % (label, hit))

        # And the halves really do join back to the digest.
        stored = document["buys"][0]
        self.assertEqual(len("".join(stored["scope_digest_halves"])), 64)
        self.assertEqual("".join(stored["artifact_sha256_halves"]), "cd" * 32)
        self.assertEqual("".join(stored["block_halves"]), "AB" * 32)

    # -- 11 -----------------------------------------------------------------
    def test_11_the_refund_window_is_bounded(self):
        """B8. 1 and 720 pass; 0 and 721 are refused."""
        for bad in (0, 721, -1, "x"):
            with self.assertRaises(buy_first.Refusal) as caught:
                proposed(refund_window_hours=bad)
            self.assertEqual(caught.exception.code,
                             "refund_window_out_of_range", repr(bad))
        for ok in (1, 720, "72"):
            _, row = proposed(refund_window_hours=ok)
            self.assertEqual(row["refund_window_hours"], int(ok))

    # -- 12 -----------------------------------------------------------------
    def test_12_the_price_is_capped_and_exact(self):
        """B9. The float implementation fails here: 1 raw over 1 XNO."""
        with self.assertRaises(buy_first.Refusal) as caught:
            proposed(price_xno="1.000000000000000000000000000001")
        self.assertEqual(caught.exception.code, "price_above_cap")

        _, row = proposed(price_xno="1")
        self.assertEqual(row["price_raw"], "1" + "0" * 30)

        for refused in ("0", "-0.05", "", "nan", "1e-3", None):
            with self.assertRaises(buy_first.Refusal) as caught:
                proposed(price_xno=refused)
            self.assertIn(caught.exception.code, ("bad_price", "price_above_cap"),
                          repr(refused))

    # -- 13 -----------------------------------------------------------------
    def test_13_buy_ids_are_the_lowest_unused_index_for_the_date(self):
        """B10. The second propose on one date does not overwrite the first."""
        document, first = proposed()
        document, second = buy_first.propose(document, now=NOW,
                                             **good(payee=OTHER))
        self.assertEqual(first["id"], "buy-2026-10-09-001")
        self.assertEqual(second["id"], "buy-2026-10-09-002")
        self.assertEqual([row["id"] for row in document["buys"]],
                         ["buy-2026-10-09-001", "buy-2026-10-09-002"])
        self.assertEqual(document["buys"][0]["payee"], PAYEE)

        # The order key is the buy id, so two buys for one scope derive two
        # different payable amounts and cannot be confused on the ledger.
        self.assertNotEqual(first["order_digest_halves"],
                            second["order_digest_halves"])

    def test_13b_a_full_id_space_is_a_state_error_not_a_wrap(self):
        """B10. Index 1000 refuses, and the exit code is 3, not 2."""
        document = buy_first.empty_buys()
        document["buys"] = [
            {"id": "buy-2026-10-09-%03d" % index, "state": "closed"}
            for index in range(1, buy_first.MAX_BUYS_PER_DATE)]
        with self.assertRaises(buy_first.Refusal) as caught:
            buy_first.next_buy_id(document, NOW)
        self.assertEqual(caught.exception.code, "buy_id_space_exhausted")
        self.assertEqual(caught.exception.exit_code, 3)


class Pay(unittest.TestCase):
    # -- 14 -----------------------------------------------------------------
    def test_14_one_block_per_buy(self):
        """B13. No new send while a send may exist, on the buyer side."""
        document, row = proposed()
        document, paid = buy_first.pay(document, row["id"], "AB" * 32, now=NOW)
        self.assertEqual(paid["state"], "paid")
        self.assertEqual(paid["block_halves"], ["AB" * 16, "AB" * 16])
        self.assertEqual(paid["amount_sent_raw"], row["amount_to_send_raw"])
        self.assertEqual(paid["paid_at"], NOW)
        self.assertIn("block_info on any public Nano node with that hash",
                      paid["verify_without_us"])

        with self.assertRaises(buy_first.Refusal) as caught:
            buy_first.pay(json.loads(json.dumps(document)), row["id"],
                          "CD" * 32, now=NOW)
        self.assertEqual(caught.exception.code, "already_paid")
        self.assertIn("AB" * 16, caught.exception.detail)

        # The SAME block twice is the idempotent case, not a second payment:
        # that is `retry_safety`'s rule, and a crashed operator re-running the
        # same command must not be told it already paid when it has not.
        again, same = buy_first.pay(json.loads(json.dumps(document)),
                                    row["id"], "ab" * 32, now=NOW)
        self.assertEqual(same["block_halves"], ["AB" * 16, "AB" * 16])
        self.assertEqual(len(again["buys"]), 1)

    def test_14b_the_idempotency_key_is_retry_safetys_own(self):
        """B13. The guard is reused, not re-implemented."""
        import retry_safety
        _, row = proposed()
        self.assertEqual(
            row["idempotency_key"],
            retry_safety.idempotency_key_for(
                "".join(row["order_digest_halves"]),
                row["amount_to_send_raw"], row["payee"]))
        self.assertTrue(row["idempotency_key"].startswith("ik-"))

    # -- 15 -----------------------------------------------------------------
    def test_15_a_malformed_block_hash_is_refused(self):
        """B12. 64 hex as a node returns it, or nothing."""
        document, row = proposed()
        for bad in ("ab" * 31, "g" + "a" * 63, "", None, "AB" * 33, " " * 64):
            with self.assertRaises(buy_first.Refusal) as caught:
                buy_first.pay(json.loads(json.dumps(document)), row["id"],
                              bad, now=NOW)
            self.assertEqual(caught.exception.code, "block_hash_malformed",
                             repr(bad))

    def test_15b_paying_a_buy_that_is_not_there(self):
        document, _ = proposed()
        with self.assertRaises(buy_first.Refusal) as caught:
            buy_first.pay(document, "buy-nope", "AB" * 32, now=NOW)
        self.assertEqual(caught.exception.code, "no_such_buy")


class DeliverAndClose(unittest.TestCase):
    # -- 16 -----------------------------------------------------------------
    def test_16_delivery_before_payment_is_refused(self):
        """B14. We pay first, so there is nothing to deliver into yet."""
        document, row = proposed()
        with self.assertRaises(buy_first.Refusal) as caught:
            buy_first.delivered(document, row["id"],
                                "https://example.invalid/poem.mp3",
                                "cd" * 32, now=NOW)
        self.assertEqual(caught.exception.code,
                         "not_deliverable_from_state_proposed")

    def test_16b_delivery_records_what_arrived_and_judges_nothing(self):
        """`delivered` must not express an opinion about usefulness."""
        document, row = proposed()
        document, _ = buy_first.pay(document, row["id"], "AB" * 32, now=NOW)
        document, got = buy_first.delivered(
            document, row["id"], "https://example.invalid/poem.mp3",
            "CD" * 32, now=NOW)
        self.assertEqual(got["state"], "delivered")
        self.assertEqual("".join(got["artifact_sha256_halves"]), "cd" * 32)
        self.assertEqual(got["artifact_url"], "https://example.invalid/poem.mp3")
        # No verdict about quality anywhere in the record.
        for field in buy_first.BUY_FIELDS:
            self.assertNotIn(field, ("accepted", "useful", "quality"))

        for bad in ("cd" * 31, "zz" * 32, None):
            with self.assertRaises(buy_first.Refusal) as caught:
                buy_first.delivered(json.loads(json.dumps(document)),
                                    row["id"], "https://example.invalid/x",
                                    bad, now=NOW)
            self.assertEqual(caught.exception.code, "artifact_digest_malformed",
                             repr(bad))

    # -- 17 -----------------------------------------------------------------
    def test_17_cannot_close_delivered_without_a_delivery(self):
        """B15. The favourable outcome is not available by assertion."""
        document, row = proposed()
        document, _ = buy_first.pay(document, row["id"], "AB" * 32, now=NOW)
        with self.assertRaises(buy_first.Refusal) as caught:
            buy_first.close(json.loads(json.dumps(document)), row["id"],
                            "delivered", now=NOW)
        self.assertEqual(caught.exception.code,
                         "cannot_close_delivered_without_delivery")

    def test_17b_a_closed_buy_is_not_reopened(self):
        """B16."""
        document, row = proposed()
        document, _ = buy_first.pay(document, row["id"], "AB" * 32, now=NOW)
        document, _ = buy_first.close(document, row["id"], "not_delivered",
                                      now=NOW)
        for outcome in buy_first.OUTCOMES:
            with self.assertRaises(buy_first.Refusal) as caught:
                buy_first.close(json.loads(json.dumps(document)), row["id"],
                                outcome, now=NOW)
            self.assertEqual(caught.exception.code, "already_closed")
        # An outcome that is not an outcome is refused BEFORE the state is
        # consulted, and that order is deliberate: "there is no such outcome"
        # is true whatever state the buy is in, and answering `already_closed`
        # would send a caller to fix the wrong half of its command.
        with self.assertRaises(buy_first.Refusal) as caught:
            buy_first.close(document, row["id"], "lost_interest", now=NOW)
        self.assertEqual(caught.exception.code, "bad_outcome")

    def test_17c_an_unknown_outcome_is_refused(self):
        document, row = proposed()
        with self.assertRaises(buy_first.Refusal) as caught:
            buy_first.close(document, row["id"], "mostly_fine", now=NOW)
        self.assertEqual(caught.exception.code, "bad_outcome")


class Feed(unittest.TestCase):
    # -- 18 -----------------------------------------------------------------
    def test_18_the_unfavourable_path_stays_published(self):
        """B19. A buyer that only publishes its wins proves nothing."""
        document, row = proposed()
        document, _ = buy_first.pay(document, row["id"], "AB" * 32, now=NOW)
        document, closed = buy_first.close(document, row["id"],
                                           "not_delivered", now=NOW)
        self.assertTrue(closed["published_even_though_unfavourable"])

        published = buy_first.feed(document, now=NOW)
        self.assertEqual(published["not_delivered_count"], 1)
        self.assertEqual(published["paid_before_delivery_count"], 1)
        self.assertEqual(len(published["closed_buys"]), 1)
        self.assertEqual(published["closed_buys"][0]["outcome"],
                         "not_delivered")
        self.assertEqual(published["open_buys"], [])
        # The money is published as having left, because it did.
        self.assertEqual(published["paid_xno_total"][:4], "0.05")
        self.assertEqual(published["sellers_paid"], 1)

    def test_18b_every_mandatory_key_is_present_at_zero(self):
        """B19. `not_delivered_count` is never omitted or folded away."""
        published = buy_first.feed(buy_first.empty_buys(), now=NOW)
        for key in ("not_delivered_count", "paid_before_delivery_count",
                    "sellers_paid", "distinct_sellers_paid", "paid_xno_total",
                    "open_buys", "closed_buys", "we_are_the_buyer",
                    "moves_first", "feed_url", "how_to_be_paid", "notes",
                    "check_without_us"):
            self.assertIn(key, published)
        self.assertEqual(published["not_delivered_count"], 0)
        self.assertEqual(published["paid_xno_total"], "0")
        self.assertTrue(published["we_are_the_buyer"])
        self.assertEqual(published["moves_first"], "buyer")

    # -- 19 -----------------------------------------------------------------
    def test_19_the_feed_is_deterministic_for_a_fixed_now(self):
        """B17. Same input, byte-identical artifact."""
        document, row = proposed()
        document, _ = buy_first.pay(document, row["id"], "AB" * 32, now=NOW)
        first = buy_first.serialise(buy_first.feed(document, now=NOW))
        second = buy_first.serialise(buy_first.feed(
            json.loads(json.dumps(document)), now=NOW))
        self.assertEqual(first, second)
        self.assertTrue(first.endswith(b"\n"))

    # -- 20 -----------------------------------------------------------------
    def test_20_one_account_in_two_spellings_counts_once(self):
        """B18. Decoded to public keys first, never counted as text.

        The legacy row is written directly rather than through `propose`,
        because `propose` canonicalises on write: the counter has to hold on
        its own, for a row something else wrote.
        """
        document, row = proposed()
        document, _ = buy_first.pay(document, row["id"], "AB" * 32, now=NOW)
        legacy = dict(document["buys"][0])
        legacy["id"] = "buy-2026-10-09-002"
        legacy["payee"] = "xrb_" + PAYEE.split("_", 1)[1]
        document["buys"].append(legacy)

        published = buy_first.feed(document, now=NOW)
        self.assertEqual(published["paid_before_delivery_count"], 2)
        self.assertEqual(published["distinct_sellers_paid"], 1)
        self.assertEqual(published["sellers_paid"], 1)

        # Two genuinely different sellers do count twice.
        document, second = buy_first.propose(document, now=NOW,
                                             **good(payee=OTHER))
        document, _ = buy_first.pay(document, second["id"], "CD" * 32, now=NOW)
        self.assertEqual(buy_first.feed(document, now=NOW)["distinct_sellers_paid"], 2)

    # -- 21 -----------------------------------------------------------------
    def test_21_the_empty_feed_is_honest_not_absent(self):
        """B21. Thirteen days of `buyer_account: null` with no reason why."""
        published = buy_first.feed(buy_first.empty_buys(), now=NOW)
        self.assertIsNone(published["buyer_account"])
        self.assertFalse(published["buyer_account_declared"])
        self.assertIn("buyer_account_undeclared_note", published)
        self.assertIn("--buyer-account",
                      published["buyer_account_undeclared_note"])

        document, _ = proposed()
        with_buy = buy_first.feed(document, now=NOW)
        self.assertEqual(with_buy["buyer_account"], BUYER)
        self.assertTrue(with_buy["buyer_account_declared"])
        self.assertNotIn("buyer_account_undeclared_note", with_buy)

    def test_21b_the_feed_publishes_the_recipes_it_asks_to_be_checked_by(self):
        """`check_without_us` is only true if the recipes are there."""
        document, _ = proposed()
        published = buy_first.feed(document, now=NOW)
        for key in ("scope_digest", "order_digest", "amount_to_send_raw"):
            self.assertIn(key, published["recipes"])
        self.assertIn("blake2b-256", published["recipes"]["scope_digest"])
        self.assertIn("bytes.fromhex", published["recipes"]["order_digest"])


class Discipline(unittest.TestCase):
    # -- 22 -----------------------------------------------------------------
    def test_22_the_self_test_refuses_at_least_twelve_times(self):
        verdict = buy_first.self_test()
        self.assertEqual(verdict["failures"], [])
        self.assertGreaterEqual(verdict["negative_controls"], 12)

    # -- 23 -----------------------------------------------------------------
    def test_23_nothing_here_can_open_a_socket(self):
        """No network in any code path, asserted over the import graph."""
        reached = {entry["module"].split(".")[0]
                   for entry in buy_first.import_graph()}
        for module in ("socket", "http", "urllib", "ssl", "requests",
                       "asyncio", "ftplib", "telnetlib", "smtplib"):
            self.assertNotIn(module, reached)
        with open(os.path.join(ROOT, "buy_first.py"), encoding="utf-8") as handle:
            source = handle.read()
        for name in ("http.client", "urllib.request", "socket(", "ssl."):
            self.assertNotIn(name, source)

    def test_24_no_field_of_the_record_is_withheld_from_the_feed(self):
        """A feed that publishes a subset can publish a flattering subset."""
        document, row = proposed()
        document, _ = buy_first.pay(document, row["id"], "AB" * 32, now=NOW)
        published = buy_first.feed(document, now=NOW)
        self.assertEqual(set(published["open_buys"][0]),
                         set(buy_first.BUY_FIELDS))

    def test_25_every_refusal_code_is_declared(self):
        """A code not in REASON_CODES raises AssertionError at construction."""
        with self.assertRaises(AssertionError):
            buy_first.Refusal("invented_code", "nope")
        for state in buy_first.STATES:
            for verb in ("not_payable", "not_deliverable"):
                self.assertIn("%s_from_state_%s" % (verb, state),
                              buy_first.REASON_CODES)

    def test_26_the_immutable_fields_are_a_subset_of_the_record(self):
        for field in buy_first.IMMUTABLE_FIELDS:
            self.assertIn(field, buy_first.BUY_FIELDS)


class Cli(unittest.TestCase):
    def test_27_the_whole_path_through_the_command_line(self):
        """propose -> pay -> delivered -> close, and the artifact it writes."""
        with tempfile.TemporaryDirectory() as tmp:
            done = cli(tmp, "propose", "--seller", "jessie_ilands",
                       "--output", POEM, "--price-xno", "0.05",
                       "--payee", PAYEE, "--buyer-account", BUYER,
                       "--seller-price-source", JESSIE,
                       "--refund-window-hours", "72")
            self.assertEqual(done.returncode, 0, done.stderr)
            row = json.loads(done.stdout)
            self.assertEqual(row["state"], "proposed")

            done = cli(tmp, "pay", "--buy-id", row["id"], "--block", "AB" * 32)
            self.assertEqual(done.returncode, 0, done.stderr)
            self.assertEqual(json.loads(done.stdout)["state"], "paid")

            done = cli(tmp, "delivered", "--buy-id", row["id"],
                       "--artifact-url", "https://example.invalid/poem.mp3",
                       "--artifact-sha256", "cd" * 32)
            self.assertEqual(done.returncode, 0, done.stderr)

            done = cli(tmp, "close", "--buy-id", row["id"],
                       "--outcome", "delivered")
            self.assertEqual(done.returncode, 0, done.stderr)

            with open(os.path.join(tmp, "feed", "buys.json")) as handle:
                published = json.load(handle)
            self.assertEqual(published["not_delivered_count"], 0)
            self.assertEqual(published["sellers_paid"], 1)
            self.assertEqual(len(published["closed_buys"]), 1)

    def test_28_the_exit_codes_are_the_four_the_spec_names(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = ["propose", "--seller", "jessie_ilands", "--output", POEM,
                    "--price-xno", "0.05", "--payee", PAYEE,
                    "--seller-price-source", JESSIE,
                    "--refund-window-hours", "72"]
            # 64: the buyer account is missing.
            self.assertEqual(cli(tmp, *base).returncode, 64)
            # 2: the buyer account is there and is not real.
            done = cli(tmp, *(base + ["--buyer-account", mutate(BUYER)]))
            self.assertEqual(done.returncode, 2)
            self.assertIn("reason=buyer_account_checksum_failed", done.stderr)
            # 2: no seller-published price is a refusal, not a usage error.
            done = cli(tmp, "propose", "--seller", "jessie_ilands",
                       "--output", POEM, "--price-xno", "0.05",
                       "--payee", PAYEE, "--buyer-account", BUYER,
                       "--refund-window-hours", "72")
            self.assertEqual(done.returncode, 2)
            self.assertIn("reason=price_source_missing", done.stderr)
            # 0: and nothing was written by any of the refusals above.
            self.assertFalse(os.path.exists(os.path.join(tmp, "buys.json")))

    def test_29_the_self_test_runs_with_no_arguments_and_no_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            done = subprocess.run(
                [sys.executable, os.path.join(ROOT, "buy_first.py"),
                 "--self-test"], cwd=tmp, capture_output=True, text=True)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout)["failures"], [])


def cli(cwd, *argv):
    return subprocess.run(
        [sys.executable, os.path.join(ROOT, "buy_first.py"), *argv,
         "--buys", os.path.join(cwd, "buys.json"),
         "--out", os.path.join(cwd, "feed", "buys.json"),
         "--now", NOW],
        capture_output=True, text=True)


def _standalone_64_hex(text):
    """The first standalone run of 64 lowercase hex characters, or None.

    Assembled at runtime rather than written as a literal: a 64-hex pattern in
    a committed test file is the very thing `validate.scan_for_secrets` refuses.
    """
    import re
    pattern = "(?<![0-9a-fA-F])[0-9a-f]{%d}(?![0-9a-fA-F])" % 64
    found = re.search(pattern, text)
    return found.group(0) if found else None


if __name__ == "__main__":
    unittest.main()
