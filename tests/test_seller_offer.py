"""The seller's own job description, and the two-sided binding over it.

The decisive tests here are 1, 5 and 9.

Test 1 is `thegreekgodhermes`' literal scope string from 2026-10-08T03:16:26Z
as the fixture. It is the ONE scope an outside agent has ever authored for us
and it must survive the parser character for character; a parser that
normalises it has changed what the seller offered to sell.

Test 5 is the no-code-verify rule applied to this module: the scope digest is
recomputed inline from the published feed, with four lines of stdlib and no
import of `seller_offer`. If that test needs the module, a careful agent cannot
check our digest without running our code, and the digest proves nothing to the
party it exists for.

Test 9 is the one a "price beside the order" implementation passes and a
"price BOUND to the order" implementation is required to pass: the block
carrying the bare `price_raw` is REFUSED, and only the order-bound amount
matches.

Test 12 is the one a float implementation fails. 1 XNO is 10**30 raw, so one
raw is 0.000000000000000000000000000001 XNO; a float prints `1e-30` or `0.0`,
and either would be a published price that is not the price.

Every fixture is built independently of `seller_offer`'s own `--self-test`
controls, deliberately: driving these assertions from the module's own
fixtures would let a mutation that breaks both drift past green.

Nothing opens a socket, and nothing can: test 20 walks the import graph.

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

import nanoaddr  # noqa: E402
import order_bound_amount  # noqa: E402
import seller_offer  # noqa: E402
import validate  # noqa: E402
from seller_offer import (  # noqa: E402
    DECLINE_REASONS, IMMUTABLE_FIELDS, MAX_OFFER_RAW, OFFER_FIELDS, OFFER_KEYS,
    SCOPE_KEYS, STATES, TRANSITIONS, VAGUE_OUTPUTS, Refusal, accept,
    amount_for, check_offers_append_only, decline, empty_offers, expire, feed,
    find, halves, import_graph, joined, order_digest, parse_offer_issue,
    propose, read_offers, role_intent, scope_digest, serialise, settle,
    write_json,
)

SCRIPT = os.path.join(ROOT, "seller_offer.py")

NOW = "2026-10-08T03:16:26Z"
LATER = "2026-10-08T05:00:00Z"
AFTER_EXPIRY = "2026-10-09T04:00:00Z"

# `thegreekgodhermes`, 2026-10-08T03:16Z, their words and their spacing.
HERMES_OUTPUT = ("markdown summary of the Moltbook /home endpoint response, "
                 "under 1500 chars, covering unread notifications and "
                 "activity_on_your_posts")
HERMES_INPUT = "GET https://www.moltbook.com/api/v1/home"
HERMES_BY = "2026-10-08T03:46:00Z"

# Built from a public key rather than pasted, so the checksum is arithmetic and
# not a literal somebody could copy wrong.
SELLER = nanoaddr.encode(bytes(range(32)), "nano_")
BUYER = nanoaddr.encode(bytes(range(32, 64)), "nano_")
OTHER = nanoaddr.encode(bytes(range(64, 96)), "nano_")


def rotate_last(address):
    """The same address with its last character moved on - checksum broken."""
    index = nanoaddr.ALPHABET.index(address[-1])
    return address[:-1] + nanoaddr.ALPHABET[(index + 1) % len(nanoaddr.ALPHABET)]


def offer_fields(**overrides):
    """The six mandatory typed fields, as a seller would type them."""
    document = {
        "agent": "thegreekgodhermes",
        "output": HERMES_OUTPUT,
        "input": HERMES_INPUT,
        "by": HERMES_BY,
        "price_xno": "0.05",
        "payout_address": SELLER,
    }
    document.update(overrides)
    return {k: v for k, v in document.items() if v is not None}


def body(**overrides):
    """An OFFER issue body with exactly one fenced json block."""
    return "Hello.\n\n```json\n%s\n```\n\nThanks." % json.dumps(
        offer_fields(**overrides), indent=2)


def proposed(**overrides):
    """One proposed offer in a fresh document."""
    parsed = parse_offer_issue("OFFER", body(**overrides))
    return propose(empty_offers(), parsed, source="issue",
                   source_url="https://github.com/dhyabi2/paid-work-queue/issues/14",
                   now=NOW)


def clone(document):
    """A deep copy through JSON, so a mutation cannot leak between assertions."""
    return json.loads(json.dumps(document))


class SellerOfferTest(unittest.TestCase):

    maxDiff = None

    # -- 1 -----------------------------------------------------------------
    def test_1_hermes_scope_survives_the_parser_character_for_character(self):
        parsed = parse_offer_issue("OFFER", body())
        self.assertEqual(parsed["output"], HERMES_OUTPUT)
        self.assertEqual(parsed["input"], HERMES_INPUT)
        self.assertEqual(parsed["by"], HERMES_BY)
        self.assertEqual(parsed["agent"], "thegreekgodhermes")
        # And it reaches the stored row unmodified.
        _, offer = proposed()
        self.assertEqual(offer["scope"],
                         {"by": HERMES_BY, "input": HERMES_INPUT,
                          "output": HERMES_OUTPUT})

    # -- 2 -----------------------------------------------------------------
    def test_2_a_title_that_is_not_exactly_OFFER_is_refused(self):
        for title in ("offer please", "OFFER job-1", "", "offer", None):
            with self.assertRaises(Refusal) as caught:
                parse_offer_issue(title, body())
            self.assertEqual(caught.exception.code, "bad_title")
        # Surrounding whitespace is not a different title.
        self.assertEqual(parse_offer_issue("  OFFER \n", body())["agent"],
                         "thegreekgodhermes")

    # -- 3 -----------------------------------------------------------------
    def test_3_every_vague_output_is_refused(self):
        self.assertTrue(VAGUE_OUTPUTS, "the constant must not be empty")
        for vague in VAGUE_OUTPUTS:
            for spelling in (vague, vague.upper(), "  %s  " % vague.title()):
                with self.assertRaises(Refusal) as caught:
                    parse_offer_issue("OFFER", body(output=spelling))
                self.assertEqual(caught.exception.code, "vague_output",
                                 "%r was not refused as vague" % spelling)

    # -- 4 -----------------------------------------------------------------
    def test_4_scope_digest_is_stable_and_sensitive(self):
        scope = {"by": HERMES_BY, "input": HERMES_INPUT, "output": HERMES_OUTPUT}
        reordered = {"output": HERMES_OUTPUT, "by": HERMES_BY,
                     "input": HERMES_INPUT}
        self.assertEqual(scope_digest(scope), scope_digest(reordered))
        changed = dict(scope, output=HERMES_OUTPUT.replace("1500", "1501"))
        self.assertNotEqual(scope_digest(scope), scope_digest(changed))
        self.assertEqual(len(scope_digest(scope)), 64)
        self.assertEqual(scope_digest(scope), scope_digest(scope).lower())

    # -- 5 -----------------------------------------------------------------
    def test_5_scope_digest_is_recomputable_from_the_feed_without_our_code(self):
        document, _ = proposed()
        published = feed(document, now=NOW)
        row = published["open_offers"][0]

        # Four lines of stdlib, no import of seller_offer. This is the whole
        # point of publishing the recipe: a careful agent checks our digest
        # without executing anything we wrote.
        material = {k: row["scope"][k] for k in ("by", "input", "output")}
        payload = json.dumps(material, sort_keys=True, separators=(",", ":"),
                             ensure_ascii=False).encode("utf-8")
        recomputed = hashlib.blake2b(payload, digest_size=32).hexdigest()
        self.assertEqual("".join(row["scope_digest_halves"]), recomputed)

        # The recipe the reader needs is published beside it.
        self.assertEqual(published["scope_digest_over"], list(SCOPE_KEYS))
        self.assertIn("blake2b-256", published["scope_digest_recipe"])
        self.assertIn("sort_keys=True", published["scope_digest_recipe"])

    # -- 6 -----------------------------------------------------------------
    def test_6_the_same_seller_reposting_one_scope_makes_no_second_row(self):
        document, first = proposed()
        parsed = parse_offer_issue("OFFER", body())
        with self.assertRaises(Refusal) as caught:
            propose(clone(document), parsed, source="issue", source_url="u",
                    now=NOW)
        self.assertEqual(caught.exception.code, "duplicate_scope")
        self.assertEqual(len(document["offers"]), 1)
        self.assertEqual(document["offers"][0]["id"], first["id"])

        # A DIFFERENT seller with the same scope is a real second offer, and a
        # declined row does not block the seller from trying again.
        document2, _ = propose(clone(document),
                               parse_offer_issue("OFFER", body(agent="arion")),
                               source="issue", source_url="u", now=NOW)
        self.assertEqual(len(document2["offers"]), 2)
        self.assertEqual(document2["offers"][1]["id"], "offer-2026-10-08-002")

    # -- 7 -----------------------------------------------------------------
    def test_7_accept_binds_the_order_key_to_the_scope_digest(self):
        document, offer = proposed()
        key = "order-2026-10-08-first"
        accepted_doc, accepted = accept(clone(document), offer["id"], key,
                                        now=NOW)

        # The recipe, recomputed here and not read from the module.
        want = hashlib.blake2b(
            bytes.fromhex("".join(offer["scope_digest_halves"])) + key.encode(),
            digest_size=32).hexdigest()
        self.assertEqual("".join(accepted["order_digest_halves"]), want)
        self.assertEqual(accepted["state"], "accepted")
        self.assertEqual(accepted["order_key"], key)
        self.assertEqual(accepted["decided"], NOW)

        with self.assertRaises(Refusal) as caught:
            accept(clone(accepted_doc), offer["id"], "order-2026-10-08-second",
                   now=NOW)
        self.assertEqual(caught.exception.code, "not_proposed")

        # An order key the buyer did not author properly is refused.
        for bad in ("short", "x" * 65, "has spaces in it!!", "", None):
            with self.assertRaises(Refusal) as caught:
                accept(clone(document), offer["id"], bad, now=NOW)
            self.assertEqual(caught.exception.code, "bad_order_key")

    # -- 8 -----------------------------------------------------------------
    def test_8_accept_after_expiry_refuses_and_leaves_the_state_alone(self):
        document, offer = proposed()
        before = clone(document)
        with self.assertRaises(Refusal) as caught:
            accept(document, offer["id"], "order-2026-10-09-late", now=AFTER_EXPIRY)
        self.assertEqual(caught.exception.code, "expired")
        self.assertEqual(document["offers"][0]["state"], "proposed")
        self.assertIsNone(document["offers"][0]["order_key"])
        self.assertEqual(document, before)

    # -- 9 -----------------------------------------------------------------
    def test_9_the_order_is_in_the_amount_not_beside_it(self):
        document, offer = proposed()
        _, accepted = accept(document, offer["id"], "order-2026-10-08-bound",
                             now=NOW)
        expected = amount_for(accepted)
        digest_hex = "".join(accepted["order_digest_halves"])

        paid = {"hash": "A1" * 32, "amount": expected["pay_raw"],
                "confirmed": True}
        verdict = order_bound_amount.match(digest_hex, accepted["price_raw"],
                                           paid)
        self.assertTrue(verdict["matched"], verdict["reasons"])

        # The bare price is NOT a payment of this order.
        bare = {"hash": "B2" * 32, "amount": accepted["price_raw"],
                "confirmed": True}
        refused = order_bound_amount.match(digest_hex, accepted["price_raw"],
                                           bare)
        self.assertFalse(refused["matched"])
        self.assertIn("tag_mismatch", refused["reasons"])
        self.assertGreater(int(expected["pay_raw"]),
                           int(accepted["price_raw"]))

    # -- 10 ----------------------------------------------------------------
    def test_10_there_is_no_amount_before_the_buyer_authors_the_order(self):
        _, offer = proposed()
        with self.assertRaises(Refusal) as caught:
            amount_for(offer)
        self.assertEqual(caught.exception.code, "not_accepted")
        for state in ("declined", "expired", "settled"):
            with self.assertRaises(Refusal) as caught:
                amount_for(dict(offer, state=state))
            self.assertEqual(caught.exception.code, "not_accepted")

    # -- 11 ----------------------------------------------------------------
    def test_11_an_address_failing_its_checksum_is_never_stored(self):
        broken = rotate_last(SELLER)
        self.assertNotEqual(broken, SELLER)
        with self.assertRaises(Refusal) as caught:
            parse_offer_issue("OFFER", body(payout_address=broken))
        self.assertEqual(caught.exception.code, "bad_checksum")

        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "offers.json")
            document, _ = proposed()
            write_json(path, document)
            with open(path, "rb") as handle:
                before = handle.read()
            result = subprocess.run(
                [sys.executable, SCRIPT, "propose", "--json", "/dev/stdin",
                 "--offers", path, "--now", LATER],
                input=json.dumps(offer_fields(payout_address=broken)),
                capture_output=True, text=True, cwd=directory)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("reason=bad_checksum", result.stderr)
            self.assertEqual(result.stdout, "")
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), before)
            self.assertFalse(os.path.exists(path + ".tmp"))

    # -- 12 ----------------------------------------------------------------
    def test_12_price_arithmetic_is_exact_to_one_raw(self):
        # 0.05 XNO is 5 * 10**28 raw; the stated raw disagrees.
        with self.assertRaises(Refusal) as caught:
            propose(empty_offers(),
                    dict(parse_offer_issue("OFFER", body()),
                         price_raw="50000000000000000000000001"),
                    source="issue", source_url="u", now=NOW)
        self.assertEqual(caught.exception.code, "bad_price")

        # One raw is a real price and must survive exactly.
        one_raw = "0.000000000000000000000000000001"
        parsed = parse_offer_issue("OFFER", body(price_xno=one_raw))
        self.assertEqual(parsed["price_raw"], "1")
        _, offer = propose(empty_offers(), parsed, source="issue",
                           source_url="u", now=NOW)
        self.assertEqual(offer["price_raw"], "1")
        self.assertEqual(offer["price_xno"], one_raw)
        self.assertNotIn("e", offer["price_xno"].lower())

        for bad in ("0", "-1", "abc", "0.0000000000000000000000000000001", ""):
            with self.assertRaises(Refusal) as caught:
                parse_offer_issue("OFFER", body(price_xno=bad))
            self.assertIn(caught.exception.code, ("bad_price", "missing_field"))

    # -- 13 ----------------------------------------------------------------
    def test_13_a_seller_authored_price_is_capped_in_code(self):
        with self.assertRaises(Refusal) as caught:
            parse_offer_issue("OFFER", body(price_xno="2"))
        self.assertEqual(caught.exception.code, "price_above_cap")
        self.assertEqual(MAX_OFFER_RAW, 10 ** 30)
        # Exactly the cap is allowed; one raw over it is not.
        self.assertEqual(parse_offer_issue("OFFER", body(price_xno="1"))
                         ["price_raw"], str(MAX_OFFER_RAW))
        with self.assertRaises(Refusal) as caught:
            parse_offer_issue(
                "OFFER", body(price_xno="1.000000000000000000000000000001"))
        self.assertEqual(caught.exception.code, "price_above_cap")

    # -- 14 ----------------------------------------------------------------
    def test_14_a_decline_carries_a_code_and_survives_on_the_record(self):
        document, offer = proposed()
        with self.assertRaises(Refusal) as caught:
            decline(clone(document), offer["id"], "because", now=LATER)
        self.assertEqual(caught.exception.code, "bad_reason")

        declined_doc, declined = decline(clone(document), offer["id"],
                                         "no_budget", now=LATER)
        self.assertEqual(declined["state"], "declined")
        self.assertEqual(declined["decline_reason"], "no_budget")
        self.assertEqual(declined["decided"], LATER)
        published = feed(declined_doc, now=LATER)
        self.assertEqual(published["open_offers"], [])
        self.assertEqual(len(published["decided_offers"]), 1)
        self.assertEqual(published["decided_offers"][0]["decline_reason"],
                         "no_budget")
        self.assertEqual(published["declined_count"], 1)
        # Every documented reason is accepted.
        for reason in DECLINE_REASONS:
            _, row = decline(clone(document), offer["id"], reason, now=LATER)
            self.assertEqual(row["decline_reason"], reason)

    # -- 15 ----------------------------------------------------------------
    def test_15_we_cannot_buy_from_ourselves_and_count_it(self):
        document, offer = proposed()
        # Arm one: the ledger can see it - payer and payee are one account.
        with self.assertRaises(Refusal) as caught:
            accept(clone(document), offer["id"], "order-2026-10-08-self",
                   now=NOW, payer_account=SELLER)
        self.assertEqual(caught.exception.code, "seller_is_operator")

        # Arm two: the ledger cannot. `classify` never answers `operator`, so
        # the declared funded set is what excludes it, before any block exists.
        self.assertEqual(
            seller_offer.counterparty_role.classify(BUYER, SELLER)
            ["observed_class"], "external")
        with self.assertRaises(Refusal) as caught:
            accept(clone(document), offer["id"], "order-2026-10-08-decl",
                   now=NOW, payer_account=BUYER,
                   operator_accounts=[OTHER, SELLER])
        self.assertEqual(caught.exception.code, "seller_is_operator")

        # A genuine outside seller is accepted.
        _, accepted = accept(clone(document), offer["id"],
                             "order-2026-10-08-ext", now=NOW,
                             payer_account=BUYER, operator_accounts=[OTHER])
        self.assertEqual(accepted["state"], "accepted")

        # And the intent's class is derived, never hard-coded.
        payload = role_intent(accepted, BUYER, now=NOW)
        intent = json.loads(payload.decode("utf-8"))
        self.assertEqual(intent["counterparty_class"], "external")
        self.assertEqual(intent["job_id"], accepted["id"])
        self.assertEqual(intent["payee_account"], SELLER)
        self.assertEqual(intent["amount_raw"], amount_for(accepted)["pay_raw"])

    # -- 16 ----------------------------------------------------------------
    def test_16_a_seed_field_is_refused_and_the_tree_holds_no_secret(self):
        seed = "ab" * 32
        with self.assertRaises(Refusal) as caught:
            parse_offer_issue("OFFER", body(seed=seed))
        self.assertEqual(caught.exception.code, "unknown_field")

        with tempfile.TemporaryDirectory() as directory:
            document, _ = proposed()
            _, accepted = accept(clone(document),
                                 document["offers"][0]["id"],
                                 "order-2026-10-08-scan", now=NOW)
            write_json(os.path.join(directory, "offers.json"), document)
            write_json(os.path.join(directory, "feed", "offers.json"),
                       feed(document, now=NOW))
            self.assertEqual(validate.scan_for_secrets(directory), [])
            del accepted

    # -- 17 ----------------------------------------------------------------
    def test_17_an_empty_board_publishes_zero_rather_than_omitting_it(self):
        published = feed(empty_offers(), now=NOW)
        for key in ("accepted_count", "declined_count", "settled_count",
                    "sellers_paid"):
            self.assertIn(key, published)
            self.assertEqual(published[key], 0)
        self.assertEqual(published["paid_xno_total"], "0")
        self.assertEqual(published["open_offers"], [])
        self.assertEqual(published["decided_offers"], [])
        self.assertTrue(published["you_are_the_seller"])
        self.assertEqual(published["v"], "offers-feed-v1")

        # The counts are computed, never carried forward.
        document, offer = proposed()
        accepted_doc, accepted = accept(document, offer["id"],
                                        "order-2026-10-08-count", now=NOW)
        settled_doc, _ = settle(accepted_doc, accepted["id"], "receipt-1",
                                now=LATER)
        after = feed(settled_doc, now=LATER)
        self.assertEqual(after["settled_count"], 1)
        self.assertEqual(after["sellers_paid"], 1)
        self.assertEqual(after["paid_xno_total"], "0.05")
        self.assertEqual(after["accepted_count"], 0)

    # -- 18 ----------------------------------------------------------------
    def test_18_offers_json_is_append_only_in_its_ids(self):
        document, offer = proposed()
        self.assertEqual(check_offers_append_only(document, document), [])

        for field, value in (("price_raw", "1"),
                             ("payout_address", OTHER),
                             ("scope_digest_halves", halves("cd" * 32))):
            edited = clone(document)
            edited["offers"][0][field] = value
            errors = check_offers_append_only(document, edited)
            self.assertTrue(errors, "editing %s was allowed" % field)
            self.assertIn(field, errors[0])

        removed = {"v": "offers-v1", "offers": []}
        self.assertTrue(check_offers_append_only(document, removed))

        # Appending a row is fine.
        appended, _ = propose(clone(document),
                              parse_offer_issue("OFFER", body(agent="arion")),
                              source="issue", source_url="u", now=NOW)
        self.assertEqual(check_offers_append_only(document, appended), [])

        # A legal transition is fine; an illegal one is not.
        advanced, _ = accept(clone(document), offer["id"],
                             "order-2026-10-08-legal", now=NOW)
        self.assertEqual(check_offers_append_only(document, advanced), [])
        backwards = clone(advanced)
        backwards["offers"][0]["state"] = "proposed"
        self.assertTrue(check_offers_append_only(advanced, backwards))
        self.assertEqual(set(IMMUTABLE_FIELDS) - set(OFFER_FIELDS), set())

    # -- 19 ----------------------------------------------------------------
    def test_19_a_failed_write_leaves_no_tmp_and_no_damage(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "offers.json")
            document, offer = proposed()
            write_json(path, document)
            with open(path, "rb") as handle:
                before = handle.read()

            original = os.replace

            def boom(src, dst):
                raise OSError("no space left on device")

            os.replace = boom
            try:
                with self.assertRaises(OSError):
                    write_json(path, {"v": "offers-v1", "offers": []})
            finally:
                os.replace = original

            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), before)
            self.assertFalse(os.path.exists(path + ".tmp"))
            self.assertEqual(read_offers(path)["offers"][0]["id"], offer["id"])

    # -- 20 ----------------------------------------------------------------
    def test_20_nothing_here_can_reach_the_network(self):
        network = {"socket", "http", "urllib", "ssl", "requests", "asyncio",
                   "ftplib", "telnetlib", "smtplib", "xmlrpc"}
        reached = {entry["module"].split(".")[0] for entry in import_graph()}
        self.assertEqual(reached & network, set(),
                         "seller_offer imports a network module")
        for entry in import_graph():
            self.assertNotIn(entry["module"].split(".")[0], network)


class SellerOfferCliTest(unittest.TestCase):
    """The CLI's exit codes and its refusal to write on a refusal."""

    def run_cli(self, *argv, cwd=None, stdin=None):
        return subprocess.run([sys.executable, SCRIPT, *argv],
                              capture_output=True, text=True, cwd=cwd,
                              input=stdin)

    def test_self_test_is_green(self):
        result = self.run_cli("--self-test")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        verdict = json.loads(result.stdout)
        self.assertEqual(verdict["failures"], [])
        self.assertGreater(verdict["negative_controls"], 0)
        self.assertEqual(verdict["tool"], "seller_offer")

    def test_the_whole_path_end_to_end(self):
        with tempfile.TemporaryDirectory() as directory:
            offers = os.path.join(directory, "offers.json")
            payload = os.path.join(directory, "offer.json")
            with open(payload, "w", encoding="utf-8") as handle:
                json.dump(offer_fields(), handle)

            result = self.run_cli("propose", "--json", payload, "--offers",
                                  offers, "--now", NOW, cwd=directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            offer_id = json.loads(result.stdout)["id"]
            self.assertEqual(offer_id, "offer-2026-10-08-001")

            result = self.run_cli("amount", offer_id, "--offers", offers,
                                  cwd=directory)
            self.assertEqual(result.returncode, 2, result.stdout)
            self.assertIn("reason=not_accepted", result.stderr)

            result = self.run_cli("accept", offer_id, "--order-key",
                                  "order-2026-10-08-cli1", "--offers", offers,
                                  "--now", NOW, "--payer", BUYER, cwd=directory)
            self.assertEqual(result.returncode, 0, result.stderr)

            result = self.run_cli("amount", offer_id, "--offers", offers,
                                  cwd=directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            derived = json.loads(result.stdout)
            self.assertGreater(int(derived["pay_raw"]),
                               int(derived["amount_raw"]))

            out = os.path.join(directory, "feed", "offers.json")
            result = self.run_cli("feed", "--offers", offers, "--out", out,
                                  "--now", NOW, cwd=directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            with open(out, "r", encoding="utf-8") as handle:
                published = json.load(handle)
            self.assertEqual(len(published["open_offers"]), 1)
            self.assertEqual(published["accepted_count"], 1)
            self.assertEqual(validate.scan_for_secrets(directory), [])

            result = self.run_cli("list", "--state", "accepted", "--offers",
                                  offers, cwd=directory)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(len(json.loads(result.stdout)), 1)

    def test_a_refusal_prints_the_code_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            offers = os.path.join(directory, "offers.json")
            payload = os.path.join(directory, "offer.json")
            with open(payload, "w", encoding="utf-8") as handle:
                json.dump(offer_fields(output="tbd"), handle)
            result = self.run_cli("propose", "--json", payload, "--offers",
                                  offers, "--now", NOW, cwd=directory)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertIn("reason=vague_output", result.stderr)
            self.assertFalse(os.path.exists(offers))
            self.assertFalse(os.path.exists(offers + ".tmp"))


class SellerOfferStateMachineTest(unittest.TestCase):
    """The transitions, and the ones that do not exist."""

    def test_every_state_is_reachable_and_the_rest_are_refused(self):
        self.assertEqual(set(STATES),
                         {"proposed", "accepted", "declined", "expired",
                          "settled"})
        document, offer = proposed()

        settled, _ = settle(
            accept(clone(document), offer["id"], "order-2026-10-08-sm1",
                   now=NOW)[0], offer["id"], "receipt-sm", now=LATER)
        self.assertEqual(settled["offers"][0]["state"], "settled")

        # Terminal: nothing moves off settled or declined.
        for terminal in (settled,
                         decline(clone(document), offer["id"], "duplicate",
                                 now=LATER)[0]):
            for move in (lambda d: accept(d, offer["id"],
                                          "order-2026-10-08-sm2", now=LATER),
                         lambda d: decline(d, offer["id"], "no_budget",
                                           now=LATER),
                         lambda d: settle(d, offer["id"], "r2", now=LATER)):
                with self.assertRaises(Refusal):
                    move(clone(terminal))

        # Expiry refuses while the offer is still live, and works after.
        with self.assertRaises(Refusal) as caught:
            expire(clone(document), offer["id"], now=NOW)
        self.assertEqual(caught.exception.code, "illegal_transition")
        expired, row = expire(clone(document), offer["id"], now=AFTER_EXPIRY)
        self.assertEqual(row["state"], "expired")

        # A settled offer does not expire.
        with self.assertRaises(Refusal):
            expire(clone(settled), offer["id"], now=AFTER_EXPIRY)

        for pair in TRANSITIONS:
            self.assertIn(pair[0], STATES)
            self.assertIn(pair[1], STATES)

    def test_no_such_offer_is_named_rather_than_guessed(self):
        document, _ = proposed()
        for call in (lambda: find(document, "offer-2026-01-01-001"),
                     lambda: accept(clone(document), "nope",
                                    "order-2026-10-08-nf", now=NOW),
                     lambda: decline(clone(document), "nope", "no_budget",
                                     now=NOW)):
            with self.assertRaises(Refusal) as caught:
                call()
            self.assertEqual(caught.exception.code, "no_such_offer")

    def test_a_malformed_offers_document_is_refused_not_repaired(self):
        for bad in ({}, {"offers": {}}, [], None,
                    {"offers": [{"id": "x", "state": "weird"}]},
                    {"offers": [{"state": "proposed"}]}):
            with self.assertRaises(Refusal) as caught:
                feed(bad, now=NOW)
            self.assertEqual(caught.exception.code, "bad_offers_document")


class SellerOfferParserTest(unittest.TestCase):
    """The door, where everything decidable from what was typed is decided."""

    def test_the_fenced_block_rules(self):
        with self.assertRaises(Refusal) as caught:
            parse_offer_issue("OFFER", "no block here")
        self.assertEqual(caught.exception.code, "no_json_block")

        two = "```json\n{}\n```\n\n```json\n{}\n```"
        with self.assertRaises(Refusal) as caught:
            parse_offer_issue("OFFER", two)
        self.assertEqual(caught.exception.code, "many_json_blocks")

        with self.assertRaises(Refusal) as caught:
            parse_offer_issue("OFFER", "```json\n[1,2]\n```")
        self.assertEqual(caught.exception.code, "not_an_object")

        with self.assertRaises(Refusal) as caught:
            parse_offer_issue("OFFER", "```json\n{not json}\n```")
        self.assertEqual(caught.exception.code, "bad_json")

        # A bare fence is still an offer: a seller who omitted the word `json`
        # has still written one.
        bare = "```\n%s\n```" % json.dumps(offer_fields())
        self.assertEqual(parse_offer_issue("OFFER", bare)["agent"],
                         "thegreekgodhermes")

    def test_missing_and_unknown_fields(self):
        for key in OFFER_KEYS:
            fields = offer_fields()
            del fields[key]
            with self.assertRaises(Refusal) as caught:
                parse_offer_issue("OFFER", "```json\n%s\n```"
                                  % json.dumps(fields))
            self.assertEqual(caught.exception.code, "missing_field")
            self.assertIn(key, caught.exception.detail)

        with self.assertRaises(Refusal) as caught:
            parse_offer_issue("OFFER", body(price="0.05"))
        self.assertEqual(caught.exception.code, "unknown_field")

        # `contact` is optional and survives.
        parsed = parse_offer_issue("OFFER", body(contact="dm @hermes"))
        self.assertEqual(parsed["contact"], "dm @hermes")
        self.assertIsNone(parse_offer_issue("OFFER", body())["contact"])

    def test_the_scope_rules(self):
        with self.assertRaises(Refusal) as caught:
            parse_offer_issue("OFFER", body(output="short output"))
        self.assertEqual(caught.exception.code, "bad_scope")

        with self.assertRaises(Refusal) as caught:
            parse_offer_issue("OFFER", body(input="tiny"))
        self.assertEqual(caught.exception.code, "bad_scope")

        for hostless in ("https://", "http:// /path", "https:///nohost"):
            with self.assertRaises(Refusal) as caught:
                parse_offer_issue("OFFER", body(input=hostless))
            self.assertEqual(caught.exception.code, "bad_scope", hostless)

        # A non-URL input of enough length is fine - not every input is fetched.
        self.assertEqual(
            parse_offer_issue("OFFER", body(input="the attached CSV file"))
            ["input"], "the attached CSV file")

        for bad in ("2026-10-08", "2026-10-08T03:46:00+00:00", "soon", ""):
            with self.assertRaises(Refusal) as caught:
                parse_offer_issue("OFFER", body(by=bad))
            self.assertIn(caught.exception.code,
                          ("bad_deadline", "missing_field"))

    def test_a_deadline_already_past_is_not_a_deadline(self):
        parsed = parse_offer_issue("OFFER", body())
        with self.assertRaises(Refusal) as caught:
            propose(empty_offers(), parsed, source="issue", source_url="u",
                    now="2026-10-08T04:00:00Z")
        self.assertEqual(caught.exception.code, "bad_deadline")

    def test_the_legacy_address_spelling_is_one_account_not_two(self):
        legacy = "xrb_" + SELLER[len("nano_"):]
        parsed = parse_offer_issue("OFFER", body(payout_address=legacy))
        self.assertEqual(parsed["payout_address"], SELLER)


class SellerOfferFeedTest(unittest.TestCase):
    """What the published artifact promises a stranger."""

    def test_the_feed_carries_every_mandatory_key(self):
        document, _ = proposed()
        published = feed(document, now=NOW, feed_url="https://example.invalid/f")
        for key in ("v", "generated_at", "you_are_the_seller", "how_to_offer",
                    "scope_digest_over", "scope_digest_recipe",
                    "accepted_count", "declined_count", "settled_count",
                    "sellers_paid", "paid_xno_total", "open_offers",
                    "decided_offers", "notes"):
            self.assertIn(key, published)
        self.assertEqual(published["feed_url"], "https://example.invalid/f")
        self.assertEqual(published["generated_at"], NOW)

    def test_hours_left_is_an_integer_and_the_payout_address_is_present(self):
        document, _ = proposed()
        row = feed(document, now=NOW)["open_offers"][0]
        self.assertIsInstance(row["hours_left"], int)
        self.assertEqual(row["hours_left"], 24)
        self.assertEqual(row["payout_address"], SELLER)
        later = feed(document, now="2026-10-08T15:16:26Z")["open_offers"][0]
        self.assertEqual(later["hours_left"], 12)

    def test_the_feed_is_serialisable_and_carries_no_standalone_digest(self):
        document, offer = proposed()
        accepted, _ = accept(document, offer["id"], "order-2026-10-08-ser",
                             now=NOW)
        payload = serialise(feed(accepted, now=NOW))
        self.assertTrue(payload.endswith(b"\n"))
        text = payload.decode("utf-8")
        self.assertIsNone(validate.SECRET_RE.search(text),
                          "the feed printed a standalone 64-hex run")
        reparsed = json.loads(text)
        self.assertEqual(
            len("".join(reparsed["open_offers"][0]["order_digest_halves"])), 64)

    def test_the_committed_feed_matches_the_committed_offers_file(self):
        """The published copy in this repository is not allowed to drift."""
        offers_path = os.path.join(ROOT, "offers.json")
        feed_path = os.path.join(ROOT, "feed", "offers.json")
        if not os.path.exists(offers_path) or not os.path.exists(feed_path):
            self.skipTest("offers.json is not committed yet")
        document = read_offers(offers_path)
        with open(feed_path, "r", encoding="utf-8") as handle:
            published = json.load(handle)
        rebuilt = feed(document, now=published["generated_at"],
                       feed_url=published.get("feed_url"))
        self.assertEqual(rebuilt, published,
                         "feed/offers.json is stale - rerun "
                         "`python3 seller_offer.py feed`")


class ValidateAgreesWithSellerOfferTest(unittest.TestCase):
    """`validate.py` restates this vocabulary instead of importing it.

    It has to: `settle.py` imports `validate`, and `tests/test_settle.py`
    asserts that nothing transitively reachable from the money-send path can
    open a socket except `nanonode.py`. Importing `seller_offer` into
    `validate` would pull in `order_bound_amount` -> `grant_mint` ->
    `authority_receipt`, two of which import `urllib`, so the validator cannot
    share the constant and the money path keep its guard.

    The cost of restating it is drift, so these assertions make the drift a
    build failure. A field, state, transition or decline reason added to one
    file and not the other turns this red.
    """

    def test_the_offer_fields_are_the_same_tuple(self):
        self.assertEqual(validate.OFFER_FIELDS, OFFER_FIELDS)

    def test_the_states_are_the_same_tuple(self):
        self.assertEqual(validate.OFFER_STATES, STATES)

    def test_the_transitions_are_the_same_set(self):
        self.assertEqual(set(validate.OFFER_TRANSITIONS), set(TRANSITIONS))
        self.assertEqual(len(validate.OFFER_TRANSITIONS), len(TRANSITIONS))

    def test_the_decline_reasons_are_the_same_tuple(self):
        self.assertEqual(validate.OFFER_DECLINE_REASONS, DECLINE_REASONS)

    def test_the_immutable_fields_are_the_same_tuple(self):
        self.assertEqual(validate.OFFER_IMMUTABLE_FIELDS, IMMUTABLE_FIELDS)

    def test_both_scope_digests_are_the_one_recipe(self):
        scope = {"by": HERMES_BY, "input": HERMES_INPUT, "output": HERMES_OUTPUT}
        self.assertEqual(validate.offer_scope_digest(scope),
                         scope_digest(scope))

    def test_both_append_only_rules_agree_on_the_same_edit(self):
        document, offer = proposed()
        edited = clone(document)
        edited["offers"][0]["price_raw"] = "1"
        self.assertTrue(validate.check_offers_append_only(document, edited))
        self.assertTrue(check_offers_append_only(document, edited))
        self.assertEqual(validate.check_offers_append_only(document, document),
                         [])
        self.assertEqual(check_offers_append_only(document, document), [])

    def test_validate_accepts_what_this_module_writes(self):
        document, offer = proposed()
        accepted, _ = accept(document, offer["id"], "order-2026-10-08-val",
                             now=NOW)
        self.assertEqual(validate.check_offers(accepted), [])
        # And refuses a tampered scope, which is the whole point of the digest.
        tampered = clone(accepted)
        tampered["offers"][0]["scope"]["output"] = HERMES_OUTPUT + " and more"
        errors = validate.check_offers(tampered)
        self.assertTrue(errors)
        self.assertIn("scope_digest does not match", errors[0])

    def test_validate_does_not_import_seller_offer(self):
        """The money path's import graph is the reason for all of the above."""
        graph = import_graph(os.path.join(ROOT, "validate.py"))
        self.assertNotIn("seller_offer", {e["module"] for e in graph})


if __name__ == "__main__":
    unittest.main()
