"""The binding lives in the handshake, and nothing is written to the ledger.

Every test here builds its own documents. Nothing opens a socket, nothing reads
a file from the repository, nothing asks the clock, and no fixture holds a value
captured from a live origin - so a failure here is a defect in
`x402_binding.py` and never a network condition.

The clean set is built INDEPENDENTLY of the module's own `--self-test`
controls, deliberately and for the reason `tests/test_authority_receipt.py`
already states: driving these assertions from the module's fixtures would let a
mutation that breaks both drift past green, which is the whole failure mode
`--self-test` exists to catch.

No 64-hex run stands as a single literal here - every block hash is joined at
runtime - which is the project's secret gate, and the same idiom
`tests/test_authority_receipt.py` and `tests/test_custody_probe.py` use.
"""

import ast
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import x402_binding  # noqa: E402  - imported first; it puts vendor/ on sys.path
import nanoaddr  # noqa: E402
from x402_binding import (  # noqa: E402
    REASON_ORDER, REQUIREMENT_KEYS, append_to_402, as_402_accepts, main,
    requirements, requirements_digest, self_test, verify,
)

PAYEE = nanoaddr.encode(bytes([0x3F]) * 32)
PAYEE_LEGACY = nanoaddr.encode(bytes([0x3F]) * 32, "xrb_")
PAYER = nanoaddr.encode(bytes([0x4A]) * 32)
STRANGER = nanoaddr.encode(bytes([0x5B]) * 32)

HASH = ("9C3D" * 8) + ("72E1" * 8)          # synthetic, joined at runtime
RAW = "50000000000000000000000000000"          # 0.05 XNO
NONCE = "7f" * 12 + "b1c2" + "0d9e"            # 32 hex characters
AFTER = "2026-10-02T00:00:00+00:00"
BEFORE = "2026-10-03T00:00:00+00:00"
SETTLED = "2026-10-02T09:30:00+00:00"
NOW = "2026-10-02T10:00:00+00:00"
RESOURCE = "https://getunstuck.space/jobs/job-2026-10-02-001"
OTHER_RESOURCE = "job-2026-10-02-002"


def fields(**overrides):
    document = {
        "scheme": "exact", "network": "nano-mainnet", "asset": "XNO",
        "pay_to": PAYEE, "amount_required_raw": RAW, "resource": RESOURCE,
        "nonce": NONCE, "valid_after": AFTER, "valid_before": BEFORE,
    }
    document.update(overrides)
    return document


def req(**overrides):
    return requirements(**fields(**overrides))


def block(**overrides):
    document = {
        "confirmed": "true", "subtype": "send", "amount": RAW,
        "link_as_account": PAYEE, "block_account": PAYER, "hash": HASH,
        "local_timestamp": SETTLED,
    }
    document.update(overrides)
    return document


def node_block(**overrides):
    """The same block as a node answers it: the destination under `contents`.

    `block_info` with `json_block=true` returns the signed block nested, so
    `link_as_account` is not a top-level field of a real answer. Everything
    else - `amount`, `confirmed`, `subtype`, `local_timestamp` - stays where
    the node puts it, at the top level.
    """
    document = block(**overrides)
    destination = document.pop("link_as_account", None)
    document["contents"] = {
        "type": "state", "account": document["block_account"],
        "link_as_account": destination,
    }
    return document


class TheTuple(unittest.TestCase):

    # -- 1 ------------------------------------------------------------------
    def test_01_a_matching_confirmed_block_verifies(self):
        verdict = verify(req(), block(), NOW)
        self.assertTrue(verdict["ok"], verdict["reasons"])
        self.assertEqual(verdict["reasons"], [])
        self.assertEqual(verdict["digest"], requirements_digest(req()))
        self.assertEqual(self.cli_verify(req(), block()), 0)

    def cli_verify(self, document, observed, seen=None, extra=None):
        with tempfile.TemporaryDirectory() as directory:
            paths = {}
            payload = [("req", document), ("block", observed)]
            if seen is not None:
                payload.append(("seen", seen))
            for name, value in payload:
                path = os.path.join(directory, name + ".json")
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(value, handle)
                paths[name] = path
            argv = ["verify", "--req", paths["req"], "--block", paths["block"],
                    "--now", NOW]
            if seen is not None:
                argv += ["--seen", paths["seen"]]
            done = subprocess.run(
                [sys.executable, os.path.join(ROOT, "x402_binding.py")]
                + argv + (extra or []),
                capture_output=True, text=True, cwd=ROOT)
        self.last = done
        return done.returncode

    # -- 2 ------------------------------------------------------------------
    def test_02_the_digest_ignores_key_insertion_order(self):
        straight = fields()
        shuffled = {key: straight[key] for key in reversed(REQUIREMENT_KEYS)}
        self.assertNotEqual(list(straight), list(shuffled))
        self.assertEqual(requirements_digest(requirements(**straight)),
                         requirements_digest(requirements(**shuffled)))

    # -- 3 ------------------------------------------------------------------
    def test_03_the_digest_moves_when_only_the_resource_moves(self):
        one = req()
        two = req(resource=OTHER_RESOURCE)
        self.assertEqual(
            {k: v for k, v in one.items() if k != "resource"},
            {k: v for k, v in two.items() if k != "resource"})
        self.assertNotEqual(requirements_digest(one), requirements_digest(two))

    # -- 4 ------------------------------------------------------------------
    def test_04_the_amount_carries_no_binding(self):
        """fishfax's objection, answered as an assertion rather than a promise.

        "unique tagged amounts are a public correlation beacon; anyone who
        guesses the scheme can scrape the ledger and reconstruct your order
        flow, timing, and payer habits in real time."

        Two different resources at the SAME price both verify against their own
        blocks of that same amount - so the amount identifies nothing, and
        there is no tagged-amount beacon on the ledger to scrape.
        """
        one = req()
        two = req(resource=OTHER_RESOURCE)
        self.assertEqual(one["amount_required_raw"], two["amount_required_raw"])
        self.assertTrue(verify(one, block(), NOW)["ok"])
        self.assertTrue(verify(two, block(), NOW)["ok"])
        self.assertNotEqual(requirements_digest(one), requirements_digest(two))

    # -- 5 ------------------------------------------------------------------
    def test_05_one_address_serves_both_resources(self):
        """No per-invoice address, so there is no sweep to leak."""
        one = req()
        two = req(resource=OTHER_RESOURCE)
        self.assertEqual(one["pay_to"], two["pay_to"])
        self.assertTrue(verify(one, block(), NOW)["ok"])
        self.assertTrue(verify(two, block(), NOW)["ok"])

    # -- 6 ------------------------------------------------------------------
    def test_06_nothing_is_written_toward_the_ledger(self):
        """exactchange's correction, as a constraint on the parsed source.

        "Nano ... features zero on-chain memo fields or contract execution
        environments. Attempting to force stateful refund intent into the
        settlement ledger itself mislocates the protocol boundary. The 402
        handshake handles message and intent consensus ... whereas the
        settlement layer simply confirms transfer finality."

        So no ledger-bound field may be constructed anywhere in this module.
        Asserted against the AST rather than against a grep of the file, so
        that the quotations in the prose above - which must name `memo` to
        explain why there is none - cannot launder a real one past this test.
        """
        ledger_fields = {"memo", "representative", "signature", "work",
                         "previous", "link", "balance", "private_key", "seed",
                         "wallet", "account_key"}
        with open(os.path.join(ROOT, "x402_binding.py"), encoding="utf-8") as handle:
            tree = ast.parse(handle.read())

        docstrings = set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef,
                                 ast.ClassDef)):
                first = node.body[0] if node.body else None
                if (isinstance(first, ast.Expr)
                        and isinstance(first.value, ast.Constant)
                        and isinstance(first.value.value, str)):
                    docstrings.add(id(first.value))

        offenders = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Dict):
                for key in node.keys:
                    if (isinstance(key, ast.Constant)
                            and isinstance(key.value, str)
                            and key.value in ledger_fields):
                        offenders.append("dict key %r" % key.value)
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if id(node) in docstrings:
                    continue
                if node.value in ledger_fields:
                    offenders.append("string literal %r" % node.value)
        self.assertEqual(offenders, [], "a ledger-bound field was constructed")

    def test_06b_no_emitted_key_is_a_ledger_field(self):
        entry = as_402_accepts(req())
        self.assertEqual(set(entry), {
            "scheme", "network", "asset", "payTo", "maxAmountRequired",
            "resource", "nonce", "validAfter", "validBefore", "extra"})
        self.assertEqual(set(entry["extra"]), {"requirementsDigest"})

        # No key at any depth is a field the ledger would carry. Asserted over
        # keys rather than over the rendered text, because "network" contains
        # "work" and a substring sweep would call that a violation.
        def keys_of(value):
            if isinstance(value, dict):
                for key, nested in value.items():
                    yield key
                    yield from keys_of(nested)
            elif isinstance(value, list):
                for nested in value:
                    yield from keys_of(nested)

        forbidden = {"memo", "representative", "signature", "work", "previous",
                     "link", "balance", "seed", "private_key"}
        self.assertEqual(set(keys_of(entry)) & forbidden, set())


class TheAmount(unittest.TestCase):

    # -- 7 ------------------------------------------------------------------
    def test_07_one_raw_unit_low_is_refused(self):
        verdict = verify(req(), block(amount=str(int(RAW) - 1)), NOW)
        self.assertEqual(verdict["reasons"], ["amount_below_required"])

    # -- 8 ------------------------------------------------------------------
    def test_08_one_raw_unit_high_is_refused_too(self):
        """The scheme is `exact`. An overpayment is an unbound payment."""
        verdict = verify(req(), block(amount=str(int(RAW) + 1)), NOW)
        self.assertEqual(verdict["reasons"], ["amount_above_required"])
        self.assertFalse(verdict["ok"])
        self.assertEqual(self.cli(block(amount=str(int(RAW) + 1))), 1)

    def cli(self, observed):
        return TheTuple.cli_verify(self, req(), observed)

    # -- 9 ------------------------------------------------------------------
    def test_09_a_padded_amount_is_the_same_amount(self):
        self.assertTrue(verify(req(), block(amount="0" + RAW), NOW)["ok"])

    # -- 10 -----------------------------------------------------------------
    def test_10_a_json_integer_amount_is_accepted(self):
        small = req(amount_required_raw="100")
        self.assertTrue(verify(small, block(amount=100), NOW)["ok"])
        self.assertTrue(verify(small, block(amount="0100"), NOW)["ok"])

    def test_10b_an_unreadable_amount_refuses_on_the_safe_side(self):
        for bad in ("lots", "", None, -5, "9" * 500_000):
            verdict = verify(req(), block(amount=bad), NOW)
            self.assertIn("amount_below_required", verdict["reasons"])
            self.assertNotIn("amount_above_required", verdict["reasons"])


class TheDestination(unittest.TestCase):

    # -- 11 -----------------------------------------------------------------
    def test_11_a_different_destination_is_refused(self):
        verdict = verify(req(), block(link_as_account=STRANGER), NOW)
        self.assertEqual(verdict["reasons"], ["pay_to_mismatch"])

    # -- 12 -----------------------------------------------------------------
    def test_12_the_legacy_xrb_spelling_is_the_same_account(self):
        self.assertTrue(verify(req(), block(link_as_account=PAYEE_LEGACY),
                               NOW)["ok"])

    def test_12b_a_missing_destination_is_refused_not_matched(self):
        for bad in (None, "", 7, "nano_not_an_address"):
            self.assertIn("pay_to_mismatch",
                          verify(req(), block(link_as_account=bad), NOW)["reasons"])

    # -- 12c ----------------------------------------------------------------
    def test_12c_the_destination_is_read_where_the_node_puts_it(self):
        """A node's own `block_info` answer nests `link_as_account`.

        `json_block=true` returns the signed block under `contents`, which is
        where `settle.py`, `authority_receipt.py` and `counterparty_role.py`
        all read the destination from, and which is the field the README tells
        an agent to read (`contents.link_as_account`). Reading only the top
        level refuses a payment that arrived in full, at the right address, for
        the right amount - the one refusal this file must never issue.
        """
        verdict = verify(req(), node_block(), NOW)
        self.assertTrue(verdict["ok"], verdict["reasons"])
        self.assertEqual(verdict["reasons"], [])
        self.assertEqual(verdict["observed"]["link_as_account"], PAYEE)

    def test_12d_a_nested_stranger_is_still_refused(self):
        verdict = verify(req(), node_block(link_as_account=STRANGER), NOW)
        self.assertEqual(verdict["reasons"], ["pay_to_mismatch"])


class TheBlock(unittest.TestCase):

    # -- 13 -----------------------------------------------------------------
    def test_13_confirmed_false_in_either_form(self):
        for value in ("false", False):
            verdict = verify(req(), block(confirmed=value), NOW)
            self.assertEqual(verdict["reasons"], ["block_not_confirmed"])

    def test_13b_confirmed_true_in_either_form(self):
        for value in ("true", True):
            self.assertTrue(verify(req(), block(confirmed=value), NOW)["ok"])

    # -- 14 -----------------------------------------------------------------
    def test_14_a_receive_is_not_a_send(self):
        verdict = verify(req(), block(subtype="receive"), NOW)
        self.assertEqual(verdict["reasons"], ["block_wrong_subtype"])


class TheWindow(unittest.TestCase):

    # -- 15 -----------------------------------------------------------------
    def test_15_the_lower_bound_is_inclusive(self):
        self.assertTrue(verify(req(), block(local_timestamp=AFTER), NOW)["ok"])

    # -- 16 -----------------------------------------------------------------
    def test_16_the_upper_bound_is_exclusive(self):
        verdict = verify(req(), block(local_timestamp=BEFORE), NOW)
        self.assertEqual(verdict["reasons"], ["outside_validity_window"])

    # -- 17 -----------------------------------------------------------------
    def test_17_a_unix_timestamp_inside_the_window_is_accepted(self):
        from datetime import datetime, timezone
        stamp = int(datetime(2026, 10, 2, 9, 30, tzinfo=timezone.utc).timestamp())
        self.assertTrue(verify(req(), block(local_timestamp=stamp), NOW)["ok"])
        self.assertTrue(verify(req(), block(local_timestamp=str(stamp)),
                               NOW)["ok"])

    def test_17b_a_timestamp_before_the_window_is_refused(self):
        verdict = verify(req(), block(local_timestamp="2026-10-01T23:59:59+00:00"),
                         NOW)
        self.assertEqual(verdict["reasons"], ["outside_validity_window"])

    def test_17c_a_naive_or_missing_timestamp_is_refused(self):
        for bad in (None, "2026-10-02T09:30:00", "yesterday", True):
            self.assertIn("outside_validity_window",
                          verify(req(), block(local_timestamp=bad), NOW)["reasons"])

    # -- 18 -----------------------------------------------------------------
    def test_18_a_zero_width_window_never_becomes_a_tuple(self):
        with self.assertRaises(ValueError) as caught:
            req(valid_before=AFTER)
        self.assertIn("strictly after", str(caught.exception))

    def test_18b_a_reversed_window_never_becomes_a_tuple(self):
        with self.assertRaises(ValueError):
            req(valid_after=BEFORE, valid_before=AFTER)

    def test_18c_a_bound_without_an_offset_never_becomes_a_tuple(self):
        with self.assertRaises(ValueError):
            req(valid_after="2026-10-02T00:00:00")


class CallerErrors(unittest.TestCase):

    def cli(self, document, argv_extra=None, command="digest"):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "req.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(document, handle)
            return subprocess.run(
                [sys.executable, os.path.join(ROOT, "x402_binding.py"),
                 command, "--req", path] + (argv_extra or []),
                capture_output=True, text=True, cwd=ROOT)

    # -- 19 -----------------------------------------------------------------
    def test_19_a_pay_to_that_fails_checksum_is_exit_two(self):
        """The nearest miss in this whole funnel was an address that fails
        checksum, and nothing else in the pipeline caught it."""
        broken = PAYEE[:-1] + ("4" if PAYEE[-1] != "4" else "5")
        done = self.cli(fields(pay_to=broken))
        self.assertEqual(done.returncode, 2)
        self.assertIn("bad_checksum", done.stderr)
        self.assertEqual(done.stdout, "")

    def test_19b_an_illegal_character_names_the_character(self):
        done = self.cli(fields(pay_to=PAYEE[:10] + "0" + PAYEE[11:]))
        self.assertEqual(done.returncode, 2)
        self.assertIn("bad_character", done.stderr)
        self.assertIn("'0'", done.stderr)

    # -- 20 -----------------------------------------------------------------
    def test_20_a_short_nonce_is_exit_two(self):
        done = self.cli(fields(nonce=NONCE[:-1]))
        self.assertEqual(done.returncode, 2)
        self.assertIn("nonce", done.stderr)

    def test_20b_a_non_hex_nonce_is_exit_two(self):
        with self.assertRaises(ValueError):
            req(nonce="z" * 32)

    def test_20c_the_module_never_generates_a_nonce(self):
        """A nonce of ours inside the payer's commitment would be our
        randomness in the party that must not be able to claim surprise."""
        with open(os.path.join(ROOT, "x402_binding.py"), encoding="utf-8") as handle:
            source = handle.read()
        for forbidden in ("import random", "import secrets", "import uuid",
                          "os.urandom"):
            self.assertNotIn(forbidden, source)

    # -- 25 -----------------------------------------------------------------
    def test_25_an_unknown_scheme_never_becomes_a_tuple(self):
        """Exit 2 at construction, not a `wrong_scheme` refusal: a profile that
        accepts anything is not a profile."""
        done = self.cli(fields(scheme="upto"))
        self.assertEqual(done.returncode, 2)
        self.assertIn("scheme", done.stderr)
        with self.assertRaises(ValueError):
            req(scheme="upto")

    def test_25b_network_and_asset_are_fixed_literals_too(self):
        for key, value in (("network", "base-mainnet"), ("asset", "USDC")):
            with self.assertRaises(ValueError):
                req(**{key: value})

    # -- 26 -----------------------------------------------------------------
    def test_26_an_extra_key_is_exit_two(self):
        document = fields()
        document["memoText"] = "thanks"
        done = self.cli(document)
        self.assertEqual(done.returncode, 2)
        self.assertIn("memoText", done.stderr)

    # -- 27 -----------------------------------------------------------------
    def test_27_a_missing_key_is_exit_two_and_names_it(self):
        document = fields()
        del document["resource"]
        done = self.cli(document)
        self.assertEqual(done.returncode, 2)
        self.assertIn("resource", done.stderr)

    # -- 28 -----------------------------------------------------------------
    def test_28_an_unparseable_now_raises_and_is_never_a_refusal(self):
        """The caller's broken clock is not the payer's fault."""
        for bad in ("not a time", "2026-10-02T10:00:00", None, 17):
            with self.assertRaises(ValueError):
                verify(req(), block(), bad)

    def test_28b_an_unparseable_now_is_exit_two_at_the_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = {}
            for name, value in (("req", fields()), ("block", block())):
                path = os.path.join(directory, name + ".json")
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(value, handle)
                paths[name] = path
            done = subprocess.run(
                [sys.executable, os.path.join(ROOT, "x402_binding.py"), "verify",
                 "--req", paths["req"], "--block", paths["block"],
                 "--now", "whenever"],
                capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")

    def test_a_bad_resource_never_becomes_a_tuple(self):
        for bad in ("", "ftp://example.org/x", "has spaces", "x" * 129,
                    "https://", 7):
            with self.assertRaises(ValueError):
                req(resource=bad)


class TheNonce(unittest.TestCase):

    def seen(self, resource, digest):
        return {NONCE: {"resource": resource, "digest": digest}}

    # -- 21 -----------------------------------------------------------------
    def test_21_a_nonce_under_a_different_resource_is_a_reuse(self):
        other = req(resource=OTHER_RESOURCE)
        verdict = verify(req(), block(), NOW,
                         seen_nonces=self.seen(OTHER_RESOURCE,
                                               requirements_digest(other)))
        self.assertEqual(verdict["reasons"], ["nonce_reused"])

    def test_21b_the_bare_resource_form_is_accepted_too(self):
        verdict = verify(req(), block(), NOW,
                         seen_nonces={NONCE: OTHER_RESOURCE})
        self.assertEqual(verdict["reasons"], ["nonce_reused"])

    # -- 22 -----------------------------------------------------------------
    def test_22_a_retry_of_one_commitment_is_not_a_reuse(self):
        """Refusing an idempotent re-presentation would punish a payer for
        retrying, which is the opposite of binding."""
        verdict = verify(req(), block(), NOW,
                         seen_nonces=self.seen(RESOURCE,
                                               requirements_digest(req())))
        self.assertTrue(verdict["ok"], verdict["reasons"])
        self.assertEqual(verdict["reasons"], [])

    def test_22b_a_bare_resource_retry_is_not_a_reuse_either(self):
        verdict = verify(req(), block(), NOW, seen_nonces={NONCE: RESOURCE})
        self.assertTrue(verdict["ok"], verdict["reasons"])

    # -- 23 -----------------------------------------------------------------
    def test_23_the_same_nonce_and_resource_with_another_digest_is_refused(self):
        other = req(resource=OTHER_RESOURCE)
        verdict = verify(req(), block(), NOW,
                         seen_nonces=self.seen(RESOURCE,
                                               requirements_digest(other)))
        self.assertEqual(verdict["reasons"], ["resource_mismatch"])

    def test_23b_an_unseen_nonce_is_no_reason_at_all(self):
        self.assertTrue(verify(req(), block(), NOW,
                               seen_nonces={"0" * 32: RESOURCE})["ok"])


class EveryReason(unittest.TestCase):

    # -- 24 -----------------------------------------------------------------
    def test_24_all_applicable_reasons_are_reported_in_the_tables_order(self):
        verdict = verify(req(), block(confirmed="false", subtype="receive",
                                      amount=str(int(RAW) + 1)), NOW)
        self.assertEqual(verdict["reasons"],
                         ["block_not_confirmed", "block_wrong_subtype",
                          "amount_above_required"])
        self.assertFalse(verdict["ok"])

    def test_24b_the_reported_order_follows_the_table_not_the_failure_order(self):
        verdict = verify(req(), block(link_as_account=STRANGER,
                                      confirmed=False,
                                      local_timestamp=BEFORE), NOW)
        self.assertEqual(verdict["reasons"],
                         ["block_not_confirmed", "pay_to_mismatch",
                          "outside_validity_window"])
        for reason in verdict["reasons"]:
            self.assertIn(reason, REASON_ORDER)

    # -- 32 -----------------------------------------------------------------
    def test_32_self_test_passes_with_a_control_for_every_reason(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = self_test()
        self.assertEqual(code, 0, buffer.getvalue())
        report = json.loads(buffer.getvalue())
        self.assertEqual(report["self_test"], "pass")
        self.assertEqual(report["failures"], [])
        self.assertEqual(report["negative_controls"], len(REASON_ORDER))

    def test_32b_every_reason_in_the_table_has_its_own_control(self):
        self.assertEqual(sorted(x402_binding._negative_controls()),
                         sorted(REASON_ORDER))

    def test_32c_the_cli_self_test_exits_zero(self):
        done = subprocess.run(
            [sys.executable, os.path.join(ROOT, "x402_binding.py"), "--self-test"],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(done.returncode, 0, done.stderr)

    # -- 33 -----------------------------------------------------------------
    def test_33_verify_is_deterministic(self):
        first = json.dumps(verify(req(), block(), NOW), indent=2, sort_keys=False)
        second = json.dumps(verify(req(), block(), NOW), indent=2, sort_keys=False)
        self.assertEqual(first, second)

    def test_33b_verify_holds_no_clock(self):
        """`now` is an argument, so a transcript can be re-verified forever."""
        with open(os.path.join(ROOT, "x402_binding.py"), encoding="utf-8") as handle:
            source = handle.read()
        inside = source.split("def verify(")[1].split("\ndef ")[0]
        self.assertNotIn("datetime.now", inside)
        self.assertNotIn("time.time", inside)


class TheLeg(unittest.TestCase):
    """Added beside the others, never in place of them."""

    def usdc_body(self):
        return {
            "x402Version": 1,
            "error": "payment required",
            "accepts": [{
                "scheme": "exact",
                "network": "base",
                "asset": "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",
                "payTo": "0x1234567890123456789012345678901234567890",
                "maxAmountRequired": "50000",
                "resource": RESOURCE,
                "extra": {"name": "USD Coin", "version": "2"},
            }],
        }

    # -- 29 -----------------------------------------------------------------
    def test_29_the_existing_usdc_entry_survives_byte_for_byte(self):
        """ARION added XNO as a THIRD leg rather than switching; a tool that
        rewrote the USDC entry would argue with the only thing that has ever
        worked."""
        existing = self.usdc_body()
        untouched = json.loads(json.dumps(existing))
        body = append_to_402(req(), existing)
        self.assertEqual(len(body["accepts"]), 2)
        self.assertEqual(body["accepts"][0], untouched["accepts"][0])
        self.assertEqual(body["accepts"][1]["network"], "nano-mainnet")
        self.assertEqual(body["accepts"][1]["asset"], "XNO")
        # Every other key of the body survives, and the input is not mutated.
        self.assertEqual(body["x402Version"], 1)
        self.assertEqual(existing["accepts"], untouched["accepts"])

    def test_29b_a_third_leg_appends_after_two(self):
        existing = self.usdc_body()
        existing["accepts"].append({"scheme": "exact", "network": "solana"})
        body = append_to_402(req(), existing)
        self.assertEqual(len(body["accepts"]), 3)
        self.assertEqual(body["accepts"][1]["network"], "solana")

    def test_29c_the_module_makes_no_claim_about_a_non_nano_entry(self):
        """merktop's Base caveat is documentation, not code: silence about
        another rail is honest, a check we have not earned is not."""
        existing = self.usdc_body()
        existing["accepts"][0]["asset"] = "0xdeadbeef-not-canonical-usdc"
        body = append_to_402(req(), existing)
        self.assertEqual(body["accepts"][0]["asset"],
                         "0xdeadbeef-not-canonical-usdc")
        self.assertEqual(len(body["accepts"]), 2)

    # -- 30 -----------------------------------------------------------------
    def test_30_a_body_without_accepts_is_exit_two(self):
        with self.assertRaises(ValueError) as caught:
            append_to_402(req(), {"x402Version": 1})
        self.assertIn("accepts", str(caught.exception))

        with tempfile.TemporaryDirectory() as directory:
            paths = {}
            for name, value in (("req", fields()),
                                ("existing", {"x402Version": 1})):
                path = os.path.join(directory, name + ".json")
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(value, handle)
                paths[name] = path
            done = subprocess.run(
                [sys.executable, os.path.join(ROOT, "x402_binding.py"),
                 "emit-402", "--req", paths["req"],
                 "--existing", paths["existing"]],
                capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(done.returncode, 2)
        self.assertIn("accepts", done.stderr)
        self.assertEqual(done.stdout, "")

    def test_30b_an_accepts_that_is_not_an_array_is_refused(self):
        with self.assertRaises(ValueError):
            append_to_402(req(), {"accepts": {"scheme": "exact"}})

    # -- 31 -----------------------------------------------------------------
    def test_31_the_emitted_entry_round_trips_to_its_own_digest(self):
        entry = as_402_accepts(req())
        rebuilt = requirements(
            scheme=entry["scheme"], network=entry["network"],
            asset=entry["asset"], pay_to=entry["payTo"],
            amount_required_raw=entry["maxAmountRequired"],
            resource=entry["resource"], nonce=entry["nonce"],
            valid_after=entry["validAfter"], valid_before=entry["validBefore"])
        self.assertEqual(requirements_digest(rebuilt),
                         entry["extra"]["requirementsDigest"])

    def test_31b_emit_402_without_an_existing_body_makes_a_one_leg_array(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "req.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(fields(), handle)
            done = subprocess.run(
                [sys.executable, os.path.join(ROOT, "x402_binding.py"),
                 "emit-402", "--req", path],
                capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(done.returncode, 0, done.stderr)
        body = json.loads(done.stdout)
        self.assertEqual(len(body["accepts"]), 1)
        self.assertEqual(body["accepts"][0]["extra"]["requirementsDigest"],
                         requirements_digest(req()))

    def test_31c_the_digest_subcommand_prints_the_same_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "req.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(fields(), handle)
            done = subprocess.run(
                [sys.executable, os.path.join(ROOT, "x402_binding.py"),
                 "digest", "--req", path],
                capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.strip(), requirements_digest(req()))
        self.assertEqual(len(done.stdout.strip()), 64)


class TheQuietFlag(unittest.TestCase):

    def test_quiet_prints_nothing_and_still_sets_the_exit_code(self):
        buffer = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            paths = {}
            for name, value in (("req", fields()),
                                ("block", block(subtype="receive"))):
                path = os.path.join(directory, name + ".json")
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(value, handle)
                paths[name] = path
            with contextlib.redirect_stdout(buffer):
                code = main(["verify", "--req", paths["req"], "--block",
                             paths["block"], "--now", NOW, "--quiet"])
        self.assertEqual(code, 1)
        self.assertEqual(buffer.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
