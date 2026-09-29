"""The suite for quotelock.py. Every test is numbered after the spec line it pins.

Test 1 is the tool's reason to exist: it pins the Tollstile defect, where
`verify()` read the exchange rate a second time and refused a payer who had sent
exactly the quoted amount. It is enforced structurally, by inspecting the
signature, because a comment saying "do not read a rate here" is not a test.

No test touches the network, and test 9 fails the build if quotelock.py ever
grows an import that could. Nothing here contains a 64-character hex literal:
validate.py's secret gate refuses one anywhere in the tree, and it is right to,
so every lock in this file is computed at runtime.
"""

import ast
import contextlib
import datetime
import io
import json
import os
import socket
import sys
import tempfile
import unittest
from decimal import Decimal

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "vendor"))

import nanoaddr  # noqa: E402
import quotelock  # noqa: E402
from quotelock import (  # noqa: E402
    BadAddress, BadRate, BadUsd, LockMismatch, QuoteExpired, QuoteInvalid,
    Underpaid, WrongPayee, check_quote, expected_raw, is_expired, make_quote,
    refund_amount, verify_payment)

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 9, 28, 6, 30, 0, tzinfo=UTC)

KEY = bytes(range(32))
PAY = nanoaddr.encode(KEY, "nano_")
PAY_XRB = nanoaddr.encode(KEY, "xrb_")
OTHER = nanoaddr.encode(bytes([255] + list(range(1, 32))), "nano_")

VECTORS = os.path.join(ROOT, "vectors", "quote-lock-v1.json")


def quote(usd="0.0500", rate="0.8412", ttl=900, now=NOW, pay_to=PAY,
          nonce="b3f1c0a49d2e4c7a"):
    return make_quote(usd=usd, rate_xno_per_usd=rate, pay_to=pay_to,
                      ttl_seconds=ttl, now=now, nonce=nonce)


def reseal(q):
    """Re-derive the lock, for building a quote that is wrong but self-consistent."""
    q = dict(q)
    q["lock"] = quotelock.lock_for(q)
    return q


class QuoteLock(unittest.TestCase):

    # -- 1 ------------------------------------------------------------------
    def test_1_the_tollstile_defect_cannot_be_reintroduced(self):
        """A payer who sent exactly amount_raw is accepted however the rate moved."""
        q = quote(rate="1.0")
        owed = int(q["amount_raw"])

        # The rate "moves" 30%. verify_payment is not told, and cannot be told.
        verdict = verify_payment(q, received_raw=owed, received_to=PAY, now=NOW)
        self.assertTrue(verdict["ok"])
        self.assertEqual(verdict["overpaid_raw"], "0")
        self.assertEqual(verdict["rate_xno_per_usd"], "1.0000000000")

        import inspect
        forbidden = ("rate", "fx", "price", "oracle", "fetch")
        for func in (verify_payment, quotelock.expected_raw,
                     quotelock.is_expired, quotelock.check_quote):
            for name in inspect.signature(func).parameters:
                for word in forbidden:
                    self.assertNotIn(
                        word, name.lower(),
                        "%s takes %r - the settlement path must not be able to "
                        "read a rate" % (func.__name__, name))

    # -- 2 ------------------------------------------------------------------
    def test_2_a_refund_carries_no_fx_risk(self):
        """The refund is the raw that arrived, not a reconversion of the dollars."""
        settled = "42060000000000000000000000000"
        at_one = {"settled_raw": settled, "rate_xno_per_usd": "1.0000000000"}
        at_half = {"settled_raw": settled, "rate_xno_per_usd": "0.5000000000"}
        self.assertEqual(refund_amount(at_one), int(settled))
        self.assertEqual(refund_amount(at_one), refund_amount(at_half))

        import inspect
        params = inspect.signature(refund_amount).parameters
        self.assertEqual(list(params), ["receipt"])
        for name in params:
            for word in ("rate", "fx", "price", "oracle", "fetch", "now"):
                self.assertNotIn(word, name.lower())

    def test_2b_a_refund_rejects_a_receipt_with_no_settled_raw(self):
        for bad in ({}, {"usd": "0.0500"}, [], None, "42"):
            with self.assertRaises(QuoteInvalid):
                refund_amount(bad)

    # -- 3 ------------------------------------------------------------------
    def test_3_no_binary_fraction_touches_an_amount(self):
        with open(os.path.join(ROOT, "quotelock.py"), "r", encoding="utf-8") as fh:
            source = fh.read()
        self.assertNotIn("float" + "(", source,
                         "a binary fraction in this path loses the bottom 13+ "
                         "digits of every amount")

        q = quote(usd="0.1000", rate="0.1000000000")
        self.assertEqual(q["amount_raw"], "10000000000000000000000000000")
        # What the arithmetic would have produced with a binary fraction:
        self.assertNotEqual(Decimal("0.1") * Decimal("0.1"),
                            Decimal(repr(0.1 * 0.1)))

    def test_3b_a_binary_fraction_is_refused_at_the_door(self):
        q = quote()
        with self.assertRaises(ValueError):
            verify_payment(q, received_raw=4.206e28, received_to=PAY, now=NOW)
        with self.assertRaises(ValueError):
            refund_amount({"settled_raw": 4.206e28})

    # -- 4 ------------------------------------------------------------------
    def test_4_one_e24_raw_round_trips_through_json(self):
        """0.000001 XNO = 1e24 raw - the amount that overflowed minia2a's column."""
        q = quote(usd="0.0010", rate="0.0010000000")
        self.assertEqual(q["amount_raw"], "1000000000000000000000000")

        revived = json.loads(json.dumps(q))
        self.assertEqual(check_quote(revived)["amount_raw"], q["amount_raw"])
        self.assertEqual(expected_raw(revived), 10 ** 24)
        verdict = verify_payment(revived, received_raw="1000000000000000000000000",
                                 received_to=PAY, now=NOW)
        self.assertEqual(verdict["settled_raw"], "1000000000000000000000000")

    # -- 5 ------------------------------------------------------------------
    def test_5_a_tampered_field_is_caught_by_the_lock(self):
        for field, value in (("usd", "0.0100"),
                             ("rate_xno_per_usd", "0.5000000000"),
                             ("amount_raw", "1")):
            tampered = dict(quote())
            tampered[field] = value
            with self.assertRaises(LockMismatch, msg=field) as caught:
                check_quote(tampered)
            self.assertEqual(caught.exception.code, "lock_mismatch")
        self.assertTrue(issubclass(LockMismatch, QuoteInvalid))

    def test_5b_a_resealed_quote_still_fails_on_the_arithmetic(self):
        """A forger who recomputes the lock is caught by the recomputed amount."""
        forged = reseal(dict(quote(), amount_raw="1"))
        with self.assertRaises(QuoteInvalid) as caught:
            check_quote(forged)
        self.assertEqual(caught.exception.code, "invalid_quote")

    # -- 6 ------------------------------------------------------------------
    def test_6_expiry_is_inclusive_at_the_boundary(self):
        q = quote(ttl=900)
        expires = datetime.datetime(2026, 9, 28, 6, 45, 0, tzinfo=UTC)
        self.assertEqual(q["expires_at"], "2026-09-28T06:45:00Z")

        self.assertFalse(is_expired(q, expires))
        owed = int(q["amount_raw"])
        self.assertTrue(verify_payment(q, received_raw=owed, received_to=PAY,
                                       now=expires)["ok"])

        one_second_later = expires + datetime.timedelta(seconds=1)
        self.assertTrue(is_expired(q, one_second_later))
        with self.assertRaises(QuoteExpired) as caught:
            verify_payment(q, received_raw=owed, received_to=PAY,
                           now=one_second_later)
        self.assertEqual(caught.exception.code, "expired")

    def test_6b_a_naive_datetime_is_an_error(self):
        q = quote()
        naive = datetime.datetime(2026, 9, 28, 6, 30, 0)
        with self.assertRaises(ValueError):
            make_quote(usd="0.0500", rate_xno_per_usd="0.8412", pay_to=PAY,
                       ttl_seconds=900, now=naive)
        with self.assertRaises(ValueError):
            verify_payment(q, received_raw=1, received_to=PAY, now=naive)
        with self.assertRaises(ValueError):
            is_expired(q, naive)

    # -- 7 ------------------------------------------------------------------
    def test_7_one_account_two_spellings(self):
        q = quote()
        owed = int(q["amount_raw"])
        self.assertTrue(verify_payment(q, received_raw=owed,
                                       received_to=PAY_XRB, now=NOW)["ok"])

        with self.assertRaises(WrongPayee) as caught:
            verify_payment(q, received_raw=owed, received_to=OTHER, now=NOW)
        self.assertEqual(caught.exception.code, "wrong_payee")

    def test_7b_a_mutated_address_is_never_accepted_anywhere(self):
        """The eddie_researcher case: an address that fails checksum."""
        broken = PAY[:-1] + ("4" if PAY[-1] != "4" else "5")
        with self.assertRaises(BadAddress) as caught:
            verify_payment(quote(), received_raw=1, received_to=broken, now=NOW)
        self.assertEqual(caught.exception.code, "invalid_checksum")

        with self.assertRaises(BadAddress) as caught:
            make_quote(usd="0.0500", rate_xno_per_usd="0.8412", pay_to=broken,
                       ttl_seconds=900, now=NOW)
        self.assertEqual(caught.exception.code, "invalid_checksum")

        with self.assertRaises(BadAddress):
            check_quote(reseal(dict(quote(), pay_to=broken)))

    # -- 8 ------------------------------------------------------------------
    def test_8_one_raw_short_is_refused_one_raw_over_is_accepted(self):
        q = quote()
        owed = int(q["amount_raw"])

        with self.assertRaises(Underpaid) as caught:
            verify_payment(q, received_raw=owed - 1, received_to=PAY, now=NOW)
        self.assertEqual(caught.exception.code, "underpaid")
        self.assertEqual(caught.exception.short_raw, "1")

        verdict = verify_payment(q, received_raw=owed + 1, received_to=PAY,
                                 now=NOW)
        self.assertTrue(verdict["ok"])
        self.assertEqual(verdict["overpaid_raw"], "1")
        self.assertEqual(verdict["quote_nonce"], q["nonce"])
        self.assertEqual(verdict["usd"], "0.0500")

    def test_8b_received_raw_accepts_an_integer_string(self):
        q = quote()
        self.assertTrue(verify_payment(q, received_raw=q["amount_raw"],
                                       received_to=PAY, now=NOW)["ok"])
        for bad in ("-1", "0x10", "1.0", "", " ", "1e28", None, True):
            with self.assertRaises(ValueError, msg=repr(bad)):
                verify_payment(q, received_raw=bad, received_to=PAY, now=NOW)

    # -- 9 ------------------------------------------------------------------
    def test_9_quotelock_cannot_open_a_socket(self):
        network = {"socket", "http", "urllib", "ssl", "requests", "asyncio",
                   "ftplib", "smtplib", "xmlrpc", "telnetlib"}
        local = {}
        for base in (ROOT, os.path.join(ROOT, "vendor")):
            for name in os.listdir(base):
                if name.endswith(".py"):
                    local.setdefault(name[:-3], os.path.join(base, name))

        seen, queue, offenders = set(), ["quotelock"], {}
        while queue:
            module = queue.pop()
            if module in seen or module not in local:
                continue
            seen.add(module)
            with open(local[module], "r", encoding="utf-8") as handle:
                tree = ast.parse(handle.read())
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    root = name.split(".")[0]
                    if root in network:
                        offenders.setdefault(module, set()).add(name)
                    queue.append(root)
        self.assertEqual(offenders, {}, "quotelock.py reaches the network")

    def test_9b_results_do_not_change_with_the_network_removed(self):
        q = quote()
        owed = int(q["amount_raw"])
        original = socket.socket

        def refuse(*args, **kwargs):
            raise AssertionError("quotelock opened a socket")

        socket.socket = refuse
        try:
            self.assertEqual(check_quote(q), q)
            self.assertEqual(expected_raw(q), owed)
            self.assertTrue(verify_payment(q, received_raw=owed,
                                           received_to=PAY, now=NOW)["ok"])
            self.assertEqual(
                quote()["amount_raw"], "42060000000000000000000000000")
        finally:
            socket.socket = original

    # -- 10 -----------------------------------------------------------------
    def test_10_every_conformance_vector_reproduces(self):
        with open(VECTORS, "r", encoding="utf-8") as handle:
            doc = json.load(handle)

        self.assertEqual(doc["digest"]["field_order"],
                         list(quotelock.LOCKED_FIELDS))
        self.assertTrue(doc["rounding"]["never_fires_for_valid_quotes"])

        checked = 0
        for case in doc["cases"]:
            name = case["name"]
            if case["kind"] == "amount":
                got = quotelock.amount_raw_for(
                    case["input"]["usd"], case["input"]["rate_xno_per_usd"])
                self.assertEqual(str(got), case["expect"]["amount_raw"], name)
            elif case["kind"] == "lock":
                fields = dict(case["input"])
                expected = "".join(case["expect"]["lock_halves"])
                self.assertEqual(len(expected), 64, name)
                sealed = dict(fields, lock=expected)
                self.assertEqual(
                    quotelock.canonical_bytes(sealed).decode(),
                    case["expect"]["preimage"], name)
                self.assertEqual(quotelock.lock_for(sealed), expected, name)
                self.assertEqual(check_quote(sealed), sealed, name)
            elif case["kind"] == "verify":
                q = quote(usd=case["input"]["usd"],
                          rate=case["input"]["rate_xno_per_usd"],
                          pay_to=case["input"]["quote_pay_to"])
                if case["expect"]["ok"]:
                    verdict = verify_payment(
                        q, received_raw=case["input"]["received_raw"],
                        received_to=case["input"]["received_to"], now=NOW)
                    self.assertEqual(verdict["overpaid_raw"],
                                     case["expect"]["overpaid_raw"], name)
                else:
                    with self.assertRaises(quotelock.QuoteError, msg=name) as c:
                        verify_payment(
                            q, received_raw=case["input"]["received_raw"],
                            received_to=case["input"]["received_to"], now=NOW)
                    self.assertEqual(c.exception.code, case["expect"]["code"], name)
            else:
                self.fail("unknown vector kind %r" % case["kind"])
            checked += 1
        self.assertEqual(checked, len(doc["cases"]))
        self.assertGreaterEqual(checked, 6)

    def test_10b_the_vectors_file_holds_no_standalone_64_hex_run(self):
        """validate.py's secret gate must stay green on what we just added."""
        sys.path.insert(0, ROOT)
        import validate
        for name in ("vectors/quote-lock-v1.json", "quotelock.py",
                     "schema/quote.json", "tests/test_quotelock.py"):
            with open(os.path.join(ROOT, name), "r", encoding="utf-8") as fh:
                text = fh.read()
            self.assertIsNone(validate.SECRET_RE.search(text), name)

    # -- 11 -----------------------------------------------------------------
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        code = quotelock.main(list(argv), out=out, err=err)
        return code, out.getvalue(), err.getvalue()

    def test_11_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            qpath = os.path.join(tmp, "quote.json")
            # The CLI reads the real clock, so this quote has to be live now.
            q = quote(now=datetime.datetime.now(UTC), ttl=3600)
            with open(qpath, "w", encoding="utf-8") as fh:
                json.dump(q, fh)
            owed = int(q["amount_raw"])

            code, out, _ = self.run_cli("verify", "--quote", qpath,
                                        "--received-raw", str(owed),
                                        "--received-to", PAY, "--json")
            self.assertEqual(code, 0)
            self.assertTrue(json.loads(out)["ok"])

            code, out, _ = self.run_cli("verify", "--quote", qpath,
                                        "--received-raw", str(owed - 1),
                                        "--received-to", PAY, "--json")
            self.assertEqual(code, 3)
            self.assertEqual(json.loads(out),
                             {"ok": False, "code": "underpaid"})

            code, out, err = self.run_cli("verify", "--quote", qpath,
                                          "--received-raw", str(owed - 1),
                                          "--received-to", PAY)
            self.assertEqual(code, 3)
            self.assertEqual(out, "")
            self.assertIn("underpaid", err)

            code, _, err = self.run_cli("verify", "--quote", qpath,
                                        "--received-to", PAY)
            self.assertEqual(code, 4)
            self.assertIn("usage error", err)

            code, _, _ = self.run_cli("check", "--quote", qpath)
            self.assertEqual(code, 0)

            # A quote is not a receipt: refused with a stated code, not a
            # usage error, because the caller gets something to switch on.
            code, out, _ = self.run_cli(
                "refund", "--receipt", qpath, "--json")
            self.assertEqual(code, 3)
            self.assertEqual(json.loads(out),
                             {"ok": False, "code": "invalid_quote"})

    def test_11b_cli_quote_then_check_round_trips(self):
        code, out, err = self.run_cli(
            "quote", "--usd", "0.05", "--rate", "0.8412", "--pay-to", PAY,
            "--ttl", "900", "--json")
        self.assertEqual(code, 0, err)
        issued = json.loads(out)
        self.assertEqual(issued["amount_raw"], "42060000000000000000000000000")
        self.assertEqual(check_quote(issued), issued)

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "q.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(issued, fh)
            code, _, _ = self.run_cli("check", "--quote", path)
            self.assertEqual(code, 0)

            receipt = os.path.join(tmp, "r.json")
            with open(receipt, "w", encoding="utf-8") as fh:
                json.dump({"settled_raw": issued["amount_raw"]}, fh)
            code, out, _ = self.run_cli("refund", "--receipt", receipt)
            self.assertEqual(code, 0)
            self.assertEqual(out.strip(), issued["amount_raw"])

    def test_11c_cli_refuses_an_unreadable_or_tampered_file(self):
        code, _, err = self.run_cli("check", "--quote", "/nonexistent/q.json")
        self.assertEqual(code, 4)
        self.assertIn("usage error", err)

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "q.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(dict(quote(), usd="0.0100"), fh)
            code, out, _ = self.run_cli("check", "--quote", path, "--json")
            self.assertEqual(code, 3)
            self.assertEqual(json.loads(out)["code"], "lock_mismatch")

    # -- normalisation and the field-format error paths ----------------------
    def test_12_the_rate_normalises_or_refuses_to_lose_a_digit(self):
        self.assertEqual(quotelock.normalise_rate("0.8412"), "0.8412000000")
        self.assertEqual(quotelock.normalise_usd("0.05"), "0.0500")
        self.assertEqual(quotelock.normalise_rate(1), "1.0000000000")

        with self.assertRaises(BadRate):
            quotelock.normalise_rate("0.84120000001")  # an 11th decimal place
        with self.assertRaises(BadUsd):
            quotelock.normalise_usd("0.00005")         # a 5th decimal place
        for bad in ("0", "-1", "abc", "1e-4", "", "0.0", None, [], 0.05):
            with self.assertRaises(BadUsd, msg=repr(bad)):
                quotelock.normalise_usd(bad)
            with self.assertRaises(BadRate, msg=repr(bad)):
                quotelock.normalise_rate(bad)

    def test_13_check_quote_rejects_a_malformed_quote(self):
        good = quote()

        with self.assertRaises(QuoteInvalid):
            check_quote("not a quote")
        for field in quotelock.QUOTE_FIELDS:
            missing = {k: v for k, v in good.items() if k != field}
            with self.assertRaises(QuoteInvalid, msg=field):
                check_quote(missing)
        with self.assertRaises(QuoteInvalid):
            check_quote(dict(good, surprise="x"))

        with self.assertRaises(QuoteInvalid):
            check_quote(reseal(dict(good, v=2)))
        with self.assertRaises(QuoteInvalid):
            check_quote(reseal(dict(good, nonce="NOTHEX")))
        with self.assertRaises(BadUsd):
            check_quote(reseal(dict(good, usd="0.05")))
        with self.assertRaises(BadRate):
            check_quote(reseal(dict(good, rate_xno_per_usd="0.8412")))
        with self.assertRaises(QuoteInvalid):
            check_quote(reseal(dict(good, amount_raw="007")))
        with self.assertRaises(QuoteInvalid):
            check_quote(reseal(dict(good, issued_at="2026-09-28 06:30:00")))
        with self.assertRaises(QuoteInvalid):
            check_quote(reseal(dict(good, expires_at="2026-09-28T06:30:00Z")))
        with self.assertRaises(LockMismatch):
            check_quote(dict(good, lock="abc"))

    def test_14_make_quote_refuses_a_nonsense_ttl_or_nonce(self):
        for ttl in (0, -1, "900", 900.0, True, None):
            with self.assertRaises((QuoteInvalid, ValueError), msg=repr(ttl)):
                make_quote(usd="0.0500", rate_xno_per_usd="0.8412", pay_to=PAY,
                           ttl_seconds=ttl, now=NOW)
        for nonce in ("short", "NOTLOWERCASE1234", "zz", 17, ""):
            with self.assertRaises(QuoteInvalid, msg=repr(nonce)):
                make_quote(usd="0.0500", rate_xno_per_usd="0.8412", pay_to=PAY,
                           ttl_seconds=900, now=NOW, nonce=nonce)

    def test_15_a_generated_nonce_is_fresh_every_time(self):
        seen = {make_quote(usd="0.0500", rate_xno_per_usd="0.8412", pay_to=PAY,
                           ttl_seconds=900, now=NOW)["nonce"]
                for _ in range(32)}
        self.assertEqual(len(seen), 32)

    def test_16_no_error_message_leaks_a_rate_source_or_a_key(self):
        forbidden = ("http://", "https://", "seed", "private", "api_key")
        cases = [
            (lambda: check_quote(dict(quote(), usd="0.0100"))),
            (lambda: verify_payment(quote(), received_raw=0,
                                    received_to=PAY, now=NOW)),
            (lambda: verify_payment(quote(), received_raw=1,
                                    received_to=OTHER, now=NOW)),
            (lambda: quotelock.normalise_rate("0")),
        ]
        for call in cases:
            try:
                call()
            except quotelock.QuoteError as exc:
                lowered = str(exc).lower()
                for word in forbidden:
                    self.assertNotIn(word, lowered)
            else:
                self.fail("expected a refusal")


if __name__ == "__main__":
    unittest.main()
