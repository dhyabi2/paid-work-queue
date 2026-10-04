"""Declaring the role before the block, and proving the old receipt was blind.

The decisive test in this file is test 1, and it asserts two things at once:
that `counterparty_role.verify` halts on a self-probe, and that
`authority_receipt.verify` returns `ok: true` with ZERO reasons on the very
same receipt. The second half is the one that records the gap. The payment leg
of a self-probe is genuinely valid - the block confirmed, the grant allowed it,
the amounts agree - and until this module existed nothing in this repository
compared the payer to the payee, so six such rows were indistinguishable from
six sales. If test 1's second assertion ever goes red, authority_receipt has
grown an opinion about roles and these two files have started to disagree about
whose job that is.

Every fixture here is built independently of `counterparty_role`'s own
`--self-test` controls, deliberately: driving these assertions from the
module's fixtures would let a mutation that breaks both drift past green, which
is the whole failure mode `--self-test` exists to catch.

Nothing opens a socket, and nothing can: test 13 walks the import graph.

No 64-hex run stands as a single literal, matching the project's secret gate.
"""

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

import authority_receipt  # noqa: E402
import counterparty_role  # noqa: E402
import grant_mint  # noqa: E402
import nanoaddr  # noqa: E402
from authority_receipt import request_digest  # noqa: E402
from counterparty_role import (  # noqa: E402
    CLASSES, OBSERVABLE, REASON_CODES, Refusal, classify, declare, digest,
    main, serialise, verify,
)
from custody_probe import NETWORK_MODULES  # noqa: E402  - reused, not re-listed

SCRIPT = os.path.join(ROOT, "counterparty_role.py")
VECTOR = os.path.join(ROOT, "vectors", "counterparty-role-v1.json")

# Distinct from the module's controls on purpose - see the docstring.
PAYER = nanoaddr.encode(bytes([0x5A]) * 32)
PAYEE = nanoaddr.encode(bytes([0x6B]) * 32)
THIRD = nanoaddr.encode(bytes([0x7C]) * 32)
PAYEE_XRB = nanoaddr.encode(bytes([0x6B]) * 32, prefix="xrb_")
PAYER_XRB = nanoaddr.encode(bytes([0x5A]) * 32, prefix="xrb_")

JOB = "job-2026-10-04-011"
RAW = "70000000000000000000000000000"          # 0.07 XNO
LIMIT = "250000000000000000000000000000"       # 0.25 XNO
BLOCK_HASH = "9F3C" * 16
DECLARED = "2026-10-04T06:00:00Z"
SETTLED = "2026-10-04T06:05:00Z"
REQUEST = {"job": JOB, "unit": "one bounded task"}


def receipt_for(payer, payee, job_id=JOB, settled_raw=RAW, grant_ref=None):
    """A receipt with exactly `authority_receipt.RECEIPT_KEYS`.

    Built here rather than imported so this file's assertions do not inherit
    the module's idea of a well-formed document.
    """
    return {
        "version": 1,
        "request_id": job_id,
        "request_digest": request_digest(REQUEST),
        "payer_account": payer,
        "payee_account": payee,
        "quoted_raw": settled_raw,
        "settled_raw": settled_raw,
        "settled_block": BLOCK_HASH,
        "committed_at": SETTLED,
        "grant": grant_ref or {"url": "https://operator.invalid/g.json",
                               "sha256": "ab" * 32, "policy_epoch": 1},
    }


def block_for(payer, payee, local_timestamp=SETTLED, amount=RAW):
    return {
        "hash": BLOCK_HASH,
        "amount": amount,
        "block_account": payer,
        "subtype": "send",
        "confirmed": "true",
        "local_timestamp": local_timestamp,
        "contents": {"link_as_account": payee},
    }


def intent_bytes(payer=PAYER, payee=PAYEE, cp_class="external", job_id=JOB,
                 amount=RAW, declared_at=DECLARED):
    return declare(job_id=job_id, payer_account=payer, payee_account=payee,
                   cp_class=cp_class, amount_raw=amount,
                   declared_at=declared_at)[1]


def run(*argv):
    """The CLI as a user runs it, so exit codes and streams are under test."""
    return subprocess.run([sys.executable, SCRIPT] + list(argv),
                          capture_output=True, text=True, cwd=ROOT, timeout=60)


class TheGapThisClosed(unittest.TestCase):
    """Test 1 and 2: the self-probe, in both spellings."""

    def _authority_passes_a_self_probe(self, payer, payee):
        """Mint a real grant that permits payer -> payee and verify it.

        The grant names the payer as subject and the payee as an allowed payee,
        so when the two are one account the operator has genuinely authorised
        the payment. Nothing is forged: this is a valid settlement that says
        nothing.
        """
        grant, payload, ref, _ = grant_mint.mint(
            subject=payer, max_raw=LIMIT, not_before="2026-09-01T00:00:00Z",
            not_after="2026-12-01T00:00:00Z", allow_payees=[payee],
            url="https://operator.invalid/g.json", now=DECLARED)
        receipt = receipt_for(payer, payee, grant_ref=ref)
        receipt["settled_block"] = grant_mint.CONTROL_BLOCK
        block = {"hash": grant_mint.CONTROL_BLOCK, "amount": RAW,
                 "block_account": payer, "subtype": "send", "confirmed": "true",
                 "local_timestamp": SETTLED,
                 "contents": {"link_as_account": payee}}
        verdict = authority_receipt.verify(receipt, payload, block,
                                           request=REQUEST, now=SETTLED)
        return receipt, block, verdict

    def test_01_the_self_probe_that_passes_today_is_a_halt(self):
        receipt, block, authority = self._authority_passes_a_self_probe(PAYER, PAYER)

        # The half that records the gap: the payment leg is valid.
        self.assertIs(authority["ok"], True,
                      "authority_receipt stopped passing a self-probe; if that "
                      "is deliberate, these two files now disagree about whose "
                      "job the role is")
        self.assertEqual(authority["reasons"], [])
        self.assertEqual(receipt["payer_account"], receipt["payee_account"])

        # The half this module adds.
        verdict = verify(intent_bytes(PAYER, PAYER, "external"), receipt, block)
        self.assertIs(verdict["ok"], False)
        self.assertEqual(verdict["reason"], "declared_external_settled_self")
        self.assertIs(verdict["halt"], True)
        self.assertEqual(verdict["declared_class"], "external")
        self.assertEqual(verdict["observed_class"], "self")

    def test_01b_the_halt_is_exit_1_through_the_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            ipath = os.path.join(tmp, "intent.json")
            rpath = os.path.join(tmp, "receipt.json")
            bpath = os.path.join(tmp, "block.json")
            with open(ipath, "wb") as fh:
                fh.write(intent_bytes(PAYER, PAYER, "external"))
            with open(rpath, "w", encoding="utf-8") as fh:
                json.dump(receipt_for(PAYER, PAYER), fh)
            with open(bpath, "w", encoding="utf-8") as fh:
                json.dump(block_for(PAYER, PAYER), fh)
            done = run("verify", "--intent", ipath, "--receipt", rpath,
                       "--block", bpath)
        self.assertEqual(done.returncode, 1, done.stderr)
        verdict = json.loads(done.stdout)
        self.assertEqual(verdict["reason"], "declared_external_settled_self")
        self.assertIs(verdict["halt"], True)

    def test_02_the_xrb_spelling_does_not_launder_a_self_probe(self):
        """The same probe with the payee in the legacy prefix.

        A string compare passes this test wrongly - the two addresses differ in
        every leading character - and `canonical.same_account` passes it
        rightly, because both decode to one public key.
        """
        self.assertNotEqual(PAYER, PAYER_XRB)
        receipt = receipt_for(PAYER, PAYER_XRB)
        block = block_for(PAYER, PAYER_XRB)
        verdict = verify(intent_bytes(PAYER, PAYER_XRB, "external"), receipt, block)
        self.assertEqual(verdict["reason"], "declared_external_settled_self")
        self.assertIs(verdict["halt"], True)
        self.assertEqual(verdict["observed_class"], "self")

    def test_02b_the_mixed_spelling_also_binds_without_a_mismatch(self):
        """An intent in one spelling and a block in the other is still one row.

        Worth its own test: if the account comparison were textual, this would
        refuse with `payer_mismatch` - telling a seller they were not paid after
        the money moved, which is the failure `canonical.py` was written for.
        """
        verdict = verify(intent_bytes(PAYER, PAYEE, "external"),
                         receipt_for(PAYER_XRB, PAYEE_XRB),
                         block_for(PAYER_XRB, PAYEE_XRB))
        self.assertIs(verdict["ok"], True)
        self.assertEqual(verdict["reason"], "declared_class_matches_observed")


class AmbiguityResolvesDownward(unittest.TestCase):

    def test_03_declaring_self_and_settling_external_is_allowed(self):
        verdict = verify(intent_bytes(PAYER, PAYEE, "self"),
                         receipt_for(PAYER, PAYEE), block_for(PAYER, PAYEE))
        self.assertIs(verdict["ok"], True)
        self.assertEqual(verdict["reason"], "declared_self_settled_external")
        self.assertIs(verdict["halt"], False)

    def test_03b_declaring_self_and_settling_self_matches(self):
        verdict = verify(intent_bytes(PAYER, PAYER, "self"),
                         receipt_for(PAYER, PAYER), block_for(PAYER, PAYER))
        self.assertIs(verdict["ok"], True)
        self.assertEqual(verdict["reason"], "declared_class_matches_observed")

    def test_03c_exit_zero_on_a_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            ipath = os.path.join(tmp, "i.json")
            rpath = os.path.join(tmp, "r.json")
            with open(ipath, "wb") as fh:
                fh.write(intent_bytes(PAYER, PAYEE, "external"))
            with open(rpath, "w", encoding="utf-8") as fh:
                json.dump(receipt_for(PAYER, PAYEE), fh)
            done = run("verify", "--intent", ipath, "--receipt", rpath)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout)["observed_from"], "receipt")


class TheDeclarationMustComeFirst(unittest.TestCase):

    def test_04_an_intent_written_after_the_block_is_refused(self):
        verdict = verify(intent_bytes(PAYER, PAYEE, "external",
                                      declared_at="2026-10-04T06:05:01Z"),
                         receipt_for(PAYER, PAYEE), block_for(PAYER, PAYEE))
        self.assertIs(verdict["ok"], False)
        self.assertEqual(verdict["reason"], "intent_declared_after_settlement")
        self.assertIs(verdict["halt"], True)

    def test_04b_the_same_second_is_not_evidence_of_coming_first(self):
        """Equal is refused. A declaration stamped at the block's own second
        proves nothing about order, and the whole design is that the class was
        asserted BEFORE the transfer."""
        verdict = verify(intent_bytes(PAYER, PAYEE, "external", declared_at=SETTLED),
                         receipt_for(PAYER, PAYEE), block_for(PAYER, PAYEE))
        self.assertEqual(verdict["reason"], "intent_declared_after_settlement")

    def test_04c_a_unix_local_timestamp_is_read_too(self):
        """Nodes answer `local_timestamp` as a unix integer; proxies restate it
        as RFC3339. Refusing over the shape of that field rather than over the
        payment is the bug `x402_binding._settled_at` already avoids."""
        unix = 1791093900          # 2026-10-04T06:05:00Z
        self.assertEqual(
            counterparty_role.settled_at(unix),
            counterparty_role.moment(SETTLED))
        late = intent_bytes(PAYER, PAYEE, "external", declared_at="2026-10-04T06:05:01Z")
        for value in (unix, str(unix)):
            verdict = verify(late, receipt_for(PAYER, PAYEE),
                             block_for(PAYER, PAYEE, local_timestamp=value))
            self.assertEqual(verdict["reason"], "intent_declared_after_settlement",
                             repr(value))

    def test_04d_no_block_timestamp_means_no_timing_claim(self):
        """Without a block there is nothing to be before, and the tool says so
        by not raising the code rather than by assuming the order was fine."""
        verdict = verify(intent_bytes(PAYER, PAYEE, "external",
                                      declared_at="2026-11-01T00:00:00Z"),
                         receipt_for(PAYER, PAYEE))
        self.assertIs(verdict["ok"], True)

    def test_04e_the_tool_holds_no_clock(self):
        """Checked against the parsed source, not by grepping the text.

        A grep for `datetime.now(` matches the module docstring, which says in
        words that it never calls one - so a text search would fail on the
        sentence that promises the thing it is checking. The AST sees calls.
        """
        import ast
        with open(SCRIPT, "r", encoding="utf-8") as fh:
            tree = ast.parse(fh.read(), filename=SCRIPT)
        banned = {"now", "utcnow", "today", "time", "monotonic", "time_ns"}
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                self.assertNotIn(node.func.attr, banned,
                                 "a clock call at line %d" % node.lineno)


class TheByteRule(unittest.TestCase):

    def test_05_the_intent_bytes_are_byte_exact(self):
        payload = intent_bytes(PAYER, PAYEE, "external")
        receipt, block = receipt_for(PAYER, PAYEE), block_for(PAYER, PAYEE)
        self.assertIs(verify(payload, receipt, block)["ok"], True)

        # One byte, mutated in place: the trailing newline becomes a space.
        # Still valid JSON, still the same object, and no longer the bytes that
        # were minted.
        mutated = payload[:-1] + b" "
        self.assertEqual(len(mutated), len(payload))
        self.assertEqual(json.loads(mutated.decode()), json.loads(payload.decode()))
        self.assertNotEqual(digest(mutated), digest(payload))
        verdict = verify(mutated, receipt, block)
        self.assertIs(verdict["ok"], False)
        self.assertEqual(verdict["reason"], "intent_digest_mismatch")

        # The digest is over the bytes and not over the object: the same object
        # re-serialised with indent=2 digests differently and is refused.
        obj = json.loads(payload.decode("utf-8"))
        pretty = (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode("utf-8")
        self.assertNotEqual(digest(pretty), digest(payload))
        self.assertEqual(verify(pretty, receipt, block)["reason"],
                         "intent_digest_mismatch")

    def test_05b_a_digest_held_elsewhere_can_pin_the_file(self):
        """Without `--intent-digest`, E-06 can only mean "these bytes are not
        canonical". With it, it means "these are not the bytes you were told
        about", which is the question a stranger actually has."""
        payload = intent_bytes(PAYER, PAYEE, "external")
        receipt = receipt_for(PAYER, PAYEE)
        self.assertIs(verify(payload, receipt, intent_digest=digest(payload))["ok"],
                      True)
        other = digest(intent_bytes(PAYER, THIRD, "external"))
        verdict = verify(payload, receipt, intent_digest=other)
        self.assertEqual(verdict["reason"], "intent_digest_mismatch")
        self.assertEqual(verdict["intent_digest"], digest(payload))

    def test_05c_a_value_mutation_is_caught_as_a_different_intent(self):
        """The honest limit of the canonicality check, stated as a test.

        A mutation inside a value leaves the file canonical, so it is NOT
        `intent_digest_mismatch` - it is a different intent, and the binding
        checks say which field moved. Both paths refuse; they refuse for
        different, stated reasons, and a test that claimed otherwise would pass
        for a reason unrelated to what it asserts.
        """
        payload = intent_bytes(PAYER, PAYEE, "external")
        moved = payload.replace(b'"amount_raw":"7', b'"amount_raw":"8')
        self.assertNotEqual(moved, payload)
        self.assertEqual(serialise(json.loads(moved.decode())), moved,
                         "the mutated file is still canonical, which is the point")
        verdict = verify(moved, receipt_for(PAYER, PAYEE), block_for(PAYER, PAYEE))
        self.assertIs(verdict["ok"], False)
        self.assertEqual(verdict["reason"], "amount_mismatch")

    def test_05d_declare_writes_exactly_what_it_digests(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "intent.json")
            done = run("declare", "--job-id", JOB, "--payer-account", PAYER,
                       "--payee-account", PAYEE, "--counterparty-class", "external",
                       "--amount-raw", RAW, "--declared-at", DECLARED, "--out", out)
            self.assertEqual(done.returncode, 0, done.stderr)
            written = open(out, "rb").read()
        reference = json.loads(done.stdout)
        self.assertEqual(reference["intent_digest"], digest(written))
        self.assertEqual(reference["bytes"], len(written))
        self.assertEqual(written, serialise(json.loads(written.decode())))
        self.assertTrue(written.endswith(b"}\n"))
        self.assertNotIn(b", ", written, "the canonical form carries no spaces")


class TheClassIsAssertedNeverInferred(unittest.TestCase):

    def test_06_no_class_is_an_error_not_a_default(self):
        done = run("declare", "--job-id", JOB, "--payer-account", PAYER,
                   "--payee-account", PAYEE, "--amount-raw", RAW,
                   "--declared-at", DECLARED)
        self.assertEqual(done.returncode, 2)
        self.assertEqual(json.loads(done.stderr)["error"],
                         "counterparty_class_absent")
        # A tool that guesses `external` is worse than no tool.
        self.assertNotIn("external", done.stdout)
        self.assertNotIn('"external"', done.stderr)

    def test_06b_absent_and_wrong_are_different_mistakes(self):
        with self.assertRaises(Refusal) as absent:
            declare(JOB, PAYER, PAYEE, None, RAW, DECLARED)
        self.assertEqual(absent.exception.code, "counterparty_class_absent")
        for bad in ("buyer", "EXTERNAL", "", "Self", 1, True, ["external"]):
            with self.assertRaises(Refusal) as wrong:
                declare(JOB, PAYER, PAYEE, bad, RAW, DECLARED)
            self.assertEqual(wrong.exception.code, "bad_counterparty_class", repr(bad))

    def test_06c_declare_records_a_contradiction_rather_than_refusing_it(self):
        """`declare` is a recorder, not a judge.

        An `external` intent naming one account twice is minted without
        complaint, because the design is that the assertion is held still and
        read back later - so the contradiction is a violation found by `verify`,
        not a typo caught at the keyboard. The spending side may write down
        something false; what it cannot do is write it down afterwards.
        """
        _, payload, reference = declare(JOB, PAYER, PAYER, "external", RAW, DECLARED)
        self.assertEqual(reference["counterparty_class"], "external")
        self.assertEqual(verify(payload, receipt_for(PAYER, PAYER))["reason"],
                         "declared_external_settled_self")


class OperatorIsNeverObserved(unittest.TestCase):

    def test_07_operator_is_never_observed(self):
        doc = json.load(open(VECTOR, "r", encoding="utf-8"))
        self.assertGreaterEqual(len(doc["classify_pairs"]), 4)
        for pair in doc["classify_pairs"]:
            told = classify(pair["payer_account"], pair["payee_account"])
            self.assertIn(told["observed_class"], OBSERVABLE)
            self.assertNotEqual(told["observed_class"], "operator")
            self.assertEqual(told["observed_class"], pair["observed_class"],
                             pair["why"])
            self.assertIs(told["same_account"], pair["same_account"])
        self.assertEqual(tuple(doc["classes"]), CLASSES)
        self.assertNotIn("operator", doc["observable_classes"])

    def test_07b_a_declared_operator_row_is_not_evidence_of_a_sale(self):
        verdict = verify(intent_bytes(PAYER, PAYEE, "operator"),
                         receipt_for(PAYER, PAYEE), block_for(PAYER, PAYEE))
        self.assertIs(verdict["ok"], True)
        self.assertEqual(verdict["reason"],
                         "declared_operator_not_checkable_on_ledger")
        self.assertIs(verdict["halt"], False)
        self.assertIn("NOT external", verdict["note"])

    def test_07c_classify_says_the_limit_out_loud(self):
        told = classify(PAYER, PAYEE)
        self.assertTrue(any("never an observed class" in n for n in told["notes"]))
        self.assertIn("never an observed class", run("--help").stdout)

    def test_07d_classify_through_the_cli(self):
        done = run("classify", "--payer-account", PAYEE,
                   "--payee-account", PAYEE_XRB)
        self.assertEqual(done.returncode, 0, done.stderr)
        told = json.loads(done.stdout)
        self.assertEqual(told["observed_class"], "self")
        self.assertIs(told["same_account"], True)


class MoneyIsComparedByValue(unittest.TestCase):

    def test_08_amount_is_compared_by_value(self):
        payload = intent_bytes(PAYER, PAYEE, "external", amount=RAW)
        padded = receipt_for(PAYER, PAYEE, settled_raw="0" + RAW)
        self.assertNotEqual(padded["settled_raw"], RAW)
        verdict = verify(payload, padded, block_for(PAYER, PAYEE))
        self.assertIs(verdict["ok"], True)
        self.assertNotEqual(verdict["reason"], "amount_mismatch")

    def test_08b_leading_zeros_declare_byte_identical_intents(self):
        self.assertEqual(intent_bytes(PAYER, PAYEE, "external", amount="0" + RAW),
                         intent_bytes(PAYER, PAYEE, "external", amount=RAW))

    def test_08c_a_float_amount_is_refused_not_coerced(self):
        """1 XNO is 10**30 raw, so a float cannot hold an amount without losing
        its low digits. Refused rather than rounded."""
        for bad in (0.07, 7e28, "7e28", "70_000", "-70", "", "٧٠", True,
                    None, [RAW], "7.0"):
            with self.assertRaises(Refusal) as caught:
                declare(JOB, PAYER, PAYEE, "external", bad, DECLARED)
            self.assertEqual(caught.exception.code, "amount_not_integer_string",
                             repr(bad))

    def test_08e_surrounding_whitespace_is_normalised_not_refused(self):
        """Rule 5 says reuse `canonical`, and `canonical.raw_amount` strips.

        Asserted rather than left implicit, because it is a decision: a padded
        amount names the same number, so it is written down in the one spelling
        this file emits and the digest stays a property of the amount. No
        spelling can change which amount is meant - every comparison here is by
        value. An Arabic-Indic "٧٠" is still refused: `isascii` is the guard
        that keeps `isdigit` from admitting a number `int()` would not read.
        """
        padded = intent_bytes(PAYER, PAYEE, "external", amount=" " + RAW + "\n")
        self.assertEqual(padded, intent_bytes(PAYER, PAYEE, "external", amount=RAW))
        self.assertIn(b'"amount_raw":"' + RAW.encode(), padded)

    def test_08d_a_real_amount_difference_still_refuses(self):
        verdict = verify(intent_bytes(PAYER, PAYEE, "external"),
                         receipt_for(PAYER, PAYEE, settled_raw="1"),
                         block_for(PAYER, PAYEE))
        self.assertEqual(verdict["reason"], "amount_mismatch")


class EveryCodeHasAControl(unittest.TestCase):

    def test_09_self_test_exits_zero_and_lists_its_negative_controls(self):
        done = run("--self-test")
        self.assertEqual(done.returncode, 0, done.stderr)
        report = json.loads(done.stdout)
        self.assertEqual(report["self_test"], "pass")
        self.assertEqual(report["failures"], [])
        self.assertEqual(report["codes_never_evaluated"], [])
        self.assertGreaterEqual(report["negative_controls"], 9)
        self.assertIs(report["positive_control"]["ok"], True)

    def test_09b_self_test_is_hermetic_in_process(self):
        self.assertEqual(main(["--self-test"]), 0)

    def test_10_every_reason_code_has_a_positive_or_negative_control(self):
        """A code no test reaches is a build failure.

        Mirrors `authority_receipt`'s `codes_never_evaluated`: each control is
        driven here, in this file, so adding a code without a control turns
        this test red rather than passing silently.
        """
        payload = intent_bytes(PAYER, PAYEE, "external")
        receipt, block = receipt_for(PAYER, PAYEE), block_for(PAYER, PAYEE)

        verdicts = {
            "declared_class_matches_observed":
                lambda: verify(payload, receipt, block),
            "declared_self_settled_external":
                lambda: verify(intent_bytes(PAYER, PAYEE, "self"), receipt, block),
            "declared_operator_not_checkable_on_ledger":
                lambda: verify(intent_bytes(PAYER, PAYEE, "operator"), receipt,
                               block),
            "declared_external_settled_self":
                lambda: verify(intent_bytes(PAYER, PAYER, "external"),
                               receipt_for(PAYER, PAYER), block_for(PAYER, PAYER)),
            "intent_declared_after_settlement":
                lambda: verify(intent_bytes(PAYER, PAYEE, "external",
                                            declared_at="2026-10-04T06:05:01Z"),
                               receipt, block),
            "job_id_mismatch":
                lambda: verify(payload, receipt_for(PAYER, PAYEE, job_id="other"),
                               block),
            "amount_mismatch":
                lambda: verify(payload, receipt_for(PAYER, PAYEE, settled_raw="1"),
                               block),
            "payer_mismatch":
                lambda: verify(payload, receipt, block_for(THIRD, PAYEE)),
            "payee_mismatch":
                lambda: verify(payload, receipt, block_for(PAYER, THIRD)),
            "intent_digest_mismatch":
                lambda: verify(payload[:-1] + b" ", receipt, block),
        }
        refusals = {
            "bad_intent_shape": lambda: verify(b"{}\n", receipt),
            "bad_receipt_shape": lambda: verify(payload, ["not", "a", "receipt"]),
            "bad_counterparty_class":
                lambda: declare(JOB, PAYER, PAYEE, "buyer", RAW, DECLARED),
            "counterparty_class_absent":
                lambda: declare(JOB, PAYER, PAYEE, None, RAW, DECLARED),
            "unreadable_payer_account":
                lambda: declare(JOB, "nano_nope", PAYEE, "external", RAW, DECLARED),
            "unreadable_payee_account":
                lambda: declare(JOB, PAYER, "nano_nope", "external", RAW, DECLARED),
            "amount_not_integer_string":
                lambda: declare(JOB, PAYER, PAYEE, "external", 0.07, DECLARED),
        }

        self.assertEqual(sorted(set(verdicts) | set(refusals)),
                         sorted(set(REASON_CODES)),
                         "a reason code has no control, or a control names a "
                         "code the module does not define")

        for code, trigger in verdicts.items():
            self.assertEqual(trigger()["reason"], code)
        for code, trigger in refusals.items():
            with self.assertRaises(Refusal) as caught:
                trigger()
            self.assertEqual(caught.exception.code, code)

    def test_10b_several_failures_are_all_reported(self):
        """A row that fails three ways should not look like it fails one."""
        verdict = verify(intent_bytes(PAYER, PAYEE, "external"),
                         receipt_for(THIRD, PAYEE, job_id="other", settled_raw="1"),
                         None)
        self.assertEqual(verdict["reason"], "job_id_mismatch")
        self.assertEqual(sorted(verdict["also"]),
                         ["amount_mismatch", "payer_mismatch"])

    def test_10c_binding_is_established_before_the_class_is_judged(self):
        """An intent that does not describe this settlement cannot accuse it.

        Reporting `declared_external_settled_self` from a row whose job id does
        not even match would be an accusation drawn from the wrong record.
        """
        verdict = verify(intent_bytes(PAYER, PAYER, "external"),
                         receipt_for(PAYER, PAYER, job_id="some-other-job"),
                         block_for(PAYER, PAYER))
        self.assertEqual(verdict["reason"], "job_id_mismatch")
        self.assertIn("declared_external_settled_self", verdict["also"])
        self.assertIs(verdict["ok"], False)


class ErrorPathsAndHousekeeping(unittest.TestCase):

    def test_11_nothing_raises_an_uncaught_traceback_on_bad_input(self):
        receipt = receipt_for(PAYER, PAYEE)
        for payload in (b"", b"null\n", b"[]\n", b"{\n", b"\xff\xfe",
                        b'{"v":"counterparty-role-v1"}\n',
                        serialise({"v": "wrong"})):
            with self.assertRaises(Refusal) as caught:
                verify(payload, receipt)
            self.assertEqual(caught.exception.code, "bad_intent_shape", repr(payload))

    def test_11b_an_intent_carrying_an_unreadable_account_refuses(self):
        good = json.loads(intent_bytes(PAYER, PAYEE, "external").decode())
        for key, code in (("payer_account", "unreadable_payer_account"),
                          ("payee_account", "unreadable_payee_account")):
            broken = dict(good)
            broken[key] = PAYEE[:-1] + ("a" if PAYEE[-1] != "a" else "b")
            with self.assertRaises(Refusal) as caught:
                verify(serialise(broken), receipt_for(PAYER, PAYEE))
            self.assertEqual(caught.exception.code, code)

    def test_11c_a_missing_file_is_exit_2_not_a_traceback(self):
        done = run("verify", "--intent", "/nonexistent/i.json",
                   "--receipt", "/nonexistent/r.json")
        self.assertEqual(done.returncode, 2)
        self.assertEqual(json.loads(done.stderr)["error"], "bad_intent_shape")

    def test_11d_no_command_is_exit_2(self):
        self.assertEqual(run().returncode, 2)

    def test_12_a_block_that_is_not_a_send_establishes_no_destination(self):
        """Fail closed: an unestablished payee refuses through `payee_mismatch`
        and the observed class is reported as unknown rather than guessed.
        Naming `external` here would invent the one claim this tool checks."""
        block = block_for(PAYER, PAYEE)
        block["subtype"] = "receive"
        verdict = verify(intent_bytes(PAYER, PAYEE, "external"),
                         receipt_for(PAYER, PAYEE), block)
        self.assertIs(verdict["ok"], False)
        self.assertEqual(verdict["reason"], "payee_mismatch")
        self.assertIsNone(verdict["observed_class"])

    def test_12b_a_top_level_link_as_account_is_read_too(self):
        block = {"hash": BLOCK_HASH, "amount": RAW, "block_account": PAYER,
                 "subtype": "send", "confirmed": "true",
                 "local_timestamp": SETTLED, "link_as_account": PAYEE}
        self.assertIs(verify(intent_bytes(PAYER, PAYEE, "external"),
                             receipt_for(PAYER, PAYEE), block)["ok"], True)

    def test_12c_the_block_outranks_the_receipt(self):
        """When both are given the ledger is read, and the verdict says so.

        A receipt is written by a party to the payment; a block is not. If the
        receipt claims an external payee and the chain shows the money went
        home, the chain wins.
        """
        verdict = verify(intent_bytes(PAYER, PAYER, "external"),
                         receipt_for(PAYER, PAYEE), block_for(PAYER, PAYER))
        self.assertEqual(verdict["observed_from"], "block")
        self.assertEqual(verdict["reason"], "declared_external_settled_self")

    def test_13_nothing_on_the_import_graph_can_reach_the_network(self):
        for entry in counterparty_role.import_graph():
            self.assertNotIn(entry["module"].split(".")[0], NETWORK_MODULES,
                             "%s imported in %s" % (entry["module"], entry["function"]))

    def test_13b_the_new_files_hold_no_standalone_64_hex_run(self):
        """validate.py's secret gate must stay green on what we just added."""
        import validate
        for name in ("counterparty_role.py", "vectors/counterparty-role-v1.json",
                     "tests/test_counterparty_role.py"):
            with open(os.path.join(ROOT, name), "r", encoding="utf-8") as fh:
                self.assertIsNone(validate.SECRET_RE.search(fh.read()), name)

    def test_14_the_vector_reproduces_byte_for_byte(self):
        """The whole purpose of the vector: another implementation that writes
        these bytes agrees with this one."""
        doc = json.load(open(VECTOR, "r", encoding="utf-8"))
        inputs = doc["inputs"]
        intent, payload, reference = declare(
            job_id=inputs["job_id"], payer_account=inputs["payer_account"],
            payee_account=inputs["payee_account"],
            cp_class=inputs["counterparty_class"],
            amount_raw=inputs["amount_raw"], declared_at=inputs["declared_at"])
        self.assertEqual(payload.decode("utf-8"), doc["bytes"])
        self.assertEqual(intent, doc["intent"])
        self.assertEqual(len(payload), doc["byte_count"])
        self.assertEqual(reference["intent_digest"],
                         "".join(doc["intent_digest_halves"]))
        self.assertEqual(len(reference["intent_digest"]), 64)
        self.assertTrue(re.fullmatch(r"[0-9a-f]{64}", reference["intent_digest"]))

    def test_14b_every_vector_verify_case_holds(self):
        doc = json.load(open(VECTOR, "r", encoding="utf-8"))
        self.assertGreaterEqual(len(doc["verify_cases"]), 6)
        for case in doc["verify_cases"]:
            payee = PAYER if case["observed_class"] == "self" else PAYEE
            declared_at = ("2026-10-04T06:05:01Z"
                           if case["reason"] == "intent_declared_after_settlement"
                           else DECLARED)
            verdict = verify(
                intent_bytes(PAYER, payee, case["declared_class"],
                             declared_at=declared_at),
                receipt_for(PAYER, payee), block_for(PAYER, payee))
            self.assertEqual(verdict["reason"], case["reason"], case["name"])
            self.assertIs(verdict["ok"], case["ok"], case["name"])
            self.assertIs(verdict["halt"], case["halt"], case["name"])

    def test_15_the_tool_does_not_claim_the_work_was_real(self):
        """The limit moltbookrevenueagent stated themselves, carried in the
        output rather than only in a docstring."""
        told = classify(PAYER, PAYEE)
        self.assertTrue(any("not that the invoice described real work" in n
                            for n in told["notes"]))
        self.assertIn("not that the invoice described real work", run("--help").stdout)


if __name__ == "__main__":
    unittest.main()
