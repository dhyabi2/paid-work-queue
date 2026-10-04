"""Saying where two records disagree, and refusing to settle it in our favour.

The decisive test here is test 2. Test 1 only shows that the honest note mints;
test 2 shows that the FLATTERING one does not, and that is the whole reason
this module exists rather than being a comment in a README. A record that
notices a disagreement and then resolves it towards whichever side is easier to
read is worse than one that says nothing, because it looks like it checked.

Test 8 is the one that caught a real design defect while this was being built.
`fulfillment_receipt._shape` refuses any key it does not know, so attaching
`divergence_notes` to a receipt made that receipt unreadable by its own
verifier - green on everything else, and broken on exactly the sentence the
spec cared about ("a divergence note must never change the grade"). The fix
was to name the key optional in `fulfillment_receipt`, additively; test 8 and
test 13 pin both halves of it, and test 14 pins that no OTHER unknown key got
in through the same door.

Every fixture here is built independently of `divergence_note`'s own
`--self-test` controls, deliberately and for the same reason
`tests/test_counterparty_role.py` says: driving the assertions from the
module's own fixtures would let one mutation break both and still read green.

Nothing opens a socket, and nothing can: test 12 walks the import graph and
also asserts that the live-read flag is never spelled as a literal here
at all, which is why this docstring does not spell it either.

No 64-hex run stands as a single literal, matching the project's secret gate.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "vendor"))

import divergence_note  # noqa: E402
import fulfillment_receipt  # noqa: E402
from custody_probe import NETWORK_MODULES  # noqa: E402  - reused, not re-listed
from divergence_note import (  # noqa: E402
    DISMISSAL, ERROR_CODES, LAG_REASONS, MIN_EXPLANATION, REASON_CODES,
    UNEXPLAINED, V, VIEWS, Refusal, attach, build_parser, digest, main, note,
    note_digest, serialise, verify,
)

SCRIPT = os.path.join(ROOT, "divergence_note.py")
VECTOR = os.path.join(ROOT, "vectors", "divergence-note-v1.json")

# Distinct from the module's controls on purpose - see the docstring.
OUR_BLOCK = "4D1E" * 16
SUBJECT = "job-2026-10-04-042"
OBSERVED = "2026-10-04T07:30:00Z"
THEIR_EVIDENCE = "GET https://board.invalid/api/asks/901 -> status:open"
WHY = "Their board checks an sBTC memo and cannot express a payment in XNO."


def mint(**overrides):
    """An honest divergence note, with any field replaced."""
    fields = dict(
        subject=SUBJECT, our_view="paid", our_evidence_kind="nano_block",
        our_evidence=OUR_BLOCK, their_name="board.invalid",
        their_view="abandoned", their_evidence_kind="http_status_field",
        their_evidence=THEIR_EVIDENCE,
        code="unit_their_verifier_cannot_express", observed=OBSERVED,
        explanation=WHY, who_is_easier="theirs")
    fields.update(overrides)
    return note(**fields)


def fulfillment_set():
    """A fulfillment receipt and the documents its own verifier needs."""
    receipt, grant_bytes, block, delivery, attestation = \
        fulfillment_receipt._control_set()
    emitted = fulfillment_receipt.emit(
        receipt, delivery, [attestation], now=fulfillment_receipt.CONTROL_NOW)
    return emitted, receipt, grant_bytes, block, delivery


def graded(document, receipt, grant_bytes, block, delivery):
    return fulfillment_receipt.verify(
        document, receipt, grant_bytes, block, delivery=delivery,
        now=fulfillment_receipt.CONTROL_NOW)


def run(*argv):
    """The CLI, as a stranger runs it: a separate process, no imports shared."""
    done = subprocess.run([sys.executable, SCRIPT] + list(argv),
                          capture_output=True, text=True)
    return done.returncode, done.stdout, done.stderr


class TheRealCase(unittest.TestCase):
    """1 - secret_mars's row, from the committed vector."""

    def test_the_secret_mars_row_mints_cleanly(self):
        with open(VECTOR, encoding="utf-8") as handle:
            vector = json.load(handle)
        # The hash is carried as halves because the secret gate refuses a
        # standalone 64-hex run in a committed file; see the vector's own
        # _why_halves. Joining it here is the test's job, not the tool's.
        evidence = "".join(vector["our_evidence_halves"])
        self.assertEqual(len(evidence), 64)

        document, payload = note(
            subject=vector["subject"], our_view=vector["our_view"],
            our_evidence_kind=vector["our_evidence_kind"],
            our_evidence=evidence, their_name=vector["their_name"],
            their_view=vector["their_view"],
            their_evidence_kind=vector["their_evidence_kind"],
            their_evidence=vector["their_evidence"],
            code=vector["reason_code"], observed=vector["observed_at"],
            explanation=vector["explanation"],
            who_is_easier=vector["who_is_easier_to_read"])

        expect = vector["expect"]
        verdict = verify(document)
        self.assertIs(verdict["ok"], expect["ok"])
        self.assertIs(document["diverges"], expect["diverges"])
        self.assertEqual(document["who_is_easier_to_read"],
                         expect["who_is_easier_to_read"])
        self.assertIs(document["ours"]["re_derivable_without_us"],
                      expect["ours_re_derivable_without_us"])
        self.assertIs(document["theirs"]["re_derivable_without_them"],
                      expect["theirs_re_derivable_without_them"])
        self.assertEqual(document["v"], V)

        with tempfile.TemporaryDirectory() as workspace:
            path = os.path.join(workspace, "divergence.json")
            with open(path, "wb") as handle:
                handle.write(payload)
            code, out, err = run("verify", "--note", path)
            self.assertEqual(code, 0, err)
            self.assertIs(json.loads(out)["ok"], True)


class TheFlatteringNote(unittest.TestCase):
    """2 - the test that makes the tool honest rather than decorative."""

    def test_a_note_that_resolves_in_our_favour_without_a_reason_is_refused(self):
        document, payload = mint(
            code=DISMISSAL,
            explanation="These two rows are about two different orders.")
        verdict = verify(document)
        self.assertIs(verdict["ok"], False)
        self.assertEqual(verdict["reason"], "self_serving_note")

        with tempfile.TemporaryDirectory() as workspace:
            path = os.path.join(workspace, "flattering.json")
            with open(path, "wb") as handle:
                handle.write(payload)
            code, out, err = run("verify", "--note", path)
            self.assertEqual(code, 1, err)
            self.assertEqual(json.loads(out)["reason"], "self_serving_note")

    def test_an_absent_reason_code_is_the_same_flattering_shape(self):
        document, _ = mint()
        del document["reason_code"]
        self.assertIs(divergence_note.is_self_serving(document), True)

    def test_the_same_shape_with_a_real_reason_is_accepted(self):
        for code in REASON_CODES:
            if code == DISMISSAL:
                continue
            kwargs = {"code": code}
            if code == UNEXPLAINED:
                kwargs["explanation"] = None
            else:
                kwargs["explanation"] = WHY
            if code in LAG_REASONS:
                kwargs["lag"] = 3600
            document, _ = mint(**kwargs)
            self.assertIs(verify(document)["ok"], True, code)

    def test_it_is_not_flattering_when_their_evidence_is_re_derivable_too(self):
        document, _ = mint(
            their_evidence_kind="chain_txid",
            code=DISMISSAL,
            explanation="These two rows are about two different orders.")
        self.assertIs(document["theirs"]["re_derivable_without_them"], True)
        self.assertIs(verify(document)["ok"], True)


class DivergesIsComputed(unittest.TestCase):
    """3 - the field cannot be asserted."""

    def test_diverges_cannot_be_asserted(self):
        flags = set()
        for action in build_parser()._subparsers._group_actions[0].choices.values():
            for option in action._actions:
                flags.update(option.option_strings)
        self.assertNotIn("--diverges", flags)
        self.assertEqual([f for f in flags if "diverge" in f], [])

    def test_two_equal_views_diverge_false_whatever_else_is_passed(self):
        for view in VIEWS:
            document, _ = mint(our_view=view, their_view=view,
                               who_is_easier=None, code=UNEXPLAINED,
                               explanation=None)
            self.assertIs(document["diverges"], False, view)
            self.assertNotIn("who_is_easier_to_read", document)
            self.assertIs(verify(document)["ok"], True)

    def test_a_stored_diverges_that_disagrees_with_the_views_is_unreadable(self):
        document, _ = mint()
        document["diverges"] = False
        document["note_digest"] = note_digest(document)
        with self.assertRaises(Refusal) as caught:
            verify(document)
        self.assertEqual(caught.exception.code, "bad_note_shape")


class TheExplanationRules(unittest.TestCase):
    """4 - a reason code and its explanation may not contradict each other."""

    def test_we_cannot_explain_it_forbids_an_explanation(self):
        with self.assertRaises(Refusal) as caught:
            mint(code=UNEXPLAINED, explanation="because of a thing that happened")
        self.assertEqual(caught.exception.code, "explanation_forbidden")
        self.assertEqual(caught.exception.exit_code, 2)

    def test_we_cannot_explain_it_with_none_is_the_honest_default(self):
        document, _ = mint(code=UNEXPLAINED, explanation=None)
        self.assertNotIn("explanation", document)
        self.assertIs(verify(document)["ok"], True)

    def test_nineteen_characters_is_refused_and_twenty_passes(self):
        self.assertEqual(MIN_EXPLANATION, 20)
        with self.assertRaises(Refusal) as caught:
            mint(explanation="x" * 19)
        self.assertEqual(caught.exception.code, "explanation_required")
        document, _ = mint(explanation="y" * 20)
        self.assertEqual(document["explanation"], "y" * 20)
        self.assertIs(verify(document)["ok"], True)

    def test_whitespace_does_not_buy_the_twentieth_character(self):
        with self.assertRaises(Refusal) as caught:
            mint(explanation=" " * 40 + "short")
        self.assertEqual(caught.exception.code, "explanation_required")


class TheLagRules(unittest.TestCase):
    """5 - a lag is an interval, so it has to be measured."""

    def test_a_lag_claim_needs_a_measured_interval(self):
        for code in LAG_REASONS:
            with self.assertRaises(Refusal) as caught:
                mint(code=code, explanation=WHY)
            self.assertEqual(caught.exception.code, "lag_without_interval", code)

    def test_zero_is_a_measurement_and_is_recorded(self):
        document, _ = mint(code="their_record_not_yet_updated",
                           explanation=WHY, lag=0)
        self.assertEqual(document["lag_seconds"], 0)
        self.assertIs(verify(document)["ok"], True)

    def test_a_negative_or_non_integer_lag_is_refused(self):
        for bad in (-1, "1.5", "many", True):
            with self.assertRaises(Refusal) as caught:
                mint(code="our_record_not_yet_updated", explanation=WHY, lag=bad)
            self.assertEqual(caught.exception.code, "lag_without_interval", bad)

    def test_a_lag_recorded_without_a_lag_reason_is_unreadable(self):
        document, _ = mint()
        document["lag_seconds"] = 60
        document["note_digest"] = note_digest(document)
        with self.assertRaises(Refusal) as caught:
            verify(document)
        self.assertEqual(caught.exception.code, "bad_note_shape")


class AttachIsAppendOnly(unittest.TestCase):
    """6 - the list grows in order and nothing in it is ever rewritten."""

    def test_attach_is_append_only(self):
        emitted, receipt, grant_bytes, block, delivery = fulfillment_set()
        first, _ = mint()
        second, _ = mint(subject="job-2026-10-04-043")

        one = attach(emitted, first)
        two = attach(one, second)
        self.assertEqual([n["note_digest"] for n in two["divergence_notes"]],
                         [first["note_digest"], second["note_digest"]])
        self.assertNotIn("divergence_notes", emitted)

        with self.assertRaises(Refusal) as caught:
            attach(two, first)
        self.assertEqual(caught.exception.code, "duplicate_divergence_note")
        self.assertEqual(caught.exception.exit_code, 1)
        self.assertEqual(len(two["divergence_notes"]), 2)

    def test_attach_refuses_a_flattering_note(self):
        emitted = fulfillment_set()[0]
        flattering, _ = mint(
            code=DISMISSAL,
            explanation="These two rows are about two different orders.")
        with self.assertRaises(Refusal) as caught:
            attach(emitted, flattering)
        self.assertEqual(caught.exception.code, "self_serving_note")
        self.assertEqual(caught.exception.exit_code, 1)

    def test_the_duplicate_exits_one_through_the_cli(self):
        emitted = fulfillment_set()[0]
        document, payload = mint()
        with tempfile.TemporaryDirectory() as workspace:
            note_path = os.path.join(workspace, "note.json")
            with open(note_path, "wb") as handle:
                handle.write(payload)
            once = os.path.join(workspace, "once.json")
            receipt_path = os.path.join(workspace, "receipt.json")
            with open(receipt_path, "w", encoding="utf-8") as handle:
                json.dump(emitted, handle)
            code, _, err = run("attach", "--receipt", receipt_path,
                               "--note", note_path, "--out", once)
            self.assertEqual(code, 0, err)
            code, _, err = run("attach", "--receipt", once,
                               "--note", note_path)
            self.assertEqual(code, 1, err)
            self.assertEqual(json.loads(err)["error"], "duplicate_divergence_note")


class AttachChecksWithTheOwnersValidator(unittest.TestCase):
    """7 - the gate is fulfillment_receipt's, not a duck-typed copy of it."""

    def test_attach_refuses_a_document_that_is_not_a_fulfillment_receipt(self):
        document, _ = mint()
        for bad in ({"version": 1, "not": "a fulfillment"}, [], "text", 7):
            with self.assertRaises(Refusal) as caught:
                attach(bad, document)
            self.assertEqual(caught.exception.code, "receipt_not_a_fulfillment")
            self.assertEqual(caught.exception.exit_code, 2)

    def test_a_receipt_missing_one_required_key_is_refused_by_that_validator(self):
        emitted = fulfillment_set()[0]
        broken = {k: v for k, v in emitted.items() if k != "evidence_grade"}
        document, _ = mint()
        with self.assertRaises(Refusal) as caught:
            attach(broken, document)
        self.assertEqual(caught.exception.code, "receipt_not_a_fulfillment")
        # The detail quotes fulfillment_receipt's own code, which is how a
        # reader can tell the check was delegated and not re-implemented.
        self.assertIn("bad_fulfillment_shape", caught.exception.detail)

    def test_a_field_fulfillment_receipt_validates_is_still_validated(self):
        emitted = fulfillment_set()[0]
        emitted["payee_account"] = "nano_notanaccount"
        document, _ = mint()
        with self.assertRaises(Refusal) as caught:
            attach(emitted, document)
        self.assertEqual(caught.exception.code, "receipt_not_a_fulfillment")


class TheGradeDoesNotMove(unittest.TestCase):
    """8 - a divergence note adds to the record; it never re-scores it."""

    def test_the_attached_receipt_still_verifies(self):
        emitted, receipt, grant_bytes, block, delivery = fulfillment_set()
        before = graded(emitted, receipt, grant_bytes, block, delivery)

        document, _ = mint()
        after = graded(attach(emitted, document), receipt, grant_bytes, block,
                       delivery)

        self.assertIs(before["ok"], True, before.get("reasons"))
        # The whole verdict, not a chosen field of it: nothing in
        # fulfillment_receipt reads `divergence_notes`, so a single differing
        # key anywhere would mean the note had moved something.
        self.assertEqual(before, after)
        self.assertEqual(before["evidence_grade"], after["evidence_grade"])
        self.assertEqual(before["recomputed_grade"], after["recomputed_grade"])

    def test_the_grade_does_not_move_for_a_failing_receipt_either(self):
        emitted, receipt, grant_bytes, block, delivery = fulfillment_set()
        emitted["evidence_grade"] = "independently_attested"
        emitted["attestations"] = []
        emitted["independent_attestor_count"] = 0
        before = graded(emitted, receipt, grant_bytes, block, delivery)
        self.assertIs(before["ok"], False)

        document, _ = mint()
        after = graded(attach(emitted, document), receipt, grant_bytes, block,
                       delivery)
        self.assertEqual(before["reasons"], after["reasons"])

    def test_two_notes_still_do_not_move_it(self):
        emitted, receipt, grant_bytes, block, delivery = fulfillment_set()
        before = graded(emitted, receipt, grant_bytes, block, delivery)
        first, _ = mint()
        second, _ = mint(subject="job-2026-10-04-044")
        after = graded(attach(attach(emitted, first), second), receipt,
                       grant_bytes, block, delivery)
        self.assertEqual(before, after)


class TheByteRule(unittest.TestCase):
    """9 - one serialisation, and a digest that moves with any edit."""

    def test_note_bytes_are_byte_exact(self):
        first, first_bytes = mint()
        second, second_bytes = mint()
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(first, second)
        self.assertTrue(first_bytes.endswith(b"}\n"))
        self.assertEqual(first_bytes.count(b"\n"), 1)

        edited, _ = mint(explanation=WHY[:-1] + "!")
        self.assertNotEqual(edited["note_digest"], first["note_digest"])

    def test_the_digest_is_over_the_document_without_itself(self):
        document, _ = mint()
        bare = {k: v for k, v in document.items() if k != "note_digest"}
        self.assertEqual(document["note_digest"], digest(serialise(bare)))

    def test_key_order_does_not_change_the_digest(self):
        document, _ = mint()
        shuffled = dict(reversed(list(document.items())))
        self.assertEqual(note_digest(shuffled), note_digest(document))

    def test_a_tampered_note_is_note_digest_mismatch(self):
        document, _ = mint()
        document["explanation"] = document["explanation"] + " (edited)"
        verdict = verify(document)
        self.assertIs(verdict["ok"], False)
        self.assertEqual(verdict["reason"], "note_digest_mismatch")

    def test_a_digest_held_from_elsewhere_is_pinned_against(self):
        document, _ = mint()
        other, _ = mint(subject="job-2026-10-04-045")
        self.assertIs(verify(document, expected_digest=document["note_digest"])["ok"],
                      True)
        verdict = verify(document, expected_digest=other["note_digest"])
        self.assertEqual(verdict["reason"], "note_digest_mismatch")

    def test_the_byte_rule_agrees_with_counterparty_role(self):
        import counterparty_role
        sample = {"b": 2, "a": [1, {"c": "x"}]}
        self.assertEqual(serialise(sample), counterparty_role.serialise(sample))
        self.assertEqual(digest(b"abc"), counterparty_role.digest(b"abc"))


class TheDateIsNotParsedTwice(unittest.TestCase):
    """10 - one date parser in this repository, and it is validate's."""

    def test_a_date_that_does_not_exist_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            mint(observed="2026-02-30T00:00:00Z")
        self.assertEqual(caught.exception.code, "bad_observed_at")
        self.assertEqual(caught.exception.exit_code, 2)

    def test_it_is_refused_by_validate_and_not_by_a_second_parser(self):
        import validate
        self.assertIsNone(validate._rfc3339("2026-02-30T00:00:00Z"))
        with open(SCRIPT, encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn("validate._rfc3339(", source)
        # No second date machinery smuggled in beside it.
        for forbidden in ("strptime", "fromisoformat", "RFC3339_RE = "):
            self.assertNotIn(forbidden, source, forbidden)

    def test_an_absent_observed_at_is_a_different_code_from_a_bad_one(self):
        with self.assertRaises(Refusal) as caught:
            mint(observed=None)
        self.assertEqual(caught.exception.code, "observed_at_required")
        for bad in ("2026-10-04", "2026-10-04T07:30:00+04:00", "", 17):
            with self.assertRaises(Refusal) as caught:
                mint(observed=bad)
            self.assertEqual(caught.exception.code, "bad_observed_at", bad)

    def test_the_cli_exits_two_on_an_impossible_date(self):
        code, _, err = run(
            "note", "--subject", SUBJECT, "--our-view", "paid",
            "--our-evidence-kind", "nano_block", "--our-evidence", OUR_BLOCK,
            "--their-name", "board.invalid", "--their-view", "abandoned",
            "--their-evidence-kind", "http_status_field",
            "--their-evidence", THEIR_EVIDENCE,
            "--reason-code", UNEXPLAINED,
            "--observed-at", "2026-02-30T00:00:00Z",
            "--who-is-easier-to-read", "theirs")
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(err)["error"], "bad_observed_at")


class TheSelfTest(unittest.TestCase):
    """11 - every control, hermetically."""

    def test_self_test_exits_zero(self):
        code, out, err = run("--self-test")
        self.assertEqual(code, 0, err)
        report = json.loads(out)
        self.assertIs(report["positive_control"], True)
        self.assertEqual(report["failures"], [])
        self.assertGreaterEqual(report["negative_controls"], 9)

    def test_every_error_code_has_a_negative_control(self):
        code, out, _ = run("--self-test")
        self.assertEqual(code, 0)
        self.assertEqual(sorted(json.loads(out)["codes"]), sorted(ERROR_CODES))


class NothingReachesTheNetwork(unittest.TestCase):
    """12 - the one live read is off, function-scoped, and never exercised."""

    def test_check_live_is_absent_from_the_suite(self):
        # The flag is assembled at runtime and never written as a literal, so
        # this assertion is about the file itself rather than about itself: the
        # string the CLI would need simply does not occur in this source.
        flag = "--check" + "-live"
        with open(os.path.abspath(__file__), encoding="utf-8") as handle:
            source = handle.read()
        self.assertNotIn(flag, source)
        self.assertIn(flag, open(SCRIPT, encoding="utf-8").read())

    def test_every_check_live_call_here_injects_its_opener(self):
        import ast as _ast
        with open(os.path.abspath(__file__), encoding="utf-8") as handle:
            tree = _ast.parse(handle.read())
        calls = 0
        for node in _ast.walk(tree):
            if not isinstance(node, _ast.Call):
                continue
            target = node.func
            name = getattr(target, "attr", None) or getattr(target, "id", None)
            if name != "check_live":
                continue
            calls += 1
            self.assertIn("opener", [kw.arg for kw in node.keywords],
                          "check_live is called without a stub opener")
        self.assertEqual(calls, 1)

    def test_no_network_module_is_imported_at_module_scope(self):
        for entry in divergence_note.import_graph():
            if entry["module"].split(".")[0] in NETWORK_MODULES:
                self.assertIsNotNone(
                    entry["function"],
                    "%s is imported at module scope" % entry["module"])

    def test_urllib_sits_only_inside_check_live(self):
        for entry in divergence_note.import_graph():
            if entry["module"].split(".")[0] == "urllib":
                self.assertEqual(entry["function"], "check_live")

    def test_check_live_records_the_status_and_a_body_digest_through_a_seam(self):
        document, _ = mint()
        before = document["note_digest"]
        enriched = divergence_note.check_live(
            document, opener=lambda url: (404, b"gone"))
        self.assertEqual(enriched["observed_status"], 404)
        self.assertEqual(enriched["observed_body_digest"], digest(b"gone"))
        self.assertNotEqual(enriched["note_digest"], before)
        self.assertIs(verify(enriched)["ok"], True)


class TheOptionalKeyIsTheOnlyOne(unittest.TestCase):
    """13/14 - the door opened in fulfillment_receipt is exactly one key wide."""

    def test_a_receipt_without_the_key_verifies_exactly_as_before(self):
        emitted, receipt, grant_bytes, block, delivery = fulfillment_set()
        self.assertNotIn("divergence_notes", emitted)
        self.assertIs(graded(emitted, receipt, grant_bytes, block, delivery)["ok"],
                      True)
        self.assertEqual(fulfillment_receipt.OPTIONAL_FULFILLMENT_KEYS,
                         frozenset({"divergence_notes"}))

    def test_every_other_unknown_key_is_still_refused(self):
        emitted, receipt, grant_bytes, block, delivery = fulfillment_set()
        emitted["divergence_note"] = []          # the near-name twin
        verdict = graded(emitted, receipt, grant_bytes, block, delivery)
        self.assertIs(verdict["ok"], False)
        self.assertEqual(verdict["reasons"], ["bad_fulfillment_shape"])

    def test_a_delivery_with_an_extra_key_is_still_refused(self):
        emitted, receipt, grant_bytes, block, delivery = fulfillment_set()
        delivery = dict(delivery)
        delivery["divergence_notes"] = []
        verdict = graded(emitted, receipt, grant_bytes, block, delivery)
        self.assertIn("delivery_digest_mismatch", verdict["reasons"])

    def test_junk_under_the_key_is_refused_at_the_gate(self):
        emitted, receipt, grant_bytes, block, delivery = fulfillment_set()
        for junk in ("notes", {}, [7], [{"v": "something-else"}],
                     [{"v": V, "note_digest": "short"}]):
            broken = dict(emitted)
            broken["divergence_notes"] = junk
            verdict = graded(broken, receipt, grant_bytes, block, delivery)
            self.assertIs(verdict["ok"], False, junk)
            self.assertEqual(verdict["reasons"], ["bad_fulfillment_shape"], junk)


class TheReDerivabilityTable(unittest.TestCase):
    """15 - an unknown evidence kind is stated, never guessed."""

    def test_an_unknown_kind_must_be_stated(self):
        with self.assertRaises(Refusal) as caught:
            mint(their_evidence_kind="a letter from their lawyer")
        self.assertEqual(caught.exception.code, "bad_note_shape")
        self.assertIn("--their-re-derivable", caught.exception.detail)

        document, _ = mint(their_evidence_kind="a letter from their lawyer",
                           their_re_derivable=False)
        self.assertIs(document["theirs"]["re_derivable_without_them"], False)

    def test_an_explicit_value_overrides_the_table(self):
        document, _ = mint(our_re_derivable=False)
        self.assertIs(document["ours"]["re_derivable_without_us"], False)
        # And that alone takes the note out of the flattering shape.
        flat, _ = mint(our_re_derivable=False, code=DISMISSAL,
                       explanation="These two rows are about two orders here.")
        self.assertIs(verify(flat)["ok"], True)

    def test_a_non_boolean_override_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            mint(our_re_derivable="yes")
        self.assertEqual(caught.exception.code, "bad_note_shape")


class TheViewsAndCodes(unittest.TestCase):
    """16 - the two closed vocabularies."""

    def test_a_view_outside_the_seven_is_refused(self):
        for bad in ("settled", "PAID", "", None, 1):
            for field in ("our_view", "their_view"):
                with self.assertRaises(Refusal) as caught:
                    mint(**{field: bad})
                self.assertEqual(caught.exception.code, "bad_view", (field, bad))

    def test_a_reason_code_outside_the_seven_is_refused(self):
        for bad in ("because", "", None, "UNIT_THEIR_VERIFIER_CANNOT_EXPRESS"):
            with self.assertRaises(Refusal) as caught:
                mint(code=bad)
            self.assertEqual(caught.exception.code, "bad_reason_code", bad)

    def test_who_is_easier_to_read_is_required_when_the_views_differ(self):
        with self.assertRaises(Refusal) as caught:
            mint(who_is_easier=None)
        self.assertEqual(caught.exception.code, "who_is_easier_to_read_required")
        for bad in ("us", "them", "ours and theirs", 2):
            with self.assertRaises(Refusal) as caught:
                mint(who_is_easier=bad)
            self.assertEqual(caught.exception.code,
                             "who_is_easier_to_read_required", bad)

    def test_it_is_refused_when_the_views_agree(self):
        with self.assertRaises(Refusal) as caught:
            mint(their_view="paid", who_is_easier="ours")
        self.assertEqual(caught.exception.code, "bad_note_shape")

    def test_all_three_answers_are_accepted(self):
        for answer in ("ours", "theirs", "neither"):
            document, _ = mint(who_is_easier=answer)
            self.assertEqual(document["who_is_easier_to_read"], answer)


class TheCliContract(unittest.TestCase):
    """17 - what a stranger running the three commands actually gets."""

    def test_note_writes_the_canonical_bytes_and_prints_the_digest(self):
        with tempfile.TemporaryDirectory() as workspace:
            path = os.path.join(workspace, "divergence.json")
            code, out, err = run(
                "note", "--subject", SUBJECT, "--our-view", "paid",
                "--our-evidence-kind", "nano_block", "--our-evidence", OUR_BLOCK,
                "--their-name", "board.invalid", "--their-view", "abandoned",
                "--their-evidence-kind", "http_status_field",
                "--their-evidence", THEIR_EVIDENCE,
                "--reason-code", "unit_their_verifier_cannot_express",
                "--explanation", WHY, "--who-is-easier-to-read", "theirs",
                "--observed-at", OBSERVED, "--out", path)
            self.assertEqual(code, 0, err)
            expected, payload = mint()
            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), payload)
            printed = json.loads(out)
            self.assertEqual(printed["note_digest"], expected["note_digest"])
            self.assertIs(printed["diverges"], True)

    def test_no_command_is_exit_two(self):
        code, _, err = run()
        self.assertEqual(code, 2)
        self.assertIn("a command is required", err)

    def test_an_unreadable_note_file_is_exit_two(self):
        with tempfile.TemporaryDirectory() as workspace:
            path = os.path.join(workspace, "not-json.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write("{ not json")
            code, _, err = run("verify", "--note", path)
            self.assertEqual(code, 2)
            self.assertEqual(json.loads(err)["error"], "bad_note_shape")

    def test_main_is_importable_and_agrees_with_the_subprocess(self):
        self.assertEqual(main(["--self-test"]), 0)


if __name__ == "__main__":
    unittest.main()
