"""The checklist must never guess in our favour, and must never quietly pass.

No test touches the network. Answer files are built in a temporary directory,
so nothing here depends on a file a previous run left behind.
"""

import contextlib
import copy
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import server_conformance  # noqa: E402
import validate  # noqa: E402
from server_conformance import (  # noqa: E402
    EXIT_UNKNOWN, EXIT_USAGE, EXIT_WOULD_REFUSE, EXIT_WOULD_SETTLE, GATE_IDS,
    evaluate, parse_answers, template,
)

EXPECTED_IDS = [
    "network_registered",
    "settleable_capability",
    "amount_column_width",
    "refunder_registered",
    "chain_route_accepts",
]


def run_cli(*argv):
    """Exit code, stdout, stderr for one command-line run."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = server_conformance.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class AnswerFileCase(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    def write(self, document, name="answers.json"):
        path = os.path.join(self.dir, name)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(document, handle)
        return path

    def answered(self, **overrides):
        """A template with every gate answered true, then the overrides applied."""
        document = template()
        for gate in document["gates"]:
            gate["answer"] = overrides.get(gate["id"], True)
        return document


class TestWouldSettleRequiresAllFive(AnswerFileCase):
    # -- 7 ------------------------------------------------------------------
    def test_7_all_five_true_is_would_settle_and_exit_0(self):
        path = self.write(self.answered())
        code, out, _ = run_cli("--answers", path, "--json")
        self.assertEqual(json.loads(out)["verdict"], "would_settle")
        self.assertEqual(code, EXIT_WOULD_SETTLE)

    def test_7b_four_true_and_one_null_is_unknown_and_exit_5(self):
        for gate_id in EXPECTED_IDS:
            path = self.write(self.answered(**{gate_id: None}))
            code, out, _ = run_cli("--answers", path, "--json")
            result = json.loads(out)
            self.assertEqual(result["verdict"], "unknown", gate_id)
            self.assertEqual(result["unknown"], [gate_id])
            self.assertEqual(result["blocking"], [])
            self.assertEqual(code, EXIT_UNKNOWN, gate_id)

    def test_7c_four_true_and_one_false_blocks_naming_that_gate_only(self):
        for gate_id in EXPECTED_IDS:
            path = self.write(self.answered(**{gate_id: False}))
            code, out, _ = run_cli("--answers", path, "--json")
            result = json.loads(out)
            self.assertEqual(result["verdict"], "would_refuse", gate_id)
            self.assertEqual(result["blocking"], [gate_id])
            self.assertEqual(result["unknown"], [])
            self.assertEqual(code, EXIT_WOULD_REFUSE, gate_id)

    def test_7d_a_false_outranks_a_null(self):
        """With one of each, the answer is would_refuse - never unknown, never a pass."""
        path = self.write(self.answered(amount_column_width=False,
                                        chain_route_accepts=None))
        code, out, _ = run_cli("--answers", path, "--json")
        result = json.loads(out)
        self.assertEqual(result["verdict"], "would_refuse")
        self.assertEqual(result["blocking"], ["amount_column_width"])
        self.assertEqual(result["unknown"], ["chain_route_accepts"])
        self.assertEqual(code, EXIT_WOULD_REFUSE)

    def test_7e_negative_control_no_input_reaches_would_settle_with_a_gap(self):
        """Every combination that is not five trues must fail to say would_settle.

        This is the negative control for test 7: it enumerates all 3**5
        answer combinations and asserts that exactly one of them passes.
        """
        import itertools

        passing = []
        for combination in itertools.product([True, False, None], repeat=5):
            answers = dict(zip(EXPECTED_IDS, combination))
            if evaluate(answers)["verdict"] == "would_settle":
                passing.append(combination)
        self.assertEqual(passing, [(True, True, True, True, True)])


class TestTheTemplate(AnswerFileCase):
    # -- 8 ------------------------------------------------------------------
    def test_8_template_parses_with_the_five_ids_in_order_every_value_null(self):
        code, out, _ = run_cli("--template")
        self.assertEqual(code, EXIT_WOULD_SETTLE)
        document = json.loads(out)
        self.assertEqual([g["id"] for g in document["gates"]], EXPECTED_IDS)
        self.assertEqual(list(GATE_IDS), EXPECTED_IDS)
        for gate in document["gates"]:
            self.assertIsNone(gate["answer"], gate["id"])
            self.assertTrue(gate["question"].strip(), gate["id"])
            self.assertTrue(gate["look_at"].strip(), gate["id"])

    def test_8b_the_template_fed_straight_back_is_unknown_never_would_settle(self):
        _, out, _ = run_cli("--template")
        path = self.write(json.loads(out))
        code, verdict_out, _ = run_cli("--answers", path, "--json")
        self.assertEqual(json.loads(verdict_out)["verdict"], "unknown")
        self.assertEqual(code, EXIT_UNKNOWN)

    def test_8c_the_documented_command_pair_behaves_as_the_readme_says(self):
        path = os.path.join(self.dir, "a.json")
        _, out, _ = run_cli("--template")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(out)
        code, verdict_out, _ = run_cli("--answers", path, "--json")
        self.assertIn('"unknown"', verdict_out)
        self.assertEqual(code, EXIT_UNKNOWN)


class TestConsequences(AnswerFileCase):
    # -- 9 ------------------------------------------------------------------
    def test_9_every_gate_carries_a_consequence(self):
        result = evaluate(dict.fromkeys(EXPECTED_IDS, False))
        self.assertEqual([g["id"] for g in result["gates"]], EXPECTED_IDS)
        for gate in result["gates"]:
            self.assertTrue(gate["consequence"].strip(), gate["id"])
            self.assertGreater(len(gate["consequence"]), 40, gate["id"])

    def test_9b_refunder_registered_names_the_five_stranded_attempts(self):
        consequence = {g["id"]: g["consequence"]
                       for g in evaluate(dict.fromkeys(EXPECTED_IDS, False))["gates"]}
        self.assertIn("attempts=5", consequence["refunder_registered"])
        self.assertIn("never broadcast", consequence["refunder_registered"])
        self.assertIn("never retried", consequence["refunder_registered"])

    def test_9c_amount_column_next_step_names_the_module_and_the_quantum(self):
        result = evaluate(dict.fromkeys(EXPECTED_IDS, False))
        self.assertIn("usdc_shape.py", result["next_step"])
        self.assertIn("10**24", result["next_step"])
        self.assertIn("0.000001", result["next_step"])

    def test_9d_the_other_four_say_the_column_must_be_settled_first(self):
        for gate_id in EXPECTED_IDS:
            if gate_id == "amount_column_width":
                continue
            answers = dict.fromkeys(EXPECTED_IDS, True)
            answers[gate_id] = False
            step = evaluate(answers)["next_step"]
            self.assertIn("amount_column_width", step, gate_id)
            self.assertIn("not a switch statement", step, gate_id)


class TestUsageErrors(AnswerFileCase):
    def test_a_missing_file_is_exit_4(self):
        code, _, err = run_cli("--answers", os.path.join(self.dir, "nope.json"))
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("cannot read", err)

    def test_malformed_json_is_exit_4(self):
        path = os.path.join(self.dir, "bad.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write("{not json")
        code, _, err = run_cli("--answers", path)
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("not valid JSON", err)

    def test_an_unknown_gate_id_is_exit_4(self):
        document = self.answered()
        document["gates"][0]["id"] = "invented_gate"
        code, _, err = run_cli("--answers", self.write(document))
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("invented_gate", err)

    def test_a_missing_gate_is_exit_4_not_a_silent_null(self):
        document = self.answered()
        del document["gates"][2]
        code, _, err = run_cli("--answers", self.write(document))
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("amount_column_width", err)

    def test_a_string_answer_is_a_usage_error_not_a_guess(self):
        """'true' is not true. Guessing what a string meant is how a false pass happens."""
        for bad in ("true", "yes", 1, 0, "false"):
            document = self.answered()
            document["gates"][0]["answer"] = bad
            code, _, err = run_cli("--answers", self.write(document))
            self.assertEqual(code, EXIT_USAGE, repr(bad))
            self.assertIn("must be true, false, or null", err)

    def test_a_duplicated_gate_is_exit_4(self):
        document = self.answered()
        document["gates"].append(copy.deepcopy(document["gates"][0]))
        code, _, err = run_cli("--answers", self.write(document))
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("more than once", err)

    def test_no_arguments_is_exit_4(self):
        code, _, err = run_cli()
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("nothing to do", err)

    def test_the_flat_mapping_shape_is_accepted(self):
        """A hand-written {id: bool} file works; refusing it helps nobody."""
        path = self.write(dict.fromkeys(EXPECTED_IDS, True))
        code, out, _ = run_cli("--answers", path, "--json")
        self.assertEqual(json.loads(out)["verdict"], "would_settle")
        self.assertEqual(code, EXIT_WOULD_SETTLE)

    def test_a_flat_mapping_missing_a_gate_is_exit_4(self):
        answers = dict.fromkeys(EXPECTED_IDS, True)
        del answers["refunder_registered"]
        code, _, err = run_cli("--answers", self.write(answers))
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("refunder_registered", err)

    def test_a_non_object_document_is_exit_4(self):
        code, _, err = run_cli("--answers", self.write([1, 2, 3]))
        self.assertEqual(code, EXIT_USAGE)
        self.assertIn("JSON object", err)


class TestHumanOutput(AnswerFileCase):
    def test_the_default_output_is_readable_and_names_the_verdict(self):
        path = self.write(self.answered(amount_column_width=False))
        code, out, _ = run_cli("--answers", path)
        self.assertIn("verdict: would_refuse", out)
        self.assertIn("amount_column_width", out)
        self.assertIn("next step:", out)
        self.assertEqual(code, EXIT_WOULD_REFUSE)


class TestTheQuantumCheckInValidate(unittest.TestCase):
    """Test 10: validate.py still passes on the real tree, and refuses 1 raw."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    def _job(self, **overrides):
        job = {
            "id": "j-1",
            "title": "t",
            "description": "d",
            "acceptance": ["a"],
            "price_xno": "0.05",
            "price_raw": "50000000000000000000000000000",
            "posted": "2026-09-26T07:00:00Z",
            "expires": "2026-10-03T07:00:00Z",
            "state": "open",
            "claimed_by": None,
            "claim_url": None,
            "receipt_id": None,
        }
        job.update(overrides)
        return job

    def _check(self, job):
        return validate.check_jobs({"currency": "XNO", "jobs": [job]})

    # -- 10 -----------------------------------------------------------------
    def test_10_validate_still_passes_on_the_repositorys_real_jobs_json(self):
        out = io.StringIO()
        code = validate.run(ROOT, write_stats=False, out=out)
        self.assertEqual(code, 0, out.getvalue())

    def test_10b_a_job_priced_at_one_raw_is_refused(self):
        errors = self._check(self._job(price_xno="0.000000000000000000000000000001",
                                       price_raw="1"))
        self.assertTrue(errors)
        self.assertTrue(any("whole micro" in e for e in errors), errors)

    def test_10c_the_refusal_names_what_is_short_and_what_it_breaks(self):
        errors = self._check(self._job(price_xno="0.000000000000000000000000000001",
                                       price_raw="1"))
        joined = " ".join(errors)
        self.assertIn("0.000001 XNO", joined)
        self.assertIn("status='failed'", joined)

    def test_10d_a_deliberate_sub_micro_price_is_allowed_on_the_record(self):
        errors = self._check(self._job(
            price_xno="0.000000000000000000000000000001",
            price_raw="1",
            sub_micro_ok=True,
            excludes_ledgers=["USDC-atomic 6-decimal int64 (minia2a, x402 reference)"],
        ))
        self.assertEqual(errors, [])

    def test_10e_the_escape_hatch_must_name_what_it_costs(self):
        for excludes in (None, [], "a string", [""], [3]):
            job = self._job(price_xno="0.000000000000000000000000000001",
                            price_raw="1", sub_micro_ok=True)
            if excludes is not None:
                job["excludes_ledgers"] = excludes
            errors = self._check(job)
            self.assertTrue(errors, repr(excludes))

    def test_10f_a_pointless_exception_on_a_whole_micro_price_is_refused(self):
        errors = self._check(self._job(sub_micro_ok=True, excludes_ledgers=["x"]))
        self.assertTrue(any("must be removed" in e for e in errors), errors)

    def test_10g_every_real_job_in_the_queue_is_a_whole_number_of_micro(self):
        from usdc_shape import MIN_SETTLEABLE_RAW

        with open(os.path.join(ROOT, "jobs.json"), "r", encoding="utf-8") as handle:
            jobs = json.load(handle)["jobs"]
        self.assertTrue(jobs)
        for job in jobs:
            self.assertEqual(int(job["price_raw"]) % MIN_SETTLEABLE_RAW, 0, job["id"])


if __name__ == "__main__":
    unittest.main()
