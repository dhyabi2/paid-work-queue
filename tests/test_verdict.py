"""The proof delivered as a file, and the assertions that keep it honest.

The decisive tests here are 6 and 11.

Test 6 makes `open` raise and then calls `check` anyway. If `check` can still
return a verdict, every `measured` claim really is re-derivable from the
artifact's own bytes - which is the property the whole file exists for. A
`check` that reached for a file would be proving something about our tree
rather than about the artifact a stranger fetched.

Test 11 imports nothing from `verdict`. It takes the built artifact, pulls
`order-is-in-the-amount`'s inputs, and recomputes the tag and the payable
amount with `hashlib` and integer arithmetic written out in the test body. That
is `modeltruthcheck`'s position - "I won't run a command pulled from a comment"
- expressed as a test. If this test ever needs our module, the spec is not met.

Test 10 is the one that makes the rest worth reading: a false claim KEEPS its
row. An artifact that silently dropped the claims it could not support would be
a brochure.

Nothing opens a socket, and nothing can: test 14 walks the import graph.

No 64-hex run stands as a single literal, matching the project's secret gate.
"""

import builtins
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

import validate  # noqa: E402
import verdict  # noqa: E402
from verdict import (  # noqa: E402
    PRIMITIVES, RULES, VERDICT_KINDS, Refusal, build, check, import_graph,
    missing_inputs, serialise, write_json,
)

SCRIPT = os.path.join(ROOT, "verdict.py")
NOW = "2026-10-08T06:00:00Z"

# The eight the spec names, plus the ninth this repository added when the
# seller got an inbox.
REQUIRED_CLAIMS = (
    "settlement-count-is-zero",
    "external-counterparties-is-zero",
    "board-is-open",
    "jobs-digest-matches",
    "no-wallet-needed-to-claim",
    "address-checksum-enforced",
    "order-is-in-the-amount",
    "self-dealing-is-excluded-before-the-block",
)


def built():
    return build(ROOT, now=NOW)


def clone(document):
    return json.loads(json.dumps(document))


def tree_with(receipts, jobs=None):
    """A minimal repository the builder can read, for the false-claim cases."""
    directory = tempfile.mkdtemp()
    with open(os.path.join(ROOT, "jobs.json"), encoding="utf-8") as handle:
        board = json.load(handle)
    if jobs is not None:
        board["jobs"] = jobs
    for name, document in (
        ("receipts.json", {"receipts": receipts}),
        ("jobs.json", board),
        ("claims.json", {"claims": []}),
        ("operator_accounts.json", {"operator_accounts": []}),
    ):
        with open(os.path.join(directory, name), "w", encoding="utf-8") as handle:
            json.dump(document, handle)
    return directory


class VerdictTest(unittest.TestCase):

    maxDiff = None

    # -- 1 -----------------------------------------------------------------
    def test_1_every_required_claim_is_present_with_inputs_and_a_recipe(self):
        artifact = built()
        ids = [c["id"] for c in artifact["claims"]]
        for claim_id in REQUIRED_CLAIMS:
            self.assertIn(claim_id, ids)
        self.assertGreaterEqual(len(artifact["claims"]), 8)
        for claim in artifact["claims"]:
            self.assertTrue(claim["inputs"], claim["id"])
            self.assertTrue(claim["recipe"].strip(), claim["id"])
            self.assertIn(claim["verdict_is"], VERDICT_KINDS)
            self.assertIsInstance(claim["verdict"], bool)
            self.assertTrue(claim["check_without_us"], claim["id"])
            self.assertTrue(claim["falsified_by"].strip(), claim["id"])
        self.assertEqual(artifact["v"], "verdict-v1")
        self.assertEqual(artifact["claims_total"], len(artifact["claims"]))
        self.assertTrue(artifact["read_this_first"].strip())
        self.assertEqual(artifact["primitives_used"], list(PRIMITIVES))

    # -- 2 -----------------------------------------------------------------
    def test_2_nothing_is_unrecheckable_from_its_own_inputs(self):
        self.assertEqual(missing_inputs(built()), [])

    # -- 3 -----------------------------------------------------------------
    def test_3_check_confirms_every_measured_claim(self):
        artifact = built()
        result = check(artifact)
        self.assertTrue(result["ok"], result["mismatches"])
        self.assertEqual(result["rechecked"], artifact["claims_measured"])
        self.assertEqual(result["mismatches"], [])
        self.assertGreaterEqual(artifact["claims_measured"], 8)

    # -- 4 -----------------------------------------------------------------
    def test_4_a_flipped_verdict_is_caught_by_name(self):
        artifact = clone(built())
        target = "settlement-count-is-zero"
        for claim in artifact["claims"]:
            if claim["id"] == target:
                claim["verdict"] = not claim["verdict"]
        result = check(artifact)
        self.assertFalse(result["ok"])
        self.assertIn(target, [m["id"] for m in result["mismatches"]])

    # -- 5 -----------------------------------------------------------------
    def test_5_a_fabricated_input_is_caught(self):
        artifact = clone(built())
        for claim in artifact["claims"]:
            if claim["id"] == "settlement-count-is-zero":
                claim["inputs"]["receipts"].append(
                    {"id": "receipt-fabricated", "paid_to": "nano_fake"})
        result = check(artifact)
        self.assertFalse(result["ok"])
        self.assertIn("settlement-count-is-zero",
                      [m["id"] for m in result["mismatches"]])

    # -- 6 -----------------------------------------------------------------
    def test_6_check_touches_no_file(self):
        """The property the whole artifact exists for."""
        artifact = clone(built())
        real_open = builtins.open

        def refuse(*args, **kwargs):
            raise AssertionError("check opened a file: %r" % (args[:1],))

        builtins.open = refuse
        try:
            result = check(artifact)
            absent = missing_inputs(artifact)
        finally:
            builtins.open = real_open
        self.assertTrue(result["ok"], result["mismatches"])
        self.assertEqual(absent, [])
        self.assertGreaterEqual(result["rechecked"], 8)

    # -- 7 -----------------------------------------------------------------
    def test_7_an_asserted_claim_with_no_reason_is_refused(self):
        with self.assertRaises(Refusal) as caught:
            verdict._claim("bare-assertion", "we say so", True, "asserted",
                           {"a": 1}, "none")
        self.assertEqual(caught.exception.code, "bare_assertion")
        # With a reason it is allowed, and it is not counted as measured.
        row = verdict._claim("stated", "we say so", True, "asserted", {"a": 1},
                             "none", why_not_measurable="no public source")
        self.assertEqual(row["why_not_measurable"], "no public source")
        self.assertNotIn("rule", row)

    # -- 8 -----------------------------------------------------------------
    def test_8_a_digest_with_no_preimage_is_named(self):
        artifact = clone(built())
        for claim in artifact["claims"]:
            if claim["id"] == "jobs-digest-matches":
                del claim["inputs"]["serialisation"]
                del claim["inputs"]["material"]
        self.assertIn("jobs-digest-matches", missing_inputs(artifact))

        # And a claim missing a required input key is named too.
        other = clone(built())
        for claim in other["claims"]:
            if claim["id"] == "order-is-in-the-amount":
                del claim["inputs"]["prefix"]
        self.assertIn("order-is-in-the-amount", missing_inputs(other))

    # -- 9 -----------------------------------------------------------------
    def test_9_claims_false_or_unproven_is_the_count_of_those_rows(self):
        artifact = built()
        counted = sum(1 for c in artifact["claims"]
                      if c["verdict"] is False
                      or c["verdict_is"] == "unproven")
        self.assertEqual(artifact["claims_false_or_unproven"], counted)

        # Driven by a fixture with one of each, so the equality is not
        # satisfied vacuously by today's all-true board.
        fixture = {
            "v": "verdict-v1", "claims_false_or_unproven": 2,
            "claims": [
                {"id": "a", "verdict": False, "verdict_is": "measured",
                 "rule": "receipts_list_is_empty",
                 "inputs": {"receipts": [{"id": "r"}]}, "recipe": "count it"},
                {"id": "b", "verdict": True, "verdict_is": "unproven",
                 "inputs": {"x": 1}, "recipe": "we claimed it once"},
                {"id": "c", "verdict": True, "verdict_is": "measured",
                 "rule": "receipts_list_is_empty",
                 "inputs": {"receipts": []}, "recipe": "count it"},
            ],
        }
        self.assertTrue(check(fixture)["ok"], check(fixture)["mismatches"])
        fixture["claims_false_or_unproven"] = 1
        self.assertFalse(check(fixture)["ok"])

    # -- 10 ----------------------------------------------------------------
    def test_10_a_false_claim_keeps_its_row(self):
        directory = tree_with([{"id": "receipt-001", "job_id": "job-x",
                                "paid_to": "nano_someone",
                                "amount_raw": "1", "amount_xno": "0",
                                "block_hash": "AB" * 32}])
        artifact = build(directory, now=NOW)
        rows = {c["id"]: c for c in artifact["claims"]}
        self.assertIn("settlement-count-is-zero", rows)
        self.assertFalse(rows["settlement-count-is-zero"]["verdict"])
        self.assertEqual(rows["settlement-count-is-zero"]["verdict_is"],
                         "measured")
        self.assertGreaterEqual(artifact["claims_false_or_unproven"], 1)
        # It is still internally consistent: a false row is a row, not an error.
        self.assertTrue(check(artifact)["ok"], check(artifact)["mismatches"])
        self.assertEqual(missing_inputs(artifact), [])

    # -- 11 ----------------------------------------------------------------
    def test_11_a_reader_reproduces_the_arithmetic_with_no_import_of_ours(self):
        """No name from `verdict` is used in this body. That is the test."""
        path = os.path.join(ROOT, "feed", "verdict.json")
        if not os.path.exists(path):
            self.skipTest("feed/verdict.json is not committed yet")
        with open(path, encoding="utf-8") as handle:
            artifact = json.load(handle)

        row = next(c for c in artifact["claims"]
                   if c["id"] == "order-is-in-the-amount")
        prefix = row["inputs"]["prefix"].encode("ascii")
        self.assertTrue(row["inputs"]["vectors"])
        for vector in row["inputs"]["vectors"]:
            digest_hex = "".join(vector["order_digest_halves"])
            # The preimage is published, so nothing is taken on trust.
            self.assertEqual(
                hashlib.sha256(vector["preimage"].encode("utf-8")).hexdigest(),
                digest_hex)
            modulus = int(vector["modulus"])
            tagged = hashlib.blake2b(prefix + bytes.fromhex(digest_hex),
                                     digest_size=32).hexdigest()
            tag = 1 + (int(tagged, 16) % (modulus - 1))
            self.assertEqual(tag, int(vector["tag"]))
            self.assertEqual(int(vector["amount_raw"]) + tag,
                             int(vector["pay_raw"]))

        # And the counterparty intent, the other inlined digest.
        intent = next(c for c in artifact["claims"]
                      if c["id"] == "self-dealing-is-excluded-before-the-block")
        payload = intent["inputs"]["intent_json"].encode("utf-8")
        self.assertEqual(
            hashlib.blake2b(payload, digest_size=32).hexdigest(),
            "".join(intent["inputs"]["intent_digest_halves"]))
        self.assertLess(intent["inputs"]["declared_at"],
                        intent["inputs"]["settled_at"])

    # -- 12 ----------------------------------------------------------------
    def test_12_the_artifact_carries_no_standalone_64_hex_run(self):
        artifact = built()
        with tempfile.TemporaryDirectory() as directory:
            write_json(os.path.join(directory, "feed", "verdict.json"), artifact)
            self.assertEqual(validate.scan_for_secrets(directory), [])
        text = serialise(artifact).decode("utf-8")
        self.assertIsNone(validate.SECRET_RE.search(text),
                          "the artifact printed a standalone 64-hex run")

        # Even with a fixture vector carrying a real 64-hex block hash, which
        # is the case the gate exempts only under the key `block_hash`.
        directory = tree_with([{"id": "receipt-001", "job_id": "job-x",
                                "paid_to": "nano_someone", "amount_raw": "1",
                                "amount_xno": "0", "block_hash": "AB" * 32}])
        with tempfile.TemporaryDirectory() as out:
            write_json(os.path.join(out, "feed", "verdict.json"),
                       build(directory, now=NOW))
            self.assertEqual(validate.scan_for_secrets(out), [])

    # -- 13 ----------------------------------------------------------------
    def test_13_a_failed_write_leaves_no_tmp_and_no_damage(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "verdict.json")
            write_json(path, built())
            with open(path, "rb") as handle:
                before = handle.read()

            original = os.replace

            def boom(src, dst):
                raise OSError("no space left on device")

            os.replace = boom
            try:
                with self.assertRaises(OSError):
                    write_json(path, {"v": "verdict-v1", "claims": []})
            finally:
                os.replace = original

            with open(path, "rb") as handle:
                self.assertEqual(handle.read(), before)
            self.assertFalse(os.path.exists(path + ".tmp"))

    # -- 14 ----------------------------------------------------------------
    def test_14_nothing_here_can_reach_the_network(self):
        network = {"socket", "http", "urllib", "ssl", "requests"}
        reached = {e["module"].split(".")[0] for e in import_graph()}
        self.assertEqual(reached & network, set())

    # -- the refusals ------------------------------------------------------
    def test_a_missing_file_refuses_rather_than_guessing(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(Refusal) as caught:
                build(directory, now=NOW)
            self.assertEqual(caught.exception.code, "missing_file")

        with self.assertRaises(Refusal) as caught:
            build(os.path.join(ROOT, "does-not-exist"), now=NOW)
        self.assertEqual(caught.exception.code, "bad_root")

        with self.assertRaises(Refusal) as caught:
            build(ROOT, now="soon")
        self.assertEqual(caught.exception.code, "bad_now")

    def test_unparseable_json_refuses_with_its_own_code(self):
        directory = tree_with([])
        with open(os.path.join(directory, "receipts.json"), "w",
                  encoding="utf-8") as handle:
            handle.write("{not json")
        with self.assertRaises(Refusal) as caught:
            build(directory, now=NOW)
        self.assertEqual(caught.exception.code, "bad_json")

    def test_a_malformed_artifact_refuses(self):
        for bad in ({}, {"claims": {}}, [], None):
            with self.assertRaises(Refusal) as caught:
                check(bad)
            self.assertEqual(caught.exception.code, "bad_artifact")

    def test_every_rule_is_reached_by_a_claim(self):
        """A rule no claim uses is dead code in the one file about honesty."""
        used = {c.get("rule") for c in built()["claims"]}
        self.assertEqual(set(RULES) - used, set(),
                         "these rules are declared and never used")


class VerdictCliTest(unittest.TestCase):

    def run_cli(self, *argv, cwd=None):
        return subprocess.run([sys.executable, SCRIPT, *argv],
                              capture_output=True, text=True, cwd=cwd)

    def test_self_test_is_green(self):
        result = self.run_cli("--self-test", cwd=ROOT)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["failures"], [])
        self.assertGreater(report["negative_controls"], 0)
        self.assertEqual(report["tool"], "verdict")

    def test_build_then_check_round_trips(self):
        with tempfile.TemporaryDirectory() as directory:
            out = os.path.join(directory, "verdict.json")
            result = self.run_cli("build", "--root", ROOT, "--out", out,
                                  "--now", NOW, cwd=ROOT)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("claims", result.stdout)

            result = self.run_cli("check", "--artifact", out, cwd=ROOT)
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertTrue(report["ok"])
            self.assertEqual(report["not_self_contained"], [])
            self.assertFalse(os.path.exists(out + ".tmp"))

    def test_check_exits_1_on_a_tampered_artifact(self):
        with tempfile.TemporaryDirectory() as directory:
            out = os.path.join(directory, "verdict.json")
            self.run_cli("build", "--root", ROOT, "--out", out, "--now", NOW,
                         cwd=ROOT)
            with open(out, encoding="utf-8") as handle:
                artifact = json.load(handle)
            artifact["claims"][0]["verdict"] = not artifact["claims"][0]["verdict"]
            with open(out, "w", encoding="utf-8") as handle:
                json.dump(artifact, handle)
            result = self.run_cli("check", "--artifact", out, cwd=ROOT)
            self.assertEqual(result.returncode, 1)
            self.assertFalse(json.loads(result.stdout)["ok"])

    def test_a_refusal_prints_its_code(self):
        result = self.run_cli("build", "--root", "/nonexistent-root",
                              "--now", NOW, cwd=ROOT)
        self.assertEqual(result.returncode, 2)
        self.assertIn("reason=bad_root", result.stderr)


class CommittedArtifactTest(unittest.TestCase):
    """The published copy is not allowed to drift from the tree."""

    def test_the_committed_artifact_rechecks_and_is_self_contained(self):
        path = os.path.join(ROOT, "feed", "verdict.json")
        if not os.path.exists(path):
            self.skipTest("feed/verdict.json is not committed yet")
        with open(path, encoding="utf-8") as handle:
            artifact = json.load(handle)
        result = check(artifact)
        self.assertTrue(result["ok"], result["mismatches"])
        self.assertEqual(missing_inputs(artifact), [])
        self.assertEqual(artifact["v"], "verdict-v1")

    def test_the_committed_artifact_still_describes_this_tree(self):
        """Rebuilt from the tree at the artifact's own timestamp, it matches."""
        path = os.path.join(ROOT, "feed", "verdict.json")
        if not os.path.exists(path):
            self.skipTest("feed/verdict.json is not committed yet")
        with open(path, encoding="utf-8") as handle:
            artifact = json.load(handle)
        rebuilt = build(ROOT, now=artifact["generated_at"])
        self.assertEqual(rebuilt, artifact,
                         "feed/verdict.json is stale - rerun "
                         "`python3 verdict.py build`")


if __name__ == "__main__":
    unittest.main()
