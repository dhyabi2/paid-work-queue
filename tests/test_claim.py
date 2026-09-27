"""The suite for claim.py. Every test is numbered after the spec line it pins.

No test touches the network, and test 11 fails the build if claim.py ever grows
an import that could. Nothing here contains a 64-character hex literal either:
validate.py's secret gate refuses one anywhere in the tree, and it is right to,
so test 12 builds its fake key at runtime.
"""

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
sys.path.insert(0, os.path.join(ROOT, "vendor"))

import claim  # noqa: E402
import nanoaddr  # noqa: E402

GENESIS = "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3"
BURN = "nano_1111111111111111111111111111111111111111111111111111hifc8npp"

FUTURE = "2099-10-03T07:00:00Z"
PAST = "2000-01-02T07:00:00Z"


def job(job_id, price_raw, price_xno, state="open", expires=FUTURE, title=None, **over):
    """A job object in the exact shape and key order jobs.json uses."""
    body = {
        "id": job_id,
        "title": title or ("job %s" % job_id),
        "description": "what to do for %s" % job_id,
        "acceptance": ["line one for %s" % job_id, "line two for %s" % job_id],
        "price_xno": price_xno,
        "price_raw": price_raw,
        "posted": "2026-09-26T07:00:00Z",
        "expires": expires,
        "state": state,
        "claimed_by": None,
        "claim_url": None,
        "receipt_id": None,
    }
    body.update(over)
    return body


def write_tree(directory, jobs):
    document = {"updated": "2026-09-26T07:00:00Z", "currency": "XNO", "jobs": jobs}
    payload = (json.dumps(document, indent=2) + "\n").encode("utf-8")
    with open(os.path.join(directory, "jobs.json"), "wb") as handle:
        handle.write(payload)
    return payload


def run(directory, *argv):
    """Call claim.main in process. Returns (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    code = claim.main(list(argv), out=out, err=err, directory=directory)
    return code, out.getvalue(), err.getvalue()


def read_bytes(directory, name="jobs.json"):
    with open(os.path.join(directory, name), "rb") as handle:
        return handle.read()


class ClaimTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    # -- 1 ------------------------------------------------------------------
    def test_01_list_prints_open_jobs_price_descending(self):
        write_tree(self.dir, [
            job("j-low", "50000000000000000000000000000", "0.05"),
            job("j-high", "250000000000000000000000000000", "0.25"),
            job("j-mid", "150000000000000000000000000000", "0.15"),
            job("j-done", "900000000000000000000000000000", "0.9", state="settled",
                claimed_by="someone", claim_url="https://example.invalid/pr/1",
                receipt_id="r-1"),
        ])
        code, out, err = run(self.dir, "--list")
        self.assertEqual(code, 0, err)
        lines = out.strip().splitlines()
        self.assertEqual(len(lines), 3, out)
        self.assertEqual([line.split()[0] for line in lines], ["j-high", "j-mid", "j-low"])
        self.assertIn("0.250000 XNO", lines[0])
        self.assertIn("expires %s" % FUTURE, lines[0])

    # -- 2 ------------------------------------------------------------------
    def test_02_list_with_only_an_expired_job_says_no_open_jobs(self):
        write_tree(self.dir, [job("j-old", "1" + "0" * 29, "0.1", expires=PAST)])
        code, out, err = run(self.dir, "--list")
        self.assertEqual(code, 0, err)
        self.assertEqual(out.strip(), "no open jobs")

    # -- 3 ------------------------------------------------------------------
    def test_03_check_address_accepts_genesis_and_burn(self):
        for address in (GENESIS, BURN):
            code, out, _ = run(self.dir, "--check-address", address)
            self.assertEqual(code, 0, address)
            self.assertEqual(out.strip(), "valid")

    # -- 4 ------------------------------------------------------------------
    def test_04_every_single_character_substitution_is_rejected(self):
        alphabet = nanoaddr.ALPHABET + "02lv"
        for address in (GENESIS, BURN):
            for position in range(len(address)):
                for replacement in alphabet:
                    if replacement == address[position]:
                        continue
                    mutated = address[:position] + replacement + address[position + 1:]
                    code, out, _ = run(self.dir, "--check-address", mutated)
                    self.assertEqual(
                        code, 2,
                        "position %d -> %r was accepted: %s" % (position, replacement, out))
                    self.assertTrue(out.startswith("invalid: "), out)

    # -- 5 ------------------------------------------------------------------
    def test_05_a_claim_sets_five_fields_and_touches_no_other_job(self):
        write_tree(self.dir, [
            job("j-1", "1" + "0" * 29, "0.1"),
            job("j-2", "2" + "0" * 29, "0.2"),
            job("j-3", "3" + "0" * 29, "0.3"),
        ])
        code, out, err = run(self.dir, "j-2", "--handle", "a-handle",
                             "--address", GENESIS,
                             "--claim-url", "https://example.invalid/pr/7")
        self.assertEqual(code, 0, err)
        jobs = json.loads(read_bytes(self.dir))["jobs"]
        by_id = {j["id"]: j for j in jobs}
        self.assertEqual(by_id["j-2"]["state"], "claimed")
        self.assertEqual(by_id["j-2"]["claimed_by"], "a-handle")
        self.assertEqual(by_id["j-2"]["payout_address"], GENESIS)
        self.assertEqual(by_id["j-2"]["claim_url"], "https://example.invalid/pr/7")
        self.assertRegex(by_id["j-2"]["claimed_at"], r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
        self.assertEqual(by_id["j-1"]["state"], "open")
        self.assertEqual(by_id["j-3"]["state"], "open")
        self.assertIsNone(by_id["j-1"]["claimed_by"])
        self.assertIsNone(by_id["j-3"]["claimed_by"])

    # -- 6 ------------------------------------------------------------------
    def test_06_the_written_file_is_byte_identical_to_the_expected_serialisation(self):
        before = write_tree(self.dir, [
            job("j-1", "1" + "0" * 29, "0.1"),
            job("j-2", "2" + "0" * 29, "0.2"),
            job("j-3", "3" + "0" * 29, "0.3"),
        ])
        code, out, err = run(self.dir, "j-2", "--handle", "a-handle",
                             "--address", GENESIS,
                             "--claim-url", "https://example.invalid/pr/7")
        self.assertEqual(code, 0, err)
        after = read_bytes(self.dir)

        document = json.loads(before.decode("utf-8"))
        target = [j for j in document["jobs"] if j["id"] == "j-2"][0]
        claimed_at = json.loads(after.decode("utf-8"))
        claimed_at = [j for j in claimed_at["jobs"] if j["id"] == "j-2"][0]["claimed_at"]
        target["state"] = "claimed"
        target["claimed_by"] = "a-handle"
        target["claim_url"] = "https://example.invalid/pr/7"
        target["claimed_at"] = claimed_at
        target["payout_address"] = GENESIS
        expected = (json.dumps(document, indent=2) + "\n").encode("utf-8")
        self.assertEqual(after, expected)

    # -- 7 ------------------------------------------------------------------
    def test_07_json_output_has_exactly_the_documented_keys(self):
        write_tree(self.dir, [job("j-1", "250000000000000000000000000000", "0.25")])
        code, out, err = run(self.dir, "j-1", "--handle", "h", "--address", BURN, "--json")
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(
            sorted(payload),
            sorted(["ok", "job_id", "price_xno", "price_raw", "expires",
                    "payout_address", "acceptance", "next"]))
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["price_xno"], "0.250000")
        self.assertTrue(payload["price_raw"].isdigit(), payload["price_raw"])
        self.assertNotIn(".", payload["price_raw"])
        self.assertNotIn("e", payload["price_raw"].lower())
        self.assertEqual(payload["payout_address"], BURN)
        self.assertEqual(len(payload["next"]), 4)

    # -- 8 ------------------------------------------------------------------
    def test_08_claiming_an_already_claimed_job_exits_4_and_writes_nothing(self):
        write_tree(self.dir, [
            job("j-1", "1" + "0" * 29, "0.1", state="claimed", claimed_by="first",
                claim_url="https://example.invalid/pr/1"),
        ])
        before = read_bytes(self.dir)
        code, out, err = run(self.dir, "j-1", "--handle", "second", "--address", GENESIS)
        self.assertEqual(code, 4)
        self.assertIn("is claimed, not open", err)
        self.assertEqual(read_bytes(self.dir), before)

    # -- 9 ------------------------------------------------------------------
    def test_09_a_bad_checksum_writes_nothing_and_leaves_no_temporary_file(self):
        before = write_tree(self.dir, [job("j-1", "1" + "0" * 29, "0.1")])
        bad = GENESIS[:-1] + ("4" if GENESIS[-1] != "4" else "5")
        code, out, err = run(self.dir, "j-1", "--handle", "h", "--address", bad)
        self.assertEqual(code, 2)
        self.assertIn("refusing to claim: address is invalid: bad_checksum", err)
        self.assertEqual(read_bytes(self.dir), before)
        self.assertEqual(
            [name for name in os.listdir(self.dir) if name.endswith(".tmp")], [])

    # -- 10 -----------------------------------------------------------------
    def test_10_release_restores_the_file_byte_for_byte(self):
        before = write_tree(self.dir, [
            job("j-1", "1" + "0" * 29, "0.1"),
            job("j-2", "2" + "0" * 29, "0.2"),
        ])
        code, _, err = run(self.dir, "j-2", "--handle", "h", "--address", GENESIS,
                           "--claim-url", "https://example.invalid/pr/7")
        self.assertEqual(code, 0, err)
        self.assertNotEqual(read_bytes(self.dir), before)
        code, out, err = run(self.dir, "j-2", "--release")
        self.assertEqual(code, 0, err)
        self.assertEqual(read_bytes(self.dir), before)

    def test_10b_release_refuses_a_job_that_is_not_claimed(self):
        write_tree(self.dir, [job("j-1", "1" + "0" * 29, "0.1")])
        before = read_bytes(self.dir)
        code, _, err = run(self.dir, "j-1", "--release")
        self.assertEqual(code, 4)
        self.assertIn("not claimed", err)
        self.assertEqual(read_bytes(self.dir), before)

    # -- 11 -----------------------------------------------------------------
    def test_11_nothing_on_the_import_graph_can_reach_the_network(self):
        import ast

        forbidden = {"socket", "http", "urllib", "ssl", "requests", "asyncio",
                     "ftplib", "telnetlib", "smtplib", "xmlrpc"}
        local = {}
        for base in (ROOT, os.path.join(ROOT, "vendor")):
            for name in os.listdir(base):
                if name.endswith(".py"):
                    local.setdefault(name[:-3], os.path.join(base, name))

        seen, queue, offences = set(), ["claim"], []
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
                    top = name.split(".")[0]
                    if top in forbidden:
                        offences.append("%s imports %s" % (module, name))
                    queue.append(top)
        self.assertEqual(offences, [], "claim.py must never reach the network")
        self.assertIn("nanoaddr", seen, "the import walk did not reach vendor/nanoaddr.py")

    # -- 12 -----------------------------------------------------------------
    def test_12_a_64_hex_value_is_refused_and_never_echoed(self):
        before = write_tree(self.dir, [job("j-1", "1" + "0" * 29, "0.1")])
        fake_key = "0123456789abcdef" * 4  # built here so no 64-hex literal is committed
        self.assertEqual(len(fake_key), 64)
        code, out, err = run(self.dir, "j-1", "--handle", "h", "--address", fake_key)
        self.assertEqual(code, 2)
        self.assertIn("looks like a private key or seed", err)
        self.assertNotIn(fake_key, out)
        self.assertNotIn(fake_key, err)
        self.assertNotIn(fake_key[:16], out + err)
        self.assertEqual(read_bytes(self.dir), before)

    # -- the remaining error rows of the spec's table ------------------------
    def test_13_unknown_job_exits_3_and_lists_what_is_open(self):
        write_tree(self.dir, [job("j-1", "1" + "0" * 29, "0.1")])
        code, out, err = run(self.dir, "j-nope", "--handle", "h", "--address", GENESIS)
        self.assertEqual(code, 3)
        self.assertIn("no such job: j-nope", err)
        self.assertIn("j-1", err)

    def test_14_an_expired_job_exits_4(self):
        write_tree(self.dir, [job("j-1", "1" + "0" * 29, "0.1", expires=PAST)])
        code, _, err = run(self.dir, "j-1", "--handle", "h", "--address", GENESIS)
        self.assertEqual(code, 4)
        self.assertIn("expired at %s" % PAST, err)

    def test_15_missing_address_and_handle_each_refuse_with_their_own_message(self):
        write_tree(self.dir, [job("j-1", "1" + "0" * 29, "0.1")])
        code, _, err = run(self.dir, "j-1", "--handle", "h")
        self.assertEqual(code, 2)
        self.assertIn("--address is required", err)

        code, _, err = run(self.dir, "j-1", "--address", GENESIS)
        self.assertEqual(code, 2)
        self.assertIn("--handle is required", err)

        code, _, err = run(self.dir, "j-1", "--address", GENESIS, "--handle", "   ")
        self.assertEqual(code, 2)
        self.assertIn("--handle is required", err)

        code, _, err = run(self.dir, "j-1", "--address", GENESIS, "--handle", "a b")
        self.assertEqual(code, 2)
        self.assertIn("--handle must be 1-64 chars", err)

        code, _, err = run(self.dir, "j-1", "--address", GENESIS, "--handle", "x" * 65)
        self.assertEqual(code, 2)
        self.assertIn("--handle must be 1-64 chars", err)

    def test_16_a_claim_url_that_is_not_https_is_refused(self):
        before = write_tree(self.dir, [job("j-1", "1" + "0" * 29, "0.1")])
        code, _, err = run(self.dir, "j-1", "--handle", "h", "--address", GENESIS,
                           "--claim-url", "http://example.invalid/pr/7")
        self.assertEqual(code, 2)
        self.assertIn("--claim-url must be an https URL", err)
        self.assertEqual(read_bytes(self.dir), before)

    def test_17_a_missing_or_malformed_jobs_file_exits_5(self):
        code, _, err = run(self.dir, "--list")
        self.assertEqual(code, 5)
        self.assertIn("jobs.json not found", err)

        with open(os.path.join(self.dir, "jobs.json"), "w", encoding="utf-8") as handle:
            handle.write("{not json")
        code, _, err = run(self.dir, "--list")
        self.assertEqual(code, 5)
        self.assertIn("jobs.json is malformed", err)

        with open(os.path.join(self.dir, "jobs.json"), "w", encoding="utf-8") as handle:
            handle.write('{"currency": "XNO"}')
        code, _, err = run(self.dir, "--list")
        self.assertEqual(code, 5)
        self.assertIn("'jobs' list", err)

    def test_18_more_than_one_job_id_is_refused(self):
        write_tree(self.dir, [job("j-1", "1" + "0" * 29, "0.1")])
        code, _, err = run(self.dir, "j-1", "j-2", "--handle", "h", "--address", GENESIS)
        self.assertEqual(code, 2)
        self.assertIn("one job per claim", err)

    def test_19_a_claim_without_a_claim_url_omits_the_key_and_says_ci_will_refuse(self):
        write_tree(self.dir, [job("j-1", "1" + "0" * 29, "0.1")])
        code, out, err = run(self.dir, "j-1", "--handle", "h", "--address", GENESIS)
        self.assertEqual(code, 0, err)
        target = json.loads(read_bytes(self.dir))["jobs"][0]
        self.assertNotIn("claim_url", target)
        self.assertIn("no --claim-url was given", out)
        self.assertIn("validate.py refuses a claimed job without one", out)

    def test_20_money_is_rendered_from_price_raw_by_integer_arithmetic(self):
        # 1 XNO = 10**30 raw. A float carries ~17 significant digits, so these
        # are the values that catch one: each differs from the next only in a
        # digit a float cannot hold.
        self.assertEqual(claim.format_xno("250000000000000000000000000000"), "0.250000")
        self.assertEqual(claim.format_xno("50000000000000000000000000000"), "0.050000")
        self.assertEqual(claim.format_xno("1" + "0" * 30), "1.000000")
        self.assertEqual(claim.format_xno("0"), "0.000000")
        self.assertEqual(claim.format_xno("1"), "0." + "0" * 29 + "1")
        self.assertEqual(
            claim.format_xno("1000000000000000000000000000001"),
            "1." + "0" * 29 + "1")
        with self.assertRaises(claim.Refused):
            claim.format_xno("0.25")

    def test_21_the_cli_runs_as_a_subprocess_from_a_clone(self):
        # Everything above calls main() in process; this one is the path a
        # seller actually types, including the exit code the shell sees.
        write_tree(self.dir, [job("j-1", "250000000000000000000000000000", "0.25")])
        result = subprocess.run(
            [sys.executable, os.path.join(ROOT, "claim.py"), "--list"],
            cwd=self.dir, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("j-1  0.250000 XNO", result.stdout)

        result = subprocess.run(
            [sys.executable, os.path.join(ROOT, "claim.py"), "--check-address", BURN[:-1] + "q"],
            cwd=self.dir, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout.strip(), "invalid: bad_checksum")


class CanonicalAddress(unittest.TestCase):
    """A claim stores the account, in the one spelling everything else answers."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    def test_a_legacy_spelling_is_stored_as_the_canonical_one(self):
        """settle.py compares accounts, so a stored `xrb_` row still settles -
        but writing it canonically means no new row is ambiguous at all."""
        legacy = "xrb_" + GENESIS.split("_", 1)[1]
        write_tree(self.dir, [job("job-001", str(25 * 10 ** 30 // 100), "0.25")])
        code, _, err = run(self.dir, "job-001", "--handle", "a-seller",
                           "--address", legacy,
                           "--claim-url", "https://example.invalid/pr/1")
        self.assertEqual(code, 0, err)
        stored = json.loads(read_bytes(self.dir))["jobs"][0]["payout_address"]
        self.assertEqual(stored, GENESIS)
        self.assertTrue(stored.startswith("nano_"))

    def test_a_canonical_spelling_is_stored_unchanged(self):
        write_tree(self.dir, [job("job-001", str(25 * 10 ** 30 // 100), "0.25")])
        code, _, err = run(self.dir, "job-001", "--handle", "a-seller",
                           "--address", GENESIS,
                           "--claim-url", "https://example.invalid/pr/1")
        self.assertEqual(code, 0, err)
        self.assertEqual(
            json.loads(read_bytes(self.dir))["jobs"][0]["payout_address"], GENESIS)


if __name__ == "__main__":
    unittest.main()
