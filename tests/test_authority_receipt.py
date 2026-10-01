"""Layer 2: bind the payment to the request, and the signer to the permission.

Every test here builds its own documents. Nothing opens a socket, nothing reads
a file from the repository, and no fixture holds a value captured from a live
origin - so a failure here is a defect in `authority_receipt.py` and never a
network condition.

The clean set is built INDEPENDENTLY of the module's own `--self-test`
controls, deliberately. Driving these assertions from the module's fixtures
would let a mutation that breaks both drift past green, which is the whole
failure mode `--self-test` exists to catch and therefore the last thing this
file should inherit.

No 64-hex run stands as a single literal in this file either: the pinned digest
of test 15 is written as two halves joined at runtime, which is the project's
secret gate and the same idiom `tests/test_custody_probe.py` uses for its
synthetic key material.
"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import authority_receipt  # noqa: E402
import nanoaddr  # noqa: E402
from authority_receipt import (  # noqa: E402
    REASON_ORDER, import_graph, main, request_digest, verify,
)
from custody_probe import NETWORK_MODULES  # noqa: E402  - reused, not re-listed

PAYER_KEY = bytes([0xA1]) * 32
PAYEE_KEY = bytes([0xB2]) * 32
STRANGER_KEY = bytes([0xC3]) * 32

PAYER = nanoaddr.encode(PAYER_KEY)
PAYEE = nanoaddr.encode(PAYEE_KEY)
STRANGER = nanoaddr.encode(STRANGER_KEY)
PAYEE_LEGACY = nanoaddr.encode(PAYEE_KEY, "xrb_")

BLOCK = "1A2B" * 16          # synthetic, built at runtime
OTHER_BLOCK = "9F8E" * 16
RAW = "50000000000000000000000000000"          # 0.05 XNO
LIMIT = "100000000000000000000000000000"       # 0.1 XNO
NOW = "2026-10-01T05:52:50Z"
REQUEST_ID = "job-2026-09-26-003"


def clean():
    """A fully consistent (receipt, grant_bytes, block, request, seen) set."""
    request = {"job": REQUEST_ID, "unit": "one witness report"}
    grant = {
        "version": 1,
        "subject_account": PAYER,
        "policy_epoch": 3,
        "not_before": "2026-09-01T00:00:00Z",
        "not_after": "2026-12-01T00:00:00Z",
        "max_raw_per_payment": LIMIT,
        "allowed_payees": [PAYEE],
        "revoked_blocks": [],
        "revoked_request_ids": [],
    }
    grant_bytes = json.dumps(grant).encode("utf-8")
    receipt = {
        "version": 1,
        "request_id": REQUEST_ID,
        "request_digest": request_digest(request),
        "payer_account": PAYER,
        "payee_account": PAYEE,
        "quoted_raw": RAW,
        "settled_raw": RAW,
        "settled_block": BLOCK,
        "committed_at": NOW,
        "grant": {
            "url": "https://operator.invalid/grants/agent-7.json",
            "sha256": authority_receipt._digest_bytes(grant_bytes),
            "policy_epoch": 3,
        },
    }
    block = {
        "hash": BLOCK,
        "amount": RAW,
        "block_account": PAYER,
        "subtype": "send",
        "confirmed": "true",
        "contents": {"link_as_account": PAYEE},
    }
    return receipt, grant_bytes, block, request, {BLOCK: REQUEST_ID}


def reseal(parts, **changes):
    """Change the grant and re-pin its digest, so one field is under test."""
    grant = json.loads(parts["grant"].decode("utf-8"))
    grant.update(changes)
    payload = json.dumps(grant).encode("utf-8")
    parts["grant"] = payload
    parts["receipt"]["grant"]["sha256"] = authority_receipt._digest_bytes(payload)


def parts_of():
    receipt, grant_bytes, block, request, seen = clean()
    return {"receipt": receipt, "grant": grant_bytes, "block": block,
            "request": request, "seen_blocks": seen}


def run(parts, **overrides):
    call = dict(parts)
    call.update(overrides)
    return verify(call["receipt"], call["grant"], call["block"],
                  request=call.get("request"), now=call.get("now", NOW),
                  seen_blocks=call.get("seen_blocks"))


class CleanSet(unittest.TestCase):
    # -- 1 ------------------------------------------------------------------
    def test_01_a_clean_receipt_passes_and_reports_every_code_as_checked(self):
        verdict = run(parts_of())
        self.assertTrue(verdict["ok"], verdict["reasons"])
        self.assertEqual(verdict["reasons"], [])
        self.assertEqual(verdict["delta_raw"], "0")
        self.assertEqual(sorted(verdict["checked"]), sorted(REASON_ORDER))
        self.assertEqual(len(verdict["checked"]), 18)
        self.assertEqual(verdict["tool"], "authority_receipt")
        self.assertEqual(verdict["request_id"], REQUEST_ID)
        self.assertTrue(verdict["notes"])


class NegativeControls(unittest.TestCase):
    """One case per reason code. A case producing the wrong code is a failure."""

    # -- 2 ------------------------------------------------------------------
    def test_02_one_negative_control_per_reason_code(self):
        cases = {
            "bad_receipt_shape": lambda p: p["receipt"].update({"note": "hello"}),
            "amount_not_integer_string": lambda p: p["receipt"].update({"quoted_raw": 0.05}),
            "bad_block_hash": lambda p: p["receipt"].update({"settled_block": "not-a-hash"}),
            "block_not_confirmed": lambda p: p["block"].update({"confirmed": "false"}),
            "payer_mismatch": lambda p: p["block"].update({"block_account": STRANGER}),
            "payee_mismatch": lambda p: p["block"].update(
                {"contents": {"link_as_account": STRANGER}}),
            "block_amount_mismatch": lambda p: p["block"].update({"amount": "1"}),
            "quote_settlement_delta": lambda p: p["receipt"].update(
                {"quoted_raw": "40000000000000000000000000000"}),
            "request_digest_mismatch": lambda p: p.update({"request": {"job": "another"}}),
            "grant_digest_mismatch": lambda p: p["receipt"]["grant"].update(
                {"sha256": "0" * 64}),
            "grant_subject_mismatch": lambda p: reseal(p, subject_account=STRANGER),
            "policy_epoch_stale": lambda p: reseal(p, policy_epoch=4),
            "outside_grant_window": lambda p: reseal(p, not_after="2026-09-02T00:00:00Z"),
            "over_grant_limit": lambda p: reseal(p, max_raw_per_payment="1"),
            "payee_not_allowed": lambda p: reseal(p, allowed_payees=[]),
            "revoked_block": lambda p: reseal(p, revoked_blocks=[BLOCK]),
            "revoked_request": lambda p: reseal(p, revoked_request_ids=[REQUEST_ID]),
            "replayed_block": lambda p: p.update({"seen_blocks": {BLOCK: "another-job"}}),
        }
        self.assertEqual(sorted(cases), sorted(REASON_ORDER),
                         "every reason code needs exactly one negative control")
        for code, mutate in sorted(cases.items()):
            with self.subTest(code=code):
                parts = parts_of()
                mutate(parts)
                verdict = run(parts)
                self.assertFalse(verdict["ok"])
                self.assertIn(code, verdict["reasons"])
                self.assertIn(code, verdict["checked"])


class Money(unittest.TestCase):
    # -- 3 ------------------------------------------------------------------
    def test_03_a_json_number_in_an_amount_is_refused_not_coerced(self):
        parts = parts_of()
        parts["receipt"]["quoted_raw"] = 0.05
        verdict = run(parts)
        self.assertIn("amount_not_integer_string", verdict["reasons"])
        self.assertFalse(verdict["ok"])
        # With no usable quote there is no delta to report, and reporting one
        # would be inventing a number for money that never parsed.
        self.assertNotIn("delta_raw", verdict)

    def test_03b_the_source_holds_no_binary_fraction_type_at_all(self):
        with open(os.path.join(ROOT, "authority_receipt.py"), "r", encoding="utf-8") as fh:
            source = fh.read()
        self.assertNotIn("f" + "loat", source,
                         "1 XNO is 10**30 raw; a 53-bit mantissa loses digits "
                         "that are somebody's money")

    def test_03c_a_full_raw_amount_survives_without_losing_its_low_digits(self):
        odd = "250000000000000000000000000001"          # 0.25 XNO plus one raw
        parts = parts_of()
        parts["receipt"]["quoted_raw"] = odd
        parts["receipt"]["settled_raw"] = odd
        parts["block"]["amount"] = odd
        reseal(parts, max_raw_per_payment=odd)
        verdict = run(parts)
        self.assertTrue(verdict["ok"], verdict["reasons"])
        self.assertEqual(verdict["delta_raw"], "0")

    def test_03d_the_delta_is_signed_and_exact_at_full_raw_width(self):
        parts = parts_of()
        parts["receipt"]["settled_raw"] = "49999999999999999999999999999"
        parts["block"]["amount"] = "49999999999999999999999999999"
        verdict = run(parts)
        self.assertEqual(verdict["delta_raw"], "-1")
        self.assertIn("quote_settlement_delta", verdict["reasons"])


class Accounts(unittest.TestCase):
    # -- 4 ------------------------------------------------------------------
    def test_04_the_legacy_xrb_spelling_is_the_same_account(self):
        parts = parts_of()
        parts["receipt"]["payee_account"] = PAYEE_LEGACY
        verdict = run(parts)
        self.assertTrue(verdict["ok"], verdict["reasons"])
        self.assertNotEqual(PAYEE_LEGACY, PAYEE, "the two spellings differ as text")

    def test_04b_the_payer_too_is_compared_by_key_not_by_text(self):
        parts = parts_of()
        parts["block"]["block_account"] = nanoaddr.encode(PAYER_KEY, "xrb_")
        self.assertTrue(run(parts)["ok"])


class Constraints(unittest.TestCase):
    # -- 5 ------------------------------------------------------------------
    def test_05_stdlib_only_and_the_network_is_reachable_from_one_function(self):
        allowed_local = {"canonical", "nanoaddr"}
        for entry in import_graph(authority_receipt.__file__):
            module, function = entry["module"], entry["function"]
            root = module.split(".")[0]
            with self.subTest(module=module):
                self.assertTrue(
                    root in sys.stdlib_module_names or module in allowed_local,
                    "%s is neither standard library nor a module of this repository" % module)
                if module in NETWORK_MODULES:
                    self.assertEqual(
                        function, "default_fetch",
                        "%s is imported in %s; the network belongs in default_fetch "
                        "alone, so that verify() cannot reach it" % (module, function))

    # -- 6 ------------------------------------------------------------------
    def test_06_verify_performs_no_io_even_when_the_seam_would_explode(self):
        def explode(timeout=10):
            raise AssertionError("verify() reached the network")

        original = authority_receipt.default_fetch
        authority_receipt.default_fetch = explode
        try:
            verdict = run(parts_of())
        finally:
            authority_receipt.default_fetch = original
        self.assertTrue(verdict["ok"], verdict["reasons"])

    def test_06b_now_is_required_because_the_module_holds_no_clock(self):
        receipt, grant_bytes, block, request, seen = clean()
        for bad in (None, "", "not-a-time", "2026-10-01T05:52:50"):
            with self.subTest(now=bad):
                with self.assertRaises(ValueError):
                    verify(receipt, grant_bytes, block, request=request, now=bad)

    # -- 7 ------------------------------------------------------------------
    def test_07_an_omitted_request_is_reported_unchecked_not_assumed_good(self):
        parts = parts_of()
        parts["request"] = None
        verdict = run(parts)
        self.assertTrue(verdict["ok"], verdict["reasons"])
        self.assertNotIn("request_digest_mismatch", verdict["reasons"])
        self.assertNotIn("request_digest_mismatch", verdict["checked"])
        self.assertLess(len(verdict["checked"]), 18)

    def test_07b_an_omitted_seen_map_is_reported_unchecked(self):
        verdict = run(parts_of(), seen_blocks=None)
        self.assertNotIn("replayed_block", verdict["checked"])

    def test_07c_a_pre_parsed_grant_loses_the_digest_check_and_says_so(self):
        parts = parts_of()
        parts["grant"] = json.loads(parts["grant"].decode("utf-8"))
        verdict = run(parts)
        self.assertNotIn("grant_digest_mismatch", verdict["checked"])
        self.assertTrue(any("bytes as fetched" in note for note in verdict["notes"]))

    # -- 8 ------------------------------------------------------------------
    def test_08_every_check_runs_so_three_defects_come_back_in_one_pass(self):
        parts = parts_of()
        parts["block"]["confirmed"] = "false"
        parts["block"]["contents"] = {"link_as_account": STRANGER}
        reseal(parts, revoked_request_ids=[REQUEST_ID])
        verdict = run(parts)
        for code in ("block_not_confirmed", "payee_mismatch", "revoked_request"):
            self.assertIn(code, verdict["reasons"])
        self.assertEqual(verdict["reasons"], sorted(set(verdict["reasons"])))

    # -- 9 ------------------------------------------------------------------
    def test_09_a_block_cited_by_a_second_request_is_a_replay(self):
        parts = parts_of()
        parts["seen_blocks"] = {BLOCK: "a-different-job"}
        verdict = run(parts)
        self.assertIn("replayed_block", verdict["reasons"])

    def test_09b_the_same_block_cited_by_the_same_request_is_idempotent(self):
        verdict = run(parts_of(), seen_blocks={BLOCK: REQUEST_ID})
        self.assertTrue(verdict["ok"], verdict["reasons"])

    def test_09c_an_unrelated_seen_block_does_not_refuse(self):
        verdict = run(parts_of(), seen_blocks={OTHER_BLOCK: "another-job"})
        self.assertTrue(verdict["ok"], verdict["reasons"])

    # -- 10 -----------------------------------------------------------------
    def test_10_an_unknown_top_level_key_is_a_refusal(self):
        parts = parts_of()
        parts["receipt"]["note"] = "hello"
        self.assertIn("bad_receipt_shape", run(parts)["reasons"])

    def test_10b_a_missing_required_key_is_a_refusal(self):
        for key in sorted(authority_receipt.RECEIPT_KEYS):
            with self.subTest(missing=key):
                parts = parts_of()
                del parts["receipt"][key]
                self.assertIn("bad_receipt_shape", run(parts)["reasons"])

    def test_10c_a_version_other_than_one_is_a_refusal(self):
        for bad in (2, "1", True, None):
            with self.subTest(version=bad):
                parts = parts_of()
                parts["receipt"]["version"] = bad
                self.assertIn("bad_receipt_shape", run(parts)["reasons"])

    # -- 11 -----------------------------------------------------------------
    def test_11_the_grant_digest_is_over_the_bytes_not_over_the_parse(self):
        parts = parts_of()
        document = json.loads(parts["grant"].decode("utf-8"))
        # Same content, different whitespace: identical parse, different bytes.
        parts["grant"] = json.dumps(document, indent=2).encode("utf-8")
        verdict = run(parts)
        self.assertIn("grant_digest_mismatch", verdict["reasons"])
        self.assertFalse(verdict["ok"])

    def test_11b_an_unparseable_grant_refuses_every_grant_dependent_check(self):
        parts = parts_of()
        payload = b"<html>not a grant</html>"
        parts["grant"] = payload
        parts["receipt"]["grant"]["sha256"] = authority_receipt._digest_bytes(payload)
        verdict = run(parts)
        self.assertFalse(verdict["ok"])
        # The digest itself is fine - the bytes are what was pinned. Everything
        # the grant was supposed to establish must still refuse, not pass.
        self.assertNotIn("grant_digest_mismatch", verdict["reasons"])
        for code in ("grant_subject_mismatch", "policy_epoch_stale",
                     "outside_grant_window", "over_grant_limit",
                     "payee_not_allowed", "revoked_block", "revoked_request"):
            self.assertIn(code, verdict["reasons"], code)

    # -- 12 -----------------------------------------------------------------
    def test_12_the_grant_window_is_inclusive_at_both_ends(self):
        for edge in ("not_before", "not_after"):
            with self.subTest(edge=edge):
                parts = parts_of()
                grant = json.loads(parts["grant"].decode("utf-8"))
                reseal(parts)
                parts["receipt"]["committed_at"] = grant[edge]
                verdict = run(parts)
                self.assertTrue(verdict["ok"], verdict["reasons"])

    def test_12b_one_second_outside_either_end_is_refused(self):
        for committed in ("2026-08-31T23:59:59Z", "2026-12-01T00:00:01Z"):
            with self.subTest(committed_at=committed):
                parts = parts_of()
                parts["receipt"]["committed_at"] = committed
                self.assertIn("outside_grant_window", run(parts)["reasons"])

    def test_12c_an_offset_timestamp_is_the_same_moment_as_its_utc_spelling(self):
        parts = parts_of()
        parts["receipt"]["committed_at"] = "2026-09-01T02:00:00+02:00"   # == not_before
        self.assertTrue(run(parts)["ok"])

    # -- 13 -----------------------------------------------------------------
    def test_13_an_empty_allowed_payees_list_allows_nobody(self):
        parts = parts_of()
        reseal(parts, allowed_payees=[])
        self.assertIn("payee_not_allowed", run(parts)["reasons"])

    def test_13b_a_wildcard_allows_any_payee(self):
        parts = parts_of()
        reseal(parts, allowed_payees="*")
        self.assertTrue(run(parts)["ok"], "a wildcard is the one blanket permission")

    def test_13c_a_payee_absent_from_a_populated_list_is_refused(self):
        parts = parts_of()
        reseal(parts, allowed_payees=[STRANGER])
        self.assertIn("payee_not_allowed", run(parts)["reasons"])


class SelfTest(unittest.TestCase):
    # -- 14 -----------------------------------------------------------------
    def test_14_self_test_fails_when_verify_can_no_longer_refuse(self):
        def always_ok(*args, **kwargs):
            return {"tool": "authority_receipt", "version": 1, "ok": True,
                    "reasons": [], "checked": list(REASON_ORDER),
                    "request_id": REQUEST_ID, "settled_block": BLOCK, "notes": []}

        original = authority_receipt.verify
        authority_receipt.verify = always_ok
        try:
            with open(os.devnull, "w", encoding="utf-8") as sink:
                stdout, sys.stdout = sys.stdout, sink
                try:
                    code = authority_receipt.self_test()
                finally:
                    sys.stdout = stdout
        finally:
            authority_receipt.verify = original
        self.assertEqual(code, 1, "a verifier that cannot fail must fail its own controls")

    def test_14b_self_test_passes_as_shipped(self):
        with open(os.devnull, "w", encoding="utf-8") as sink:
            stdout, sys.stdout = sys.stdout, sink
            try:
                code = authority_receipt.self_test()
            finally:
                sys.stdout = stdout
        self.assertEqual(code, 0)


class Digest(unittest.TestCase):
    # -- 15 -----------------------------------------------------------------
    def test_15_the_canonical_digest_is_stable_and_pinned(self):
        pinned = "ed27301157c61775e8c20bd8855672fb" + "df01990a519e251363eb2b996a1c3a68"
        first = {"b": "café", "a": 1, "z": [3, 2, 1]}
        second = {"z": [3, 2, 1], "a": 1, "b": "café"}
        self.assertEqual(request_digest(first), request_digest(second),
                         "key order must not change the digest")
        self.assertEqual(request_digest(first), pinned,
                         "changing the serialisation rule breaks every payer "
                         "and seller that already agreed on a request_digest")


class Cli(unittest.TestCase):
    def files(self, parts):
        directory = tempfile.mkdtemp()
        paths = {}
        for name in ("receipt", "block", "request", "seen_blocks"):
            value = parts.get(name)
            if value is None:
                continue
            path = os.path.join(directory, name + ".json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(value, handle)
            paths[name] = path
        grant_path = os.path.join(directory, "grant.json")
        with open(grant_path, "wb") as handle:
            handle.write(parts["grant"])
        paths["grant"] = grant_path
        return paths

    def cli(self, argv):
        return subprocess.run(
            [sys.executable, os.path.join(ROOT, "authority_receipt.py")] + argv,
            capture_output=True, text=True, cwd=ROOT)

    def argv_for(self, paths, now=NOW):
        argv = ["verify", "--receipt", paths["receipt"], "--grant", paths["grant"],
                "--block", paths["block"]]
        if "request" in paths:
            argv += ["--request", paths["request"]]
        if "seen_blocks" in paths:
            argv += ["--seen", paths["seen_blocks"]]
        if now is not None:
            argv += ["--now", now]
        return argv

    # -- 16 -----------------------------------------------------------------
    def test_16_a_clean_set_exits_zero(self):
        done = self.cli(self.argv_for(self.files(parts_of())))
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(json.loads(done.stdout)["ok"])

    def test_16b_a_refused_set_exits_one(self):
        parts = parts_of()
        parts["block"]["confirmed"] = "false"
        done = self.cli(self.argv_for(self.files(parts)))
        self.assertEqual(done.returncode, 1)
        self.assertIn("block_not_confirmed", json.loads(done.stdout)["reasons"])

    def test_16c_a_missing_now_exits_two_and_writes_nothing_to_stdout(self):
        done = self.cli(self.argv_for(self.files(parts_of()), now=None))
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")
        self.assertTrue(done.stderr)

    def test_16d_an_unreadable_document_exits_two(self):
        paths = self.files(parts_of())
        paths["receipt"] = os.path.join(os.path.dirname(paths["receipt"]), "absent.json")
        done = self.cli(self.argv_for(paths))
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")

    def test_16e_quiet_prints_nothing_and_still_carries_the_verdict_in_its_code(self):
        done = self.cli(self.argv_for(self.files(parts_of())) + ["--quiet"])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, "")

    def test_16f_digest_prints_the_canonical_hash_and_exits_zero(self):
        paths = self.files(parts_of())
        done = self.cli(["digest", "--request", paths["request"]])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout.strip(),
                         request_digest({"job": REQUEST_ID, "unit": "one witness report"}))

    def test_16g_self_test_exits_zero_from_the_command_line(self):
        done = self.cli(["--self-test"])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout)["self_test"], "pass")

    def test_16h_no_command_exits_two(self):
        done = self.cli([])
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")


class Leaks(unittest.TestCase):
    # -- 17 -----------------------------------------------------------------
    def test_17_the_verdict_names_no_hash_but_the_block_and_no_key_material(self):
        import custody_probe

        verdict = run(parts_of())
        serialised = json.dumps(verdict)
        found = custody_probe.HEX64_RE.findall(serialised)
        self.assertEqual(found, [verdict["settled_block"]],
                         "the only 64-hex run in a verdict is the block it is about: "
                         "a request_digest or a grant digest echoed here would put a "
                         "pinned secret-shaped value into logs")
        for forbidden in ("seed", "private_key", "privateKey", "secret",
                          "mnemonic", "passphrase", "wallet_key"):
            self.assertNotIn(forbidden, serialised)

    def test_17b_a_refusal_leaks_no_more_than_a_pass(self):
        parts = parts_of()
        reseal(parts, revoked_blocks=[BLOCK])
        import custody_probe

        serialised = json.dumps(run(parts))
        self.assertEqual(custody_probe.HEX64_RE.findall(serialised), [BLOCK])


if __name__ == "__main__":
    unittest.main()
