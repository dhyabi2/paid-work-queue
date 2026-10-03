"""Minting the permission, and proving the verifier accepts it.

The decisive test in this file is test 3. Every other artifact in this
repository sits on the payee side; `authority_receipt.py` has always been able
to CONSUME a grant and nothing could PRODUCE one, so a round trip - mint a
grant, cite it in a receipt, hand both to `authority_receipt.verify`, get a
pass - was a test that could not be written. It can now, and if it ever goes
red the operator's policy is unstateable again.

Every fixture here is built independently of `grant_mint`'s own `--self-test`
controls, deliberately: driving these assertions from the module's fixtures
would let a mutation that breaks both drift past green, which is the whole
failure mode `--self-test` exists to catch.

Nothing opens a socket. `publish-check` is exercised through its injected
`fetcher`, not against a listening port, because this repository's rule is no
network at any point in the suite - and a fake fetcher can serve the one thing
a real server cannot be made to serve reliably, which is byte-for-byte
identical content with a single space added.

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

import authority_receipt  # noqa: E402
import grant_mint  # noqa: E402
import nanoaddr  # noqa: E402
from authority_receipt import GRANT_KEYS, REASON_ORDER, request_digest  # noqa: E402
from custody_probe import NETWORK_MODULES  # noqa: E402  - reused, not re-listed
from grant_mint import (  # noqa: E402
    Refusal, bump, digest, grant_defects, main, mint, publish_check, serialise,
)

SCRIPT = os.path.join(ROOT, "grant_mint.py")

# Distinct from the module's controls on purpose - see the docstring.
PAYER = nanoaddr.encode(bytes([0xD4]) * 32)
PAYEE = nanoaddr.encode(bytes([0xE5]) * 32)
STRANGER = nanoaddr.encode(bytes([0xF6]) * 32)
PAYEE_LEGACY = nanoaddr.encode(bytes([0xE5]) * 32, "xrb_")

BLOCK = "7C4D" * 16                              # built at runtime, never a literal
OTHER_BLOCK = "2E6F" * 16
RAW = "50000000000000000000000000000"             # 0.05 XNO
LIMIT = "250000000000000000000000000000"          # 0.25 XNO
NOW = "2026-10-03T06:00:00Z"
NOT_BEFORE = "2026-09-01T00:00:00Z"
NOT_AFTER = "2026-12-01T00:00:00Z"
URL = "https" + "://operator.invalid/grants/d4.json"
REQUEST_ID = "job-2026-09-26-001"
REQUEST = {"job": REQUEST_ID, "unit": "one witness report"}

# The eight codes authority_receipt can report about a grant. Read out of the
# verifier's own REASON_ORDER so a rename there fails HERE rather than silently
# reducing this file's coverage.
GRANT_CODES = tuple(code for code in REASON_ORDER if code in {
    "grant_digest_mismatch", "grant_subject_mismatch", "policy_epoch_stale",
    "outside_grant_window", "over_grant_limit", "payee_not_allowed",
    "revoked_block", "revoked_request"})


def a_grant(**over):
    """Mint a clean grant. Returns (grant, bytes, ref)."""
    kwargs = dict(subject=PAYER, max_raw=LIMIT, not_before=NOT_BEFORE,
                  not_after=NOT_AFTER, allow_payees=[PAYEE], url=URL, now=NOW)
    kwargs.update(over)
    grant, payload, ref, _warnings = mint(**kwargs)
    return grant, payload, ref


def a_receipt(ref, payer=PAYER, payee=PAYEE, quoted=RAW, settled=RAW,
              block_hash=BLOCK, committed=NOW, request_id=REQUEST_ID):
    return {
        "version": 1,
        "request_id": request_id,
        "request_digest": request_digest(REQUEST),
        "payer_account": payer,
        "payee_account": payee,
        "quoted_raw": quoted,
        "settled_raw": settled,
        "settled_block": block_hash,
        "committed_at": committed,
        "grant": dict(ref),
    }


def a_block(payer=PAYER, payee=PAYEE, amount=RAW, block_hash=BLOCK):
    return {
        "hash": block_hash,
        "amount": amount,
        "block_account": payer,
        "subtype": "send",
        "confirmed": "true",
        "contents": {"link_as_account": payee},
    }


def reseal(grant, **changes):
    """Change a grant and re-pin its digest, so exactly one field is under test."""
    updated = dict(grant)
    updated.update(changes)
    payload = serialise(updated)
    ref = {"url": URL, "sha256": digest(payload),
           "policy_epoch": updated["policy_epoch"]}
    return updated, payload, ref


def run(*argv, **kwargs):
    """The CLI as a user runs it, so exit codes and streams are under test."""
    return subprocess.run(
        [sys.executable, SCRIPT] + list(argv),
        capture_output=True, text=True, cwd=ROOT, timeout=60, **kwargs)


def fixed_fetcher(status, payload):
    def fetcher(url, timeout=10):
        return status, payload
    return fetcher


class MintShape(unittest.TestCase):
    # -- 1 ------------------------------------------------------------------
    def test_01_key_set_is_exactly_the_verifiers(self):
        """An extra key is a bug, not a feature, and a missing one is fatal."""
        grant, _payload, _ref = a_grant()
        self.assertEqual(set(grant), set(GRANT_KEYS))

    def test_01b_reference_block_is_exactly_what_a_receipt_carries(self):
        _grant, _payload, ref = a_grant()
        self.assertEqual(set(ref), set(authority_receipt.GRANT_REF_KEYS))
        self.assertEqual(ref["url"], URL)
        self.assertEqual(ref["policy_epoch"], 1)

    # -- 2 ------------------------------------------------------------------
    def test_02_digest_is_of_the_bytes_that_reach_the_disk(self):
        """Re-read from disk and re-hash: the whole spec is this invariant."""
        with tempfile.TemporaryDirectory() as box:
            path = os.path.join(box, "grant.json")
            result = run("mint", "--subject", PAYER, "--max-raw", LIMIT,
                         "--not-before", NOT_BEFORE, "--not-after", NOT_AFTER,
                         "--allow-payee", PAYEE, "--url", URL, "--now", NOW,
                         "--out", path)
            self.assertEqual(result.returncode, 0, result.stderr)
            ref = json.loads(result.stdout)
            with open(path, "rb") as handle:
                on_disk = handle.read()
            self.assertEqual(digest(on_disk), ref["sha256"])
            # And the bytes are the ones the library would have produced.
            self.assertEqual(on_disk, serialise(json.loads(on_disk.decode("utf-8"))))
            self.assertTrue(on_disk.endswith(b"\n"))

    # -- 9 ------------------------------------------------------------------
    def test_09_bytes_are_stable_across_repeats_and_argument_order(self):
        first = run("mint", "--subject", PAYER, "--max-raw", LIMIT,
                    "--not-before", NOT_BEFORE, "--not-after", NOT_AFTER,
                    "--allow-payee", PAYEE, "--url", URL, "--now", NOW)
        second = run("mint", "--now", NOW, "--url", URL, "--allow-payee", PAYEE,
                     "--not-after", NOT_AFTER, "--not-before", NOT_BEFORE,
                     "--max-raw", LIMIT, "--subject", PAYER)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(first.stdout, second.stdout)

    def test_09b_equivalent_spellings_mint_identical_bytes(self):
        """A normalised input is what makes the digest a property of the policy."""
        plain, _p, _r = a_grant()
        padded, _p2, _r2 = a_grant(max_raw="0" * 3 + LIMIT)
        self.assertEqual(serialise(plain), serialise(padded))
        offset, _p3, _r3 = a_grant(not_after="2026-12-01T01:00:00+01:00")
        self.assertEqual(offset["not_after"], NOT_AFTER)
        legacy, _p4, _r4 = a_grant(allow_payees=[PAYEE_LEGACY])
        self.assertEqual(legacy["allowed_payees"], [PAYEE])

    # -- 7 ------------------------------------------------------------------
    def test_07_no_payee_emits_an_empty_list_and_warns_but_succeeds(self):
        result = run("mint", "--subject", PAYER, "--max-raw", LIMIT,
                     "--not-before", NOT_BEFORE, "--not-after", NOT_AFTER,
                     "--url", URL, "--now", NOW)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("allowed_payees is empty", result.stderr)
        self.assertIn("payee_not_allowed", result.stderr)
        grant = json.loads(result.stdout[:result.stdout.index("}\n{") + 1]
                           if "}\n{" in result.stdout else result.stdout)
        self.assertEqual(grant["allowed_payees"], [])

    def test_07b_a_grant_without_a_url_warns_that_it_cannot_be_cited(self):
        _grant, _payload, ref = a_grant(url=None)
        self.assertIsNone(ref["url"])
        result = run("mint", "--subject", PAYER, "--max-raw", LIMIT,
                     "--not-after", NOT_AFTER, "--allow-payee", PAYEE, "--now", NOW)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("cannot be cited", result.stderr)

    def test_07c_zero_max_raw_is_legal_and_refuses_every_payment(self):
        """The pre-stage shape: a grant that exists before the wallet is funded."""
        _grant, payload, ref = a_grant(max_raw="0")
        verdict = authority_receipt.verify(a_receipt(ref), payload, a_block(),
                                           request=REQUEST, now=NOW)
        self.assertFalse(verdict["ok"])
        self.assertEqual(verdict["reasons"], ["over_grant_limit"])

    def test_07d_not_before_defaults_to_now(self):
        grant, _payload, _ref = a_grant(not_before=None)
        self.assertEqual(grant["not_before"], NOW)


class RoundTrip(unittest.TestCase):
    """Test 3, and the eight negative controls that give it meaning."""

    # -- 3 ------------------------------------------------------------------
    def test_03_a_minted_grant_verifies_end_to_end(self):
        """THE test that could not be written before this file existed."""
        _grant, payload, ref = a_grant()
        verdict = authority_receipt.verify(a_receipt(ref), payload, a_block(),
                                           request=REQUEST, now=NOW)
        self.assertTrue(verdict["ok"], verdict["reasons"])
        self.assertEqual(verdict["reasons"], [])
        # Every grant-related code was actually evaluated, not skipped.
        for code in GRANT_CODES:
            self.assertIn(code, verdict["checked"])

    def test_03b_the_cli_output_feeds_the_verifier_unchanged(self):
        """The two tools agree through files, which is how they will be used."""
        with tempfile.TemporaryDirectory() as box:
            path = os.path.join(box, "grant.json")
            result = run("mint", "--subject", PAYER, "--max-raw", LIMIT,
                         "--not-before", NOT_BEFORE, "--not-after", NOT_AFTER,
                         "--allow-payee", PAYEE, "--url", URL, "--now", NOW,
                         "--out", path)
            self.assertEqual(result.returncode, 0, result.stderr)
            with open(path, "rb") as handle:
                payload = handle.read()
            verdict = authority_receipt.verify(
                a_receipt(json.loads(result.stdout)), payload, a_block(),
                request=REQUEST, now=NOW)
            self.assertTrue(verdict["ok"], verdict["reasons"])

    # -- 4: eight codes, one test each --------------------------------------
    def _assert_only(self, code, receipt, payload):
        verdict = authority_receipt.verify(receipt, payload, a_block(),
                                           request=REQUEST, now=NOW)
        self.assertFalse(verdict["ok"])
        self.assertEqual(verdict["reasons"], [code])

    def test_04a_grant_digest_mismatch(self):
        """The one control that must NOT re-pin: bytes changed after publication."""
        _grant, payload, ref = a_grant()
        tampered = payload.replace(b'\n  "version"', b'\n   "version"', 1)
        self.assertNotEqual(tampered, payload)
        self._assert_only("grant_digest_mismatch", a_receipt(ref), tampered)

    def test_04b_grant_subject_mismatch(self):
        grant, _payload, _ref = a_grant()
        _g, payload, ref = reseal(grant, subject_account=STRANGER)
        self._assert_only("grant_subject_mismatch", a_receipt(ref), payload)

    def test_04c_policy_epoch_stale(self):
        grant, _payload, _ref = a_grant()
        _g, payload, ref = reseal(grant, policy_epoch=2)
        receipt = a_receipt(ref)
        receipt["grant"]["policy_epoch"] = 1
        self._assert_only("policy_epoch_stale", receipt, payload)

    def test_04d_outside_grant_window(self):
        grant, _payload, _ref = a_grant()
        _g, payload, ref = reseal(grant, not_before="2026-10-04T00:00:00Z",
                                  not_after="2026-10-05T00:00:00Z")
        self._assert_only("outside_grant_window", a_receipt(ref), payload)

    def test_04e_over_grant_limit(self):
        grant, _payload, _ref = a_grant()
        _g, payload, ref = reseal(grant, max_raw_per_payment="1")
        self._assert_only("over_grant_limit", a_receipt(ref), payload)

    def test_04f_payee_not_allowed(self):
        grant, _payload, _ref = a_grant()
        _g, payload, ref = reseal(grant, allowed_payees=[STRANGER])
        self._assert_only("payee_not_allowed", a_receipt(ref), payload)

    def test_04g_revoked_block(self):
        grant, _payload, _ref = a_grant()
        _g, payload, ref = reseal(grant, revoked_blocks=[BLOCK])
        self._assert_only("revoked_block", a_receipt(ref), payload)

    def test_04h_revoked_request(self):
        grant, _payload, _ref = a_grant()
        _g, payload, ref = reseal(grant, revoked_request_ids=[REQUEST_ID])
        self._assert_only("revoked_request", a_receipt(ref), payload)

    def test_04i_a_legacy_spelling_of_an_allowed_payee_still_passes(self):
        """`xrb_` and `nano_` name one account; the grant must not care."""
        _grant, payload, ref = a_grant(allow_payees=[PAYEE_LEGACY])
        verdict = authority_receipt.verify(a_receipt(ref), payload, a_block(),
                                           request=REQUEST, now=NOW)
        self.assertTrue(verdict["ok"], verdict["reasons"])


class Bump(unittest.TestCase):
    # -- 5 ------------------------------------------------------------------
    def test_05_bump_increments_by_exactly_one_and_stales_the_old_receipt(self):
        _grant, payload, ref = a_grant()
        bumped, bumped_payload, bumped_ref, _w = bump(payload, url=URL)
        self.assertEqual(bumped["policy_epoch"], 2)
        self.assertEqual(bumped_ref["policy_epoch"], 2)
        # A receipt citing the pre-bump epoch no longer verifies: that IS
        # revocation here, because Nano cannot un-send a block.
        verdict = authority_receipt.verify(a_receipt(ref), bumped_payload, a_block(),
                                           request=REQUEST, now=NOW)
        self.assertFalse(verdict["ok"])
        self.assertIn("policy_epoch_stale", verdict["reasons"])
        # A receipt citing the NEW epoch verifies again.
        fresh = authority_receipt.verify(a_receipt(bumped_ref), bumped_payload,
                                         a_block(), request=REQUEST, now=NOW)
        self.assertTrue(fresh["ok"], fresh["reasons"])

    # -- 6 ------------------------------------------------------------------
    def test_06_bump_appends_dedupes_and_preserves_order(self):
        _grant, payload, _ref = a_grant()
        once, payload_once, _r1, _w = bump(payload, revoke_blocks=[BLOCK], url=URL)
        self.assertEqual(once["revoked_blocks"], [BLOCK.upper()])
        twice, payload_twice, _r2, _w = bump(
            payload_once, revoke_blocks=[OTHER_BLOCK, BLOCK], url=URL)
        self.assertEqual(twice["revoked_blocks"], [BLOCK.upper(), OTHER_BLOCK.upper()])
        self.assertEqual(twice["policy_epoch"], 3)
        # An exact repeat must not grow the document.
        again, _p, _r3, _w = bump(payload_twice, revoke_blocks=[OTHER_BLOCK], url=URL)
        self.assertEqual(again["revoked_blocks"], twice["revoked_blocks"])

    def test_06b_bump_appends_request_ids_newest_last_and_dedupes(self):
        _grant, payload, _ref = a_grant()
        once, payload_once, _r, _w = bump(payload, revoke_requests=[REQUEST_ID], url=URL)
        self.assertEqual(once["revoked_request_ids"], [REQUEST_ID])
        twice, _p, _r2, _w = bump(payload_once,
                                  revoke_requests=["job-other", REQUEST_ID], url=URL)
        self.assertEqual(twice["revoked_request_ids"], [REQUEST_ID, "job-other"])

    def test_06c_bump_can_tighten_the_limit_and_the_window(self):
        _grant, payload, _ref = a_grant()
        tighter, tight_payload, tight_ref, _w = bump(
            payload, max_raw="1", not_after="2026-11-01T00:00:00Z", url=URL)
        self.assertEqual(tighter["max_raw_per_payment"], "1")
        self.assertEqual(tighter["not_after"], "2026-11-01T00:00:00Z")
        verdict = authority_receipt.verify(a_receipt(tight_ref), tight_payload,
                                           a_block(), request=REQUEST, now=NOW)
        self.assertEqual(verdict["reasons"], ["over_grant_limit"])

    def test_06d_bump_keeps_every_other_key_untouched(self):
        grant, payload, _ref = a_grant()
        bumped, _p, _r, _w = bump(payload, url=URL)
        for key in set(GRANT_KEYS) - {"policy_epoch"}:
            self.assertEqual(bumped[key], grant[key], key)

    def test_06e_bump_refuses_a_window_it_would_empty(self):
        _grant, payload, _ref = a_grant()
        with self.assertRaises(Refusal) as caught:
            bump(payload, not_after="2026-08-01T00:00:00Z", url=URL)
        self.assertEqual(caught.exception.code, "empty_grant_window")


class ErrorTable(unittest.TestCase):
    """Every row of the spec's error table: exit 2, the exact code, no stdout."""

    def _refused(self, code, *argv):
        result = run(*argv)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "", "a refusal must never print a partial grant")
        body = json.loads(result.stderr)
        self.assertEqual(body["tool"], "grant_mint")
        self.assertEqual(body["error"], code)
        self.assertTrue(body["detail"])

    def _mint_args(self, **over):
        args = {"--subject": PAYER, "--max-raw": LIMIT, "--not-after": NOT_AFTER,
                "--not-before": NOT_BEFORE, "--now": NOW, "--url": URL}
        args.update(over)
        flat = ["mint"]
        for key, value in args.items():
            if value is not None:
                flat += [key, value]
        return flat

    def test_08a_invalid_subject_account(self):
        broken = PAYER[:-1] + ("3" if PAYER[-1] != "3" else "4")
        self._refused("invalid_subject_account", *self._mint_args(**{"--subject": broken}))

    def test_08b_invalid_payee_account(self):
        broken = PAYEE[:-1] + ("3" if PAYEE[-1] != "3" else "4")
        self._refused("invalid_payee_account",
                      *(self._mint_args() + ["--allow-payee", broken]))

    def test_08c_max_raw_not_integer_string(self):
        self._refused("max_raw_not_integer_string",
                      *self._mint_args(**{"--max-raw": "1.5"}))

    def test_08d_max_raw_rejects_every_funny_spelling(self):
        for spelling in ("+1", "1_000", " 1", "1e30", "-1", "0x10", "", "\u00b2"):
            with self.subTest(spelling=spelling):
                self._refused("max_raw_not_integer_string",
                              *self._mint_args(**{"--max-raw": spelling}))

    def test_08e_empty_grant_window(self):
        self._refused("empty_grant_window",
                      *self._mint_args(**{"--not-after": NOT_BEFORE}))

    def test_08f_timestamp_not_absolute(self):
        self._refused("timestamp_not_absolute",
                      *self._mint_args(**{"--not-after": "2026-12-01T00:00:00"}))
        self._refused("timestamp_not_absolute",
                      *self._mint_args(**{"--not-before": "2026-09-01T00:00:00"}))

    def test_08g_policy_epoch_out_of_range(self):
        for epoch in ("0", "-1", "abc"):
            with self.subTest(epoch=epoch):
                self._refused("policy_epoch_out_of_range",
                              *(self._mint_args() + ["--policy-epoch", epoch]))

    def test_08h_grant_url_not_https(self):
        self._refused("grant_url_not_https",
                      *self._mint_args(**{"--url": "htt" + "p://operator.invalid/g.json"}))

    def test_08i_bad_grant_shape(self):
        with tempfile.TemporaryDirectory() as box:
            path = os.path.join(box, "not-a-grant.json")
            with open(path, "w", encoding="utf-8") as handle:
                handle.write('{"hello": "world"}\n')
            self._refused("bad_grant_shape", "bump", "--grant", path, "--url", URL)

    def test_08j_bad_block_hash(self):
        with tempfile.TemporaryDirectory() as box:
            path = os.path.join(box, "grant.json")
            _grant, payload, _ref = a_grant()
            with open(path, "wb") as handle:
                handle.write(payload)
            self._refused("bad_block_hash", "bump", "--grant", path,
                          "--revoke-block", "not-a-hash", "--url", URL)

    def test_08k_now_not_parseable(self):
        self._refused("now_not_parseable", *self._mint_args(**{"--now": "yesterday"}))

    def test_08l_a_revoke_request_must_be_sane(self):
        _grant, payload, _ref = a_grant()
        for bad in ("", "   ", "x" * 257):
            with self.subTest(value=bad):
                with self.assertRaises(Refusal) as caught:
                    bump(payload, revoke_requests=[bad], url=URL)
                self.assertEqual(caught.exception.code, "bad_revoke_request")

    def test_08m_a_grant_with_an_extra_key_is_not_a_grant(self):
        grant, _payload, _ref = a_grant()
        grant["surprise"] = True
        self.assertIsNotNone(grant_defects(grant))
        with self.assertRaises(Refusal) as caught:
            bump(serialise(grant), url=URL)
        self.assertEqual(caught.exception.code, "bad_grant_shape")

    def test_08n_no_subcommand_is_exit_two(self):
        result = run()
        self.assertEqual(result.returncode, 2)


class PublishCheck(unittest.TestCase):
    """Test 10, through the injected fetcher: no socket, exact bytes."""

    def test_10a_matching_bytes_are_ok(self):
        _grant, payload, ref = a_grant()
        verdict = publish_check(ref, expected_subject=PAYER,
                                fetcher=fixed_fetcher(200, payload))
        self.assertTrue(verdict["ok"], verdict["reasons"])
        self.assertEqual(verdict["reasons"], [])
        self.assertEqual(verdict["http_status"], 200)
        self.assertEqual(verdict["bytes_received"], len(payload))
        self.assertEqual(verdict["sha256_received"], ref["sha256"])

    def test_10b_one_added_space_is_a_digest_mismatch(self):
        """The failure a CDN causes, and the reason the note is shouted."""
        _grant, payload, ref = a_grant()
        verdict = publish_check(ref, fetcher=fixed_fetcher(200, payload + b" "))
        self.assertFalse(verdict["ok"])
        self.assertIn("digest_mismatch", verdict["reasons"])
        self.assertTrue(any("re-serialising" in note for note in verdict["notes"]))

    def test_10c_a_reindented_grant_is_a_digest_mismatch(self):
        """Semantically identical, byte-different: the whole point of the rule."""
        grant, _payload, ref = a_grant()
        reindented = (json.dumps(grant, indent=4, sort_keys=True) + "\n").encode("utf-8")
        verdict = publish_check(ref, fetcher=fixed_fetcher(200, reindented))
        self.assertFalse(verdict["ok"])
        self.assertIn("digest_mismatch", verdict["reasons"])
        # It is still a valid grant, so shape must NOT be blamed.
        self.assertNotIn("bad_grant_shape", verdict["reasons"])

    def test_10d_a_404_is_http_not_200(self):
        _grant, _payload, ref = a_grant()
        verdict = publish_check(ref, fetcher=fixed_fetcher(404, b"not found"))
        self.assertFalse(verdict["ok"])
        self.assertIn("http_not_200", verdict["reasons"])

    def test_10e_a_higher_served_epoch_is_a_policy_epoch_mismatch(self):
        _grant, payload, ref = a_grant()
        bumped, bumped_payload, _bumped_ref, _w = bump(payload, url=URL)
        verdict = publish_check(ref, fetcher=fixed_fetcher(200, bumped_payload))
        self.assertFalse(verdict["ok"])
        self.assertIn("policy_epoch_mismatch", verdict["reasons"])
        self.assertEqual(verdict["policy_epoch_served"], 2)
        self.assertEqual(verdict["policy_epoch_expected"], 1)

    def test_10f_a_served_stranger_is_a_subject_mismatch(self):
        _grant, payload, ref = a_grant()
        verdict = publish_check(ref, expected_subject=STRANGER,
                                fetcher=fixed_fetcher(200, payload))
        self.assertFalse(verdict["ok"])
        self.assertIn("subject_mismatch", verdict["reasons"])

    def test_10g_not_json_and_bad_shape_are_distinct(self):
        _grant, _payload, ref = a_grant()
        self.assertIn("not_json",
                      publish_check(ref, fetcher=fixed_fetcher(200, b"<html>"))["reasons"])
        shaped = publish_check(ref, fetcher=fixed_fetcher(200, b'{"a": 1}'))
        self.assertIn("bad_grant_shape", shaped["reasons"])
        self.assertNotIn("not_json", shaped["reasons"])

    def test_10h_a_transport_failure_is_fetch_failed(self):
        _grant, _payload, ref = a_grant()

        def broken(url, timeout=10):
            raise grant_mint.FetchFailed("name or service not known")

        verdict = publish_check(ref, fetcher=broken)
        self.assertEqual(verdict["reasons"], ["fetch_failed"])
        self.assertIsNone(verdict["http_status"])

    def test_10i_a_grant_with_no_url_cannot_be_checked(self):
        _grant, _payload, ref = a_grant(url=None)
        verdict = publish_check(ref, fetcher=fixed_fetcher(200, b"{}"))
        self.assertIn("fetch_failed", verdict["reasons"])

    def test_10j_reasons_come_back_in_the_closed_order(self):
        _grant, _payload, ref = a_grant()
        verdict = publish_check(ref, expected_subject=PAYER,
                                fetcher=fixed_fetcher(500, b"<html>"))
        order = list(grant_mint.PUBLISH_REASON_ORDER)
        positions = [order.index(code) for code in verdict["reasons"]]
        self.assertEqual(positions, sorted(positions))
        for code in verdict["reasons"]:
            self.assertIn(code, order)

    def test_10k_the_unchecked_subject_is_declared_not_hidden(self):
        _grant, payload, ref = a_grant()
        verdict = publish_check(ref, fetcher=fixed_fetcher(200, payload))
        self.assertTrue(any("subject_mismatch was not checked" in note
                            for note in verdict["notes"]))


class Vector(unittest.TestCase):
    # -- 11 -----------------------------------------------------------------
    def test_11_the_cli_reproduces_the_pinned_vector(self):
        """One fixture, checked by both the CLI and the consent page."""
        with open(os.path.join(ROOT, "vectors", "grant-mint-v1.json"),
                  "r", encoding="utf-8") as handle:
            vector = json.load(handle)
        inputs = vector["inputs"]
        grant, payload, ref, _warnings = mint(
            subject=inputs["subject"], max_raw=inputs["max_raw"],
            not_before=inputs["not_before"], not_after=inputs["not_after"],
            allow_payees=inputs["allow_payees"], policy_epoch=inputs["policy_epoch"],
            url=inputs["url"], now=inputs["now"])
        self.assertEqual(grant, vector["grant"])
        self.assertEqual(payload.decode("utf-8"), vector["bytes"])
        self.assertEqual(len(payload), vector["byte_length"])
        # The digest is pinned as two halves: see the vector's sha256_note.
        self.assertEqual(ref["sha256"], "".join(vector["sha256_halves"]))
        self.assertEqual(ref, dict(vector["reference_template"],
                                   sha256="".join(vector["sha256_halves"])))

    def test_11b_the_vector_grant_verifies_against_the_verifier(self):
        """A vector that cannot be used is a vector nobody should implement."""
        with open(os.path.join(ROOT, "vectors", "grant-mint-v1.json"),
                  "r", encoding="utf-8") as handle:
            vector = json.load(handle)
        payload = vector["bytes"].encode("utf-8")
        subject = vector["grant"]["subject_account"]
        payee = vector["grant"]["allowed_payees"][0]
        reference = dict(vector["reference_template"],
                         sha256="".join(vector["sha256_halves"]))
        receipt = a_receipt(reference, payer=subject, payee=payee,
                            committed="2026-10-15T00:00:00Z")
        verdict = authority_receipt.verify(
            receipt, payload, a_block(payer=subject, payee=payee),
            request=REQUEST, now="2026-10-15T00:00:00Z")
        self.assertTrue(verdict["ok"], verdict["reasons"])


class ConsentPage(unittest.TestCase):
    PAGE = os.path.join(ROOT, "consent", "grant.html")

    # -- 12 -----------------------------------------------------------------
    def test_12_the_page_reaches_no_network(self):
        """No external script, no font, no analytics, no request of any kind."""
        with open(self.PAGE, "r", encoding="utf-8") as handle:
            source = handle.read()
        for token in ("htt" + "p://", "htt" + "ps://", "src=", "fetch(",
                      "XMLHttpRequest", "EventSource", "WebSocket", "importScripts",
                      "navigator.sendBeacon", "@import"):
            with self.subTest(token=token):
                self.assertNotIn(token, source,
                                 "%r in the consent page: it must reach nothing" % token)

    def test_12b_the_page_says_what_it_does_not_do(self):
        with open(self.PAGE, "r", encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn("holds no key, signs nothing, and sends nothing anywhere", source)
        self.assertIn("Produce the grant", source)
        for forbidden in (">Authorize<", ">Connect<"):
            self.assertNotIn(forbidden, source)

    def test_12c_the_page_shouts_the_byte_rule(self):
        with open(self.PAGE, "r", encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn("must return these bytes unchanged", source)
        self.assertIn("re-serialises JSON", source)

    def test_12d_the_page_pins_the_same_digest_as_the_vector(self):
        """The page self-checks against this exact value when it loads."""
        with open(os.path.join(ROOT, "vectors", "grant-mint-v1.json"),
                  "r", encoding="utf-8") as handle:
            vector = json.load(handle)
        with open(self.PAGE, "r", encoding="utf-8") as handle:
            source = handle.read()
        # Both halves, since neither the page nor the vector may hold the
        # joined 64-hex run: the secret gate refuses one anywhere in the tree.
        for half in vector["sha256_halves"]:
            self.assertIn(half, source)
        self.assertNotIn("".join(vector["sha256_halves"]), source)
        self.assertIn(vector["grant"]["subject_account"], source)
        self.assertIn(vector["grant"]["allowed_payees"][0], source)


class House(unittest.TestCase):
    # -- 13 -----------------------------------------------------------------
    def test_13_self_test_passes_in_the_house_shape(self):
        result = run("--self-test")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["tool"], "grant_mint")
        self.assertEqual(report["self_test"], "pass")
        self.assertEqual(report["failures"], [])
        self.assertTrue(report["positive_control"]["ok"])
        self.assertGreaterEqual(report["negative_controls"], len(GRANT_CODES))

    def test_13b_the_self_test_covers_every_grant_code(self):
        """A control per code, read off the verifier's own list."""
        self.assertEqual(set(grant_mint.GRANT_CODES), set(GRANT_CODES))

    def test_13c_stdlib_only_and_the_network_sits_in_fetch_alone(self):
        allowed_local = {"canonical", "nanoaddr", "authority_receipt"}
        for entry in grant_mint.import_graph(grant_mint.__file__):
            module, function = entry["module"], entry["function"]
            root = module.split(".")[0]
            with self.subTest(module=module):
                self.assertTrue(
                    root in sys.stdlib_module_names or module in allowed_local,
                    "%s is neither standard library nor a module of this repository"
                    % module)
                if module in NETWORK_MODULES:
                    self.assertEqual(
                        function, "fetch",
                        "%s is imported in %s; the network belongs in fetch alone, "
                        "so that mint() cannot reach it" % (module, function))

    def test_13d_the_module_shares_the_verifiers_key_set_by_import(self):
        """Not re-listed: the two files cannot drift without this going red."""
        with open(grant_mint.__file__, "r", encoding="utf-8") as handle:
            source = handle.read()
        self.assertIn("from authority_receipt import GRANT_KEYS", source)
        self.assertIs(grant_mint.GRANT_KEYS, GRANT_KEYS)

    def test_13e_main_returns_an_exit_code_rather_than_raising(self):
        import contextlib
        import io
        # The report goes to stdout by design; swallow it so the suite's own
        # output stays readable.
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--self-test"]), 0)

    def test_13f_the_help_carries_the_byte_rule(self):
        result = run("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("must return these bytes unchanged", result.stdout)
        self.assertIn("re-serialises JSON", result.stdout)

    def test_13g_mint_holds_no_clock_when_told_the_time(self):
        """Two runs a day apart must agree, which is what --now buys."""
        first, _p, _r = a_grant()
        second, _p2, _r2 = a_grant()
        self.assertEqual(serialise(first), serialise(second))


if __name__ == "__main__":
    unittest.main()
