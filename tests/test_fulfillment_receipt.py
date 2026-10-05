"""Grading the third fact, and proving the grade cannot be inflated.

The decisive test in this file is test 4, the `xrb_` test. Every other artifact
in this repository compares accounts by decoded public key because a string
comparison refuses a payment that DID arrive; here the same defect runs the
other way and would ACCEPT a claim that is worth nothing - a seller attesting to
its own work under the legacy spelling while the receipt writes the modern one
would come out `independently_attested`, the top grade, on its own word. If
test 4 ever goes red, this tool has become the self-asserted delivery record it
was written to replace.

Test 7 is the other load-bearing one: it proves the payment leg is DELEGATED by
making `authority_receipt` refuse on a code this file never mentions
(`over_grant_limit`) and asserting that exact string surfaces under
`payment.reasons`. A re-implementation would have to reproduce 18 codes to pass
it, which is the point.

Every fixture here is built independently of `fulfillment_receipt`'s own
`--self-test` controls, deliberately: driving these assertions from the module's
fixtures would let a mutation that breaks both drift past green, which is the
whole failure mode `--self-test` exists to catch. Different keys, a different
request, a different artifact.

Nothing opens a socket. `--fetch` is exercised through the injected seam, and
test 9 asserts that a `verify` without it cannot reach the network even when the
real opener is replaced with one that raises.

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
import fulfillment_receipt  # noqa: E402
import grant_mint  # noqa: E402
import nanoaddr  # noqa: E402
from custody_probe import NETWORK_MODULES  # noqa: E402  - reused, not re-listed
from fulfillment_receipt import (  # noqa: E402
    DELIVERY_KEYS, GRADES, Refusal, delivery_digest, digest, effective_kind,
    emit, grade, import_graph, independent_attestors, main, serialise, verify,
)

SCRIPT = os.path.join(ROOT, "fulfillment_receipt.py")

# Distinct from the module's controls on purpose - see the docstring.
PAYER_KEY = bytes([0xD1]) * 32
PAYEE_KEY = bytes([0xE2]) * 32
WITNESS_KEY = bytes([0xF3]) * 32
OTHER_WITNESS_KEY = bytes([0x17]) * 32

PAYER = nanoaddr.encode(PAYER_KEY)
PAYEE = nanoaddr.encode(PAYEE_KEY)
PAYEE_LEGACY = nanoaddr.encode(PAYEE_KEY, "xrb_")
PAYER_LEGACY = nanoaddr.encode(PAYER_KEY, "xrb_")
WITNESS = nanoaddr.encode(WITNESS_KEY)
WITNESS_LEGACY = nanoaddr.encode(WITNESS_KEY, "xrb_")
OTHER_WITNESS = nanoaddr.encode(OTHER_WITNESS_KEY)

BLOCK_HASH = "3C4D" * 16          # synthetic, built at runtime
RAW_80 = "80000000000000000000000000000"
RAW_LIMIT = "100000000000000000000000000000"

REQUEST = {"job": "job-2026-09-26-002", "unit": "one finality study"}
REQUEST_DIGEST = authority_receipt.request_digest(REQUEST)

SETTLED_AT = "2026-10-03T11:00:00Z"
DELIVERED_AT = "2026-10-03T12:30:00Z"
OBSERVED_AT = "2026-10-03T13:00:00Z"
NOW = "2026-10-03T14:00:00Z"

ARTIFACT = b"block_hash,confirm_ms\n3C4D,318\n4E5F,402\n"


class Answer(object):
    """What the injected seam hands back, mirroring `authority_receipt.Fetched`."""

    def __init__(self, status, body):
        self.status = status
        self.headers = {}
        self.body = body


def a_grant(**changes):
    grant = {
        "version": 1,
        "subject_account": PAYER,
        "policy_epoch": 5,
        "not_before": "2026-09-01T00:00:00Z",
        "not_after": "2026-12-01T00:00:00Z",
        "max_raw_per_payment": RAW_LIMIT,
        "allowed_payees": [PAYEE],
        "revoked_blocks": [],
        "revoked_request_ids": [],
    }
    grant.update(changes)
    return json.dumps(grant).encode("utf-8")


def a_receipt(grant_bytes, **changes):
    receipt = {
        "version": 1,
        "request_id": REQUEST["job"],
        "request_digest": REQUEST_DIGEST,
        "payer_account": PAYER,
        "payee_account": PAYEE,
        "quoted_raw": RAW_80,
        "settled_raw": RAW_80,
        "settled_block": BLOCK_HASH,
        "committed_at": SETTLED_AT,
        "grant": {
            "url": "https://operator.test/grants/agent-9.json",
            "sha256": digest(grant_bytes),
            "policy_epoch": 5,
        },
    }
    receipt.update(changes)
    return receipt


def a_block(**changes):
    block = {
        "hash": BLOCK_HASH,
        "amount": RAW_80,
        "block_account": PAYER,
        "subtype": "send",
        "confirmed": "true",
        "contents": {"link_as_account": PAYEE},
    }
    block.update(changes)
    return block


def a_delivery(**changes):
    delivery = {
        "version": 1,
        "request_id": REQUEST["job"],
        "request_digest": REQUEST_DIGEST,
        "artifact_url": "https://seller.test/finality-rows.csv",
        "artifact_sha256": digest(ARTIFACT),
        "acceptance_claimed": ["at least 50 rows", "every block hash resolves"],
        "delivered_at": DELIVERED_AT,
    }
    delivery.update(changes)
    return delivery


def an_attestation(delivery=None, **changes):
    attestation = {
        "version": 1,
        "attestor": WITNESS,
        "attestor_kind": "third_party",
        "delivery_digest": digest(serialise(delivery or a_delivery())),
        "method": "re-ran the published script against 3 nodes of my own choosing",
        "verdict": "accepted",
        "observed_at": OBSERVED_AT,
        "citation": "https://moltbook.test/post/9ab/#comment-4",
    }
    attestation.update(changes)
    return attestation


def a_set(attestations=None, grant_bytes=None):
    """A consistent payment + delivery + attestation set, emitted honestly."""
    grant_bytes = grant_bytes or a_grant()
    receipt = a_receipt(grant_bytes)
    delivery = a_delivery()
    given = [an_attestation(delivery)] if attestations is None else attestations
    fulfillment = emit(receipt, delivery, given, now=NOW)
    return fulfillment, receipt, grant_bytes, a_block(), delivery


def a_fetch(body=None, status=200):
    def fetch(url, headers):
        return Answer(status, ARTIFACT if body is None else body)
    return fetch


def run_cli(*argv, **kwargs):
    """The CLI as a stranger runs it: a real process, real exit code."""
    proc = subprocess.run(
        [sys.executable, SCRIPT] + list(argv),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, cwd=ROOT, **kwargs)
    return proc


class TempDocs(object):
    """A directory of JSON documents, written as the house byte rule writes them."""

    def __init__(self):
        self.dir = tempfile.mkdtemp(prefix="fulfillment-")

    def write(self, name, document):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as handle:
            if isinstance(document, bytes):
                handle.write(document)
            else:
                handle.write(serialise(document))
        return path


class DigestIsStable(unittest.TestCase):
    """-- 1 -- byte-stable across key order, and sensitive to every value."""

    def test_01_digest_ignores_key_order(self):
        forward = a_delivery()
        reversed_keys = {key: forward[key] for key in sorted(forward, reverse=True)}
        self.assertNotEqual(list(forward), list(reversed_keys))
        self.assertEqual(delivery_digest(forward), delivery_digest(reversed_keys))

    def test_01_digest_changes_when_any_key_changes(self):
        """One assertion per key of the delivery document: 7 keys, 7 changes."""
        base = delivery_digest(a_delivery())
        mutations = {
            "version": None,          # version is pinned to 1; see below
            "request_id": "job-2026-09-26-003",
            "request_digest": digest(b"a different order"),
            "artifact_url": "https://seller.test/other-rows.csv",
            "artifact_sha256": digest(b"other bytes"),
            "acceptance_claimed": ["at least 50 rows"],
            "delivered_at": "2026-10-03T12:31:00Z",
        }
        self.assertEqual(set(mutations), set(DELIVERY_KEYS),
                         "a key was added to the delivery document and this "
                         "test did not grow a mutation for it")
        for key, value in sorted(mutations.items()):
            if key == "version":
                # `version` cannot be mutated and still be a delivery document,
                # so its sensitivity is proven the only way it can be: the
                # shape gate refuses any other value.
                with self.assertRaises(Refusal) as caught:
                    delivery_digest(a_delivery(version=2))
                self.assertEqual(caught.exception.code, "bad_delivery_shape")
                continue
            self.assertNotEqual(base, delivery_digest(a_delivery(**{key: value})),
                                "%s does not change the digest" % key)

    def test_01_byte_rule_agrees_with_grant_mint(self):
        probe = {"version": 1, "b": "two", "a": "one", "unicode": "é"}
        self.assertEqual(serialise(probe), grant_mint.serialise(probe))
        self.assertTrue(serialise(probe).endswith(b"\n"))


class EmitBindsOneOrder(unittest.TestCase):
    """-- 2 -- the payment and the delivery must be about the same order."""

    def test_02_emit_refuses_a_delivery_for_another_order(self):
        receipt = a_receipt(a_grant())
        delivery = a_delivery(request_digest=digest(b"another order entirely"))
        with self.assertRaises(Refusal) as caught:
            emit(receipt, delivery, [], now=NOW)
        self.assertEqual(caught.exception.code, "request_digest_mismatch")

    def test_02_emit_accepts_the_matching_pair(self):
        fulfillment, _, _, _, _ = a_set()
        self.assertEqual(fulfillment["request_digest"], REQUEST_DIGEST)
        self.assertEqual(fulfillment["settled_block"], BLOCK_HASH)


class TheFiveGrades(unittest.TestCase):
    """-- 3 -- one test per row of the evidence_grade table."""

    def test_03_independently_attested(self):
        fulfillment, _, _, _, _ = a_set()
        self.assertEqual(fulfillment["evidence_grade"], "independently_attested")
        self.assertEqual(fulfillment["independent_attestor_count"], 1)

    def test_03_counterparty_attested(self):
        delivery = a_delivery()
        payer_said_so = an_attestation(delivery, attestor=PAYER, attestor_kind="payer")
        fulfillment = emit(a_receipt(a_grant()), delivery, [payer_said_so], now=NOW)
        self.assertEqual(fulfillment["evidence_grade"], "counterparty_attested")
        self.assertEqual(fulfillment["independent_attestor_count"], 0)

    def test_03_self_attested(self):
        delivery = a_delivery()
        payee_said_so = an_attestation(delivery, attestor=PAYEE, attestor_kind="payee")
        fulfillment = emit(a_receipt(a_grant()), delivery, [payee_said_so], now=NOW)
        self.assertEqual(fulfillment["evidence_grade"], "self_attested")
        self.assertEqual(fulfillment["independent_attestor_count"], 0)

    def test_03_disputed(self):
        delivery = a_delivery()
        rejected = an_attestation(delivery, verdict="rejected")
        fulfillment = emit(a_receipt(a_grant()), delivery, [rejected], now=NOW)
        self.assertEqual(fulfillment["evidence_grade"], "disputed")

    def test_03_unattested(self):
        fulfillment, _, _, _, _ = a_set(attestations=[])
        self.assertEqual(fulfillment["evidence_grade"], "unattested")
        self.assertEqual(fulfillment["attestations"], [])
        self.assertEqual(fulfillment["independent_attestor_count"], 0)

    def test_03_every_grade_row_is_covered(self):
        covered = {"independently_attested", "counterparty_attested",
                   "self_attested", "disputed", "unattested"}
        self.assertEqual(covered, set(GRADES),
                         "a grade was added and the table above did not grow a test")


class TheLegacySpellingTest(unittest.TestCase):
    """-- 4 -- THE decisive test: a seller cannot grade its own work independent."""

    def test_04_payee_under_xrb_grades_self_attested(self):
        delivery = a_delivery()
        # It CLAIMS third_party, and its account is the payee written `xrb_`
        # while the receipt writes `nano_`. A string comparison promotes this to
        # the top grade on the seller's own word.
        liar = an_attestation(delivery, attestor=PAYEE_LEGACY,
                              attestor_kind="third_party")
        self.assertNotEqual(PAYEE_LEGACY, PAYEE)
        fulfillment = emit(a_receipt(a_grant()), delivery, [liar], now=NOW)
        self.assertEqual(fulfillment["evidence_grade"], "self_attested")
        self.assertEqual(fulfillment["independent_attestor_count"], 0)

    def test_04_payer_under_xrb_is_still_the_payer(self):
        delivery = a_delivery()
        liar = an_attestation(delivery, attestor=PAYER_LEGACY,
                              attestor_kind="third_party")
        fulfillment = emit(a_receipt(a_grant()), delivery, [liar], now=NOW)
        self.assertEqual(fulfillment["evidence_grade"], "counterparty_attested")

    def test_04_effective_kind_reads_the_account_not_the_claim(self):
        delivery = a_delivery()
        self.assertEqual(
            effective_kind(an_attestation(delivery, attestor=PAYEE_LEGACY), PAYER, PAYEE),
            "payee")
        self.assertEqual(
            effective_kind(an_attestation(delivery, attestor=WITNESS), PAYER, PAYEE),
            "third_party")

    def test_04_one_witness_in_two_spellings_is_one_attestor(self):
        delivery = a_delivery()
        twice = [an_attestation(delivery, attestor=WITNESS),
                 an_attestation(delivery, attestor=WITNESS_LEGACY)]
        fulfillment = emit(a_receipt(a_grant()), delivery, twice, now=NOW)
        self.assertEqual(fulfillment["independent_attestor_count"], 1)
        self.assertEqual(len(independent_attestors(twice, PAYER, PAYEE)), 1)

    def test_04_two_real_witnesses_count_as_two(self):
        delivery = a_delivery()
        both = [an_attestation(delivery, attestor=WITNESS),
                an_attestation(delivery, attestor=OTHER_WITNESS)]
        fulfillment = emit(a_receipt(a_grant()), delivery, both, now=NOW)
        self.assertEqual(fulfillment["independent_attestor_count"], 2)


class DisputeOutranks(unittest.TestCase):
    """-- 5 -- a rejection is reported whenever it is present."""

    def test_05_disputed_outranks_independently_attested(self):
        delivery = a_delivery()
        good = an_attestation(delivery, attestor=WITNESS, verdict="accepted")
        bad = an_attestation(delivery, attestor=OTHER_WITNESS, verdict="rejected")
        fulfillment = emit(a_receipt(a_grant()), delivery, [good, bad], now=NOW)
        self.assertEqual(fulfillment["evidence_grade"], "disputed")
        # The accepted attestation is still counted and still published: the
        # grade says there is a dispute, it does not erase the other side.
        self.assertEqual(fulfillment["independent_attestor_count"], 1)
        self.assertEqual(len(fulfillment["attestations"]), 2)

    def test_05_grade_helper_agrees(self):
        delivery = a_delivery()
        mixed = [an_attestation(delivery, verdict="accepted"),
                 an_attestation(delivery, attestor=OTHER_WITNESS, verdict="rejected")]
        self.assertEqual(grade(mixed, PAYER, PAYEE), "disputed")


class MismatchedAttestationsAreNamed(unittest.TestCase):
    """-- 6 -- dropped, never silently ignored, and emit still succeeds."""

    def test_06_a_mismatched_attestation_is_dropped_and_named(self):
        delivery = a_delivery()
        elsewhere = an_attestation(delivery, delivery_digest=digest(b"another delivery"))
        fulfillment = emit(a_receipt(a_grant()), delivery, [elsewhere], now=NOW)
        self.assertEqual(fulfillment["attestations"], [])
        self.assertEqual(len(fulfillment["dropped_attestations"]), 1)
        self.assertEqual(fulfillment["independent_attestor_count"], 0)
        self.assertEqual(fulfillment["evidence_grade"], "unattested")

    def test_06_emit_exits_zero_through_the_cli(self):
        docs = TempDocs()
        delivery = a_delivery()
        elsewhere = an_attestation(delivery, delivery_digest=digest(b"another delivery"))
        proc = run_cli("emit",
                       "--receipt", docs.write("receipt.json", a_receipt(a_grant())),
                       "--delivery", docs.write("delivery.json", delivery),
                       "--attestation", docs.write("att.json", elsewhere),
                       "--now", NOW)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        document = json.loads(proc.stdout.decode())
        self.assertEqual(len(document["dropped_attestations"]), 1)


class ThePaymentLegIsDelegated(unittest.TestCase):
    """-- 7 -- a code this file never mentions must surface verbatim."""

    def test_07_over_grant_limit_surfaces_under_payment(self):
        tight = a_grant(max_raw_per_payment="1")
        fulfillment, receipt, grant_bytes, block, delivery = a_set(grant_bytes=tight)
        verdict = verify(fulfillment, receipt, grant_bytes, block,
                         delivery=delivery, now=NOW, fetch=a_fetch())
        self.assertIn("over_grant_limit", verdict["payment"]["reasons"])
        self.assertIn("payment_leg_failed", verdict["reasons"])
        self.assertFalse(verdict["ok"])
        # Verbatim, not re-derived: the embedded verdict is the sibling's own.
        expected = authority_receipt.verify(receipt, grant_bytes, block,
                                            request=None, now=NOW)
        self.assertEqual(verdict["payment"], expected)

    def test_07_this_file_names_none_of_the_payment_codes(self):
        source = open(os.path.join(ROOT, "fulfillment_receipt.py"),
                      encoding="utf-8").read()
        # Two codes are shared by name for reasons that are not
        # re-implementation: `request_digest_mismatch` is checked here on this
        # tool's OWN documents (receipt against delivery, which the sibling
        # never sees), and `bad_receipt_shape` is `emit`'s input gate on the
        # receipt it is handed - reading a document's shape is not verifying a
        # payment. Everything else must come from the sibling or not at all.
        shared = {"request_digest_mismatch", "bad_receipt_shape"}
        for code in authority_receipt.REASON_ORDER:
            if code in shared:
                continue
            self.assertNotIn(
                '"%s"' % code, source,
                "%s is quoted here; the payment leg must be delegated" % code)

    def test_07_a_clean_set_passes_both_legs(self):
        fulfillment, receipt, grant_bytes, block, delivery = a_set()
        verdict = verify(fulfillment, receipt, grant_bytes, block,
                         delivery=delivery, now=NOW, fetch=a_fetch())
        self.assertTrue(verdict["ok"], verdict["reasons"])
        self.assertEqual(verdict["reasons"], [])
        self.assertTrue(verdict["payment"]["ok"])


class TheGradeCannotBeInflated(unittest.TestCase):
    """-- 8 -- a seller must not write a better grade than its evidence supports."""

    def test_08_grade_overstated_is_refused(self):
        delivery = a_delivery()
        payee_said_so = an_attestation(delivery, attestor=PAYEE, attestor_kind="payee")
        honest = emit(a_receipt(a_grant()), delivery, [payee_said_so], now=NOW)
        self.assertEqual(honest["evidence_grade"], "self_attested")
        inflated = dict(honest, evidence_grade="independently_attested")
        verdict = verify(inflated, a_receipt(a_grant()), a_grant(), a_block(),
                         delivery=delivery, now=NOW, fetch=a_fetch())
        self.assertIn("grade_overstated", verdict["reasons"])
        self.assertFalse(verdict["ok"])
        self.assertEqual(verdict["recomputed_grade"], "self_attested")

    def test_08_a_lower_stored_grade_is_allowed_and_noted(self):
        fulfillment, receipt, grant_bytes, block, delivery = a_set()
        modest = dict(fulfillment, evidence_grade="self_attested")
        verdict = verify(modest, receipt, grant_bytes, block, delivery=delivery,
                         now=NOW, fetch=a_fetch())
        self.assertNotIn("grade_overstated", verdict["reasons"])
        self.assertTrue(verdict["ok"], verdict["reasons"])
        self.assertTrue(any("BELOW" in note for note in verdict["notes"]))

    def test_08_claiming_independence_for_a_counterparty_is_refused(self):
        delivery = a_delivery()
        liar = an_attestation(delivery, attestor=PAYEE_LEGACY,
                              attestor_kind="third_party")
        honest = emit(a_receipt(a_grant()), delivery, [liar], now=NOW)
        verdict = verify(honest, a_receipt(a_grant()), a_grant(), a_block(),
                         delivery=delivery, now=NOW, fetch=a_fetch())
        self.assertIn("attestor_is_counterparty", verdict["reasons"])

    def test_08_an_honest_payee_kind_does_not_fire_that_code(self):
        delivery = a_delivery()
        honest_payee = an_attestation(delivery, attestor=PAYEE, attestor_kind="payee")
        fulfillment = emit(a_receipt(a_grant()), delivery, [honest_payee], now=NOW)
        verdict = verify(fulfillment, a_receipt(a_grant()), a_grant(), a_block(),
                         delivery=delivery, now=NOW, fetch=a_fetch())
        self.assertNotIn("attestor_is_counterparty", verdict["reasons"])
        self.assertTrue(verdict["ok"], verdict["reasons"])


class NoNetworkWithoutFetch(unittest.TestCase):
    """-- 9 -- verify() cannot reach the network, and this file holds no import."""

    def test_09_verify_opens_no_socket_even_when_the_opener_explodes(self):
        def explode(timeout=10):
            raise AssertionError("verify() reached the network")

        saved = authority_receipt.default_fetch
        authority_receipt.default_fetch = explode
        try:
            fulfillment, receipt, grant_bytes, block, delivery = a_set()
            verdict = verify(fulfillment, receipt, grant_bytes, block,
                             delivery=delivery, now=NOW)
        finally:
            authority_receipt.default_fetch = saved
        self.assertTrue(verdict["ok"], verdict["reasons"])
        self.assertTrue(any("no --fetch" in note for note in verdict["notes"]))
        self.assertNotIn("artifact_changed", verdict["checked"])
        self.assertNotIn("artifact_unreachable", verdict["checked"])

    def test_09_this_file_imports_no_network_module_at_all(self):
        local = {"authority_receipt", "canonical", "nanoaddr", "grant_mint",
                 "order_bound_amount"}
        for entry in import_graph():
            module, function = entry["module"], entry["function"]
            root = module.split(".")[0]
            self.assertNotIn(
                module, NETWORK_MODULES,
                "%s is imported in %s; this file reaches the network only "
                "through an injected seam" % (module, function))
            self.assertTrue(
                root in sys.stdlib_module_names or module in local,
                "%s is neither standard library nor a module of this repository"
                % module)


class TheArtifactIsRefetchable(unittest.TestCase):
    """-- 10 -- matching bytes pass, one changed byte and a 404 do not."""

    def test_10_matching_bytes_verify(self):
        fulfillment, receipt, grant_bytes, block, delivery = a_set()
        verdict = verify(fulfillment, receipt, grant_bytes, block,
                         delivery=delivery, now=NOW, fetch=a_fetch(ARTIFACT))
        self.assertTrue(verdict["ok"], verdict["reasons"])
        self.assertIn("artifact_changed", verdict["checked"])

    def test_10_one_changed_byte_is_artifact_changed(self):
        fulfillment, receipt, grant_bytes, block, delivery = a_set()
        tampered = ARTIFACT.replace(b"318", b"319", 1)
        self.assertNotEqual(tampered, ARTIFACT)
        verdict = verify(fulfillment, receipt, grant_bytes, block,
                         delivery=delivery, now=NOW, fetch=a_fetch(tampered))
        self.assertIn("artifact_changed", verdict["reasons"])
        self.assertFalse(verdict["ok"])

    def test_10_a_404_is_artifact_unreachable(self):
        fulfillment, receipt, grant_bytes, block, delivery = a_set()
        verdict = verify(fulfillment, receipt, grant_bytes, block,
                         delivery=delivery, now=NOW, fetch=a_fetch(b"", 404))
        self.assertIn("artifact_unreachable", verdict["reasons"])
        self.assertNotIn("artifact_changed", verdict["reasons"])
        self.assertFalse(verdict["ok"])

    def test_10_a_raising_seam_is_unreachable_not_a_crash(self):
        def dead(url, headers):
            raise OSError("no route to host")

        fulfillment, receipt, grant_bytes, block, delivery = a_set()
        verdict = verify(fulfillment, receipt, grant_bytes, block,
                         delivery=delivery, now=NOW, fetch=dead)
        self.assertIn("artifact_unreachable", verdict["reasons"])


class DeliverFirstIsNormal(unittest.TestCase):
    """-- 11 -- this board pays deliver-first sellers, so it is a note."""

    def test_11_delivered_before_settled_is_a_note_and_ok_stays_true(self):
        # Delivered BEFORE the payment settled: ARION's own working order.
        early = a_delivery(delivered_at="2026-10-03T10:00:00Z")
        attestation = an_attestation(early)
        receipt = a_receipt(a_grant())
        fulfillment = emit(receipt, early, [attestation], now=NOW)
        verdict = verify(fulfillment, receipt, a_grant(), a_block(),
                         delivery=early, now=NOW, fetch=a_fetch())
        self.assertTrue(verdict["ok"], verdict["reasons"])
        self.assertNotIn("delivered_before_settled", verdict["reasons"])
        self.assertTrue(any("delivered_before_settled" in note
                            for note in verdict["notes"]))

    def test_11_an_attestation_before_the_delivery_is_refused(self):
        delivery = a_delivery()
        impossible = an_attestation(delivery, observed_at="2026-10-03T11:30:00Z")
        receipt = a_receipt(a_grant())
        fulfillment = emit(receipt, delivery, [impossible], now=NOW)
        verdict = verify(fulfillment, receipt, a_grant(), a_block(),
                         delivery=delivery, now=NOW, fetch=a_fetch())
        self.assertIn("attestation_before_delivery", verdict["reasons"])
        self.assertFalse(verdict["ok"])

    def test_11_that_check_is_skipped_without_the_delivery(self):
        delivery = a_delivery()
        impossible = an_attestation(delivery, observed_at="2026-10-03T11:30:00Z")
        receipt = a_receipt(a_grant())
        fulfillment = emit(receipt, delivery, [impossible], now=NOW)
        verdict = verify(fulfillment, receipt, a_grant(), a_block(),
                         delivery=None, now=NOW, fetch=a_fetch())
        self.assertNotIn("attestation_before_delivery", verdict["checked"])
        self.assertNotIn("attestation_before_delivery", verdict["reasons"])
        self.assertNotIn("delivery_digest_mismatch", verdict["checked"])

    def test_11_a_substituted_delivery_is_caught(self):
        fulfillment, receipt, grant_bytes, block, _ = a_set()
        other = a_delivery(acceptance_claimed=["a different claim entirely"])
        verdict = verify(fulfillment, receipt, grant_bytes, block,
                         delivery=other, now=NOW, fetch=a_fetch())
        self.assertIn("delivery_digest_mismatch", verdict["reasons"])


class EveryErrorPath(unittest.TestCase):
    """-- 12 -- exit 2, the exact code, and an empty stdout."""

    def setUp(self):
        self.docs = TempDocs()
        self.receipt = self.docs.write("receipt.json", a_receipt(a_grant()))

    def refuses(self, code, delivery=None, attestation=None, now=NOW):
        argv = ["emit", "--receipt", self.receipt,
                "--delivery", self.docs.write("delivery.json",
                                              delivery or a_delivery())]
        if attestation is not None:
            argv += ["--attestation", self.docs.write("att.json", attestation)]
        argv += ["--now", now]
        proc = run_cli(*argv)
        self.assertEqual(proc.returncode, 2, proc.stdout.decode())
        self.assertEqual(proc.stdout, b"", "a refusal must print nothing to stdout")
        body = json.loads(proc.stderr.decode())
        self.assertEqual(body["tool"], "fulfillment_receipt")
        self.assertEqual(body["error"], code)
        return body

    def test_12_bad_delivery_shape_missing_key(self):
        broken = a_delivery()
        del broken["delivered_at"]
        self.refuses("bad_delivery_shape", delivery=broken)

    def test_12_bad_delivery_shape_extra_key(self):
        self.refuses("bad_delivery_shape",
                     delivery=dict(a_delivery(), note="an unknown key is a refusal"))

    def test_12_bad_attestation_shape(self):
        broken = an_attestation(a_delivery())
        del broken["citation"]
        self.refuses("bad_attestation_shape", attestation=broken)

    def test_12_bad_digest(self):
        self.refuses("bad_digest", delivery=a_delivery(artifact_sha256="not-a-digest"))

    def test_12_invalid_account(self):
        self.refuses("invalid_account",
                     attestation=an_attestation(a_delivery(), attestor="nano_notanaccount"))

    def test_12_bad_enum_kind(self):
        self.refuses("bad_enum",
                     attestation=an_attestation(a_delivery(), attestor_kind="auditor"))

    def test_12_bad_enum_verdict(self):
        self.refuses("bad_enum",
                     attestation=an_attestation(a_delivery(), verdict="probably"))

    def test_12_timestamp_not_absolute(self):
        self.refuses("timestamp_not_absolute",
                     delivery=a_delivery(delivered_at="2026-10-03T12:30:00"))

    def test_12_artifact_url_not_https(self):
        self.refuses("artifact_url_not_https",
                     delivery=a_delivery(artifact_url="http://seller.test/rows.csv"))

    def test_12_now_not_parseable(self):
        self.refuses("now_not_parseable", now="whenever")

    def test_12_request_digest_mismatch(self):
        self.refuses("request_digest_mismatch",
                     delivery=a_delivery(request_digest=digest(b"another order")))

    def test_12_an_empty_acceptance_list_is_refused(self):
        self.refuses("bad_delivery_shape", delivery=a_delivery(acceptance_claimed=[]))

    def test_12_a_bad_fulfillment_shape_is_a_reason_not_exit_two(self):
        """The one documented departure from the spec's error list.

        `authority_receipt.py` treats `bad_receipt_shape` the same way: the
        primary document's shape is a verdict about the document, and exit 2 is
        reserved for a caller error. See the module docstring.
        """
        fulfillment, receipt, grant_bytes, block, delivery = a_set()
        docs = TempDocs()
        proc = run_cli("verify",
                       "--fulfillment", docs.write(
                           "f.json", dict(fulfillment, note="unknown key")),
                       "--receipt", docs.write("r.json", receipt),
                       "--grant", docs.write("g.json", grant_bytes),
                       "--block", docs.write("b.json", block),
                       "--delivery", docs.write("d.json", delivery),
                       "--now", NOW)
        self.assertEqual(proc.returncode, 1)
        verdict = json.loads(proc.stdout.decode())
        self.assertEqual(verdict["reasons"], ["bad_fulfillment_shape"])
        self.assertFalse(verdict["ok"])

    def test_12_a_missing_file_is_a_usage_error(self):
        proc = run_cli("digest", "--delivery", os.path.join(self.docs.dir, "nope.json"))
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, b"")

    def test_12_invalid_json_is_a_usage_error(self):
        path = self.docs.write("bad.json", b"{not json")
        proc = run_cli("digest", "--delivery", path)
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, b"")

    def test_12_no_command_is_a_usage_error(self):
        proc = run_cli()
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, b"")

    def test_12_verify_requires_a_parseable_now(self):
        fulfillment, receipt, grant_bytes, block, delivery = a_set()
        docs = TempDocs()
        proc = run_cli("verify",
                       "--fulfillment", docs.write("f.json", fulfillment),
                       "--receipt", docs.write("r.json", receipt),
                       "--grant", docs.write("g.json", grant_bytes),
                       "--block", docs.write("b.json", block),
                       "--now", "whenever")
        self.assertEqual(proc.returncode, 2)
        self.assertEqual(proc.stdout, b"")


class TheSelfTest(unittest.TestCase):
    """-- 13 -- it exits 0, touches no network, and reports in the house shape."""

    def test_13_self_test_passes_through_the_cli(self):
        proc = run_cli("--self-test")
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        report = json.loads(proc.stdout.decode())
        self.assertEqual(report["tool"], "fulfillment_receipt")
        self.assertEqual(report["self_test"], "pass")
        self.assertEqual(report["failures"], [])
        self.assertTrue(report["positive_control"]["ok"])
        self.assertEqual(report["positive_control"]["evidence_grade"],
                         "independently_attested")
        self.assertGreaterEqual(report["negative_controls"], 9)

    def test_13_self_test_has_a_control_per_refusal_code(self):
        from fulfillment_receipt import (
            DELIVERY_DEPENDENT, ORDER_DEPENDENT, REASON_ORDER,
            _negative_controls)
        self.assertEqual(set(_negative_controls()),
                         set(REASON_ORDER) | set(DELIVERY_DEPENDENT)
                         | set(ORDER_DEPENDENT),
                         "a refusal code has no negative control, so it is a "
                         "check that has never been proven able to fail")

    def test_13_self_test_opens_no_socket(self):
        def explode(timeout=10):
            raise AssertionError("--self-test reached the network")

        saved = authority_receipt.default_fetch
        authority_receipt.default_fetch = explode
        try:
            self.assertEqual(fulfillment_receipt.self_test(), 0)
        finally:
            authority_receipt.default_fetch = saved

    def test_13_main_returns_two_without_a_command(self):
        self.assertEqual(main([]), 2)


class TheCliRoundTrip(unittest.TestCase):
    """The end-to-end path a stranger actually runs, through real processes."""

    def test_14_digest_emit_verify(self):
        docs = TempDocs()
        delivery = a_delivery()
        grant_bytes = a_grant()
        receipt = a_receipt(grant_bytes)

        dig = run_cli("digest", "--delivery", docs.write("d.json", delivery))
        self.assertEqual(dig.returncode, 0, dig.stderr.decode())
        computed = dig.stdout.decode().strip()
        self.assertEqual(computed, digest(serialise(delivery)))

        attestation = an_attestation(delivery, delivery_digest=computed)
        made = run_cli("emit",
                       "--receipt", docs.write("r.json", receipt),
                       "--delivery", docs.write("d.json", delivery),
                       "--attestation", docs.write("a.json", attestation),
                       "--now", NOW)
        self.assertEqual(made.returncode, 0, made.stderr.decode())
        document = json.loads(made.stdout.decode())
        self.assertEqual(document["evidence_grade"], "independently_attested")

        checked = run_cli("verify",
                          "--fulfillment", docs.write("f.json", document),
                          "--receipt", docs.write("r.json", receipt),
                          "--grant", docs.write("g.json", grant_bytes),
                          "--block", docs.write("b.json", a_block()),
                          "--delivery", docs.write("d.json", delivery),
                          "--now", NOW)
        self.assertEqual(checked.returncode, 0, checked.stdout.decode())
        verdict = json.loads(checked.stdout.decode())
        self.assertTrue(verdict["ok"])
        self.assertEqual(verdict["evidence_grade"], "independently_attested")
        self.assertTrue(verdict["payment"]["ok"])

    def test_14_emit_writes_the_house_byte_rule(self):
        docs = TempDocs()
        proc = run_cli("emit",
                       "--receipt", docs.write("r.json", a_receipt(a_grant())),
                       "--delivery", docs.write("d.json", a_delivery()),
                       "--now", NOW)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
        self.assertEqual(proc.stdout, serialise(json.loads(proc.stdout.decode())))


if __name__ == "__main__":
    unittest.main()
