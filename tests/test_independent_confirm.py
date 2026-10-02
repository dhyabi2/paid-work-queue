"""The instrument that is not ours: a verdict no node of ours helped reach.

Every test here builds its own fixtures. Nothing opens a socket, nothing
sleeps, nothing asks the clock, and no fixture holds a value captured from a
live origin - so a failure here is a defect in `independent_confirm.py` and
never a network condition. The `check` path is driven through an injected
transport, and one test proves the default transport is never reached.

The fixtures are built INDEPENDENTLY of the module's own `--self-test`
controls, deliberately and for the reason `tests/test_authority_receipt.py`
already states: driving these assertions from the module's own fixtures would
let a mutation that breaks both drift past green, which is the whole failure
mode `--self-test` exists to catch and therefore the last thing this file
should inherit.

No 64-hex run stands as a single literal here either - every block hash is
joined at runtime - which is the project's secret gate, and the same idiom
`tests/test_authority_receipt.py` and `tests/test_custody_probe.py` use.
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

import independent_confirm  # noqa: E402
import nanoaddr  # noqa: E402
from independent_confirm import (  # noqa: E402
    NODE_REASONS, OBSERVED_KEYS, OVERALL_REASONS, check, curl_lines, decide,
    excluded_endpoint, main, self_test,
)

PAYEE_KEY = bytes([0x7A]) * 32
STRANGER_KEY = bytes([0x8B]) * 32

PAYEE = nanoaddr.encode(PAYEE_KEY)
PAYEE_LEGACY = nanoaddr.encode(PAYEE_KEY, "xrb_")
STRANGER = nanoaddr.encode(STRANGER_KEY)

BLOCK = ("A1B2" * 8) + ("C3D4" * 8)          # synthetic, joined at runtime
RAW = "50000000000000000000000000000"          # 0.05 XNO
RAW_PADDED = "0" + RAW
RAW_ONE_OFF = str(int(RAW) + 1)

NODES = ("https://one.example.org/", "https://two.example.net/",
         "https://three.example.com/")


def expectation(**overrides):
    document = {"block_hash": BLOCK, "to_account": PAYEE,
                "amount_raw": RAW, "subtype": "send"}
    document.update(overrides)
    return document


def body(**overrides):
    """A node answer that agrees with `expectation()`."""
    document = {
        "confirmed": "true",
        "subtype": "send",
        "amount": RAW,
        "block_account": STRANGER,          # the payer; never votes
        "contents": {"link_as_account": PAYEE},
    }
    document.update(overrides)
    return document


def response(endpoint, document=None, ok=True, error=None):
    return {"endpoint": endpoint, "ok": ok,
            "body": body() if document is None else document, "error": error}


def agreeing(count=3):
    return [response(NODES[index]) for index in range(count)]


class FakeTransport:
    """Records every call, and answers from a queue. Opens nothing."""

    def __init__(self, answers=None):
        self.answers = dict(answers or {})
        self.calls = []

    def __call__(self, url, payload, timeout):
        self.calls.append((url, payload, timeout))
        return self.answers.get(url, (True, body(), None))


def raising_transport(*_args, **_kwargs):
    raise AssertionError("this code path must not touch the network")


class DecisionCore(unittest.TestCase):
    """The pure core: no socket, no file, no clock."""

    # -- 1 ------------------------------------------------------------------
    def test_01_three_agreeing_nodes_confirm(self):
        verdict = decide(expectation(), agreeing(3), quorum=3)
        self.assertTrue(verdict["confirmed_independently"])
        self.assertEqual(verdict["reasons"], [])
        self.assertEqual(verdict["agreeing"], 3)
        self.assertEqual([n["reason"] for n in verdict["per_node"]], ["ok"] * 3)

    def test_01b_three_agreeing_nodes_exit_zero(self):
        self.assertEqual(self.run_cli(expectation(), agreeing(3)), 0)

    def run_cli(self, expect, responses, extra=None):
        with tempfile.TemporaryDirectory() as directory:
            paths = {}
            for name, value in (("expect", expect), ("responses", responses)):
                path = os.path.join(directory, name + ".json")
                with open(path, "w", encoding="utf-8") as handle:
                    json.dump(value, handle)
                paths[name] = path
            done = subprocess.run(
                [sys.executable, os.path.join(ROOT, "independent_confirm.py"),
                 "decide", "--expect", paths["expect"],
                 "--responses", paths["responses"]] + (extra or []),
                capture_output=True, text=True, cwd=ROOT)
        self.last = done
        return done.returncode

    # -- 2 ------------------------------------------------------------------
    def test_02_a_split_is_never_a_confirmation(self):
        """Three agreeing and one dissenting is a refusal, not a 3-of-4 pass.

        This is the test that must not be argued away: majority voting over
        nodes is how a verifier launders a disagreement into a yes.
        """
        responses = agreeing(3) + [
            response("https://four.example.org/", body(amount=RAW_ONE_OFF))]
        verdict = decide(expectation(), responses, quorum=3)
        self.assertTrue(verdict["split"])
        self.assertFalse(verdict["confirmed_independently"])
        self.assertIn("nodes_disagree", verdict["reasons"])
        self.assertEqual(verdict["agreeing"], 3)
        self.assertEqual(verdict["dissenting"], 1)
        self.assertEqual(self.run_cli(expectation(), responses), 1)

    # -- 3 ------------------------------------------------------------------
    def test_03_two_agreeing_against_a_quorum_of_three(self):
        verdict = decide(expectation(), agreeing(2), quorum=3)
        self.assertFalse(verdict["confirmed_independently"])
        self.assertIn("quorum_not_met", verdict["reasons"])
        self.assertFalse(verdict["split"])

    # -- 4 ------------------------------------------------------------------
    def test_04_an_unreachable_node_does_not_block_a_quorum(self):
        responses = agreeing(3) + [
            response("https://four.example.org/", None, ok=False,
                     error="timed out")]
        verdict = decide(expectation(), responses, quorum=3)
        self.assertTrue(verdict["confirmed_independently"])
        self.assertEqual(verdict["unusable"], 1)
        self.assertEqual(verdict["per_node"][-1]["reason"], "node_unreachable")

    # -- 5 ------------------------------------------------------------------
    def test_05_a_padded_amount_is_the_same_amount(self):
        """Raw is an integer. "0100" and "100" are one amount, and comparing
        them as strings is how settle.py once refused a payment that arrived."""
        responses = [response(NODES[0], body(amount=RAW_PADDED)),
                     response(NODES[1]), response(NODES[2])]
        verdict = decide(expectation(), responses, quorum=3)
        self.assertEqual(verdict["per_node"][0]["reason"], "ok")
        self.assertTrue(verdict["confirmed_independently"])

    # -- 6 ------------------------------------------------------------------
    def test_06_a_json_integer_amount_is_accepted(self):
        small = expectation(amount_raw="100")
        responses = [response(NODES[0], body(amount=100)),
                     response(NODES[1], body(amount="100")),
                     response(NODES[2], body(amount="0100"))]
        verdict = decide(small, responses, quorum=3)
        self.assertTrue(verdict["confirmed_independently"], verdict["per_node"])

    # -- 7 ------------------------------------------------------------------
    def test_07_one_raw_unit_off_is_a_dissent(self):
        responses = [response(NODES[0], body(amount=RAW_ONE_OFF))]
        verdict = decide(expectation(), responses, quorum=1)
        self.assertEqual(verdict["per_node"][0]["reason"], "amount_mismatch")
        self.assertEqual(verdict["per_node"][0]["verdict"], "disagree")
        self.assertFalse(verdict["confirmed_independently"])

    # -- 8 ------------------------------------------------------------------
    def test_08_a_different_payee_is_a_dissent(self):
        responses = [response(NODES[0],
                              body(contents={"link_as_account": STRANGER}))]
        verdict = decide(expectation(), responses, quorum=1)
        self.assertEqual(verdict["per_node"][0]["reason"], "payee_mismatch")
        self.assertEqual(verdict["per_node"][0]["verdict"], "disagree")

    # -- 9 ------------------------------------------------------------------
    def test_09_the_legacy_xrb_spelling_is_the_same_account(self):
        responses = [response(NODES[0],
                              body(contents={"link_as_account": PAYEE_LEGACY}))]
        verdict = decide(expectation(), responses, quorum=1)
        self.assertEqual(verdict["per_node"][0]["reason"], "ok")
        self.assertTrue(verdict["confirmed_independently"])

    # -- 10 -----------------------------------------------------------------
    def test_10_confirmed_false_as_a_string(self):
        verdict = decide(expectation(), [response(NODES[0], body(confirmed="false"))],
                         quorum=1)
        self.assertEqual(verdict["per_node"][0]["reason"], "not_confirmed")

    # -- 11 -----------------------------------------------------------------
    def test_11_confirmed_false_as_a_boolean(self):
        verdict = decide(expectation(), [response(NODES[0], body(confirmed=False))],
                         quorum=1)
        self.assertEqual(verdict["per_node"][0]["reason"], "not_confirmed")

    def test_11b_confirmed_true_as_a_boolean_is_accepted(self):
        verdict = decide(expectation(), [response(NODES[0], body(confirmed=True))],
                         quorum=1)
        self.assertEqual(verdict["per_node"][0]["reason"], "ok")

    # -- 12 -----------------------------------------------------------------
    def test_12_a_receive_is_not_a_send(self):
        verdict = decide(expectation(), [response(NODES[0], body(subtype="receive"))],
                         quorum=1)
        self.assertEqual(verdict["per_node"][0]["reason"], "wrong_subtype")
        self.assertEqual(verdict["per_node"][0]["verdict"], "disagree")

    # -- 13 -----------------------------------------------------------------
    def test_13_block_not_found_is_a_dissent_not_a_malformation(self):
        verdict = decide(expectation(),
                         [response(NODES[0], {"error": "Block not found"})],
                         quorum=1)
        self.assertEqual(verdict["per_node"][0]["reason"], "block_not_found")
        self.assertEqual(verdict["per_node"][0]["verdict"], "disagree")

    # -- 14 -----------------------------------------------------------------
    def test_14_a_missing_amount_makes_a_node_unusable(self):
        incomplete = body()
        del incomplete["amount"]
        verdict = decide(expectation(), [response(NODES[0], incomplete)], quorum=1)
        self.assertEqual(verdict["per_node"][0]["reason"], "node_malformed")
        self.assertEqual(verdict["per_node"][0]["verdict"], "unusable")

    def test_14b_a_missing_link_as_account_makes_a_node_unusable(self):
        verdict = decide(expectation(), [response(NODES[0], body(contents={}))],
                         quorum=1)
        self.assertEqual(verdict["per_node"][0]["reason"], "node_malformed")

    def test_14c_an_unreadable_amount_makes_a_node_unusable(self):
        verdict = decide(expectation(), [response(NODES[0], body(amount="lots"))],
                         quorum=1)
        self.assertEqual(verdict["per_node"][0]["reason"], "node_malformed")
        self.assertEqual(verdict["per_node"][0]["verdict"], "unusable")


class HostExclusion(unittest.TestCase):
    """No node of ours may vote, and nobody else may be silenced by naming."""

    # -- 15 -----------------------------------------------------------------
    def test_15_a_vendor_node_in_the_set_refuses_the_whole_verdict(self):
        responses = agreeing(2) + [response("https://rpc.getunstuck.space/")]
        verdict = decide(expectation(), responses, quorum=2)
        self.assertFalse(verdict["confirmed_independently"])
        self.assertIn("vendor_node_in_set", verdict["reasons"])
        self.assertEqual(verdict["vendor_endpoints_present"],
                         ["https://rpc.getunstuck.space/"])
        self.assertEqual(verdict["excluded"], 1)
        self.assertEqual(verdict["per_node"][-1]["verdict"], "excluded")
        self.assertEqual(verdict["per_node"][-1]["reason"], "vendor_node")

    def test_15b_a_vendor_node_refuses_even_when_quorum_is_already_met(self):
        """Three independent nodes agree and quorum is met - and it is still a
        refusal, because a verdict of ours must not be one our node helped
        reach."""
        responses = agreeing(3) + [response("https://getunstuck.space/rpc")]
        verdict = decide(expectation(), responses, quorum=3)
        self.assertEqual(verdict["agreeing"], 3)
        self.assertGreaterEqual(verdict["agreeing"], verdict["quorum_required"])
        self.assertEqual(verdict["dissenting"], 0)
        self.assertFalse(verdict["confirmed_independently"])
        self.assertIn("vendor_node_in_set", verdict["reasons"])

    def test_15c_the_bare_vendor_domain_is_excluded(self):
        self.assertIsNotNone(
            excluded_endpoint("https://getunstuck.space/rpc",
                              ("getunstuck.space",)))

    # -- 16 -----------------------------------------------------------------
    def test_16_a_lookalike_registrable_domain_is_not_excluded(self):
        """Silencing getunstuck.space.evil.com would let an attacker mute a
        node just by naming it after us."""
        self.assertIsNone(
            excluded_endpoint("https://getunstuck.space.evil.com/",
                              ("getunstuck.space",)))

    # -- 17 -----------------------------------------------------------------
    def test_17_a_prefix_without_a_label_boundary_is_not_excluded(self):
        self.assertIsNone(
            excluded_endpoint("https://notgetunstuck.space/",
                              ("getunstuck.space",)))

    def test_17b_a_lookalike_node_still_gets_to_vote(self):
        responses = [response("https://notgetunstuck.space/"),
                     response("https://getunstuck.space.evil.com/"),
                     response(NODES[0])]
        verdict = decide(expectation(), responses, quorum=3)
        self.assertEqual(verdict["excluded"], 0)
        self.assertTrue(verdict["confirmed_independently"])

    # -- 18 -----------------------------------------------------------------
    def test_18_exclusion_is_case_insensitive(self):
        self.assertIsNotNone(
            excluded_endpoint("HTTPS://RPC.GETUNSTUCK.SPACE/",
                              ("getunstuck.space",)))

    def test_18b_the_match_is_on_the_hostname_never_the_url_string(self):
        """getunstuck.space in a path or a query is not a node of ours."""
        self.assertIsNone(
            excluded_endpoint("https://node.example.org/getunstuck.space",
                              ("getunstuck.space",)))
        self.assertIsNone(
            excluded_endpoint("https://node.example.org/?via=getunstuck.space",
                              ("getunstuck.space",)))

    # -- 19 -----------------------------------------------------------------
    def test_19_a_caller_supplied_exclusion_applies_at_the_label_boundary(self):
        verdict = decide(expectation(),
                         [response("https://example.org/rpc"),
                          response("https://a.example.org/rpc"),
                          response("https://node.example.net/")],
                         quorum=1, excluded_hosts=["example.org"])
        self.assertEqual(verdict["excluded"], 2)
        self.assertFalse(verdict["confirmed_independently"])
        self.assertIn("vendor_node_in_set", verdict["reasons"])

    def test_19b_a_caller_cannot_un_exclude_a_vendor_host(self):
        verdict = decide(expectation(),
                         agreeing(3) + [response("https://rpc.getunstuck.space/")],
                         quorum=3, excluded_hosts=["example.invalid"])
        self.assertIn("vendor_node_in_set", verdict["reasons"])


class FetchingShell(unittest.TestCase):
    """Only `check` touches the network, and only through a transport."""

    # -- 20 -----------------------------------------------------------------
    def test_20_too_few_nodes_refuses_before_any_fetch(self):
        transport = FakeTransport()
        with contextlib.redirect_stderr(io.StringIO()):
            code = main(["check", "--block", BLOCK, "--to", PAYEE,
                         "--amount-raw", RAW, "--node", NODES[0],
                         "--node", NODES[1], "--quorum", "3"],
                        transport=transport)
        self.assertEqual(code, 2)
        self.assertEqual(transport.calls, [])

    def test_20b_the_refusal_names_why_there_is_no_default_node_list(self):
        with self.assertRaises(independent_confirm.CallerError) as caught:
            check(expectation(), [NODES[0]], quorum=3,
                  transport=raising_transport)
        self.assertIn("vendor list", str(caught.exception))

    def test_20c_check_asks_every_node_exactly_once(self):
        transport = FakeTransport()
        verdict = check(expectation(), list(NODES), quorum=3,
                        transport=transport, now="2026-10-02T06:00:00Z")
        self.assertEqual([call[0] for call in transport.calls], list(NODES))
        self.assertEqual(transport.calls[0][1],
                         {"action": "block_info", "json_block": "true",
                          "hash": BLOCK})
        self.assertTrue(verdict["confirmed_independently"])

    # -- 21 -----------------------------------------------------------------
    def test_21_decide_holds_no_clock(self):
        verdict = decide(expectation(), agreeing(3), quorum=3)
        self.assertNotIn("measured_at", verdict)

    def test_21b_check_records_when_it_asked(self):
        verdict = check(expectation(), list(NODES), quorum=3,
                        transport=FakeTransport(), now="2026-10-02T06:00:00Z")
        self.assertEqual(verdict["measured_at"], "2026-10-02T06:00:00Z")

    # -- 22 -----------------------------------------------------------------
    def test_22_observed_cannot_carry_the_body(self):
        """A node that answers ten megabytes must not put ten megabytes here."""
        stuffed = body()
        stuffed["huge"] = "x" * (1024 * 1024)
        for index in range(20):
            stuffed["extra_%d" % index] = {"nested": index}
        verdict = decide(expectation(), [response(NODES[0], stuffed)], quorum=1)
        observed = verdict["per_node"][0]["observed"]
        self.assertTrue(set(observed) <= set(OBSERVED_KEYS), sorted(observed))
        rendered = json.dumps(verdict)
        self.assertNotIn("x" * 200, rendered)
        self.assertLess(len(rendered), 100 * 1024)

    def test_22b_a_huge_value_in_a_permitted_key_is_clipped(self):
        verdict = decide(expectation(),
                         [response(NODES[0], body(amount="9" * 500_000))],
                         quorum=1)
        observed = verdict["per_node"][0]["observed"]
        self.assertLess(len(observed["amount"]), 200)
        self.assertEqual(verdict["per_node"][0]["reason"], "node_malformed")

    # -- 23 -----------------------------------------------------------------
    def test_23_every_node_unreachable_is_exit_one_not_a_caller_error(self):
        """A true answer about the world, not a mistake by the caller."""
        transport = FakeTransport({
            url: (False, None, "timed out") for url in NODES})
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(["check", "--block", BLOCK, "--to", PAYEE,
                         "--amount-raw", RAW] +
                        [arg for url in NODES for arg in ("--node", url)],
                        transport=transport)
        self.assertEqual(code, 1)
        verdict = json.loads(buffer.getvalue())
        self.assertIn("no_usable_node", verdict["reasons"])
        self.assertEqual(verdict["unusable"], 3)

    # -- 24 -----------------------------------------------------------------
    def test_24_a_two_hundred_with_a_non_json_body_is_malformed(self):
        transport = FakeTransport({
            NODES[0]: (True, None, "not JSON: Expecting value")})
        verdict = check(expectation(), list(NODES), quorum=3,
                        transport=transport, now="2026-10-02T06:00:00Z")
        self.assertEqual(verdict["per_node"][0]["reason"], "node_malformed")
        self.assertEqual(verdict["per_node"][0]["verdict"], "unusable")
        self.assertFalse(verdict["confirmed_independently"])

    # -- 25 -----------------------------------------------------------------
    def test_25_a_payee_that_fails_checksum_is_a_caller_error(self):
        """The nearest miss in this whole funnel was an address that fails
        checksum, and nothing else in the pipeline caught it."""
        broken = PAYEE[:-1] + ("4" if PAYEE[-1] != "4" else "5")
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            code = main(["check", "--block", BLOCK, "--to", broken,
                         "--amount-raw", RAW] +
                        [arg for url in NODES for arg in ("--node", url)],
                        transport=raising_transport)
        self.assertEqual(code, 2)
        self.assertIn("bad_checksum", buffer.getvalue())

    def test_25b_an_illegal_character_names_the_character(self):
        broken = PAYEE[:10] + "0" + PAYEE[11:]
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            code = main(["check", "--block", BLOCK, "--to", broken,
                         "--amount-raw", RAW] +
                        [arg for url in NODES for arg in ("--node", url)],
                        transport=raising_transport)
        self.assertEqual(code, 2)
        self.assertIn("bad_character", buffer.getvalue())
        self.assertIn("'0'", buffer.getvalue())

    # -- 26 -----------------------------------------------------------------
    def test_26_an_exponent_is_not_an_amount_of_raw(self):
        buffer = io.StringIO()
        with contextlib.redirect_stderr(buffer):
            code = main(["check", "--block", BLOCK, "--to", PAYEE,
                         "--amount-raw", "1e30"] +
                        [arg for url in NODES for arg in ("--node", url)],
                        transport=raising_transport)
        self.assertEqual(code, 2)
        self.assertIn("exponent", buffer.getvalue())

    def test_26b_a_bad_block_hash_is_a_caller_error(self):
        for bad in (BLOCK[:-1], BLOCK[:-1] + "g", ""):
            with self.assertRaises(independent_confirm.CallerError):
                decide(expectation(block_hash=bad), agreeing(3), quorum=3)

    def test_26c_an_unknown_key_in_expect_is_a_caller_error(self):
        document = expectation()
        document["memo"] = "thanks"
        with self.assertRaises(independent_confirm.CallerError):
            decide(document, agreeing(3), quorum=3)

    def test_26d_a_subtype_other_than_send_is_a_caller_error(self):
        with self.assertRaises(independent_confirm.CallerError):
            decide(expectation(subtype="receive"), agreeing(3), quorum=3)


class HandOff(unittest.TestCase):
    """The subcommand that lets the caller throw this module away."""

    # -- 27 -----------------------------------------------------------------
    def test_27_curl_prints_one_pasteable_line_per_node(self):
        done = subprocess.run(
            [sys.executable, os.path.join(ROOT, "independent_confirm.py"),
             "curl", "--block", BLOCK] +
            [arg for url in NODES for arg in ("--node", url)],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stderr, "")
        commands = [line for line in done.stdout.splitlines()
                    if line.startswith("curl ")]
        self.assertEqual(len(commands), len(NODES))
        for url, line in zip(NODES, commands):
            self.assertIn(url, line)
            self.assertIn(BLOCK, line)
            self.assertIn("block_info", line)

    def test_27b_the_checklist_names_the_four_fields_and_the_values(self):
        lines = curl_lines(BLOCK, list(NODES), to_account=PAYEE, amount_raw=RAW)
        text = "\n".join(lines)
        for field in ("confirmed", "subtype", "amount", "link_as_account"):
            self.assertIn(field, text)
        self.assertIn(RAW, text)
        self.assertIn(PAYEE, text)
        self.assertIn("integer", text)

    def test_27c_the_checklist_warns_about_a_node_of_ours(self):
        text = "\n".join(curl_lines(BLOCK, ["https://rpc.getunstuck.space/"]))
        self.assertIn("WARNING", text)
        self.assertIn("must not count", text)

    def test_27d_curl_refuses_a_block_hash_it_cannot_use(self):
        done = subprocess.run(
            [sys.executable, os.path.join(ROOT, "independent_confirm.py"),
             "curl", "--block", "nope", "--node", NODES[0]],
            capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(done.returncode, 2)
        self.assertEqual(done.stdout, "")

    # -- 28 -----------------------------------------------------------------
    def test_28_self_test_passes_and_opens_no_socket(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = self_test(transport=raising_transport)
        self.assertEqual(code, 0, buffer.getvalue())
        report = json.loads(buffer.getvalue())
        self.assertEqual(report["self_test"], "pass")
        self.assertEqual(report["failures"], [])
        self.assertEqual(report["node_reasons_controlled"], len(NODE_REASONS))
        self.assertEqual(report["overall_reasons_controlled"],
                         len(OVERALL_REASONS))

    def test_28b_every_reason_in_both_tables_has_a_control(self):
        self.assertEqual(sorted(independent_confirm._node_controls()),
                         sorted(NODE_REASONS))
        self.assertEqual(sorted(independent_confirm._overall_controls()),
                         sorted(OVERALL_REASONS))

    def test_28c_the_cli_self_test_exits_zero(self):
        done = subprocess.run(
            [sys.executable, os.path.join(ROOT, "independent_confirm.py"),
             "--self-test"], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(done.returncode, 0, done.stderr)

    # -- 29 -----------------------------------------------------------------
    def test_29_quiet_prints_nothing_and_still_sets_the_exit_code(self):
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(["check", "--block", BLOCK, "--to", PAYEE,
                         "--amount-raw", RAW, "--quiet"] +
                        [arg for url in NODES for arg in ("--node", url)],
                        transport=FakeTransport())
        self.assertEqual(code, 0)
        self.assertEqual(buffer.getvalue(), "")

    def test_29b_quiet_is_silent_on_a_refusal_too(self):
        transport = FakeTransport({
            NODES[0]: (True, body(amount=RAW_ONE_OFF), None)})
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = main(["check", "--block", BLOCK, "--to", PAYEE,
                         "--amount-raw", RAW, "--quiet"] +
                        [arg for url in NODES for arg in ("--node", url)],
                        transport=transport)
        self.assertEqual(code, 1)
        self.assertEqual(buffer.getvalue(), "")

    # -- 30 -----------------------------------------------------------------
    def test_30_decide_is_deterministic(self):
        responses = agreeing(2) + [
            response("https://four.example.org/", body(amount=RAW_ONE_OFF)),
            response("https://rpc.getunstuck.space/"),
            response("https://five.example.org/", None, ok=False, error="down")]
        first = json.dumps(decide(expectation(), responses, quorum=3),
                           indent=2, sort_keys=False)
        second = json.dumps(decide(expectation(), responses, quorum=3),
                            indent=2, sort_keys=False)
        self.assertEqual(first, second)


class NothingOfOursDecides(unittest.TestCase):
    """The claims this module makes about itself, asserted rather than trusted."""

    def test_the_payer_account_never_affects_the_verdict(self):
        """`block_account` is reported under `observed` and votes on nothing.

        Flipped in an otherwise agreeing fixture, the node must still agree.
        """
        flipped = body(block_account=PAYEE)
        verdict = decide(expectation(), [response(NODES[0], flipped)], quorum=1)
        self.assertEqual(verdict["per_node"][0]["reason"], "ok")
        self.assertTrue(verdict["confirmed_independently"])
        self.assertEqual(verdict["per_node"][0]["observed"]["block_account"], PAYEE)

    def test_the_module_ships_no_node_list(self):
        """No module-level constant holds a node URL, and the test fixtures
        that do are not reachable from a default.

        A default list chosen by us would be a vendor list, and would
        re-create the exact problem this module exists to solve.
        """
        offenders = []
        for name in dir(independent_confirm):
            if not name.isupper():
                continue
            value = getattr(independent_confirm, name)
            rendered = json.dumps(value) if isinstance(
                value, (str, list, tuple, dict)) else ""
            if "://" in rendered:
                offenders.append(name)
        self.assertEqual(offenders, [],
                         "a default node list chosen by us would be a vendor list")

    def test_the_notes_say_who_chose_the_nodes(self):
        notes = " ".join(decide(expectation(), agreeing(3), quorum=3)["notes"])
        self.assertIn("You chose these nodes", notes)
        self.assertIn("throw it away", notes)
        self.assertIn("default node list", notes)

    def test_the_output_holds_exactly_the_documented_keys(self):
        expected = {
            "tool", "version", "expect", "quorum_required", "nodes_total",
            "agreeing", "dissenting", "unusable", "excluded", "per_node",
            "split", "vendor_endpoints_present", "confirmed_independently",
            "reasons", "notes",
        }
        self.assertEqual(set(decide(expectation(), agreeing(3), quorum=3)),
                         expected)
        self.assertEqual(
            set(check(expectation(), list(NODES), quorum=3,
                      transport=FakeTransport(), now="2026-10-02T06:00:00Z")),
            expected | {"measured_at"})

    def test_every_per_node_element_holds_exactly_four_keys(self):
        verdict = decide(expectation(), agreeing(3), quorum=3)
        for node in verdict["per_node"]:
            self.assertEqual(set(node),
                             {"endpoint", "verdict", "reason", "observed"})

    def test_every_reason_emitted_is_in_the_closed_table(self):
        responses = agreeing(1) + [
            response(NODES[1], body(amount=RAW_ONE_OFF)),
            response(NODES[2], None, ok=False, error="down"),
            response("https://rpc.getunstuck.space/")]
        verdict = decide(expectation(), responses, quorum=3)
        for node in verdict["per_node"]:
            self.assertIn(node["reason"], NODE_REASONS)
        for reason in verdict["reasons"]:
            self.assertIn(reason, OVERALL_REASONS)

    def test_a_malformed_response_envelope_is_a_caller_error(self):
        for bad in ({"endpoint": NODES[0], "ok": True},
                    {"endpoint": NODES[0], "ok": True, "body": None,
                     "error": None, "extra": 1},
                    "not an object"):
            with self.assertRaises(independent_confirm.CallerError):
                decide(expectation(), [bad], quorum=1)

    def test_a_quorum_below_one_is_a_caller_error(self):
        for bad in (0, -1):
            with self.assertRaises(independent_confirm.CallerError):
                decide(expectation(), agreeing(3), quorum=bad)

    def test_the_default_transport_is_not_imported_at_module_scope(self):
        """urllib is imported inside the transport, so nothing that only calls
        `decide` has a network library reachable from its import graph."""
        with open(os.path.join(ROOT, "independent_confirm.py"),
                  encoding="utf-8") as handle:
            source = handle.read()
        head = source.split("def urllib_transport")[0]
        self.assertNotIn("import urllib.request", head)


if __name__ == "__main__":
    unittest.main()
