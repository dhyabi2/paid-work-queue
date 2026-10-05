#!/usr/bin/env python3
"""The demand signal is the count of distinct strangers, and never the settlement count.

Every test here is one line of the specification an outside agent wrote for us.
`moltbookrevenueagent`, 2026-10-04T12:26:14Z, having published 328 settlement
rows of which 16 survived dropping the operator wallets:

    "the 16-of-328 ratio is the honest headline ... require each application to
    carry N external settlement edges with distinct non-operator counterparties,
    each re-derivable from chain alone. Anything the operator can backdate
    doesn't count."

The fixture in `external_edge_count.control_settlements()` is that ratio.
"""

import builtins
import io
import json
import os
import socket
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "vendor"))

import external_edge_count as eec  # noqa: E402
import jobs_feed  # noqa: E402
import nanoaddr  # noqa: E402
import validate  # noqa: E402

OPERATORS = eec.control_operator_accounts()
FULL_REQUIREMENT = {"min_distinct_external_counterparties": 3,
                    "max_largest_counterparty_share": 0.5,
                    "require_chain_rederivable": True}


def hash_for(n):
    """A 64-character block hash, built rather than written out.

    `validate.scan_for_secrets` refuses any standalone 64-hex run in a
    committed file, because a Nano seed looks exactly like one.
    """
    return "%064X" % n


def external_row(payer, payee, n, **over):
    row = {"payer_account": payer, "payee_account": payee,
           "amount_raw": str(10 ** 28 + n), "block_hash": hash_for(5000 + n),
           "confirmed": True, "declared_role": "external"}
    row.update(over)
    return row


class Counting(unittest.TestCase):

    # 1 ------------------------------------------------------------------
    def test_01_moltbookrevenueagents_own_numbers(self):
        """328 rows: 240 self, 72 operator, 16 external across 11 payers.

        Their ratio, published at their own receipts endpoint and quoted in
        the module docstring. 16-of-328 is the headline they refused to soften,
        and 312 is the number of rows they could have authored themselves.
        """
        result = eec.count(eec.control_settlements(), OPERATORS)
        self.assertEqual(result["settlement_count"], 328)
        self.assertEqual(result["settlements_considered"], 328)
        self.assertEqual(result["self_edges"], 240)
        self.assertEqual(result["operator_edges"], 72)
        self.assertEqual(result["external_edges"], 16)
        self.assertEqual(result["distinct_external_counterparties"], 11)
        self.assertEqual(result["operator_authorable"], 312)
        self.assertEqual(result["re_derivable_from_chain_alone"], 16)
        self.assertEqual(result["demand_signal"]["value"], 11)
        self.assertEqual(result["operator_accounts_declared"], 3)
        self.assertEqual(result["undeclared_edges"], 0)
        self.assertEqual(result["reasons"], [])

    # 2 ------------------------------------------------------------------
    def test_02_the_demand_signal_is_never_the_settlement_count(self):
        result = eec.count(eec.control_settlements(), OPERATORS)
        self.assertNotEqual(result["demand_signal"]["value"],
                            result["settlement_count"])
        self.assertEqual(result["demand_signal"]["not"], "settlement_count")
        self.assertEqual(result["demand_signal"]["field"],
                         "distinct_external_counterparties")
        # And the count it is NOT is still published, so a reader can see both.
        self.assertIn("settlement_count", result)

    # 3 ------------------------------------------------------------------
    def test_03_sixteen_payments_from_one_stranger_is_one_counterparty(self):
        result = eec.count(eec.single_payer_settlements(), OPERATORS)
        self.assertEqual(result["external_edges"], 16)
        self.assertEqual(result["distinct_external_counterparties"], 1)
        self.assertEqual(result["largest_counterparty_share"], 1.0)
        self.assertEqual(result["demand_signal"]["value"], 1)

    # 4 ------------------------------------------------------------------
    def test_04_an_undeclared_operator_set_is_refused(self):
        """Empty is a refusal, not "no operator accounts, so all 328 are external".

        A build that treated it as a convenience would publish 328 as demand,
        which is the exact failure this whole file exists to prevent.
        """
        rows = eec.control_settlements()
        for undeclared in ([], None, ()):
            with self.subTest(undeclared=undeclared):
                with self.assertRaises(eec.Refusal) as caught:
                    eec.count(rows, undeclared)
                self.assertEqual(caught.exception.code,
                                 "operator_accounts_not_declared")
        out = io.StringIO()
        self.assertEqual(self.cli(["count", "--settlements", self.write(rows),
                                   "--operator-accounts", self.write([])], out), 2)
        self.assertEqual(json.loads(out.getvalue())["error"],
                         "operator_accounts_not_declared")

    # 5 ------------------------------------------------------------------
    def test_05_self_edges_are_found_by_value_not_by_spelling(self):
        """One account in both its spellings is one account, so the edge is self.

        `canonical.py`'s own docstring records this as a defect that already
        bit this repository: the legacy `xrb_` form and the modern `nano_` form
        carry the same 60 characters encoding the same public key.
        """
        import hashlib
        key = hashlib.sha256(b"two-spellings").digest()
        modern = nanoaddr.encode(key, "nano_")
        legacy = nanoaddr.encode(key, "xrb_")
        # The control: the two strings differ, so a naive `==` on them would
        # have called one account two accounts and the edge external.
        self.assertNotEqual(modern, legacy)
        row = {"payer_account": legacy, "payee_account": modern,
               "amount_raw": "1", "block_hash": hash_for(11),
               "confirmed": True, "declared_role": "self"}
        result = eec.count([row], OPERATORS)
        self.assertEqual(result["self_edges"], 1)
        self.assertEqual(result["external_edges"], 0)
        self.assertEqual(result["distinct_external_counterparties"], 0)
        # The control: comparing the raw strings would have called it external.
        self.assertNotEqual(row["payer_account"], row["payee_account"])

    # 6 ------------------------------------------------------------------
    def test_06_a_bad_checksum_is_a_refusal_not_a_row(self):
        """eddie_researcher's failure mode: an address that fails checksum.

        It names an account that does not exist, so it can never be counted as
        a stranger who paid.
        """
        good = eec.address("checksum-control")
        broken = good[:-1] + ("a" if good[-1] != "a" else "b")
        row = external_row(broken, eec.address("seller"), 1)
        with self.assertRaises(eec.Refusal) as caught:
            eec.count([row], OPERATORS)
        self.assertEqual(caught.exception.code, "bad_account")
        self.assertIn(broken, caught.exception.detail)

    # 7 ------------------------------------------------------------------
    def test_07_a_violation_is_found_and_halts(self):
        own = OPERATORS[0]
        row = {"payer_account": own, "payee_account": own, "amount_raw": "1",
               "block_hash": hash_for(13), "confirmed": True,
               "declared_role": "external"}
        found = eec.violations([row], OPERATORS)
        self.assertEqual(found, [{"block_hash": hash_for(13),
                                  "declared": "external", "observed": "self"}])
        result = eec.count([row], OPERATORS)
        self.assertIn("role_violations_present", result["reasons"])
        out = io.StringIO()
        self.assertEqual(self.cli(["count", "--settlements", self.write([row]),
                                   "--operator-accounts", self.write(OPERATORS)],
                                  out), 3)

    def test_07b_an_operator_edge_declared_external_is_also_a_violation(self):
        """Observable only because the operator set is DECLARED.

        `counterparty_role.py` cannot contradict an operator claim from two
        addresses alone; here the declaration makes it checkable.
        """
        row = external_row(eec.address("stranger"), OPERATORS[1], 2)
        found = eec.violations([row], OPERATORS)
        self.assertEqual([entry["observed"] for entry in found], ["operator"])

    # 8 ------------------------------------------------------------------
    def test_08_chain_rederivable_is_stricter_than_external(self):
        """"Anything the operator can backdate doesn't count." """
        rows = [external_row(eec.address("payer-a"), eec.address("seller-a"), 1),
                external_row(eec.address("payer-b"), eec.address("seller-b"), 2,
                             confirmed=False),
                external_row(eec.address("payer-c"), eec.address("seller-c"), 3,
                             block_hash="not-a-hash")]
        result = eec.count(rows, OPERATORS)
        self.assertEqual(result["external_edges"], 3)
        self.assertEqual(result["re_derivable_from_chain_alone"], 1)
        self.assertNotEqual(result["external_edges"],
                            result["re_derivable_from_chain_alone"])
        self.assertEqual(result["operator_authorable"], 2)

    # 9 ------------------------------------------------------------------
    def test_09_concentration_is_reported(self):
        """projectzeromarket's "top ten at 66.4%" is why this field exists."""
        rows = []
        hog = eec.address("the-hog")
        for n in range(7):
            rows.append(external_row(hog, eec.address("seller-%d" % n), n))
        for n in range(7, 10):
            rows.append(external_row(eec.address("payer-%d" % n),
                                     eec.address("seller-%d" % n), n))
        result = eec.count(rows, OPERATORS)
        self.assertEqual(result["external_edges"], 10)
        self.assertEqual(result["distinct_external_counterparties"], 4)
        self.assertEqual(result["largest_counterparty_share"], 0.7)
        self.assertLessEqual(result["top_counterparty_concentration"]["top_3"], 1.0)
        self.assertEqual(result["top_counterparty_concentration"]["top_1"], 0.7)
        self.assertEqual(result["top_counterparty_concentration"]["top_3"], 0.9)

    # 10 -----------------------------------------------------------------
    def test_10_the_honest_zero(self):
        """Today's true answer has to be publishable, so zero is not a refusal."""
        result = eec.count([], OPERATORS)
        self.assertEqual(result["settlement_count"], 0)
        self.assertEqual(result["external_edges"], 0)
        self.assertEqual(result["distinct_external_counterparties"], 0)
        self.assertEqual(result["operator_authorable"], 0)
        self.assertEqual(result["largest_counterparty_share"], 0.0)
        self.assertEqual(result["demand_signal"]["value"], 0)
        self.assertEqual(result["reasons"], ["no_settlements_yet"])
        out = io.StringIO()
        self.assertEqual(self.cli(["count", "--settlements", self.write([]),
                                   "--operator-accounts", self.write(OPERATORS)],
                                  out), 0)

    # 11 -----------------------------------------------------------------
    def test_11_attest_falls_short_without_raising(self):
        short = eec.count(eec.single_payer_settlements(), OPERATORS)
        verdict = eec.attest(short, FULL_REQUIREMENT)
        self.assertFalse(verdict["meets_requirement"])
        rules = {entry["rule"]: entry for entry in verdict["failed"]}
        self.assertIn("min_distinct_external_counterparties", rules)
        self.assertEqual(rules["min_distinct_external_counterparties"]["required"], 3)
        self.assertEqual(rules["min_distinct_external_counterparties"]["observed"], 1)
        self.assertIn("not say the work they paid for was real", verdict["note"])
        out = io.StringIO()
        self.assertEqual(self.cli(["attest", "--count", self.write(short),
                                   "--requirement", self.write(FULL_REQUIREMENT)],
                                  out), 3)

    def test_11b_attest_passes_a_book_that_carries_the_strangers(self):
        full = eec.count(eec.control_settlements(), OPERATORS)
        verdict = eec.attest(full, FULL_REQUIREMENT)
        self.assertTrue(verdict["meets_requirement"], verdict["failed"])
        self.assertEqual(verdict["failed"], [])
        out = io.StringIO()
        self.assertEqual(self.cli(["attest", "--count", self.write(full),
                                   "--requirement", self.write(FULL_REQUIREMENT)],
                                  out), 0)

    # 12 -----------------------------------------------------------------
    def test_12_attest_is_bounded_by_concentration_too(self):
        """Five strangers, one of them 80% of the edges, is not five strangers."""
        rows = []
        hog = eec.address("concentration-hog")
        for n in range(16):
            rows.append(external_row(hog, eec.address("c-seller-%d" % n), n))
        for n in range(16, 20):
            rows.append(external_row(eec.address("c-payer-%d" % n),
                                     eec.address("c-seller-%d" % n), n))
        result = eec.count(rows, OPERATORS)
        self.assertEqual(result["external_edges"], 20)
        self.assertEqual(result["distinct_external_counterparties"], 5)
        self.assertEqual(result["largest_counterparty_share"], 0.8)
        verdict = eec.attest(result, FULL_REQUIREMENT)
        self.assertFalse(verdict["meets_requirement"])
        self.assertEqual([entry["rule"] for entry in verdict["failed"]],
                         ["max_largest_counterparty_share"])
        self.assertEqual(verdict["failed"][0]["required"], 0.5)
        self.assertEqual(verdict["failed"][0]["observed"], 0.8)

    def test_12b_require_chain_rederivable_fails_on_an_unconfirmed_edge(self):
        rows = [external_row(eec.address("r-payer-%d" % n),
                             eec.address("r-seller-%d" % n), n,
                             confirmed=(n != 0))
                for n in range(4)]
        result = eec.count(rows, OPERATORS)
        verdict = eec.attest(result, {"min_distinct_external_counterparties": 3,
                                      "max_largest_counterparty_share": 1.0,
                                      "require_chain_rederivable": True})
        self.assertEqual([entry["rule"] for entry in verdict["failed"]],
                         ["require_chain_rederivable"])
        self.assertEqual(verdict["failed"][0]["required"], 4)
        self.assertEqual(verdict["failed"][0]["observed"], 3)
        # The same book passes when the requirement does not ask for it.
        relaxed = eec.attest(result, {"min_distinct_external_counterparties": 3,
                                      "max_largest_counterparty_share": 1.0,
                                      "require_chain_rederivable": False})
        self.assertTrue(relaxed["meets_requirement"], relaxed["failed"])

    # 13 -----------------------------------------------------------------
    def test_13_no_period_is_invented(self):
        rows = [{"payer_account": eec.address("p-%d" % n),
                 "payee_account": eec.address("s-%d" % n),
                 "amount_raw": "1", "block_hash": hash_for(600 + n),
                 "confirmed": True, "declared_role": "external"}
                for n in range(2)]
        self.assertIsNone(eec.count(rows, OPERATORS)["period"])
        with self.assertRaises(eec.Refusal) as caught:
            eec.count(rows, OPERATORS, period={"from": "2026-10-01T00:00:00Z",
                                               "to": "2026-10-08T00:00:00Z"})
        self.assertEqual(caught.exception.code, "period_without_timestamps")

    def test_13b_a_period_is_half_open_and_reported(self):
        """from <= timestamp < to, so two adjacent windows never double-count."""
        stamped = []
        for n, when in enumerate(("2026-09-30T23:59:59Z", "2026-10-01T00:00:00Z",
                                  "2026-10-07T23:59:59Z", "2026-10-08T00:00:00Z")):
            stamped.append(external_row(eec.address("w-p-%d" % n),
                                        eec.address("w-s-%d" % n), 700 + n,
                                        timestamp=when))
        window = {"from": "2026-10-01T00:00:00Z", "to": "2026-10-08T00:00:00Z"}
        result = eec.count(stamped, OPERATORS, period=window)
        self.assertEqual(result["settlements_considered"], 4)
        self.assertEqual(result["settlement_count"], 2)
        self.assertEqual(result["external_edges"], 2)
        self.assertEqual(result["period"], window)

    def test_13c_a_window_spelled_wrongly_is_refused_not_ignored(self):
        """A window this tool cannot read must never be read as "no window"."""
        rows = [external_row(eec.address("b-p"), eec.address("b-s"), 800,
                             timestamp="2026-10-02T00:00:00Z")]
        for bad in ({"from": "yesterday"}, {"from": None, "to": None},
                    {"from": "2026-10-08T00:00:00Z", "to": "2026-10-01T00:00:00Z"},
                    {"window": "a week"}, "a week"):
            with self.subTest(bad=bad):
                with self.assertRaises(eec.Refusal) as caught:
                    eec.count(rows, OPERATORS, period=bad)
                self.assertEqual(caught.exception.code, "bad_period")

    # 14 -----------------------------------------------------------------
    def test_14_a_duplicate_block_hash_is_refused(self):
        """Double-counting one block is the cheapest way to inflate demand."""
        first = external_row(eec.address("d-p1"), eec.address("d-s1"), 1)
        second = external_row(eec.address("d-p2"), eec.address("d-s2"), 2,
                              block_hash=first["block_hash"])
        with self.assertRaises(eec.Refusal) as caught:
            eec.count([first, second], OPERATORS)
        self.assertEqual(caught.exception.code, "duplicate_block_hash")
        # And in the other spelling: one block is one block in either case.
        # The hash has to carry hex LETTERS for this control to control
        # anything - an all-digit hash is its own lowercase, so a
        # case-sensitive comparison would pass a test built on one.
        mixed = "ABCDEF" + hash_for(7)[6:]
        self.assertNotEqual(mixed, mixed.lower())
        upper = external_row(eec.address("d-p3"), eec.address("d-s3"), 3,
                             block_hash=mixed)
        lowered = external_row(eec.address("d-p4"), eec.address("d-s4"), 4,
                               block_hash=mixed.lower())
        with self.assertRaises(eec.Refusal) as caught:
            eec.count([upper, lowered], OPERATORS)
        self.assertEqual(caught.exception.code, "duplicate_block_hash")
        # Both spellings are still 64 hex characters, so both are re-derivable:
        # the refusal is about the duplicate and not about the casing.
        self.assertEqual(eec.count([upper], OPERATORS)
                         ["re_derivable_from_chain_alone"], 1)
        self.assertEqual(eec.count([lowered], OPERATORS)
                         ["re_derivable_from_chain_alone"], 1)

    # 15 -----------------------------------------------------------------
    def test_15_no_network_and_no_disk(self):
        """count and attest run on in-memory data with both taken away."""
        rows = eec.control_settlements()
        requirement = dict(FULL_REQUIREMENT)

        def no_socket(*args, **kwargs):
            raise AssertionError("this tool must never open a socket")

        def no_open(*args, **kwargs):
            raise AssertionError("this tool must never open a file")

        real_socket, real_open = socket.socket, builtins.open
        socket.socket, builtins.open = no_socket, no_open
        try:
            result = eec.count(rows, OPERATORS)
            verdict = eec.attest(result, requirement)
            found = eec.violations(rows, OPERATORS)
            fields = eec.demand_fields([], OPERATORS)
        finally:
            socket.socket, builtins.open = real_socket, real_open
        self.assertEqual(result["distinct_external_counterparties"], 11)
        self.assertTrue(verdict["meets_requirement"])
        self.assertEqual(found, [])
        self.assertEqual(fields["demand_signal"]["value"], 0)

    def test_15b_nothing_on_the_import_graph_can_reach_the_network(self):
        network = {"urllib", "http", "socket", "ssl", "ftplib", "smtplib",
                   "poplib", "imaplib", "telnetlib", "asyncio", "requests",
                   "httpx", "aiohttp", "urllib3"}
        for source in ("external_edge_count.py", "counterparty_role.py",
                       "canonical.py", os.path.join("vendor", "nanoaddr.py")):
            with self.subTest(source=source):
                roots = {entry["module"].split(".")[0]
                         for entry in eec.import_graph(os.path.join(ROOT, source))}
                self.assertEqual(roots & network, set())

    def test_15c_this_tool_holds_no_clock(self):
        """Asserted over the parse tree, not over the text."""
        import ast
        with open(os.path.join(ROOT, "external_edge_count.py"),
                  encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        clock = {"now", "utcnow", "today", "time", "monotonic", "perf_counter",
                 "process_time", "localtime", "gmtime", "fromtimestamp"}
        called = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                name = getattr(func, "attr", None) or getattr(func, "id", None)
                if name:
                    called.add(name)
        self.assertEqual(called & clock, set())

    # 16 -----------------------------------------------------------------
    def test_16_every_reason_code_is_reachable(self):
        report = eec.self_test()
        self.assertTrue(report["ok"],
                        [c for c in report["controls"] if not c["ok"]])
        self.assertEqual(report["codes_never_evaluated"], [])
        covered = {control["code"] for control in report["controls"]}
        for code in eec.ALL_CODES:
            with self.subTest(code=code):
                self.assertIn(code, covered)
        out = io.StringIO()
        self.assertEqual(eec.main(["--self-test"], out=out), 0)

    def test_16b_the_remaining_refusals_each_have_their_own_code(self):
        rows = eec.control_settlements()
        cases = (
            ("bad_settlement_shape", lambda: eec.count(["not a row"], OPERATORS)),
            ("bad_settlement_shape",
             lambda: eec.count([{k: v for k, v in rows[0].items()
                                 if k != "payee_account"}], OPERATORS)),
            ("bad_settlement_shape",
             lambda: eec.count([dict(rows[0], declared_role="customer")],
                               OPERATORS)),
            ("bad_settlement_shape", lambda: eec.count({"rows": []}, OPERATORS)),
            ("bad_amount_raw",
             lambda: eec.count([dict(rows[0], amount_raw="0.25")], OPERATORS)),
            ("bad_amount_raw",
             lambda: eec.count([dict(rows[0], amount_raw=1e26)], OPERATORS)),
            ("bad_amount_raw",
             lambda: eec.count([dict(rows[0], amount_raw="-1")], OPERATORS)),
            ("bad_requirement_shape",
             lambda: eec.attest(eec.count([], OPERATORS),
                                {"min_distinct_external_counterparties": 3})),
            ("bad_requirement_shape",
             lambda: eec.attest(eec.count([], OPERATORS),
                                dict(FULL_REQUIREMENT,
                                     max_largest_counterparty_share=1.5))),
            ("bad_requirement_shape",
             lambda: eec.attest(eec.count([], OPERATORS),
                                dict(FULL_REQUIREMENT,
                                     require_chain_rederivable="yes"))),
            ("bad_count_shape", lambda: eec.attest({"external_edges": 1},
                                                   FULL_REQUIREMENT)),
            ("bad_count_shape", lambda: eec.attest("328", FULL_REQUIREMENT)),
        )
        for code, call in cases:
            with self.subTest(code=code):
                with self.assertRaises(eec.Refusal) as caught:
                    call()
                self.assertEqual(caught.exception.code, code)

    def test_16c_money_is_never_read_through_a_float(self):
        """1 XNO is 10**30 raw: a float loses the bottom digits of one.

        `float(1e26)` is 100000000000000004764729344, so an amount handed in as
        a float is refused rather than coerced.
        """
        row = external_row(eec.address("f-p"), eec.address("f-s"), 1,
                           amount_raw=float(10 ** 26))
        with self.assertRaises(eec.Refusal) as caught:
            eec.count([row], OPERATORS)
        self.assertEqual(caught.exception.code, "bad_amount_raw")
        # The same number as a string of digits is read exactly.
        exact = external_row(eec.address("f-p"), eec.address("f-s"), 1,
                             amount_raw="100000000000000000000000000")
        self.assertEqual(eec.count([exact], OPERATORS)["external_edges"], 1)

    def test_16d_a_missing_role_is_reported_and_never_inferred(self):
        rows = [external_row(eec.address("u-p"), eec.address("u-s"), 1)]
        rows[0].pop("declared_role")
        result = eec.count(rows, OPERATORS)
        self.assertEqual(result["undeclared_edges"], 1)
        # Observed external, because that is what the two addresses say; the
        # DECLARATION is still recorded as absent rather than filled in.
        self.assertEqual(result["external_edges"], 1)
        self.assertEqual(eec.violations(rows, OPERATORS), [])

    # 17 -----------------------------------------------------------------
    def test_17_the_vectors_are_frozen(self):
        """Byte for byte. A changed number here is a decision, not a refactor."""
        path = os.path.join(ROOT, "vectors", "external-edge-count-v1.json")
        with open(path, "rb") as handle:
            on_disk = handle.read()
        self.assertEqual(on_disk, eec.vectors_bytes())
        document = json.loads(on_disk.decode("utf-8"))
        self.assertEqual(document["moltbookrevenueagent_328"]["external_edges"], 16)
        self.assertEqual(
            document["moltbookrevenueagent_328"]["distinct_external_counterparties"],
            11)
        self.assertEqual(document["moltbookrevenueagent_328"]["operator_authorable"],
                         312)
        self.assertEqual(document["one_stranger_16_edges"]
                         ["distinct_external_counterparties"], 1)
        self.assertEqual(document["honest_zero"]["reasons"], ["no_settlements_yet"])
        self.assertFalse(document["attest_falls_short"]["meets_requirement"])
        out = io.StringIO()
        self.assertEqual(eec.main(["--vectors"], out=out), 0)
        self.assertEqual(out.getvalue().encode("utf-8"), on_disk)

    def test_17b_the_vectors_carry_no_standalone_64_hex(self):
        """The secret gate's rule, asserted here so the file cannot grow one."""
        path = os.path.join(ROOT, "vectors", "external-edge-count-v1.json")
        self.assertEqual(validate.scan_for_secrets(os.path.dirname(path)), [])

    # 18 -----------------------------------------------------------------
    def test_18_stats_and_the_feed_publish_the_new_fields_as_zero(self):
        """With today's empty receipts.json every one of them reads zero."""
        jobs_document = {"jobs": [{"id": "job-001", "state": "open"}]}
        stats = validate.compute_stats(jobs_document, {"receipts": []},
                                       OPERATORS)
        for field in ("settlement_count", "external_edges",
                      "distinct_external_counterparties", "operator_authorable"):
            with self.subTest(field=field):
                self.assertEqual(stats[field], 0)
        self.assertEqual(stats["demand_signal"]["value"], 0)
        self.assertEqual(stats["demand_signal"]["not"], "settlement_count")
        self.assertEqual(stats["demand_reasons"], ["no_settlements_yet"])
        # Beside the old counters, never instead of them.
        self.assertEqual(stats["jobs_settled"], 0)
        self.assertEqual(stats["sellers_paid"], 0)

        feed, _ = jobs_feed.build([], [], 0, jobs_feed._now("2026-10-05T07:00:00Z"),
                                  operator_accounts=OPERATORS)
        for field in ("distinct_external_counterparties", "operator_authorable",
                      "demand_signal"):
            with self.subTest(field=field):
                self.assertIn(field, feed)
        self.assertEqual(feed["distinct_external_counterparties"], 0)
        self.assertEqual(feed["operator_authorable"], 0)
        self.assertEqual(feed["demand_signal"]["value"], 0)
        self.assertEqual(feed["settled_count"], 0)
        published = json.loads(jobs_feed.serialise(feed).decode("utf-8"))
        self.assertEqual(published["demand_signal"]["field"],
                         "distinct_external_counterparties")

    def test_18b_the_live_committed_stats_json_carries_them(self):
        with open(os.path.join(ROOT, "stats.json"), encoding="utf-8") as handle:
            live = json.load(handle)
        self.assertEqual(live["settlement_count"], 0)
        self.assertEqual(live["distinct_external_counterparties"], 0)
        self.assertEqual(live["operator_authorable"], 0)
        self.assertEqual(live["demand_signal"]["value"], 0)
        self.assertEqual(live["demand_reasons"], ["no_settlements_yet"])

    def test_18c_a_row_we_cannot_classify_publishes_null_and_a_reason(self):
        """The whole point of the block: never a count we cannot stand behind.

        A receipt records the payee and not the payer, so with one real receipt
        and no payer recorded the countable numbers are null with the reason
        beside them - and `operator_authorable` is the whole settlement count,
        because nothing in the book has been shown to be anything else.
        """
        receipts = [{"id": "receipt-001", "paid_to": eec.address("seller"),
                     "amount_raw": "1", "block_hash": hash_for(42),
                     "settled_at": "2026-10-05T06:00:00Z", "confirmed": True}]
        fields = eec.demand_fields(receipts, OPERATORS)
        self.assertEqual(fields["settlement_count"], 1)
        self.assertIsNone(fields["distinct_external_counterparties"])
        self.assertIsNone(fields["external_edges"])
        self.assertIsNone(fields["demand_signal"]["value"])
        self.assertEqual(fields["demand_reasons"], ["payer_not_recorded"])
        self.assertEqual(fields["operator_authorable"], 1)

    def test_18d_an_undeclared_operator_set_publishes_null_never_a_stranger(self):
        """With nothing declared, a self-dealing book must not read as demand."""
        own = eec.address("undeclared-operator")
        receipts = [{"id": "receipt-001", "payer_account": own, "paid_to": own,
                     "amount_raw": "1", "block_hash": hash_for(43),
                     "confirmed": True}]
        fields = eec.demand_fields(receipts, [])
        self.assertEqual(fields["settlement_count"], 1)
        self.assertIsNone(fields["demand_signal"]["value"])
        self.assertEqual(fields["demand_reasons"],
                         ["operator_accounts_not_declared"])
        self.assertEqual(fields["operator_accounts_declared"], 0)
        self.assertEqual(fields["operator_authorable"], 1)
        # Declared, the same row is correctly a self edge and demand is zero.
        declared = eec.demand_fields(receipts, [own])
        self.assertEqual(declared["demand_signal"]["value"], 0)
        self.assertEqual(declared["external_edges"], 0)
        self.assertEqual(declared["operator_accounts_declared"], 1)

    def test_18d2_a_receipt_with_no_confirmed_field_is_not_re_derivable(self):
        """Absent means not SHOWN confirmed, and never assumed confirmed.

        Erring the other way would count a row as chain-re-derivable on the
        strength of a missing field, which is the one direction a demand
        number must never move in.
        """
        payer, payee = eec.address("nc-payer"), eec.address("nc-seller")
        row = {"id": "receipt-001", "payer_account": payer, "paid_to": payee,
               "amount_raw": "1", "block_hash": hash_for(44)}
        fields = eec.demand_fields([row], OPERATORS)
        self.assertEqual(fields["external_edges"], 1)
        self.assertEqual(fields["distinct_external_counterparties"], 1)
        # One settlement, nothing shown re-derivable, so the whole row is ours
        # to have authored.
        self.assertEqual(fields["operator_authorable"], 1)
        confirmed = eec.demand_fields([dict(row, confirmed=True)], OPERATORS)
        self.assertEqual(confirmed["operator_authorable"], 0)

    def test_18e_demand_fields_never_raises(self):
        for receipts in (None, "receipts", [], [None], [{"payer_account": "x",
                                                         "paid_to": "y"}]):
            with self.subTest(receipts=receipts):
                fields = eec.demand_fields(receipts, OPERATORS)
                self.assertIn("demand_signal", fields)
                self.assertEqual(fields["demand_signal"]["not"],
                                 "settlement_count")

    def test_18f_the_declared_file_is_read_and_an_absent_one_is_not_a_crash(self):
        self.assertEqual(validate.read_operator_accounts(ROOT), [])
        self.assertEqual(validate.read_operator_accounts("/nonexistent-root"), [])
        self.assertEqual(jobs_feed.read_operator_accounts(), [])
        self.assertEqual(jobs_feed.read_operator_accounts("/nonexistent/file"), [])
        path = os.path.join(ROOT, "operator_accounts.json")
        with open(path, encoding="utf-8") as handle:
            document = json.load(handle)
        self.assertEqual(document["operator_accounts"], [])

    # the CLI ------------------------------------------------------------
    def test_19_the_cli_exits_as_documented(self):
        out = io.StringIO()
        self.assertEqual(eec.main([], out=out, err=io.StringIO()), 2)
        rows = eec.control_settlements()
        out = io.StringIO()
        self.assertEqual(self.cli(["count", "--settlements", self.write(rows),
                                   "--operator-accounts", self.write(OPERATORS)],
                                  out), 0)
        document = json.loads(out.getvalue())
        self.assertEqual(document["distinct_external_counterparties"], 11)
        # Both wrappings of each input file are accepted.
        out = io.StringIO()
        self.assertEqual(self.cli(
            ["count", "--settlements", self.write({"settlements": rows}),
             "--operator-accounts", self.write({"operator_accounts": OPERATORS})],
            out), 0)
        self.assertEqual(json.loads(out.getvalue())["external_edges"], 16)
        # And an unreadable file refuses rather than counting nothing.
        out = io.StringIO()
        self.assertEqual(self.cli(["count", "--settlements", "/nope.json",
                                   "--operator-accounts", self.write(OPERATORS)],
                                  out), 2)

    def test_19b_the_cli_window_comes_from_the_command_line(self):
        stamped = [external_row(eec.address("c-p-%d" % n),
                                eec.address("c-s-%d" % n), 900 + n,
                                timestamp="2026-10-0%dT00:00:00Z" % (n + 1))
                   for n in range(5)]
        out = io.StringIO()
        self.assertEqual(self.cli(["count", "--settlements", self.write(stamped),
                                   "--operator-accounts", self.write(OPERATORS),
                                   "--from", "2026-10-02T00:00:00Z",
                                   "--to", "2026-10-04T00:00:00Z"], out), 0)
        document = json.loads(out.getvalue())
        self.assertEqual(document["settlements_considered"], 5)
        self.assertEqual(document["settlement_count"], 2)
        self.assertEqual(document["period"], {"from": "2026-10-02T00:00:00Z",
                                              "to": "2026-10-04T00:00:00Z"})

    # helpers ------------------------------------------------------------
    def write(self, document):
        import tempfile
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                             encoding="utf-8")
        json.dump(document, handle)
        handle.close()
        self.addCleanup(os.unlink, handle.name)
        return handle.name

    def cli(self, argv, out):
        return eec.main(argv, out=out, err=io.StringIO())


if __name__ == "__main__":
    unittest.main()
