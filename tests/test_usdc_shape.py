"""The arithmetic that decides whether a USDC-shaped column can hold an XNO amount.

No test touches the network and none reads the live jobs.json; every fixture is
built here or comes from vectors/usdc-shape-v1.json.

Randomised cases are seeded, so a failure reproduces exactly rather than once.
"""

import json
import os
import random
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import usdc_shape  # noqa: E402
from usdc_shape import (  # noqa: E402
    INT64_MAX, MIN_SETTLEABLE_RAW, RAW_PER_MICRO, AmountError, Int64Overflow,
    NegativeAmount, NotRepresentable, describe, fits_int64, micro_to_raw,
    raw_to_micro,
)

VECTORS = os.path.join(ROOT, "vectors", "usdc-shape-v1.json")

#: The amount from `@x402nano/exact` that overflowed minia2a's refunds column.
MINIA2A_AMOUNT = 1000000000000000000000000


class TestTheAmountTheyCouldNotStore(unittest.TestCase):
    # -- 1 ------------------------------------------------------------------
    def test_1_minia2a_exact_amount_is_one_micro_and_fits(self):
        self.assertEqual(MINIA2A_AMOUNT, RAW_PER_MICRO)
        self.assertEqual(raw_to_micro(MINIA2A_AMOUNT), 1)
        self.assertTrue(fits_int64(1))

    def test_1b_the_quantum_is_stated_once_and_is_the_micro(self):
        self.assertEqual(MIN_SETTLEABLE_RAW, RAW_PER_MICRO)
        self.assertEqual(MIN_SETTLEABLE_RAW, 10 ** 24)


class TestOverflowIsRefusedNotWrapped(unittest.TestCase):
    # -- 2 ------------------------------------------------------------------
    def test_2_one_micro_above_int64_raises_rather_than_returning(self):
        too_big = (INT64_MAX + 1) * RAW_PER_MICRO
        with self.assertRaises(Int64Overflow) as caught:
            raw_to_micro(too_big)
        self.assertEqual(caught.exception.micro, INT64_MAX + 1)
        self.assertEqual(caught.exception.code, "int64_overflow")

    def test_2b_the_largest_representable_amount_is_accepted(self):
        self.assertEqual(raw_to_micro(INT64_MAX * RAW_PER_MICRO), INT64_MAX)
        self.assertTrue(fits_int64(INT64_MAX))
        self.assertFalse(fits_int64(INT64_MAX + 1))

    def test_2c_negative_control_a_wrapping_implementation_would_fail_this(self):
        """The assertion is the exception, never a large return value.

        A port that stored into a real int64 and let it wrap would return
        -9223372036854775808 here and pass a test written as
        `assertNotEqual(result, INT64_MAX + 1)`. This one cannot.
        """
        try:
            result = raw_to_micro((INT64_MAX + 1) * RAW_PER_MICRO)
        except Int64Overflow:
            return
        self.fail("expected Int64Overflow, got a value: %r" % result)


class TestSubMicroRefusesByDefault(unittest.TestCase):
    # -- 3 ------------------------------------------------------------------
    def test_3_one_raw_is_not_representable(self):
        with self.assertRaises(NotRepresentable) as caught:
            raw_to_micro(1)
        self.assertEqual(caught.exception.remainder_raw, "1")
        self.assertEqual(caught.exception.code, "not_representable")

    def test_3b_floor_and_ceil_must_be_asked_for(self):
        self.assertEqual(raw_to_micro(1, on_remainder="floor"), 0)
        self.assertEqual(raw_to_micro(1, on_remainder="ceil"), 1)

    def test_3c_an_unknown_policy_is_a_ValueError_not_a_silent_default(self):
        for bad in ("truncate", "round", "REFUSE", "", None, 0):
            with self.assertRaises(ValueError):
                raw_to_micro(RAW_PER_MICRO, on_remainder=bad)

    def test_3d_the_policy_is_checked_before_the_amount(self):
        """A bad policy on a good amount still raises; the default is never assumed."""
        with self.assertRaises(ValueError):
            raw_to_micro(RAW_PER_MICRO, on_remainder="nonsense")

    def test_3e_a_real_tail_is_reported_with_its_remainder(self):
        with self.assertRaises(NotRepresentable) as caught:
            raw_to_micro(RAW_PER_MICRO + 7)
        self.assertEqual(caught.exception.remainder_raw, "7")
        self.assertEqual(raw_to_micro(RAW_PER_MICRO + 7, on_remainder="floor"), 1)
        self.assertEqual(raw_to_micro(RAW_PER_MICRO + 7, on_remainder="ceil"), 2)

    def test_3f_ceil_can_itself_overflow_and_still_refuses(self):
        """Rounding up off the top of the column is an overflow, not a wrap."""
        with self.assertRaises(Int64Overflow):
            raw_to_micro(INT64_MAX * RAW_PER_MICRO + 1, on_remainder="ceil")


class TestRoundTripExactness(unittest.TestCase):
    # -- 4 ------------------------------------------------------------------
    def test_4_round_trip_over_every_vector(self):
        with open(VECTORS, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        checked = 0
        for case in document["cases"]:
            expect = case["expect"]
            if "error" in expect or "micro" not in expect:
                continue
            raw = int(case["input"]["raw"])
            micro = expect["micro"]
            self.assertEqual(raw_to_micro(raw), micro, case["name"])
            self.assertEqual(micro_to_raw(micro), int(expect["raw_round_trip"]), case["name"])
            self.assertEqual(raw_to_micro(micro_to_raw(micro)), micro, case["name"])
            checked += 1
        self.assertGreaterEqual(checked, 5, "the vector file lost its round-trip cases")

    def test_4a_every_error_vector_raises_the_class_it_names(self):
        """The refusals are conformance too: a port must refuse the same amounts."""
        with open(VECTORS, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        classes = {"not_representable": NotRepresentable,
                   "int64_overflow": Int64Overflow,
                   "negative_amount": NegativeAmount}
        checked = 0
        for case in document["cases"]:
            expect = case["expect"]
            if "error" not in expect:
                continue
            raw = int(case["input"]["raw"])
            with self.assertRaises(classes[expect["error"]], msg=case["name"]) as caught:
                raw_to_micro(raw)
            if "remainder_raw" in expect:
                self.assertEqual(caught.exception.remainder_raw, expect["remainder_raw"])
                self.assertEqual(raw_to_micro(raw, on_remainder="floor"), expect["floor"])
                self.assertEqual(raw_to_micro(raw, on_remainder="ceil"), expect["ceil"])
            if "micro" in expect:
                self.assertEqual(str(caught.exception.micro), expect["micro"])
            checked += 1
        self.assertGreaterEqual(checked, 4, "the vector file lost its refusal cases")

    def test_4b_round_trip_over_500_randomised_micro_values(self):
        rng = random.Random(20260929)
        for _ in range(500):
            micro = rng.randint(1, INT64_MAX)
            raw = micro_to_raw(micro)
            self.assertIsInstance(raw, int)
            self.assertEqual(raw_to_micro(raw), micro)
            self.assertEqual(raw % RAW_PER_MICRO, 0)

    def test_4c_no_float_survives_this_path(self):
        """A float argument is refused outright rather than rounded into money."""
        for bad in (1.0, 1e24, float(RAW_PER_MICRO)):
            with self.assertRaises(TypeError):
                raw_to_micro(bad)
            with self.assertRaises(TypeError):
                micro_to_raw(bad)
        for value in (raw_to_micro(RAW_PER_MICRO), micro_to_raw(1)):
            self.assertIsInstance(value, int)
            self.assertNotIsInstance(value, float)

    def test_4d_booleans_are_not_amounts(self):
        for bad in (True, False):
            with self.assertRaises(TypeError):
                raw_to_micro(bad)
            with self.assertRaises(TypeError):
                micro_to_raw(bad)


class TestDescribeIsJsonSafe(unittest.TestCase):
    # -- 5 ------------------------------------------------------------------
    def test_5_describe_round_trips_through_json_with_no_float(self):
        for raw in (0, 1, RAW_PER_MICRO, RAW_PER_MICRO + 7, 10 ** 30,
                    INT64_MAX * RAW_PER_MICRO):
            result = describe(raw)
            reparsed = json.loads(json.dumps(result))
            self.assertIsInstance(reparsed["raw"], str, raw)
            self.assertEqual(int(reparsed["raw"]), raw)
            self.assertIsInstance(reparsed["remainder_raw"], str, raw)
            self.assertIsInstance(reparsed["micro"], int, raw)
            self.assertIsInstance(reparsed["fits_int64"], bool, raw)
            for key, value in reparsed.items():
                self.assertNotIsInstance(value, float, "%s is a float for %d" % (key, raw))

    def test_5b_a_53_bit_consumer_would_still_read_raw_exactly(self):
        """The reason `raw` is a string: 10**30 does not fit a JSON double."""
        raw = 10 ** 30
        text = json.dumps(describe(raw))
        self.assertIn('"%d"' % raw, text)
        self.assertEqual(int(json.loads(text)["raw"]), raw)

    def test_5c_describe_names_the_remainder_rather_than_raising(self):
        result = describe(RAW_PER_MICRO + 7)
        self.assertEqual(result["remainder_raw"], "7")
        self.assertEqual(result["micro"], 1)
        self.assertEqual(result["xno"], "0.000001000000000000000000000007")

    def test_5d_describe_matches_its_vectors(self):
        with open(VECTORS, "r", encoding="utf-8") as handle:
            document = json.load(handle)
        for case in document["describe_cases"]:
            self.assertEqual(describe(int(case["input"]["raw"])), case["expect"], case["name"])


class TestNegatives(unittest.TestCase):
    # -- 6 ------------------------------------------------------------------
    def test_6_negative_raw_and_negative_micro_are_refused(self):
        with self.assertRaises(NegativeAmount) as caught:
            raw_to_micro(-1)
        self.assertEqual(caught.exception.code, "negative_amount")
        with self.assertRaises(NegativeAmount):
            micro_to_raw(-1)
        with self.assertRaises(NegativeAmount):
            describe(-1)
        self.assertFalse(fits_int64(-1))

    def test_6b_negative_is_checked_before_remainder_and_before_overflow(self):
        """An amount that is wrong three ways is reported as the first one."""
        wrong_three_ways = -((INT64_MAX + 1) * RAW_PER_MICRO + 1)
        with self.assertRaises(NegativeAmount):
            raw_to_micro(wrong_three_ways)

    def test_6c_every_refusal_subclasses_AmountError_with_a_code(self):
        for cls, code in ((NotRepresentable, "not_representable"),
                          (Int64Overflow, "int64_overflow"),
                          (NegativeAmount, "negative_amount")):
            self.assertTrue(issubclass(cls, AmountError))
            self.assertEqual(cls.code, code)


class TestOffline(unittest.TestCase):
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

        seen, queue, offences = set(), ["usdc_shape", "server_conformance"], []
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
        self.assertEqual(offences, [])
        self.assertIn("usdc_shape", seen)
        self.assertIn("server_conformance", seen)


class TestCli(unittest.TestCase):
    def test_describe_from_the_command_line(self):
        import contextlib
        import io

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = usdc_shape.main(["describe", str(RAW_PER_MICRO)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(buffer.getvalue())["micro"], 1)

    def test_a_non_integer_argument_is_a_usage_error(self):
        import contextlib
        import io

        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(usdc_shape.main(["describe", "1.5"]), 4)


if __name__ == "__main__":
    unittest.main()
