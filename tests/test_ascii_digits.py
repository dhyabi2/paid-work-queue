"""Amounts are ASCII digits only (FEEDBACK 2026-10-31, board ask 617 parity).

str.isdigit() accepts fullwidth, Arabic-Indic and superscript digits; a port
that reads [0-9] refuses them, so the two disagreed on what an amount is.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(HERE, "..", "vendor"))

import canonical  # noqa: E402
import money  # noqa: E402


class AsciiDigitsOnly(unittest.TestCase):
    def test_non_ascii_digits_are_refused(self):
        for text in ["１", "١", "1.５", "²", "１.0"]:
            with self.assertRaises(ValueError, msg=repr(text)):
                money.xno_to_raw(text)

    def test_ascii_amounts_still_convert(self):
        self.assertEqual(money.xno_to_raw("1"), 10 ** 30)
        self.assertEqual(money.xno_to_raw("1.5"), 15 * 10 ** 29)
        self.assertEqual(money.xno_to_raw(".000001"), 10 ** 24)

    def test_raw_amount_never_raises_on_a_huge_string(self):
        self.assertIsNone(canonical.raw_amount("9" * 5000))
        self.assertEqual(canonical.raw_amount("9" * 40), int("9" * 40))


if __name__ == "__main__":
    unittest.main()
