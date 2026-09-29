#!/usr/bin/env python3
"""The arithmetic that stops a USDC-shaped ledger refusing XNO by accident.

A maintainer reviewed our client, wrote the fixes for us on their own branch,
and then closed the pull request anyway (`minia2auk/minia2a#1`, closed
2026-09-27). Their reason was not our code:

    "The amount column cannot hold the value. The refunder interface states
    its contract in the source: USDC atomic units, 6 decimals, uniform across
    all chains. `refunds.amount_micro` is a SQLite INTEGER read into a Go
    int64. Nano amounts are raw - 10^30 per XNO - and int64 tops out at
    ~9.22e18. The example amount in `@x402nano/exact`
    (1000000000000000000000000) is 1e24 raw, i.e. 0.000001 XNO, and it
    overflows this column."

That is not reluctance and it is not fees. It is a type error in the receiving
system, and it strands refunds silently: the nano row sits at status='failed',
attempts=5, never broadcast, never retried, forever.

This module is the mapping, stated in advance. A ledger column that is an
"integer count of 10^-6 units, int64" cannot hold raw. So say exactly which
XNO amounts that column CAN hold, and refuse the rest loudly instead of
overflowing quietly:

    1 micro = 10**24 raw = 0.000001 XNO          (the quantum)
    int64 max = 9223372036854775807 micro        (~9.223e12 XNO)

`raw_to_micro` therefore REFUSES by default rather than rounding. Silently
truncating a payment amount is the one thing this module exists to prevent,
so the default cannot be the lossy branch - a caller who wants floor or ceil
has to say so in the call, in writing, at the site where the loss happens.

Integers and `Decimal` only; no float ever touches an amount here, because a
float carries ~15-17 significant digits and a raw amount has up to 30. Standard
library only and no network: `tests/test_usdc_shape.py` asserts both by walking
the import graph.

Usage:
    python3 usdc_shape.py describe 1000000000000000000000000
"""

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "vendor"))

from money import raw_to_xno  # noqa: E402  - the one XNO speller, not a second

#: One micro is 10^-6 XNO, which is the unit a "USDC atomic, 6 decimals"
#: column counts. 1 XNO is 10**30 raw, so 10^-6 XNO is 10**24 raw.
RAW_PER_MICRO = 10 ** 24

#: The ceiling the refunder's column actually has. Not a Python limit - Python
#: integers are unbounded - but the limit of the Go int64 on the other side.
INT64_MAX = 2 ** 63 - 1

#: On a ledger with this shape, 0.000001 XNO is the smallest payment that
#: exists, and a job priced below it cannot be settled there at all.
MIN_SETTLEABLE_RAW = RAW_PER_MICRO

#: The three words `on_remainder` accepts. Anything else is a ValueError, not
#: a quiet fallback to the default, because "on_remainder='truncate'" silently
#: meaning "refuse" would be exactly the class of surprise this module is about.
REMAINDER_POLICIES = ("refuse", "floor", "ceil")


class AmountError(Exception):
    """Base class for every refusal in this module. Carries a stable `.code`."""

    code = "amount_error"


class NotRepresentable(AmountError):
    """Raw is not a whole multiple of 10**24, so a micro column would lose it.

    `.remainder_raw` is the part that would be lost, as a decimal string.
    """

    code = "not_representable"

    def __init__(self, message, remainder_raw):
        super().__init__(message)
        self.remainder_raw = str(remainder_raw)


class Int64Overflow(AmountError):
    """The micro value is real but larger than the column can hold.

    `.micro` is the value that did not fit, as an int.
    """

    code = "int64_overflow"

    def __init__(self, message, micro):
        super().__init__(message)
        self.micro = micro


class NegativeAmount(AmountError):
    """A negative amount. There is no such payment."""

    code = "negative_amount"


def _require_int(value, what):
    """Reject a float before it can be rounded into an amount.

    `isinstance(True, int)` is True, so booleans are excluded by name: a
    stray `True` arriving as an amount should be a usage error, not 1 raw.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(
            "%s must be an int, got %s - a float cannot hold a raw amount "
            "exactly and must not be used for money" % (what, type(value).__name__)
        )


def raw_to_micro(raw, *, on_remainder="refuse"):
    """Integer raw -> integer micro (10^-6 XNO), refusing rather than rounding.

    Checks run in the order negative, remainder, overflow, so the message a
    caller gets names the first thing that is wrong with the amount rather
    than the last.
    """
    if on_remainder not in REMAINDER_POLICIES:
        raise ValueError(
            "on_remainder must be one of %s, got %r"
            % (", ".join(repr(p) for p in REMAINDER_POLICIES), on_remainder)
        )
    _require_int(raw, "raw")
    if raw < 0:
        raise NegativeAmount("raw must not be negative, got %d" % raw)

    whole, remainder = divmod(raw, RAW_PER_MICRO)
    if remainder:
        if on_remainder == "refuse":
            raise NotRepresentable(
                "%d raw is %d micro plus %d raw left over, and a 6-decimal "
                "int64 column cannot hold the remainder. The smallest amount "
                "that column can represent is %d raw (0.000001 XNO). Pass "
                "on_remainder='floor' or 'ceil' if losing it is genuinely "
                "what you want." % (raw, whole, remainder, MIN_SETTLEABLE_RAW),
                remainder,
            )
        if on_remainder == "ceil":
            whole += 1

    if whole > INT64_MAX:
        raise Int64Overflow(
            "%d micro exceeds int64 (%d). The column on the other side is a "
            "SQLite INTEGER read into a Go int64; a value above this does not "
            "wrap there, it fails to store." % (whole, INT64_MAX),
            whole,
        )
    return whole


def micro_to_raw(micro):
    """Integer micro -> integer raw. Exact and total for every non-negative micro."""
    _require_int(micro, "micro")
    if micro < 0:
        raise NegativeAmount("micro must not be negative, got %d" % micro)
    return micro * RAW_PER_MICRO


def fits_int64(micro):
    """Whether this micro value can be stored in the refunder's column."""
    _require_int(micro, "micro")
    return 0 <= micro <= INT64_MAX


def describe(raw):
    """A JSON-safe account of what a micro column would do with this amount.

    Every integer is a decimal STRING except `micro`, because a JSON consumer
    in a language with 53-bit numbers (JavaScript, and so most of the
    x402 ecosystem) must not be handed a 10^30 integer as a JSON number - it
    would arrive there already rounded. `micro` stays an int because its whole
    point is that it fits in an int64, and every JSON number up to 2^53 is
    exact.
    """
    _require_int(raw, "raw")
    if raw < 0:
        raise NegativeAmount("raw must not be negative, got %d" % raw)
    whole, remainder = divmod(raw, RAW_PER_MICRO)
    return {
        "raw": str(raw),
        "xno": raw_to_xno(raw),
        "micro": whole,
        "fits_int64": fits_int64(whole),
        "remainder_raw": str(remainder),
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("command", choices=("describe",))
    parser.add_argument("raw", help="an integer amount of raw")
    args = parser.parse_args(argv)
    try:
        amount = int(args.raw)
    except ValueError:
        print("raw must be an integer, got %r" % args.raw, file=sys.stderr)
        return 4
    try:
        result = describe(amount)
    except AmountError as exc:
        print(json.dumps({"error": exc.code, "reason": str(exc)}, indent=2))
        return 3
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
