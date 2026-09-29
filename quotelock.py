#!/usr/bin/env python3
"""Price in dollars, settle in XNO, and read the exchange rate exactly once.

A maintainer refused our rail because "a volatile settlement asset would mean
an exchange rate in every quote and refund, which we don't want to take on"
(MikeyPetrillo/Agent402#1464, closed not_planned). A second reviewer found the
same thing as a live defect in our own published package: `offer()` read the
rate and built the challenge, `verify()` read the rate AGAIN and recomputed the
expected amount, so any movement between the two refused a payer who had sent
exactly what they were asked for (tollstile/Tollstile#49).

This module makes that bug unrepresentable rather than fixed:

  * the rate is an argument to `make_quote` and appears nowhere else,
  * the quote carries the amount it produced, digest-sealed together with the
    usd and rate it came from, so a tampered rate cannot survive, and
  * `verify_payment` and `refund_amount` take no rate, no rate function and no
    rate URL - `tests/test_quotelock.py` asserts that by inspecting their
    signatures, which is the reason this file exists.

A refund is the raw that arrived, never a reconversion of the dollar figure, so
there is no rate in a refund either.

This is not a price oracle. It never fetches a rate, recommends one, or says a
rate is right. The seller supplies the number; the only claim made here is that
the number is used once.

Amounts are `Decimal` with a 60-digit context and integer raw; 1 XNO = 10**30
raw, so a binary floating-point value anywhere in this path would silently lose
the bottom 13+ digits of every amount. Standard library only, and no network:
the suite asserts this module imports none of socket, http, urllib, ssl or
requests.
"""

import argparse
import datetime
import json
import os
import re
import secrets
import sys
from decimal import Decimal, ROUND_CEILING, localcontext
from hashlib import blake2b

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "vendor"))

import nanoaddr  # noqa: E402
from canonical import same_account  # noqa: E402  - one comparison, not three

QUOTE_VERSION = 1
RAW_PER_XNO = 10 ** 30

#: The product of a 4dp usd and a 10dp rate has at most 14 decimal places, so
#: scaling by 10**30 always lands on a whole raw. The ceiling below is a
#: guarantee for callers who scale differently, not live behaviour here; see
#: `vectors/quote-lock-v1.json`, which records that every schema-valid case is
#: exact.
AMOUNT_CONTEXT_PRECISION = 60

USD_PLACES = 4
RATE_PLACES = 10

USD_RE = re.compile(r"\A(0|[1-9][0-9]*)\.[0-9]{4}\Z")
RATE_RE = re.compile(r"\A(0|[1-9][0-9]*)\.[0-9]{10}\Z")
RAW_RE = re.compile(r"\A(0|[1-9][0-9]*)\Z")
NONCE_RE = re.compile(r"\A[0-9a-f]{8,64}\Z")
LOCK_RE = re.compile(r"\A[0-9a-f]{64}\Z")
RFC3339_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")

#: The order the lock digests. `amount_raw` is covered together with the `usd`
#: and `rate_xno_per_usd` it was derived from, so a rate cannot be edited to
#: match a forged amount.
LOCKED_FIELDS = ("v", "nonce", "usd", "rate_xno_per_usd", "amount_raw",
                 "pay_to", "issued_at", "expires_at")

QUOTE_FIELDS = LOCKED_FIELDS + ("lock",)

EXIT_OK = 0
EXIT_REFUSED = 3
EXIT_USAGE = 4


# --------------------------------------------------------------------------
# errors - one class per failure, each with a stable machine-readable code
# --------------------------------------------------------------------------

class QuoteError(Exception):
    """Base class. `code` is stable and safe to put in an API response body.

    No subclass ever carries a rate source, a URL, a seed or a private key in
    its message.
    """

    code = "quote_error"

    def __init__(self, message, **extra):
        super().__init__(message)
        self.message = message
        for key, value in extra.items():
            setattr(self, key, value)

    def as_dict(self):
        return {"ok": False, "code": self.code}


class QuoteInvalid(QuoteError):
    """Schema, field format, or a recomputed amount that disagrees."""

    code = "invalid_quote"


class LockMismatch(QuoteInvalid):
    """The digest does not match the fields it is supposed to seal."""

    code = "lock_mismatch"


class BadUsd(QuoteInvalid):
    code = "bad_usd"


class BadRate(QuoteInvalid):
    code = "bad_rate"


class BadAddress(QuoteInvalid):
    """An address failed its checksum.

    `code` is always `invalid_checksum`, whichever way the address was wrong;
    `reason` carries nanoaddr's finer verdict for a human reading the log.
    """

    code = "invalid_checksum"


class QuoteExpired(QuoteError):
    code = "expired"


class WrongPayee(QuoteError):
    code = "wrong_payee"


class Underpaid(QuoteError):
    code = "underpaid"


# --------------------------------------------------------------------------
# normalisation - the one place a loose decimal string becomes a wire value
# --------------------------------------------------------------------------

def _decimal_from(text, error, label):
    """A plain decimal string to Decimal. No exponent, no sign, no NaN."""
    if isinstance(text, Decimal):
        candidate = format(text, "f")
    elif isinstance(text, int) and not isinstance(text, bool):
        candidate = str(text)
    elif isinstance(text, str):
        candidate = text.strip()
    else:
        raise error("%s must be a decimal string, got %s"
                    % (label, type(text).__name__))
    if not re.fullmatch(r"[0-9]+(\.[0-9]+)?", candidate):
        raise error("%s must be a plain decimal string without a sign or an "
                    "exponent, got %r" % (label, text))
    value = Decimal(candidate)
    if value <= 0:
        raise error("%s must be greater than zero, got %r" % (label, text))
    return value


def _quantise(value, places, error, label, original):
    """Render `value` at exactly `places` decimals, refusing a lossy round."""
    quantum = Decimal(1).scaleb(-places)
    with localcontext() as ctx:
        ctx.prec = AMOUNT_CONTEXT_PRECISION
        snapped = value.quantize(quantum)
        if snapped != value:
            raise error("%s needs more than %d decimal places; %r would lose a "
                        "non-zero digit" % (label, places, original))
    return format(snapped, "f")


def normalise_usd(usd):
    """A dollar figure at exactly 4 decimal places, or `BadUsd`."""
    return _quantise(_decimal_from(usd, BadUsd, "usd"), USD_PLACES,
                     BadUsd, "usd", usd)


def normalise_rate(rate_xno_per_usd):
    """XNO per one USD at exactly 10 decimal places, or `BadRate`."""
    return _quantise(_decimal_from(rate_xno_per_usd, BadRate,
                                   "rate_xno_per_usd"),
                     RATE_PLACES, BadRate, "rate_xno_per_usd",
                     rate_xno_per_usd)


# --------------------------------------------------------------------------
# the amount, and the bytes the lock digests
# --------------------------------------------------------------------------

def amount_raw_for(usd, rate_xno_per_usd):
    """`ceil(usd * rate * 10**30)` as an integer of raw.

    Rounding up by at most one raw favours the seller, so a payer is never
    refused for a fraction the quote could not express.
    """
    with localcontext() as ctx:
        ctx.prec = AMOUNT_CONTEXT_PRECISION
        product = Decimal(usd) * Decimal(rate_xno_per_usd) * Decimal(RAW_PER_XNO)
        return int(product.to_integral_value(rounding=ROUND_CEILING))


def canonical_bytes(quote):
    """UTF-8 of the locked fields joined by \\n, with no trailing newline."""
    parts = []
    for field in LOCKED_FIELDS:
        value = quote[field]
        parts.append(str(int(value)) if field == "v" else str(value))
    return "\n".join(parts).encode("utf-8")


def lock_for(quote):
    """`blake2b(canonical_bytes, digest_size=32)` as 64 lowercase hex."""
    return blake2b(canonical_bytes(quote), digest_size=32).hexdigest()


# --------------------------------------------------------------------------
# timestamps
# --------------------------------------------------------------------------

def _require_utc(now, label="now"):
    if not isinstance(now, datetime.datetime):
        raise ValueError("%s must be a datetime, got %s"
                         % (label, type(now).__name__))
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("%s must be timezone-aware; a naive datetime has no "
                         "defined instant" % label)
    return now.astimezone(datetime.timezone.utc)


def _format_instant(moment):
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_instant(text, field):
    if not isinstance(text, str) or not RFC3339_RE.match(text):
        raise QuoteInvalid("%s must be RFC3339 UTC to the second, as "
                           "YYYY-MM-DDTHH:MM:SSZ, got %r" % (field, text))
    try:
        moment = datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise QuoteInvalid("%s is not a real instant: %r" % (field, text)) from None
    return moment.replace(tzinfo=datetime.timezone.utc)


def _require_address(address, field):
    try:
        return nanoaddr.decode(address)
    except nanoaddr.InvalidAddress as exc:
        raise BadAddress("%s is not a payable Nano address: %s"
                         % (field, exc.message), reason=exc.reason) from None


# --------------------------------------------------------------------------
# the interface
# --------------------------------------------------------------------------

def make_quote(*, usd, rate_xno_per_usd, pay_to, ttl_seconds, now, nonce=None):
    """Seal a dollar price, a rate and the raw they imply into one quote.

    This is the only function in the module that reads a rate.
    """
    moment = _require_utc(now)
    usd_text = normalise_usd(usd)
    rate_text = normalise_rate(rate_xno_per_usd)
    _require_address(pay_to, "pay_to")

    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int):
        raise QuoteInvalid("ttl_seconds must be an integer number of seconds, "
                           "got %s" % type(ttl_seconds).__name__)
    if ttl_seconds <= 0:
        raise QuoteInvalid("ttl_seconds must be greater than zero, got %d"
                           % ttl_seconds)

    if nonce is None:
        nonce = secrets.token_hex(8)
    if not isinstance(nonce, str) or not NONCE_RE.match(nonce):
        raise QuoteInvalid("nonce must be 8 to 64 lowercase hex characters")

    quote = {
        "v": QUOTE_VERSION,
        "nonce": nonce,
        "usd": usd_text,
        "rate_xno_per_usd": rate_text,
        "amount_raw": str(amount_raw_for(usd_text, rate_text)),
        "pay_to": pay_to.strip(),
        "issued_at": _format_instant(moment),
        "expires_at": _format_instant(
            moment + datetime.timedelta(seconds=ttl_seconds)),
    }
    quote["lock"] = lock_for(quote)
    return quote


def check_quote(quote):
    """Return `quote` unchanged, or raise the first defect found.

    The lock is checked BEFORE the amount is recomputed, so editing `usd` or
    `rate_xno_per_usd` is reported as the tamper it is rather than as an
    arithmetic disagreement.
    """
    if not isinstance(quote, dict):
        raise QuoteInvalid("a quote must be a JSON object, got %s"
                           % type(quote).__name__)

    missing = [f for f in QUOTE_FIELDS if f not in quote]
    if missing:
        raise QuoteInvalid("quote is missing %s" % ", ".join(sorted(missing)))
    unknown = [k for k in quote if k not in QUOTE_FIELDS]
    if unknown:
        raise QuoteInvalid("quote carries unknown field(s) %s"
                           % ", ".join(sorted(unknown)))

    if quote["v"] != QUOTE_VERSION or isinstance(quote["v"], bool):
        raise QuoteInvalid("unsupported quote version %r; this build speaks v%d"
                           % (quote["v"], QUOTE_VERSION))
    if not isinstance(quote["nonce"], str) or not NONCE_RE.match(quote["nonce"]):
        raise QuoteInvalid("nonce must be 8 to 64 lowercase hex characters")

    if not isinstance(quote["usd"], str) or not USD_RE.match(quote["usd"]):
        raise BadUsd("usd must be a decimal string with exactly %d decimal "
                     "places, got %r" % (USD_PLACES, quote["usd"]))
    if Decimal(quote["usd"]) <= 0:
        raise BadUsd("usd must be greater than zero, got %r" % quote["usd"])

    if (not isinstance(quote["rate_xno_per_usd"], str)
            or not RATE_RE.match(quote["rate_xno_per_usd"])):
        raise BadRate("rate_xno_per_usd must be a decimal string with exactly "
                      "%d decimal places, got %r"
                      % (RATE_PLACES, quote["rate_xno_per_usd"]))
    if Decimal(quote["rate_xno_per_usd"]) <= 0:
        raise BadRate("rate_xno_per_usd must be greater than zero, got %r"
                      % quote["rate_xno_per_usd"])

    if not isinstance(quote["amount_raw"], str) or not RAW_RE.match(quote["amount_raw"]):
        raise QuoteInvalid("amount_raw must be a decimal integer string of raw, "
                           "got %r" % quote["amount_raw"])

    _require_address(quote["pay_to"], "pay_to")

    issued = _parse_instant(quote["issued_at"], "issued_at")
    expires = _parse_instant(quote["expires_at"], "expires_at")
    if expires <= issued:
        raise QuoteInvalid("expires_at must be after issued_at")

    if not isinstance(quote["lock"], str) or not LOCK_RE.match(quote["lock"]):
        raise LockMismatch("lock must be 64 lowercase hex characters")
    if not secrets.compare_digest(quote["lock"], lock_for(quote)):
        raise LockMismatch("lock does not match the fields it seals - a field "
                           "was edited after the quote was issued")

    if int(quote["amount_raw"]) != amount_raw_for(quote["usd"],
                                                  quote["rate_xno_per_usd"]):
        raise QuoteInvalid("amount_raw disagrees with the usd and rate it is "
                           "sealed with")
    if int(quote["amount_raw"]) <= 0:
        raise QuoteInvalid("amount_raw must be greater than zero")
    return quote


def expected_raw(quote):
    """The raw that settles this quote, recomputed and cross-checked."""
    check_quote(quote)
    return int(quote["amount_raw"])


def is_expired(quote, now):
    return _require_utc(now) > _parse_instant(quote["expires_at"], "expires_at")


def _received_raw_as_int(received_raw):
    """An `int` or a decimal integer string. Never a binary fraction."""
    if isinstance(received_raw, bool):
        raise ValueError("received_raw must be an integer of raw, not a bool")
    if isinstance(received_raw, int):
        value = received_raw
    elif isinstance(received_raw, str):
        text = received_raw.strip()
        if not RAW_RE.match(text):
            raise ValueError("received_raw must be a decimal integer string of "
                             "raw, got %r" % received_raw)
        value = int(text)
    else:
        raise ValueError(
            "received_raw must be an int or a decimal integer string; %s cannot "
            "carry 30 significant digits without losing the bottom of the "
            "amount" % type(received_raw).__name__)
    if value < 0:
        raise ValueError("received_raw must not be negative")
    return value


def verify_payment(quote, *, received_raw, received_to, now):
    """Decide whether this payment settles this quote.

    Takes no rate, and must never take one: the rate was read at quote time and
    is already sealed into `quote`. Reading a rate here is the Tollstile defect.
    """
    check_quote(quote)

    moment = _require_utc(now)
    if moment > _parse_instant(quote["expires_at"], "expires_at"):
        raise QuoteExpired("the quote expired at %s" % quote["expires_at"])

    _require_address(received_to, "received_to")
    if not same_account(quote["pay_to"], received_to):
        raise WrongPayee("the payment went to a different account than the "
                         "quote's pay_to")

    received = _received_raw_as_int(received_raw)
    owed = int(quote["amount_raw"])
    if received < owed:
        raise Underpaid("the payment is short of the quoted amount",
                        short_raw=str(owed - received))

    return {
        "ok": True,
        "quote_nonce": quote["nonce"],
        "settled_raw": str(received),
        "usd": quote["usd"],
        "rate_xno_per_usd": quote["rate_xno_per_usd"],
        "overpaid_raw": str(received - owed),
    }


def refund_amount(receipt):
    """The raw that arrived. Never a reconversion of the USD figure."""
    if not isinstance(receipt, dict) or "settled_raw" not in receipt:
        raise QuoteInvalid("a receipt must be an object carrying settled_raw")
    return _received_raw_as_int(receipt["settled_raw"])


# --------------------------------------------------------------------------
# the CLI - `verify` printing exit 0 is the ONLY thing that means paid
# --------------------------------------------------------------------------

class _Usage(Exception):
    """A malformed invocation: exit 4, distinct from a refusal at exit 3."""


class _Parser(argparse.ArgumentParser):
    def error(self, message):  # argparse exits 2 by default; this CLI owes 4
        raise _Usage(message)


def _build_parser():
    parser = _Parser(
        prog="quotelock.py",
        description="Lock an exchange rate into a quote, then settle against "
                    "the quote and never the rate.")
    subs = parser.add_subparsers(dest="command", required=True)

    quote = subs.add_parser("quote", help="issue a locked quote")
    quote.add_argument("--usd", required=True,
                       help="dollar price, normalised to 4 decimal places")
    quote.add_argument("--rate", required=True,
                       help="XNO per one USD, normalised to 10 decimal places")
    quote.add_argument("--pay-to", required=True, dest="pay_to")
    quote.add_argument("--ttl", type=int, default=900, dest="ttl",
                       help="seconds the quote stays payable (default 900)")
    quote.add_argument("--nonce", default=None)

    check = subs.add_parser("check", help="validate a quote and its lock")
    check.add_argument("--quote", required=True, dest="quote_path")

    verify = subs.add_parser("verify", help="decide whether a payment settles")
    verify.add_argument("--quote", required=True, dest="quote_path")
    verify.add_argument("--received-raw", required=True, dest="received_raw")
    verify.add_argument("--received-to", required=True, dest="received_to")

    refund = subs.add_parser("refund", help="the raw to send back")
    refund.add_argument("--receipt", required=True, dest="receipt_path")

    for sub in (quote, check, verify, refund):
        sub.add_argument("--json", action="store_true", dest="as_json")
    return parser


def _load_json(path, label):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise _Usage("cannot read the %s at %s: %s"
                     % (label, path, exc.strerror or exc)) from None
    except ValueError as exc:
        raise _Usage("the %s at %s is not valid JSON: %s"
                     % (label, path, exc)) from None


def main(argv=None, out=None, err=None):
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err

    try:
        args = _build_parser().parse_args(
            sys.argv[1:] if argv is None else list(argv))
    except _Usage as exc:
        err.write("usage error: %s\n" % exc)
        return EXIT_USAGE
    except SystemExit as exc:  # --help and argparse's own exits
        return EXIT_OK if exc.code in (0, None) else EXIT_USAGE

    now = datetime.datetime.now(datetime.timezone.utc)

    try:
        if args.command == "quote":
            payload = make_quote(usd=args.usd, rate_xno_per_usd=args.rate,
                                 pay_to=args.pay_to, ttl_seconds=args.ttl,
                                 now=now, nonce=args.nonce)
        elif args.command == "check":
            payload = check_quote(_load_json(args.quote_path, "quote"))
        elif args.command == "verify":
            payload = verify_payment(
                _load_json(args.quote_path, "quote"),
                received_raw=args.received_raw,
                received_to=args.received_to, now=now)
        else:
            payload = {"ok": True,
                       "refund_raw": str(refund_amount(
                           _load_json(args.receipt_path, "receipt")))}
    except _Usage as exc:
        err.write("usage error: %s\n" % exc)
        return EXIT_USAGE
    except ValueError as exc:
        err.write("usage error: %s\n" % exc)
        return EXIT_USAGE
    except QuoteError as exc:
        if args.as_json:
            out.write(json.dumps(exc.as_dict(), sort_keys=True) + "\n")
        else:
            err.write("refused: %s (%s)\n" % (exc.message, exc.code))
        return EXIT_REFUSED

    if args.as_json:
        out.write(json.dumps(payload, indent=1, sort_keys=True) + "\n")
    elif args.command == "quote":
        for field in QUOTE_FIELDS:
            out.write("%-17s %s\n" % (field, payload[field]))
    elif args.command == "refund":
        out.write("%s\n" % payload["refund_raw"])
    else:
        out.write("ok\n")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
