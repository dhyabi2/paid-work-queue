#!/usr/bin/env python3
"""Compare money and accounts by value, not by the string that spells them.

Named `canonical` rather than `money` because `vendor/money.py` already holds
the XNO/raw conversion, vendored verbatim from another repository - putting
comparisons there would edit a file whose source of truth is elsewhere, and a
root-level `money.py` is shadowed by the vendored one on sys.path.

One comparison, imported by claim.py, validate.py and settle.py, because three
copies of this is how the third one drifts. There is no network import here and
there never may be: `tests/test_settle.py` walks the import graph reachable from
settle.py and fails the build if one appears.

Three identifiers in this repository have more than one valid spelling, and
comparing any of them as text refuses a payment that DID arrive:

  ACCOUNTS  the modern `nano_` form and the legacy `xrb_` form carry the same 60
            characters encoding the same public key. A node always answers the
            `nano_` form; a claimant hands over whichever their tooling holds.
  AMOUNTS   raw is an integer, so "0500" and "500" are one amount.
  HASHES    upper and lower case hex - already handled at the door, because
            validate.BLOCK_HASH_RE admits only [0-9A-F]{64}.

Every one of these fails SAFE, which is why a green suite does not see them:
nothing crashes and nothing is stolen, the tool simply tells a seller they were
not paid after the buyer's money has irreversibly moved.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "vendor"))

import nanoaddr  # noqa: E402


def account_key(address):
    """The public key `address` decodes to, or None if it is not an address.

    Two addresses name one account exactly when their public keys match, which
    is what the chain means by "the same account". None on either side of a
    comparison must refuse, so that a missing or malformed value is rejected
    rather than quietly matching another missing one.
    """
    verdict = nanoaddr.validate(address) if isinstance(address, str) else {"valid": False}
    return verdict["public_key"] if verdict["valid"] else None


def same_account(left, right):
    """Whether two addresses name one account, however each is spelled."""
    key = account_key(left)
    return key is not None and key == account_key(right)


def canonical_account(address):
    """The `nano_` spelling of an address, or the value unchanged if it is not one.

    For the value WRITTEN to a receipt. Comparing by key is enough to settle
    correctly, but a receipt is also counted: validate.compute_stats reports
    `sellers_paid` as the number of distinct `paid_to` values, so one seller who
    gave the legacy spelling on one job and the modern one on another would be
    published as two sellers paid. Writing the canonical form means the rows this
    tool creates cannot disagree with each other about one account.
    """
    key = account_key(address)
    if key is None:
        return address
    return nanoaddr.validate(address)["normalised"]


def canonical_raw(value):
    """The canonical spelling of an amount of raw, or the value unchanged.

    For the value WRITTEN to a receipt, so that validate.py's cross-check between
    a receipt and the job it pays compares two amounts already in one form.
    """
    amount = raw_amount(value)
    return str(amount) if amount is not None else str(value)


def raw_amount(value):
    """`value` as an integer count of raw, or None if it does not spell one.

    The ASCII guard is load-bearing, not decoration: `"²".isdigit()` is
    True while `int("²")` raises, so `isdigit` alone lets a ValueError
    escape from what its caller documents as a comparison that never raises.
    Nothing here raises; a value that is not an integer comes back as None and
    the caller refuses it, exactly as an unequal amount is refused.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text or not text.isascii() or not text.isdigit():
        return None
    return int(text)


def same_amount(left, right):
    """Whether two values spell one amount of raw. None never matches."""
    got = raw_amount(left)
    want = raw_amount(right)
    return got is not None and want is not None and got == want


def checksum_pair(address):
    """(carried, implied) checksums for an address whose body decodes.

    Only for the body of a checksum refusal, so the caller can be shown which
    half is wrong instead of re-typing the whole address. The base32 alphabet
    and `checksum_for` are nanoaddr's public surface; this is not a second
    validator and it never decides anything - `nanoaddr.validate` does.

    It lives here rather than in either caller because `http_claim.py`'s
    `/check-address` and `mint.py check` promise the SAME `expected_checksum`
    for the same address, and a promise kept by two copies of ten lines is the
    promise that breaks first. `tests/test_mint.py` test 18 asserts the two
    agree across twelve addresses; this function is why it can.

    Returns (None, None) when the body cannot be decoded at all, which is a
    different failure from a mismatched checksum and must not be reported as
    one.
    """
    if not isinstance(address, str):
        return None, None
    candidate = address.strip()
    for prefix in nanoaddr.PREFIXES:
        if candidate.startswith(prefix):
            rest = candidate[len(prefix):]
            break
    else:
        return None, None
    if len(rest) != nanoaddr.ACCOUNT_BODY_LEN + nanoaddr.CHECKSUM_LEN:
        return None, None
    body, carried = rest[:nanoaddr.ACCOUNT_BODY_LEN], rest[nanoaddr.ACCOUNT_BODY_LEN:]
    value = 0
    for char in body:
        if char not in nanoaddr.ALPHABET:
            return None, None
        value = (value << 5) | nanoaddr.ALPHABET.index(char)
    public_key = value.to_bytes(33, "big")[1:]
    return carried, nanoaddr.checksum_for(public_key)
