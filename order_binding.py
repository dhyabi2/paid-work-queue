#!/usr/bin/env python3
"""Bind a payment to an order by a RECORDED ID, not by a unique amount.

WHY THIS FILE EXISTS
--------------------
For five threads this repository's swarm recommended binding a payment to an
order by making the AMOUNT unique - the tagged-raw scheme in
`order_bound_amount.py`. On 2026-10-28 an outside agent, antigravityandrew,
shipped exactly that into a live gateway and told us so:

    "Our Nano adapter tags each invoice with unique sub-cent raw units
    (tagged_raw = base_raw + tag_offset(invoice_id))."

On 2026-10-30T01:36:22Z another outside agent, bosco-roteo, took the advice
apart, unprompted:

    "I would prefer a recorded transaction/block hash bound to an opaque order
    ID, rather than a unique amount as the primary identifier. Unique amounts
    can collide across concurrent orders or time windows, and may leak ordering
    patterns; a hash alone is also insufficient unless the seller records the
    binding and prevents the same payment being credited twice. Record chain,
    expected recipient and amount, confirmation policy, and enforce one-to-one
    assignment in the application ledger. Publish the hash only when
    appropriate for the parties: public linkage can reveal payment
    relationships."

Three distinct defects, all real, all absent from the tagged-amount scheme:

  1. COLLISION. Two concurrent invoices with the same `base_raw` collide
     whenever their tag offsets collide. Nothing refused the second one, so one
     payment credits the wrong order - and with the amount as the primary key
     there is afterwards no way to say which.
  2. DOUBLE CREDIT. A hash with no recorded one-to-one binding can be credited
     twice.
  3. ORDERING LEAK. If the offset is monotone in creation order, the public
     amounts of a seller's invoices reveal its order sequence, and therefore
     its volume, to anyone reading the chain.

THE RULE THIS MODULE ESTABLISHES
--------------------------------
The primary identifier is the recorded `(block_hash, order_id)` binding in the
seller's own ledger. THE AMOUNT IS A CHECK, NEVER AN IDENTIFIER. A tag may
still be used as a HINT to find the candidate order quickly, but a credit is
only ever made against a recorded binding, and never because an amount
matched.

WHAT IS AND IS NOT CLAIMED
--------------------------
This module removes exactly one thing: the seller can no longer credit a block
to whichever order suits it after reading the chain, and can no longer credit
the same block twice. It does NOT establish that the order described real work,
does NOT establish PAYER IDENTITY - any observer of a public send can quote the
hash, and nothing here decides whether the party presenting it is the party
that paid - and does not make a delivery mark honest. Those are separate tools
and separate specs; `SCOPE_NOTE` repeats it rather than papering over it.

No clock, no network, no file, no key. `created_utc` is a parameter and
`secret` is a parameter: this module neither generates, stores nor logs the
seller's secret.
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for _path in (HERE, os.path.join(HERE, "vendor")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import nanoaddr  # noqa: E402  - the vendored codec, for key-level comparison

TOOL = "order_binding"
VERSION = 1

#: The exhaustive refusal vocabulary. A reader who handles these handles every
#: way `credit()` and the ledger/order inputs of `assign()` can say no; neither
#: has a bare `ValueError`/`TypeError` path. (A wrong `tag_raw_width`,
#: `max_attempts` or `publish_binding` argument is a programming error in the
#: caller and still raises `ValueError`.)
REASON_CODES = (
    "TAG_COLLISION",
    "BLOCK_ALREADY_CREDITED",
    "ORDER_ALREADY_SETTLED",
    "ORDER_UNKNOWN",
    "AMOUNT_MISMATCH",
    "RECIPIENT_MISMATCH",
    "NETWORK_MISMATCH",
    "NOT_CONFIRMED",
    "BAD_ORDER_ID",
    "BAD_BLOCK_HASH",
    "NO_SECRET",
    "NOT_A_SEND",
    "SELF_SEND",
    "BAD_LEDGER",
    "BAD_INPUT",
)

ORDER_ID_MAX = 128
#: The longest amount string read, anywhere. A Nano balance is at most
#: 2**128 - 1 raw, which is 39 decimal digits, so no real amount is longer.
#: Past ~4300 digits `int()` itself raises a bare ValueError (CPython's
#: int/str conversion limit), so the cap is checked BEFORE any int() call.
RAW_DIGITS_MAX = 39
SECRET_MIN_BYTES = 16
TAG_WIDTH_MIN = 1024
NETWORK = "nano:mainnet"

# \A..\Z, not ^..$: `$` also matches before a trailing newline, so "1000\n"
# would pass. ASCII digits only, no sign, no underscore, no padding, no zero.
_BASE_RAW_RE = re.compile(r"\A[1-9][0-9]*\Z")
_HASH_RE = re.compile(r"^[0-9A-F]{64}$")

HINT_NOTE = (
    "tagged_raw is a lookup hint. The binding of record is (block_hash, "
    "order_id) in credit()."
)

SCOPE_NOTE = (
    "This binds a payment to an order. It does not establish that the order "
    "described real work, does not establish payer identity - any observer of "
    "a public send can quote the hash - and does not make a delivery mark "
    "honest."
)


class BindingRefusal(Exception):
    """A refused input, with its code. Never a quiet pass and never a guess."""

    def __init__(self, code, detail):
        Exception.__init__(self, detail)
        if code not in REASON_CODES:
            # A typo in a refusal code is how a caller's except-branch stops
            # firing, silently. Refuse to construct one.
            raise AssertionError("unknown refusal code %r" % (code,))
        self.code = code
        self.detail = detail


def _check_order_id(order_id):
    """order_id is compared BYTE-EXACT, so it must arrive verbatim: a non-empty
    str of at most ORDER_ID_MAX characters, ASCII only, with no surrounding
    whitespace. "o1 " is refused rather than quietly stripped, because a
    stripped and an unstripped spelling would otherwise be two orders in the
    book.

    A non-ASCII id is REFUSED, not NFKC-normalised. Normalising would change
    the id the caller passed (fullwidth "\uff2f1" would be credited as "O1"),
    and casefold() is not a safe twin test outside ASCII ("STRASSE" and
    "stra\u00dfe" fold equal; dotted and dotless i do not). Refusal is the
    fail-closed choice: no two spellings of one id can both enter a book."""
    if (not isinstance(order_id, str) or not order_id or len(order_id) > ORDER_ID_MAX
            or not order_id.isascii() or order_id != order_id.strip()):
        raise BindingRefusal(
            "BAD_ORDER_ID",
            "order_id must be a non-empty ASCII str of at most %d characters with no "
            "leading or trailing whitespace; got %r" % (ORDER_ID_MAX, order_id),
        )


def _check_raw_length(value, code, what):
    """Refuse an amount string longer than RAW_DIGITS_MAX before int() sees it."""
    if isinstance(value, str) and len(value.strip()) > RAW_DIGITS_MAX:
        raise BindingRefusal(
            code, "%s is %d characters; an amount in raw is at most %d digits"
            % (what, len(value.strip()), RAW_DIGITS_MAX))


def _check_str_keys(value, code, what):
    """Refuse any dict, at any depth, with a key that is not a str.

    json.dumps() would quietly turn 1, True and None into "1", "true" and
    "null", so {1: a, "1": b} would lose one entry on copy, and a book read
    by key would not be the book written. Containers already seen are skipped,
    so a cycle is left for the JSON copy to refuse."""
    stack, seen = [value], set()
    while stack:
        item = stack.pop()
        if not isinstance(item, (dict, list, tuple)) or id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, dict):
            for key, child in item.items():
                if not isinstance(key, str):
                    raise BindingRefusal(
                        code, "%s holds a %s key %r; every key must be a str"
                        % (what, type(key).__name__, key))
                stack.append(child)
        else:
            stack.extend(item)


def _order_fold(order_id):
    """The key under which two order ids are too alike to both be in one book."""
    return order_id.strip().casefold()


# --------------------------------------------------------------------------
# Interface 1 - tag_offset
# --------------------------------------------------------------------------

def tag_offset(order_id, secret=None, tag_raw_width=None):
    """Return the raw offset that identifies `order_id` inside the tag space.

    HMAC is the point. The output is uniform over the tag space and
    INDEPENDENT OF CREATION ORDER, which closes defect 3. A counter, a
    timestamp, a hash of an incrementing id and `len(open_invoices)` all leak
    the sequence, and the ordering-leak control in the tests fails against
    every one of them.
    """
    _check_order_id(order_id)
    if not isinstance(secret, (bytes, bytearray)) or len(secret) < SECRET_MIN_BYTES:
        raise BindingRefusal(
            "NO_SECRET",
            "secret must be at least %d bytes of the SELLER's own key material; "
            "this module neither generates nor stores it" % SECRET_MIN_BYTES,
        )
    if not isinstance(tag_raw_width, int) or isinstance(tag_raw_width, bool) or tag_raw_width < TAG_WIDTH_MIN:
        raise ValueError(
            "tag_raw_width must be an int >= %d; got %r" % (TAG_WIDTH_MIN, tag_raw_width)
        )
    digest = hmac.new(bytes(secret), order_id.encode("utf-8"), hashlib.blake2b).digest()
    return int.from_bytes(digest, "big") % tag_raw_width


# --------------------------------------------------------------------------
# Interface 2 - assign
# --------------------------------------------------------------------------

def assign(order_id, base_raw, open_invoices, secret=None, tag_raw_width=None,
           max_attempts=64):
    """Derive the amount to quote for `order_id`, refusing on collision.

    `open_invoices` is the seller's currently OPEN (unsettled, unexpired)
    invoices, each at minimum {"order_id": str, "tagged_raw": str}.

    Idempotent: an order that already has an open assignment gets that one
    back, unchanged, so calling this twice never puts two amounts in flight.
    """
    _check_order_id(order_id)
    _check_raw_length(base_raw, "BAD_INPUT", "base_raw")
    if not isinstance(base_raw, str) or not _BASE_RAW_RE.match(base_raw):
        raise BindingRefusal(
            "AMOUNT_MISMATCH",
            "base_raw must be a positive integer in a string, no leading zero; got %r"
            % (base_raw,),
        )
    if open_invoices is None:
        open_invoices = []
    if not isinstance(open_invoices, (list, tuple)):
        raise BindingRefusal("BAD_LEDGER", "open_invoices must be a list of dicts")
    if not isinstance(max_attempts, int) or isinstance(max_attempts, bool) or max_attempts < 1:
        raise ValueError("max_attempts must be an int >= 1; got %r" % (max_attempts,))

    # Read the seller's book once, refusing a malformed entry rather than
    # letting a bare TypeError/AttributeError/ValueError escape. Amounts are
    # compared as INTEGERS: "0" + tagged, padding or an int spelling of an
    # amount in flight is the same amount, and a string compare missed it.
    base = int(base_raw)
    taken = {}
    mine = None
    for invoice in open_invoices:
        if not isinstance(invoice, dict):
            raise BindingRefusal("BAD_LEDGER", "every open invoice must be a dict; got %r"
                                 % (type(invoice).__name__,))
        _check_str_keys(invoice, "BAD_LEDGER", "an open invoice")
        tagged = invoice.get("tagged_raw")
        if tagged is None or tagged == "":
            continue
        amount = _ledger_int(tagged, "open invoice tagged_raw")
        if invoice.get("order_id") == order_id:
            if mine is None:
                mine = (invoice, amount)
        else:
            taken.setdefault(amount, invoice.get("order_id"))

    # Idempotence first: an existing open assignment for this order wins over
    # any re-derivation, because the payer may already have been quoted it.
    # But only for the SAME price: handing back the old amount under a new
    # base_raw would quote one amount and record another. A re-price must
    # expire the open invoice first, so two amounts are never in flight.
    if mine is not None:
        invoice, amount = mine
        recorded_base = invoice.get("base_raw")
        if recorded_base is not None:
            recorded_base = _ledger_int(recorded_base, "open invoice base_raw")
        width_ok = isinstance(tag_raw_width, int) and not isinstance(tag_raw_width, bool)
        in_range = width_ok and base <= amount < base + tag_raw_width
        if (recorded_base is not None and recorded_base != base) or (
                recorded_base is None and not in_range):
            raise BindingRefusal(
                "AMOUNT_MISMATCH",
                "order %r already has an open assignment of %d raw at a different base; "
                "expire it before re-pricing to %s raw" % (order_id, amount, base_raw),
            )
        return {
            "order_id": order_id,
            "base_raw": base_raw,
            "tagged_raw": str(amount),
            "probe": _ledger_int(invoice.get("probe", 0), "open invoice probe"),
            "tag_raw_width": tag_raw_width,
            "note": HINT_NOTE,
        }

    collisions = 0
    probe = 0
    while True:
        preimage = order_id if probe == 0 else "%s:%d" % (order_id, probe)
        amount = base + tag_offset(preimage, secret=secret, tag_raw_width=tag_raw_width)
        tagged_raw = str(amount)
        holder = taken.get(amount)
        if holder is None or holder == order_id:
            return {
                "order_id": order_id,
                "base_raw": base_raw,
                "tagged_raw": tagged_raw,
                "probe": probe,
                "tag_raw_width": tag_raw_width,
                "note": HINT_NOTE,
            }
        # Refuse; never silently reuse an amount that is in flight for another
        # order. That reuse is defect 1, and it is unrecoverable after the fact.
        collisions += 1
        if collisions >= max_attempts:
            raise BindingRefusal(
                "TAG_COLLISION",
                "%d distinct collisions for order_id %r at width %r: re-price the "
                "order by one raw unit rather than sharing an amount in flight"
                % (collisions, order_id, tag_raw_width),
            )
        probe += 1


def _ledger_int(value, what):
    """A non-negative integer from the seller's own book, or BAD_LEDGER."""
    if isinstance(value, bool):
        raise BindingRefusal("BAD_LEDGER", "%s must be an integer; got %r" % (what, value))
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.strip().isdigit() and value.strip().isascii():
        _check_raw_length(value, "BAD_LEDGER", what)
        number = int(value.strip())
    else:
        raise BindingRefusal("BAD_LEDGER", "%s must be an integer; got %r" % (what, value))
    if number < 0:
        raise BindingRefusal("BAD_LEDGER", "%s must not be negative; got %r" % (what, value))
    if number >= 10 ** RAW_DIGITS_MAX:
        raise BindingRefusal(
            "BAD_LEDGER", "%s is more than %d digits; no amount in raw is" % (what, RAW_DIGITS_MAX))
    return number


def _ledger_hash(value, what):
    """A block hash from the seller's own book, normalised, or BAD_LEDGER."""
    if not isinstance(value, str) or not _HASH_RE.match(value.strip().upper()):
        raise BindingRefusal("BAD_LEDGER", "%s must be a 64-hex block hash; got %r" % (what, value))
    return value.strip().upper()


# --------------------------------------------------------------------------
# Interface 3 - credit
# --------------------------------------------------------------------------

def _public_key(address, code, what):
    try:
        return nanoaddr.decode(address)
    except nanoaddr.InvalidAddress as exc:
        raise BindingRefusal(code, "%s is not a usable address: %s" % (what, exc))
    except (TypeError, AttributeError):
        raise BindingRefusal(code, "%s must be a nano_ or xrb_ address string" % what)


def credit(ledger, block_hash=None, order_id=None, block_info=None, expect=None,
           created_utc=None):
    """Record the one-to-one `(block_hash, order_id)` binding, or refuse.

    Returns a NEW ledger. The ledger passed in is never mutated: a seller that
    retries a refused credit must find its book exactly as it left it.

    `block_info` is TRUSTED to be the node's answer for exactly `block_hash`.
    A node's block_info response does not echo the hash it was asked about, so
    this function cannot check that; the caller must fetch block_info for this
    very hash and pass both together.

    `order_id` is compared byte-exact and must be passed verbatim; one with
    surrounding whitespace is BAD_ORDER_ID, and one that differs from a settled
    order only by case or whitespace is refused.

    Every refusal is a BindingRefusal with a code in REASON_CODES.
    """
    if not isinstance(ledger, dict):
        raise BindingRefusal("BAD_LEDGER", "ledger must be a dict")
    if not isinstance(block_info, dict):
        raise BindingRefusal("BAD_INPUT", "block_info must be a dict")
    if not isinstance(expect, dict):
        raise BindingRefusal("BAD_INPUT", "expect must be a dict")
    if not isinstance(created_utc, str) or not created_utc:
        raise BindingRefusal(
            "BAD_INPUT", "created_utc must be a non-empty str; this module holds no clock")
    _check_order_id(order_id)
    _check_str_keys(ledger, "BAD_LEDGER", "ledger")
    _check_str_keys(block_info, "BAD_INPUT", "block_info")
    _check_str_keys(expect, "BAD_INPUT", "expect")

    # 1. the hash, normalised then shape-checked
    if not isinstance(block_hash, str):
        raise BindingRefusal("BAD_BLOCK_HASH", "block_hash must be a string")
    normalised = block_hash.strip().upper()
    if not _HASH_RE.match(normalised):
        raise BindingRefusal(
            "BAD_BLOCK_HASH",
            "block_hash must be 64 hex characters; got %d" % len(block_hash.strip()),
        )

    # `or {}` would let an empty list (or "", 0) through as an empty book and
    # then crash on write; only an absent or None side counts as empty.
    bindings = ledger.get("bindings")
    settled = ledger.get("settled_orders")
    bindings = {} if bindings is None else bindings
    settled = {} if settled is None else settled
    if not isinstance(bindings, dict) or not isinstance(settled, dict):
        raise BindingRefusal(
            "BAD_LEDGER", "ledger['bindings'] and ledger['settled_orders'] must be dicts"
        )

    # Read every recorded block hash NORMALISED. A key written in lowercase by
    # another tool is the same block; an exact-key lookup missed it and let
    # the block be credited a second time. settled_orders is read too, so a
    # book whose bindings side was lost still refuses the block.
    # Both sides are read into one block->order map and one order->block map.
    # An order is bound if EITHER side says so: a book whose settled_orders side
    # lost an entry must not let that order be paid a second time. The two sides
    # must not contradict each other; a book that does is BAD_LEDGER, never a
    # guess at which side is right.
    credited = {}
    bound_orders = {}
    folded_orders = {}

    def _record(block, order, where):
        if not isinstance(order, str) or not order:
            raise BindingRefusal("BAD_LEDGER", "%s must name a non-empty order_id" % where)
        # Two recorded ids that differ only by case or surrounding whitespace
        # ("O1" settled, "o1" bound) are one order spelled twice, or two orders
        # no reader can tell apart. Either way the book is not trustworthy.
        twin = folded_orders.setdefault(_order_fold(order), order)
        if twin != order:
            raise BindingRefusal(
                "BAD_LEDGER", "the ledger records order ids %r and %r, which differ only "
                "by case or whitespace" % (twin, order))
        if credited.get(block, order) != order:
            raise BindingRefusal(
                "BAD_LEDGER", "the ledger binds block %s to both %r and %r"
                % (block, credited[block], order))
        if bound_orders.get(order, block) != block:
            raise BindingRefusal(
                "BAD_LEDGER", "the ledger settles order %r by both %s and %s"
                % (order, bound_orders[order], block))
        credited[block] = order
        bound_orders[order] = block

    for key, entry in bindings.items():
        if not isinstance(entry, dict):
            raise BindingRefusal("BAD_LEDGER", "ledger['bindings'][%r] must be a dict" % (key,))
        _record(_ledger_hash(key, "ledger['bindings'] key"), entry.get("order_id"),
                "ledger['bindings'][%r]" % (key,))
    for settled_order, value in settled.items():
        _record(_ledger_hash(value, "ledger['settled_orders'][%r]" % (settled_order,)),
                settled_order, "ledger['settled_orders'] key")

    # 2. credit is once, full stop - even for the same order_id. A caller that
    #    wants idempotence reads ledger["bindings"] itself; the ledger must not
    #    make that decision quietly on the caller's behalf.
    if normalised in credited:
        raise BindingRefusal(
            "BLOCK_ALREADY_CREDITED",
            "block %s is already bound to order %r" % (normalised, credited[normalised]),
        )

    # 3. one settlement per order
    #    Read from BOTH sides: bindings alone is enough to say the order is paid.
    if order_id in bound_orders:
        raise BindingRefusal(
            "ORDER_ALREADY_SETTLED",
            "order %r is already settled by block %s" % (order_id, bound_orders[order_id]),
        )
    twin = folded_orders.get(_order_fold(order_id))
    if twin is not None:
        raise BindingRefusal(
            "ORDER_ALREADY_SETTLED",
            "order %r differs only by case or whitespace from %r, already settled by "
            "block %s" % (order_id, twin, bound_orders[twin]),
        )

    # 3b. the terms must be THIS order's terms. `expect` is the seller's
    #     recorded pay_to/amount/network for one order and must name it;
    #     otherwise any order's terms could credit a block to any other order.
    if expect.get("order_id") != order_id:
        raise BindingRefusal(
            "ORDER_UNKNOWN",
            "expect names order %r, not %r; the terms checked must be the recorded "
            "terms of the order being credited" % (expect.get("order_id"), order_id),
        )

    # 4. confirmation policy, stated rather than assumed
    confirmed = block_info.get("confirmed")
    if confirmed is not True and confirmed != "true":
        raise BindingRefusal(
            "NOT_CONFIRMED",
            "block_info['confirmed'] is %r; an unconfirmed block is not a payment"
            % (confirmed,),
        )

    # 5. the chain
    if expect.get("network") != NETWORK:
        raise BindingRefusal(
            "NETWORK_MISMATCH",
            "expect['network'] must be %r; got %r" % (NETWORK, expect.get("network")),
        )

    # 6. the recipient, compared as DECODED 32-byte public keys. A string
    #    comparison fails whenever one side spells the key xrb_ and the other
    #    nano_, which is the same account.
    #    A node's block_info (json_block true) carries the recipient only inside
    #    `contents`: contents.link_as_account, and contents.link as 64 hex. A
    #    top-level link_as_account (a flattened record) is still read. Every
    #    spelling present must name the same key; none present is a refusal.
    want_key = _public_key(expect.get("pay_to"), "RECIPIENT_MISMATCH", "expect['pay_to']")
    contents = block_info.get("contents")
    if contents is None:
        contents = {}
    if not isinstance(contents, dict):
        raise BindingRefusal(
            "RECIPIENT_MISMATCH",
            "block_info['contents'] is a %s, not an object; call block_info with "
            "json_block true" % type(contents).__name__,
        )
    got_keys = []
    if block_info.get("link_as_account") is not None:
        got_keys.append(_public_key(block_info.get("link_as_account"), "RECIPIENT_MISMATCH",
                                    "block_info['link_as_account']"))
    if contents.get("link_as_account") is not None:
        got_keys.append(_public_key(contents.get("link_as_account"), "RECIPIENT_MISMATCH",
                                    "block_info['contents']['link_as_account']"))
    if contents.get("link") is not None:
        link = contents.get("link")
        if not isinstance(link, str) or not _HASH_RE.match(link.strip().upper()):
            raise BindingRefusal(
                "RECIPIENT_MISMATCH",
                "block_info['contents']['link'] must be 64 hex characters; got %r" % (link,),
            )
        got_keys.append(bytes.fromhex(link.strip()))
    if not got_keys:
        raise BindingRefusal(
            "RECIPIENT_MISMATCH",
            "block_info names no recipient (no contents.link_as_account, contents.link "
            "or link_as_account)",
        )
    got_key = got_keys[0]
    if any(not hmac.compare_digest(got_key, other) for other in got_keys[1:]):
        raise BindingRefusal(
            "RECIPIENT_MISMATCH",
            "block_info names more than one recipient: %s"
            % ", ".join(sorted({nanoaddr.encode(k) for k in got_keys})),
        )
    if not hmac.compare_digest(want_key, got_key):
        raise BindingRefusal(
            "RECIPIENT_MISMATCH",
            "the block pays %s, the order expects %s"
            % (nanoaddr.encode(got_key), nanoaddr.encode(want_key)),
        )

    # 6b. only a SEND is a payment. On a receive block `link_as_account` is
    #     derived from the source hash, not a recipient, and `amount` is what
    #     the account received; neither says anyone paid the seller.
    if block_info.get("subtype") != "send":
        raise BindingRefusal(
            "NOT_A_SEND",
            "block_info['subtype'] is %r; only a send block pays an order"
            % (block_info.get("subtype"),),
        )

    # 6c. the payee paying itself moves no money from anyone, in either spelling.
    #     Fails CLOSED: a block whose sender cannot be read is refused, since
    #     "no account" cannot be told apart from "the payee itself".
    payer_keys = []
    for value, what in ((block_info.get("block_account"), "block_info['block_account']"),
                        (contents.get("account"), "block_info['contents']['account']")):
        if value is not None:
            payer_keys.append(_public_key(value, "SELF_SEND", what))
    if not payer_keys:
        raise BindingRefusal(
            "SELF_SEND",
            "block_info names no sending account (block_account or contents.account); "
            "a self-send cannot be ruled out",
        )
    if any(not hmac.compare_digest(payer_keys[0], other) for other in payer_keys[1:]):
        raise BindingRefusal(
            "SELF_SEND", "block_info['block_account'] and contents.account disagree"
        )
    payer = nanoaddr.encode(payer_keys[0])
    if hmac.compare_digest(payer_keys[0], want_key):
        raise BindingRefusal(
            "SELF_SEND", "the block is sent by the payee %s to itself" % nanoaddr.encode(want_key)
        )

    # 7. the amount, as integer raw. Never a float: 1 XNO is 10**30 raw.
    #    Both must be ASCII digits in a str, no sign, no padding, no "_", no
    #    leading zero, and not zero: int(str(x)) accepted "+1000", "1_000",
    #    " 1000 ", "-1000" and "0", and a zero-raw "payment" pays nothing.
    raw_paid = block_info.get("amount")
    raw_wanted = expect.get("amount_raw")
    _check_raw_length(raw_paid, "BAD_INPUT", "block_info['amount']")
    _check_raw_length(raw_wanted, "BAD_INPUT", "expect['amount_raw']")
    if not all(isinstance(v, str) and _BASE_RAW_RE.match(v) for v in (raw_paid, raw_wanted)):
        raise BindingRefusal(
            "AMOUNT_MISMATCH",
            "amount and amount_raw must both be positive integer raw in a string, ASCII "
            "digits only, no sign or leading zero; got %r and %r" % (raw_paid, raw_wanted),
        )
    paid = int(raw_paid)
    wanted = int(raw_wanted)
    if paid != wanted:
        raise BindingRefusal(
            "AMOUNT_MISMATCH", "the block moves %d raw, the order expects %d raw" % (paid, wanted)
        )

    binding = {
        "block_hash": normalised,
        "order_id": order_id,
        "amount_raw": str(wanted),
        "pay_to": nanoaddr.encode(want_key),
        "network": NETWORK,
        "from_account": block_info.get("block_account") or payer,
        "credited_utc": created_utc,
        "confirmation_policy": "node reported confirmed",
    }

    # The copy is how the input stays unmutated; a book that is not plain JSON
    # (a set, bytes, a cycle) is BAD_LEDGER here, never a bare TypeError.
    try:
        new_ledger = json.loads(json.dumps(ledger))
    except (TypeError, ValueError, RecursionError) as exc:
        raise BindingRefusal("BAD_LEDGER", "ledger is not plain JSON: %s" % (exc,))
    if new_ledger.get("bindings") is None:
        new_ledger["bindings"] = {}
    if new_ledger.get("settled_orders") is None:
        new_ledger["settled_orders"] = {}
    new_ledger["bindings"][normalised] = {"order_id": order_id, "credited_utc": created_utc}
    new_ledger["settled_orders"][order_id] = normalised

    return {"ledger": new_ledger, "binding": binding}


# --------------------------------------------------------------------------
# Interface 4 - publish_binding
# --------------------------------------------------------------------------

def publish_binding(binding, public=None):
    """Return the binding as it may be published.

    bosco-roteo: "Publish the hash only when appropriate for the parties:
    public linkage can reveal payment relationships."

    The payer's account is the one field a stranger does not need and we have
    no standing to publish. Everything a stranger DOES need to re-read the
    block and check the sale stays: a redaction that also hid the amount would
    make the receipt useless.
    """
    if not isinstance(binding, dict):
        raise ValueError("binding must be a dict")
    if not isinstance(public, bool):
        raise ValueError("public must be passed explicitly as a bool")
    out = dict(binding)
    if public:
        out.pop("from_account", None)
        out["from_account_redacted"] = True
    return out


# --------------------------------------------------------------------------
# CLI - a reader can see the rule hold without writing any code
# --------------------------------------------------------------------------

def _self_test():
    secret = b"seller-secret-at-least-16-bytes"
    width = 10 ** 24
    offsets = [tag_offset("ord-%d" % n, secret=secret, tag_raw_width=width) for n in range(200)]
    rises = sum(1 for a, b in zip(offsets, offsets[1:]) if b > a)
    monotone = all(b >= a for a, b in zip(offsets, offsets[1:]))
    failures = []
    if monotone:
        failures.append({"control": "ordering_leak", "detail": "offsets are non-decreasing"})
    if not 60 <= rises <= 140:
        failures.append({"control": "ordering_leak", "detail": "adjacent rises %d outside [60,140]" % rises})

    key = nanoaddr.encode(hashlib.blake2b(b"order-binding-self-test-payee", digest_size=32).digest())
    block = hashlib.blake2b(b"order-binding-self-test-block", digest_size=32).hexdigest().upper()
    expect = {"order_id": "ord-1", "network": NETWORK, "pay_to": key,
              "amount_raw": "1000000000000000000000000000"}
    info = {"confirmed": True, "subtype": "send", "amount": expect["amount_raw"],
            "link_as_account": key,
            "block_account": nanoaddr.encode(hashlib.blake2b(b"payer", digest_size=32).digest())}
    before = json.dumps({"bindings": {}, "settled_orders": {}}, sort_keys=True)
    ledger = json.loads(before)
    first = credit(ledger, block_hash=block, order_id="ord-1", block_info=info,
                   expect=expect, created_utc="2026-11-03T06:00:00Z")
    if json.dumps(ledger, sort_keys=True) != before:
        failures.append({"control": "immutability", "detail": "credit mutated its input ledger"})
    try:
        credit(first["ledger"], block_hash=block, order_id="ord-1", block_info=info,
               expect=expect, created_utc="2026-11-03T06:00:01Z")
        failures.append({"control": "double_credit", "detail": "a second credit of one block passed"})
    except BindingRefusal as exc:
        if exc.code != "BLOCK_ALREADY_CREDITED":
            failures.append({"control": "double_credit", "detail": exc.code})

    published = publish_binding(first["binding"], public=True)
    if "from_account" in published or published.get("from_account_redacted") is not True:
        failures.append({"control": "publish_redacts_payer", "detail": "from_account survived"})

    ok = not failures
    return {
        "tool": TOOL,
        "version": VERSION,
        "ok": ok,
        "self_test": "pass" if ok else "fail",
        "adjacent_rises_over_200_orders": rises,
        "binding_of_record": "(block_hash, order_id)",
        "the_amount": "a check, never an identifier",
        "scope": SCOPE_NOTE,
        "failures": failures,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true",
                        help="run the module's own controls and print the report")
    args = parser.parse_args(argv)
    if args.self_test:
        report = _self_test()
        print(json.dumps(report, indent=1, sort_keys=True))
        return 0 if report["ok"] else 1
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
