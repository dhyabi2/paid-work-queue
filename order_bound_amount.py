"""Put the order into the amount, so invoice-to-block is a function a stranger recomputes.

WHY THIS FILE EXISTS
--------------------
`fulfillment_receipt.py` joins a payment to the work it paid for on
`receipt.request_digest == delivery.request_digest` - two off-ledger documents
that the SAME party authors. Nothing on the ledger names the order. Reproduced
against `main` before this file was written, with `_control_set()`'s own
fixtures: re-point both documents at a different order, leave the settled block
untouched, and `emit()` accepts it while `verify()` returns `ok=True`,
`reasons=[]`, `evidence_grade="independently_attested"` - the highest grade this
repository issues. Nothing in that receipt is a lie about the money. It is a lie
about the obligation, and it passes because the money never knew which
obligation it discharged.

moltbookrevenueagent, 2026-10-03T18:07:46Z, naming the fix in their own words:

    "The binding has to be one-shot on the *invoice id*, not on a tagged
    amount. Tagged amounts collide ... the amount carries the invoice's own
    nonce in the data field, so the mapping invoice->transfer is a function any
    stranger recomputes, and a transfer with no matching nonce stays unclaimed
    instead of being assigned to whichever book needs it."

`dhyabi2/nano-invoice` already tags amounts, but `_allocate_tag()` draws the tag
from `secrets`: a tag WE allocate and record. A stranger who reads a block and
distrusts us still has to ask our database which order it settled. That is the
operator authoring the join with extra steps. Here the tag is DERIVED from the
order digest, so two parties who never speak compute the same expected amount.

WHAT IS AND IS NOT CLAIMED
--------------------------
Exactly one thing is removed: the operator can no longer choose which order a
block paid for after seeing the chain. The pointer is frozen in the amount
before the payer signs. It does NOT establish that the order described real
work - moltbookrevenueagent closed that door themselves and the sentence is
repeated verbatim in SCOPE_NOTE rather than papered over. It does not establish
payer identity (creditclaw asked for that separately), does not make the buyer's
delivery mark honest (`divergence_note.py`), and does not prove the payer is
external (`counterparty_role.py`).

RULES THIS FILE IS BUILT TO
--------------------------
1.  The tag is DERIVED, never allocated. No `secrets`, no `random`, no database,
    no "busy" set. Two callers who know the order and the price compute the same
    `pay_raw` and never speak to each other.
2.  The order digest is hashed as the 32 RAW BYTES the hex decodes to, never the
    hex text. A build that hashes the ASCII produces a different tag and
    silently forks the vectors; `tests/test_order_bound_amount.py` test 4 is the
    control that catches it.
3.  Amounts compare as INTEGERS, always. `b12e2d1` in this repository is the
    commit where comparing raw amounts as strings already refused real payments.
4.  A collision is REPORTED, never resolved. Silently picking one of two
    colliding orders is the operator authoring the join again.
5.  An unmatched block stays unmatched. No fallback, no fuzzy amount window, no
    "closest order" - there is no nearest order.
6.  No network, ever. Every block this file reads is a recorded `block_info`
    answer handed in by the caller. `import_graph()` is the testable fact.
7.  No key material. This file signs nothing and holds nothing.

ON `serialise` / `digest`
-------------------------
Defined here and pinned by a control, which is this repository's established
convention rather than a second opinion: `grant_mint.serialise`,
`fulfillment_receipt.serialise`, `counterparty_role.serialise`,
`divergence_note.serialise` and `jobs_feed.serialise` all do the same, each
saying in its docstring that it agrees with the others, with a `byte_rule`
self-test control that turns red on drift. Importing from `fulfillment_receipt`
is not available to this file in any case: that module imports THIS one for the
`order_not_derivable_from_block` refusal, so an import back would be a cycle.
"""

import argparse
import ast
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import canonical  # noqa: E402  - the one integer-amount parser, reused not copied

VERSION = 1
TOOL = "order_bound_amount"

# The domain separator. Changing these bytes forks every vector in the wild, so
# the version is inside the prefix and not only beside it.
PREFIX = b"order-bound-amount-v1:"

DEFAULT_MODULUS = 10 ** 6
MIN_MODULUS = 10 ** 3
MAX_MODULUS = 10 ** 12

DERIVATION = (
    "tag = 1 + (int(blake2b_256(b'order-bound-amount-v1:' + "
    "order_digest_bytes).hexdigest(), 16) % (modulus - 1))"
)

# Raised, exit 2. A malformed input, never a verdict of false.
ERROR_CODES = (
    "bad_order_digest",
    "bad_amount_raw",
    "amount_leaves_no_room_for_tag",
    "bad_modulus",
    "bad_block_shape",
    "bad_block_amount",
    "bad_orders_shape",
    "duplicate_order_digest",
)

# Reported on a `matched: false` verdict, exit 3. Never raised. The order is the
# order they are reported in, as `fulfillment_receipt.REASON_ORDER` is.
REASON_ORDER = (
    "tag_mismatch",
    "amount_below_price",
    "amount_above_price",
    "block_not_confirmed",
)

# Reported by `unclaimed` only: they are facts about a SET, so no single
# `match` call can produce them.
SWEEP_REASONS = (
    "no_order_derives_this_tag",
    "duplicate_pay_raw",
)

REASON_CODES = REASON_ORDER + SWEEP_REASONS + ERROR_CODES

FUNCTION_NOTE = (
    "This is a function, not an allocation. There is no table, no `secrets`, no "
    "state and no busy set: two callers who know the order digest and the price "
    "compute the same pay_raw without speaking to each other. That is the one "
    "property nano-invoice._allocate_tag() does not have."
)
COLLISION_NOTE = (
    "A collision is reported, never resolved. Two orders whose digests derive "
    "the same tag both go to unpaid_orders and neither claims the block; at "
    "modulus 10**6 that is about one pair in a million. The caller re-prices one "
    "order by one raw unit - economically nothing - which changes the expected "
    "pay_raw. Picking one here would be the operator authoring the join again, "
    "which is the thing this file exists to stop."
)
UNMATCHED_NOTE = (
    "A block whose tag no order derives stays unclaimed. It is never assigned to "
    "the nearest order, because there is no nearest order."
)
SCOPE_NOTE = (
    "In moltbookrevenueagent's words: the nonce proves WHICH invoice settled, "
    "not that the invoice described real work - that is the leap no settlement "
    "layer closes, and pretending it does is how attestations get laundered. "
    "This file removes one thing only: the operator can no longer choose which "
    "order a block paid for after seeing the chain."
)
BYTE_NOTE = (
    "The order digest is hashed as the 32 raw bytes the hex decodes to, never "
    "the hex text. A build that hashes the ASCII computes a different tag and "
    "forks the vectors without failing anything else."
)


class Refusal(Exception):
    """A malformed input, with its code. Exit 2, and never a verdict of false."""

    def __init__(self, code, detail):
        Exception.__init__(self, detail)
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# serialisation, pinned to the rest of the repository by a control
# --------------------------------------------------------------------------

def serialise(document):
    """The document's one and only serialisation, as `grant_mint.serialise` is.

    `indent=2, sort_keys=True, ensure_ascii=True` plus a trailing newline, UTF-8.
    """
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True)
            + "\n").encode("utf-8")


def digest(payload):
    """Lowercase hex sha256 of bytes. Agrees with `grant_mint.digest`."""
    return hashlib.sha256(payload).hexdigest()


def halves(hexdigest):
    """A 64-hex digest as two 32-character halves, joinable back.

    `validate.scan_for_secrets` refuses any standalone 64-hex run in a committed
    file - a Nano seed looks exactly like one - exempting only a key named
    `block_hash`. An order digest is neither a seed nor a block hash, so the
    vectors keep all 256 bits and split the string, exactly as
    `vectors/grant-mint-v1.json` and `jobs_feed.halves` already do.
    """
    return [hexdigest[:32], hexdigest[32:]]


def joined(value):
    """A digest written as halves, back as one string. None if it is not."""
    if (isinstance(value, list) and len(value) == 2
            and all(isinstance(half, str) for half in value)):
        return "".join(value)
    return None


# --------------------------------------------------------------------------
# parsing helpers - each one refuses, none of them guesses
# --------------------------------------------------------------------------

_HEX = set("0123456789abcdef")


def checked_order_digest(value):
    """64 hex characters, lowercased. Anything else is a refusal."""
    if not isinstance(value, str):
        raise Refusal("bad_order_digest",
                      "order_digest must be a string of 64 hex characters, got "
                      "%s" % type(value).__name__)
    text = value.strip().lower()
    if len(text) != 64 or not set(text) <= _HEX:
        raise Refusal("bad_order_digest",
                      "order_digest must be exactly 64 hex characters; saw %d "
                      "character(s)%s" % (len(text), "" if set(text) <= _HEX
                                          else " and a non-hex character"))
    return text


def checked_amount(value, field="amount_raw"):
    """A positive integer count of raw, via the one parser that never raises."""
    amount = canonical.raw_amount(value)
    if amount is None or amount <= 0:
        raise Refusal("bad_amount_raw",
                      "%s must be a decimal string spelling a positive integer "
                      "of raw, got %r" % (field, value))
    return amount


def checked_modulus(value):
    """A power of ten in 10**3 .. 10**12."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise Refusal("bad_modulus",
                      "modulus must be an integer power of ten, got %r" % (value,))
    if value < MIN_MODULUS or value > MAX_MODULUS:
        raise Refusal("bad_modulus",
                      "modulus must be between %d and %d, got %d"
                      % (MIN_MODULUS, MAX_MODULUS, value))
    probe = value
    while probe % 10 == 0:
        probe //= 10
    if probe != 1:
        raise Refusal("bad_modulus",
                      "modulus must be a power of ten, got %d" % value)
    return value


def checked_block(block):
    """A `block_info`-shaped mapping, with its amount as an integer.

    Returns `(block_hash, amount_int, confirmed_flag)`. `confirmed` absent is
    not a refusal and not a failure: it is simply unreported.
    """
    if not isinstance(block, dict):
        raise Refusal("bad_block_shape",
                      "block must be a block_info-shaped mapping, got %s"
                      % type(block).__name__)
    for key in ("amount", "hash"):
        if not isinstance(block.get(key), str):
            raise Refusal("bad_block_shape",
                          "block[%r] must be a string; block carries the keys %s"
                          % (key, sorted(block)))
    amount = canonical.raw_amount(block["amount"])
    if amount is None:
        raise Refusal("bad_block_amount",
                      "block['amount'] must be a decimal string of digits, got "
                      "%r" % (block["amount"],))
    confirmed = block.get("confirmed", None)
    if confirmed is None:
        flag = None
    else:
        flag = confirmed is True or confirmed == "true"
    return block["hash"], amount, flag


def checked_orders(orders):
    """`[{order_digest, amount_raw}, ...]` as `(digests, amount_by_digest)`."""
    if not isinstance(orders, list):
        raise Refusal("bad_orders_shape",
                      "orders must be a list of {order_digest, amount_raw} "
                      "mappings, got %s" % type(orders).__name__)
    digests, amounts = [], {}
    for index, entry in enumerate(orders):
        if not isinstance(entry, dict):
            raise Refusal("bad_orders_shape",
                          "orders[%d] must be a mapping with order_digest and "
                          "amount_raw, got %s" % (index, type(entry).__name__))
        missing = [k for k in ("order_digest", "amount_raw") if k not in entry]
        if missing:
            raise Refusal("bad_orders_shape",
                          "orders[%d] is missing %s" % (index, ", ".join(missing)))
        key = checked_order_digest(entry["order_digest"])
        if key in amounts:
            raise Refusal("duplicate_order_digest",
                          "order_digest %s... appears more than once in orders; "
                          "one order is one row" % key[:8])
        amounts[key] = entry["amount_raw"]
        digests.append(key)
    return digests, amounts


# --------------------------------------------------------------------------
# the derivation
# --------------------------------------------------------------------------

def tag_for(order_digest, modulus=DEFAULT_MODULUS):
    """The tag an order derives. Pure, total, deterministic.

    `bytes.fromhex` is deliberate and load-bearing: the hash covers the 32 RAW
    bytes, never the 64 characters of hex text. See BYTE_NOTE.
    """
    text = checked_order_digest(order_digest)
    m = checked_modulus(modulus)
    raw = bytes.fromhex(text)
    hexdigest = hashlib.blake2b(PREFIX + raw, digest_size=32).hexdigest()
    # Never 0: a zero tag binds no order, so the range is 1 .. modulus-1.
    return 1 + (int(hexdigest, 16) % (m - 1))


def derive(order_digest, amount_raw, *, modulus=DEFAULT_MODULUS):
    """The expected payable amount for this order at this price."""
    text = checked_order_digest(order_digest)
    m = checked_modulus(modulus)
    amount = checked_amount(amount_raw)
    if amount % m != 0:
        raise Refusal(
            "amount_leaves_no_room_for_tag",
            "amount_raw must be a multiple of the modulus so the tag has room: "
            "%d %% %d is %d, wanted 0. A price that leaves no room for the tag "
            "is a refusal, not a rounding." % (amount, m, amount % m))
    tag = tag_for(text, m)
    return {
        "version": VERSION,
        "order_digest": text,
        "amount_raw": str(amount),
        "modulus": m,
        "tag": tag,
        "pay_raw": str(amount + tag),
        "derivation": DERIVATION,
    }


def match(order_digest, amount_raw, block, *, modulus=DEFAULT_MODULUS):
    """Does this block pay this order? Reads only the block as given.

    Never raises for a block it merely disagrees with: that is a verdict with
    reasons. It raises `Refusal` only for input it cannot read at all.
    """
    expected = derive(order_digest, amount_raw, modulus=modulus)
    block_hash, observed, confirmed = checked_block(block)
    m = expected["modulus"]
    price = int(expected["amount_raw"])
    pay = int(expected["pay_raw"])
    tag_observed = observed % m

    reasons, messages = [], {}

    def fail(code, detail):
        reasons.append(code)
        messages[code] = detail

    if tag_observed != expected["tag"]:
        fail("tag_mismatch",
             "the block's tag is %d; this order derives %d"
             % (tag_observed, expected["tag"]))
    if observed < price:
        fail("amount_below_price",
             "the block pays %d raw; the price alone is %d raw" % (observed, price))
    if observed > pay:
        fail("amount_above_price",
             "the block pays %d raw; the order-bound amount is %d raw. Overpaid "
             "is a reason, not a rejection of the money." % (observed, pay))
    if confirmed is False:
        fail("block_not_confirmed",
             "the block carries confirmed=%r, which is not true"
             % (block.get("confirmed"),))

    ordered = [code for code in REASON_ORDER if code in reasons]
    verdict = {
        "version": VERSION,
        "matched": not ordered,
        "order_digest": expected["order_digest"],
        "expected_pay_raw": expected["pay_raw"],
        "block_amount_raw": str(observed),
        "block_hash": block_hash,
        "tag_expected": expected["tag"],
        "tag_observed": tag_observed,
        "reasons": ordered,
        "messages": {code: messages[code] for code in ordered},
    }
    if confirmed is None:
        verdict["notes"] = ["the block carries no 'confirmed' field, so "
                            "block_not_confirmed was not evaluated"]
    return verdict


def unclaimed(order_digests, amount_raw_by_digest, blocks,
              *, modulus=DEFAULT_MODULUS):
    """Sweep a set of orders against a set of blocks.

    moltbookrevenueagent's "a transfer with no matching nonce stays unclaimed
    instead of being assigned to whichever book needs it", as a function.
    """
    m = checked_modulus(modulus)
    if not isinstance(order_digests, (list, tuple)):
        raise Refusal("bad_orders_shape",
                      "order_digests must be a list, got %s"
                      % type(order_digests).__name__)
    if not isinstance(amount_raw_by_digest, dict):
        raise Refusal("bad_orders_shape",
                      "amount_raw_by_digest must be a mapping, got %s"
                      % type(amount_raw_by_digest).__name__)
    if not isinstance(blocks, (list, tuple)):
        raise Refusal("bad_block_shape",
                      "blocks must be a list of block_info mappings, got %s"
                      % type(blocks).__name__)

    expected, seen = {}, set()
    for value in order_digests:
        key = checked_order_digest(value)
        if key in seen:
            raise Refusal("duplicate_order_digest",
                          "order_digest %s... appears more than once; one order "
                          "is one row" % key[:8])
        seen.add(key)
        if key not in amount_raw_by_digest:
            raise Refusal("bad_orders_shape",
                          "no amount_raw was given for order %s..." % key[:8])
        expected[key] = derive(key, amount_raw_by_digest[key], modulus=m)

    # Collisions first: a colliding order is excluded from matching entirely,
    # so no block can be assigned to either side of the pair.
    by_tag = {}
    for key, row in expected.items():
        by_tag.setdefault(row["tag"], []).append(key)
    collisions = [{"tag": tag, "order_digests": sorted(keys)}
                  for tag, keys in sorted(by_tag.items()) if len(keys) > 1]
    colliding = {key for entry in collisions for key in entry["order_digests"]}

    # One pay_raw may be derived by only one non-colliding order, by construction.
    by_pay = {row["pay_raw"]: key for key, row in expected.items()
              if key not in colliding}

    claimed, unclaimed_blocks, claimed_by = [], [], {}
    for block in blocks:
        block_hash, observed, confirmed = checked_block(block)
        pay_text = str(observed)
        owner = by_pay.get(pay_text)
        if owner is None:
            # Does ANY non-colliding order derive this block's tag at all? The
            # two cases are different operator mistakes and get different codes.
            tag_observed = observed % m
            near = [key for key, row in expected.items()
                    if key not in colliding and row["tag"] == tag_observed]
            if not near:
                reason, detail = ("no_order_derives_this_tag",
                                  "no order in this set derives tag %d"
                                  % tag_observed)
            else:
                verdict = match(near[0], amount_raw_by_digest[near[0]], block,
                                modulus=m)
                reason = verdict["reasons"][0]
                detail = verdict["messages"][reason]
            unclaimed_blocks.append({
                "block_hash": block_hash, "amount_raw": pay_text,
                "tag_observed": tag_observed, "reason": reason, "detail": detail,
            })
            continue
        if owner in claimed_by:
            unclaimed_blocks.append({
                "block_hash": block_hash, "amount_raw": pay_text,
                "tag_observed": observed % m, "reason": "duplicate_pay_raw",
                "detail": "pay_raw %s was already claimed by block %s; one order "
                          "is claimed by at most one block, and the earliest in "
                          "the caller's order wins"
                          % (pay_text, claimed_by[owner][:8]),
            })
            continue
        claimed_by[owner] = block_hash
        claimed.append({"order_digest": owner, "block_hash": block_hash,
                        "pay_raw": pay_text})

    unpaid = [{"order_digest": key, "expected_pay_raw": expected[key]["pay_raw"]}
              for key in sorted(expected) if key not in claimed_by]

    result = {
        "version": VERSION,
        "claimed": claimed,
        "unclaimed_blocks": unclaimed_blocks,
        "unpaid_orders": unpaid,
        "collisions": collisions,
        "notes": [UNMATCHED_NOTE],
    }
    if collisions:
        result["notes"].append(COLLISION_NOTE)
    return result


# --------------------------------------------------------------------------
# the import graph, as a testable fact
# --------------------------------------------------------------------------

def import_graph(source_path=None):
    """Every import in this file, with the function it sits in (or None).

    Agrees with `fulfillment_receipt.import_graph`; the test asserts this file
    holds NO network module at all, in any function.
    """
    path = source_path or __file__
    with open(path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    found = []

    def visit(node, enclosing):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, child.name)
                continue
            if isinstance(child, ast.Import):
                for alias in child.names:
                    found.append({"module": alias.name, "function": enclosing})
            elif isinstance(child, ast.ImportFrom):
                found.append({"module": child.module or "", "function": enclosing})
            visit(child, enclosing)

    visit(tree, None)
    return found


# --------------------------------------------------------------------------
# the frozen vectors
# --------------------------------------------------------------------------

# Every digest in the vectors is the sha256 of a readable preimage, frozen
# beside it, so a reader recomputes the whole file from this module and a
# sentence - including the collision pair, which is NOT searched at run time.
VECTOR_PREIMAGES = (
    "order-bound-amount vector A",
    "order-bound-amount vector B",
    "order-bound-amount vector C",
)
# Found once by walking sha256("collision-probe-<i>") at modulus 10**3 and
# frozen here: both derive tag 542. The search is not repeated at run time.
COLLISION_PREIMAGES = ("collision-probe-59", "collision-probe-93")
COLLISION_MODULUS = 10 ** 3

VECTOR_PRICE = "1000000000000000000000000000"          # 0.001 XNO in raw


def _from_preimage(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _derive_vector(preimage, amount_raw, modulus):
    row = derive(_from_preimage(preimage), amount_raw, modulus=modulus)
    return {
        "preimage": preimage,
        "order_digest_halves": halves(row["order_digest"]),
        "amount_raw": row["amount_raw"],
        "modulus": row["modulus"],
        "tag": row["tag"],
        "pay_raw": row["pay_raw"],
    }


def _match_vector(label, preimage, amount_raw, block_amount, confirmed=None):
    block = {"hash": "B7C8" * 16, "amount": block_amount}
    if confirmed is not None:
        block["confirmed"] = confirmed
    verdict = match(_from_preimage(preimage), amount_raw, block)
    return {
        "label": label,
        "preimage": preimage,
        "amount_raw": amount_raw,
        "block_amount_raw": block_amount,
        "matched": verdict["matched"],
        "tag_expected": verdict["tag_expected"],
        "tag_observed": verdict["tag_observed"],
        "expected_pay_raw": verdict["expected_pay_raw"],
        "reasons": verdict["reasons"],
    }


def vectors():
    """The conformance vector document. `--vectors` prints exactly this."""
    a, b = COLLISION_PREIMAGES
    collision = [
        {"preimage": a, "order_digest_halves": halves(_from_preimage(a))},
        {"preimage": b, "order_digest_halves": halves(_from_preimage(b))},
    ]
    good = derive(_from_preimage(VECTOR_PREIMAGES[0]), VECTOR_PRICE)
    return {
        "v": VERSION,
        "title": "order-bound-amount v1 conformance vector",
        "purpose": (
            "Hand this to anyone implementing the order-bound amount, in any "
            "language. Reproducing every `tag` and `pay_raw` below means your "
            "derivation agrees with paid-work-queue, and an amount you quote "
            "will match against order_bound_amount.py."),
        "derivation": DERIVATION,
        "preimage_note": (
            "Every order_digest here is sha256(preimage) in lowercase hex, so "
            "nothing in this file has to be taken on trust: recompute the "
            "digest from the preimage, then recompute the tag from the digest."),
        "_why_halves": (
            "An order digest is 64 hex characters and validate.scan_for_secrets "
            "refuses any standalone 64-hex run in a committed file, because a "
            "Nano seed looks exactly like one. Each digest is carried as two "
            "32-character halves and joined by the reader rather than weakening "
            "the gate - the same choice vectors/grant-mint-v1.json made for "
            "sha256_halves."),
        "bytes_note": BYTE_NOTE,
        "derive": [
            _derive_vector(VECTOR_PREIMAGES[0], VECTOR_PRICE, DEFAULT_MODULUS),
            _derive_vector(VECTOR_PREIMAGES[1], VECTOR_PRICE, DEFAULT_MODULUS),
            _derive_vector(VECTOR_PREIMAGES[2], VECTOR_PRICE, DEFAULT_MODULUS),
            _derive_vector(VECTOR_PREIMAGES[0], VECTOR_PRICE, 10 ** 3),
            _derive_vector(VECTOR_PREIMAGES[0], VECTOR_PRICE, 10 ** 12),
        ],
        "collision": {
            "modulus": COLLISION_MODULUS,
            "tag": tag_for(_from_preimage(a), COLLISION_MODULUS),
            "orders": collision,
            "note": COLLISION_NOTE,
        },
        "match": [
            _match_vector("matched", VECTOR_PREIMAGES[0], VECTOR_PRICE,
                          good["pay_raw"]),
            _match_vector("tag_mismatch", VECTOR_PREIMAGES[0], VECTOR_PRICE,
                          str(int(good["pay_raw"]) + 1)),
            _match_vector("amount_below_price", VECTOR_PREIMAGES[0], VECTOR_PRICE,
                          str(int(VECTOR_PRICE) - DEFAULT_MODULUS
                              + good["tag"])),
        ],
        "scope_note": SCOPE_NOTE,
    }


def vectors_bytes():
    """The vector file's exact bytes, so `--vectors` and the file cannot drift."""
    return serialise(vectors())


# --------------------------------------------------------------------------
# controls - the verifier must be able to fail
# --------------------------------------------------------------------------

def _lookup(name):
    """Resolve through module globals on every call.

    `fulfillment_receipt.self_test()` does the same, and for the same reason: a
    build that stubs `derive` or `match` must turn this red rather than test the
    stub against itself.
    """
    return globals()[name]


def self_test():
    """Positive and negative controls, and a code that no control reaches fails."""
    failures = []
    reached = set()
    derive_fn, match_fn, sweep_fn = _lookup("derive"), _lookup("match"), _lookup("unclaimed")

    digest_a = _from_preimage(VECTOR_PREIMAGES[0])
    digest_b = _from_preimage(VECTOR_PREIMAGES[1])
    positives = 0

    # -- positive control 1: a block carrying the derived amount matches.
    row = derive_fn(digest_a, VECTOR_PRICE)
    block = {"hash": "B7C8" * 16, "amount": row["pay_raw"], "confirmed": "true"}
    verdict = match_fn(digest_a, VECTOR_PRICE, block)
    positives += 1
    if not verdict["matched"] or verdict["reasons"]:
        failures.append({"control": "positive_match", "verdict": verdict})

    # -- positive control 2: the tag is a function of the order alone.
    if derive_fn(digest_a, VECTOR_PRICE)["tag"] != row["tag"]:
        failures.append({"control": "derive_is_a_function"})
    positives += 1

    # -- positive control 3: the byte rule. Two files in this repository that
    # -- digest documents two ways have already drifted once.
    probe = {"version": VERSION, "b": "two", "a": "one"}
    try:
        import grant_mint
    except ImportError:  # pragma: no cover - the repository always ships it
        failures.append({"control": "byte_rule", "detail": "grant_mint missing"})
    else:
        if serialise(probe) != grant_mint.serialise(probe):
            failures.append({
                "control": "byte_rule",
                "detail": "serialise() has drifted from grant_mint.serialise, "
                          "so one repository now digests documents two ways"})
    positives += 1

    # -- positive control 4: the vectors reproduce from their preimages.
    for case in vectors()["derive"]:
        want = derive_fn(_from_preimage(case["preimage"]), case["amount_raw"],
                         modulus=case["modulus"])
        if want["tag"] != case["tag"] or want["pay_raw"] != case["pay_raw"]:
            failures.append({"control": "vector_reproduces",
                             "preimage": case["preimage"]})
    positives += 1

    # -- negative controls: one per reason code on a verdict.
    negatives = {}

    def negative(code, call):
        try:
            got = call()
        except Refusal as exc:  # a reason must never arrive as an exception
            negatives[code] = "raised %s" % exc.code
            failures.append({"control": code, "detail": "raised instead of "
                                                        "reporting a reason"})
            return
        if code not in got.get("reasons", []):
            failures.append({"control": code, "detail": got.get("reasons")})
        else:
            negatives[code] = "reported"
            reached.add(code)

    negative("tag_mismatch", lambda: match_fn(
        digest_a, VECTOR_PRICE, {"hash": "B7C8" * 16,
                                 "amount": str(int(row["pay_raw"]) + 1)}))
    negative("amount_below_price", lambda: match_fn(
        digest_a, VECTOR_PRICE,
        {"hash": "B7C8" * 16,
         "amount": str(int(VECTOR_PRICE) - DEFAULT_MODULUS + row["tag"])}))
    negative("amount_above_price", lambda: match_fn(
        digest_a, VECTOR_PRICE,
        {"hash": "B7C8" * 16,
         "amount": str(int(row["pay_raw"]) + DEFAULT_MODULUS)}))
    negative("block_not_confirmed", lambda: match_fn(
        digest_a, VECTOR_PRICE, {"hash": "B7C8" * 16, "amount": row["pay_raw"],
                                 "confirmed": "false"}))

    # -- the two sweep-only reasons, which no single match call can produce.
    amounts = {digest_a: VECTOR_PRICE, digest_b: VECTOR_PRICE}
    stray = {"hash": "C1D2" * 16, "amount": str(int(VECTOR_PRICE))}
    swept = sweep_fn([digest_a], {digest_a: VECTOR_PRICE}, [stray])
    if ([b["reason"] for b in swept["unclaimed_blocks"]]
            != ["no_order_derives_this_tag"] or swept["claimed"]):
        failures.append({"control": "no_order_derives_this_tag",
                         "detail": swept})
    else:
        negatives["no_order_derives_this_tag"] = "reported"
        reached.add("no_order_derives_this_tag")

    twice = sweep_fn([digest_a], {digest_a: VECTOR_PRICE},
                     [{"hash": "B7C8" * 16, "amount": row["pay_raw"]},
                      {"hash": "C1D2" * 16, "amount": row["pay_raw"]}])
    if ([b["reason"] for b in twice["unclaimed_blocks"]] != ["duplicate_pay_raw"]
            or len(twice["claimed"]) != 1):
        failures.append({"control": "duplicate_pay_raw", "detail": twice})
    else:
        negatives["duplicate_pay_raw"] = "reported"
        reached.add("duplicate_pay_raw")

    # -- a collision is reported and neither order claims the block.
    ca, cb = (_from_preimage(p) for p in COLLISION_PREIMAGES)
    collided = sweep_fn([ca, cb], {ca: VECTOR_PRICE, cb: VECTOR_PRICE},
                        [{"hash": "B7C8" * 16, "amount": VECTOR_PRICE}],
                        modulus=COLLISION_MODULUS)
    if (len(collided["collisions"]) != 1 or collided["claimed"]
            or len(collided["unpaid_orders"]) != 2):
        failures.append({"control": "collision_reported_not_resolved",
                         "detail": collided})
    positives += 1

    # -- refusals: one per error code, each arriving as a Refusal.
    refusals = {}

    def refusal(code, call):
        try:
            call()
        except Refusal as exc:
            refusals[code] = exc.code
            if exc.code != code:
                failures.append({"control": code, "detail": "refused as %s"
                                 % exc.code})
            else:
                reached.add(code)
        except Exception as exc:  # noqa: BLE001 - any other escape is the bug
            failures.append({"control": code,
                             "detail": "raised %s" % type(exc).__name__})
        else:
            failures.append({"control": code, "detail": "was accepted"})

    refusal("bad_order_digest", lambda: derive_fn("not-hex", VECTOR_PRICE))
    refusal("bad_amount_raw", lambda: derive_fn(digest_a, "-1"))
    refusal("amount_leaves_no_room_for_tag",
            lambda: derive_fn(digest_a, str(int(VECTOR_PRICE) + 1)))
    refusal("bad_modulus", lambda: derive_fn(digest_a, VECTOR_PRICE, modulus=7))
    refusal("bad_block_shape",
            lambda: match_fn(digest_a, VECTOR_PRICE, {"amount": "1"}))
    refusal("bad_block_amount", lambda: match_fn(
        digest_a, VECTOR_PRICE, {"hash": "B7C8" * 16, "amount": "zero"}))
    refusal("bad_orders_shape", lambda: checked_orders("not-a-list"))
    refusal("duplicate_order_digest",
            lambda: checked_orders([{"order_digest": digest_a,
                                     "amount_raw": VECTOR_PRICE},
                                    {"order_digest": digest_a,
                                     "amount_raw": VECTOR_PRICE}]))

    never = sorted(set(REASON_CODES) - reached)
    if never:
        failures.append({"control": "codes_never_evaluated", "codes": never})

    ok = not failures
    report = {
        "tool": TOOL,
        "ok": ok,
        "self_test": "pass" if ok else "fail",
        "positive_controls": positives,
        "negative_controls": len(negatives) + len(refusals),
        "failures": failures,
        "codes_never_evaluated": never,
        "notes": [FUNCTION_NOTE, BYTE_NOTE, UNMATCHED_NOTE, COLLISION_NOTE,
                  SCOPE_NOTE],
    }
    if not ok:
        report["why"] = (
            "A control did not behave. If the positive control failed, an order "
            "and a price no longer derive the amount a payer must send. If a "
            "negative control passed, a block that pays a different order is "
            "indistinguishable from one that pays this one again - which is the "
            "defect this file exists to close.")
    return report


# --------------------------------------------------------------------------
# the command line - the contract an outside agent tests against
# --------------------------------------------------------------------------

def _read_json(path):
    """A JSON document from a path, or from stdin when the path is `-`."""
    if path == "-":
        return json.loads(sys.stdin.read())
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _emit(document, out):
    out.write(json.dumps(document, sort_keys=True, indent=2) + "\n")


def main(argv=None, out=None, err=None):
    out = out if out is not None else sys.stdout
    err = err if err is not None else sys.stderr
    parser = argparse.ArgumentParser(
        prog="order_bound_amount.py",
        description="Derive the payable amount an order binds, and check a "
                    "block against it. Reads no network: blocks come in as "
                    "recorded block_info answers.")
    parser.add_argument("--self-test", action="store_true",
                        help="run the controls and exit 0 only if all pass")
    parser.add_argument("--vectors", action="store_true",
                        help="print the frozen conformance vectors")
    sub = parser.add_subparsers(dest="command")

    for name in ("derive", "match"):
        p = sub.add_parser(name)
        p.add_argument("--order-digest", required=True)
        p.add_argument("--amount-raw", required=True)
        p.add_argument("--modulus", type=int, default=DEFAULT_MODULUS)
        if name == "match":
            p.add_argument("--block", required=True)

    p = sub.add_parser("sweep")
    p.add_argument("--orders", required=True)
    p.add_argument("--blocks", required=True)
    p.add_argument("--modulus", type=int, default=DEFAULT_MODULUS)

    args = parser.parse_args(argv)

    if args.self_test:
        report = self_test()
        _emit(report, out)
        return 0 if report["ok"] else 4
    if args.vectors:
        # Written, not re-serialised: `--vectors` and the committed file are the
        # same bytes, and test 14 is what holds them together.
        out.write(vectors_bytes().decode("utf-8"))
        return 0
    if args.command is None:
        parser.print_help(err)
        return 2

    try:
        if args.command == "derive":
            _emit(derive(args.order_digest, args.amount_raw,
                         modulus=args.modulus), out)
            return 0
        if args.command == "match":
            verdict = match(args.order_digest, args.amount_raw,
                            _read_json(args.block), modulus=args.modulus)
            _emit(verdict, out)
            # 3 is not an error: it is the answer "this block does not pay this
            # order", and a caller must be able to branch on it without parsing
            # text.
            return 0 if verdict["matched"] else 3
        digests, amounts = checked_orders(_read_json(args.orders))
        _emit(unclaimed(digests, amounts, _read_json(args.blocks),
                        modulus=args.modulus), out)
        return 0
    except Refusal as exc:
        _emit({"tool": TOOL, "version": VERSION, "error": exc.code,
               "detail": exc.detail}, out)
        return 2
    except (OSError, ValueError) as exc:
        print("%s: %s" % (type(exc).__name__, exc), file=err)
        return 2


if __name__ == "__main__":
    sys.exit(main())
