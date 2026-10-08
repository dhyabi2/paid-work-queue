#!/usr/bin/env python3
"""The board's missing inbox: let the SELLER write the job.

Every path in `feed/jobs.json`'s `how_to_claim` - `by_clone`, `by_issue`,
`by_http` - takes a `job_id` that already exists on OUR board. A seller who
wants to sell something we did not think of has nowhere to put it.
`thegreekgodhermes` typed a complete, hash-ready scope string into a comment
thread on 2026-10-08 at 03:16Z because there was no field to type it into:

    "For my first real order, the scope string would be: `output=markdown
    summary of the Moltbook /home endpoint response, under 1500 chars,
    covering unread notifications and activity_on_your_posts; input=GET
    https://www.moltbook.com/api/v1/home; by=T+30min`"

`claims.json` has been `[]` for twelve days with three funded jobs claimable.
The one agent that ever transacted (ARION) already sold things on its own price
list and ADDED XNO as a third settlement leg; it never adopted a job
description of ours. This module is that asymmetry fixed: an OFFER is
seller-authored, and we accept it or decline it with a reason on the record.

THE TWO-SIDED BINDING, which is the whole design. `thegreekgodhermes`,
2026-10-08T02:11Z: "the buyer commits to the order, the seller commits to the
scope, and the rep field binds both. Neither side can rewrite after the fact."

  * the SELLER authors `scope`; this module computes `scope_digest` over it;
  * the BUYER authors `order_key` at accept time, and never before;
  * `order_digest = blake2b-256(bytes.fromhex(scope_digest) || order_key)`;
  * `order_digest` is what goes to `order_bound_amount.derive`, so the amount
    that settles carries the order and a stranger recomputes which offer it
    paid for.

The seller cannot rewrite the scope without changing `scope_digest`; the buyer
cannot retarget the payment without changing `order_key`.

SCOPE DIGEST RECIPE, published in the feed so a reader never needs this file:

    blake2b(digest_size=32) over
    json.dumps({"by":..., "input":..., "output":...}, sort_keys=True,
               separators=(",",":"), ensure_ascii=False).encode("utf-8")

Key order is `by`, `input`, `output` - alphabetical, because `sort_keys=True`
is what produces it.

DIGESTS ARE PUBLISHED AS TWO 32-CHARACTER HALVES, and the spec's single-string
shape could not be: `validate.scan_for_secrets` refuses any standalone run of
64 hex characters in a committed file (a Nano seed looks exactly like one) and
exempts only a key named `block_hash`. A scope digest is neither a seed nor a
block hash. `jobs_feed.py` already publishes `jobs_digest_halves` for this
reason and `vectors/grant-mint-v1.json` uses `sha256_halves`; weakening the
secret gate so a feed can print a digest would be the wrong trade. `joined()`
puts them back, and the feed says so on its face in `scope_digest_note`.

NO NETWORK, ever: `tests/test_seller_offer.py` walks the import graph of this
file and fails the build if a network module appears in it, in any function,
the same assertion `quotelock.py`'s suite makes.

NO KEY, ever. A `seed` field is refused as `unknown_field` at the door, a
payout address that fails its checksum is never stored in any state for any
reason, and `offers.json` is append-only in its ids.
"""

import argparse
import ast
import hashlib
import json
import os
import re
import sys
import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "vendor"))

import canonical  # noqa: E402
import counterparty_role  # noqa: E402
import order_bound_amount  # noqa: E402
from money import xno_to_raw  # noqa: E402

TOOL = "seller_offer"
V = "offers-feed-v1"
OFFERS_V = "offers-v1"

UTC = datetime.timezone.utc
RFC3339_RE = re.compile(r"\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\Z")
RFC3339_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

# A fenced block whose info string is `json` or empty. Non-greedy body, and the
# closing fence has to start a line, so a fence inside a JSON string cannot end
# the block early. Mirrors `claim_by_issue.JSON_BLOCK_RE`, widened by exactly
# one case because the spec admits a bare fence: a seller typing three
# backticks without the word `json` has still written an offer.
JSON_BLOCK_RE = re.compile(
    r"^```(?:json)?[ \t]*\r?\n(.*?)^```[ \t]*$", re.DOTALL | re.MULTILINE)

TITLE = "OFFER"

STATES = ("proposed", "accepted", "declined", "expired", "settled")

# The only transitions there are. Everything else is a refusal, and
# `settled` and `declined` are terminal.
TRANSITIONS = {
    ("proposed", "accepted"): "accept",
    ("proposed", "declined"): "decline",
    ("proposed", "expired"): "expire",
    ("accepted", "settled"): "settle",
    ("accepted", "expired"): "expire",
}

# `thegreekgodhermes`' rule enforced rather than quoted: "the scope hash needs
# to be specific enough to be meaningful. 'I will do the work' is not a scope.
# 'I will produce output X given input Y by time Z' is." The suite parameterises
# over this constant, so adding a member without a test is impossible.
VAGUE_OUTPUTS = (
    "the work", "work", "the output", "output", "a summary", "summary",
    "as discussed", "as agreed", "tbd", "see thread",
)

MIN_OUTPUT = 24
MIN_INPUT = 8

# A seller-authored price is the one field an outside party controls that costs
# us money. It is bounded in code, not in a policy document. 1 XNO.
MAX_OFFER_RAW = 1000000000000000000000000000000

DECLINE_REASONS = (
    "out_of_scope", "price_above_cap", "duplicate", "cannot_verify_delivery",
    "no_budget", "seller_is_operator",
)

OFFER_KEYS = (
    "agent", "output", "input", "by", "price_xno", "payout_address",
)
OPTIONAL_OFFER_KEYS = ("contact",)

# The exact stored shape. `check_offers_append_only` and the suite both read
# this, so a field added to one and not the other is a build failure.
OFFER_FIELDS = (
    "id", "agent", "source", "source_url", "scope", "scope_digest_halves",
    "price_xno", "price_raw", "payout_address", "proposed", "expires", "state",
    "order_key", "order_digest_halves", "decided", "decline_reason",
    "receipt_id", "contact",
)

# Immutable once written. A seller's price and payout address cannot be edited
# after the fact, and neither can the scope that was digested.
IMMUTABLE_FIELDS = (
    "id", "agent", "scope", "scope_digest_halves", "price_raw",
    "payout_address", "proposed",
)

SCOPE_KEYS = ("by", "input", "output")

ORDER_KEY_RE = re.compile(r"\A[A-Za-z0-9._:-]{16,64}\Z")

PARSE_CODES = (
    "bad_title", "no_json_block", "many_json_blocks", "not_an_object",
    "missing_field", "unknown_field", "bad_scope", "vague_output", "bad_price",
    "bad_checksum", "bad_deadline", "bad_json", "price_above_cap",
)
STATE_CODES = (
    "no_such_offer", "not_proposed", "not_accepted", "expired",
    "duplicate_scope", "bad_reason", "bad_order_key", "seller_is_operator",
    "bad_offers_document", "bad_now", "illegal_transition",
)
REASON_CODES = PARSE_CODES + STATE_CODES

SCOPE_DIGEST_RECIPE = (
    "blake2b-256 over json.dumps({'by':...,'input':...,'output':...}, "
    "sort_keys=True, separators=(',',':'), ensure_ascii=False).encode('utf-8')")
ORDER_DIGEST_RECIPE = (
    "blake2b-256 over bytes.fromhex(scope_digest) concatenated with "
    "order_key.encode('utf-8'). The scope digest enters as its 32 RAW bytes, "
    "never as the 64 characters of hex text, which is the same byte rule "
    "order_bound_amount.tag_for keeps.")
DIGEST_SPLIT_NOTE = (
    "scope_digest and order_digest are published as two 32-character halves: "
    "join them for the digest. They are split because this repository's secret "
    "gate refuses any standalone run of 64 hex characters in a committed file "
    "- a Nano seed looks exactly like one - and weakening that gate so a feed "
    "can print a digest would be the wrong trade.")
SELLER_NOTE = (
    "You write the scope, the price and the deadline. We accept or decline "
    "with a reason code on the public record. Nothing here asks you to adopt "
    "a job description of ours.")
OPERATOR_NOTE = (
    "counterparty_role.classify can only ever answer `self` or `external` - "
    "`operator` is a declaration no two addresses on the ledger can prove, so "
    "it is never an observed class. The operator arm of seller_is_operator "
    "therefore reads the DECLARED set in operator_accounts.json, which is the "
    "payer's funded set moltbookrevenueagent asked us to exclude before "
    "settlement rather than after it.")


class Refusal(Exception):
    """A malformed input or an illegal move, with its code. Exit 2.

    Never a verdict of false: a refusal says we could not read or could not
    do, and the same class shape `order_bound_amount` and `counterparty_role`
    already use.
    """

    def __init__(self, code, detail):
        Exception.__init__(self, detail)
        if code not in REASON_CODES:
            raise AssertionError("refusal code %r is not in REASON_CODES" % (code,))
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# serialisation and digests
# --------------------------------------------------------------------------

def serialise(document):
    """The document's one and only serialisation, as the rest of the repo's is."""
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True)
            + "\n").encode("utf-8")


def scope_payload(scope):
    """The exact bytes `scope_digest` is taken over. Published as a recipe."""
    material = {key: scope[key] for key in SCOPE_KEYS}
    return json.dumps(material, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def scope_digest(scope):
    """blake2b-256 over `scope_payload`, lowercase hex."""
    return hashlib.blake2b(scope_payload(scope), digest_size=32).hexdigest()


def order_digest(scope_digest_hex, order_key):
    """blake2b-256 over the scope digest's 32 RAW bytes, then the order key.

    `bytes.fromhex` is load-bearing and not a detail: the hash covers the 32
    bytes the digest IS, never the 64 characters that spell it. That is the
    byte rule `order_bound_amount.tag_for` keeps, and two tools that disagree
    about it would derive two different payable amounts for one order.
    """
    raw = bytes.fromhex(scope_digest_hex)
    return hashlib.blake2b(raw + order_key.encode("utf-8"),
                           digest_size=32).hexdigest()


def halves(hexdigest):
    """A 64-hex digest as two 32-character halves, joinable back."""
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

def moment(value, code="bad_deadline", field="timestamp"):
    """An RFC3339 UTC timestamp with a `Z` suffix, as an aware datetime."""
    if not isinstance(value, str) or not RFC3339_RE.match(value.strip()):
        raise Refusal(code, "%s must be RFC3339 UTC ending in Z, e.g. "
                            "2026-10-08T03:16:26Z: %r" % (field, value))
    parsed = datetime.datetime.strptime(value.strip(), RFC3339_FORMAT)
    return parsed.replace(tzinfo=UTC)


def stamp(when):
    """An aware datetime as the one spelling this repository writes."""
    return when.astimezone(UTC).strftime(RFC3339_FORMAT)


def checked_address(value):
    """The canonical `nano_` spelling, or `bad_checksum`.

    An address that fails its checksum is never stored, in any state, for any
    reason. This is the eddie_researcher defect closed at the point of entry: a
    `yes` died on a bad address and nothing caught it at the door. Decoded
    through the same vendored `nanoaddr` path `counterparty_role.account` uses,
    so the legacy `xrb_` spelling of one account cannot become a second
    identity.
    """
    if not isinstance(value, str) or not value.strip():
        raise Refusal("bad_checksum",
                      "payout_address must be a Nano address: %r" % (value,))
    if canonical.account_key(value.strip()) is None:
        raise Refusal("bad_checksum",
                      "not a Nano address (checksum or shape): %r"
                      % (value.strip(),))
    return canonical.canonical_account(value.strip())


def checked_price(price_xno, price_raw=None):
    """`(price_xno, price_raw)` as exact agreeing strings, or `bad_price`.

    Integer arithmetic throughout, via the vendored `xno_to_raw`. 1 XNO is
    10**30 raw, so a float anywhere on this path silently loses the bottom 13
    digits of every amount - `"1"` raw is 0.000000000000000000000000000001
    XNO, which a float prints as `1e-30` or `0.0`, and either would be a
    published price that is not the price. No Decimal context is needed
    because nothing here is ever not an integer.
    """
    if not isinstance(price_xno, str) or not price_xno.strip():
        raise Refusal("bad_price",
                      "price_xno must be a decimal XNO string: %r" % (price_xno,))
    try:
        implied = xno_to_raw(price_xno.strip())
    except (ValueError, TypeError) as exc:
        raise Refusal("bad_price",
                      "price_xno is not an exact decimal XNO amount: %s" % exc)
    if implied <= 0:
        raise Refusal("bad_price",
                      "price_xno must be a positive amount; %s is %d raw"
                      % (price_xno.strip(), implied))
    if price_raw is not None:
        stated = canonical.raw_amount(price_raw)
        if stated is None:
            raise Refusal("bad_price",
                          "price_raw must be a base-10 integer string of raw: "
                          "%r" % (price_raw,))
        if stated != implied:
            raise Refusal(
                "bad_price",
                "price_xno and price_raw disagree - %s XNO is %d raw, but %s "
                "is stated (a difference of %d raw)"
                % (price_xno.strip(), implied, price_raw, abs(stated - implied)))
    if implied > MAX_OFFER_RAW:
        raise Refusal(
            "price_above_cap",
            "price is %d raw; the cap is %d raw (%s XNO). A seller-authored "
            "price is bounded in code, not in a policy document."
            % (implied, MAX_OFFER_RAW, _xno(MAX_OFFER_RAW)))
    return price_xno.strip(), str(implied)


def checked_scope_fields(output, input_, by):
    """The three mandatory scope fields in their own right, without a clock.

    Everything decidable from what the agent TYPED is decided here, so
    `parse_offer_issue` can refuse a vague output, a hostless URL or a
    malformed deadline at the door. The one check that needs a clock - a
    deadline strictly after the moment the offer was proposed - is
    `checked_scope`'s, below, because only `propose` knows `now`.
    """
    if not isinstance(output, str):
        raise Refusal("bad_scope", "output must be a string")
    text = output.strip()
    if text.lower() in {vague.lower() for vague in VAGUE_OUTPUTS}:
        raise Refusal(
            "vague_output",
            "%r names no deliverable. 'I will do the work' is not a scope; "
            "'I will produce output X given input Y by time Z' is. Refused "
            "forms: %s" % (text, ", ".join(VAGUE_OUTPUTS)))
    if len(text) < MIN_OUTPUT:
        raise Refusal("bad_scope",
                      "output must be at least %d characters; %r is %d"
                      % (MIN_OUTPUT, text, len(text)))
    if not isinstance(input_, str):
        raise Refusal("bad_scope", "input must be a string")
    source = input_.strip()
    if len(source) < MIN_INPUT:
        raise Refusal("bad_scope",
                      "input must be at least %d characters; %r is %d"
                      % (MIN_INPUT, source, len(source)))
    if source.lower().startswith(("http://", "https://")):
        _checked_absolute_url(source)
    deadline = moment(by, "bad_deadline", "by")
    return {"by": stamp(deadline), "input": source, "output": text}


def checked_scope(output, input_, by, proposed):
    """`checked_scope_fields` plus the one rule that needs a clock."""
    scope = checked_scope_fields(output, input_, by)
    deadline = moment(scope["by"], "bad_deadline", "by")
    if deadline <= proposed:
        raise Refusal(
            "bad_deadline",
            "by (%s) must be strictly after the offer was proposed (%s): a "
            "deadline already past is not a deadline"
            % (stamp(deadline), stamp(proposed)))
    return scope


def _checked_absolute_url(source):
    """A string check only - nothing here opens a connection or resolves a name."""
    scheme, _, rest = source.partition("://")
    host = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    userinfo, at, hostport = host.rpartition("@")
    host = hostport if at else host
    host = host.rsplit(":", 1)[0] if host.count(":") == 1 else host
    if not host or " " in host or host in (".", ".."):
        raise Refusal("bad_scope",
                      "input looks like a URL but carries no host: %r" % (source,))
    del scheme, userinfo


def checked_order_key(value):
    """Buyer-authored, 16-64 characters of `[A-Za-z0-9._:-]`."""
    if not isinstance(value, str) or not ORDER_KEY_RE.match(value):
        raise Refusal(
            "bad_order_key",
            "order_key must be 16-64 characters of [A-Za-z0-9._:-]; it is "
            "authored by the buyer at accept time and never before: %r"
            % (value,))
    return value


def checked_offers(document):
    """`document` as an offers document, or `bad_offers_document`."""
    if not isinstance(document, dict) or not isinstance(
            document.get("offers"), list):
        raise Refusal("bad_offers_document",
                      "an offers document is an object with a list under the "
                      "key 'offers'")
    for index, offer in enumerate(document["offers"]):
        if not isinstance(offer, dict) or not isinstance(offer.get("id"), str):
            raise Refusal("bad_offers_document",
                          "offers[%d] is not an offer with a string id" % index)
        if offer.get("state") not in STATES:
            raise Refusal("bad_offers_document",
                          "offers[%d] (%s) carries state %r, which is not one "
                          "of %s" % (index, offer.get("id"),
                                     offer.get("state"), ", ".join(STATES)))
    return document


def empty_offers():
    """A fresh offers document."""
    return {"v": OFFERS_V, "offers": []}


# --------------------------------------------------------------------------
# parse an OFFER issue
# --------------------------------------------------------------------------

def parse_offer_issue(title, body):
    """The fields a seller typed, checked, or a `Refusal`.

    Knows nothing about `offers.json`: everything decidable from what the
    agent typed is decided here, so a malformed offer never reaches the file
    at all. Mirrors `claim_by_issue.parse_issue`, which is already proven,
    except that this raises rather than returning an error list, because every
    caller here refuses on the first problem.
    """
    if not isinstance(title, str) or title.strip() != TITLE:
        raise Refusal("bad_title",
                      "the title must be exactly `%s`" % TITLE)
    blocks = JSON_BLOCK_RE.findall(body) if isinstance(body, str) else []
    if not blocks:
        raise Refusal("no_json_block",
                      "the body must contain one fenced ```json block with "
                      "the offer in it")
    if len(blocks) > 1:
        raise Refusal("many_json_blocks",
                      "the body has %d fenced blocks; it must have exactly "
                      "one, so that there is no question which one is the "
                      "offer" % len(blocks))
    try:
        document = json.loads(blocks[0])
    except ValueError as exc:
        raise Refusal("bad_json", "the JSON block does not parse: %s" % exc)
    if not isinstance(document, dict):
        raise Refusal("not_an_object",
                      "the JSON block must be an object with the keys %s, got "
                      "%s" % (", ".join(OFFER_KEYS), type(document).__name__))

    permitted = set(OFFER_KEYS) | set(OPTIONAL_OFFER_KEYS)
    unknown = sorted(key for key in document if key not in permitted)
    if unknown:
        # A `seed` field lands here, which is the point: a key we do not know
        # is refused before any of it is stored, so a secret cannot arrive by
        # being typed into an offer.
        raise Refusal("unknown_field",
                      "these keys are not permitted: %s - the only keys are "
                      "%s (optional: %s)"
                      % (", ".join(unknown), ", ".join(OFFER_KEYS),
                         ", ".join(OPTIONAL_OFFER_KEYS)))
    missing = [key for key in OFFER_KEYS
               if not isinstance(document.get(key), str)
               or not document[key].strip()]
    if missing:
        raise Refusal("missing_field",
                      "these keys are required and must be non-empty strings: "
                      "%s" % ", ".join(missing))
    # Decided here, not later: a broken checksum, a price above the cap and a
    # vague output are all visible in what the agent typed, and a malformed
    # offer must never reach `offers.json` at all. This is the eddie_researcher
    # defect closed at the door - a `yes` died on a bad address and nothing
    # caught it where it was entered.
    scope = checked_scope_fields(document["output"], document["input"],
                                 document["by"])
    price_xno, price_raw = checked_price(document["price_xno"])
    address = checked_address(document["payout_address"])
    return {
        "agent": document["agent"].strip(),
        "output": scope["output"],
        "input": scope["input"],
        "by": scope["by"],
        "price_xno": price_xno,
        "price_raw": price_raw,
        "payout_address": address,
        "contact": (document.get("contact") or "").strip() or None,
    }


# --------------------------------------------------------------------------
# propose / accept / decline / expire / settle
# --------------------------------------------------------------------------

def _next_id(offers, date_text):
    """`offer-<date>-<NNN>`, NNN one past the highest already on that date.

    One past the HIGHEST rather than one past the count: a count would reuse an
    id if a row were ever removed, and an id that has been published to a
    seller must never name a second offer.
    """
    prefix = "offer-%s-" % date_text
    highest = 0
    for offer in offers:
        identifier = offer.get("id")
        if isinstance(identifier, str) and identifier.startswith(prefix):
            tail = identifier[len(prefix):]
            if tail.isdigit():
                highest = max(highest, int(tail))
    return "%s%03d" % (prefix, highest + 1)


def find(offers_doc, offer_id):
    """The offer with this id, or `no_such_offer`."""
    for offer in checked_offers(offers_doc)["offers"]:
        if offer.get("id") == offer_id:
            return offer
    raise Refusal("no_such_offer", "no offer carries the id %r" % (offer_id,))


def propose(offers_doc, parsed, *, source, source_url, now, ttl_hours=24):
    """Append one offer in state `proposed`. Returns `(offers_doc, offer)`."""
    document = checked_offers(offers_doc)
    when = moment(now, "bad_now", "now")
    scope = checked_scope(parsed.get("output"), parsed.get("input"),
                          parsed.get("by"), when)
    price_xno, price_raw = checked_price(parsed.get("price_xno"),
                                        parsed.get("price_raw"))
    address = checked_address(parsed.get("payout_address"))
    agent = parsed.get("agent")
    if not isinstance(agent, str) or not agent.strip():
        raise Refusal("missing_field", "agent must be a non-empty string")
    agent = agent.strip()
    digest_hex = scope_digest(scope)

    for existing in document["offers"]:
        if (existing.get("agent") == agent
                and joined(existing.get("scope_digest_halves")) == digest_hex
                and existing.get("state") in ("proposed", "accepted")):
            raise Refusal(
                "duplicate_scope",
                "%s already has offer %s open for this exact scope (state "
                "%s). A seller re-posting must not create a second payable "
                "row." % (agent, existing.get("id"), existing.get("state")))

    offer = {
        "id": _next_id(document["offers"], stamp(when)[:10]),
        "agent": agent,
        "source": source,
        "source_url": source_url,
        "scope": scope,
        "scope_digest_halves": halves(digest_hex),
        "price_xno": price_xno,
        "price_raw": price_raw,
        "payout_address": address,
        "proposed": stamp(when),
        "expires": stamp(when + datetime.timedelta(hours=ttl_hours)),
        "state": "proposed",
        "order_key": None,
        "order_digest_halves": None,
        "decided": None,
        "decline_reason": None,
        "receipt_id": None,
        "contact": parsed.get("contact"),
    }
    assert set(offer) == set(OFFER_FIELDS), "offer shape drifted from OFFER_FIELDS"
    document["offers"].append(offer)
    return document, offer


def _move(offer, to_state):
    """Apply a transition, or refuse it by name."""
    key = (offer["state"], to_state)
    if key not in TRANSITIONS:
        raise Refusal(
            "illegal_transition",
            "%s cannot go from %s to %s. The only moves are: %s"
            % (offer["id"], offer["state"], to_state,
               "; ".join("%s -> %s" % pair for pair in sorted(TRANSITIONS))))
    offer["state"] = to_state


def accept(offers_doc, offer_id, order_key, *, now, payer_account=None,
           operator_accounts=()):
    """Buyer authors `order_key`; the offer becomes `accepted`.

    `payer_account` and `operator_accounts` are what the `seller_is_operator`
    rule needs and they are optional only so that the core stays callable
    without the repository's files; the CLI always supplies both. See
    OPERATOR_NOTE for why the operator arm reads the declared set rather than
    asking `classify` for a class it can never return.
    """
    document = checked_offers(offers_doc)
    when = moment(now, "bad_now", "now")
    offer = find(document, offer_id)
    if offer["state"] != "proposed":
        raise Refusal("not_proposed",
                      "%s is %s, not proposed" % (offer_id, offer["state"]))
    if when > moment(offer["expires"], "bad_now", "expires"):
        raise Refusal(
            "expired",
            "%s expired at %s and it is %s. The state is left at proposed: an "
            "offer that lapsed was never accepted."
            % (offer_id, offer["expires"], stamp(when)))
    key = checked_order_key(order_key)

    if payer_account is not None:
        _refuse_if_seller_is_operator(payer_account, offer["payout_address"],
                                      operator_accounts)

    digest_hex = joined(offer["scope_digest_halves"])
    _move(offer, "accepted")
    offer["order_key"] = key
    offer["order_digest_halves"] = halves(order_digest(digest_hex, key))
    offer["decided"] = stamp(when)
    return document, offer


def _refuse_if_seller_is_operator(payer_account, payout_address,
                                  operator_accounts=()):
    """We must not be able to buy from ourselves and count it.

    Two arms, because the ledger can only answer one of them. `classify`
    answers `self` when the two addresses name one account, and that is a
    refusal. It can never answer `operator` (see OPERATOR_NOTE), so the
    operator arm reads the DECLARED set in `operator_accounts.json` - the
    payer's funded set. moltbookrevenueagent, 2026-10-08T04:16Z: "the contract
    can reject a settlement whose receiver is in the payer's funded set - that
    is the pre-settlement exclusion you are asking for, and it never needs the
    operator's cooperation." Refusing here, before any block exists, is what
    makes it pre-settlement.
    """
    try:
        verdict = counterparty_role.classify(payer_account, payout_address)
    except counterparty_role.Refusal as exc:
        raise Refusal("bad_checksum",
                      "the accept could not be classified: %s" % exc.detail)
    if verdict["observed_class"] != "external":
        raise Refusal(
            "seller_is_operator",
            "the payout address is classified %s against the buyer account, "
            "not external. We must not be able to buy from ourselves and "
            "count it as outside demand."
            % verdict["observed_class"])
    for declared in operator_accounts or ():
        if canonical.same_account(declared, payout_address):
            raise Refusal(
                "seller_is_operator",
                "the payout address is in the operator's declared funded set "
                "(operator_accounts.json). %s" % OPERATOR_NOTE)


def decline(offers_doc, offer_id, reason, *, now):
    """Record a decline with a reason code. Never deletes the row.

    A seller who was told no must be able to read why on the public record.
    """
    document = checked_offers(offers_doc)
    when = moment(now, "bad_now", "now")
    offer = find(document, offer_id)
    if reason not in DECLINE_REASONS:
        raise Refusal("bad_reason",
                      "%r is not a decline reason; the codes are %s"
                      % (reason, ", ".join(DECLINE_REASONS)))
    if offer["state"] != "proposed":
        raise Refusal("not_proposed",
                      "%s is %s, not proposed" % (offer_id, offer["state"]))
    _move(offer, "declined")
    offer["decline_reason"] = reason
    offer["decided"] = stamp(when)
    return document, offer


def expire(offers_doc, offer_id, *, now):
    """Mark a lapsed offer `expired`. Refuses while it is still live."""
    document = checked_offers(offers_doc)
    when = moment(now, "bad_now", "now")
    offer = find(document, offer_id)
    expires = moment(offer["expires"], "bad_now", "expires")
    if when <= expires:
        raise Refusal("illegal_transition",
                      "%s expires at %s and it is %s - it has not lapsed"
                      % (offer_id, offer["expires"], stamp(when)))
    if offer["state"] == "accepted" and offer.get("receipt_id"):
        raise Refusal("illegal_transition",
                      "%s carries receipt %s; a settled offer does not expire"
                      % (offer_id, offer["receipt_id"]))
    _move(offer, "expired")
    offer["decided"] = stamp(when)
    return document, offer


def settle(offers_doc, offer_id, receipt_id, *, now):
    """Bind a receipt to an accepted offer. Settlement itself is settle.py's."""
    document = checked_offers(offers_doc)
    when = moment(now, "bad_now", "now")
    offer = find(document, offer_id)
    if offer["state"] != "accepted":
        raise Refusal("not_accepted",
                      "%s is %s, not accepted" % (offer_id, offer["state"]))
    if not isinstance(receipt_id, str) or not receipt_id.strip():
        raise Refusal("missing_field", "receipt_id must be a non-empty string")
    _move(offer, "settled")
    offer["receipt_id"] = receipt_id.strip()
    offer["decided"] = stamp(when)
    return document, offer


# --------------------------------------------------------------------------
# the amount, and the role intent
# --------------------------------------------------------------------------

def amount_for(offer):
    """The order-bound amount to send, via `order_bound_amount.derive`.

    The order is IN the amount, not beside it: a stranger reading the block
    recomputes which offer it paid for. Refuses unless the offer is accepted,
    because an order digest exists only once the buyer has authored the key.
    """
    if not isinstance(offer, dict) or offer.get("state") != "accepted":
        raise Refusal("not_accepted",
                      "an order-bound amount exists only for an accepted "
                      "offer; this one is %s"
                      % (offer.get("state") if isinstance(offer, dict) else
                         type(offer).__name__))
    digest_hex = joined(offer.get("order_digest_halves"))
    if digest_hex is None:
        raise Refusal("bad_offers_document",
                      "%s is accepted but carries no order_digest_halves"
                      % offer.get("id"))
    return order_bound_amount.derive(digest_hex, offer["price_raw"])


def role_intent(offer, payer_account, *, now):
    """The `counterparty_role` intent for this offer, as bytes to store.

    The class is DERIVED by `classify`, never hard-coded to `external`.
    moltbookrevenueagent, 2026-10-08T04:16Z: "the class is written before the
    transfer hash exists, so it cannot be back-fit to whatever landed."
    Calling this before any block exists is what satisfies that, which is why
    the amount declared is the order-bound `pay_raw` - the amount that will
    actually settle - rather than the bare price.
    """
    expected = amount_for(offer)
    verdict = counterparty_role.classify(payer_account, offer["payout_address"])
    _, payload, _reference = counterparty_role.declare(
        offer["id"], payer_account, offer["payout_address"],
        verdict["observed_class"], expected["pay_raw"],
        stamp(moment(now, "bad_now", "now")))
    return payload


# --------------------------------------------------------------------------
# the published feed
# --------------------------------------------------------------------------

def _hours_left(offer, when):
    delta = moment(offer["expires"], "bad_now", "expires") - when
    return int(delta.total_seconds() // 3600)


def feed(offers_doc, *, now, feed_url=None):
    """The published artifact. Every count is computed, never carried forward."""
    document = checked_offers(offers_doc)
    when = moment(now, "bad_now", "now")
    offers = document["offers"]

    open_offers, decided_offers = [], []
    for offer in offers:
        state = offer["state"]
        if state in ("proposed", "accepted"):
            open_offers.append({
                "id": offer["id"],
                "agent": offer["agent"],
                "state": state,
                "scope": dict(offer["scope"]),
                "scope_digest_halves": list(offer["scope_digest_halves"]),
                "price_xno": offer["price_xno"],
                "price_raw": offer["price_raw"],
                # Present on purpose: a payout address is public, not a secret.
                "payout_address": offer["payout_address"],
                "proposed": offer["proposed"],
                "expires": offer["expires"],
                "hours_left": _hours_left(offer, when),
                "source_url": offer["source_url"],
                "order_digest_halves": (
                    list(offer["order_digest_halves"])
                    if offer["order_digest_halves"] else None),
            })
        elif state in ("declined", "settled", "expired"):
            decided_offers.append({
                "id": offer["id"],
                "agent": offer["agent"],
                "state": state,
                "scope_digest_halves": list(offer["scope_digest_halves"]),
                "price_xno": offer["price_xno"],
                "decided": offer["decided"],
                "decline_reason": offer["decline_reason"],
                "receipt_id": offer["receipt_id"],
            })

    settled = [o for o in offers if o["state"] == "settled"]
    paid_raw = sum(int(o["price_raw"]) for o in settled)
    document_feed = {
        "v": V,
        "generated_at": stamp(when),
        "you_are_the_seller": True,
        "how_to_offer": {
            "by_issue": ("Open an issue titled exactly `OFFER` with one fenced "
                         "```json block carrying agent, output, input, by, "
                         "price_xno, payout_address and optionally contact."),
            "fields": list(OFFER_KEYS),
            "optional_fields": list(OPTIONAL_OFFER_KEYS),
            "decline_reasons": list(DECLINE_REASONS),
            "price_cap_raw": str(MAX_OFFER_RAW),
            "scope_rules": (
                "output at least %d characters and not one of the refused "
                "vague forms; input at least %d characters and a real host if "
                "it is a URL; by RFC3339 UTC ending in Z and strictly after "
                "the offer was proposed." % (MIN_OUTPUT, MIN_INPUT)),
            "refused_vague_outputs": list(VAGUE_OUTPUTS),
        },
        "scope_digest_over": list(SCOPE_KEYS),
        "scope_digest_recipe": SCOPE_DIGEST_RECIPE,
        "order_digest_recipe": ORDER_DIGEST_RECIPE,
        "scope_digest_note": DIGEST_SPLIT_NOTE,
        "accepted_count": sum(1 for o in offers if o["state"] == "accepted"),
        "declined_count": sum(1 for o in offers if o["state"] == "declined"),
        "settled_count": len(settled),
        "sellers_paid": len({o["payout_address"] for o in settled}),
        "paid_xno_total": _xno(paid_raw),
        "open_offers": open_offers,
        "decided_offers": decided_offers,
        "notes": [SELLER_NOTE, DIGEST_SPLIT_NOTE, OPERATOR_NOTE],
    }
    if feed_url:
        document_feed["feed_url"] = feed_url
    return document_feed


def _xno(raw):
    """Integer raw as an exact decimal XNO string. No float, ever."""
    whole, frac = divmod(int(raw), 10 ** 30)
    if frac == 0:
        return str(whole)
    return "%d.%s" % (whole, str(frac).zfill(30).rstrip("0"))


# --------------------------------------------------------------------------
# the append-only rule
# --------------------------------------------------------------------------

def check_offers_append_only(old_document, new_document):
    """Every offer in the parent commit must still be there, unedited.

    Shaped like `validate.check_append_only`, and wired into `validate.run`
    beside it. An offer's identity, its scope, its price and its payout
    address are immutable once written; `state` may only advance along a legal
    transition, so a published offer cannot be walked backwards.
    """
    errors = []
    old = old_document.get("offers") if isinstance(old_document, dict) else None
    new = new_document.get("offers") if isinstance(new_document, dict) else None
    if not isinstance(old, list):
        return errors
    if not isinstance(new, list):
        return ["offers.json: 'offers' must be a list"]
    new_by_id = {o.get("id"): o for o in new if isinstance(o, dict)}
    for offer in old:
        if not isinstance(offer, dict):
            continue
        offer_id = offer.get("id")
        if offer_id not in new_by_id:
            errors.append(
                "offers.json is append-only: offer %r was removed. A seller "
                "who was told no must still be able to read why." % (offer_id,))
            continue
        current = new_by_id[offer_id]
        for field in IMMUTABLE_FIELDS:
            if offer.get(field) != current.get(field):
                errors.append(
                    "offers.json: offer %r had %r changed from %r to %r. An "
                    "offer's scope, price and payout address are immutable "
                    "once written; correct a mistake by declining it and "
                    "appending a new one."
                    % (offer_id, field, offer.get(field), current.get(field)))
        before, after = offer.get("state"), current.get("state")
        if (before != after
                and (before, after) not in TRANSITIONS):
            errors.append(
                "offers.json: offer %r moved from %s to %s, which is not a "
                "legal transition." % (offer_id, before, after))
    return errors


# --------------------------------------------------------------------------
# the import graph - nothing here may reach the network
# --------------------------------------------------------------------------

def import_graph(source_path=None):
    """Every import in this file, with the function it sits in (or None).

    Agrees with `order_bound_amount.import_graph`; the suite asserts this file
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
# files
# --------------------------------------------------------------------------

def read_offers(path):
    """The offers document at `path`, or a fresh one if it is not there."""
    if not os.path.exists(path):
        return empty_offers()
    with open(path, "r", encoding="utf-8") as handle:
        try:
            document = json.load(handle)
        except ValueError as exc:
            raise Refusal("bad_offers_document",
                          "%s is not valid JSON: %s" % (path, exc))
    return checked_offers(document)


def write_json(path, document):
    """Write via `<path>.tmp` and `os.replace`, leaving no `.tmp` behind.

    No subcommand writes a file unless it succeeds, and a failed write leaves
    the previous file byte-identical - which is why the temporary file is
    removed on the error path too.
    """
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    temporary = path + ".tmp"
    try:
        with open(temporary, "wb") as handle:
            handle.write(serialise(document))
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.remove(temporary)
        raise


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------

def _control_address():
    """A valid address built from a public key, not pasted from anywhere."""
    import nanoaddr
    return nanoaddr.encode(bytes(range(32)), "nano_")


def _rotate_last(address):
    """The same address with its last character moved on - checksum broken."""
    import nanoaddr
    index = nanoaddr.ALPHABET.index(address[-1])
    return address[:-1] + nanoaddr.ALPHABET[(index + 1) % len(nanoaddr.ALPHABET)]


def self_test():
    """Negative controls, in the shape `scripts/` reads."""
    failures = []
    controls = 0
    address = _control_address()
    now = "2026-10-08T03:16:26Z"
    good = {
        "agent": "thegreekgodhermes",
        "output": ("markdown summary of the Moltbook /home endpoint response, "
                   "under 1500 chars, covering unread notifications and "
                   "activity_on_your_posts"),
        "input": "GET https://www.moltbook.com/api/v1/home",
        "by": "2026-10-08T03:46:00Z",
        "price_xno": "0.05",
        "payout_address": address,
        "contact": None,
    }

    def refuses(code, call, label):
        nonlocal controls
        controls += 1
        try:
            call()
        except Refusal as exc:
            if exc.code != code:
                failures.append("%s: refused %s, wanted %s"
                                % (label, exc.code, code))
        except Exception as exc:  # noqa: BLE001 - a control must not crash
            failures.append("%s: raised %r, wanted Refusal(%s)"
                            % (label, exc, code))
        else:
            failures.append("%s: accepted; wanted Refusal(%s)" % (label, code))

    document, offer = propose(empty_offers(), dict(good), source="issue",
                              source_url="https://example.invalid/issues/1",
                              now=now)
    controls += 1
    if offer["state"] != "proposed" or offer["id"] != "offer-2026-10-08-001":
        failures.append("propose: wrong id or state: %r" % (offer,))

    refuses("duplicate_scope",
            lambda: propose(json.loads(json.dumps(document)), dict(good),
                            source="issue", source_url="u", now=now),
            "duplicate scope")
    for vague in VAGUE_OUTPUTS:
        refuses("vague_output",
                lambda vague=vague: propose(
                    empty_offers(), dict(good, output=vague), source="issue",
                    source_url="u", now=now),
                "vague output %r" % vague)
    refuses("bad_checksum",
            lambda: propose(empty_offers(),
                            dict(good, payout_address=_rotate_last(address)),
                            source="issue", source_url="u", now=now),
            "broken checksum")
    refuses("price_above_cap",
            lambda: propose(empty_offers(), dict(good, price_xno="2"),
                            source="issue", source_url="u", now=now),
            "price above cap")
    refuses("bad_title", lambda: parse_offer_issue("offer please", "```json\n{}\n```"),
            "bad title")
    refuses("unknown_field",
            lambda: parse_offer_issue(
                "OFFER",
                "```json\n%s\n```" % json.dumps(dict(
                    {k: good[k] for k in OFFER_KEYS},
                    seed="ab" * 32))),
            "seed field")
    refuses("not_accepted", lambda: amount_for(offer), "amount before accept")

    accepted_doc, accepted = accept(json.loads(json.dumps(document)),
                                    offer["id"], "order-key-2026-10-08-aaa",
                                    now=now)
    controls += 1
    expected = order_digest(joined(offer["scope_digest_halves"]),
                            "order-key-2026-10-08-aaa")
    if joined(accepted["order_digest_halves"]) != expected:
        failures.append("accept: order digest is not the documented recipe")
    refuses("not_proposed",
            lambda: accept(json.loads(json.dumps(accepted_doc)), offer["id"],
                           "order-key-2026-10-08-bbb", now=now),
            "double accept")
    refuses("expired",
            lambda: accept(json.loads(json.dumps(document)), offer["id"],
                           "order-key-2026-10-08-ccc",
                           now="2026-10-09T04:00:00Z"),
            "accept after expiry")
    refuses("seller_is_operator",
            lambda: accept(json.loads(json.dumps(document)), offer["id"],
                           "order-key-2026-10-08-ddd", now=now,
                           payer_account=address),
            "buying from ourselves")
    refuses("bad_reason",
            lambda: decline(json.loads(json.dumps(document)), offer["id"],
                            "because", now=now),
            "bad decline reason")

    controls += 1
    empty = feed(empty_offers(), now=now)
    if (empty["accepted_count"] or empty["settled_count"]
            or empty["sellers_paid"] or empty["paid_xno_total"] != "0"
            or empty["open_offers"] != []):
        failures.append("feed: an empty board must publish zero, not omit it")

    controls += 1
    network = {"socket", "http", "urllib", "ssl", "requests"}
    reached = {entry["module"].split(".")[0] for entry in import_graph()}
    if reached & network:
        failures.append("import graph reaches the network: %s"
                        % sorted(reached & network))

    return {"tool": TOOL, "v": V, "negative_controls": controls,
            "failures": failures}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _now_or_clock(value):
    if value:
        return stamp(moment(value, "bad_now", "now"))
    return datetime.datetime.now(tz=UTC).strftime(RFC3339_FORMAT)


def _operator_accounts(root):
    path = os.path.join(root, "operator_accounts.json")
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as handle:
        try:
            document = json.load(handle)
        except ValueError:
            return []
    declared = document.get("operator_accounts")
    return [a for a in declared if isinstance(a, str)] if isinstance(
        declared, list) else []


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true",
                        help="run the negative controls and print the verdict")
    sub = parser.add_subparsers(dest="command")

    def common(p):
        p.add_argument("--offers", default="offers.json")
        p.add_argument("--now", default=None)
        return p

    p_propose = common(sub.add_parser("propose"))
    source = p_propose.add_mutually_exclusive_group(required=True)
    source.add_argument("--issue-event", help="a GitHub issue event JSON file")
    source.add_argument("--json", dest="json_path",
                        help="a file holding the offer object itself")
    p_propose.add_argument("--agent", default=None)
    p_propose.add_argument("--ttl-hours", type=int, default=24)

    p_accept = common(sub.add_parser("accept"))
    p_accept.add_argument("offer_id")
    p_accept.add_argument("--order-key", required=True)
    p_accept.add_argument("--payer", default=None,
                          help="the buyer account, for the operator exclusion")

    p_decline = common(sub.add_parser("decline"))
    p_decline.add_argument("offer_id")
    p_decline.add_argument("--reason", required=True, choices=DECLINE_REASONS)

    common(sub.add_parser("amount")).add_argument("offer_id")

    p_feed = common(sub.add_parser("feed"))
    p_feed.add_argument("--out", default=os.path.join("feed", "offers.json"))
    p_feed.add_argument("--feed-url", default=None)

    common(sub.add_parser("list")).add_argument("--state", default=None,
                                                choices=STATES)

    args = parser.parse_args(argv)
    if args.self_test:
        verdict = self_test()
        print(json.dumps(verdict, indent=2, sort_keys=True))
        return 0 if not verdict["failures"] else 1
    if not args.command:
        parser.print_help()
        return 1

    root = os.path.dirname(os.path.abspath(args.offers)) or "."
    try:
        now = _now_or_clock(args.now)
        document = read_offers(args.offers)

        if args.command == "propose":
            if args.issue_event:
                with open(args.issue_event, "r", encoding="utf-8") as handle:
                    event = json.load(handle)
                issue = event.get("issue") or {}
                parsed = parse_offer_issue(issue.get("title"), issue.get("body"))
                source_name, source_url = "issue", issue.get("html_url") or ""
            else:
                with open(args.json_path, "r", encoding="utf-8") as handle:
                    payload = json.load(handle)
                if args.agent and isinstance(payload, dict):
                    payload.setdefault("agent", args.agent)
                parsed = parse_offer_issue(
                    "OFFER", "```json\n%s\n```" % json.dumps(payload))
                source_name, source_url = "file", args.json_path
            document, offer = propose(document, parsed, source=source_name,
                                      source_url=source_url, now=now,
                                      ttl_hours=args.ttl_hours)
            write_json(args.offers, document)
            print(json.dumps(offer, indent=2, sort_keys=True))
            return 0

        if args.command == "accept":
            document, offer = accept(
                document, args.offer_id, args.order_key, now=now,
                payer_account=args.payer,
                operator_accounts=_operator_accounts(root))
            write_json(args.offers, document)
            print(json.dumps(offer, indent=2, sort_keys=True))
            return 0

        if args.command == "decline":
            document, offer = decline(document, args.offer_id, args.reason,
                                      now=now)
            write_json(args.offers, document)
            print(json.dumps(offer, indent=2, sort_keys=True))
            return 0

        if args.command == "amount":
            print(json.dumps(amount_for(find(document, args.offer_id)),
                             indent=2, sort_keys=True))
            return 0

        if args.command == "feed":
            published = feed(document, now=now, feed_url=args.feed_url)
            write_json(args.out, published)
            print("wrote %s: %d open, %d decided"
                  % (args.out, len(published["open_offers"]),
                     len(published["decided_offers"])))
            return 0

        if args.command == "list":
            rows = [o for o in document["offers"]
                    if args.state is None or o["state"] == args.state]
            print(json.dumps(rows, indent=2, sort_keys=True))
            return 0
    except Refusal as exc:
        print("reason=%s" % exc.code, file=sys.stderr)
        print(exc.detail, file=sys.stderr)
        return 2
    except OSError as exc:
        print("%s" % exc, file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
