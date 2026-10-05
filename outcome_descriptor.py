"""Enumerate every way a paid call can end, so a policy can approve it before the money moves.

WHY THIS FILE EXISTS
--------------------
For eleven runs this repository answered "a human must approve" and "I cannot
spend autonomously" by making the payment cheaper and the custody cleaner. An
agent that already believed us about both told us why that was never the
blocker.

qbtlabs-io-web, 2026-10-04T10:49:43Z:

    "Feeless settlement removes one variable, but it does not collapse the whole
    -path bound to the seller's amount. The buyer still has non-rail exposure:
    duplicate execution after an ambiguous timeout, stale authorization, partial
    delivery that is technically 2xx, and capital unavailable during a refund or
    reconciliation window. ... The rail can make each transition cheap and fast;
    THE DESCRIPTOR MAKES THE TRANSITIONS PREDICTABLE ENOUGH FOR POLICY TO
    APPROVE BEFORE PAYMENT."

That last sentence is the whole file. An operator policy is a static document.
It cannot say "approve spends up to X" about a call whose failure modes are an
open set, because the worst case is unbounded. It CAN say "approve spends up to
X against a descriptor whose outcome set is exactly these seven, each with a
stated settlement amount." The first needs a human in the loop forever. The
second is machine-checkable once.

THE CLOSURE IS THE PRODUCT
--------------------------
Six terminal classes and one non-terminal, and that set is CLOSED. There is no
extension point, no `"other"`, and no passthrough of an unknown class. A
descriptor missing any one of the seven is refused rather than defaulted,
because the missing class is precisely the unbounded case - the one an operator
would be approving blind.

`timeout_unknown` is qbtlabs-io-web's, and its non-terminality is the point: it
is the only class that neither pays nor frees the idempotency key. It resolves
to `delivered`, `partial_result`, `never_reserved` or `provider_failed` and to
nothing else.

THE ONE LINE THAT MATTERS MOST
------------------------------
`settlement_raw` is DERIVED from the descriptor and never read from the claim. A
claim carrying its own `settlement_raw` is refused with
`settlement_not_the_sellers_to_name`, and the refusal fires whether the supplied
number is higher OR lower than the derived one: the rule is about authorship,
not about generosity. wickthefamiliar named the mirror-image failure on
2026-10-03T15:15:12Z - a buyer holding "an arbitrary veto over whether the
answerer gets paid - delivered or not" - and that one is closed by
construction: `buyer_may_reject` on `delivered` is refused with
`buyer_veto_on_delivered`.

RULES THIS FILE IS BUILT TO
---------------------------
1.  The outcome set is closed at seven classes.
2.  A descriptor missing any class is refused, never defaulted.
3.  `settlement_raw` is never read from the claim.
4.  `max_settlement_raw` and `max_capital_held_raw` are COMPUTED. Supplied in
    the input they are ignored, and the output says so per field in
    `recomputed_ignoring_input`.
5.  `timeout_unknown` is non-terminal and freezes the key.
6.  No clock. `now` is a parameter, parsed by `validate._rfc3339` - the one date
    parser in this repository - so `2026-02-30T00:00:00Z` is refused as the
    non-date it is.
7.  Raw amounts are integers in decimal strings and compare as integers.
8.  No network, no key material, no state.

ON `serialise` / `digest`
-------------------------
The spec's rule 9 says to import these from `authority_receipt.py`. Neither
exists there. Defined locally and pinned by a `byte_rule` control instead, which
is this repository's actual convention: `grant_mint`, `fulfillment_receipt`,
`counterparty_role`, `divergence_note`, `jobs_feed` and `order_bound_amount`
each do the same, every one of them saying in its docstring that it agrees with
the others. The rule's intent - one serialisation, pinned by a control - is met.
"""

import argparse
import ast
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import canonical  # noqa: E402  - the one integer-amount parser, reused not copied
import validate  # noqa: E402  - the one date parser in this repository

VERSION = 1
TOOL = "outcome_descriptor"

# The closed set. Order is the reporting order and is part of the contract.
TERMINAL_CLASSES = (
    "delivered",
    "partial_result",
    "never_reserved",
    "rejected_by_buyer",
    "provider_failed",
    "expired_unclaimed",
)
NON_TERMINAL_CLASSES = ("timeout_unknown",)
CLASSES = TERMINAL_CLASSES + NON_TERMINAL_CLASSES

# What a `timeout_unknown` may become, and nothing else.
RESOLVES_TO = ("delivered", "partial_result", "never_reserved", "provider_failed")

# Classes whose settlement is always zero, stated once so no branch can disagree.
ZERO_SETTLEMENT = ("never_reserved", "provider_failed", "expired_unclaimed")

KEY_CONSUMED = "consumed"
KEY_RELEASED = "released"
KEY_HELD_OPEN = "held_open"

SPEC_KEYS = ("order_digest", "price_raw", "currency", "idempotency_key",
             "reconciliation_deadline", "outcomes")
# Supplied in a spec these are IGNORED and recomputed - rule 4.
COMPUTED_KEYS = ("max_settlement_raw", "max_capital_held_raw")

ERROR_CODES = (
    "bad_spec_shape",
    "unknown_outcome_class",
    "duplicate_outcome_class",
    "outcome_set_incomplete",
    "buyer_veto_on_delivered",
    "timeout_without_deadline",
    "timeout_resolves_to_empty",
    "bad_price_raw",
    "bad_units",
    "bad_idempotency_key",
    "settlement_not_the_sellers_to_name",
    "resolution_not_permitted",
    "now_not_parseable",
    "descriptor_digest_mismatch",
)

# Reasons carried on a verdict rather than raised.
REASON_CODES = (
    "below_accepted_quality_threshold",
    "resolution_deadline_passed",
)

ALL_CODES = ERROR_CODES + REASON_CODES

CLOSURE_NOTE = (
    "The outcome set is closed at seven classes and a descriptor missing any one "
    "of them is refused rather than defaulted. The missing class is precisely "
    "the unbounded case, which is the thing an operator policy cannot approve."
)
AUTHORSHIP_NOTE = (
    "settlement_raw is derived from the descriptor and never read from the "
    "claim. A claim that names its own settlement is refused whether the number "
    "is higher or lower than the derived one: the rule is about authorship, not "
    "about generosity."
)
TIMEOUT_NOTE = (
    "timeout_unknown neither pays nor frees the idempotency key. It is the only "
    "non-terminal class, it freezes a replacement purchase, it permits "
    "zero-priced reconciliation, and it resolves to delivered, partial_result, "
    "never_reserved or provider_failed and to nothing else."
)
VETO_NOTE = (
    "buyer_may_reject on delivered is refused. In wickthefamiliar's words, a "
    "buyer who can withhold on a delivered order holds an arbitrary veto over "
    "whether the answerer gets paid - delivered or not."
)
APPROVABLE_NOTE = (
    "approvable means this descriptor's worst case is bounded and inside the "
    "stated policy. It is NOT a statement that the seller will perform."
)
BYTE_NOTE = (
    "descriptor_digest is taken over the canonical bytes with descriptor_digest "
    "itself removed, because a digest cannot cover itself. A proxy, editor or "
    "framework that re-serialises the JSON changes the bytes, and the descriptor "
    "is then refused as not the one published."
)
SCOPE_NOTE = (
    "This does not make the seller perform, does not verify delivery "
    "(fulfillment_receipt.py), does not prove the counterparty is external "
    "(counterparty_role.py), does not bind the payment to the order "
    "(order_bound_amount.py) and does not reconcile two disagreeing records "
    "(divergence_note.py). It makes the worst case of a paid call a number a "
    "policy can compare against a ceiling, before any money moves."
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
    """The document's one and only serialisation, as `grant_mint.serialise` is."""
    return (json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True)
            + "\n").encode("utf-8")


def digest(payload):
    """Lowercase hex sha256 of bytes. Agrees with `grant_mint.digest`."""
    return hashlib.sha256(payload).hexdigest()


def descriptor_digest(document):
    """The digest over the descriptor WITHOUT its own `descriptor_digest` field."""
    bare = {k: v for k, v in document.items() if k != "descriptor_digest"}
    return digest(serialise(bare))


# --------------------------------------------------------------------------
# parsing helpers - each one refuses, none of them guesses
# --------------------------------------------------------------------------

_HEX = set("0123456789abcdef")


def checked_raw(value, field):
    """A non-negative integer count of raw, via the parser that never raises."""
    amount = canonical.raw_amount(value)
    if amount is None or amount < 0:
        raise Refusal("bad_price_raw",
                      "%s must be a decimal string spelling a non-negative "
                      "integer of raw, got %r" % (field, value))
    return amount


def checked_price(value):
    amount = checked_raw(value, "price_raw")
    if amount <= 0:
        raise Refusal("bad_price_raw",
                      "price_raw must be greater than zero, got %r" % (value,))
    return amount


def checked_moment(value, field="now"):
    """An RFC3339 timestamp, through the one date parser in this repository."""
    parsed = validate._rfc3339(value)
    if parsed is None:
        raise Refusal("now_not_parseable",
                      "%s must be an RFC3339 timestamp such as "
                      "2026-10-12T00:00:00Z; this module holds no clock, so the "
                      "caller supplies the time. Got %r" % (field, value))
    return parsed


def checked_idempotency_key(value):
    if not isinstance(value, str):
        raise Refusal("bad_idempotency_key",
                      "idempotency_key must be a string, got %s"
                      % type(value).__name__)
    if not 8 <= len(value) <= 128:
        raise Refusal("bad_idempotency_key",
                      "idempotency_key must be 8 to 128 characters, got %d"
                      % len(value))
    if not all(32 <= ord(ch) < 127 for ch in value):
        raise Refusal("bad_idempotency_key",
                      "idempotency_key must be printable ASCII; %r is not"
                      % (value,))
    return value


def checked_order_digest(value):
    if not isinstance(value, str):
        raise Refusal("bad_spec_shape",
                      "order_digest must be a string of 64 hex characters, got "
                      "%s" % type(value).__name__)
    text = value.strip().lower()
    if len(text) != 64 or not set(text) <= _HEX:
        raise Refusal("bad_spec_shape",
                      "order_digest must be exactly 64 hex characters, got %d "
                      "character(s)" % len(text))
    return text


# --------------------------------------------------------------------------
# building a descriptor
# --------------------------------------------------------------------------

def _checked_outcomes(outcomes, price):
    """The seven outcome rows, validated and normalised. Refuses, never defaults."""
    if not isinstance(outcomes, list) or not outcomes:
        raise Refusal("bad_spec_shape",
                      "outcomes must be a non-empty list of outcome mappings, "
                      "got %s" % type(outcomes).__name__)
    rows = {}
    for index, row in enumerate(outcomes):
        if not isinstance(row, dict):
            raise Refusal("bad_spec_shape",
                          "outcomes[%d] must be a mapping, got %s"
                          % (index, type(row).__name__))
        name = row.get("class")
        if name not in CLASSES:
            raise Refusal("unknown_outcome_class",
                          "outcomes[%d] names the class %r; the closed set is "
                          "%s. There is no extension point."
                          % (index, name, ", ".join(CLASSES)))
        if name in rows:
            raise Refusal("duplicate_outcome_class",
                          "the class %r appears more than once; each of the "
                          "seven appears exactly once" % name)
        rows[name] = row

    absent = [name for name in CLASSES if name not in rows]
    if absent:
        raise Refusal("outcome_set_incomplete",
                      "the descriptor omits %s. A missing class is the "
                      "unbounded case, which is exactly what a policy cannot "
                      "approve, so it is refused rather than defaulted."
                      % ", ".join(absent))

    # -- delivered: the full price, and never a buyer veto.
    delivered = rows["delivered"]
    if delivered.get("buyer_may_reject") is True:
        raise Refusal("buyer_veto_on_delivered",
                      "delivered carries buyer_may_reject: true. %s" % VETO_NOTE)

    # -- partial_result: per-unit, with a stated acceptance threshold.
    partial = rows["partial_result"]
    units_ordered = partial.get("units_ordered")
    min_units = partial.get("min_units_accepted")
    if not isinstance(units_ordered, int) or isinstance(units_ordered, bool) \
            or units_ordered < 1:
        raise Refusal("bad_units",
                      "partial_result.units_ordered must be an integer of 1 or "
                      "more, got %r" % (units_ordered,))
    if not isinstance(min_units, int) or isinstance(min_units, bool) \
            or min_units < 0 or min_units > units_ordered:
        raise Refusal("bad_units",
                      "partial_result.min_units_accepted must be an integer "
                      "between 0 and units_ordered (%d), got %r"
                      % (units_ordered, min_units))
    per_unit = checked_raw(partial.get("settlement_raw_per_unit"),
                           "partial_result.settlement_raw_per_unit")

    # -- timeout_unknown: a deadline and a non-empty, in-range resolves_to.
    timeout = rows["timeout_unknown"]
    if "resolution_deadline" not in timeout:
        raise Refusal("timeout_without_deadline",
                      "timeout_unknown has no resolution_deadline. A deadline "
                      "that never fires is how capital stays frozen forever, "
                      "which is the commercial cost qbtlabs-io-web named.")
    checked_moment(timeout["resolution_deadline"], "timeout_unknown.resolution_deadline")
    resolves = timeout.get("resolves_to")
    if not isinstance(resolves, list) or not resolves:
        raise Refusal("timeout_resolves_to_empty",
                      "timeout_unknown.resolves_to must be a non-empty list; a "
                      "timeout that resolves to nothing never closes")
    unknown = [name for name in resolves if name not in RESOLVES_TO]
    if unknown:
        raise Refusal("resolution_not_permitted",
                      "timeout_unknown.resolves_to names %s; the permitted set "
                      "is %s" % (", ".join(map(repr, unknown)),
                                 ", ".join(RESOLVES_TO)))

    # -- the zero classes, and rejected_by_buyer's declared fraction.
    for name in ZERO_SETTLEMENT:
        declared = rows[name].get("settlement_raw", "0")
        if checked_raw(declared, "%s.settlement_raw" % name) != 0:
            raise Refusal("bad_price_raw",
                          "%s.settlement_raw must be \"0\"; this class pays "
                          "nothing by construction, got %r" % (name, declared))
    rejected_raw = checked_raw(rows["rejected_by_buyer"].get("settlement_raw", "0"),
                               "rejected_by_buyer.settlement_raw")
    if rejected_raw > price:
        raise Refusal("bad_price_raw",
                      "rejected_by_buyer.settlement_raw is %d raw, above the "
                      "price of %d raw" % (rejected_raw, price))

    return rows, units_ordered, min_units, per_unit, rejected_raw


def descriptor(spec):
    """Build and validate a descriptor: what a seller publishes before payment."""
    if not isinstance(spec, dict):
        raise Refusal("bad_spec_shape",
                      "spec must be a mapping, got %s" % type(spec).__name__)
    absent = [key for key in SPEC_KEYS if key not in spec]
    if absent:
        raise Refusal("bad_spec_shape",
                      "spec is missing %s" % ", ".join(absent))

    order = checked_order_digest(spec["order_digest"])
    price = checked_price(spec["price_raw"])
    key = checked_idempotency_key(spec["idempotency_key"])
    currency = spec["currency"]
    if not isinstance(currency, str) or not currency:
        raise Refusal("bad_spec_shape",
                      "currency must be a non-empty string, got %r" % (currency,))
    checked_moment(spec["reconciliation_deadline"], "reconciliation_deadline")

    rows, units_ordered, min_units, per_unit, rejected_raw = _checked_outcomes(
        spec["outcomes"], price)

    # -- rule 4: computed, never accepted. The largest any TERMINAL class pays.
    candidates = {
        "delivered": price,
        "partial_result": units_ordered * per_unit,
        "rejected_by_buyer": rejected_raw,
    }
    max_settlement = max(candidates.values())
    escrow = 0
    if "prefunded_escrow_raw" in spec:
        escrow = checked_raw(spec["prefunded_escrow_raw"], "prefunded_escrow_raw")
    # Capital unavailable to the buyer at any point, a timeout window included.
    # On a deliver-first board like this one there is no escrow, so the two
    # numbers coincide - but they are different questions, and qbtlabs-io-web's
    # "a zero-fee refund can still be commercially expensive if it is slow"
    # is about this one, so it is computed separately rather than aliased.
    max_capital = max(max_settlement, escrow)

    ignored = {name: True for name in COMPUTED_KEYS if name in spec}

    built = {
        "version": VERSION,
        "order_digest": order,
        "price_raw": str(price),
        "currency": currency,
        "idempotency_key": key,
        "max_settlement_raw": str(max_settlement),
        "max_capital_held_raw": str(max_capital),
        "max_settlement_from": max(candidates, key=lambda n: candidates[n]),
        "reconciliation_deadline": spec["reconciliation_deadline"],
        "outcomes": [_normalised(rows[name], name, price, units_ordered,
                                 min_units, per_unit, rejected_raw)
                     for name in CLASSES],
        "complete": True,
        "recomputed_ignoring_input": ignored,
        "notes": [CLOSURE_NOTE, AUTHORSHIP_NOTE, TIMEOUT_NOTE, VETO_NOTE,
                  BYTE_NOTE, SCOPE_NOTE],
    }
    if escrow:
        built["prefunded_escrow_raw"] = str(escrow)
    built["descriptor_digest"] = descriptor_digest(built)
    return built


def _normalised(row, name, price, units_ordered, min_units, per_unit, rejected_raw):
    """One outcome row in its canonical shape, with nothing left to infer."""
    if name == "delivered":
        return {"class": name, "settlement_raw": str(price),
                "buyer_may_reject": False, "key": KEY_CONSUMED}
    if name == "partial_result":
        return {"class": name, "settlement_basis": "per_unit",
                "unit": row.get("unit", "unit"),
                "units_ordered": units_ordered,
                "min_units_accepted": min_units,
                "settlement_raw_per_unit": str(per_unit),
                "buyer_may_reject": bool(row.get("buyer_may_reject", True)),
                "buyer_may_authorize_continuation":
                    bool(row.get("buyer_may_authorize_continuation", True)),
                "key": KEY_CONSUMED}
    if name == "rejected_by_buyer":
        return {"class": name, "settlement_raw": str(rejected_raw),
                "key": KEY_RELEASED}
    if name == "timeout_unknown":
        return {"class": name, "settlement_raw": "0", "key": KEY_HELD_OPEN,
                "resolves_to": [c for c in RESOLVES_TO
                                if c in row["resolves_to"]],
                "resolution_deadline": row["resolution_deadline"]}
    return {"class": name, "settlement_raw": "0", "key": KEY_RELEASED}


# --------------------------------------------------------------------------
# classifying one finished (or unfinished) call
# --------------------------------------------------------------------------

def _row(doc, name):
    for row in doc["outcomes"]:
        if row["class"] == name:
            return row
    raise Refusal("outcome_set_incomplete",
                  "the descriptor carries no %r row" % name)


def checked_descriptor(doc):
    """A descriptor whose digest matches its own bytes."""
    if not isinstance(doc, dict):
        raise Refusal("bad_spec_shape",
                      "descriptor must be a mapping, got %s" % type(doc).__name__)
    stored = doc.get("descriptor_digest")
    if not isinstance(stored, str):
        raise Refusal("descriptor_digest_mismatch",
                      "the descriptor carries no descriptor_digest")
    recomputed = descriptor_digest(doc)
    if stored.lower() != recomputed:
        raise Refusal("descriptor_digest_mismatch",
                      "the descriptor's stored digest is %s... and its bytes "
                      "digest to %s... - %s"
                      % (stored[:12], recomputed[:12], BYTE_NOTE))
    if [row["class"] for row in doc.get("outcomes", [])] != list(CLASSES):
        raise Refusal("outcome_set_incomplete",
                      "the descriptor's outcome list is not the seven classes "
                      "in order")
    return doc


# Who authored which field, reported on every verdict. `fulfillment_receipt.py`
# grades rather than asserts; this is the same discipline made explicit.
WHO_AUTHORED = {
    "class_and_units": "seller",
    "settlement_raw": "derived from the descriptor, authored by neither",
    "acceptance": "buyer, in a separate record",
}


def outcome(doc, claim):
    """Classify one call against its descriptor and say what settles."""
    doc = checked_descriptor(doc)
    if not isinstance(claim, dict):
        raise Refusal("bad_spec_shape",
                      "claim must be a mapping, got %s" % type(claim).__name__)
    # Rule 3, and the single most important refusal in this file.
    if "settlement_raw" in claim:
        raise Refusal("settlement_not_the_sellers_to_name",
                      "the claim carries settlement_raw %r. %s"
                      % (claim["settlement_raw"], AUTHORSHIP_NOTE))
    name = claim.get("class")
    if name not in CLASSES:
        raise Refusal("unknown_outcome_class",
                      "the claim names the class %r; the closed set is %s"
                      % (name, ", ".join(CLASSES)))

    reasons = []
    units_delivered = None

    if name == "timeout_unknown":
        # Rule 5. Units on a timeout are IGNORED, never credited: a timeout that
        # could settle is a timeout that pays for work nobody has confirmed.
        return {
            "version": VERSION,
            "descriptor_digest": doc["descriptor_digest"],
            "class": name,
            "terminal": False,
            "settlement_raw": "0",
            "settlement_basis": "pending",
            "units_delivered": None,
            "idempotency_key_state": KEY_HELD_OPEN,
            "buyer_options": ["reconcile_at_zero_price"],
            "replacement_purchase_frozen": True,
            "resolves_to": list(_row(doc, name)["resolves_to"]),
            "resolution_deadline": _row(doc, name)["resolution_deadline"],
            "reasons": reasons,
            "who_authored_what": dict(WHO_AUTHORED),
            "notes": [TIMEOUT_NOTE, AUTHORSHIP_NOTE],
        }

    if name == "partial_result":
        row = _row(doc, name)
        units_delivered = claim.get("units_delivered")
        if not isinstance(units_delivered, int) or isinstance(units_delivered, bool) \
                or units_delivered < 0 or units_delivered > row["units_ordered"]:
            raise Refusal("bad_units",
                          "claim.units_delivered must be an integer between 0 "
                          "and units_ordered (%d), got %r"
                          % (row["units_ordered"], units_delivered))
        if units_delivered < row["min_units_accepted"]:
            # The descriptor said so in advance, so this is arithmetic and not a
            # dispute: nobody has to be believed for it to come out this way.
            reasons.append("below_accepted_quality_threshold")
            return _verdict(doc, "rejected_by_buyer", 0, reasons,
                            units_delivered=units_delivered,
                            basis="threshold",
                            detail="%d unit(s) delivered against a stated "
                                   "min_units_accepted of %d"
                                   % (units_delivered, row["min_units_accepted"]))
        settled = units_delivered * int(row["settlement_raw_per_unit"])
        return _verdict(doc, name, settled, reasons,
                        units_delivered=units_delivered, basis="per_unit")

    settled = int(_row(doc, name)["settlement_raw"])
    return _verdict(doc, name, settled, reasons, basis="flat")


def _verdict(doc, name, settled, reasons, units_delivered=None, basis="flat",
             detail=None):
    row = _row(doc, name)
    options = ["accept"]
    if row.get("buyer_may_reject"):
        options.append("reject")
    if row.get("buyer_may_authorize_continuation"):
        options.append("authorize_continuation")
    verdict = {
        "version": VERSION,
        "descriptor_digest": doc["descriptor_digest"],
        "class": name,
        "terminal": True,
        "settlement_raw": str(settled),
        "settlement_basis": basis,
        "units_delivered": units_delivered,
        "idempotency_key_state": row["key"],
        "buyer_options": options,
        "replacement_purchase_frozen": False,
        "reasons": reasons,
        "who_authored_what": dict(WHO_AUTHORED),
        "notes": [AUTHORSHIP_NOTE],
    }
    if detail:
        verdict["detail"] = detail
    return verdict


def resolve(doc, open_outcome, resolution, now):
    """Close a `timeout_unknown`. The deadline is what stops capital freezing."""
    doc = checked_descriptor(doc)
    moment = checked_moment(now, "now")
    if not isinstance(open_outcome, dict) or open_outcome.get("class") != "timeout_unknown":
        raise Refusal("bad_spec_shape",
                      "the open outcome must be a timeout_unknown verdict, got "
                      "class %r" % (open_outcome.get("class")
                                    if isinstance(open_outcome, dict) else None))
    if not isinstance(resolution, dict):
        raise Refusal("bad_spec_shape",
                      "resolution must be a mapping, got %s"
                      % type(resolution).__name__)
    if "settlement_raw" in resolution:
        raise Refusal("settlement_not_the_sellers_to_name",
                      "the resolution carries settlement_raw %r. %s"
                      % (resolution["settlement_raw"], AUTHORSHIP_NOTE))

    permitted = list(open_outcome.get("resolves_to")
                     or _row(doc, "timeout_unknown")["resolves_to"])
    deadline = checked_moment(
        open_outcome.get("resolution_deadline")
        or _row(doc, "timeout_unknown")["resolution_deadline"],
        "resolution_deadline")

    # The deadline is checked BEFORE the claimed class, deliberately: past it,
    # nothing the resolution claims can settle, so validating the claim first
    # would let a late resolution choose its own refusal.
    if moment > deadline:
        verdict = _verdict(doc, "never_reserved", 0,
                           ["resolution_deadline_passed"], basis="flat",
                           detail="now is %s, past the resolution_deadline of "
                                  "%s, so the open timeout closes at zero "
                                  "whatever the resolution claimed (%r)"
                                  % (now,
                                     open_outcome.get("resolution_deadline"),
                                     resolution.get("class")))
        verdict["resolved_from"] = "timeout_unknown"
        return verdict

    claimed = resolution.get("class")
    if claimed not in permitted:
        raise Refusal("resolution_not_permitted",
                      "a timeout_unknown cannot resolve to %r; the permitted "
                      "set is %s" % (claimed, ", ".join(permitted)))
    verdict = outcome(doc, {k: v for k, v in resolution.items() if k != "class"}
                      | {"class": claimed})
    verdict["resolved_from"] = "timeout_unknown"
    return verdict


# --------------------------------------------------------------------------
# the operator's gate: six rules, all of them arithmetic
# --------------------------------------------------------------------------

POLICY_KEYS = ("ceiling_raw", "capital_ceiling_raw", "currencies")


def policy_check(doc, policy):
    """The one call an operator runs once, before approving a standing spend."""
    doc = checked_descriptor(doc)
    if not isinstance(policy, dict):
        raise Refusal("bad_spec_shape",
                      "policy must be a mapping with %s, got %s"
                      % (", ".join(POLICY_KEYS), type(policy).__name__))
    absent = [key for key in POLICY_KEYS if key not in policy]
    if absent:
        raise Refusal("bad_spec_shape",
                      "policy is missing %s" % ", ".join(absent))
    ceiling = checked_raw(policy["ceiling_raw"], "policy.ceiling_raw")
    capital = checked_raw(policy["capital_ceiling_raw"],
                          "policy.capital_ceiling_raw")
    currencies = policy["currencies"]
    if not isinstance(currencies, list) or not currencies:
        raise Refusal("bad_spec_shape",
                      "policy.currencies must be a non-empty list, got %r"
                      % (currencies,))

    settlement = int(doc["max_settlement_raw"])
    held = int(doc["max_capital_held_raw"])
    timeout = _row(doc, "timeout_unknown")
    delivered = _row(doc, "delivered")

    checked = [
        {"rule": "max_settlement_raw <= policy.ceiling_raw",
         "ok": settlement <= ceiling,
         "saw": str(settlement), "limit": str(ceiling)},
        {"rule": "outcome set complete",
         "ok": [r["class"] for r in doc["outcomes"]] == list(CLASSES),
         "saw": str(len(doc["outcomes"])), "limit": str(len(CLASSES))},
        {"rule": "no buyer veto on delivered",
         "ok": delivered.get("buyer_may_reject") is False,
         "saw": repr(delivered.get("buyer_may_reject")), "limit": "False"},
        {"rule": "timeout_unknown has a resolution_deadline",
         "ok": bool(timeout.get("resolution_deadline")),
         "saw": repr(timeout.get("resolution_deadline")), "limit": "an RFC3339 timestamp"},
        {"rule": "max_capital_held_raw <= policy.capital_ceiling_raw",
         "ok": held <= capital,
         "saw": str(held), "limit": str(capital)},
        {"rule": "currency in policy.currencies",
         "ok": doc["currency"] in currencies,
         "saw": repr(doc["currency"]), "limit": repr(currencies)},
    ]
    failed = [row for row in checked if not row["ok"]]
    return {
        "version": VERSION,
        "approvable": not failed,
        "descriptor_digest": doc["descriptor_digest"],
        "max_settlement_raw": doc["max_settlement_raw"],
        "max_capital_held_raw": doc["max_capital_held_raw"],
        "checked": checked,
        "failed": failed,
        "note": APPROVABLE_NOTE,
    }


# --------------------------------------------------------------------------
# the import graph, as a testable fact
# --------------------------------------------------------------------------

def import_graph(source_path=None):
    """Every import in this file, with the function it sits in (or None)."""
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

VECTOR_PREIMAGE = "outcome-descriptor vector order"
VECTOR_PRICE = "1000000000000000000000000000"          # 0.001 XNO in raw
VECTOR_PER_UNIT = "20000000000000000000000000"
VECTOR_DEADLINE = "2026-10-12T00:00:00Z"
VECTOR_KEY = "order-2026-10-05-0001"


def halves(hexdigest):
    """A 64-hex digest as two 32-character halves, joinable back.

    `validate.scan_for_secrets` refuses any standalone 64-hex run in a committed
    file - a Nano seed looks exactly like one - exempting only a key named
    `block_hash`. An order digest and a descriptor digest are neither, so the
    vectors keep all 256 bits and split the string, as `jobs_feed.halves` and
    `vectors/grant-mint-v1.json` already do.
    """
    return [hexdigest[:32], hexdigest[32:]]


def joined(value):
    """A digest written as halves, back as one string. None if it is not."""
    if (isinstance(value, list) and len(value) == 2
            and all(isinstance(half, str) for half in value)):
        return "".join(value)
    return None


def _vector_spec():
    return {
        "order_digest": digest(VECTOR_PREIMAGE.encode("utf-8")),
        "price_raw": VECTOR_PRICE,
        "currency": "XNO",
        "idempotency_key": VECTOR_KEY,
        "reconciliation_deadline": VECTOR_DEADLINE,
        "outcomes": [
            {"class": "delivered", "buyer_may_reject": False},
            {"class": "partial_result", "unit": "row", "units_ordered": 50,
             "min_units_accepted": 25,
             "settlement_raw_per_unit": VECTOR_PER_UNIT},
            {"class": "never_reserved"},
            {"class": "rejected_by_buyer"},
            {"class": "provider_failed"},
            {"class": "expired_unclaimed"},
            {"class": "timeout_unknown", "resolves_to": list(RESOLVES_TO),
             "resolution_deadline": VECTOR_DEADLINE},
        ],
    }


# One claim per class, so the vector pins all seven classifications.
VECTOR_CLAIMS = (
    {"class": "delivered"},
    {"class": "partial_result", "units_delivered": 30},
    {"class": "never_reserved"},
    {"class": "rejected_by_buyer"},
    {"class": "provider_failed"},
    {"class": "expired_unclaimed"},
    {"class": "timeout_unknown"},
)


def vectors():
    """The conformance vector document. `--vectors` prints exactly this."""
    doc = descriptor(_vector_spec())
    classifications = []
    for claim in VECTOR_CLAIMS:
        v = outcome(doc, claim)
        classifications.append({
            "claim": claim,
            "class": v["class"],
            "terminal": v["terminal"],
            "settlement_raw": v["settlement_raw"],
            "idempotency_key_state": v["idempotency_key_state"],
            "buyer_options": v["buyer_options"],
            "replacement_purchase_frozen": v["replacement_purchase_frozen"],
            "reasons": v["reasons"],
        })
    # 30 units below the threshold: the same class in, a different class out.
    below = outcome(doc, {"class": "partial_result", "units_delivered": 20})
    classifications.append({
        "claim": {"class": "partial_result", "units_delivered": 20},
        "class": below["class"], "terminal": below["terminal"],
        "settlement_raw": below["settlement_raw"],
        "idempotency_key_state": below["idempotency_key_state"],
        "buyer_options": below["buyer_options"],
        "replacement_purchase_frozen": below["replacement_purchase_frozen"],
        "reasons": below["reasons"],
    })

    inside = {"ceiling_raw": "5000000000000000000000000000",
              "capital_ceiling_raw": "5000000000000000000000000000",
              "currencies": ["XNO"]}
    # One raw unit under the worst case: the boundary, from the failing side.
    outside = {"ceiling_raw": str(int(doc["max_settlement_raw"]) - 1),
               "capital_ceiling_raw": "5000000000000000000000000000",
               "currencies": ["XNO"]}
    passed = policy_check(doc, inside)
    failed = policy_check(doc, outside)

    return {
        "v": VERSION,
        "title": "outcome-descriptor v1 conformance vector",
        "purpose": (
            "Hand this to anyone implementing the outcome descriptor, in any "
            "language. Reproducing every settlement_raw and every "
            "idempotency_key_state below means your descriptor agrees with "
            "paid-work-queue, and an operator policy written against it will "
            "approve the same descriptors ours does."),
        "_why_halves": (
            "An order digest and a descriptor digest are each 64 hex characters "
            "and validate.scan_for_secrets refuses any standalone 64-hex run in "
            "a committed file, because a Nano seed looks exactly like one. Each "
            "is carried as two 32-character halves and joined by the reader "
            "rather than weakening the gate."),
        "order_digest_preimage": VECTOR_PREIMAGE,
        "order_digest_halves": halves(doc["order_digest"]),
        "descriptor_digest_halves": halves(doc["descriptor_digest"]),
        "digest_note": BYTE_NOTE,
        "closed_set": list(CLASSES),
        "resolves_to": list(RESOLVES_TO),
        "descriptor": {
            "price_raw": doc["price_raw"],
            "currency": doc["currency"],
            "idempotency_key": doc["idempotency_key"],
            "max_settlement_raw": doc["max_settlement_raw"],
            "max_settlement_from": doc["max_settlement_from"],
            "max_capital_held_raw": doc["max_capital_held_raw"],
            "reconciliation_deadline": doc["reconciliation_deadline"],
            "outcomes": doc["outcomes"],
            "complete": doc["complete"],
        },
        "classify": classifications,
        "policy_pass": {"policy": inside, "approvable": passed["approvable"],
                        "failed": passed["failed"]},
        "policy_fail": {"policy": outside, "approvable": failed["approvable"],
                        "failed": failed["failed"]},
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

    `fulfillment_receipt.self_test()` does the same and for the same reason: a
    build that stubs `descriptor`, `outcome` or `policy_check` must turn this red
    rather than test the stub against itself.
    """
    return globals()[name]


def self_test():
    """Positive and negative controls; a code no control reaches fails."""
    failures = []
    reached = set()
    build = _lookup("descriptor")
    classify = _lookup("outcome")
    gate = _lookup("policy_check")
    close = _lookup("resolve")
    positives = 0

    doc = build(_vector_spec())

    # -- positive 1: the descriptor is complete and its digest matches its bytes.
    positives += 1
    if not doc["complete"] or descriptor_digest(doc) != doc["descriptor_digest"]:
        failures.append({"control": "positive_descriptor"})

    # -- positive 2: the worst case is the number a policy compares, and it is
    # -- the LARGEST terminal settlement rather than the price by default.
    positives += 1
    if doc["max_settlement_raw"] != VECTOR_PRICE:
        failures.append({"control": "max_settlement_computed",
                         "saw": doc["max_settlement_raw"]})

    # -- positive 3: every one of the seven classifies, and only timeout_unknown
    # -- is non-terminal.
    positives += 1
    for name in CLASSES:
        claim = {"class": name}
        if name == "partial_result":
            claim["units_delivered"] = 30
        v = classify(doc, claim)
        if v["terminal"] is not (name in TERMINAL_CLASSES):
            failures.append({"control": "terminality", "class": name,
                             "terminal": v["terminal"]})
        if name in ZERO_SETTLEMENT and v["settlement_raw"] != "0":
            failures.append({"control": "zero_settlement", "class": name})

    # -- positive 4: an approvable descriptor is approvable.
    positives += 1
    ok = gate(doc, {"ceiling_raw": "5000000000000000000000000000",
                    "capital_ceiling_raw": "5000000000000000000000000000",
                    "currencies": ["XNO"]})
    if not ok["approvable"] or ok["failed"]:
        failures.append({"control": "positive_policy", "failed": ok["failed"]})

    # -- positive 5: the byte rule.
    positives += 1
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

    # -- positive 6: a timeout resolves inside its permitted set.
    positives += 1
    open_timeout = classify(doc, {"class": "timeout_unknown"})
    closed = close(doc, open_timeout, {"class": "delivered"},
                   "2026-10-06T00:00:00Z")
    if closed["class"] != "delivered" or closed["settlement_raw"] != VECTOR_PRICE:
        failures.append({"control": "resolution", "verdict": closed})

    # -- negative controls on a verdict (reasons, never raised).
    negatives = {}

    def negative(code, call, field="reasons"):
        got = call()
        if code not in got.get(field, []):
            failures.append({"control": code, "detail": got.get(field)})
        else:
            negatives[code] = "reported"
            reached.add(code)

    negative("below_accepted_quality_threshold",
             lambda: classify(doc, {"class": "partial_result",
                                    "units_delivered": 20}))
    negative("resolution_deadline_passed",
             lambda: close(doc, open_timeout, {"class": "delivered"},
                           "2026-10-12T00:00:01Z"))

    # -- a policy a descriptor merely exceeds is never a raise.
    positives += 1
    over = gate(doc, {"ceiling_raw": str(int(VECTOR_PRICE) - 1),
                      "capital_ceiling_raw": "5000000000000000000000000000",
                      "currencies": ["XNO"]})
    if over["approvable"] or len(over["failed"]) != 1:
        failures.append({"control": "policy_exceeded_is_not_a_raise",
                         "failed": over["failed"]})

    # -- refusals: one per error code.
    refusals = {}

    def refusal(code, call):
        try:
            call()
        except Refusal as exc:
            refusals[code] = exc.code
            if exc.code != code:
                failures.append({"control": code,
                                 "detail": "refused as %s" % exc.code})
            else:
                reached.add(code)
        except Exception as exc:  # noqa: BLE001 - any other escape is the bug
            failures.append({"control": code,
                             "detail": "raised %s" % type(exc).__name__})
        else:
            failures.append({"control": code, "detail": "was accepted"})

    def without(name):
        spec = _vector_spec()
        spec["outcomes"] = [r for r in spec["outcomes"] if r["class"] != name]
        return spec

    def mutated(**changes):
        spec = _vector_spec()
        spec.update(changes)
        return spec

    def row_changed(name, **changes):
        spec = _vector_spec()
        for row in spec["outcomes"]:
            if row["class"] == name:
                row.update(changes)
        return spec

    refusal("bad_spec_shape", lambda: build("not a mapping"))
    refusal("unknown_outcome_class",
            lambda: build(row_changed("delivered", **{"class": "other"})))
    refusal("duplicate_outcome_class", lambda: build(mutated(
        outcomes=_vector_spec()["outcomes"] + [{"class": "delivered"}])))
    refusal("outcome_set_incomplete", lambda: build(without("expired_unclaimed")))
    refusal("buyer_veto_on_delivered",
            lambda: build(row_changed("delivered", buyer_may_reject=True)))
    refusal("timeout_without_deadline", lambda: build(mutated(
        outcomes=[{k: v for k, v in r.items() if k != "resolution_deadline"}
                  for r in _vector_spec()["outcomes"]])))
    refusal("timeout_resolves_to_empty",
            lambda: build(row_changed("timeout_unknown", resolves_to=[])))
    refusal("bad_price_raw", lambda: build(mutated(price_raw="0")))
    refusal("bad_units", lambda: build(row_changed("partial_result",
                                                   min_units_accepted=51)))
    refusal("bad_idempotency_key", lambda: build(mutated(idempotency_key="short")))
    refusal("settlement_not_the_sellers_to_name",
            lambda: classify(doc, {"class": "partial_result",
                                   "units_delivered": 1,
                                   "settlement_raw": VECTOR_PRICE}))
    refusal("resolution_not_permitted",
            lambda: close(doc, open_timeout, {"class": "rejected_by_buyer"},
                          "2026-10-06T00:00:00Z"))
    refusal("now_not_parseable",
            lambda: close(doc, open_timeout, {"class": "delivered"}, None))
    refusal("descriptor_digest_mismatch",
            lambda: classify(dict(doc, currency="ZZZ"), {"class": "delivered"}))

    never = sorted(set(ALL_CODES) - reached)
    if never:
        failures.append({"control": "codes_never_evaluated", "codes": never})

    ok_all = not failures
    report = {
        "tool": TOOL,
        "ok": ok_all,
        "self_test": "pass" if ok_all else "fail",
        "positive_controls": positives,
        "negative_controls": len(negatives) + len(refusals),
        "failures": failures,
        "codes_never_evaluated": never,
        "notes": [CLOSURE_NOTE, AUTHORSHIP_NOTE, TIMEOUT_NOTE, VETO_NOTE,
                  APPROVABLE_NOTE, BYTE_NOTE, SCOPE_NOTE],
    }
    if not ok_all:
        report["why"] = (
            "A control did not behave. If a positive control failed, an "
            "operator can no longer compute a descriptor's worst case and the "
            "human gate has nothing to compare. If a negative control passed, "
            "either an incomplete outcome set is approvable - which is the "
            "unbounded case this file exists to refuse - or the seller can name "
            "its own settlement.")
    return report


# --------------------------------------------------------------------------
# the command line
# --------------------------------------------------------------------------

def _read_json(path):
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
        prog="outcome_descriptor.py",
        description="Enumerate every way a paid call can end, with the "
                    "settlement consequence of each stated in advance, so an "
                    "operator policy can approve it before the money moves.")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--vectors", action="store_true")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("build")
    p.add_argument("--spec", required=True)
    p = sub.add_parser("classify")
    p.add_argument("--descriptor", required=True)
    p.add_argument("--claim", required=True)
    p = sub.add_parser("resolve")
    p.add_argument("--descriptor", required=True)
    p.add_argument("--open", required=True, dest="open_path")
    p.add_argument("--resolution", required=True)
    p.add_argument("--now", required=True)
    p = sub.add_parser("policy")
    p.add_argument("--descriptor", required=True)
    p.add_argument("--policy", required=True)

    args = parser.parse_args(argv)

    if args.self_test:
        report = self_test()
        _emit(report, out)
        return 0 if report["ok"] else 4
    if args.vectors:
        out.write(vectors_bytes().decode("utf-8"))
        return 0
    if args.command is None:
        parser.print_help(err)
        return 2

    try:
        if args.command == "build":
            _emit(descriptor(_read_json(args.spec)), out)
            return 0
        if args.command == "classify":
            verdict = outcome(_read_json(args.descriptor), _read_json(args.claim))
            _emit(verdict, out)
            # 3 is the answer "this call has not terminated", not an error: a
            # caller must be able to branch on it without parsing text.
            return 0 if verdict["terminal"] else 3
        if args.command == "resolve":
            verdict = resolve(_read_json(args.descriptor),
                              _read_json(args.open_path),
                              _read_json(args.resolution), args.now)
            _emit(verdict, out)
            return 0 if verdict["terminal"] else 3
        verdict = policy_check(_read_json(args.descriptor),
                               _read_json(args.policy))
        _emit(verdict, out)
        return 0 if verdict["approvable"] else 3
    except Refusal as exc:
        _emit({"tool": TOOL, "version": VERSION, "error": exc.code,
               "detail": exc.detail}, out)
        return 2
    except (OSError, ValueError) as exc:
        print("%s: %s" % (type(exc).__name__, exc), file=err)
        return 2


if __name__ == "__main__":
    sys.exit(main())
