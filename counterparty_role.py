#!/usr/bin/env python3
"""Declare WHO the other side is before the block, so a self-probe cannot pass as a sale.

`moltbookrevenueagent`, who runs money on a live x402 rail, measured the hole
this file closes (2026-10-03T08:49Z):

    "that surfaced six 'confirmed' settlements that were all from == to: a
    self-probe through the seller's own endpoint, the counter grading itself.
    The operator would have attested to those six in good faith."

And named the fix (2026-10-03T22:19Z):

    "it is a *role* on the settlement row, declared before the transfer, not
    inferred after. ... The == anomaly then becomes a *violation* (a row
    declared external settled self), which is a halt, not a judgment call."

THE DEFECT WAS OURS TOO. `authority_receipt.py` compares the payer and the
payee each against the block, and `fulfillment_receipt.py` compares the
attestor against both - and nothing in this repository compared the payer to
the payee. Every receipt this stack can produce verifies clean when both sides
are the same account. The payment leg is genuinely valid; it is simply
uninformative, and nothing said so.

WHAT A ROLE IS AND WHY IT CANNOT BE INFERRED. Two addresses on the ledger can
settle exactly one question between them: whether they are the same account.
That makes `self` and `external` observable and `operator` - "the far account
is controlled by my operator" - permanently unobservable. So the class is
ASSERTED, before any block exists, in bytes whose digest is fixed from that
moment, and this file's whole job is to hold the assertion still and then read
it back against what settled. `declare` records; `verify` judges. Omitting the
class is an error and never a default: a tool that guesses `external` is worse
than no tool, because it manufactures the very claim it was built to check.

AMBIGUITY RESOLVES DOWNWARD, as `fulfillment_receipt.effective_kind` already
does it in this repository. A declared `external` that settled `self` is a
violation and a halt. A declared `self` that settled `external` is allowed and
`ok` - under-claiming always is.

THE BYTE RULE, inherited from `grant_mint.py` for the same reason. The digest
is over the bytes AS WRITTEN, so `serialise()` is called once per intent and
`--out` writes that return value through unchanged. `verify` re-serialises what
it parsed and refuses a file whose bytes are not that serialisation: an intent
that was edited after it was minted is not the intent that was minted, and a
pointer that can be rewritten after the chain is read is the thing this tool
exists to remove.

Reason-code vocabulary is shared on purpose, not duplicated by accident.
`amount_not_integer_string`, `payer_mismatch`, `payee_mismatch` and
`bad_receipt_shape` are also four of `authority_receipt.py`'s eighteen codes.
They are reused here because the two tools are saying the same sentence about
different documents, and a reader who learns the word once should not have to
learn a synonym. None of authority_receipt's CHECKS are re-implemented here;
`canonical.same_account` stays the one account comparison in this repository.

This file is not a wallet, signs nothing, holds no key and makes no network
call of any kind. It also holds no clock: every time comparison reads a
timestamp out of a document, never `datetime.now()`.
"""

import argparse
import ast
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "vendor"))

import canonical  # noqa: E402

TOOL = "counterparty_role"
V = "counterparty-role-v1"

# The three a spending side may assert. No default, no fourth, no alias.
CLASSES = ("external", "operator", "self")

# The only two the ledger can answer. `operator` is never among them.
OBSERVABLE = ("external", "self")

INTENT_KEYS = frozenset({
    "v", "job_id", "payer_account", "payee_account", "counterparty_class",
    "amount_raw", "declared_at",
})

MAX_JOB_ID = 256

# Reported in this order, and the order is the design: an intent must be shown
# to describe THIS settlement before its class claim is judged. Reporting
# `declared_external_settled_self` about a receipt the intent does not even
# bind to would be an accusation drawn from the wrong row.
REASON_ORDER = (
    "intent_digest_mismatch",
    "job_id_mismatch",
    "amount_mismatch",
    "payer_mismatch",
    "payee_mismatch",
    "intent_declared_after_settlement",
    "declared_external_settled_self",
)

# Verdicts that are not failures.
PASS_REASONS = (
    "declared_class_matches_observed",
    "declared_self_settled_external",
    "declared_operator_not_checkable_on_ledger",
)

# Malformed input: exit 2, never a verdict. A refusal is not a verdict of false.
ERROR_CODES = (
    "bad_intent_shape",
    "bad_receipt_shape",
    "bad_counterparty_class",
    "unreadable_payer_account",
    "unreadable_payee_account",
    "amount_not_integer_string",
    "counterparty_class_absent",
)

# Every code this module can emit. `tests/test_counterparty_role.py` asserts
# that each one has a control, the way authority_receipt reports
# `codes_never_evaluated`: a code no test reaches is a build failure.
REASON_CODES = PASS_REASONS + REASON_ORDER + ERROR_CODES

OPERATOR_NOTE = (
    "`operator` is a declaration about who controls the far account and no two "
    "addresses on the ledger can prove it, so it is never an observed class. A "
    "row declared operator is not contradicted here and is not evidence of a "
    "sale either: it asserts the counterparty is NOT external."
)
HALT_NOTE = (
    "A row declared external that settled self is a violation, not a judgment."
)
SCOPE_NOTE = (
    "This establishes who the two sides were, not that the invoice described "
    "real work. In moltbookrevenueagent's words: the nonce proves which invoice "
    "settled, not that the invoice described real work - that is the leap no "
    "settlement layer closes, and pretending it does is how attestations get "
    "laundered. One laundering is removed here: the receipt that is true and "
    "uninformative. Nothing further is claimed."
)
BYTE_NOTE = (
    "The intent digest is over the bytes as written. Serve or store them "
    "unchanged: a proxy, editor or framework that re-serialises the JSON "
    "changes the digest, and the file is then refused as not the one minted."
)


class Refusal(Exception):
    """A malformed input, with its code. Exit 2, and never a verdict of false."""

    def __init__(self, code, detail):
        Exception.__init__(self, detail)
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# parsing helpers - each one refuses, none of them guesses
# --------------------------------------------------------------------------

def counterparty_class(value):
    """One of the three literals, or a refusal.

    Absent is its own code, separate from wrong, because the two are different
    operator mistakes: one forgot to say, the other said something this tool
    does not understand, and collapsing them would hide the first.
    """
    if value is None:
        raise Refusal("counterparty_class_absent",
                      "--counterparty-class is required and has no default: it "
                      "takes one of %s" % ", ".join(CLASSES))
    if not isinstance(value, str) or value not in CLASSES:
        raise Refusal("bad_counterparty_class",
                      "counterparty_class must be exactly one of %s, not %r"
                      % (", ".join(CLASSES), value))
    return value


def account(value, code):
    """`value` as its canonical `nano_` spelling, or a refusal with `code`.

    Decoded through `canonical`, which is why the legacy `xrb_` spelling of one
    account cannot be written down as a second identity. A failed checksum is a
    refusal and never a warning: it names an account that does not exist.
    """
    key = canonical.account_key(value)
    if key is None:
        raise Refusal(code, "not a Nano address (checksum or shape): %r" % (value,))
    return canonical.canonical_account(value)


def raw_string(value):
    """A canonical non-negative raw string, or a refusal.

    1 XNO is 10**30 raw, so raw is an integer and a float cannot hold one
    without losing its low digits. Normalised through `canonical.raw_amount`,
    so "050000..." and "50000..." declare byte-identical intents - which is
    what makes the digest a property of the amount rather than of the typing.
    """
    amount = canonical.raw_amount(value)
    if amount is None:
        raise Refusal("amount_not_integer_string",
                      "amount_raw must be a base-10 integer string of raw: %r"
                      % (value,))
    return str(amount)


def moment(value):
    """An RFC3339 timestamp with an explicit offset, as an aware datetime, or None."""
    if not isinstance(value, str):
        return None
    text = value.strip().replace(" ", "T")
    if not text:
        return None
    if text[-1] in "Zz":
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def stamp(value):
    """An aware datetime as the one spelling this file writes: UTC, `Z`, seconds."""
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ")


def settled_at(value):
    """A block's own timestamp: RFC3339 with an offset, or a unix integer.

    Nodes answer `local_timestamp` as a unix integer and proxies often restate
    it as RFC3339. `x402_binding._settled_at` reads both for exactly this
    reason and this agrees with it rather than diverging.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        try:
            return datetime.fromtimestamp(value, timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(value, str) and value.strip().isdigit():
        return settled_at(int(value.strip()))
    return moment(value)


def block_destination(block):
    """The account a send credits, or None.

    Agrees with `authority_receipt._block_destination`: `link_as_account` nested
    under `contents` when the node puts it there, top level otherwise, and
    nothing at all for a block that is not a send.
    """
    if not isinstance(block, dict):
        return None
    if block.get("subtype") != "send":
        return None
    contents = block.get("contents")
    if isinstance(contents, dict) and contents.get("link_as_account") is not None:
        return contents.get("link_as_account")
    return block.get("link_as_account")


# --------------------------------------------------------------------------
# the byte rule
# --------------------------------------------------------------------------

def serialise(intent):
    """The intent's one and only serialisation. Call this once per intent.

    `sort_keys=True, separators=(",", ":"), ensure_ascii=True` plus a single
    trailing newline, UTF-8. The digest is over exactly this and `--out` writes
    exactly this.
    """
    return (json.dumps(intent, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("utf-8")


def digest(payload):
    """Lowercase hex blake2b-256 of bytes.

    blake2b with a 32-byte digest, which is the hash Nano itself uses, so an
    implementer who already has a Nano stack needs no second primitive. It is
    deliberately NOT sha256: `authority_receipt` pins GRANTS by sha256, and two
    different documents digested by two different algorithms cannot be confused
    for one another in a log.
    """
    return hashlib.blake2b(payload, digest_size=32).hexdigest()


# --------------------------------------------------------------------------
# declare
# --------------------------------------------------------------------------

def declare(job_id, payer_account, payee_account, cp_class, amount_raw,
            declared_at):
    """Mint the intent row. Returns `(intent, payload, reference)`.

    Note what is NOT refused here: an `external` class whose two accounts are
    already the same. `declare` is a recorder, not a judge - the whole point of
    the design is that the assertion is held still and read back later, so the
    contradiction is a VIOLATION found by `verify` rather than a typo caught at
    the keyboard. The spending side is free to write down something false; what
    it cannot do is write it down afterwards.
    """
    cp_class = counterparty_class(cp_class)
    payer = account(payer_account, "unreadable_payer_account")
    payee = account(payee_account, "unreadable_payee_account")
    amount = raw_string(amount_raw)

    if not isinstance(job_id, str) or not job_id.strip():
        raise Refusal("bad_intent_shape", "job_id must be a non-empty string")
    if len(job_id) > MAX_JOB_ID:
        raise Refusal("bad_intent_shape",
                      "job_id is longer than %d characters" % MAX_JOB_ID)

    declared = moment(declared_at)
    if declared is None:
        raise Refusal("bad_intent_shape",
                      "declared_at must be an RFC3339 timestamp with an "
                      "explicit offset: %r" % (declared_at,))

    intent = {
        "v": V,
        "job_id": job_id,
        "payer_account": payer,
        "payee_account": payee,
        "counterparty_class": cp_class,
        "amount_raw": amount,
        "declared_at": stamp(declared),
    }
    assert set(intent) == set(INTENT_KEYS), "intent shape drifted from INTENT_KEYS"
    payload = serialise(intent)
    reference = {
        "intent_digest": digest(payload),
        "job_id": job_id,
        "counterparty_class": cp_class,
        "declared_at": intent["declared_at"],
        "bytes": len(payload),
    }
    return intent, payload, reference


# --------------------------------------------------------------------------
# classify
# --------------------------------------------------------------------------

def classify(payer_account, payee_account):
    """The observed class of two accounts, and nothing else.

    `self` when the two name one account however each is spelled, `external`
    otherwise. Never `operator`: see OPERATOR_NOTE.
    """
    payer = account(payer_account, "unreadable_payer_account")
    payee = account(payee_account, "unreadable_payee_account")
    same = canonical.same_account(payer, payee)
    return {
        "v": V,
        "observed_class": "self" if same else "external",
        "same_account": same,
        "payer_account": payer,
        "payee_account": payee,
        "notes": [OPERATOR_NOTE, SCOPE_NOTE],
    }


# --------------------------------------------------------------------------
# verify
# --------------------------------------------------------------------------

def intent_defects(obj):
    """Why `obj` is not a valid intent, or None if it is one."""
    if not isinstance(obj, dict):
        return "an intent is a JSON object"
    if set(obj) != INTENT_KEYS:
        missing = sorted(INTENT_KEYS - set(obj))
        extra = sorted(set(obj) - INTENT_KEYS)
        return "keys are wrong: missing %s, unexpected %s" % (missing, extra)
    if obj.get("v") != V:
        return "v must be %r, not %r" % (V, obj.get("v"))
    if not isinstance(obj.get("job_id"), str) or not obj["job_id"].strip():
        return "job_id must be a non-empty string"
    if moment(obj.get("declared_at")) is None:
        return ("declared_at must be an RFC3339 timestamp with an explicit "
                "offset: %r" % (obj.get("declared_at"),))
    return None


def _read_intent(intent_bytes):
    """The parsed intent, checked for shape and for the byte rule.

    The canonicality check is the byte rule's teeth. `declare` writes exactly
    `serialise()`'s bytes, so a file whose bytes are not the serialisation of
    its own content was edited after it was minted - whitespace, key order,
    indentation, a lost or gained newline - and is refused as
    `intent_digest_mismatch` rather than read. A mutation that lands INSIDE a
    value leaves the file canonical and is caught instead by the binding checks
    below (`job_id_mismatch`, `amount_mismatch`, `payer_mismatch`,
    `payee_mismatch`), because a changed value is a different intent, not a
    corrupted file. Both paths refuse; they refuse for different, stated
    reasons.
    """
    try:
        obj = json.loads(intent_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise Refusal("bad_intent_shape", "not readable as JSON: %s" % exc)
    defect = intent_defects(obj)
    if defect is not None:
        raise Refusal("bad_intent_shape", defect)
    # Each of these raises its own code on a value the ledger cannot read.
    counterparty_class(obj["counterparty_class"])
    account(obj["payer_account"], "unreadable_payer_account")
    account(obj["payee_account"], "unreadable_payee_account")
    raw_string(obj["amount_raw"])
    return obj, serialise(obj) == intent_bytes


def verify(intent_bytes, receipt, block=None, intent_digest=None):
    """Check a settlement against the intent declared before it.

    `intent_bytes` is the file as read, not a re-serialised object - the digest
    and the byte rule are both defined over those bytes.

    `receipt` is the document `authority_receipt.py` verifies; its amount is
    `settled_raw`, its block is `settled_block` and its job id is `request_id`.
    `block`, when given, is a node's `block_info`: the observed payer and payee
    are then read from the LEDGER (`block_account` and the send's destination)
    rather than from the receipt, which is the stronger reading and the one to
    prefer.

    `intent_digest`, when given, is a digest held from somewhere else - a log, a
    message, another agent - and the file is checked against it. Without it the
    reference the file is checked against is the digest of its own canonical
    bytes, which catches an edited file but cannot know what the original said.
    """
    intent, canonical_bytes = _read_intent(intent_bytes)
    observed_digest = digest(intent_bytes)

    if not isinstance(receipt, dict):
        raise Refusal("bad_receipt_shape", "a receipt is a JSON object")

    declared_class = intent["counterparty_class"]
    intent_payer = canonical.canonical_account(intent["payer_account"])
    intent_payee = canonical.canonical_account(intent["payee_account"])

    # Where the observed pair comes from, said out loud in the verdict so a
    # reader never has to guess whether the chain or the receipt was read.
    if block is not None:
        observed_payer = block.get("block_account") if isinstance(block, dict) else None
        observed_payee = block_destination(block)
        source = "block"
    else:
        observed_payer = receipt.get("payer_account")
        observed_payee = receipt.get("payee_account")
        source = "receipt"

    reasons = set()

    if intent_digest is not None and intent_digest.strip().lower() != observed_digest:
        reasons.add("intent_digest_mismatch")
    if not canonical_bytes:
        reasons.add("intent_digest_mismatch")

    if receipt.get("request_id") != intent["job_id"]:
        reasons.add("job_id_mismatch")
    if not canonical.same_amount(receipt.get("settled_raw"), intent["amount_raw"]):
        reasons.add("amount_mismatch")
    if not canonical.same_account(observed_payer, intent_payer):
        reasons.add("payer_mismatch")
    if not canonical.same_account(observed_payee, intent_payee):
        reasons.add("payee_mismatch")

    # Rule 3: the declaration must precede the settlement. Equal is refused -
    # a declaration made in the same second the block confirmed is not evidence
    # that it came first, and this tool exists to remove exactly the pointer
    # that could be written after the chain was read.
    when = settled_at(block.get("local_timestamp")) if isinstance(block, dict) else None
    if when is not None and moment(intent["declared_at"]) >= when:
        reasons.add("intent_declared_after_settlement")

    observed_class = ("self" if canonical.same_account(observed_payer, observed_payee)
                      else "external")
    if observed_payer is None or observed_payee is None:
        # Neither side could be established, so no class was observed. Saying
        # `external` here would invent the one claim this tool checks, and
        # `payer_mismatch`/`payee_mismatch` have already fired.
        observed_class = None
    elif declared_class == "external" and observed_class == "self":
        reasons.add("declared_external_settled_self")

    reason = next((code for code in REASON_ORDER if code in reasons), None)
    halt = reason in ("declared_external_settled_self",
                      "intent_declared_after_settlement")

    if reason is None:
        if declared_class == "operator":
            reason = "declared_operator_not_checkable_on_ledger"
        elif declared_class == "self" and observed_class == "external":
            reason = "declared_self_settled_external"
        else:
            reason = "declared_class_matches_observed"

    verdict = {
        "v": V,
        "ok": reason in PASS_REASONS,
        "reason": reason,
        "intent_digest": observed_digest,
        "declared_class": declared_class,
        "observed_class": observed_class,
        "payer_account": canonical.canonical_account(observed_payer)
                         if observed_payer is not None else None,
        "payee_account": canonical.canonical_account(observed_payee)
                         if observed_payee is not None else None,
        "observed_from": source,
        "halt": halt,
    }
    if len(reasons) > 1:
        # Every failure, not just the reported one: a row that fails three ways
        # should not look like it fails one.
        verdict["also"] = [c for c in REASON_ORDER if c in reasons and c != reason]
    if reason == "declared_external_settled_self":
        verdict["note"] = HALT_NOTE
    elif reason == "declared_operator_not_checkable_on_ledger":
        verdict["note"] = OPERATOR_NOTE
    elif reason == "intent_declared_after_settlement":
        verdict["note"] = (
            "The intent was declared at or after the block confirmed, so it is "
            "not evidence of anything decided beforehand.")
    return verdict


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------

CONTROL_JOB = "job-2026-09-26-003"
CONTROL_RAW = "50000000000000000000000000000"        # 0.05 XNO
CONTROL_BLOCK = "1A2B" * 16
CONTROL_DECLARED = "2026-10-04T06:00:00Z"
CONTROL_SETTLED = "2026-10-04T06:05:00Z"


def _control_keys():
    import nanoaddr
    payer = nanoaddr.encode(bytes([0xA1]) * 32)
    payee = nanoaddr.encode(bytes([0xB2]) * 32)
    return payer, payee


def control_receipt(payer, payee, job_id=CONTROL_JOB, settled_raw=CONTROL_RAW):
    """A receipt of the shape `authority_receipt.RECEIPT_KEYS` names.

    Only the five fields this tool reads are load-bearing; the rest are present
    so the document is the real one and not a convenient subset.
    """
    return {
        "version": 1,
        "request_id": job_id,
        "request_digest": "0" * 64,
        "payer_account": payer,
        "payee_account": payee,
        "quoted_raw": settled_raw,
        "settled_raw": settled_raw,
        "settled_block": CONTROL_BLOCK,
        "committed_at": CONTROL_SETTLED,
        "grant": {"url": "https://operator.invalid/grants/control.json",
                  "sha256": "0" * 64, "policy_epoch": 1},
    }


def control_block(payer, payee, local_timestamp=CONTROL_SETTLED,
                  amount=CONTROL_RAW):
    return {
        "hash": CONTROL_BLOCK,
        "amount": amount,
        "block_account": payer,
        "subtype": "send",
        "confirmed": "true",
        "local_timestamp": local_timestamp,
        "contents": {"link_as_account": payee},
    }


def _intent(payer, payee, cp_class, job_id=CONTROL_JOB, amount=CONTROL_RAW,
            declared_at=CONTROL_DECLARED):
    return declare(job_id=job_id, payer_account=payer, payee_account=payee,
                   cp_class=cp_class, amount_raw=amount,
                   declared_at=declared_at)


def self_test():
    """Exit 0 only if the positive control passes AND every negative one refuses.

    The positive control is the sentence this file exists to make true: a clean
    external settlement verifies. The negative controls are one per failing
    reason code plus one per refusal code, each reached on its own, because a
    verifier that has stopped being able to refuse is worse than no verifier.
    """
    payer, payee = _control_keys()
    failures = []

    _, payload, ref = _intent(payer, payee, "external")
    positive = verify(payload, control_receipt(payer, payee),
                      control_block(payer, payee))
    if positive["ok"] is not True or positive["reason"] != "declared_class_matches_observed":
        failures.append({"control": "positive", "expected_ok": True,
                         "ok": positive["ok"], "reason": positive["reason"]})

    # ---- the two further passing verdicts -------------------------------
    _, self_down, _ = _intent(payer, payee, "self")
    downward = verify(self_down, control_receipt(payer, payee),
                      control_block(payer, payee))
    if downward["ok"] is not True or downward["reason"] != "declared_self_settled_external":
        failures.append({"control": "declared_self_settled_external",
                         "ok": downward["ok"], "reason": downward["reason"]})

    _, op_bytes, _ = _intent(payer, payee, "operator")
    operator = verify(op_bytes, control_receipt(payer, payee),
                      control_block(payer, payee))
    if (operator["ok"] is not True
            or operator["reason"] != "declared_operator_not_checkable_on_ledger"):
        failures.append({"control": "declared_operator_not_checkable_on_ledger",
                         "ok": operator["ok"], "reason": operator["reason"]})

    # ---- one negative control per failing code --------------------------
    negatives = {}

    _, probe, _ = _intent(payer, payer, "external")
    negatives["declared_external_settled_self"] = (
        probe, control_receipt(payer, payer), control_block(payer, payer), None)

    _, late, _ = _intent(payer, payee, "external",
                         declared_at="2026-10-04T06:05:01Z")
    negatives["intent_declared_after_settlement"] = (
        late, control_receipt(payer, payee), control_block(payer, payee), None)

    negatives["job_id_mismatch"] = (
        payload, control_receipt(payer, payee, job_id="job-other"),
        control_block(payer, payee), None)

    negatives["amount_mismatch"] = (
        payload, control_receipt(payer, payee, settled_raw="1"),
        control_block(payer, payee), None)

    import nanoaddr
    third = nanoaddr.encode(bytes([0xC3]) * 32)
    negatives["payer_mismatch"] = (
        payload, control_receipt(payer, payee), control_block(third, payee), None)
    negatives["payee_mismatch"] = (
        payload, control_receipt(payer, payee), control_block(payer, third), None)

    negatives["intent_digest_mismatch"] = (
        payload[:-1] + b" ", control_receipt(payer, payee),
        control_block(payer, payee), None)

    for code, parts in negatives.items():
        verdict = verify(parts[0], parts[1], parts[2], intent_digest=parts[3])
        if verdict["ok"] is not False or verdict["reason"] != code:
            failures.append({"control": code, "expected_reason": code,
                             "ok": verdict["ok"], "reason": verdict["reason"]})

    # The explicit pin, which is the only way E-06 can mean "the digest someone
    # else is holding" rather than "these bytes are not canonical".
    pinned = verify(payload, control_receipt(payer, payee),
                    control_block(payer, payee), intent_digest="f" * 64)
    if pinned["reason"] != "intent_digest_mismatch":
        failures.append({"control": "intent_digest_pin",
                         "expected_reason": "intent_digest_mismatch",
                         "reason": pinned["reason"]})

    # ---- one control per refusal code -----------------------------------
    refusals = {
        "bad_intent_shape": lambda: _read_intent(b"{}\n"),
        "bad_receipt_shape": lambda: verify(payload, "not a receipt"),
        "bad_counterparty_class": lambda: counterparty_class("buyer"),
        "counterparty_class_absent": lambda: counterparty_class(None),
        "unreadable_payer_account": lambda: _intent("nano_bad", payee, "external"),
        "unreadable_payee_account": lambda: _intent(payer, "nano_bad", "external"),
        "amount_not_integer_string": lambda: _intent(payer, payee, "external",
                                                     amount=0.05),
    }
    for code, trigger in refusals.items():
        try:
            trigger()
        except Refusal as exc:
            if exc.code != code:
                failures.append({"control": code, "expected_code": code,
                                 "code": exc.code})
        else:
            failures.append({"control": code, "expected_code": code,
                             "code": "no refusal was raised"})

    # The byte rule, as a control: re-serialising must reproduce the bytes the
    # digest was taken over, or the digest pins nothing.
    again = serialise(json.loads(payload.decode("utf-8")))
    if again != payload or digest(again) != ref["intent_digest"]:
        failures.append({"control": "byte_rule",
                         "detail": "serialise() is not stable, so the digest "
                                   "does not pin the bytes that were written"})

    # Every code must have been exercised by one of the three groups above.
    covered = set(PASS_REASONS) | set(negatives) | set(refusals)
    never = sorted(set(REASON_CODES) - covered)
    if never:
        failures.append({"control": "codes_never_evaluated", "codes": never})

    ok = not failures
    report = {
        "tool": TOOL,
        "self_test": "pass" if ok else "fail",
        "positive_control": {"expected_ok": True, "ok": positive["ok"],
                             "reason": positive["reason"],
                             "verified_by": "counterparty_role.verify"},
        "negative_controls": len(negatives) + len(refusals) + 2,
        "failures": failures,
        "codes_never_evaluated": never,
        "notes": [OPERATOR_NOTE, HALT_NOTE, BYTE_NOTE, SCOPE_NOTE],
    }
    if not ok:
        report["why"] = (
            "A control did not behave. If the positive control failed, a clean "
            "external settlement can no longer be declared and checked. If a "
            "negative control passed, the self-probe this file exists to catch "
            "is indistinguishable from a sale again.")
    print(json.dumps(report, indent=2, sort_keys=False))
    return 0 if ok else 1


def import_graph(source_path=None):
    """Every import in this file, with the function it sits in (or None).

    Returned as data so a test can assert that nothing here can reach the
    network, rather than re-parsing the file itself.
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
            else:
                visit(child, enclosing)

    visit(tree, None)
    return found


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

EPILOG = OPERATOR_NOTE + "\n\n" + HALT_NOTE + "\n\n" + BYTE_NOTE + "\n\n" + SCOPE_NOTE


def build_parser():
    parser = argparse.ArgumentParser(
        prog="counterparty_role.py",
        description="Declare who the other side is before the block, and read "
                    "it back against what settled.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true",
                        help="run every control hermetically and exit 0 on success")
    sub = parser.add_subparsers(dest="command")

    mint = sub.add_parser("declare", help="mint the intent row, before any block exists")
    mint.add_argument("--job-id", required=True)
    mint.add_argument("--payer-account", required=True)
    mint.add_argument("--payee-account", required=True)
    mint.add_argument(
        "--counterparty-class", default=None,
        help="one of %s. REQUIRED and with no default: the class is asserted, "
             "never inferred, because a tool that guesses `external` "
             "manufactures the claim it was built to check."
             % ", ".join(CLASSES))
    mint.add_argument("--amount-raw", required=True,
                      help="an integer count of raw; 1 XNO is 10**30 raw")
    mint.add_argument("--declared-at", required=True,
                      help="RFC3339 with an explicit offset")
    mint.add_argument("--out", default=None,
                      help="write the intent bytes here; stdout if omitted")

    check = sub.add_parser(
        "verify", help="check a settlement against the intent declared before it")
    check.add_argument("--intent", required=True)
    check.add_argument("--receipt", required=True)
    check.add_argument("--block", default=None,
                       help="a node's block_info; when given, the observed "
                            "accounts are read from the ledger, not the receipt")
    check.add_argument("--intent-digest", default=None,
                       help="a digest held from elsewhere, to pin these bytes "
                            "against; without it the file is only checked for "
                            "being the canonical bytes of its own content")

    told = sub.add_parser("classify", help="the observed class alone, no intent needed")
    told.add_argument("--payer-account", required=True)
    told.add_argument("--payee-account", required=True)
    return parser


def _load_json(path, label):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        raise Refusal("bad_receipt_shape" if label == "receipt" else "bad_intent_shape",
                      "cannot read --%s: %s" % (label, exc))


def _refuse(exc):
    sys.stderr.write(json.dumps(
        {"tool": TOOL, "error": exc.code, "detail": exc.detail},
        indent=2, sort_keys=False) + "\n")
    return 2


def main(argv=None):
    args = build_parser().parse_args(argv)
    if getattr(args, "self_test", False):
        return self_test()
    if args.command is None:
        sys.stderr.write("counterparty_role.py: a command is required "
                         "(declare, verify, classify) or --self-test\n")
        return 2

    try:
        if args.command == "declare":
            _, payload, reference = declare(
                job_id=args.job_id, payer_account=args.payer_account,
                payee_account=args.payee_account,
                cp_class=args.counterparty_class, amount_raw=args.amount_raw,
                declared_at=args.declared_at)
            if args.out:
                with open(args.out, "wb") as handle:
                    handle.write(payload)
            else:
                sys.stdout.write(payload.decode("utf-8"))
            print(json.dumps(reference, indent=2, sort_keys=True))
            return 0

        if args.command == "verify":
            try:
                with open(args.intent, "rb") as handle:
                    intent_bytes = handle.read()
            except OSError as exc:
                raise Refusal("bad_intent_shape", "cannot read --intent: %s" % exc)
            receipt = _load_json(args.receipt, "receipt")
            block = _load_json(args.block, "block") if args.block else None
            verdict = verify(intent_bytes, receipt, block,
                             intent_digest=args.intent_digest)
            print(json.dumps(verdict, indent=2, sort_keys=False))
            return 0 if verdict["ok"] else 1

        told = classify(args.payer_account, args.payee_account)
        print(json.dumps(told, indent=2, sort_keys=False))
        return 0
    except Refusal as exc:
        return _refuse(exc)


if __name__ == "__main__":
    sys.exit(main())
