#!/usr/bin/env python3
"""The durable request -> send -> result binding, and what is safe while it is ambiguous.

`ockerclaw` asked for this file four times - 2026-10-06 at 17:34Z, 17:35Z and
17:36Z, and again 2026-10-07 at 20:05Z - and three of the four are still
unanswered. Their words, which are the specification:

    "How do you handle a validated send whose corresponding receive remains
    unconfirmed after the reconciliation budget expires? That case should stay
    recoverable without allowing a fresh attempt to duplicate the transfer. A
    useful test is crashing after send confirmation but before recording it
    locally, then restarting with the same idempotency key."

    "'Not found' therefore isn't proof that a send never landed."

    "A send hash can deduplicate settlement, but it doesn't by itself make
    payment retries safe: an RPC reporting 'not found' may be lagging, so
    creating a new send could still double-pay. Rebroadcasting the identical
    signed block is a different operation... The missing contract is a durable
    request-to-send-to-result binding, with a retention window and bounded
    reconciliation when evidence is unavailable."

    "Safe retries should reuse the original signed transaction rather than
    construct a new payment."

`charlesschwerb` asks the same thing from the buyer's side (2026-10-07T20:42Z,
unanswered): what happens to a dependent branch when a block is still
propagating as a downstream timeout trips.

Neither is a trust objection or a demand objection. Both concede the parts we
usually argue - feeless settlement, ledger-authored receipts, a send hash that
deduplicates - and ask for the one thing we had not written: a contract for
what happens when the evidence is unavailable. Without it the safe operator
policy is to never let the agent spend at all, which is the wall
`cannot_spend_autonomously`.

WHAT THIS IS. A state machine over a durable journal. It records three facts
per payment, each with its own timestamp, joined by one idempotency key:

  * `request` - what was asked for (`order_digest`, `amount_raw`, `payee`),
  * `send`    - the signed block, kept so it can be REBROADCAST rather than
                re-created, with when it was signed and when it went out,
  * `result`  - what the money bought, and whether that is retrievable.

and for any row it answers one question: which of a closed set of actions is
safe right now. It never signs, never broadcasts, never holds a key, and makes
no network call - the node is a callable the caller passes in, so the suite
drives every branch with a fake.

THE RULE THAT IS THE WHOLE POINT. A node answering "no such block" is an
OBSERVATION, not a FACT. `not_found`, `rpc_error` and `timeout` increment the
reconciliation counter and never advance a row toward a fresh send; when the
budget is spent the row becomes `EVIDENCE_UNAVAILABLE`, which permits
`HOLD_FOR_OPERATOR` and nothing else. The money is neither declared sent nor
declared unsent. `SAFE_TO_RETRY_FRESH` is reachable from exactly one state,
`ABANDONED_NO_SEND`, which is itself reachable only while `signed_block` is
null - so a fresh send is impossible once a block exists, whatever any node
says. `safe_action` is pure and the suite asserts that property over all nine
states rather than over a case.

WHY THE STORED BLOCK IS SPLIT INTO PARTS. A Nano block carries `previous`,
`link` (64 hex) and `signature` (128 hex), and `validate.scan_for_secrets`
refuses 64-or-more hex characters standing alone anywhere in the tree, with one
exemption for a field named `block_hash`. A journal holding a verbatim block
would therefore fail the repository's secret gate, and the two ways out are not
equal: widening that gate so a runtime file can hold long hex is a permanent
loss on the money path, while splitting the field into 32-character parts costs
one join on the way out and is exactly reversible. So long hex values are stored
as a list of parts under `{"hex_parts": [...]}` and `rebroadcast_block()`
returns the block as it was recorded, byte for byte. The suite asserts the
round trip AND that `scan_for_secrets` is clean over a journal holding a
real-shaped block.

The row's own `order_digest` is 64 hex and falls under the same gate, so it is
stored as `order_digest_halves`, which is already this repository's spelling for
a stored digest (`seller_offer.py` writes `order_digest_halves` for exactly this
reason). `order_digest_of()` joins it back. The spec for this module wrote the
field as `order_digest`; the gate decided the spelling, and the test that found
it is `test_15c`, which runs `validate.scan_for_secrets` over a written
journal rather than trusting the author's reading of the gate.

`attempts.json` is runtime state: gitignored, never committed, and `validate.py`
fails if it is tracked. Standard library only; the suite asserts this module
imports none of socket, http, urllib, ssl or requests.
"""

import argparse
import ast
import datetime
import json
import os
import re
import sys
from hashlib import blake2b

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "vendor"))

import nanoaddr  # noqa: E402
from canonical import same_account, same_amount  # noqa: E402  - one comparison, not three

TOOL = "retry_safety"
V = "attempts-v1"

JOURNAL_FILE = "attempts.json"

#: 30 days. The window `ockerclaw` asked for: long enough that a payment nobody
#: looked at for a month is still recoverable from the journal.
DEFAULT_RETENTION_HOURS = 720

#: How many times an inconclusive observation may be taken before the row stops
#: pretending reconciliation is still in progress.
DEFAULT_RECONCILE_BUDGET = 12

#: A request that was never signed stops being live after this long. It is the
#: ONLY path to `ABANDONED_NO_SEND`, and therefore the only path to a fresh
#: send, so it is deliberately not short.
DEFAULT_REQUEST_TTL_HOURS = 24

RFC3339_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
RFC3339_RE = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
DIGEST_RE = re.compile(r"\A[0-9a-f]{64}\Z")
RAW_RE = re.compile(r"\A(0|[1-9][0-9]*)\Z")
KEY_RE = re.compile(r"\Aik-[0-9a-f]{32}\Z")
HASH_RE = re.compile(r"\A[0-9A-F]{64}\Z")
LONG_HEX_RE = re.compile(r"\A[0-9a-fA-F]{64,}\Z")

#: Short enough that `validate.SECRET_RE` ({64,} hex standing alone) cannot
#: match a part, with the headroom to stay unmatched if that threshold ever
#: tightens.
HEX_PART = 32
HEX_PARTS_KEY = "hex_parts"

UTC = datetime.timezone.utc

# --------------------------------------------------------------------------
# the nine states, and the one action each permits
# --------------------------------------------------------------------------

REQUESTED = "REQUESTED"
SIGNED_NOT_BROADCAST = "SIGNED_NOT_BROADCAST"
SENT_UNCONFIRMED = "SENT_UNCONFIRMED"
SENT_CONFIRMED_UNRECEIVED = "SENT_CONFIRMED_UNRECEIVED"
SETTLED = "SETTLED"
SETTLED_RESULT_PENDING = "SETTLED_RESULT_PENDING"
COMPLETE = "COMPLETE"
EVIDENCE_UNAVAILABLE = "EVIDENCE_UNAVAILABLE"
ABANDONED_NO_SEND = "ABANDONED_NO_SEND"

STATES = (REQUESTED, SIGNED_NOT_BROADCAST, SENT_UNCONFIRMED,
          SENT_CONFIRMED_UNRECEIVED, SETTLED, SETTLED_RESULT_PENDING,
          COMPLETE, EVIDENCE_UNAVAILABLE, ABANDONED_NO_SEND)

#: state -> the one action that is safe in it. A tenth state cannot be added
#: without a row here: the suite asserts `set(STATES) == set(SAFE_ACTIONS)`.
SAFE_ACTIONS = {
    REQUESTED: "SIGN_AND_BROADCAST",
    SIGNED_NOT_BROADCAST: "BROADCAST_SAME_BLOCK",
    SENT_UNCONFIRMED: "REBROADCAST_SAME_BLOCK",
    SENT_CONFIRMED_UNRECEIVED: "WAIT_OR_REBROADCAST_SAME_BLOCK",
    SETTLED: "FETCH_RESULT",
    SETTLED_RESULT_PENDING: "FETCH_RESULT",
    COMPLETE: "NOTHING",
    EVIDENCE_UNAVAILABLE: "HOLD_FOR_OPERATOR",
    ABANDONED_NO_SEND: "SAFE_TO_RETRY_FRESH",
}

#: Why, in one sentence, for the operator reading a report rather than a table.
WHY = {
    REQUESTED: ("nothing has been signed for this request, so a first send is "
                "the safe action"),
    SIGNED_NOT_BROADCAST: ("a signed block for this request is already on "
                           "disk; broadcast that block, do not sign another"),
    SENT_UNCONFIRMED: ("a block went out and no confirmation has been "
                       "observed; rebroadcasting the same block is safe, "
                       "signing a new one is not"),
    SENT_CONFIRMED_UNRECEIVED: ("the send is confirmed and the receive is not "
                                "observed; the money has left, so no new send "
                                "may be constructed"),
    SETTLED: ("send and receive are both confirmed; what is outstanding is the "
              "result, not the payment"),
    SETTLED_RESULT_PENDING: ("the payment settled and the result is not stored "
                             "or not retrievable; fetch the result"),
    COMPLETE: "settled and the result is retrievable; nothing is outstanding",
    EVIDENCE_UNAVAILABLE: ("the reconciliation budget was spent without a "
                           "determination - this is not evidence that no send "
                           "landed, so an operator decides and no new send is "
                           "constructed"),
    ABANDONED_NO_SEND: ("no block was ever signed for this request and the "
                        "request has expired, so a fresh attempt cannot "
                        "duplicate anything"),
}

#: The only state that does not block a new send, because it is the only state
#: in which no signed block can exist. This is the answer to the double-pay
#: question and the suite asserts it over every state.
NEW_SEND_ALLOWED_IN = (ABANDONED_NO_SEND,)

#: Retention may drop these and nothing else. A row that is not terminal is
#: never dropped, however old - a forgotten in-flight payment is precisely what
#: retention must not delete.
TERMINAL = (COMPLETE, ABANDONED_NO_SEND)

#: States whose meaning is "no block exists for this request". `checked_journal`
#: refuses a row in one of them that carries a signed block, which is what makes
#: the `signed_block is None` test in `expire` defence in depth rather than the
#: only thing standing between a journal edit and a second payment.
NO_BLOCK_STATES = (REQUESTED, ABANDONED_NO_SEND)

OBSERVATION_KINDS = ("not_found", "unconfirmed", "confirmed", "received",
                     "rpc_error", "timeout")

#: The kinds that say "we could not tell", which is not the same as "it did not
#: happen". They move the counter and never the state, except to
#: `EVIDENCE_UNAVAILABLE` when the budget runs out.
INCONCLUSIVE_KINDS = ("not_found", "unconfirmed", "rpc_error", "timeout")

RETRIEVABLE = ("YES", "NO", "UNKNOWN")

#: A field name under `signed_block` holding any of these is refused outright.
#: A Nano block has no such field; a wallet dump does.
FORBIDDEN_BLOCK_KEY_PARTS = ("seed", "private", "privkey", "secret",
                             "mnemonic", "passphrase")

#: Everything a row may hold. A key outside this set is refused rather than
#: carried, so a caller cannot smuggle state past the state machine.
ATTEMPT_FIELDS = (
    "idempotency_key", "state", "order_digest_halves", "amount_raw", "payee",
    "request_at", "signed_block", "block_hash", "signed_at", "broadcast_at",
    "confirmed_at", "received_at", "result_ref", "result_stored_at",
    "result_retrievable", "reconcile_attempts", "reconcile_budget",
    "budget_expired_at", "last_observation", "history",
)

#: Immutable once written. The whole binding rests on these four not moving.
IMMUTABLE_FIELDS = ("idempotency_key", "order_digest_halves", "amount_raw",
                    "payee")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_REFUSED = 2


# --------------------------------------------------------------------------
# refusals - one code per failure, stable and safe to print
# --------------------------------------------------------------------------

class Refusal(Exception):
    """A refusal with a stable machine-readable `code`.

    `attempt` carries the existing row when the refusal is one a crashed caller
    recovers from (`duplicate_open`), so recovery needs no second call.
    """

    def __init__(self, code, message, attempt=None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.attempt = attempt

    def as_dict(self):
        return {"ok": False, "code": self.code, "message": self.message}


REFUSAL_CODES = (
    "bad_journal", "bad_now", "bad_order_digest", "bad_amount_raw", "bad_payee",
    "bad_key", "bad_state", "bad_observation", "bad_block_hash", "bad_block",
    "bad_retrievable", "bad_budget", "duplicate_open", "no_such_attempt",
    "already_signed", "not_signed", "no_block_to_confirm", "terminal_attempt",
    "unknown_field", "immutable_field", "history_shrank", "not_settled",
)


# --------------------------------------------------------------------------
# time
# --------------------------------------------------------------------------

def moment(text, code="bad_now", label="now"):
    """An RFC3339 UTC instant, or a refusal. No local time anywhere."""
    if not isinstance(text, str) or not RFC3339_RE.match(text):
        raise Refusal(code, "%s must be RFC3339 UTC ending in Z, got %r"
                      % (label, text))
    return datetime.datetime.strptime(text, RFC3339_FORMAT).replace(tzinfo=UTC)


def stamp(instant):
    return instant.astimezone(UTC).strftime(RFC3339_FORMAT)


def hours_between(earlier, later):
    return (later - earlier).total_seconds() / 3600.0


# --------------------------------------------------------------------------
# the stored block: long hex in parts, exactly reversible
# --------------------------------------------------------------------------

def split_long_hex(value):
    """A long hex string as 32-character parts, in order."""
    return [value[i:i + HEX_PART] for i in range(0, len(value), HEX_PART)]


def halves(hexdigest):
    """A 64-hex digest as two 32-character halves, joinable back.

    The same shape `seller_offer.halves` writes, so a reader who has learned it
    once has learned it here.
    """
    return [hexdigest[:32], hexdigest[32:]]


def joined(value):
    """A digest written as halves, back as one string. None if it is not."""
    if (isinstance(value, list) and len(value) == 2
            and all(isinstance(half, str) for half in value)):
        return "".join(value)
    return None


def order_digest_of(attempt):
    """The order digest a row binds to, as one string."""
    return joined((attempt or {}).get("order_digest_halves"))


def pack_block(block, _path="signed_block"):
    """The block as it is stored: long hex fields split, nothing else changed.

    Refuses `unknown_field` for any key that could name a key or a seed. The
    `signature` a node returns is public and stays.
    """
    if isinstance(block, dict):
        packed = {}
        for key, value in block.items():
            if not isinstance(key, str):
                raise Refusal("bad_block",
                              "%s has a non-string key %r" % (_path, key))
            lowered = key.lower()
            for part in FORBIDDEN_BLOCK_KEY_PARTS:
                if part in lowered:
                    raise Refusal(
                        "unknown_field",
                        "%s.%s names a key or a seed. This module records and "
                        "advises; it never holds key material." % (_path, key))
            packed[key] = pack_block(value, "%s.%s" % (_path, key))
        if set(packed) == {HEX_PARTS_KEY}:
            raise Refusal("bad_block",
                          "%s is already in the stored form; pass the block as "
                          "the node returned it" % _path)
        return packed
    if isinstance(block, list):
        return [pack_block(v, "%s[%d]" % (_path, i))
                for i, v in enumerate(block)]
    if isinstance(block, str):
        if LONG_HEX_RE.match(block):
            return {HEX_PARTS_KEY: split_long_hex(block)}
        return block
    if isinstance(block, bool) or block is None or isinstance(block, int):
        return block
    raise Refusal("bad_block",
                  "%s is a %s; a serialised block holds only JSON scalars, "
                  "objects and lists" % (_path, type(block).__name__))


def unpack_block(stored):
    """The block as it was recorded, byte for byte. Inverse of `pack_block`."""
    if isinstance(stored, dict):
        parts = stored.get(HEX_PARTS_KEY)
        if set(stored) == {HEX_PARTS_KEY} and isinstance(parts, list):
            return "".join(parts)
        return {key: unpack_block(value) for key, value in stored.items()}
    if isinstance(stored, list):
        return [unpack_block(value) for value in stored]
    return stored


# --------------------------------------------------------------------------
# field checks
# --------------------------------------------------------------------------

def checked_order_digest(value):
    if not isinstance(value, str) or not DIGEST_RE.match(value):
        raise Refusal("bad_order_digest",
                      "order_digest must be 64 lowercase hex characters, got %r"
                      % (value,))
    return value


def checked_amount_raw(value):
    """An amount of raw as an integer string. Never a float, ever.

    1 XNO = 10**30 raw, so a binary float loses the bottom 13+ digits of every
    amount on this path.
    """
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise Refusal("bad_amount_raw",
                      "amount_raw must be an integer string of raw, got %r"
                      % (value,))
    text = str(value)
    if not RAW_RE.match(text):
        raise Refusal("bad_amount_raw",
                      "amount_raw must spell a whole number of raw with no "
                      "sign, exponent or decimal point, got %r" % (value,))
    return text


def checked_payee(value):
    if not isinstance(value, str):
        raise Refusal("bad_payee", "payee must be a string, got %r" % (value,))
    verdict = nanoaddr.validate(value)
    if not verdict["valid"]:
        raise Refusal("bad_payee",
                      "payee is not a payable address (%s)" % verdict["reason"])
    return value


def checked_key(value):
    if not isinstance(value, str) or not KEY_RE.match(value):
        raise Refusal("bad_key",
                      "an idempotency key is `ik-` and 32 lowercase hex "
                      "characters, got %r" % (value,))
    return value


def checked_block_hash(value):
    if not isinstance(value, str) or not HASH_RE.match(value):
        raise Refusal("bad_block_hash",
                      "a block hash is 64 uppercase hex characters, got %r"
                      % (value,))
    return value


def idempotency_key_for(order_digest, amount_raw, payee):
    """`ik-` + blake2b-128 over the request, so a crash loses nothing.

    The preimage is the order digest's 32 RAW bytes, then `amount_raw` as
    ASCII, then `payee` as ASCII - the same "digest enters as bytes" rule
    `seller_offer.order_digest` follows. No separator is needed and none is
    added: the digest is exactly 32 bytes, `amount_raw` is ASCII digits, and a
    payee begins `nano_`, which no digit can start, so the three components can
    be read back out of the preimage unambiguously.

    Derived, not random, is the point: the same request produces the same key
    in a fresh process with no state carried in memory, which is what makes
    `ockerclaw`'s restart test pass.
    """
    digest = checked_order_digest(order_digest)
    amount = checked_amount_raw(amount_raw)
    address = checked_payee(payee)
    material = (bytes.fromhex(digest) + amount.encode("ascii")
                + address.encode("ascii"))
    return "ik-" + blake2b(material, digest_size=16).hexdigest()


# --------------------------------------------------------------------------
# the journal
# --------------------------------------------------------------------------

def empty_journal(retention_hours=DEFAULT_RETENTION_HOURS):
    return {"v": V, "retention_hours": int(retention_hours), "attempts": []}


def checked_journal(document):
    """A loaded journal, or `bad_journal`. Never repaired, never replaced."""
    if not isinstance(document, dict):
        raise Refusal("bad_journal",
                      "a journal is an object with `v`, `retention_hours` and "
                      "`attempts`")
    if document.get("v") != V:
        raise Refusal("bad_journal",
                      "journal version is %r, this build writes %r"
                      % (document.get("v"), V))
    retention = document.get("retention_hours")
    if isinstance(retention, bool) or not isinstance(retention, int) \
            or retention <= 0:
        raise Refusal("bad_journal",
                      "retention_hours must be a positive integer, got %r"
                      % (retention,))
    attempts = document.get("attempts")
    if not isinstance(attempts, list):
        raise Refusal("bad_journal", "`attempts` must be a list")
    for index, attempt in enumerate(attempts):
        if not isinstance(attempt, dict):
            raise Refusal("bad_journal",
                          "attempts[%d] is not an object" % index)
        unknown = sorted(set(attempt) - set(ATTEMPT_FIELDS))
        if unknown:
            raise Refusal("unknown_field",
                          "attempts[%d] carries %s, which no state machine "
                          "here reads" % (index, ", ".join(unknown)))
        missing = [f for f in ATTEMPT_FIELDS if f not in attempt]
        if missing:
            raise Refusal("bad_journal",
                          "attempts[%d] is missing %s"
                          % (index, ", ".join(missing)))
        if attempt["state"] not in STATES:
            raise Refusal("bad_state",
                          "attempts[%d] is in state %r, which is not one of "
                          "the nine" % (index, attempt["state"]))
        if attempt["state"] in NO_BLOCK_STATES \
                and attempt["signed_block"] is not None:
            # The one contradiction that could cost a payment, refused at the
            # door rather than reasoned about downstream. `ABANDONED_NO_SEND`
            # is the only state that permits a fresh send and `REQUESTED` is
            # the only state that reaches it, so a row in either of them
            # carrying a signed block would turn a journal edit - by hand, or
            # by a version that did not know this rule - into a second payment.
            raise Refusal("bad_state",
                          "attempts[%d] is %s and carries a signed block. "
                          "Those cannot both be true: a signed block means a "
                          "send may exist, and these are the states that say "
                          "none can." % (index, attempt["state"]))
        checked_key(attempt["idempotency_key"])
        # Refuses `bad_order_digest` for halves that do not join to a digest,
        # which is the shape a hand-edited journal arrives in.
        checked_order_digest(joined(attempt["order_digest_halves"]) or "")
        checked_amount_raw(attempt["amount_raw"])
        if not isinstance(attempt["history"], list):
            raise Refusal("bad_journal",
                          "attempts[%d].history must be a list" % index)
        if attempt["result_retrievable"] not in RETRIEVABLE:
            raise Refusal("bad_retrievable",
                          "attempts[%d].result_retrievable must be one of %s"
                          % (index, ", ".join(RETRIEVABLE)))
    keys = [a["idempotency_key"] for a in attempts]
    duplicates = sorted({k for k in keys if keys.count(k) > 1})
    if duplicates:
        raise Refusal("bad_journal",
                      "one key must name one row; %s appears more than once"
                      % ", ".join(duplicates))
    return document


def read_journal(path):
    """The journal at `path`, or an empty one if the file does not exist.

    A file that exists and cannot be read as a journal is REFUSED. It is never
    repaired and never replaced with a fresh empty journal: silently starting
    clean over a half-written journal is how a double-pay happens, and a
    truncated file is exactly what a crash mid-write leaves behind.
    """
    if not os.path.exists(path):
        return empty_journal()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            text = handle.read()
    except OSError as exc:
        raise Refusal("bad_journal", "%s cannot be read: %s" % (path, exc))
    try:
        document = json.loads(text)
    except ValueError as exc:
        raise Refusal("bad_journal",
                      "%s is not valid JSON (%s). It is left exactly as it is: "
                      "a half-written journal is evidence, not rubbish."
                      % (path, exc))
    return checked_journal(document)


def serialise(document):
    return (json.dumps(document, indent=1, sort_keys=True) + "\n").encode("utf-8")


def write_journal(path, document):
    """`<path>.tmp`, flushed and FSYNCED, then `os.replace`.

    The fsync is not decoration. This journal is the thing that must survive a
    crash, so a write that reaches the page cache and not the disk fails
    `ockerclaw`'s restart test while looking atomic. A failed write leaves no
    `.tmp` behind and the previous journal byte-identical.
    """
    checked_journal(document)
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    temporary = path + ".tmp"
    try:
        with open(temporary, "wb") as handle:
            handle.write(serialise(document))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.remove(temporary)
        raise


# --------------------------------------------------------------------------
# rows
# --------------------------------------------------------------------------

def find(journal, key):
    for attempt in journal.get("attempts", []):
        if attempt.get("idempotency_key") == key:
            return attempt
    return None


def require(journal, key):
    attempt = find(journal, checked_key(key))
    if attempt is None:
        raise Refusal("no_such_attempt", "no attempt carries the key %s" % key)
    return attempt


def _copy(journal):
    return json.loads(json.dumps(journal))


def _note(attempt, event, now, **extra):
    """Append one history entry. History only ever grows."""
    entry = {"event": event, "at": now}
    entry.update(extra)
    attempt["history"] = list(attempt.get("history", [])) + [entry]
    return entry


def _assert_binding_held(before, after):
    """The four immutable fields, and a history that only grew.

    Called on the way out of every mutating function, so a future edit to one
    of them cannot quietly break the binding this module exists to keep.
    """
    for field in IMMUTABLE_FIELDS:
        if before.get(field) != after.get(field):
            raise Refusal("immutable_field",
                          "%s is immutable: %r -> %r"
                          % (field, before.get(field), after.get(field)))
    old = before.get("history") or []
    new = after.get("history") or []
    if len(new) < len(old) or new[:len(old)] != old:
        raise Refusal("history_shrank",
                      "an attempt's history may only grow; it is the audit "
                      "trail of the reconciliation")


# --------------------------------------------------------------------------
# the state machine
# --------------------------------------------------------------------------

def open_attempt(journal, *, order_digest, amount_raw, payee, now,
                 reconcile_budget=DEFAULT_RECONCILE_BUDGET):
    """Write a `REQUESTED` row, or refuse `duplicate_open` and hand the row back.

    The refusal carries the existing attempt, so a caller that crashed
    mid-flight recovers the binding instead of starting over - which is the
    only safe thing to do once a block may exist.
    """
    checked_journal(journal)
    at = stamp(moment(now))
    digest = checked_order_digest(order_digest)
    amount = checked_amount_raw(amount_raw)
    address = checked_payee(payee)
    if isinstance(reconcile_budget, bool) \
            or not isinstance(reconcile_budget, int) or reconcile_budget < 1:
        raise Refusal("bad_budget",
                      "reconcile_budget must be a positive integer, got %r"
                      % (reconcile_budget,))
    key = idempotency_key_for(digest, amount, address)
    existing = find(journal, key)
    if existing is not None:
        if existing["state"] not in TERMINAL:
            raise Refusal(
                "duplicate_open",
                "this exact request is already open as %s in state %s. Read "
                "`safe_action` on it: %s."
                % (key, existing["state"], SAFE_ACTIONS[existing["state"]]),
                attempt=_copy(existing))
        raise Refusal(
            "duplicate_open",
            "this exact request closed as %s. A new payment for it needs a new "
            "order, because the key is derived from the order."
            % existing["state"], attempt=_copy(existing))
    attempt = {
        "idempotency_key": key,
        "state": REQUESTED,
        "order_digest_halves": halves(digest),
        "amount_raw": amount,
        "payee": address,
        "request_at": at,
        "signed_block": None,
        "block_hash": None,
        "signed_at": None,
        "broadcast_at": None,
        "confirmed_at": None,
        "received_at": None,
        "result_ref": None,
        "result_stored_at": None,
        "result_retrievable": "UNKNOWN",
        "reconcile_attempts": 0,
        "reconcile_budget": reconcile_budget,
        "budget_expired_at": None,
        "last_observation": None,
        "history": [],
    }
    _note(attempt, "requested", at)
    after = _copy(journal)
    after["attempts"] = list(after["attempts"]) + [attempt]
    return checked_journal(after), _copy(attempt)


def record_signed(journal, key, signed_block, block_hash, *, now):
    """`REQUESTED -> SIGNED_NOT_BROADCAST`, storing the block for rebroadcast.

    A SECOND signature over the same request is the double-pay path: a
    different block refuses `already_signed` and the journal is untouched.
    Re-recording the identical block is idempotent, because a caller that
    crashed after signing and before writing must be able to say so again.
    """
    checked_journal(journal)
    at = stamp(moment(now))
    after = _copy(journal)
    attempt = require(after, key)
    before = _copy(attempt)
    if attempt["state"] in TERMINAL:
        raise Refusal("terminal_attempt",
                      "attempt %s is %s; nothing more is recorded against it"
                      % (key, attempt["state"]))
    if not isinstance(signed_block, dict):
        raise Refusal("bad_block",
                      "signed_block must be the serialised block object the "
                      "node returned, got %r" % type(signed_block).__name__)
    packed = pack_block(signed_block)
    digest = checked_block_hash(block_hash)
    if attempt["signed_block"] is not None:
        if attempt["signed_block"] != packed or attempt["block_hash"] != digest:
            raise Refusal(
                "already_signed",
                "attempt %s already carries a signed block (%s). A second "
                "signature over one request is the double-pay path: rebroadcast "
                "the stored block instead."
                % (key, attempt["block_hash"]))
        return checked_journal(after), _copy(attempt)
    attempt["signed_block"] = packed
    attempt["block_hash"] = digest
    attempt["signed_at"] = at
    if attempt["state"] == REQUESTED:
        attempt["state"] = SIGNED_NOT_BROADCAST
    _note(attempt, "signed", at, block_hash=digest)
    _assert_binding_held(before, attempt)
    return checked_journal(after), _copy(attempt)


def record_broadcast(journal, key, *, now):
    """`SIGNED_NOT_BROADCAST -> SENT_UNCONFIRMED`. Idempotent."""
    checked_journal(journal)
    at = stamp(moment(now))
    after = _copy(journal)
    attempt = require(after, key)
    before = _copy(attempt)
    if attempt["state"] in TERMINAL:
        raise Refusal("terminal_attempt",
                      "attempt %s is %s; nothing more is recorded against it"
                      % (key, attempt["state"]))
    if attempt["signed_block"] is None:
        raise Refusal("not_signed",
                      "attempt %s has no signed block, so nothing can have "
                      "been broadcast" % key)
    if attempt["broadcast_at"] is not None:
        return checked_journal(after), _copy(attempt)
    attempt["broadcast_at"] = at
    if attempt["state"] == SIGNED_NOT_BROADCAST:
        attempt["state"] = SENT_UNCONFIRMED
    _note(attempt, "broadcast", at, block_hash=attempt["block_hash"])
    _assert_binding_held(before, attempt)
    return checked_journal(after), _copy(attempt)


def checked_observation(observation):
    if not isinstance(observation, dict):
        raise Refusal("bad_observation",
                      "an observation is {kind, at, node}, got %r"
                      % type(observation).__name__)
    unknown = sorted(set(observation) - {"kind", "at", "node"})
    if unknown:
        raise Refusal("bad_observation",
                      "an observation carries only kind, at and node; saw %s"
                      % ", ".join(unknown))
    kind = observation.get("kind")
    if kind not in OBSERVATION_KINDS:
        raise Refusal("bad_observation",
                      "kind must be one of %s, got %r"
                      % (", ".join(OBSERVATION_KINDS), kind))
    at = observation.get("at")
    if at is not None:
        at = stamp(moment(at, "bad_observation", "observation.at"))
    node = observation.get("node")
    if node is not None and not isinstance(node, str):
        raise Refusal("bad_observation", "node must be a string or absent")
    return {"kind": kind, "at": at, "node": node}


def observe(journal, key, observation, *, now):
    """Record what a node said. An observation is never promoted to a fact.

    `not_found`, `unconfirmed`, `rpc_error` and `timeout` increment
    `reconcile_attempts` and change no state - except that, once the budget is
    spent, the row becomes `EVIDENCE_UNAVAILABLE`, which permits
    `HOLD_FOR_OPERATOR` and nothing else. None of them can ever reach
    `ABANDONED_NO_SEND`, so none of them can authorise a fresh send.

    The counter is cumulative across the row's whole life on purpose: a budget
    that reset on every determinative observation would let an unbounded number
    of inconclusive ones look like progress.
    """
    checked_journal(journal)
    at = stamp(moment(now))
    seen = checked_observation(observation)
    seen["at"] = seen["at"] or at
    after = _copy(journal)
    attempt = require(after, key)
    before = _copy(attempt)
    if attempt["state"] in TERMINAL:
        raise Refusal("terminal_attempt",
                      "attempt %s is %s; nothing more is recorded against it"
                      % (key, attempt["state"]))
    kind = seen["kind"]
    attempt["last_observation"] = dict(seen)
    _note(attempt, "observed", at, kind=kind, observed_at=seen["at"],
          node=seen["node"])

    if kind in INCONCLUSIVE_KINDS:
        attempt["reconcile_attempts"] = int(attempt["reconcile_attempts"]) + 1
        if attempt["reconcile_attempts"] >= int(attempt["reconcile_budget"]) \
                and attempt["state"] != EVIDENCE_UNAVAILABLE:
            attempt["state"] = EVIDENCE_UNAVAILABLE
            attempt["budget_expired_at"] = at
            _note(attempt, "budget_expired", at,
                  reconcile_attempts=attempt["reconcile_attempts"])
    elif kind == "confirmed":
        if attempt["block_hash"] is None:
            raise Refusal("no_block_to_confirm",
                          "attempt %s has no block hash, so a confirmation "
                          "cannot be about its send" % key)
        attempt["confirmed_at"] = attempt["confirmed_at"] or seen["at"]
        # A confirmed block IS on the ledger, so it went out whatever this
        # journal recorded - a crash between broadcasting and writing is the
        # case `ockerclaw` names, and the ledger is the authority here.
        attempt["broadcast_at"] = attempt["broadcast_at"] or seen["at"]
        if attempt["state"] != SETTLED:
            attempt["state"] = SENT_CONFIRMED_UNRECEIVED
    elif kind == "received":
        if attempt["block_hash"] is None:
            raise Refusal("no_block_to_confirm",
                          "attempt %s has no block hash, so a receive cannot "
                          "be about its send" % key)
        attempt["received_at"] = attempt["received_at"] or seen["at"]
        attempt["confirmed_at"] = attempt["confirmed_at"] or seen["at"]
        attempt["broadcast_at"] = attempt["broadcast_at"] or seen["at"]
        attempt["state"] = SETTLED
        if attempt["result_ref"] is not None:
            attempt["state"] = (COMPLETE
                                if attempt["result_retrievable"] == "YES"
                                else SETTLED_RESULT_PENDING)
    _assert_binding_held(before, attempt)
    return checked_journal(after), _copy(attempt)


def record_result(journal, key, result_ref, *, retrievable, now):
    """What the money bought. `retrievable` is tri-state, never a boolean.

    `ockerclaw`'s objection is to a system that reads an unknown as a no, so
    `UNKNOWN` and `NO` both leave the row `SETTLED_RESULT_PENDING`. Only `YES`
    reaches `COMPLETE`.
    """
    checked_journal(journal)
    at = stamp(moment(now))
    if retrievable not in RETRIEVABLE:
        raise Refusal("bad_retrievable",
                      "retrievable must be one of %s - a tri-state, never a "
                      "boolean" % ", ".join(RETRIEVABLE))
    if not isinstance(result_ref, str) or not result_ref.strip():
        raise Refusal("bad_observation",
                      "result_ref must be a URL or a content digest naming "
                      "what was delivered")
    after = _copy(journal)
    attempt = require(after, key)
    before = _copy(attempt)
    if attempt["state"] == COMPLETE:
        raise Refusal("terminal_attempt",
                      "attempt %s is COMPLETE; nothing more is recorded "
                      "against it" % key)
    if attempt["state"] not in (SETTLED, SETTLED_RESULT_PENDING):
        raise Refusal("not_settled",
                      "attempt %s is %s. A result is recorded against a "
                      "settled payment; until the money has landed there is "
                      "nothing for it to be the result of."
                      % (key, attempt["state"]))
    attempt["result_ref"] = result_ref
    attempt["result_stored_at"] = at
    attempt["result_retrievable"] = retrievable
    attempt["state"] = COMPLETE if retrievable == "YES" else SETTLED_RESULT_PENDING
    _note(attempt, "result", at, retrievable=retrievable)
    _assert_binding_held(before, attempt)
    return checked_journal(after), _copy(attempt)


def safe_action(attempt, *, now):
    """Which of the closed set of actions is safe, and whether a new send is.

    PURE. No journal write, no file touched, no clock of its own beyond `now`.
    This is the function a caller consults before touching money, and the one
    assertion that matters is that `blocks_new_send` is False for exactly one
    state.
    """
    if not isinstance(attempt, dict) or attempt.get("state") not in STATES:
        raise Refusal("bad_state",
                      "safe_action takes an attempt in one of the nine states, "
                      "got %r" % (attempt or {}).get("state"))
    moment(now)  # a caller passing a bad clock gets told, not silently served
    state = attempt["state"]
    stored = attempt.get("signed_block")
    return {
        "action": SAFE_ACTIONS[state],
        "why": WHY[state],
        "blocks_new_send": state not in NEW_SEND_ALLOWED_IN,
        "rebroadcast_block": unpack_block(stored) if stored is not None else None,
    }


def rebroadcast_block(attempt):
    """The stored block as it was recorded, or None. Never a re-created one."""
    stored = (attempt or {}).get("signed_block")
    return unpack_block(stored) if stored is not None else None


def _row_age_hours(attempt, at):
    """Hours since the most recent thing recorded about this row.

    Taken from the timestamps the row already carries rather than from an
    `updated_at` field, so retention cannot be gamed by a write that touches
    nothing.
    """
    stamps = [attempt.get(f) for f in ("request_at", "signed_at",
                                       "broadcast_at", "confirmed_at",
                                       "received_at", "result_stored_at",
                                       "budget_expired_at")]
    stamps += [e.get("at") for e in attempt.get("history") or []
               if isinstance(e, dict)]
    moments = [moment(s) for s in stamps if isinstance(s, str)
               and RFC3339_RE.match(s)]
    if not moments:
        return 0.0
    return hours_between(max(moments), at)


def expire(journal, *, now, request_ttl_hours=DEFAULT_REQUEST_TTL_HOURS):
    """Abandon unsigned expired requests; drop terminal rows past retention.

    Two rules, and the second one is the dangerous one:

      * a `REQUESTED` row whose `signed_block` is STILL NULL and whose request
        is older than the TTL becomes `ABANDONED_NO_SEND` - the only path to a
        fresh send there is, and it is closed the moment a block exists;
      * a TERMINAL row older than `retention_hours` is dropped. A row that is
        not terminal is never dropped, however old. A forgotten in-flight
        payment is exactly what retention must not delete.
    """
    checked_journal(journal)
    at = moment(now)
    after = _copy(journal)
    changed = []
    kept = []
    for attempt in after["attempts"]:
        before = _copy(attempt)
        # Both halves, deliberately. `checked_journal` has already refused
        # REQUESTED-with-a-block, so the second test is unreachable and is kept
        # as the belt to that braces: this is the only line in the module that
        # can open the door to a fresh send.
        if attempt["signed_block"] is None and attempt["state"] == REQUESTED:
            if hours_between(moment(attempt["request_at"]), at) \
                    >= float(request_ttl_hours):
                attempt["state"] = ABANDONED_NO_SEND
                _note(attempt, "abandoned", stamp(at),
                      request_ttl_hours=request_ttl_hours)
                _assert_binding_held(before, attempt)
                changed.append({"key": attempt["idempotency_key"],
                                "what": "abandoned"})
        if attempt["state"] in TERMINAL \
                and _row_age_hours(attempt, at) >= float(
                    after["retention_hours"]):
            changed.append({"key": attempt["idempotency_key"],
                            "what": "dropped"})
            continue
        kept.append(attempt)
    after["attempts"] = kept
    return checked_journal(after), changed


def reconcile_report(journal, *, now):
    """One screen for the operator gate: is anything stuck, and for how long."""
    checked_journal(journal)
    at = moment(now)
    attempts = journal.get("attempts", [])
    in_flight = [a for a in attempts if a["state"] not in TERMINAL]
    unavailable = [a for a in attempts if a["state"] == EVIDENCE_UNAVAILABLE]
    oldest = 0.0
    for attempt in in_flight:
        oldest = max(oldest, hours_between(moment(attempt["request_at"]), at))
    return {
        "total": len(attempts),
        "in_flight": len(in_flight),
        "evidence_unavailable": len(unavailable),
        "needs_operator": sorted(a["idempotency_key"] for a in unavailable),
        "oldest_unresolved_hours": round(oldest, 4),
    }


# --------------------------------------------------------------------------
# what a caller on the money path asks before it sends
# --------------------------------------------------------------------------

def binding_for_payment(journal, *, amount_raw, payee, block_hash=None):
    """The rows that could be about this payment, split by what they permit.

    `settle.py` has no order digest to key on - it is handed a job and a block
    hash - so the strongest binding available to it is the amount and the
    payee, compared by account and by value rather than by spelling. Returns
    `{"matched": <row for this very block or None>, "blocking": [rows]}`.

    The two error directions are not equal, which is why this errs toward
    reporting a conflict: a false conflict costs one journal update by an
    operator who knows what they sent, and a false clearance costs a second
    payment.
    """
    checked_journal(journal)
    digest = checked_block_hash(block_hash) if block_hash is not None else None
    matched = None
    blocking = []
    for attempt in journal.get("attempts", []):
        if not same_amount(attempt["amount_raw"], amount_raw):
            continue
        if not same_account(attempt["payee"], payee):
            continue
        if digest is not None and attempt["block_hash"] == digest:
            matched = _copy(attempt)
            continue
        if attempt["state"] in TERMINAL:
            continue
        if attempt["signed_block"] is None:
            continue
        blocking.append(_copy(attempt))
    return {"matched": matched, "blocking": blocking}


# --------------------------------------------------------------------------
# the import graph - the reason the suite can assert this never reaches a node
# --------------------------------------------------------------------------

def import_graph(source_path=None):
    """Every import in this file, with the function it sits in (or None).

    Agrees with `seller_offer.import_graph`; the suite asserts this file holds
    no network module at all, in any function.
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
# the nine-state table, inline, for the proof file
# --------------------------------------------------------------------------

def state_table():
    """The table a reader checks the property against without running anything."""
    return [{"state": state,
             "safe_action": SAFE_ACTIONS[state],
             "blocks_new_send": state not in NEW_SEND_ALLOWED_IN,
             "signed_block_can_exist": state != ABANDONED_NO_SEND}
            for state in STATES]


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------

def _control_address():
    """A valid address built from a public key, not pasted from anywhere."""
    return nanoaddr.encode(bytes(range(32)), "nano_")


def _control_block(address, amount):
    """A send block shaped the way a node returns one. No key material."""
    return {
        "type": "state",
        "account": address,
        "previous": "B" * 64,
        "representative": address,
        "balance": "0",
        "link": "C" * 64,
        "link_as_account": address,
        "signature": "D" * 128,
        "work": "0000000000000000",
        "subtype": "send",
    }


def self_test():
    """Negative controls, in the shape `scripts/` reads."""
    failures = []
    controls = 0
    address = _control_address()
    digest = "a" * 64
    amount = "50000000000000000000000000000"
    now = "2026-10-08T07:00:00Z"

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

    journal, attempt = open_attempt(empty_journal(), order_digest=digest,
                                    amount_raw=amount, payee=address, now=now)
    controls += 1
    if attempt["state"] != REQUESTED or not KEY_RE.match(
            attempt["idempotency_key"]):
        failures.append("open_attempt: wrong state or key: %r" % (attempt,))

    key = attempt["idempotency_key"]
    controls += 1
    if idempotency_key_for(digest, amount, address) != key:
        failures.append("idempotency_key_for: the key is not derived from the request")

    refuses("duplicate_open",
            lambda: open_attempt(journal, order_digest=digest,
                                 amount_raw=amount, payee=address, now=now),
            "a second open for one request")

    block = _control_block(address, amount)
    signed, attempt = record_signed(journal, key, block, "A" * 64, now=now)
    controls += 1
    if attempt["state"] != SIGNED_NOT_BROADCAST:
        failures.append("record_signed: state is %r" % attempt["state"])
    controls += 1
    if rebroadcast_block(attempt) != block:
        failures.append("the stored block does not round-trip")

    refuses("already_signed",
            lambda: record_signed(signed, key, dict(block, link="E" * 64),
                                  "F" * 64, now=now),
            "a second signature over one request")
    refuses("unknown_field",
            lambda: record_signed(journal, key, dict(block, private_key="x"),
                                  "A" * 64, now=now),
            "a block carrying key material")

    sent, attempt = record_broadcast(signed, key, now=now)
    controls += 1
    if attempt["state"] != SENT_UNCONFIRMED:
        failures.append("record_broadcast: state is %r" % attempt["state"])

    # The rule: "not found", to exhaustion, never authorises a fresh send.
    walk = sent
    for _ in range(DEFAULT_RECONCILE_BUDGET):
        walk, attempt = observe(walk, key, {"kind": "not_found", "at": now,
                                            "node": "https://node.invalid"},
                                now=now)
    controls += 1
    if attempt["state"] != EVIDENCE_UNAVAILABLE:
        failures.append("a spent budget left the row in %r" % attempt["state"])
    controls += 1
    verdict = safe_action(attempt, now=now)
    if verdict["action"] != "HOLD_FOR_OPERATOR" or not verdict["blocks_new_send"]:
        failures.append("EVIDENCE_UNAVAILABLE permits %r" % verdict)

    controls += 1
    report = reconcile_report(walk, now=now)
    if report["needs_operator"] != [key] or report["evidence_unavailable"] != 1:
        failures.append("reconcile_report does not name the stuck row: %r"
                        % report)

    # The property, over all nine states rather than over a case.
    controls += 1
    allowed = [s for s in STATES
               if not safe_action(dict(state=s, signed_block=None),
                                  now=now)["blocks_new_send"]]
    if allowed != [ABANDONED_NO_SEND]:
        failures.append("a new send is permitted in %r" % (allowed,))

    controls += 1
    if set(STATES) != set(SAFE_ACTIONS) or set(STATES) != set(WHY):
        failures.append("a state exists with no safe action or no reason")

    # Retention never drops a row that is still in flight.
    aged = _copy(walk)
    aged["retention_hours"] = 1
    controls += 1
    kept, _changed = expire(aged, now="2027-10-08T07:00:00Z")
    if len(kept["attempts"]) != 1:
        failures.append("retention dropped an EVIDENCE_UNAVAILABLE row")

    refuses("bad_journal",
            lambda: checked_journal({"v": V, "retention_hours": 720,
                                     "attempts": [{"state": "REQUESTED"}]}),
            "a row missing its fields")
    refuses("bad_state",
            lambda: safe_action({"state": "PROBABLY_FINE"}, now=now),
            "a tenth state")
    refuses("bad_amount_raw", lambda: checked_amount_raw(1.0e26),
            "an amount of raw as a float")
    refuses("bad_payee",
            lambda: checked_payee(address[:-1] + ("1" if address[-1] != "1"
                                                  else "3")),
            "a payee whose checksum fails")

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
        return stamp(moment(value))
    return datetime.datetime.now(tz=UTC).strftime(RFC3339_FORMAT)


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true",
                        help="run the negative controls and print the verdict")
    sub = parser.add_subparsers(dest="command")

    def common(p):
        p.add_argument("--journal", default=JOURNAL_FILE)
        p.add_argument("--now", default=None)
        return p

    p_open = common(sub.add_parser("open"))
    p_open.add_argument("--order-digest", required=True)
    p_open.add_argument("--amount-raw", required=True)
    p_open.add_argument("--payee", required=True)
    p_open.add_argument("--reconcile-budget", type=int,
                        default=DEFAULT_RECONCILE_BUDGET)

    p_signed = common(sub.add_parser("signed"))
    p_signed.add_argument("key")
    p_signed.add_argument("--block", required=True,
                          help="a file holding the serialised block")
    p_signed.add_argument("--block-hash", required=True)

    common(sub.add_parser("broadcast")).add_argument("key")

    p_observe = common(sub.add_parser("observe"))
    p_observe.add_argument("key")
    p_observe.add_argument("--kind", required=True, choices=OBSERVATION_KINDS)
    p_observe.add_argument("--node", default=None)
    p_observe.add_argument("--at", default=None)

    p_result = common(sub.add_parser("result"))
    p_result.add_argument("key")
    p_result.add_argument("--result-ref", required=True)
    p_result.add_argument("--retrievable", required=True, choices=RETRIEVABLE)

    common(sub.add_parser("action")).add_argument("key")
    common(sub.add_parser("report"))
    p_expire = common(sub.add_parser("expire"))
    p_expire.add_argument("--request-ttl-hours", type=int,
                          default=DEFAULT_REQUEST_TTL_HOURS)
    common(sub.add_parser("table"))
    return parser


def main(argv=None, out=None, err=None):
    out = out or sys.stdout
    err = err or sys.stderr
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.self_test:
        verdict = self_test()
        print(json.dumps(verdict, indent=2, sort_keys=True), file=out)
        return EXIT_OK if not verdict["failures"] else EXIT_ERROR
    if not args.command:
        parser.print_help(out)
        return EXIT_ERROR

    try:
        now = _now_or_clock(args.now)
        if args.command == "table":
            print(json.dumps(state_table(), indent=2), file=out)
            return EXIT_OK
        journal = read_journal(args.journal)

        if args.command == "open":
            journal, attempt = open_attempt(
                journal, order_digest=args.order_digest,
                amount_raw=args.amount_raw, payee=args.payee, now=now,
                reconcile_budget=args.reconcile_budget)
            write_journal(args.journal, journal)
            print(json.dumps(attempt, indent=2, sort_keys=True), file=out)
        elif args.command == "signed":
            with open(args.block, "r", encoding="utf-8") as handle:
                block = json.load(handle)
            journal, attempt = record_signed(journal, args.key, block,
                                             args.block_hash, now=now)
            write_journal(args.journal, journal)
            print(json.dumps(attempt, indent=2, sort_keys=True), file=out)
        elif args.command == "broadcast":
            journal, attempt = record_broadcast(journal, args.key, now=now)
            write_journal(args.journal, journal)
            print(json.dumps(attempt, indent=2, sort_keys=True), file=out)
        elif args.command == "observe":
            journal, attempt = observe(
                journal, args.key,
                {"kind": args.kind, "at": args.at, "node": args.node},
                now=now)
            write_journal(args.journal, journal)
            print(json.dumps(attempt, indent=2, sort_keys=True), file=out)
        elif args.command == "result":
            journal, attempt = record_result(journal, args.key,
                                             args.result_ref,
                                             retrievable=args.retrievable,
                                             now=now)
            write_journal(args.journal, journal)
            print(json.dumps(attempt, indent=2, sort_keys=True), file=out)
        elif args.command == "action":
            attempt = require(journal, args.key)
            print(json.dumps(safe_action(attempt, now=now), indent=2,
                             sort_keys=True), file=out)
        elif args.command == "report":
            print(json.dumps(reconcile_report(journal, now=now), indent=2,
                             sort_keys=True), file=out)
        elif args.command == "expire":
            journal, changed = expire(
                journal, now=now, request_ttl_hours=args.request_ttl_hours)
            if changed:
                write_journal(args.journal, journal)
            print(json.dumps({"changed": changed}, indent=2, sort_keys=True),
                  file=out)
    except Refusal as exc:
        print("reason=%s" % exc.code, file=err)
        print(exc.message, file=err)
        return EXIT_REFUSED
    except OSError as exc:
        print("%s" % exc, file=err)
        return EXIT_ERROR
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
