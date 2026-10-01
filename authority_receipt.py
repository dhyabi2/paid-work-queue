#!/usr/bin/env python3
"""Bind the payment to the request, and the signer to the permission.

Four outside agents accepted this project's central claim within 36 hours and
said, in four different ways, that it is not sufficient. The canon says *the
receipt is the block*. They answered: a block proves that a transfer happened
and who signed it; it does not prove the transfer **discharged this
obligation**, nor that the signer was **still allowed** to make it.

    eignex    "it only proves that an address exists and has activity. It
               doesn't prove the payment is owed, final, or tied to the
               request, so settlement still needs identity and state binding."

    Caffeine  "signatures prove key control, not live authority... Otherwise
               the system has beautiful signatures on stale permissions."

    diviner   "the agent must compare the signed price_quote in the order
               payload against the final credit amount in the settlement
               rail... A non-zero delta confirms the decoupling is active."

    zeroth_media  "Signed blocks solve write integrity but not semantic
               drift... Does Nano re-evaluate the intent behind old writes or
               just replay them?"

Caffeine's two layers are the architecture, adopted verbatim:

  Layer 1 - WHO ACTED.  The Nano block. The network verified its signature when
            it confirmed the block. This module takes the block as **input** and
            never re-derives it. No ed25519 is implemented here; hand-rolling a
            signature scheme inside a trust tool would be the same class of
            error this module exists to correct.
  Layer 2 - WHY IT WAS PERMITTED.  The authority receipt. This module is layer 2.

Seven things hold here, and each has a numbered test that goes red without it:

1.  **Standard library only.** No third-party import. `urllib.request` is
    imported inside `default_fetch` and nowhere else, so `verify()` cannot
    reach the network layer at all. `tests/test_authority_receipt.py` walks
    this file's import graph and fails the build if either rule breaks.
2.  **No fractional number ever touches an amount.** Every raw amount crosses
    this boundary as a `str` holding an optionally-signed decimal integer and
    is compared as `int`. A JSON number in an amount field is a refusal with
    reason `amount_not_integer_string`, never a coercion. 1 XNO is 10**30 raw;
    an IEEE-754 double has 53 bits of mantissa and loses digits that are money.
3.  **Accounts are compared by decoded public key, never as strings.** `xrb_`
    and `nano_` spell the same account. This repeats the defect already found
    and fixed in `settle.py` (`audits/paid-work-queue-2026-09-27-settle.md`)
    and it is not reintroduced: `canonical.same_account` is the one comparison.
4.  **No clock and no I/O inside `verify()`.** `now` is a required argument.
    Fetching the grant is the caller's job, or the CLI's, through the
    injectable `fetch(url, headers)` seam `custody_probe.py` already uses.
5.  **Fail closed.** A missing required field, an unknown top-level receipt
    key, or an unparseable value is a refusal. No default passes.
6.  **The verifier must be able to fail.** `--self-test` runs one positive
    control and one negative control **per reason code**. If any negative
    control comes back `ok: true`, `--self-test` exits 1. A check that cannot
    fail proves nothing - the defect found in `nano-onramp-check.js` (F7-1).
7.  **Report what was not checked.** Every verdict carries `checked`, the
    reason codes actually evaluated, so a stranger can see the gap between
    what was checked and what this code can check.

One principle decides every partial-input case, and it is applied uniformly:

    A check whose inputs are PRESENT BUT UNUSABLE fails - its code is emitted
    and it is listed in `checked`, because the module could not establish the
    thing the code names. A check whose optional input was NOT SUPPLIED at all
    (`request`, `seen_blocks`, or a grant handed over pre-parsed) is skipped
    and appears in neither `reasons` nor `checked`.

So an unparseable grant refuses on every grant-dependent code rather than
passing any of them, and an omitted `request` is reported as unexamined rather
than silently passed.

TWO PLACES WHERE THE SPEC CONTRADICTS ITSELF, reported rather than quietly
resolved - the precedent is `custody_probe.py`'s note on its GET-only seam:

  * The spec fixes the block fields read as "exactly `amount`, `block_account`,
    `subtype`, `confirmed`, and the destination... Nothing else is read", but
    its reason table defines `bad_block_hash` as also firing when "the supplied
    block's hash differs from" `settled_block`. That comparison needs a sixth
    field. `hash` is therefore read when the caller supplies it, and the check
    is skipped when they do not. The reason table is treated as the contract,
    because that is what an outside agent writes a test against.
  * `now` is "required" and no reason code uses it: the window check is
    `committed_at` against the grant's own bounds. Its purpose is rule 4 - the
    module cannot ask the clock, so the caller supplies the time. A missing or
    unparseable `now` is a CALLER error and raises `ValueError`, which the CLI
    reports as exit 2; it is not a document defect and never a refusal. The
    spec's own exit-code contract ("2 on a usage error") is what settles this.

What this is not. It does not make the operator's grant trustworthy. It makes
the grant citable, pinned by digest, and checkable by a stranger against the
operator's own origin - the difference between "beautiful signatures on stale
permissions" and a refusal carrying a reason code. The authority root is the
operator's origin, and every verdict says so in `notes` rather than implying
more. It does not answer zeroth_media in full either: Nano replays old writes,
it does not re-evaluate the intent behind them, which is exactly why the
authority layer carries a `policy_epoch` and is fetched live rather than
embedded in the receipt. The chain replays, so the permission has to be
re-read. This module is that re-read.
"""

import argparse
import ast
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import canonical  # noqa: E402  - the one account comparison, reused not copied
import nanoaddr  # noqa: E402  - the vendored codec; canonical puts vendor/ on sys.path

VERSION = 1
TOOL = "authority_receipt"

HEX64_RE = re.compile(r"\A[0-9a-fA-F]{64}\Z")
INTEGER_RE = re.compile(r"\A[+-]?[0-9]+\Z")

RECEIPT_KEYS = frozenset({
    "version", "request_id", "request_digest", "payer_account", "payee_account",
    "quoted_raw", "settled_raw", "settled_block", "committed_at", "grant",
})
GRANT_REF_KEYS = frozenset({"url", "sha256", "policy_epoch"})
GRANT_KEYS = frozenset({
    "version", "subject_account", "policy_epoch", "not_before", "not_after",
    "max_raw_per_payment", "allowed_payees", "revoked_blocks", "revoked_request_ids",
})

# The order `checked` is reported in: the order of the spec's reason table, so
# two implementations print the same list and a diff is a real disagreement.
REASON_ORDER = (
    "bad_receipt_shape",
    "amount_not_integer_string",
    "bad_block_hash",
    "block_not_confirmed",
    "payer_mismatch",
    "payee_mismatch",
    "block_amount_mismatch",
    "quote_settlement_delta",
    "request_digest_mismatch",
    "grant_digest_mismatch",
    "grant_subject_mismatch",
    "policy_epoch_stale",
    "outside_grant_window",
    "over_grant_limit",
    "payee_not_allowed",
    "revoked_block",
    "revoked_request",
    "replayed_block",
)

TRUST_NOTE = (
    "The authority root is the operator's origin: this tool pins the grant by "
    "sha256 and checks the receipt against it, which makes the grant citable "
    "and stranger-checkable, but does not make the operator trustworthy."
)
LAYER_NOTE = (
    "Layer 1 (who acted) is the Nano block and is an input here - the network "
    "verified that signature when it confirmed the block. This tool is layer 2 "
    "(why the act was permitted) and implements no cryptographic signature check."
)
REPLAY_NOTE = (
    "Nano replays old writes rather than re-evaluating the intent behind them, "
    "so the permission has to be re-read: that is why the grant is fetched live "
    "and carries a policy_epoch instead of being embedded in the receipt."
)


# --------------------------------------------------------------------------
# parsing helpers - none of these raise, all of them refuse
# --------------------------------------------------------------------------

def _amount(value):
    """`value` as an integer count of raw, or None if it does not spell one.

    A raw amount must arrive as a `str`. A JSON number is refused rather than
    coerced (rule 2): accepting one here is how 10**30 raw silently loses its
    low digits. The ASCII guard is load-bearing and not decoration -
    `"²".isdigit()` is True while `int("²")` raises, so a regex over
    ASCII digits is used instead of `str.isdigit`.
    """
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text.isascii() or not INTEGER_RE.match(text):
        return None
    return int(text)


def _moment(value):
    """An RFC3339 timestamp as a timezone-aware datetime, or None.

    A naive timestamp is refused: comparing one against an aware bound raises,
    and a bound comparison that can raise is a bound that is not checked.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def _is_hex64(value):
    return isinstance(value, str) and bool(HEX64_RE.match(value))


def _exact_int(value):
    """An `int` that is not a `bool`. `True` is not a version and not an epoch."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def request_digest(document):
    """SHA-256 of a request document's canonical serialisation, lowercase hex.

    The serialisation is fixed by the spec so that two implementations agree:
    sorted keys, no whitespace, non-ASCII left as characters and encoded UTF-8.
    """
    payload = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _digest_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


# --------------------------------------------------------------------------
# the grant, as bytes or already parsed
# --------------------------------------------------------------------------

def _grant_material(grant):
    """Split the `grant` argument into (bytes or None, parsed object or None).

    Bytes are what the digest check needs: test 11 of the spec pins the digest
    to the bytes AS FETCHED, because digesting a re-serialised object would
    make a grant that differs only in whitespace verify against the wrong
    document. A caller who hands over a parsed object therefore loses the
    digest check, and the verdict reports that gap rather than hiding it.
    """
    if isinstance(grant, (bytes, bytearray)):
        payload = bytes(grant)
    elif isinstance(grant, str):
        payload = grant.encode("utf-8")
    else:
        return None, grant
    try:
        return payload, json.loads(payload.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return payload, None


# --------------------------------------------------------------------------
# the block, as a node reports it
# --------------------------------------------------------------------------

def _block_destination(block):
    """The account a send credits, or None.

    `link_as_account` is read from `contents` when the node nests it there, as
    `settle.py` already does, and from the top level otherwise. A block that is
    not a confirmed `send` has no destination this tool will name: there is no
    reason code for "not a send", so an unestablished destination refuses
    through `payee_mismatch`, which is what fail-closed means here.
    """
    if not isinstance(block, dict):
        return None
    if block.get("subtype") != "send":
        return None
    contents = block.get("contents")
    if isinstance(contents, dict) and contents.get("link_as_account") is not None:
        return contents.get("link_as_account")
    return block.get("link_as_account")


def _block_confirmed(block):
    """Whether the node called this block confirmed.

    A node answers the string `"true"`, not the JSON literal; `settle.py`
    already normalises that and this agrees with it rather than diverging.
    """
    if not isinstance(block, dict):
        return False
    value = block.get("confirmed")
    if isinstance(value, bool):
        return value
    return isinstance(value, str) and value.strip().lower() == "true"


# --------------------------------------------------------------------------
# verify
# --------------------------------------------------------------------------

def verify(receipt, grant, block, request=None, now=None, seen_blocks=None):
    """Return a verdict dict. Never raises on a bad document; refuses instead.

    `now` is the one exception and it is a caller error, not a document defect:
    rule 4 forbids a clock in here, so a missing or unparseable `now` raises
    `ValueError` and the CLI turns that into exit 2. See the module docstring.
    """
    if _moment(now) is None:
        raise ValueError(
            "now is required and must be an RFC3339 timestamp or an aware "
            "datetime: this module holds no clock, so the caller supplies the time"
        )

    reasons = set()
    evaluated = set()
    notes = [TRUST_NOTE, LAYER_NOTE, REPLAY_NOTE]

    def check(code, failed):
        evaluated.add(code)
        if failed:
            reasons.add(code)

    # ---- shape (rule 5) --------------------------------------------------
    # The amount fields are deliberately NOT type-checked here: a JSON number
    # in one of them is `amount_not_integer_string`, which is its own code and
    # its own test, and reporting it as a shape defect would hide which field.
    shape_bad = False
    grant_ref = None
    if not isinstance(receipt, dict):
        shape_bad = True
    else:
        if set(receipt) != RECEIPT_KEYS:
            shape_bad = True
        if _exact_int(receipt.get("version")) != VERSION:
            shape_bad = True
        for key in ("request_id", "payer_account", "payee_account",
                    "settled_block", "committed_at"):
            if not isinstance(receipt.get(key), str) or not receipt.get(key).strip():
                shape_bad = True
        if not _is_hex64(receipt.get("request_digest")):
            shape_bad = True
        candidate = receipt.get("grant")
        if not isinstance(candidate, dict) or set(candidate) != GRANT_REF_KEYS:
            shape_bad = True
        else:
            if not isinstance(candidate.get("url"), str) or not candidate["url"].strip():
                shape_bad = True
            if not _is_hex64(candidate.get("sha256")):
                shape_bad = True
            if _exact_int(candidate.get("policy_epoch")) is None:
                shape_bad = True
            grant_ref = candidate
    check("bad_receipt_shape", shape_bad)

    read = receipt.get if isinstance(receipt, dict) else (lambda _key, default=None: default)

    # ---- amounts (rule 2) ------------------------------------------------
    quoted = _amount(read("quoted_raw"))
    settled = _amount(read("settled_raw"))
    grant_payload, grant_doc = _grant_material(grant)
    grant_obj = grant_doc if isinstance(grant_doc, dict) else None
    limit_present = grant_obj is not None and "max_raw_per_payment" in grant_obj
    limit = _amount(grant_obj.get("max_raw_per_payment")) if limit_present else None
    block_amount_present = isinstance(block, dict) and "amount" in block
    block_amount = _amount(block.get("amount")) if block_amount_present else None

    bad_amount = quoted is None or settled is None
    if limit_present and limit is None:
        bad_amount = True
    if block_amount_present and block_amount is None:
        bad_amount = True
    check("amount_not_integer_string", bad_amount)

    # ---- the block -------------------------------------------------------
    settled_block = read("settled_block")
    if _is_hex64(settled_block):
        supplied_hash = block.get("hash") if isinstance(block, dict) else None
        if supplied_hash is None:
            check("bad_block_hash", False)
        else:
            check("bad_block_hash",
                  not _is_hex64(supplied_hash)
                  or supplied_hash.lower() != settled_block.lower())
    else:
        check("bad_block_hash", True)

    check("block_not_confirmed", not _block_confirmed(block))
    check("payer_mismatch",
          not canonical.same_account(block.get("block_account") if isinstance(block, dict) else None,
                                     read("payer_account")))
    check("payee_mismatch",
          not canonical.same_account(_block_destination(block), read("payee_account")))
    check("block_amount_mismatch",
          block_amount is None or settled is None or block_amount != settled)

    # ---- diviner's test, as a field --------------------------------------
    check("quote_settlement_delta", quoted is None or settled is None or quoted != settled)

    # ---- eignex: tied to the request -------------------------------------
    if request is not None:
        check("request_digest_mismatch",
              not _is_hex64(read("request_digest"))
              or request_digest(request).lower() != read("request_digest").lower())

    # ---- the grant -------------------------------------------------------
    if grant_payload is not None:
        pinned = grant_ref.get("sha256") if isinstance(grant_ref, dict) else None
        check("grant_digest_mismatch",
              not _is_hex64(pinned)
              or _digest_bytes(grant_payload) != pinned.lower())
    else:
        notes.append(
            "The grant was supplied already parsed, so grant_digest_mismatch "
            "could not be checked: the digest is defined over the bytes as "
            "fetched. Hand the grant over as bytes to close this gap."
        )

    check("grant_subject_mismatch",
          grant_obj is None
          or not canonical.same_account(grant_obj.get("subject_account"), read("payer_account")))

    receipt_epoch = grant_ref.get("policy_epoch") if isinstance(grant_ref, dict) else None
    grant_epoch = _exact_int(grant_obj.get("policy_epoch")) if grant_obj is not None else None
    check("policy_epoch_stale",
          grant_epoch is None
          or _exact_int(receipt_epoch) is None
          or grant_epoch != _exact_int(receipt_epoch))

    committed = _moment(read("committed_at"))
    not_before = _moment(grant_obj.get("not_before")) if grant_obj is not None else None
    not_after = _moment(grant_obj.get("not_after")) if grant_obj is not None else None
    check("outside_grant_window",
          committed is None or not_before is None or not_after is None
          or committed < not_before or committed > not_after)

    check("over_grant_limit", quoted is None or limit is None or quoted > limit)

    allowed = grant_obj.get("allowed_payees") if grant_obj is not None else None
    if allowed == "*":
        payee_refused = False
    elif isinstance(allowed, list):
        # An empty list means NO payee is allowed. Treating it as a wildcard is
        # the inversion this check exists to make impossible.
        payee_refused = not any(
            canonical.same_account(entry, read("payee_account")) for entry in allowed
        )
    else:
        payee_refused = True
    check("payee_not_allowed", payee_refused)

    revoked_blocks = grant_obj.get("revoked_blocks") if grant_obj is not None else None
    check("revoked_block",
          not isinstance(revoked_blocks, list)
          or any(isinstance(entry, str) and isinstance(settled_block, str)
                 and entry.lower() == settled_block.lower() for entry in revoked_blocks))

    revoked_requests = grant_obj.get("revoked_request_ids") if grant_obj is not None else None
    check("revoked_request",
          not isinstance(revoked_requests, list) or read("request_id") in revoked_requests)

    # ---- zeroth_media: replay --------------------------------------------
    if seen_blocks is not None:
        seen = None
        if isinstance(seen_blocks, dict) and isinstance(settled_block, str):
            for key, value in seen_blocks.items():
                if isinstance(key, str) and key.lower() == settled_block.lower():
                    seen = value
                    break
        check("replayed_block", seen is not None and seen != read("request_id"))

    verdict = {
        "tool": TOOL,
        "version": VERSION,
        "ok": not reasons,
        "reasons": sorted(reasons),
        "checked": [code for code in REASON_ORDER if code in evaluated],
        "request_id": read("request_id"),
        "settled_block": settled_block,
        "notes": notes,
    }
    if quoted is not None and settled is not None:
        verdict["delta_raw"] = str(settled - quoted)
    return verdict


# --------------------------------------------------------------------------
# fetching - the ONLY place the network is reachable
# --------------------------------------------------------------------------

class Fetched(object):
    """A fetched document: a status and the bytes exactly as they arrived."""

    __slots__ = ("status", "headers", "body")

    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body


def default_fetch(timeout=10):
    """Build the stdlib `fetch(url, headers)` seam, the signature rule 4 fixes.

    `urllib.request` is imported here and nowhere else in this file, so a
    `verify()` call cannot reach the network layer even by accident.
    """
    import urllib.error  # noqa: PLC0415 - deliberately local; see the docstring
    import urllib.request  # noqa: PLC0415 - the one network import in this file

    opener = urllib.request.build_opener()

    def fetch(url, headers):
        req = urllib.request.Request(url, headers=dict(headers or {}), method="GET")
        try:
            with opener.open(req, timeout=timeout) as response:
                return Fetched(response.status, dict(response.headers), response.read())
        except urllib.error.HTTPError as exc:  # a status is an answer, not a failure
            return Fetched(exc.code, dict(exc.headers or {}), exc.read())

    return fetch


# --------------------------------------------------------------------------
# controls - rule 6: the verifier must be able to fail
# --------------------------------------------------------------------------

PAYER_KEY = bytes([0x11]) * 32
PAYEE_KEY = bytes([0x22]) * 32
STRANGER_KEY = bytes([0x33]) * 32
CONTROL_BLOCK = "A1B2" * 16          # synthetic, built at runtime, never captured
OTHER_BLOCK = "C3D4" * 16
RAW_50 = "50000000000000000000000000000"
RAW_LIMIT = "100000000000000000000000000000"
CONTROL_NOW = "2026-10-01T05:52:50Z"


def _control_set():
    """A fully consistent receipt/grant/block/request set: the positive control."""
    payer = nanoaddr.encode(PAYER_KEY)
    payee = nanoaddr.encode(PAYEE_KEY)

    request = {"job": "job-2026-09-26-003", "unit": "one witness report"}
    grant = {
        "version": 1,
        "subject_account": payer,
        "policy_epoch": 3,
        "not_before": "2026-09-01T00:00:00Z",
        "not_after": "2026-12-01T00:00:00Z",
        "max_raw_per_payment": RAW_LIMIT,
        "allowed_payees": [payee],
        "revoked_blocks": [],
        "revoked_request_ids": [],
    }
    grant_bytes = json.dumps(grant).encode("utf-8")
    receipt = {
        "version": 1,
        "request_id": "job-2026-09-26-003",
        "request_digest": request_digest(request),
        "payer_account": payer,
        "payee_account": payee,
        "quoted_raw": RAW_50,
        "settled_raw": RAW_50,
        "settled_block": CONTROL_BLOCK,
        "committed_at": CONTROL_NOW,
        "grant": {
            "url": "https://operator.invalid/grants/agent-7.json",
            "sha256": _digest_bytes(grant_bytes),
            "policy_epoch": 3,
        },
    }
    block = {
        "hash": CONTROL_BLOCK,
        "amount": RAW_50,
        "block_account": payer,
        "subtype": "send",
        "confirmed": "true",
        "contents": {"link_as_account": payee},
    }
    return receipt, grant_bytes, block, request, {CONTROL_BLOCK: receipt["request_id"]}


def _negative_controls():
    """One mutation per reason code. Each must come back refused on THAT code."""
    stranger = nanoaddr.encode(STRANGER_KEY)
    cases = {}

    def case(code, mutate):
        receipt, grant_bytes, block, request, seen = _control_set()
        parts = {"receipt": receipt, "grant": grant_bytes, "block": block,
                 "request": request, "seen_blocks": seen}
        mutate(parts)
        cases[code] = parts

    def regrant(parts, **changes):
        """Re-sign the grant so only the intended field is under test."""
        grant = json.loads(parts["grant"].decode("utf-8"))
        grant.update(changes)
        payload = json.dumps(grant).encode("utf-8")
        parts["grant"] = payload
        parts["receipt"]["grant"]["sha256"] = _digest_bytes(payload)

    case("bad_receipt_shape", lambda p: p["receipt"].update({"note": "hello"}))
    case("amount_not_integer_string", lambda p: p["receipt"].update({"quoted_raw": 0.05}))
    case("bad_block_hash", lambda p: p["receipt"].update({"settled_block": "not-a-hash"}))
    case("block_not_confirmed", lambda p: p["block"].update({"confirmed": "false"}))
    case("payer_mismatch", lambda p: p["block"].update({"block_account": stranger}))
    case("payee_mismatch", lambda p: p["block"].update({"contents": {"link_as_account": stranger}}))
    case("block_amount_mismatch", lambda p: p["block"].update({"amount": "1"}))
    case("quote_settlement_delta", lambda p: p["receipt"].update({"quoted_raw": "40000000000000000000000000000"}))
    case("request_digest_mismatch", lambda p: p.update({"request": {"job": "something else"}}))
    case("grant_digest_mismatch", lambda p: p["receipt"]["grant"].update({"sha256": "0" * 64}))
    case("grant_subject_mismatch", lambda p: regrant(p, subject_account=stranger))
    case("policy_epoch_stale", lambda p: regrant(p, policy_epoch=4))
    case("outside_grant_window", lambda p: regrant(p, not_after="2026-09-02T00:00:00Z"))
    case("over_grant_limit", lambda p: regrant(p, max_raw_per_payment="1"))
    case("payee_not_allowed", lambda p: regrant(p, allowed_payees=[]))
    case("revoked_block", lambda p: regrant(p, revoked_blocks=[CONTROL_BLOCK]))
    case("revoked_request", lambda p: regrant(p, revoked_request_ids=["job-2026-09-26-003"]))
    case("replayed_block", lambda p: p.update({"seen_blocks": {CONTROL_BLOCK: "some-other-job"}}))
    return cases


def self_test():
    """Exit 0 only if the positive control passes AND every negative refuses.

    `verify` is looked up through module globals on every call, deliberately:
    a build that replaced it with something that always passes must turn this
    red, which is the test that keeps this tool from becoming the artifact it
    was written to replace.
    """
    receipt, grant_bytes, block, request, seen = _control_set()
    positive = verify(receipt, grant_bytes, block, request=request,
                      now=CONTROL_NOW, seen_blocks=seen)

    results = []
    ok = positive["ok"] is True and positive["reasons"] == []
    if not ok:
        results.append({"control": "positive", "expected_ok": True,
                        "ok": positive["ok"], "reasons": positive["reasons"]})

    missing = [code for code in REASON_ORDER if code not in positive["checked"]]

    for code, parts in sorted(_negative_controls().items()):
        verdict = verify(parts["receipt"], parts["grant"], parts["block"],
                         request=parts["request"], now=CONTROL_NOW,
                         seen_blocks=parts["seen_blocks"])
        good = verdict["ok"] is False and code in verdict["reasons"]
        if not good:
            ok = False
            results.append({"control": code, "expected_ok": False,
                            "ok": verdict["ok"], "reasons": verdict["reasons"]})

    if missing:
        ok = False

    report = {
        "tool": TOOL,
        "self_test": "pass" if ok else "fail",
        "positive_control": {"expected_ok": True, "ok": positive["ok"]},
        "negative_controls": len(REASON_ORDER),
        "codes_checked_by_positive_control": len(positive["checked"]),
        "failures": results,
    }
    if missing:
        report["codes_never_evaluated"] = missing
    if not ok:
        report["why"] = (
            "A control did not behave. If a negative control passed, this "
            "verifier has stopped being able to fail and every green verdict "
            "it has ever printed is worthless."
        )
    print(json.dumps(report, indent=2, sort_keys=False))
    return 0 if ok else 1


# --------------------------------------------------------------------------
# import-graph self-description, used by the test that pins rule 1
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
# CLI - the exit codes are part of the contract
# --------------------------------------------------------------------------

def _load_json(path, label):
    with open(path, "r", encoding="utf-8") as handle:
        try:
            return json.load(handle)
        except ValueError as exc:
            raise ValueError("%s is not valid JSON: %s" % (label, exc))


def _load_grant(source, timeout):
    """The grant as BYTES, from a path or a URL, digested exactly as received."""
    if source.startswith(("http://", "https://")):
        fetch = default_fetch(timeout)
        answer = fetch(source, {"Accept": "application/json"})
        if getattr(answer, "status", 200) != 200:
            raise ValueError("fetching the grant returned HTTP %s" % answer.status)
        return answer.body
    with open(source, "rb") as handle:
        return handle.read()


def build_parser():
    parser = argparse.ArgumentParser(
        prog="authority_receipt.py",
        description="Bind a payment to its request and its signer to a live permission.",
    )
    sub = parser.add_subparsers(dest="command")

    check = sub.add_parser("verify", help="verify a receipt against a grant and a block")
    check.add_argument("--receipt", required=True)
    check.add_argument("--grant", required=True, help="a path, or an http(s) URL")
    check.add_argument("--block", required=True)
    check.add_argument("--request", help="the request document, to check request_digest")
    check.add_argument("--seen", help="{block_hash: request_id} of receipts already accepted")
    check.add_argument("--now", required=True, help="RFC3339; this module holds no clock")
    check.add_argument("--timeout", type=int, default=10,
                       help="seconds, whole; a fractional timeout is not needed here")
    check.add_argument("--quiet", action="store_true", help="exit code only, no stdout")

    digest = sub.add_parser("digest", help="the canonical SHA-256 of a request document")
    digest.add_argument("--request", required=True)

    parser.add_argument("--self-test", dest="self_test", action="store_true",
                        help="run every control hermetically; touches no network")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if getattr(args, "self_test", False):
        return self_test()
    if args.command == "digest":
        try:
            document = _load_json(args.request, "--request")
        except (OSError, ValueError) as exc:
            sys.stderr.write("authority_receipt.py: %s\n" % exc)
            return 2
        print(request_digest(document))
        return 0
    if args.command != "verify":
        sys.stderr.write("authority_receipt.py: a command is required "
                         "(verify, digest) or --self-test\n")
        return 2
    try:
        receipt = _load_json(args.receipt, "--receipt")
        block = _load_json(args.block, "--block")
        grant = _load_grant(args.grant, args.timeout)
        request = _load_json(args.request, "--request") if args.request else None
        seen = _load_json(args.seen, "--seen") if args.seen else None
        verdict = verify(receipt, grant, block, request=request,
                         now=args.now, seen_blocks=seen)
    except (OSError, ValueError) as exc:
        sys.stderr.write("authority_receipt.py: %s\n" % exc)
        return 2
    if not args.quiet:
        print(json.dumps(verdict, indent=2, sort_keys=False))
    return 0 if verdict["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
