"""Mint the permission that `authority_receipt.py` already verifies.

Every other tool in this repository sits on the PAYEE side: it helps someone
verify, price or claim a payment they are about to receive. `authority_receipt`
is the far end of that chain - it fetches a grant by URL, pins it by sha256 and
refuses a receipt on eight distinct grant-related reason codes - and until this
file existed nothing in any repository PRODUCED one. An operator who read the
README was told their policy would be checked and given no way to state it.

The chain an outside agent described, and where each link lives:

    cap authorizes class   ->  grant_mint.py      (this file)
    invoice binds instance ->  x402_binding.py
    receipt closes the loop->  authority_receipt.py

This file is not a wallet, not a custodian, not a signer, and it holds no key.
A grant is a DECLARATION BY THE OPERATOR'S ORIGIN that a named account may
spend under named limits. `authority_receipt.TRUST_NOTE` already says exactly
what that buys and what it does not, and this file claims no more.

THE BYTE RULE, AND IT IS THE WHOLE FILE. `authority_receipt._grant_material`
digests the grant AS FETCHED, not as re-serialised, because digesting a
re-serialised object would make a grant that differs only in whitespace verify
against the wrong document. So `serialise()` is called exactly once per grant,
the digest is taken over ITS return value, and `--out` writes those same bytes
through unchanged. The server must return them unchanged too: a proxy, CDN or
framework that re-serialises JSON will break every receipt that cites the
grant. That sentence is in `--help` as well as here, because it is the single
most likely production failure and it must be impossible to deploy without
having read it.

`GRANT_KEYS` is imported from `authority_receipt` rather than re-listed, so the
two files cannot drift: if the verifier's key set changes, the minter's tests
go red in the same commit.
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

import canonical  # noqa: E402  - puts vendor/ on sys.path as a side effect
import nanoaddr  # noqa: E402  - the vendored codec
from authority_receipt import GRANT_KEYS, GRANT_REF_KEYS  # noqa: E402

TOOL = "grant_mint"
VERSION = 1

RAW_RE = re.compile(r"\A[0-9]+\Z")
HEX64_RE = re.compile(r"\A[0-9a-fA-F]{64}\Z")
# RFC3339 with an EXPLICIT offset or `Z`. A naive timestamp is refused rather
# than assumed to be UTC: `authority_receipt._moment` refuses one too, so a
# grant minted from a naive bound would be a grant whose window is never
# checked.
MOMENT_RE = re.compile(
    r"\A\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})\Z"
)

MAX_REQUEST_ID = 256

SERVE_NOTE = (
    "The server must return these bytes unchanged. A proxy, CDN or framework "
    "that re-serialises JSON will break every receipt that cites this grant, "
    "because the digest is defined over the bytes as fetched."
)
TRUST_NOTE = (
    "This mints a declaration, not an authorisation: it holds no key, signs "
    "nothing, and makes the operator's policy citable and stranger-checkable "
    "without making the operator trustworthy."
)
REVOKE_NOTE = (
    "Bumping the epoch IS revocation here. `authority_receipt` refuses a "
    "receipt whose cited policy_epoch differs from the grant's, so the moment "
    "the bumped bytes are served, every receipt citing the old epoch stops "
    "verifying. Nano cannot un-send a block; this is the only revocation the "
    "ledger permits."
)

PUBLISH_REASON_ORDER = (
    "fetch_failed",
    "http_not_200",
    "digest_mismatch",
    "not_json",
    "bad_grant_shape",
    "policy_epoch_mismatch",
    "subject_mismatch",
)


class Refusal(Exception):
    """A refusal with a reason code. Never a partial grant, never a warning."""

    def __init__(self, code, detail):
        Exception.__init__(self, detail)
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# parsing helpers - each one refuses, none of them guesses
# --------------------------------------------------------------------------

def _exact_int(value):
    """An `int` that is not a `bool`. `True` is not an epoch."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def raw_string(value):
    """`value` as a canonical non-negative raw string, or None.

    A raw amount is an integer count of the smallest unit: 1 XNO is 10**30 raw,
    so a float cannot hold one without losing its low digits. Only ASCII digits
    are accepted - no sign, no underscore, no whitespace, no exponent - because
    every one of those spellings is a different number to somebody. The ASCII
    guard is load-bearing: `"²".isdigit()` is True while `int("²")`
    raises, so the regex is over ASCII digits and not `str.isdigit`.
    """
    if not isinstance(value, str):
        return None
    if not value.isascii() or not RAW_RE.match(value):
        return None
    # Normalised so that "007" and "7" mint byte-identical grants.
    return str(int(value))


def moment(value):
    """An RFC3339 timestamp with an explicit offset, as an aware datetime, or None."""
    if not isinstance(value, str) or not MOMENT_RE.match(value.strip()):
        return None
    text = value.strip().replace(" ", "T")
    if text[-1] in "Zz":
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else None


def stamp(value):
    """An aware datetime as the one spelling this file writes: UTC, `Z`, seconds.

    Normalising means two operators who passed the same instant in different
    offsets mint byte-identical grants, which is what makes the digest a
    property of the policy rather than of the typing.
    """
    return value.astimezone(timezone.utc).replace(microsecond=0).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def account(value, code):
    """`value` as a canonical `nano_` address, or a refusal with `code`.

    A failed checksum is a refusal and never a warning: an address that fails
    it is not a typo to be passed through, it is an account that does not exist,
    and a grant naming one is a grant that can never be used.
    """
    verdict = nanoaddr.validate(value) if isinstance(value, str) else {
        "valid": False, "reason": "not_a_string", "message": "expected a string"}
    if not verdict["valid"]:
        # `nanoaddr`'s bad_checksum message already names both the checksum the
        # address carries and the one its key implies, which is the pair
        # http_claim.py's /check-address reports. Pass it through rather than
        # re-deriving it, so the two tools say the same thing.
        raise Refusal(code, "%s: %s" % (verdict.get("reason"), verdict.get("message")))
    return canonical.canonical_account(verdict["address"])


# --------------------------------------------------------------------------
# the byte rule
# --------------------------------------------------------------------------

def serialise(grant):
    """The grant's one and only serialisation. Call this once per grant.

    `indent=2, sort_keys=True, ensure_ascii=True` plus a trailing newline, UTF-8.
    The digest is taken over exactly this, and `--out` writes exactly this.
    """
    return (json.dumps(grant, indent=2, sort_keys=True, ensure_ascii=True)
            + "\n").encode("utf-8")


def digest(payload):
    """Lowercase hex sha256 of bytes. Agrees with `authority_receipt._digest_bytes`."""
    return hashlib.sha256(payload).hexdigest()


def reference(url, payload, policy_epoch):
    """The three keys `authority_receipt` reads from a receipt's `grant` field."""
    ref = {"url": url, "sha256": digest(payload), "policy_epoch": policy_epoch}
    assert set(ref) == set(GRANT_REF_KEYS), "reference block drifted from the verifier"
    return ref


def grant_defects(obj):
    """Why `obj` is not a valid grant, or None if it is one."""
    if not isinstance(obj, dict):
        return "not a JSON object"
    if set(obj) != set(GRANT_KEYS):
        missing = sorted(set(GRANT_KEYS) - set(obj))
        extra = sorted(set(obj) - set(GRANT_KEYS))
        return "key set is wrong (missing %s, unexpected %s)" % (missing, extra)
    if _exact_int(obj.get("version")) != VERSION:
        return "version must be the integer %d" % VERSION
    epoch = _exact_int(obj.get("policy_epoch"))
    if epoch is None or epoch < 1:
        return "policy_epoch must be an integer >= 1"
    if not nanoaddr.is_valid(obj.get("subject_account")
                             if isinstance(obj.get("subject_account"), str) else ""):
        return "subject_account is not a valid Nano address"
    if raw_string(obj.get("max_raw_per_payment")) is None:
        return "max_raw_per_payment must be a non-negative integer string"
    before, after = moment(obj.get("not_before")), moment(obj.get("not_after"))
    if before is None or after is None:
        return "not_before and not_after must be RFC3339 with an explicit offset"
    if before >= after:
        return "not_before must be strictly before not_after"
    payees = obj.get("allowed_payees")
    if not isinstance(payees, list) or not all(isinstance(p, str) for p in payees):
        return "allowed_payees must be a list of strings"
    for key in ("revoked_blocks", "revoked_request_ids"):
        if not isinstance(obj.get(key), list) or not all(
                isinstance(entry, str) for entry in obj[key]):
            return "%s must be a list of strings" % key
    return None


# --------------------------------------------------------------------------
# mint
# --------------------------------------------------------------------------

def mint(subject, max_raw, not_after, not_before=None, allow_payees=None,
         policy_epoch=1, url=None, now=None):
    """Build a grant and its reference block. Returns (grant, bytes, ref, warnings).

    `now` owns the clock, exactly as `authority_receipt.verify` does: this file
    reads the system clock in one place only (the CLI, when `--now` is absent),
    so the same inputs replayed with the same `--now` mint the same bytes.
    """
    warnings = []

    if now is None:
        now_dt = datetime.now(timezone.utc)
    else:
        now_dt = moment(now)
        if now_dt is None:
            raise Refusal("now_not_parseable",
                          "--now must be RFC3339 with an explicit offset or Z: %r" % (now,))
    now_dt = now_dt.replace(microsecond=0)

    subject_account = account(subject, "invalid_subject_account")

    limit = raw_string(max_raw)
    if limit is None:
        raise Refusal(
            "max_raw_not_integer_string",
            "--max-raw must be a non-negative integer string of ASCII digits - "
            "no sign, underscore, whitespace or exponent, and never a float, "
            "because 1 XNO is 10**30 raw: %r" % (max_raw,))

    after = moment(not_after)
    if after is None:
        raise Refusal("timestamp_not_absolute",
                      "--not-after must be RFC3339 with an explicit offset or Z: %r"
                      % (not_after,))
    if not_before is None:
        before = now_dt
    else:
        before = moment(not_before)
        if before is None:
            raise Refusal("timestamp_not_absolute",
                          "--not-before must be RFC3339 with an explicit offset or Z: %r"
                          % (not_before,))
    if before >= after:
        raise Refusal("empty_grant_window",
                      "--not-after (%s) must be strictly after --not-before (%s); "
                      "a grant whose window is empty can never authorise anything"
                      % (stamp(after), stamp(before)))

    epoch = _exact_int(policy_epoch)
    if epoch is None or epoch < 1:
        raise Refusal("policy_epoch_out_of_range",
                      "--policy-epoch must be an integer >= 1: %r" % (policy_epoch,))

    payees = []
    for candidate in (allow_payees or []):
        canonical_payee = account(candidate, "invalid_payee_account")
        if canonical_payee not in payees:
            payees.append(canonical_payee)
    if not payees:
        warnings.append("warning: allowed_payees is empty; every payment will "
                        "refuse with payee_not_allowed")

    if url is None:
        warnings.append("warning: no --url; this grant cannot be cited by a receipt")
    elif not isinstance(url, str) or not url.startswith("https://") or len(url) <= len("https://"):
        raise Refusal("grant_url_not_https",
                      "--url must be an https URL: a grant served over http can "
                      "be rewritten in flight, and the digest would then pin the "
                      "rewrite: %r" % (url,))

    grant = {
        "version": VERSION,
        "subject_account": subject_account,
        "policy_epoch": epoch,
        "not_before": stamp(before),
        "not_after": stamp(after),
        "max_raw_per_payment": limit,
        "allowed_payees": payees,
        "revoked_blocks": [],
        "revoked_request_ids": [],
    }
    if set(grant) != set(GRANT_KEYS):
        raise AssertionError("minted key set drifted from authority_receipt.GRANT_KEYS")

    payload = serialise(grant)
    return grant, payload, reference(url, payload, epoch), warnings


# --------------------------------------------------------------------------
# bump - the only revocation Nano permits
# --------------------------------------------------------------------------

def bump(grant_bytes, revoke_blocks=None, revoke_requests=None,
         max_raw=None, not_after=None, url=None):
    """Increment the epoch by exactly 1 and append revocations. Returns the same tuple."""
    try:
        existing = json.loads(grant_bytes.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise Refusal("bad_grant_shape", "--grant is not valid UTF-8 JSON: %s" % exc)
    defect = grant_defects(existing)
    if defect is not None:
        raise Refusal("bad_grant_shape", "--grant is not a valid grant: %s" % defect)

    blocks = list(existing["revoked_blocks"])
    for candidate in (revoke_blocks or []):
        if not isinstance(candidate, str) or not HEX64_RE.match(candidate):
            raise Refusal("bad_block_hash",
                          "--revoke-block must be 64 hex characters: %r" % (candidate,))
        normalised = candidate.upper()
        # De-duplicated, order preserved, newest last: a repeat is not an error,
        # it is an operator making sure, and it must not grow the document.
        if not any(entry.upper() == normalised for entry in blocks):
            blocks.append(normalised)

    requests = list(existing["revoked_request_ids"])
    for candidate in (revoke_requests or []):
        if not isinstance(candidate, str) or not candidate.strip():
            raise Refusal("bad_revoke_request",
                          "--revoke-request must be a non-empty string: %r" % (candidate,))
        if len(candidate) > MAX_REQUEST_ID:
            raise Refusal("bad_revoke_request",
                          "--revoke-request must be at most %d characters, got %d"
                          % (MAX_REQUEST_ID, len(candidate)))
        if candidate not in requests:
            requests.append(candidate)

    limit = existing["max_raw_per_payment"]
    if max_raw is not None:
        limit = raw_string(max_raw)
        if limit is None:
            raise Refusal("max_raw_not_integer_string",
                          "--max-raw must be a non-negative integer string: %r" % (max_raw,))

    after_text = existing["not_after"]
    if not_after is not None:
        parsed = moment(not_after)
        if parsed is None:
            raise Refusal("timestamp_not_absolute",
                          "--not-after must be RFC3339 with an explicit offset or Z: %r"
                          % (not_after,))
        after_text = stamp(parsed)
    if moment(existing["not_before"]) >= moment(after_text):
        raise Refusal("empty_grant_window",
                      "--not-after (%s) must be strictly after the grant's "
                      "not_before (%s)" % (after_text, existing["not_before"]))

    warnings = []
    if url is None:
        warnings.append("warning: no --url; this grant cannot be cited by a receipt")
    elif not url.startswith("https://") or len(url) <= len("https://"):
        raise Refusal("grant_url_not_https", "--url must be an https URL: %r" % (url,))

    grant = dict(existing)
    grant["policy_epoch"] = existing["policy_epoch"] + 1
    grant["max_raw_per_payment"] = limit
    grant["not_after"] = after_text
    grant["revoked_blocks"] = blocks
    grant["revoked_request_ids"] = requests

    payload = serialise(grant)
    return grant, payload, reference(url, payload, grant["policy_epoch"]), warnings


# --------------------------------------------------------------------------
# publish-check - the ONLY place the network is reachable
# --------------------------------------------------------------------------

class FetchFailed(Exception):
    """The transport did not answer at all. A status IS an answer; see `fetch`."""


def fetch(url, timeout=10):
    """Return (http_status, bytes). Raises `FetchFailed` only if nothing answered.

    `urllib` is imported HERE and nowhere else in this file, so that `mint` and
    `bump` cannot reach the network even by accident - the same confinement
    `authority_receipt.default_fetch` uses, and a test asserts it by walking
    this file's import graph.

    A non-200 is returned rather than raised, because a status is an answer and
    `publish-check` has a reason code for it. The bytes come back exactly as
    they arrived: that is what the digest is defined over.
    """
    import urllib.error  # noqa: PLC0415 - deliberately local; see the docstring
    import urllib.request  # noqa: PLC0415 - the one network import in this file

    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return getattr(response, "status", response.getcode()), response.read()
    except urllib.error.HTTPError as exc:
        try:
            payload = exc.read()
        except OSError:
            payload = b""
        return exc.code, payload
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise FetchFailed(str(exc))


def publish_check(ref, expected_subject=None, timeout=10, fetcher=None):
    """Prove the bytes a URL actually serves still digest to the reference."""
    fetcher = fetcher or fetch
    reasons = set()
    notes = [SERVE_NOTE]

    url = ref.get("url") if isinstance(ref, dict) else None
    expected_digest = ref.get("sha256") if isinstance(ref, dict) else None
    expected_epoch = ref.get("policy_epoch") if isinstance(ref, dict) else None

    status, payload = None, None
    if not isinstance(url, str) or not url.strip():
        reasons.add("fetch_failed")
        notes.append("The reference block carries no url, so there was nothing "
                     "to fetch. Mint with --url to make the grant citable.")
    else:
        try:
            status, payload = fetcher(url, timeout)
        except (FetchFailed, OSError, ValueError) as exc:
            reasons.add("fetch_failed")
            notes.append("fetch failed: %s" % exc)
        else:
            if status != 200:
                reasons.add("http_not_200")

    received_digest = digest(payload) if payload is not None else None
    if payload is not None and isinstance(expected_digest, str):
        if received_digest != expected_digest.lower():
            reasons.add("digest_mismatch")
            notes.append(
                "The bytes served do not digest to the reference. The usual "
                "cause is not an attack: it is a proxy, CDN or framework "
                "re-serialising the JSON. Serve the file as opaque bytes.")
    elif payload is not None:
        reasons.add("digest_mismatch")

    served = None
    if payload is not None:
        try:
            served = json.loads(payload.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            reasons.add("not_json")
        else:
            defect = grant_defects(served)
            if defect is not None:
                reasons.add("bad_grant_shape")
                notes.append("served document is not a valid grant: %s" % defect)

    served_epoch = None
    served_subject = None
    if isinstance(served, dict):
        served_epoch = _exact_int(served.get("policy_epoch"))
        served_subject = served.get("subject_account")
        if served_epoch is None or _exact_int(expected_epoch) is None \
                or served_epoch != _exact_int(expected_epoch):
            reasons.add("policy_epoch_mismatch")
            notes.append(
                "The epoch served differs from the one the reference pins. If "
                "you have just bumped, re-mint the reference; receipts citing "
                "the old epoch refuse with policy_epoch_stale.")
        if expected_subject is not None:
            if not canonical.same_account(served_subject, expected_subject):
                reasons.add("subject_mismatch")
    elif expected_subject is not None:
        reasons.add("subject_mismatch")

    if expected_subject is None:
        notes.append("subject_mismatch was not checked: a reference block "
                     "carries no subject. Pass --subject to close that gap.")

    return {
        "tool": TOOL,
        "subcommand": "publish-check",
        "url": url,
        "http_status": status,
        "bytes_received": len(payload) if payload is not None else None,
        "sha256_expected": expected_digest,
        "sha256_received": received_digest,
        "policy_epoch_served": served_epoch,
        "policy_epoch_expected": _exact_int(expected_epoch),
        "ok": not reasons,
        "reasons": [code for code in PUBLISH_REASON_ORDER if code in reasons],
        "notes": notes,
    }


# --------------------------------------------------------------------------
# self-test - hermetic, and it proves the round trip through the verifier
# --------------------------------------------------------------------------

CONTROL_NOW = "2026-10-03T06:00:00Z"
CONTROL_RAW = "50000000000000000000000000000"        # 0.05 XNO
CONTROL_LIMIT = "250000000000000000000000000000"     # 0.25 XNO
CONTROL_BLOCK = "1A2B" * 16
CONTROL_REQUEST_ID = "job-2026-09-26-003"
CONTROL_URL = "https://operator.invalid/grants/control.json"

# The eight grant-related codes `authority_receipt` can report. Listed here so
# a control exists for each one; the module imports the order from the verifier
# in the test file, which is where drift must bite.
GRANT_CODES = (
    "grant_digest_mismatch",
    "grant_subject_mismatch",
    "policy_epoch_stale",
    "outside_grant_window",
    "over_grant_limit",
    "payee_not_allowed",
    "revoked_block",
    "revoked_request",
)


def _control_keys():
    payer = nanoaddr.encode(bytes([0xA1]) * 32)
    payee = nanoaddr.encode(bytes([0xB2]) * 32)
    stranger = nanoaddr.encode(bytes([0xC3]) * 32)
    return payer, payee, stranger


def _control_receipt(payer, payee, ref, request):
    import authority_receipt
    return {
        "version": 1,
        "request_id": CONTROL_REQUEST_ID,
        "request_digest": authority_receipt.request_digest(request),
        "payer_account": payer,
        "payee_account": payee,
        "quoted_raw": CONTROL_RAW,
        "settled_raw": CONTROL_RAW,
        "settled_block": CONTROL_BLOCK,
        "committed_at": CONTROL_NOW,
        "grant": dict(ref),
    }


def _control_block(payer, payee):
    return {
        "hash": CONTROL_BLOCK,
        "amount": CONTROL_RAW,
        "block_account": payer,
        "subtype": "send",
        "confirmed": "true",
        "contents": {"link_as_account": payee},
    }


def _reseal(grant, **changes):
    """Change a grant and re-pin its digest, so exactly one field is under test."""
    updated = dict(grant)
    updated.update(changes)
    payload = serialise(updated)
    return updated, payload, reference(CONTROL_URL, payload, updated["policy_epoch"])


def self_test():
    """Exit 0 only if a minted grant verifies AND every negative control refuses.

    The positive control is the test the spec said could not be written: mint a
    grant, cite it in a receipt, and hand both to `authority_receipt.verify`.
    If it passes, the three-link chain is complete in shipped code.
    """
    import authority_receipt

    payer, payee, stranger = _control_keys()
    request = {"job": CONTROL_REQUEST_ID, "unit": "one witness report"}

    grant, payload, ref, _ = mint(
        subject=payer, max_raw=CONTROL_LIMIT,
        not_before="2026-09-01T00:00:00Z", not_after="2026-12-01T00:00:00Z",
        allow_payees=[payee], url=CONTROL_URL, now=CONTROL_NOW)
    block = _control_block(payer, payee)
    receipt = _control_receipt(payer, payee, ref, request)

    positive = authority_receipt.verify(receipt, payload, block, request=request,
                                        now=CONTROL_NOW)
    ok = positive["ok"] is True and positive["reasons"] == []
    failures = []
    if not ok:
        failures.append({"control": "positive", "expected_ok": True,
                         "ok": positive["ok"], "reasons": positive["reasons"]})

    controls = {}

    # The digest check is the one control that must NOT re-pin: a grant whose
    # bytes changed after publication is exactly what it exists to catch.
    tampered = payload.replace(b"\n  \"version\"", b"\n   \"version\"", 1)
    if tampered == payload:
        tampered = payload + b" "
    controls["grant_digest_mismatch"] = (receipt, tampered, block)

    subject_grant, subject_payload, subject_ref = _reseal(grant, subject_account=stranger)
    controls["grant_subject_mismatch"] = (
        _control_receipt(payer, payee, subject_ref, request), subject_payload, block)

    stale_grant, stale_payload, stale_ref = _reseal(grant, policy_epoch=2)
    stale_receipt = _control_receipt(payer, payee, stale_ref, request)
    stale_receipt["grant"]["policy_epoch"] = 1
    controls["policy_epoch_stale"] = (stale_receipt, stale_payload, block)

    window_grant, window_payload, window_ref = _reseal(
        grant, not_before="2026-10-04T00:00:00Z", not_after="2026-10-05T00:00:00Z")
    controls["outside_grant_window"] = (
        _control_receipt(payer, payee, window_ref, request), window_payload, block)

    limit_grant, limit_payload, limit_ref = _reseal(grant, max_raw_per_payment="1")
    controls["over_grant_limit"] = (
        _control_receipt(payer, payee, limit_ref, request), limit_payload, block)

    payee_grant, payee_payload, payee_ref = _reseal(grant, allowed_payees=[stranger])
    controls["payee_not_allowed"] = (
        _control_receipt(payer, payee, payee_ref, request), payee_payload, block)

    block_grant, block_payload, block_ref = _reseal(
        grant, revoked_blocks=[CONTROL_BLOCK])
    controls["revoked_block"] = (
        _control_receipt(payer, payee, block_ref, request), block_payload, block)

    request_grant, request_payload, request_ref = _reseal(
        grant, revoked_request_ids=[CONTROL_REQUEST_ID])
    controls["revoked_request"] = (
        _control_receipt(payer, payee, request_ref, request), request_payload, block)

    for code in GRANT_CODES:
        parts = controls[code]
        verdict = authority_receipt.verify(parts[0], parts[1], parts[2],
                                           request=request, now=CONTROL_NOW)
        if verdict["ok"] is not False or verdict["reasons"] != [code]:
            ok = False
            failures.append({"control": code, "expected_reasons": [code],
                             "ok": verdict["ok"], "reasons": verdict["reasons"]})

    # The byte rule, as a control: the digest must be of the bytes, re-read.
    again = serialise(grant)
    if again != payload or digest(again) != ref["sha256"]:
        ok = False
        failures.append({"control": "byte_rule", "expected_ok": True,
                         "detail": "serialise() is not stable, so the digest "
                                   "does not pin the published bytes"})

    report = {
        "tool": TOOL,
        "self_test": "pass" if ok else "fail",
        "positive_control": {"expected_ok": True, "ok": positive["ok"],
                             "verified_by": "authority_receipt.verify"},
        "negative_controls": len(GRANT_CODES) + 1,
        "failures": failures,
        "notes": [TRUST_NOTE, SERVE_NOTE, REVOKE_NOTE],
    }
    if not ok:
        report["why"] = (
            "A control did not behave. If the positive control failed, nothing "
            "this file mints can be verified by authority_receipt, and the "
            "operator's policy is unstateable again. If a negative control "
            "passed, the verifier has stopped being able to refuse.")
    print(json.dumps(report, indent=2, sort_keys=False))
    return 0 if ok else 1


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def import_graph(source_path=None):
    """Every import in this file, with the function it sits in (or None).

    Returned as data so a test can assert the network stays inside `fetch`
    rather than re-parsing the file itself.
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


EPILOG = SERVE_NOTE + "\n\n" + REVOKE_NOTE + "\n\n" + TRUST_NOTE


def build_parser():
    parser = argparse.ArgumentParser(
        prog="grant_mint.py",
        description=("Mint the operator grant that authority_receipt.py "
                     "verifies. Holds no key, signs nothing."),
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command")

    new = sub.add_parser("mint", help="produce the grant document and its reference",
                         epilog=EPILOG,
                         formatter_class=argparse.RawDescriptionHelpFormatter)
    new.add_argument("--subject", required=True,
                     help="the Nano account allowed to spend")
    new.add_argument("--max-raw", required=True,
                     help="maximum raw per single payment, as an integer string "
                          "(1 XNO = 10**30 raw); 0 is legal and refuses every payment")
    new.add_argument("--not-after", required=True, help="RFC3339 with an offset or Z")
    new.add_argument("--not-before", help="RFC3339; defaults to --now")
    new.add_argument("--allow-payee", action="append", default=[],
                     help="repeatable; zero occurrences emits [] which allows NO payee")
    new.add_argument("--policy-epoch", default="1", help="integer >= 1, default 1")
    new.add_argument("--url", help="the https URL the grant will be served from")
    new.add_argument("--out", help="write the grant bytes here; the reference goes to stdout")
    new.add_argument("--now", help="RFC3339; this file holds no clock in tests")

    rev = sub.add_parser("bump", help="revoke by moving the epoch - the only "
                                      "revocation Nano permits",
                         epilog=EPILOG,
                         formatter_class=argparse.RawDescriptionHelpFormatter)
    rev.add_argument("--grant", required=True, help="path to the existing grant bytes")
    rev.add_argument("--revoke-block", action="append", default=[],
                     help="repeatable; 64 hex characters")
    rev.add_argument("--revoke-request", action="append", default=[],
                     help="repeatable; opaque, non-empty, at most %d characters"
                          % MAX_REQUEST_ID)
    rev.add_argument("--max-raw", help="change the per-payment limit")
    rev.add_argument("--not-after", help="change the window's end")
    rev.add_argument("--url", help="the https URL the bumped grant will be served from")
    rev.add_argument("--out", help="write the new grant bytes here")

    check = sub.add_parser("publish-check",
                           help="prove the published bytes still digest to the reference")
    check.add_argument("--ref", required=True, help="path to a reference block, or its URL")
    check.add_argument("--subject", help="the account the served grant must name")
    check.add_argument("--timeout", type=int, default=10)

    parser.add_argument("--self-test", dest="self_test", action="store_true",
                        help="run every control hermetically; touches no network")
    return parser


def _emit(grant, payload, ref, warnings, out_path):
    """Write the grant bytes and the reference. The bytes are never re-serialised."""
    for line in warnings:
        sys.stderr.write(line + "\n")
    if out_path:
        with open(out_path, "wb") as handle:
            handle.write(payload)
    else:
        sys.stdout.write(payload.decode("utf-8"))
    print(json.dumps(ref, indent=2, sort_keys=True))
    return 0


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
        sys.stderr.write("grant_mint.py: a command is required "
                         "(mint, bump, publish-check) or --self-test\n")
        return 2

    try:
        if args.command == "mint":
            epoch = args.policy_epoch
            try:
                epoch = int(str(epoch).strip())
            except ValueError:
                raise Refusal("policy_epoch_out_of_range",
                              "--policy-epoch must be an integer >= 1: %r" % (epoch,))
            grant, payload, ref, warnings = mint(
                subject=args.subject, max_raw=args.max_raw,
                not_after=args.not_after, not_before=args.not_before,
                allow_payees=args.allow_payee, policy_epoch=epoch,
                url=args.url, now=args.now)
            return _emit(grant, payload, ref, warnings, args.out)

        if args.command == "bump":
            try:
                with open(args.grant, "rb") as handle:
                    existing = handle.read()
            except OSError as exc:
                raise Refusal("bad_grant_shape", "cannot read --grant: %s" % exc)
            grant, payload, ref, warnings = bump(
                existing, revoke_blocks=args.revoke_block,
                revoke_requests=args.revoke_request, max_raw=args.max_raw,
                not_after=args.not_after, url=args.url)
            return _emit(grant, payload, ref, warnings, args.out)

        # publish-check
        if args.ref.startswith("http://") or args.ref.startswith("https://"):
            try:
                status, ref_bytes = fetch(args.ref, args.timeout)
                if status != 200:
                    raise ValueError("the reference URL answered HTTP %s" % status)
                ref = json.loads(ref_bytes.decode("utf-8"))
            except (FetchFailed, OSError, ValueError) as exc:
                raise Refusal("bad_grant_shape", "cannot read --ref: %s" % exc)
        else:
            try:
                with open(args.ref, "r", encoding="utf-8") as handle:
                    ref = json.load(handle)
            except (OSError, ValueError) as exc:
                raise Refusal("bad_grant_shape", "cannot read --ref: %s" % exc)
        verdict = publish_check(ref, expected_subject=args.subject, timeout=args.timeout)
        print(json.dumps(verdict, indent=2, sort_keys=False))
        return 0 if verdict["ok"] else 1

    except Refusal as exc:
        return _refuse(exc)


if __name__ == "__main__":
    raise SystemExit(main())
