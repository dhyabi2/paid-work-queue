#!/usr/bin/env python3
"""CI entry point for the paid work queue.

Every rule this file enforces exists because getting it wrong costs somebody
real money or real time:

  * the secret gate runs FIRST, before anything else is even parsed, because
    a key that reaches a public commit is already compromised;
  * money is compared as integer raw, never as a float, because 1 XNO is
    10**30 raw and a float loses the bottom thirteen digits of that;
  * a payout address is checksum-validated before it can be merged, because
    one outside agent (eddie_researcher) handed over an address that failed
    checksum and nothing downstream caught it;
  * receipts are append-only, because a payment that already happened cannot
    stop having happened;
  * `offers.json` is append-only in its ids and its states only advance along a
    legal transition, because an offer is a SELLER's proposal: editing its
    scope, its price or its payout address after the fact would rewrite what
    somebody outside this repository offered to sell, and a seller who was
    told no must be able to read why on the public record.

Usage:
    python3 validate.py [--root DIR] [--base GIT_REF] [--no-write-stats]

Exit 0 and write stats.json when everything holds; exit 1 and print every
failure otherwise. Each failure names the entry it is about.
"""

import argparse
import datetime
import hashlib
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor"))

import nanoaddr  # noqa: E402
from canonical import account_key, raw_amount, same_amount  # noqa: E402
from money import raw_to_xno, xno_to_raw  # noqa: E402
from usdc_shape import MIN_SETTLEABLE_RAW  # noqa: E402
import external_edge_count  # noqa: E402

JOB_STATES = ("open", "claimed", "delivered", "settled", "expired", "cancelled")
CLAIMED_STATES = ("claimed", "delivered", "settled")
BLOCK_HASH_RE = re.compile(r"\A[0-9A-F]{64}\Z")
ANY_CASE_HASH_RE = re.compile(r"\A[0-9a-fA-F]{64}\Z")
# 64 hex characters standing on their own: a Nano seed or private key is
# exactly this, and so is a block hash - which is why block_hash is the one
# field allowed to hold one.
SECRET_RE = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{64,}(?![0-9A-Za-z])")
RFC3339_RE = re.compile(
    r"\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\Z"
)
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache"}


# --------------------------------------------------------------------------
# 1. the secret gate - runs before every other check
# --------------------------------------------------------------------------

def _walk_json_for_secrets(node, path, findings):
    if isinstance(node, dict):
        for key, value in node.items():
            here = "%s.%s" % (path, key)
            if isinstance(key, str) and SECRET_RE.search(key):
                findings.append("%s: a JSON key is 64 hex characters" % here)
            if key == "block_hash" and isinstance(value, str) and ANY_CASE_HASH_RE.match(value):
                # The one exemption. It is deliberately case-insensitive: a
                # lowercase 64-hex value here is still refused, but by the
                # block_hash format check, which tells the author it is the
                # casing that is wrong. The secret gate reporting "this might
                # be a key" instead would be true of every block hash and
                # would send the author looking for the wrong problem.
                continue
            _walk_json_for_secrets(value, here, findings)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _walk_json_for_secrets(value, "%s[%d]" % (path, index), findings)
    elif isinstance(node, str):
        if SECRET_RE.search(node):
            findings.append(
                "%s: contains 64 hex characters standing alone - a seed or a "
                "private key looks exactly like this, and only a block_hash "
                "field may hold one" % path
            )


def scan_for_secrets(root):
    """Return a list of failure messages. Empty means the tree is clean."""
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root)
            try:
                with open(full, "r", encoding="utf-8") as handle:
                    text = handle.read()
            except (UnicodeDecodeError, OSError):
                continue  # not text; nothing to read a key out of
            if name.endswith(".json"):
                try:
                    document = json.loads(text)
                except ValueError:
                    pass
                else:
                    local = []
                    _walk_json_for_secrets(document, rel, local)
                    findings.extend(local)
                    continue
            for match in SECRET_RE.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                findings.append(
                    "%s:%d: 64 hex characters standing alone (%s...) - if this "
                    "is a seed or a private key it must never be committed"
                    % (rel, line, match.group(0)[:8])
                )
    return findings


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def _is_positive_int_string(value):
    """A string spelling a positive integer of raw.

    Via raw_amount for the ASCII guard: `"\u00b2".isdigit()` is True while
    `int("\u00b2")` raises, so the previous `value.isdigit() and int(value) > 0`
    let a ValueError escape a validator documented as returning a verdict. A
    price field carrying a superscript two crashed the whole run instead of
    being reported as the bad field it is.
    """
    if not isinstance(value, str):
        return False
    amount = raw_amount(value)
    return amount is not None and amount > 0


def _rfc3339(value):
    match = RFC3339_RE.match(value) if isinstance(value, str) else None
    if not match:
        return None
    year, month, day, hour, minute, second = (int(g) for g in match.groups())
    try:
        # A real calendar check, not a 1..31 range: 2026-02-31 matches the
        # pattern and is inside the range, but it is not a date, and a public
        # ledger should not carry a job that expires on a day that never comes.
        datetime.date(year, month, day)
    except ValueError:
        return None
    if hour > 23 or minute > 59 or second > 60:
        return None
    return (year, month, day, hour, minute, second)


def _duplicates(ids):
    seen, dupes = set(), []
    for value in ids:
        if value in seen and value not in dupes:
            dupes.append(value)
        seen.add(value)
    return dupes


# --------------------------------------------------------------------------
# 2. jobs.json
# --------------------------------------------------------------------------

def check_jobs(document):
    errors = []
    if not isinstance(document, dict):
        return ["jobs.json: top level must be a JSON object"]
    jobs = document.get("jobs")
    if not isinstance(jobs, list):
        return ["jobs.json: 'jobs' must be a list"]
    if document.get("currency") != "XNO":
        errors.append("jobs.json: 'currency' must be \"XNO\"")

    for dupe in _duplicates([j.get("id") for j in jobs if isinstance(j, dict)]):
        errors.append("jobs.json: duplicate job id %r" % dupe)

    for index, job in enumerate(jobs):
        where = "jobs.json: job[%d]" % index
        if not isinstance(job, dict):
            errors.append("%s is not an object" % where)
            continue
        job_id = job.get("id")
        if not isinstance(job_id, str) or not job_id:
            errors.append("%s has no usable 'id'" % where)
            job_id = "<no id>"
        where = "jobs.json: %s" % job_id

        for field in ("title", "description"):
            if not isinstance(job.get(field), str) or not job[field].strip():
                errors.append("%s: '%s' must be a non-empty string" % (where, field))
        if isinstance(job.get("description"), str) and len(job["description"]) > 1200:
            errors.append(
                "%s: 'description' is %d characters; the limit is 1200"
                % (where, len(job["description"]))
            )
        acceptance = job.get("acceptance")
        if not isinstance(acceptance, list) or not acceptance:
            errors.append("%s: 'acceptance' must be a non-empty list" % where)
        elif not all(isinstance(line, str) and line.strip() for line in acceptance):
            errors.append("%s: every 'acceptance' line must be a non-empty string" % where)

        errors.extend(_check_price(where, job))
        errors.extend(_check_quantum(where, job))

        posted, expires = job.get("posted"), job.get("expires")
        posted_parts, expires_parts = _rfc3339(posted), _rfc3339(expires)
        if posted_parts is None:
            errors.append("%s: 'posted' is not an RFC3339 UTC timestamp: %r" % (where, posted))
        if expires_parts is None:
            errors.append("%s: 'expires' is not an RFC3339 UTC timestamp: %r" % (where, expires))
        if posted_parts and expires_parts and expires_parts <= posted_parts:
            errors.append(
                "%s: 'expires' (%s) does not come after 'posted' (%s)"
                % (where, expires, posted)
            )

        state = job.get("state")
        if state not in JOB_STATES:
            errors.append(
                "%s: 'state' is %r; the allowed set is %s"
                % (where, state, ", ".join(JOB_STATES))
            )
            continue

        claimed_by = job.get("claimed_by")
        if state == "open" and claimed_by is not None:
            errors.append(
                "%s: state is 'open' but 'claimed_by' is %r - an open job is claimed by nobody"
                % (where, claimed_by)
            )
        if state in CLAIMED_STATES and (not isinstance(claimed_by, str) or not claimed_by.strip()):
            errors.append(
                "%s: state is %r but 'claimed_by' is %r - a claimed job names its claimant"
                % (where, state, claimed_by)
            )
        if state == "settled" and not job.get("receipt_id"):
            errors.append(
                "%s: state is 'settled' but 'receipt_id' is %r - no receipt, no settled state"
                % (where, job.get("receipt_id"))
            )
        if state != "settled" and job.get("receipt_id"):
            errors.append(
                "%s: state is %r but 'receipt_id' is set - only a settled job carries one"
                % (where, state)
            )
        if state in CLAIMED_STATES and not isinstance(job.get("claim_url"), str):
            errors.append("%s: state is %r but 'claim_url' is not a URL string" % (where, state))
    return errors


def _check_price(where, entry, xno_key="price_xno", raw_key="price_raw"):
    errors = []
    price_xno, price_raw = entry.get(xno_key), entry.get(raw_key)
    if not _is_positive_int_string(price_raw):
        errors.append(
            "%s: '%s' must be a positive integer string of raw, got %r"
            % (where, raw_key, price_raw)
        )
        return errors
    try:
        implied = xno_to_raw(price_xno)
    except (ValueError, TypeError) as exc:
        errors.append("%s: '%s' is not an exact decimal XNO amount: %s" % (where, xno_key, exc))
        return errors
    if implied != int(price_raw):
        errors.append(
            "%s: '%s' and '%s' disagree - %s XNO is %d raw, but %s is recorded "
            "(a difference of %d raw)"
            % (where, xno_key, raw_key, price_xno, implied, price_raw,
               abs(implied - int(price_raw)))
        )
    return errors



def _check_quantum(where, job):
    """A job priced below one micro cannot be settled on a USDC-shaped ledger.

    `minia2auk/minia2a#1` was closed because their refunder's amount column is
    "USDC atomic units, 6 decimals" read into a Go int64: 1e24 raw is the
    smallest amount it can hold, and anything with a sub-micro tail strands
    there at status='failed' rather than being rejected at quote time.

    The rule here is a warning with a door, not a ban, and the door is
    deliberate. One micro is a property of OTHER people's ledgers, not of
    Nano - Nano's own quantum is 1 raw - so refusing outright would let a
    foreign int64 column decide what this queue is allowed to advertise. A
    maintainer who wants a sub-micro price may have one by saying so on the
    record: set `sub_micro_ok` and name, in `excludes_ledgers`, the ledger
    shapes the price excludes. The default stays the safe one, and the
    exception is never silent.
    """
    errors = []
    price_raw = raw_amount(job.get("price_raw"))
    if price_raw is None:
        return errors  # already reported by _check_price

    remainder = price_raw % MIN_SETTLEABLE_RAW
    declared = job.get("sub_micro_ok")
    excludes = job.get("excludes_ledgers")

    if remainder == 0:
        if declared is not None or excludes is not None:
            errors.append(
                "%s: 'price_raw' is a whole number of micro, so 'sub_micro_ok'/"
                "'excludes_ledgers' say nothing and must be removed - a "
                "standing exception nobody needs is one nobody rereads" % where
            )
        return errors

    if declared is not True:
        errors.append(
            "%s: 'price_raw' is %d raw, which is %d raw short of a whole micro "
            "(1 micro = %d raw = 0.000001 XNO). A server whose amount column is "
            "6-decimal int64 - the shape minia2a refused us over - cannot hold "
            "this price, and its refund would strand at status='failed'. Either "
            "price it in whole micro, or set 'sub_micro_ok': true and name the "
            "ledger shapes it excludes in 'excludes_ledgers'."
            % (where, price_raw, MIN_SETTLEABLE_RAW - remainder, MIN_SETTLEABLE_RAW)
        )
        return errors

    if not isinstance(excludes, list) or not excludes:
        errors.append(
            "%s: 'sub_micro_ok' is set but 'excludes_ledgers' is %r - the "
            "exception has to name what it costs, or it is just a way of "
            "switching the check off" % (where, excludes)
        )
    elif not all(isinstance(item, str) and item.strip() for item in excludes):
        errors.append(
            "%s: every 'excludes_ledgers' entry must be a non-empty string" % where
        )
    return errors

# --------------------------------------------------------------------------
# 3. receipts.json
# --------------------------------------------------------------------------

def check_receipts(document):
    errors = []
    if not isinstance(document, dict):
        return ["receipts.json: top level must be a JSON object"]
    receipts = document.get("receipts")
    if not isinstance(receipts, list):
        return ["receipts.json: 'receipts' must be a list"]

    for dupe in _duplicates([r.get("id") for r in receipts if isinstance(r, dict)]):
        errors.append("receipts.json: duplicate receipt id %r" % dupe)

    hashes = {}
    for index, receipt in enumerate(receipts):
        where = "receipts.json: receipt[%d]" % index
        if not isinstance(receipt, dict):
            errors.append("%s is not an object" % where)
            continue
        receipt_id = receipt.get("id")
        if not isinstance(receipt_id, str) or not receipt_id:
            errors.append("%s has no usable 'id'" % where)
            receipt_id = "<no id>"
        where = "receipts.json: %s" % receipt_id

        if not isinstance(receipt.get("job_id"), str) or not receipt["job_id"]:
            errors.append("%s: 'job_id' must be a non-empty string" % where)

        verdict = nanoaddr.validate(receipt.get("paid_to"))
        if not verdict["valid"]:
            errors.append(
                "%s: 'paid_to' is not a valid Nano address - reason=%s: %s"
                % (where, verdict["reason"], verdict["message"])
            )

        errors.extend(_check_price(where, receipt, "amount_xno", "amount_raw"))

        block_hash = receipt.get("block_hash")
        if not isinstance(block_hash, str) or not BLOCK_HASH_RE.match(block_hash):
            errors.append(
                "%s: 'block_hash' must be 64 uppercase hex characters, got %r - "
                "a receipt without a block hash is not evidence of anything"
                % (where, block_hash)
            )
        else:
            hashes.setdefault(block_hash, []).append(receipt_id)

        if _rfc3339(receipt.get("settled_at")) is None:
            errors.append(
                "%s: 'settled_at' is not an RFC3339 UTC timestamp: %r"
                % (where, receipt.get("settled_at"))
            )
        if not isinstance(receipt.get("delivery_url"), str) or not receipt["delivery_url"]:
            errors.append("%s: 'delivery_url' must be a non-empty string" % where)

    for block_hash, owners in hashes.items():
        if len(owners) > 1:
            errors.append(
                "receipts.json: block %s... is claimed by more than one receipt (%s) - "
                "one block pays one receipt" % (block_hash[:8], ", ".join(owners))
            )
    return errors


# --------------------------------------------------------------------------
# 4. jobs x receipts
# --------------------------------------------------------------------------

def cross_check(jobs_document, receipts_document):
    errors = []
    jobs = jobs_document.get("jobs") if isinstance(jobs_document, dict) else None
    receipts = receipts_document.get("receipts") if isinstance(receipts_document, dict) else None
    if not isinstance(jobs, list) or not isinstance(receipts, list):
        return errors
    by_id = {r.get("id"): r for r in receipts if isinstance(r, dict)}
    job_ids = {j.get("id") for j in jobs if isinstance(j, dict)}

    for job in jobs:
        if not isinstance(job, dict) or job.get("state") != "settled":
            continue
        receipt_id = job.get("receipt_id")
        if not receipt_id:
            continue  # already reported by check_jobs
        receipt = by_id.get(receipt_id)
        if receipt is None:
            errors.append(
                "jobs.json: %s is settled against receipt %r, which is not in receipts.json"
                % (job.get("id"), receipt_id)
            )
            continue
        if receipt.get("job_id") != job.get("id"):
            errors.append(
                "receipts.json: %s names job %r but job %s claims it"
                % (receipt_id, receipt.get("job_id"), job.get("id"))
            )
        block_hash = receipt.get("block_hash")
        if not isinstance(block_hash, str) or not BLOCK_HASH_RE.match(block_hash):
            errors.append(
                "jobs.json: %s is settled but its receipt %s carries no block hash - "
                "the block hash is in the receipt before the state changes"
                % (job.get("id"), receipt_id)
            )
        # By value: raw is an integer, so a padded "0500" and "500" are one
        # amount and this must not report a correct tree as a disagreement.
        if not same_amount(receipt.get("amount_raw"), job.get("price_raw")):
            errors.append(
                "receipts.json: %s paid %r raw for job %s, which is priced at %r raw"
                % (receipt_id, receipt.get("amount_raw"), job.get("id"), job.get("price_raw"))
            )

    for receipt in receipts:
        if isinstance(receipt, dict) and receipt.get("job_id") not in job_ids:
            errors.append(
                "receipts.json: %s names job %r, which is not in jobs.json"
                % (receipt.get("id"), receipt.get("job_id"))
            )
    return errors


# --------------------------------------------------------------------------
# 5. append-only
# --------------------------------------------------------------------------

def check_append_only(old_document, new_document):
    """Every receipt in the parent commit must still be present, unchanged."""
    errors = []
    old = old_document.get("receipts") if isinstance(old_document, dict) else None
    new = new_document.get("receipts") if isinstance(new_document, dict) else None
    if not isinstance(old, list):
        return errors
    if not isinstance(new, list):
        return ["receipts.json: 'receipts' must be a list"]
    new_by_id = {r.get("id"): r for r in new if isinstance(r, dict)}
    for receipt in old:
        if not isinstance(receipt, dict):
            continue
        receipt_id = receipt.get("id")
        if receipt_id not in new_by_id:
            errors.append(
                "receipts.json is append-only: receipt %r was removed. A payment "
                "that already happened cannot stop having happened." % receipt_id
            )
            continue
        current = new_by_id[receipt_id]
        if current != receipt:
            changed = sorted(
                key for key in set(receipt) | set(current)
                if receipt.get(key) != current.get(key)
            )
            errors.append(
                "receipts.json is append-only: receipt %r was edited (field(s): %s). "
                "Correct a mistake by appending a new receipt, never by rewriting one."
                % (receipt_id, ", ".join(changed))
            )
    return errors


def receipts_at_ref(ref, root, path="receipts.json"):
    """receipts.json as of a git ref, or None if it cannot be read."""
    try:
        blob = subprocess.run(
            ["git", "show", "%s:%s" % (ref, path)],
            cwd=root, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=True,
        ).stdout
    except (subprocess.CalledProcessError, OSError):
        return None
    try:
        return json.loads(blob.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None


# --------------------------------------------------------------------------
# 5b. the seller's offers - shape, then append-only
# --------------------------------------------------------------------------

OFFERS_FILE = "offers.json"

# The offers vocabulary is restated here rather than imported, and the reason is
# an import-graph rule this file is downstream of. `settle.py` imports this
# module, and `tests/test_settle.py` asserts that NOTHING transitively reachable
# from settle.py can open a socket except `nanonode.py`. Importing
# `seller_offer` here would pull in `order_bound_amount` -> `grant_mint` ->
# `authority_receipt`, two of which import `urllib`, and the money-send path
# would silently acquire a route to the network. Relaxing that guard so the
# validator could share one constant would be the wrong trade.
#
# Restating it costs a drift risk, so the drift is made a BUILD FAILURE instead
# of a comment: `tests/test_seller_offer.py` asserts, field for field and
# transition for transition, that these four values equal `seller_offer`'s. A
# field added there and not here turns that test red.
OFFER_FIELDS = (
    "id", "agent", "source", "source_url", "scope", "scope_digest_halves",
    "price_xno", "price_raw", "payout_address", "proposed", "expires", "state",
    "order_key", "order_digest_halves", "decided", "decline_reason",
    "receipt_id", "contact",
)
OFFER_STATES = ("proposed", "accepted", "declined", "expired", "settled")
OFFER_TRANSITIONS = (
    ("proposed", "accepted"), ("proposed", "declined"), ("proposed", "expired"),
    ("accepted", "settled"), ("accepted", "expired"),
)
OFFER_DECLINE_REASONS = (
    "out_of_scope", "price_above_cap", "duplicate", "cannot_verify_delivery",
    "no_budget", "seller_is_operator",
)
OFFER_SCOPE_KEYS = ("by", "input", "output")


def offer_scope_digest(scope):
    """The published recipe, implemented in four lines of stdlib.

    This is deliberately the reader's own path and not a call into
    `seller_offer`: the recipe is published on the face of `feed/offers.json`
    precisely so that it can be recomputed without our code, and a validator
    that checked it by asking the module that wrote it would be checking
    nothing.
    """
    material = {key: scope[key] for key in OFFER_SCOPE_KEYS}
    payload = json.dumps(material, sort_keys=True, separators=(",", ":"),
                         ensure_ascii=False).encode("utf-8")
    return hashlib.blake2b(payload, digest_size=32).hexdigest()


def offer_joined(value):
    """A digest written as two halves, back as one string. None if it is not."""
    if (isinstance(value, list) and len(value) == 2
            and all(isinstance(half, str) for half in value)):
        return "".join(value)
    return None


def check_offers(document):
    """Why `document` is not a valid offers document, as a list of failures."""
    if not isinstance(document, dict) or not isinstance(
            document.get("offers"), list):
        return ["offers.json: an offers document is an object with a list "
                "under the key 'offers'"]
    errors = []
    errors.extend("offers.json: %s" % message
                  for message in _duplicates([o.get("id")
                                              for o in document["offers"]
                                              if isinstance(o, dict)]))
    for index, offer in enumerate(document["offers"]):
        if not isinstance(offer, dict) or not isinstance(offer.get("id"), str):
            errors.append("offers.json: offers[%d] is not an offer with a "
                          "string id" % index)
            continue
        where = "offers.json: offer %r" % offer["id"]
        if offer.get("state") not in OFFER_STATES:
            errors.append("%s carries state %r, which is not one of %s"
                          % (where, offer.get("state"),
                             ", ".join(OFFER_STATES)))
            continue
        missing = sorted(set(OFFER_FIELDS) - set(offer))
        extra = sorted(set(offer) - set(OFFER_FIELDS))
        if missing or extra:
            errors.append("%s has the wrong fields: missing %s, unexpected %s"
                          % (where, missing, extra))
            continue
        if account_key(offer["payout_address"]) is None:
            errors.append("%s: payout_address fails its checksum - an address "
                          "that names no account is never stored" % where)
        errors.extend(_check_price(where, offer))
        if not isinstance(offer["scope"], dict) or set(
                offer["scope"]) != set(OFFER_SCOPE_KEYS):
            errors.append("%s: scope must carry exactly %s"
                          % (where, ", ".join(OFFER_SCOPE_KEYS)))
        elif offer_joined(offer["scope_digest_halves"]) is None:
            errors.append("%s: scope_digest_halves must be two 32-character "
                          "halves" % where)
        elif offer_joined(offer["scope_digest_halves"]) != offer_scope_digest(
                offer["scope"]):
            errors.append("%s: scope_digest does not match the scope it is "
                          "over. A seller's scope cannot be edited after it "
                          "was digested." % where)
        if offer["state"] == "accepted" and not offer["order_key"]:
            errors.append("%s is accepted but carries no order_key, so no "
                          "amount binds to it" % where)
        if offer["state"] == "declined" and (
                offer["decline_reason"] not in OFFER_DECLINE_REASONS):
            errors.append("%s is declined with reason %r, which is not one of "
                          "%s" % (where, offer["decline_reason"],
                                  ", ".join(OFFER_DECLINE_REASONS)))
        if offer["state"] == "settled" and not offer["receipt_id"]:
            errors.append("%s is settled but names no receipt" % where)
    return errors


# An offer's identity, the scope that was digested, the price and the payout
# address are immutable once written. A seller who was told no must be able to
# read why, so a declined row is never removed either.
OFFER_IMMUTABLE_FIELDS = (
    "id", "agent", "scope", "scope_digest_halves", "price_raw",
    "payout_address", "proposed",
)


def check_offers_append_only(old_document, new_document):
    """Every offer in the parent commit must still be there, unedited."""
    errors = []
    old = old_document.get("offers") if isinstance(old_document, dict) else None
    new = new_document.get("offers") if isinstance(new_document, dict) else None
    if not isinstance(old, list):
        return errors
    if not isinstance(new, list):
        return ["offers.json: 'offers' must be a list"]
    new_by_id = {o.get("id"): o for o in new if isinstance(o, dict)}
    legal = set(OFFER_TRANSITIONS)
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
        for field in OFFER_IMMUTABLE_FIELDS:
            if offer.get(field) != current.get(field):
                errors.append(
                    "offers.json: offer %r had %r changed. An offer's scope, "
                    "price and payout address are immutable once written; "
                    "correct a mistake by declining it and appending a new "
                    "one." % (offer_id, field))
        before, after = offer.get("state"), current.get("state")
        if before != after and (before, after) not in legal:
            errors.append(
                "offers.json: offer %r moved from %s to %s, which is not a "
                "legal transition." % (offer_id, before, after))
    return errors


# --------------------------------------------------------------------------
# 6. stats.json
# --------------------------------------------------------------------------

OPERATOR_ACCOUNTS_FILE = "operator_accounts.json"


def read_operator_accounts(root):
    """Every account this operator declares it controls, or an empty list.

    Declared in a file and never discovered from the data: an undeclared
    operator set is how a self-referential book publishes every row as outside
    demand (`external_edge_count.py`). An absent or unreadable file reads as
    "nothing declared", which makes the demand numbers publish as null with a
    reason rather than as a count - it never makes them read as strangers.
    """
    path = os.path.join(root, OPERATOR_ACCOUNTS_FILE)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            document = json.load(handle)
    except (OSError, ValueError):
        return []
    listed = document.get("operator_accounts") if isinstance(document, dict) else document
    return [value for value in listed if isinstance(value, str)] \
        if isinstance(listed, list) else []


def compute_stats(jobs_document, receipts_document, operator_accounts=()):
    jobs = [j for j in jobs_document.get("jobs", []) if isinstance(j, dict)]
    receipts = [r for r in receipts_document.get("receipts", []) if isinstance(r, dict)]
    total_raw = sum(int(r["amount_raw"]) for r in receipts)
    settled_at = sorted(r["settled_at"] for r in receipts)
    stats = {
        "jobs_open": sum(1 for j in jobs if j.get("state") == "open"),
        "jobs_settled": sum(1 for j in jobs if j.get("state") == "settled"),
        # By account, not by spelling: a receipt written before settle.py
        # canonicalised paid_to may carry the legacy form of an account another
        # row carries as nano_, and that is one seller, not two.
        "sellers_paid": len({account_key(r["paid_to"]) or r["paid_to"]
                             for r in receipts}),
        "paid_xno_total": raw_to_xno(total_raw),
        "first_settlement": settled_at[0] if settled_at else None,
        "last_settlement": settled_at[-1] if settled_at else None,
    }
    # Beside jobs_settled and sellers_paid, never instead of them. A settlement
    # count is the number a book inflates by accident, because it counts every
    # row the operator could have written; the number an underwriter can mark
    # is the count of distinct strangers who paid. Both are published, and
    # `demand_signal` names which is which.
    stats.update(external_edge_count.demand_fields(receipts, operator_accounts))
    return stats


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

def run(root, base_ref=None, write_stats=True, out=sys.stdout):
    errors = scan_for_secrets(root)
    if errors:
        # The secret gate runs before every other check and stops the run.
        print("SECRET GATE FAILED - nothing else was checked:", file=out)
        for error in errors:
            print("  %s" % error, file=out)
        return 1

    documents = {}
    for name in ("jobs.json", "receipts.json"):
        path = os.path.join(root, name)
        try:
            with open(path, "r", encoding="utf-8") as handle:
                documents[name] = json.load(handle)
        except OSError as exc:
            errors.append("%s: cannot be read (%s)" % (name, exc))
        except ValueError as exc:
            errors.append("%s: is not valid JSON (%s)" % (name, exc))
    if errors:
        for error in errors:
            print("FAIL %s" % error, file=out)
        return 1

    jobs_document, receipts_document = documents["jobs.json"], documents["receipts.json"]
    errors.extend(check_jobs(jobs_document))
    errors.extend(check_receipts(receipts_document))
    if not errors:
        errors.extend(cross_check(jobs_document, receipts_document))

    # offers.json is optional: the board worked before the seller had an inbox
    # and must go on working if the file is absent.
    offers_path = os.path.join(root, OFFERS_FILE)
    offers_document = None
    if os.path.exists(offers_path):
        try:
            with open(offers_path, "r", encoding="utf-8") as handle:
                offers_document = json.load(handle)
        except OSError as exc:
            errors.append("%s: cannot be read (%s)" % (OFFERS_FILE, exc))
        except ValueError as exc:
            errors.append("%s: is not valid JSON (%s)" % (OFFERS_FILE, exc))
        else:
            errors.extend(check_offers(offers_document))

    if base_ref:
        previous = receipts_at_ref(base_ref, root)
        if previous is None:
            print("note: no receipts.json at %s; append-only check skipped" % base_ref, file=out)
        else:
            errors.extend(check_append_only(previous, receipts_document))
        if offers_document is not None:
            previous_offers = receipts_at_ref(base_ref, root, OFFERS_FILE)
            if previous_offers is None:
                print("note: no %s at %s; append-only check skipped"
                      % (OFFERS_FILE, base_ref), file=out)
            else:
                errors.extend(check_offers_append_only(previous_offers,
                                                       offers_document))

    if errors:
        for error in errors:
            print("FAIL %s" % error, file=out)
        print("\n%d failure(s). Nothing was merged." % len(errors), file=out)
        return 1

    stats = compute_stats(jobs_document, receipts_document,
                          read_operator_accounts(root))
    if write_stats:
        with open(os.path.join(root, "stats.json"), "w", encoding="utf-8") as handle:
            json.dump(stats, handle, indent=2, sort_keys=True)
            handle.write("\n")
    print("OK  jobs_open=%d  jobs_settled=%d  sellers_paid=%d  paid_xno_total=%s XNO"
          % (stats["jobs_open"], stats["jobs_settled"],
             stats["sellers_paid"], stats["paid_xno_total"]), file=out)
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", default=os.path.dirname(os.path.abspath(__file__)))
    parser.add_argument(
        "--base", default=os.environ.get("VALIDATE_BASE_REF"),
        help="git ref of the parent commit, for the append-only check "
             "(CI passes the pull request's base SHA)",
    )
    parser.add_argument("--no-write-stats", action="store_true")
    args = parser.parse_args(argv)
    return run(args.root, base_ref=args.base, write_stats=not args.no_write_stats)


if __name__ == "__main__":
    sys.exit(main())
