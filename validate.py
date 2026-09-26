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
    stop having happened.

Usage:
    python3 validate.py [--root DIR] [--base GIT_REF] [--no-write-stats]

Exit 0 and write stats.json when everything holds; exit 1 and print every
failure otherwise. Each failure names the entry it is about.
"""

import argparse
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor"))

import nanoaddr  # noqa: E402
from money import raw_to_xno, xno_to_raw  # noqa: E402

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
    return isinstance(value, str) and value.isdigit() and int(value) > 0


def _rfc3339(value):
    match = RFC3339_RE.match(value) if isinstance(value, str) else None
    if not match:
        return None
    year, month, day, hour, minute, second = (int(g) for g in match.groups())
    if not (1 <= month <= 12 and 1 <= day <= 31):
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
        if receipt.get("amount_raw") != job.get("price_raw"):
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
# 6. stats.json
# --------------------------------------------------------------------------

def compute_stats(jobs_document, receipts_document):
    jobs = [j for j in jobs_document.get("jobs", []) if isinstance(j, dict)]
    receipts = [r for r in receipts_document.get("receipts", []) if isinstance(r, dict)]
    total_raw = sum(int(r["amount_raw"]) for r in receipts)
    settled_at = sorted(r["settled_at"] for r in receipts)
    return {
        "jobs_open": sum(1 for j in jobs if j.get("state") == "open"),
        "jobs_settled": sum(1 for j in jobs if j.get("state") == "settled"),
        "sellers_paid": len({r["paid_to"] for r in receipts}),
        "paid_xno_total": raw_to_xno(total_raw),
        "first_settlement": settled_at[0] if settled_at else None,
        "last_settlement": settled_at[-1] if settled_at else None,
    }


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

    if base_ref:
        previous = receipts_at_ref(base_ref, root)
        if previous is None:
            print("note: no receipts.json at %s; append-only check skipped" % base_ref, file=out)
        else:
            errors.extend(check_append_only(previous, receipts_document))

    if errors:
        for error in errors:
            print("FAIL %s" % error, file=out)
        print("\n%d failure(s). Nothing was merged." % len(errors), file=out)
        return 1

    stats = compute_stats(jobs_document, receipts_document)
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
