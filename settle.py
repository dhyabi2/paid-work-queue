#!/usr/bin/env python3
"""Turn a payment that already happened into a receipt anyone can check.

README step 6 says "We pay, then we publish the receipt". This is the second
half, and only the second half: it holds no seed, no private key, no wallet id
and no node credential, and it cannot move money. The operator sends the payment
with their own wallet and hands this tool the block hash. The tool asks a public
node four questions before it writes anything:

  1. is that block confirmed,
  2. is it a send,
  3. did it go to the address the job's claimant gave, and
  4. was the amount exactly `price_raw`.

Only then does a receipt exist. That ordering is the custody answer in
executable form - this repository can prove a payment happened and is
structurally incapable of causing one. `tests/test_settle.py` enforces it: no
module reachable from here can sign or send, and nothing but `nanonode.py` can
open a socket.
"""

import argparse
import datetime
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "vendor"))

import nanoaddr  # noqa: E402
import nanonode  # noqa: E402
import validate  # noqa: E402
from claim import format_xno  # noqa: E402  - one renderer for money, not two
from canonical import (  # noqa: E402  - one comparison, not three
    canonical_account, canonical_raw, same_account, same_amount)

JOBS_FILE = "jobs.json"
RECEIPTS_FILE = "receipts.json"
STATS_FILE = "stats.json"
TRACKED = (JOBS_FILE, RECEIPTS_FILE, STATS_FILE)

BASE_REF = "origin/main"
HASH_RE = re.compile(r"\A[0-9a-fA-F]{64}\Z")

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NO_SUCH_JOB = 3
EXIT_WRONG_STATE = 4
EXIT_NO_FILE = 5
EXIT_NO_NODE = 6
EXIT_NODE = 7
EXIT_NOT_APPENDED = 8
EXIT_MISMATCH = 9


class Refused(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


def now_utc():
    """Overridden in tests so a dry run and a real run can be compared."""
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def looks_like_a_key(value):
    """64 bare hex characters is a seed or a private key, never a URL or handle."""
    return bool(value) and bool(HASH_RE.match(str(value).strip()))


# --------------------------------------------------------------------------
# reading and writing the three files, all or nothing
# --------------------------------------------------------------------------

def read_document(root, name):
    path = os.path.join(root, name)
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        raise Refused(
            EXIT_NO_FILE,
            "%s not found - run this from a clone of dhyabi2/paid-work-queue" % name)
    try:
        return raw, json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise Refused(EXIT_NO_FILE, "%s is malformed: %s" % (name, exc))


def snapshot(root):
    """The bytes of every file this tool may touch, for an exact rollback."""
    state = {}
    for name in TRACKED:
        path = os.path.join(root, name)
        try:
            with open(path, "rb") as handle:
                state[name] = handle.read()
        except OSError:
            state[name] = None
    return state


def restore(root, state):
    for name, payload in state.items():
        path = os.path.join(root, name)
        if payload is None:
            continue
        with open(path, "wb") as handle:
            handle.write(payload)


def write_atomically(root, name, payload):
    final = os.path.join(root, name)
    tmp = final + ".tmp"
    try:
        with open(tmp, "wb") as handle:
            handle.write(payload)
        os.replace(tmp, final)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def serialise(document, trailing_newline=True):
    text = json.dumps(document, indent=2)
    if trailing_newline:
        text += "\n"
    return text.encode("utf-8")


# --------------------------------------------------------------------------
# append-only, checked here so the failure is found before a pull request
# --------------------------------------------------------------------------

APPEND_ONLY_RULE = (
    "receipts.json is append-only: a payment that already happened cannot stop "
    "having happened, so an existing receipt is never edited or deleted"
)


def assert_only_appended(root, receipts_document):
    previous = validate.receipts_at_ref(BASE_REF, root)
    if previous is None:
        raise Refused(
            EXIT_NOT_APPENDED,
            "cannot read %s at %s, so this run cannot prove that %s - refusing"
            % (RECEIPTS_FILE, BASE_REF, APPEND_ONLY_RULE))
    errors = validate.check_append_only(previous, receipts_document)
    if errors:
        raise Refused(
            EXIT_NOT_APPENDED,
            "receipts.json has been edited, not appended to - refusing\n  %s"
            % "\n  ".join(errors))


# --------------------------------------------------------------------------
# the job and the block
# --------------------------------------------------------------------------

def find_job(jobs_document, job_id):
    for job in jobs_document.get("jobs", []):
        if isinstance(job, dict) and job.get("id") == job_id:
            return job
    raise Refused(EXIT_NO_SUCH_JOB, "no such job: %s" % job_id)


def check_job_is_settleable(job, job_id, receipts_document):
    for receipt in receipts_document.get("receipts", []):
        if isinstance(receipt, dict) and receipt.get("job_id") == job_id:
            raise Refused(
                EXIT_WRONG_STATE,
                "job %s is already settled by block %s - a payment is never "
                "recorded twice" % (job_id, receipt.get("block_hash")))
    state = job.get("state")
    if state != "claimed":
        raise Refused(
            EXIT_WRONG_STATE,
            "job %s is %s; only a claimed job can settle" % (job_id, state))
    address = job.get("payout_address")
    if not isinstance(address, str) or not address.strip():
        raise Refused(
            EXIT_WRONG_STATE,
            "job %s has no payout_address - the seller has not given one" % job_id)
    verdict = nanoaddr.validate(address)
    if not verdict["valid"]:
        raise Refused(
            EXIT_WRONG_STATE,
            "job %s carries a payout_address that fails its checksum (%s) - it "
            "was never payable" % (job_id, verdict["reason"]))
    claim_url = job.get("claim_url")
    if not isinstance(claim_url, str) or not claim_url:
        # Not in the spec's error table, and it has to be: validate.py refuses a
        # job in any claimed state without a claim_url string, so settling this
        # job would produce a tree CI rejects. Refusing here, before the node is
        # asked anything, says so with the fix attached.
        raise Refused(
            EXIT_WRONG_STATE,
            "job %s has no claim_url - validate.py refuses a job in a claimed "
            "state without one, so a receipt for it could not be merged; run "
            "claim.py %s --release and claim it again with --claim-url"
            % (job_id, job_id))
    if not str(job.get("price_raw", "")).isdigit():
        raise Refused(
            EXIT_NO_FILE,
            "%s is malformed: 'price_raw' of %s is %r, which is not an integer "
            "string" % (JOBS_FILE, job_id, job.get("price_raw")))
    return address


def interrogate(node, node_url, block_hash, job, job_id, address):
    """One request. Returns nothing; raises on every disagreement."""
    try:
        answer = node.block_info(block_hash)
    except nanonode.NodeError as exc:
        raise Refused(EXIT_NODE, "node %s did not answer: %s" % (node_url, exc))
    if answer.get("error"):
        raise Refused(
            EXIT_NODE,
            "node %s does not know block %s - nothing was written"
            % (node_url, block_hash))
    if str(answer.get("confirmed")).lower() != "true":
        raise Refused(
            EXIT_NODE,
            "block %s is not confirmed yet - refusing to publish an "
            "unconfirmed receipt" % block_hash)
    subtype = answer.get("subtype")
    if subtype != "send":
        raise Refused(EXIT_NODE, "block %s is a %s, not a send" % (block_hash, subtype))

    contents = answer.get("contents") or {}
    destination = contents.get("link_as_account")
    # By account, not by spelling. The node answers the `nano_` form; the job
    # carries whatever the claimant typed, which for older tooling is the `xrb_`
    # form of that very same account. Comparing the two strings refused a
    # payment that had arrived in full - and the buyer's money had already moved.
    if not same_account(destination, address):
        raise Refused(
            EXIT_MISMATCH,
            "block %s paid %s, but job %s is owed %s - refusing"
            % (block_hash, destination, job_id, address))
    amount = str(answer.get("amount"))
    expected = str(job["price_raw"])
    # Raw is an integer: "0500" and "500" are one amount, and a padded price
    # reaches here because validate.py admits one. A non-integer on either side
    # refuses, so this is no weaker than the string comparison it replaces.
    if not same_amount(amount, expected):
        raise Refused(
            EXIT_MISMATCH,
            "block %s paid %s raw, job %s is priced at %s raw - refusing"
            % (block_hash, amount, job_id, expected))


# The explorer to look the block up on. It deliberately does NOT interpolate the
# hash: validate.py's secret gate permits 64 hex characters in a `block_hash`
# field and nowhere else, so a URL carrying the hash would fail the tree. This is
# the same form the repository's own e2e fixture uses - the reader appends the
# receipt's block_hash.
EXPLORER = "https://nanolooker.com/block/see-block_hash"


def next_receipt_id(receipts):
    """receipt-001, receipt-002, ... - the id convention the repository uses.

    `id` is not in the spec's receipt object and has to be: validate.py refuses
    a receipt without a usable one, requires it unique, and a settled job points
    at it through `receipt_id`. Numbering from the count and then stepping past
    anything taken keeps it stable and unique even if a receipt was added by
    hand.
    """
    taken = {r.get("id") for r in receipts if isinstance(r, dict)}
    index = len(receipts) + 1
    while ("receipt-%03d" % index) in taken:
        index += 1
    return "receipt-%03d" % index


def build_receipt(job, job_id, address, block_hash, node_url, delivery_url,
                  moment, receipt_id):
    receipt = {
        "id": receipt_id,
        "job_id": job_id,
        "seller": job.get("claimed_by"),
        # Canonical, not as-typed: sellers_paid counts distinct paid_to values,
        # so one account written two ways would publish as two sellers paid.
        "paid_to": canonical_account(address),
        "amount_raw": canonical_raw(job["price_raw"]),
        "amount_xno": format_xno(str(job["price_raw"]), job_id),
        "block_hash": block_hash,
        "confirmed": True,
        # `verify` is the point of the whole file: a stranger reads the receipt
        # and checks the payment on a chain we do not run.
        "verify": EXPLORER,
        "node_queried": node_url,
        "delivery_url": delivery_url,
    }
    claim_url = job.get("claim_url")
    if isinstance(claim_url, str) and claim_url:
        receipt["claim_url"] = claim_url
    receipt["settled_at"] = moment.strftime("%Y-%m-%dT%H:%M:%SZ")
    return receipt


# --------------------------------------------------------------------------
# the run
# --------------------------------------------------------------------------

def settle(root, job_id, block_hash, delivery_url, node_url, node=None,
           dry_run=False, as_json=False, out=sys.stdout, expected_payee=None):
    if not HASH_RE.match(block_hash or ""):
        raise Refused(EXIT_USAGE, "--block-hash must be 64 hex characters")
    block_hash = block_hash.upper()
    if not delivery_url or not delivery_url.startswith("https://"):
        raise Refused(
            EXIT_USAGE,
            "--delivery-url must be an https URL - a receipt names the work it paid for")
    for value in (node_url, delivery_url):
        if looks_like_a_key(value):
            raise Refused(EXIT_USAGE, "that looks like a key or seed - refusing")
    if not node_url:
        raise Refused(
            EXIT_NO_NODE,
            "--node or NANO_NODE_URL is required - a receipt that was not "
            "checked against a node is not a receipt")

    jobs_raw, jobs_document = read_document(root, JOBS_FILE)
    receipts_raw, receipts_document = read_document(root, RECEIPTS_FILE)
    if not isinstance(receipts_document.get("receipts"), list):
        raise Refused(
            EXIT_NO_FILE, "%s is malformed: no 'receipts' list" % RECEIPTS_FILE)

    job = find_job(jobs_document, job_id)
    address = check_job_is_settleable(job, job_id, receipts_document)
    if expected_payee is not None and address != expected_payee:
        # The claim and the job disagree about who gets paid. Whichever is
        # right, paying either without finding out is how money goes to the
        # wrong account, so this refuses and names both.
        raise Refused(
            EXIT_MISMATCH,
            "the claim says pay %s and job %s says pay %s - they must be the "
            "same account before anything is recorded"
            % (expected_payee, job_id, address))
    if looks_like_a_key(job.get("claimed_by")):
        raise Refused(EXIT_USAGE, "that looks like a key or seed - refusing")

    assert_only_appended(root, receipts_document)

    if node is None:
        node = nanonode.HttpNanoNode(node_url)
    interrogate(node, node_url, block_hash, job, job_id, address)

    receipt_id = next_receipt_id(receipts_document["receipts"])
    receipt = build_receipt(job, job_id, address, block_hash, node_url,
                            delivery_url, now_utc(), receipt_id)

    after_receipts = {"receipts": list(receipts_document["receipts"]) + [receipt]}
    after_jobs = json.loads(jobs_raw.decode("utf-8"))
    for candidate in after_jobs["jobs"]:
        if candidate.get("id") == job_id:
            candidate["state"] = "settled"
            # validate.py: "no receipt, no settled state". The job points at the
            # receipt, and cross_check compares the two in both directions.
            candidate["receipt_id"] = receipt_id
    stats = validate.compute_stats(after_jobs, after_receipts)

    if dry_run:
        if as_json:
            print(json.dumps({"ok": True, "receipt": receipt, "stats": stats},
                             indent=2), file=out)
        else:
            print("dry run - nothing was written. the receipt this would append:", file=out)
            print(json.dumps(receipt, indent=2), file=out)
            print("the stats.json this would produce:", file=out)
            print(json.dumps(stats, indent=2, sort_keys=True), file=out)
        return EXIT_OK

    before = snapshot(root)
    try:
        write_atomically(root, RECEIPTS_FILE,
                         serialise(after_receipts, receipts_raw.endswith(b"\n")))
        write_atomically(root, JOBS_FILE,
                         serialise(after_jobs, jobs_raw.endswith(b"\n")))
        # The repository's own regeneration, so stats.json is byte-identical to
        # what CI produces - and a settlement that CI would reject never lands.
        with open(os.devnull, "w", encoding="utf-8") as quiet:
            code = validate.run(root, write_stats=True, out=quiet)
        if code != 0:
            report = []
            validate.run(root, write_stats=False, out=_Collector(report))
            raise Refused(
                EXIT_MISMATCH,
                "the settled tree does not pass validate.py, so nothing was "
                "written:\n  %s" % "\n  ".join(report))
    except BaseException:
        restore(root, before)
        raise

    if as_json:
        print(json.dumps({"ok": True, "receipt": receipt, "stats": stats}, indent=2),
              file=out)
    else:
        print("settled %s: %s XNO to %s" % (job_id, receipt["amount_xno"], address),
              file=out)
        print("block %s confirmed by %s" % (block_hash, node_url), file=out)
        print("receipt appended to %s, %s regenerated" % (RECEIPTS_FILE, STATS_FILE),
              file=out)
        print("jobs_settled=%s  sellers_paid=%s  paid_xno_total=%s XNO"
              % (stats["jobs_settled"], stats["sellers_paid"],
                 stats["paid_xno_total"]), file=out)
    return EXIT_OK


class _Collector:
    """Gives validate.run's printed failures somewhere to go."""

    def __init__(self, sink):
        self.sink = sink

    def write(self, text):
        for line in text.splitlines():
            if line.strip():
                self.sink.append(line.strip())

    def flush(self):
        pass


CLAIMS_FILE = "claims.json"


def resolve_claim(root, claim_id):
    """(job_id, payee) for a claim taken over HTTP, or raise Refused.

    A claim made at `POST /unstuck/api/v1/jobs/{id}/claim` is recorded in
    claims.json rather than by pull request, so the operator settling it has no
    job id in front of them - only the claim id the agent was handed. This
    resolves one to the other and then hands the normal path the same two facts
    it always had, so a claim taken over HTTP settles with the same tool and
    the same refusals - including the checksum refusal - as one taken by pull
    request.
    """
    path = os.path.join(root, CLAIMS_FILE)
    try:
        with open(path, "rb") as handle:
            document = json.loads(handle.read().decode("utf-8"))
    except FileNotFoundError:
        raise Refused(
            EXIT_NO_FILE,
            "%s not found - there are no HTTP claims to settle in this clone"
            % CLAIMS_FILE) from None
    except ValueError as exc:
        raise Refused(EXIT_NO_FILE, "%s is malformed: %s" % (CLAIMS_FILE, exc)) from None

    claims = document.get("claims")
    if not isinstance(claims, list):
        raise Refused(EXIT_NO_FILE, "%s is malformed: no 'claims' list" % CLAIMS_FILE)
    for claim in claims:
        if isinstance(claim, dict) and claim.get("claim_id") == claim_id:
            break
    else:
        raise Refused(EXIT_NO_SUCH_JOB,
                      "no claim %r in %s" % (claim_id, CLAIMS_FILE))

    payee = claim.get("payee")
    verdict = nanoaddr.validate(payee or "")
    if not verdict["valid"]:
        # http_claim.py never stores an address that fails checksum, so this is
        # a claims.json that was edited by hand or corrupted. Refusing here
        # keeps the one rule that matters: an address that fails its checksum
        # is never paid to.
        raise Refused(
            EXIT_WRONG_STATE,
            "claim %s carries a payee that fails its checksum (%s) - it was "
            "never payable" % (claim_id, verdict["reason"]))
    job_id = claim.get("job_id")
    if not isinstance(job_id, str) or not job_id:
        raise Refused(EXIT_WRONG_STATE,
                      "claim %s names no job" % claim_id)
    # Normalised on both sides. The two prefixes name the same account, and on
    # 2026-09-27 this file compared them as strings - so an xrb_-spelled payee
    # could never be settled, found after the money had gone irreversibly.
    return job_id, verdict["normalised"]


def build_parser():
    parser = argparse.ArgumentParser(
        prog="settle.py",
        description="Record a payment that already happened. This tool cannot make one.",
    )
    parser.add_argument("job_id", nargs="?",
                        help="the id of the job being settled; omit it when "
                             "--claim-id names an HTTP claim")
    parser.add_argument("--claim-id",
                        help="settle the job held by this claim (clm_...), "
                             "taken over HTTP rather than by pull request")
    parser.add_argument("--block-hash", required=False, default="",
                        help="the 64-hex hash of the send block")
    parser.add_argument("--delivery-url", default="",
                        help="the https URL of the work being paid for")
    parser.add_argument("--node", default=os.environ.get("NANO_NODE_URL", ""),
                        help="a public Nano node's RPC URL, or NANO_NODE_URL")
    parser.add_argument("--dry-run", action="store_true",
                        help="print the receipt and stats this would write, and stop")
    parser.add_argument("--json", action="store_true", dest="as_json")
    return parser


def main(argv=None, out=None, err=None, root=HERE, node=None):
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    args = build_parser().parse_args(argv)
    try:
        job_id, expected_payee = args.job_id, None
        if args.claim_id:
            resolved, expected_payee = resolve_claim(root, args.claim_id)
            if job_id and job_id != resolved:
                raise Refused(
                    EXIT_USAGE,
                    "claim %s is against job %s, not %s - settle the job the "
                    "claim names or drop the positional argument"
                    % (args.claim_id, resolved, job_id))
            job_id = resolved
        if not job_id:
            raise Refused(EXIT_USAGE,
                          "give a job id, or --claim-id to settle an HTTP claim")
        return settle(root, job_id, args.block_hash, args.delivery_url,
                      args.node, node=node, dry_run=args.dry_run,
                      as_json=args.as_json, out=out,
                      expected_payee=expected_payee)
    except Refused as refusal:
        print(refusal.message, file=err)
        return refusal.code


if __name__ == "__main__":
    sys.exit(main())
