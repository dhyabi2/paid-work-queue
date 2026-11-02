#!/usr/bin/env python3
"""Settle an XNO leg against a claim link on SOMEONE ELSE'S board.

`AutomatedJanitor2015` (RustChain bounties) refused twice on 2026-10-24: "The current RustChain bounty architecture
is designed for internal settlement via RTC ... There is no designated slot or primitive for an external settlement
leg ... the reward payout is hard-coded to the RustChain reward pool." And in the same message: "The
'claim-on-GitHub-issue' pattern serves as the verifiable link for work completion."

So the claim is public and checkable and only the payment is captive. We do not ask that board to add a leg. WE are
the payer: a parallel, second XNO payment against the claim link their board already produced. Their state machine
does not change by one line, and that is the headline this tool publishes (`state_machines_we_asked_to_change: 0`).

    python3 foreign_claim.py record    --board-url U --claim-url U --worker-handle H --work-url U --their-settlement S --now T
    python3 foreign_claim.py address   ID --payout-address nano_... --said-at T --said-in URL [--replace] --now T
    python3 foreign_claim.py authorise ID --amount-raw N --by WHO --now T
    python3 foreign_claim.py settle    ID --block HASH --now T
    python3 foreign_claim.py feed      --now T
    python3 foreign_claim.py --self-test

MONEY BOUNDARY. This tool never chooses an amount, never sends, never signs. `authorise` only RECORDS an amount a
named person gave and refuses without one: there is no default and no suggestion. `settle` records a block hash that
already exists; it does not look the block up (no network in any path) and so writes `verification_tier:
live_editable_file` on the receipt, honestly: nobody here confirmed the block. Confirming it is a separate step
(`settle.py` against a node, or the reader's own node).

It does not fetch `claim_url`: a tool that fetches arbitrary URLs supplied by strangers is a different and worse
tool. It holds no clock: `--now` is required. Standard library plus this repository's vendored `money`/`nanoaddr`.
"""
import argparse
import json
import os
import re
import sys
import urllib.parse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "vendor"))

import money  # noqa: E402
import nanoaddr  # noqa: E402

TOOL = "foreign_claim"
V = "foreign-claim-v1"
FEED_V = "foreign-claims-feed-v1"
STATE_FILE = "foreign_claims.json"
RECEIPTS_FILE = "receipts.json"
OPERATOR_FILE = "operator_accounts.json"
EXPLORER = "https://nanolooker.com/block/see-block_hash"      # the same constant settle.py writes

STATES = ("recorded", "addressed", "authorised", "settled")
CODES = (
    "claim_url_not_a_url", "claim_url_not_public", "claim_url_is_ours", "duplicate_claim_url",
    "bad_address_checksum", "address_not_in_their_words", "address_already_recorded", "amount_not_authorised",
    "amount_not_integer_string", "address_required_before_amount", "wrong_state", "no_clock", "bad_block_hash",
    "block_already_used", "no_such_foreign_claim", "bad_field", "bad_state_file", "authorised_by_required",
)

NOTE = ("This is a SECOND payment for work already settled on the worker's own board under its own rules. Nothing "
        "here asks that board to change, to hold XNO, or to add a settlement leg.")

_RFC3339 = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_HASH = re.compile(r"^[0-9A-Fa-f]{64}$")
_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F]*:[0-9a-fA-F:.]*$")
_FORGES = ("github.com", "gitlab.com", "codeberg.org", "bitbucket.org")


class Refusal(Exception):
    def __init__(self, code, detail):
        super().__init__("%s: %s" % (code, detail))
        if code not in CODES:
            raise AssertionError("undeclared refusal code %r" % code)
        self.code, self.detail = code, detail


# --------------------------------------------------------------------------
# checks
# --------------------------------------------------------------------------

def need_now(now):
    if not (isinstance(now, str) and _RFC3339.match(now)):
        raise Refusal("no_clock", "--now is required, RFC3339 UTC ending in Z: this tool holds no clock")
    return now


def parse_url(value, code):
    try:
        u = urllib.parse.urlsplit(value) if isinstance(value, str) else None
    except ValueError:
        u = None
    if not u or u.scheme not in ("http", "https") or not u.hostname:
        raise Refusal(code, "%r is not an absolute http(s) URL" % (value,))
    return u


def claim_host(claim_url):
    return parse_url(claim_url, "claim_url_not_a_url").hostname.lower()


def check_public(u):
    host = u.hostname.lower()
    if host in ("localhost",) or host.endswith(".local") or host.endswith(".localhost") or _IP.match(host):
        raise Refusal("claim_url_not_public", "%r is not a name anyone else can resolve; a claim nobody else can read "
                      "is not a verifiable link" % host)


def owners_of(url, owners):
    """Whether `url` points inside an account the operator owns (first path segment on a forge, or <owner>.github.io)."""
    u = urllib.parse.urlsplit(url)
    host = (u.hostname or "").lower()
    low = {o.lower() for o in owners}
    if host in _FORGES:
        seg = [p for p in u.path.split("/") if p]
        return bool(seg) and seg[0].lower() in low
    if host.endswith(".github.io"):
        return host[: -len(".github.io")] in low
    return False


def checked_amount_raw(value):
    if not (isinstance(value, str) and re.fullmatch(r"[0-9]+", value) and int(value) > 0):
        raise Refusal("amount_not_integer_string", "--amount-raw must be a positive integer string of raw (1 XNO = 10**30 "
                      "raw); %r is not. A float cannot hold 1 raw." % (value,))
    return str(int(value))


# --------------------------------------------------------------------------
# state
# --------------------------------------------------------------------------

def empty():
    return {"v": V, "foreign_claims": []}


def load(root):
    path = os.path.join(root, STATE_FILE)
    if not os.path.exists(path):
        return empty()
    with open(path, "r", encoding="utf-8") as fh:
        try:
            doc = json.load(fh)
        except ValueError as exc:
            raise Refusal("bad_state_file", "%s is not JSON: %s" % (STATE_FILE, exc))
    if not isinstance(doc, dict) or not isinstance(doc.get("foreign_claims"), list):
        raise Refusal("bad_state_file", "%s must be {\"foreign_claims\": [...]}" % STATE_FILE)
    return doc


def dump(doc):
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode("utf-8")


def write_atomic(root, name, payload):
    final = os.path.join(root, name)
    tmp = final + ".tmp"
    try:
        with open(tmp, "wb") as fh:
            fh.write(payload)
        os.replace(tmp, final)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def operator_github_owners(root):
    try:
        with open(os.path.join(root, OPERATOR_FILE), "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return []
    owners = doc.get("operator_github_owners") if isinstance(doc, dict) else None
    return [o for o in owners if isinstance(o, str)] if isinstance(owners, list) else []


def find(doc, claim_id):
    for row in doc["foreign_claims"]:
        if row.get("id") == claim_id:
            return row
    raise Refusal("no_such_foreign_claim", "no foreign claim %r" % (claim_id,))


def need_state(row, wanted, doing):
    if row["state"] != wanted:
        raise Refusal("wrong_state", "%s needs state %r and %s is %r" % (doing, wanted, row["id"], row["state"]))


def next_id(doc, now):
    date = now[:10]
    taken = {r.get("id") for r in doc["foreign_claims"]}
    n = 1
    while "fc-%s-%03d" % (date, n) in taken:
        n += 1
    return "fc-%s-%03d" % (date, n)


def next_receipt_id(receipts):
    """receipt-001, ... exactly as settle.next_receipt_id (a test pins the parity)."""
    taken = {r.get("id") for r in receipts if isinstance(r, dict)}
    index = len(receipts) + 1
    while ("receipt-%03d" % index) in taken:
        index += 1
    return "receipt-%03d" % index


# --------------------------------------------------------------------------
# the moves
# --------------------------------------------------------------------------

def record(doc, *, board_url, claim_url, worker_handle, work_url, their_settlement, now, owners=()):
    now = need_now(now)
    parse_url(board_url, "claim_url_not_a_url")
    cu = parse_url(claim_url, "claim_url_not_a_url")
    parse_url(work_url, "claim_url_not_a_url")
    check_public(cu)
    for url in (claim_url, board_url, work_url):
        if owners_of(url, owners):
            raise Refusal("claim_url_is_ours", "%s is inside an account the operator declared (operator_accounts.json, "
                          "operator_github_owners). A foreign claim we could have written ourselves is not external "
                          "demand." % url)
    for field, value in (("worker_handle", worker_handle), ("their_settlement", their_settlement)):
        if not (isinstance(value, str) and value.strip()):
            raise Refusal("bad_field", "%s must be a non-empty string" % field)
    for row in doc["foreign_claims"]:
        if row.get("claim_url") == claim_url:
            raise Refusal("duplicate_claim_url", "%s already has a row (%s); paying twice for one claim is how a board "
                          "loses a stranger's trust" % (claim_url, row["id"]))
    row = {
        "v": V,
        "id": next_id(doc, now),
        "state": "recorded",
        "board_url": board_url,
        "claim_url": claim_url,
        "claim_host": cu.hostname.lower(),
        "worker_handle": worker_handle,
        "work_url": work_url,
        "their_settlement": their_settlement,           # verbatim, never classified: not ours to classify
        "our_settlement": "XNO",
        "changes_their_state_machine": False,
        "payout_address": None,
        "payout_address_said_in": None,
        "payout_address_said_at": None,
        "payout_address_history": [],
        "amount_raw": None,
        "amount_authorised_by": None,
        "recorded_at": now,
        "receipt_id": None,
        "note": NOTE,
    }
    doc["foreign_claims"].append(row)
    return doc, row


def address(doc, claim_id, *, payout_address, said_in, said_at, replace=False, now=None):
    need_now(now)
    row = find(doc, claim_id)
    verdict = nanoaddr.validate(payout_address)
    if not verdict["valid"]:
        raise Refusal("bad_address_checksum", "reason=%s: %s" % (verdict["reason"], verdict["message"]))
    try:
        parse_url(said_in, "address_not_in_their_words")
    except Refusal:
        raise Refusal("address_not_in_their_words", "--said-in must be the URL of the message where THEY typed the "
                      "address; we never type an address on an agent's behalf")
    if not (isinstance(said_at, str) and _RFC3339.match(said_at)):
        raise Refusal("bad_field", "--said-at must be RFC3339 UTC")
    if row["state"] not in ("recorded", "addressed"):
        raise Refusal("wrong_state", "address needs state recorded or addressed and %s is %r" % (row["id"], row["state"]))
    if row["payout_address"] is not None:
        if not (replace and said_at > (row["payout_address_said_at"] or "")):
            raise Refusal("address_already_recorded", "%s already has an address; replacing needs --replace AND a newer "
                          "--said-at than %s" % (row["id"], row["payout_address_said_at"]))
        row["payout_address_history"].append({"payout_address": row["payout_address"],
                                              "said_in": row["payout_address_said_in"],
                                              "said_at": row["payout_address_said_at"]})
    row.update(payout_address=payout_address, payout_address_said_in=said_in, payout_address_said_at=said_at,
               state="addressed")
    return doc, row


def authorise(doc, claim_id, *, amount_raw, by, now):
    need_now(now)
    row = find(doc, claim_id)
    if amount_raw is None:
        raise Refusal("amount_not_authorised", "--amount-raw is required: no default, no suggestion, no typical value. "
                      "The amount is the owner's.")
    raw = checked_amount_raw(amount_raw)
    if not (isinstance(by, str) and by.strip()):
        raise Refusal("authorised_by_required", "--by must name who authorised the amount")
    if row["state"] == "recorded":
        raise Refusal("address_required_before_amount", "an authorised amount with nowhere to send it is a promise, and "
                      "this board does not make promises")
    need_state(row, "addressed", "authorise")
    row.update(amount_raw=raw, amount_authorised_by=by.strip(), state="authorised",
               authorised_at=now)
    return doc, row


def settle(doc, receipts_doc, claim_id, *, block, now):
    now = need_now(now)
    row = find(doc, claim_id)
    need_state(row, "authorised", "settle")
    if not (isinstance(block, str) and _HASH.match(block)):
        raise Refusal("bad_block_hash", "--block must be 64 hex characters")
    block = block.upper()
    receipts = receipts_doc["receipts"]
    if any(r.get("block_hash") == block for r in receipts if isinstance(r, dict)):
        raise Refusal("block_already_used", "one block pays one receipt")
    receipt_id = next_receipt_id(receipts)
    receipt = {
        "id": receipt_id,
        "job_id": row["id"],
        "seller": row["worker_handle"],
        "paid_to": row["payout_address"],
        "amount_raw": row["amount_raw"],
        "amount_xno": money.raw_to_xno(int(row["amount_raw"])),
        "block_hash": block,
        "verify": EXPLORER,
        "delivery_url": row["work_url"],
        "claim_url": row["claim_url"],
        "work_url": row["work_url"],
        "foreign_claim_id": row["id"],
        # Honest: this tool recorded a hash and asked no node about it.
        "verification_tier": "live_editable_file",
        "settled_at": now,
    }
    receipts.append(receipt)
    row.update(state="settled", receipt_id=receipt_id, block_hash=block, settled_at=now)
    return doc, receipts_doc, row, receipt


def feed(doc, *, now):
    now = need_now(now)
    rows = sorted(doc["foreign_claims"], key=lambda r: r["id"])
    settled = [r for r in rows if r["state"] == "settled"]
    total = sum(int(r["amount_raw"]) for r in settled)
    after_work = [r for r in settled if (r.get("payout_address_said_at") or "") >= r["recorded_at"]]
    return {
        "v": FEED_V,
        "generated_at": now,
        # Nothing below is derived from a clock: every aggregate is a function of the rows alone, so there is no
        # `hours_left`-shaped field that needs its own `_as_of`.
        "clock_derived_fields": [],
        "read_this_first": ("The claim is public and checkable; only the payment is captive. We pay a second XNO "
                            "payment against the claim link a foreign board already produced. "
                            "`state_machines_we_asked_to_change` is 0 by construction."),
        "state_machines_we_asked_to_change": 0,
        "foreign_boards": len({r["board_url"] for r in settled}),
        "foreign_settled_count": len(settled),
        "foreign_settled_total_raw": str(total),
        "foreign_settled_total_xno": money.raw_to_xno(total),
        "workers_paid_who_hold_no_xno_account_with_us": len(after_work),
        "workers_paid_note": "settled rows whose payout address was given by the worker after we recorded their claim",
        "foreign_claims": [json.loads(json.dumps(r)) for r in rows],
        "what_this_does_not_do": ["fetch claim_url", "send XNO", "ask the foreign board for anything"],
    }


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _out(obj):
    print(json.dumps(obj, indent=2, sort_keys=True))


def build_parser():
    p = argparse.ArgumentParser(prog="foreign_claim.py", description=__doc__.splitlines()[0])
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--root", default=HERE)
    sub = p.add_subparsers(dest="cmd")
    r = sub.add_parser("record")
    for f in ("board-url", "claim-url", "worker-handle", "work-url", "their-settlement", "now"):
        r.add_argument("--" + f, default=None)
    a = sub.add_parser("address")
    a.add_argument("id")
    for f in ("payout-address", "said-in", "said-at", "now"):
        a.add_argument("--" + f, default=None)
    a.add_argument("--replace", action="store_true")
    z = sub.add_parser("authorise")
    z.add_argument("id")
    for f in ("amount-raw", "by", "now"):
        z.add_argument("--" + f, default=None)
    s = sub.add_parser("settle")
    s.add_argument("id")
    s.add_argument("--block", default=None)
    s.add_argument("--now", default=None)
    f = sub.add_parser("feed")
    f.add_argument("--now", default=None)
    f.add_argument("--out", default=os.path.join("feed", "foreign_claims.json"))
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.self_test:
        return self_test()
    if not args.cmd:
        build_parser().print_usage(sys.stderr)
        return 64
    root = os.path.abspath(args.root)
    try:
        doc = load(root)
        if args.cmd == "record":
            doc, row = record(doc, board_url=args.board_url, claim_url=args.claim_url, worker_handle=args.worker_handle,
                              work_url=args.work_url, their_settlement=args.their_settlement, now=args.now,
                              owners=operator_github_owners(root))
        elif args.cmd == "address":
            doc, row = address(doc, args.id, payout_address=args.payout_address, said_in=args.said_in,
                               said_at=args.said_at, replace=args.replace, now=args.now)
        elif args.cmd == "authorise":
            doc, row = authorise(doc, args.id, amount_raw=args.amount_raw, by=args.by, now=args.now)
        elif args.cmd == "settle":
            with open(os.path.join(root, RECEIPTS_FILE), "r", encoding="utf-8") as fh:
                receipts_doc = json.load(fh)
            doc, receipts_doc, row, _ = settle(doc, receipts_doc, args.id, block=args.block, now=args.now)
            # Both files change or neither: write the receipt first (the append-only one), then the claim row.
            write_atomic(root, RECEIPTS_FILE, (json.dumps(receipts_doc, indent=2) + "\n").encode("utf-8"))
        elif args.cmd == "feed":
            published = feed(doc, now=args.now)
            out = args.out if os.path.isabs(args.out) else os.path.join(root, args.out)
            os.makedirs(os.path.dirname(out), exist_ok=True)
            with open(out, "wb") as fh:
                fh.write(dump(published))
            _out({"v": FEED_V, "wrote": args.out, "foreign_settled_count": published["foreign_settled_count"]})
            return 0
        write_atomic(root, STATE_FILE, dump(doc))
        _out(row)
        return 0
    except Refusal as exc:
        _out({"v": V, "error": exc.code, "detail": exc.detail})
        return 2


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------

def self_test():
    failures = []

    def expect(name, cond):
        if not cond:
            failures.append(name)

    def refuses(code, fn):
        try:
            fn()
        except Refusal as exc:
            return exc.code == code
        return False

    addr = nanoaddr.encode(bytes(range(32)), "nano_")
    now = "2026-10-25T06:00:00Z"
    doc, row = record(empty(), board_url="https://github.com/Scottcjn/rustchain-bounties",
                      claim_url="https://github.com/Scottcjn/rustchain-bounties/issues/41#issuecomment-1",
                      worker_handle="w", work_url="https://github.com/Scottcjn/rustchain-bounties/pull/58",
                      their_settlement="RTC", now=now, owners=["dhyabi2"])
    expect("id", row["id"] == "fc-2026-10-25-001")
    expect("never changes their machine", row["changes_their_state_machine"] is False)
    expect("authorise needs an address", refuses("address_required_before_amount",
                                                 lambda: authorise(doc, row["id"], amount_raw="1", by="o", now=now)))
    expect("amount required", refuses("amount_not_authorised", lambda: authorise(doc, row["id"], amount_raw=None, by="o", now=now)))
    expect("bad checksum", refuses("bad_address_checksum", lambda: address(
        doc, row["id"], payout_address=addr[:-1] + ("1" if addr[-1] != "1" else "3"), said_in="https://x.example/m",
        said_at=now, now=now)))
    expect("words required", refuses("address_not_in_their_words", lambda: address(
        doc, row["id"], payout_address=addr, said_in="", said_at=now, now=now)))
    address(doc, row["id"], payout_address=addr, said_in="https://x.example/m", said_at=now, now=now)
    expect("float refused", refuses("amount_not_integer_string", lambda: authorise(doc, row["id"], amount_raw="0.05", by="o", now=now)))
    authorise(doc, row["id"], amount_raw="50000000000000000000000000000", by="owner", now=now)
    expect("exact xno", money.raw_to_xno(50000000000000000000000000000) == "0.05")
    expect("ours refused", refuses("claim_url_is_ours", lambda: record(
        empty(), board_url="https://github.com/dhyabi2/x", claim_url="https://github.com/dhyabi2/x/issues/1",
        worker_handle="w", work_url="https://github.com/dhyabi2/x/pull/1", their_settlement="x", now=now, owners=["dhyabi2"])))
    expect("duplicate refused", refuses("duplicate_claim_url", lambda: record(
        doc, board_url="https://github.com/Scottcjn/rustchain-bounties",
        claim_url="https://github.com/Scottcjn/rustchain-bounties/issues/41#issuecomment-1", worker_handle="other",
        work_url="https://github.com/Scottcjn/rustchain-bounties/pull/58", their_settlement="RTC", now=now)))
    expect("no clock", refuses("no_clock", lambda: record(empty(), board_url="https://a.example", claim_url="https://a.example/1",
                                                          worker_handle="w", work_url="https://a.example/2", their_settlement="x", now=None)))
    expect("local refused", refuses("claim_url_not_public", lambda: record(
        empty(), board_url="https://a.example", claim_url="http://127.0.0.1/1", worker_handle="w",
        work_url="https://a.example/2", their_settlement="x", now=now)))
    print(json.dumps({"tool": TOOL, "ok": not failures, "failures": failures}, indent=2))
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
