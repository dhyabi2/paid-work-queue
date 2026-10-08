#!/usr/bin/env python3
"""End-to-end acceptance run: the real CLI, real files, real exit codes.

The unit suite calls functions. This calls `python3 validate.py` as a
subprocess against trees on disk, once per numbered acceptance item in the
spec, and checks the exit code and what the seller would actually read.
No network access at any point.

    python3 e2e_check.py        # exit 0 if every check passes
"""

import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
VALIDATE = os.path.join(ROOT, "validate.py")
XNO = 10 ** 30
SELLER = "nano_11131a3ia3a81w61k4id3i8iw5ri46b3871o4rdji8at5eg3t9izij86w3hz"
# A second real address, so the offer path has a buyer that is not the seller:
# `accept` refuses `seller_is_operator` when the two are one account.
BUYER = "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3"
OFFER_NOW = "2026-10-08T03:16:26Z"
RETRY_NOW = "2026-10-08T07:00:00Z"
PRICE_RAW = str(25 * XNO // 100)
CHECKS = []


def block(prefix="9F2C"):
    return (prefix + "0123456789ABCDEF" * 4)[:64]


def job(**over):
    entry = {
        "id": "job-001", "title": "A job",
        "description": "Do the thing and publish it at a public URL.",
        "acceptance": ["the URL returns 200"],
        "price_xno": "0.25", "price_raw": str(25 * XNO // 100),
        "posted": "2026-09-26T06:00:00Z", "expires": "2026-10-03T06:00:00Z",
        "state": "open", "claimed_by": None, "claim_url": None, "receipt_id": None,
    }
    entry.update(over)
    return entry


def receipt(**over):
    entry = {
        "id": "receipt-001", "job_id": "job-002", "paid_to": SELLER,
        "amount_raw": str(25 * XNO // 100), "amount_xno": "0.25",
        "block_hash": block(), "settled_at": "2026-09-26T09:14:02Z",
        "delivery_url": "https://example.invalid/delivery",
        "verify": "https://nanolooker.com/block/see-block_hash",
    }
    entry.update(over)
    return entry


def settled_job(**over):
    base = {"id": "job-002", "state": "settled", "claimed_by": "a-seller",
            "claim_url": "https://example.invalid/pr/1", "receipt_id": "receipt-001"}
    base.update(over)
    return job(**base)


def tree(jobs, receipts, extra=None):
    root = tempfile.mkdtemp()
    # Every top-level module, not just validate.py: the moment validate.py
    # imported a sibling, copying it alone left the subprocess dying on a
    # ModuleNotFoundError, which surfaced here as a missing stats.json.
    for name in sorted(os.listdir(ROOT)):
        if name.endswith(".py"):
            shutil.copy(os.path.join(ROOT, name), os.path.join(root, name))
    shutil.copytree(os.path.join(ROOT, "vendor"), os.path.join(root, "vendor"))
    with open(os.path.join(root, "jobs.json"), "w") as handle:
        json.dump({"updated": "2026-09-26T06:00:00Z", "currency": "XNO", "jobs": jobs},
                  handle, indent=2)
    with open(os.path.join(root, "receipts.json"), "w") as handle:
        json.dump({"receipts": receipts}, handle, indent=2)
    for name, text in (extra or {}).items():
        with open(os.path.join(root, name), "w") as handle:
            handle.write(text)
    return root


def offer_cli(root, *args):
    """`seller_offer.py` as a subprocess, from the copied tree on disk."""
    done = subprocess.run(
        [sys.executable, os.path.join(root, "seller_offer.py")] + list(args),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=root,
    )
    return done.returncode, done.stdout.decode("utf-8")


def cli(root, *args):
    done = subprocess.run(
        [sys.executable, os.path.join(root, "validate.py"), "--root", root] + list(args),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=root,
    )
    return done.returncode, done.stdout.decode("utf-8")


def retry_cli(root, *args):
    """`retry_safety.py` as a subprocess, from the copied tree on disk.

    A separate process per call on purpose: `ockerclaw`'s test is a restart, and
    an in-process check cannot tell a derived key from a remembered one.
    """
    done = subprocess.run(
        [sys.executable, os.path.join(root, "retry_safety.py")] + list(args),
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=root,
    )
    return done.returncode, done.stdout.decode("utf-8")


def check(label, condition, detail=""):
    CHECKS.append((label, bool(condition), detail))
    print("[%s] %s%s" % ("pass" if condition else "FAIL", label,
                         "" if condition else "\n       " + detail.strip()))


def expect_fail(label, jobs, receipts, must_contain, extra=None, args=()):
    root = tree(jobs, receipts, extra)
    code, output = cli(root, *args)
    missing = [needle for needle in must_contain if needle not in output]
    check(label, code == 1 and not missing,
          "exit=%d missing=%r\n%s" % (code, missing, output))


def main():
    print("paid work queue - end-to-end acceptance run\n")

    expect_fail("1  price_xno and price_raw disagreeing by one raw is refused",
                [job(price_raw=str(25 * XNO // 100 + 1))], [],
                ["job-001", "disagree", str(25 * XNO // 100 + 1)])

    expect_fail("2  settled job with receipt_id null is refused",
                [settled_job(receipt_id=None)], [], ["receipt_id", "no receipt, no settled"])

    expect_fail("3  settled job whose receipt has no block hash is refused",
                [job(), settled_job()], [receipt(block_hash=None)],
                ["block_hash", "receipt-001"])

    expect_fail("4  a block hash that is not 64 uppercase hex is refused",
                [job(), settled_job()], [receipt(block_hash=block().lower())],
                ["64 uppercase hex"])

    altered = SELLER[:-1] + ("a" if SELLER[-1] != "a" else "b")
    expect_fail("5  a payout address failing checksum is refused, with the reason code",
                [job(), settled_job()], [receipt(paid_to=altered)],
                ["reason=bad_checksum"])

    expect_fail("6  amount_raw that is not a positive integer string is refused",
                [job(), settled_job()], [receipt(amount_raw="0.25")], ["amount_raw"])

    # 7 - append-only, driven through a real git parent commit
    root = tree([job(), settled_job()], [receipt()])
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
    for command in (["git", "init", "-q", "-b", "main"], ["git", "add", "-A"],
                    ["git", "commit", "-qm", "seed"]):
        subprocess.run(command, cwd=root, check=True, env=env, stdout=subprocess.DEVNULL)
    code, output = cli(root, "--base", "HEAD")
    check("7a unchanged receipts pass the append-only check", code == 0, output)
    with open(os.path.join(root, "receipts.json"), "w") as handle:
        json.dump({"receipts": [receipt(amount_xno="1", amount_raw=str(XNO))]}, handle)
    code, output = cli(root, "--base", "HEAD")
    check("7b editing a receipt already in the parent commit is refused",
          code == 1 and "append-only" in output and "amount_raw" in output, output)

    expect_fail("8  two jobs sharing an id is refused",
                [job(), job()], [], ["duplicate job id"])
    expect_fail("8b two receipts sharing an id is refused",
                [job(), settled_job()], [receipt(), receipt()], ["duplicate receipt id"])

    expect_fail("9  claimed with claimed_by null is refused",
                [job(state="claimed", claimed_by=None, claim_url="u")], [], ["claimed_by"])
    expect_fail("9b open with claimed_by set is refused",
                [job(claimed_by="somebody")], [], ["claimed by nobody"])

    expect_fail("10 a state outside the six is refused, and the six are listed",
                [job(state="in_progress")], [],
                ["open", "claimed", "delivered", "settled", "expired", "cancelled"])

    expect_fail("11 expires before posted is refused",
                [job(expires="2026-09-25T06:00:00Z")], [], ["does not come after"])

    # 12 - the secret gate, and the proof that it runs before everything else
    root = tree([job(price_raw="1")], [],
                {"notes.md": "scratch %s\n" % ("DEADBEEF" * 8)})
    code, output = cli(root)
    check("12 the secret gate refuses 64 standalone hex characters, and runs first",
          code == 1 and "SECRET GATE FAILED" in output and "notes.md" in output
          and "disagree" not in output
          and not os.path.exists(os.path.join(root, "stats.json")), output)

    # 13 - the clean case
    root = tree([job(), settled_job()], [receipt()])
    code, output = cli(root)
    check("13 a clean pair exits 0 and prints the settled count",
          code == 0 and "jobs_settled=1" in output and "jobs_open=1" in output, output)
    with open(os.path.join(root, "stats.json")) as handle:
        stats = json.load(handle)
    check("13b stats.json carries every counter and nothing else",
          sorted(stats) == ["demand_note", "demand_reasons", "demand_signal",
                            "distinct_external_counterparties",
                            "external_edges", "first_settlement", "jobs_open",
                            "jobs_settled", "largest_counterparty_share",
                            "last_settlement", "operator_accounts_declared",
                            "operator_authorable", "paid_xno_total",
                            "sellers_paid", "settlement_count"],
          json.dumps(stats))
    # The demand half of 13b, which is the whole reason those fields exist: a
    # receipt records the payee and not the payer, and no operator set is
    # declared in this fixture, so the countable numbers must publish as null
    # with the reason - never as "one stranger paid us". The settlement count
    # is still published, and so is operator_authorable, which at one row with
    # nothing shown to be external is that one row.
    check("13c a row we cannot classify publishes null and a reason, not demand",
          stats["settlement_count"] == 1
          and stats["distinct_external_counterparties"] is None
          and stats["external_edges"] is None
          and stats["demand_signal"]["value"] is None
          and stats["demand_signal"]["not"] == "settlement_count"
          and stats["demand_reasons"] == ["payer_not_recorded"]
          and stats["operator_authorable"] == 1,
          json.dumps(stats))

    # 14 - money is exact
    first = receipt(amount_raw=str(XNO // 10), amount_xno="0.1")
    second = receipt(id="receipt-002", job_id="job-003", amount_raw=str(2 * XNO // 10),
                     amount_xno="0.2", block_hash=block("1A2B"))
    third = settled_job(id="job-003", receipt_id="receipt-002",
                        price_xno="0.2", price_raw=str(2 * XNO // 10))
    root = tree([job(), settled_job(price_xno="0.1", price_raw=str(XNO // 10)), third],
                [first, second])
    code, output = cli(root)
    with open(os.path.join(root, "stats.json")) as handle:
        stats = json.load(handle)
    check("14 paid_xno_total is the exact integer sum (0.1 + 0.2 == 0.3, not 0.30000000000000004)",
          code == 0 and stats["paid_xno_total"] == "0.3" and "0.3 XNO" in output,
          output + json.dumps(stats))

    # the live repository itself
    code, output = cli(ROOT, "--no-write-stats")
    check("15 the committed jobs.json and receipts.json pass", code == 0, output)
    with open(os.path.join(ROOT, "jobs.json")) as handle:
        live = json.load(handle)["jobs"]
    # Not "exactly three open": claim-by-issue.yml claims a job without a
    # person in the loop, so pinning the open count would make the first real
    # claim red. The board holding its three jobs, with one still claimable, is
    # what this check was always for.
    check("16 the board holds its three jobs, one open, one above 0.1 XNO",
          len(live) == 3
          and sum(1 for j in live if j["state"] == "open") >= 1
          and any(int(j["price_raw"]) > XNO // 10 for j in live),
          json.dumps([(j["id"], j["state"], j["price_xno"]) for j in live]))

    # 17-20 - the seller's own offer, propose -> accept -> amount -> settle,
    # through the real CLI against a tree on disk. This is the path no job on
    # the board can express: the SELLER wrote the scope and the price.
    offer_root = tree([job()], [])
    offers = os.path.join(offer_root, "offers.json")
    payload = os.path.join(offer_root, "offer.json")
    with open(payload, "w") as handle:
        json.dump({
            "agent": "thegreekgodhermes",
            "output": ("markdown summary of the Moltbook /home endpoint "
                       "response, under 1500 chars, covering unread "
                       "notifications and activity_on_your_posts"),
            "input": "GET https://www.moltbook.com/api/v1/home",
            "by": "2026-10-08T03:46:00Z",
            "price_xno": "0.05",
            "payout_address": SELLER,
        }, handle)

    code, output = offer_cli(offer_root, "propose", "--json", payload,
                             "--offers", offers, "--now", OFFER_NOW)
    offer_id = json.loads(output)["id"] if code == 0 else None
    check("17 a seller's OFFER issue becomes a proposed row",
          code == 0 and offer_id == "offer-2026-10-08-001", output)

    code, output = offer_cli(offer_root, "amount", offer_id or "x",
                             "--offers", offers)
    check("18 there is no payable amount before the buyer authors the order",
          code == 2 and "reason=not_accepted" in output, output)

    code, output = offer_cli(offer_root, "accept", offer_id or "x",
                             "--order-key", "order-2026-10-08-e2e1",
                             "--offers", offers, "--now", OFFER_NOW,
                             "--payer", BUYER)
    accepted_ok = code == 0
    code2, amount_output = offer_cli(offer_root, "amount", offer_id or "x",
                                     "--offers", offers)
    derived = json.loads(amount_output) if code2 == 0 else {}
    check("19 accepting binds the order and the amount carries it",
          accepted_ok and code2 == 0
          and int(derived.get("pay_raw", 0)) > int(derived.get("amount_raw", 0)),
          output + amount_output)

    feed_out = os.path.join(offer_root, "feed", "offers.json")
    code, output = offer_cli(offer_root, "feed", "--offers", offers,
                             "--out", feed_out, "--now", OFFER_NOW)
    published = {}
    if os.path.exists(feed_out):
        with open(feed_out) as handle:
            published = json.load(handle)
    validate_code, validate_output = cli(offer_root, "--no-write-stats")
    check("20 the offers feed publishes the row and validate.py stays green",
          code == 0 and published.get("accepted_count") == 1
          and len(published.get("open_offers", [])) == 1
          and validate_code == 0,
          output + validate_output + json.dumps(published)[:400])

    # ------------------------------------------------------------------
    # 21-25: the retry-safety binding, driven as separate processes.
    retry_root = tree([job()], [])
    journal = os.path.join(retry_root, "attempts.json")
    order_digest = hashlib.blake2b(b"e2e-order", digest_size=32).hexdigest()
    block_path = os.path.join(retry_root, "block.json")
    with open(block_path, "w") as handle:
        json.dump({"type": "state", "account": SELLER, "previous": "b" * 64,
                   "representative": SELLER, "balance": "0", "link": "c" * 64,
                   "link_as_account": SELLER, "signature": "d" * 128,
                   "work": "0" * 16, "subtype": "send"}, handle)
    code, output = retry_cli(retry_root, "open", "--order-digest", order_digest,
                             "--amount-raw", PRICE_RAW, "--payee", SELLER,
                             "--journal", journal, "--now", RETRY_NOW)
    key = json.loads(output)["idempotency_key"] if code == 0 else "ik-" + "0" * 32
    check("21 a payment request opens with a key derived from the request",
          code == 0 and key == "ik-" + hashlib.blake2b(
              bytes.fromhex(order_digest) + PRICE_RAW.encode("ascii")
              + SELLER.encode("ascii"), digest_size=16).hexdigest(), output)

    for args in (("signed", key, "--block", block_path, "--block-hash",
                  block("AB")),
                 ("broadcast", key),
                 ("observe", key, "--kind", "confirmed", "--node",
                  "https://node.invalid")):
        code, output = retry_cli(retry_root, *args, "--journal", journal,
                                 "--now", RETRY_NOW)
        if code != 0:
            break
    sent_ok = code == 0

    # The crash: a brand-new process asks for the identical payment again.
    code, output = retry_cli(retry_root, "open", "--order-digest", order_digest,
                             "--amount-raw", PRICE_RAW, "--payee", SELLER,
                             "--journal", journal, "--now", RETRY_NOW)
    check("22 a restart with the same request is refused, not duplicated",
          sent_ok and code == 2 and "reason=duplicate_open" in output, output)

    code, output = retry_cli(retry_root, "action", key, "--journal", journal,
                             "--now", RETRY_NOW)
    verdict = json.loads(output) if code == 0 else {}
    check("23 the safe action rebroadcasts the stored block and blocks a new send",
          code == 0 and verdict.get("blocks_new_send") is True
          and "REBROADCAST_SAME_BLOCK" in (verdict.get("action") or "")
          and (verdict.get("rebroadcast_block") or {}).get("signature")
          == "d" * 128, output)

    for _ in range(12):
        code, output = retry_cli(retry_root, "observe", key, "--kind",
                                 "not_found", "--node", "https://node.invalid",
                                 "--journal", journal, "--now", RETRY_NOW)
    code, output = retry_cli(retry_root, "report", "--journal", journal,
                             "--now", RETRY_NOW)
    report = json.loads(output) if code == 0 else {}
    check("24 a spent budget holds for the operator and never concludes",
          code == 0 and report.get("needs_operator") == [key]
          and report.get("in_flight") == 1, output)

    # The block the operator handed in is a VERBATIM block, and the secret
    # gate refuses one - which is the whole reason the journal stores long hex
    # in parts. So the input is removed, as an operator would, and the journal
    # is left where validate.py walks: the gate must be clean over the file
    # this module wrote.
    gate_before = cli(retry_root, "--no-write-stats")[1]
    os.remove(block_path)
    validate_code, validate_output = cli(retry_root, "--no-write-stats")
    check("25 the journal passes the secret gate that refuses a verbatim block",
          "block.json" in gate_before and validate_code == 0
          and "attempts.json" not in validate_output
          and os.path.exists(journal),
          gate_before + validate_output)

    passed = sum(1 for _, ok, _ in CHECKS if ok)
    print("\n%d/%d checks pass" % (passed, len(CHECKS)))
    return 0 if passed == len(CHECKS) else 1


if __name__ == "__main__":
    sys.exit(main())
