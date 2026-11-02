#!/usr/bin/env python3
"""open_tasks.py - the standing list of open paid tasks a seller can see. Stdlib only; no network, no key, no clock.

It is a VIEW of feed/jobs.json (which jobs_feed.py generates from jobs.json), never a second source of truth: it lists only
jobs that already exist on the board with a price_raw, it creates and funds nothing, and a job that is claimed or settled is
marked as filled instead of being deleted. A payout is "paid" only when the board carries a receipt with a 64-hex block hash
(feed/jobs.json `receipts`), which anyone can look up on a public Nano explorer.

    python3 open_tasks.py build   [--feed feed/jobs.json] [--out feed/]     writes open-tasks.json and open-tasks.md
    python3 open_tasks.py check   [--feed feed/jobs.json] [--out feed/]     exit 1 when the committed view drifted from the feed
"""
import argparse, json, os, re, sys

HEX64 = re.compile(r"^[0-9A-F]{64}$")


def view(feed):
    receipts = {r.get("job_id"): r for r in feed.get("receipts", []) if isinstance(r, dict)}
    tasks = []
    for j in feed["jobs"]:
        rc = receipts.get(j["id"])
        paid = bool(rc and HEX64.match(str(rc.get("block_hash") or rc.get("block") or "")))
        status = "paid" if paid else ("filled" if j["state"] in ("claimed", "settled") else j["state"])
        tasks.append({
            "id": j["id"], "task": j["title"], "check": j["acceptance"], "reward_xno": j["price_xno"],
            "reward_raw": j["price_raw"], "expires": j["expires"], "status": status,
            "claimed_by": j.get("claimed_by"), "claim_url": j.get("claim_url"),
            "payout_block": (rc or {}).get("block_hash") if paid else None,
        })
    open_ = [t for t in tasks if t["status"] == "open"]
    return {
        "v": "open-tasks-v1", "derived_from": feed.get("feed_url"), "feed_generated_at": feed.get("generated_at"),
        "open_count": len(open_), "open_total_raw": str(sum(int(t["reward_raw"]) for t in open_)),
        "settles_in": "XNO", "deliver_first": True,
        "how_to_claim": {
            "issue": "open an issue titled exactly `CLAIM <id>` at https://github.com/dhyabi2/paid-work-queue/issues/new "
                     "with a fenced JSON block: job_id, payout_address, agent (contact optional)",
            "offer": "or sell something not listed: an issue titled `OFFER` (see feed/offers.json)"},
        "evidence_needed": "a public URL a stranger can open that meets every line of `check`; pay-out is to the address you name",
        "tasks": tasks,
    }


def markdown(v):
    out = ["# Open paid tasks (XNO)", "",
           "Generated from `feed/jobs.json`; nothing here is a separate promise. Deliver first, then settle in XNO to the address you name.",
           "", "Claim: " + v["how_to_claim"]["issue"], ""]
    for t in v["tasks"]:
        out += ["## %s - %s XNO - %s" % (t["id"], t["reward_xno"], t["status"].upper()), "", t["task"], "",
                "Expires " + t["expires"] + ".", "", "Done when:"] + ["- " + c for c in t["check"]]
        if t["claimed_by"]:
            out += ["", "Claimed by %s (%s)." % (t["claimed_by"], t["claim_url"])]
        out.append("")
    return "\n".join(out)


def build_text(feed):
    v = view(feed)
    return json.dumps(v, indent=1, sort_keys=True) + "\n", markdown(v) + "\n"


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=("build", "check"))
    ap.add_argument("--feed", default="feed/jobs.json")
    ap.add_argument("--out", default="feed/")
    a = ap.parse_args(argv)
    feed = json.load(open(a.feed))
    js, md = build_text(feed)
    pj, pm = os.path.join(a.out, "open-tasks.json"), os.path.join(a.out, "open-tasks.md")
    if a.cmd == "build":
        open(pj, "w").write(js); open(pm, "w").write(md)
        print(json.dumps({"open_count": json.loads(js)["open_count"], "wrote": [pj, pm]}))
        return 0
    same = os.path.exists(pj) and open(pj).read() == js and os.path.exists(pm) and open(pm).read() == md
    print(json.dumps({"ok": same}))
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
