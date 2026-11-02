#!/usr/bin/env python3
"""external_demand/build.py - an index of XNO payments for agent work where the buyer is not us.

    python3 external_demand/build.py build [--candidates external_demand/candidates.json]
                                           [--out feed/external_demand.json] [--now ISO] [--node URL]...
    python3 external_demand/build.py check [--feed feed/external_demand.json]

Admission, all required (EXTERNAL-DEMAND.md): the block resolves on every node read; funding provenance is
`unsubsidised`, `sponsor_funded` or `dispenser_funded` and is printed in the row (`self_funded` and
`unknown` are refused and listed in `excluded`); neither side is us. A row where WE are the payee is not
external demand even when the payer is a stranger: it goes in `our_own_receipts`, counted separately, never
in the headline. Our accounts are the declared `external_demand/operators.json`, never discovered; an empty list
fails the build (`operator_accounts_undeclared`). A partial node read fails the build and writes nothing
(the previous feed is left untouched). Zero admissible rows still publishes a feed that says so.
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "vendor"))
sys.path.insert(0, HERE)

import canonical  # noqa: E402
import provenance as prov  # noqa: E402
from money import raw_to_xno  # noqa: E402

V = "external-demand-v1"
DEFAULT_NODES = ("https://rpc.nano.to", "https://node.somenano.com/proxy")
ADMIT = ("unsubsidised", "sponsor_funded", "dispenser_funded")
THIS_IS_NOT = ("a claim that these buyers will buy from you, or that they found their sellers through us")


class BuildFailed(Exception):
    def __init__(self, code, detail=""):
        super().__init__(f"{code}: {detail}")
        self.code, self.detail = code, detail


def _iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _read_operator_accounts(path):
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        doc = {}
    accounts = doc.get("operator_accounts") if isinstance(doc, dict) else None
    accounts = [a for a in (accounts or []) if isinstance(a, str)]
    if not accounts or any(canonical.account_key(a) is None for a in accounts):
        raise BuildFailed("operator_accounts_undeclared",
                          "operators.json must list every account we control, each a valid address")
    return accounts


def _is_ours(account, ours):
    return any(canonical.same_account(account, o) for o in ours)


def _read_send(fetch, nodes, block):
    """The send block behind `block` as every node read it agrees, else BuildFailed."""
    answers = {}
    for url in nodes:
        try:
            info = fetch(url, {"action": "block_info", "json_block": "true", "hash": block})
            if info.get("subtype") == "receive":
                info = fetch(url, {"action": "block_info", "json_block": "true",
                                   "hash": info["contents"]["link"]})
            answers[url] = info
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
            raise BuildFailed("node_unreachable", f"{url}: {type(e).__name__}: {e}")
    story = set()
    for url, a in answers.items():
        c = a.get("contents") if isinstance(a, dict) else None
        if not isinstance(a, dict) or "error" in a or not isinstance(c, dict) or a.get("subtype") != "send" \
                or a.get("confirmed") != "true":
            raise BuildFailed("block_not_a_confirmed_send", f"{block} on {url}")
        story.add((a["block_account"], c["link_as_account"], a["amount"]))
    if len(story) != 1:
        raise BuildFailed("nodes_disagree", block)
    first = answers[nodes[0]]
    return {"payer": first["block_account"], "payee": first["contents"]["link_as_account"],
            "amount_raw": first["amount"], "paid_at": _iso(int(first["local_timestamp"]))}


def _disclosures(result):
    out = []
    for f in result.get("funders", []):
        if f["classification"] in ("dispenser_funded", "sponsor_funded", "self_funded"):
            out.append("%s funded the payer in the window as %s (received_raw %s, %s ppm of the window's receives)"
                       % (f["funder"], f["classification"], f["received_raw"], f["share_of_window_receives_ppm"]))
    return out


def counts_of(rows):
    return {"rows": len(rows),
            "unsubsidised": sum(r["provenance"] == "unsubsidised" for r in rows),
            "sponsor_funded": sum(r["provenance"] == "sponsor_funded" for r in rows),
            "dispenser_funded": sum(r["provenance"] == "dispenser_funded" for r in rows),
            "distinct_payers_not_us": len({canonical.account_key(r["payer"]) for r in rows}),
            "payer_published": sum(1 for r in rows if r["payer_published"]),
            "xno_total": raw_to_xno(sum(int(r["amount_raw"]) for r in rows))}


def build(candidates, operator_accounts, nodes=DEFAULT_NODES, now=None, fetch=None, citation_ok=None) -> dict:
    """The feed document. Raises BuildFailed (and the caller writes nothing) on any partial read."""
    if not operator_accounts:
        raise BuildFailed("operator_accounts_undeclared", "no accounts declared")
    fetch = fetch or prov.post_json
    nodes = list(nodes)
    rows, ours_rows, excluded = [], [], []
    stamp = now or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    for cand in candidates:
        block = cand["block_hash"].upper()
        facts = _read_send(fetch, nodes, block)
        result = prov.provenance(block, nodes, cand.get("sponsor", []), cand.get("self", []),
                                 cand.get("window_hours", 720), fetch)
        if result["verdict"] not in ADMIT:
            why = result["verdict"] if result["verdict"] != "unknown" else "unknown"
            excluded.append({"block_hash": block, "why": why, "excluded_at": stamp,
                             "detail": result.get("why")})
            continue
        if _is_ours(facts["payer"], operator_accounts):
            excluded.append({"block_hash": block, "why": "payer_is_operator", "excluded_at": stamp})
            continue
        published = cand.get("payer_published")
        row = {"block_hash": block, "paid_at": facts["paid_at"], "payer": facts["payer"], "payee": facts["payee"],
               "amount_raw": facts["amount_raw"], "amount_xno": raw_to_xno(int(facts["amount_raw"])),
               "what": cand.get("what"), "what_source": cand.get("what_source"),
               "provenance": result["verdict"], "provenance_disclosures": _disclosures(result),
               "payer_published": published, "nodes_read": nodes,
               "we_are_a_party": _is_ours(facts["payee"], operator_accounts),
               "check_it_yourself": "curl -s -X POST %s -H 'Content-Type: application/json' -A 'Mozilla/5.0' "
                                    "-d '{\"action\":\"block_info\",\"json_block\":\"true\",\"hash\":\"<block_hash>\"}'  "
                                    "# replace <block_hash> with this row's block_hash" % nodes[0]}
        if published and citation_ok is not None and not citation_ok(published):
            row["payer_published"] = None
            row["citation_unreachable_at"] = stamp
        (ours_rows if row["we_are_a_party"] else rows).append(row)
    return {"v": V, "generated_at": stamp, "built_from": nodes, "counts": counts_of(rows), "rows": rows,
            "our_own_receipts": ours_rows, "excluded": excluded, "this_is_not": THIS_IS_NOT}


def check(feed) -> list:
    """Problems with a feed document; [] when it is internally consistent."""
    errors = []
    if not isinstance(feed, dict) or feed.get("v") != V:
        return ["not an external-demand-v1 document"]
    for key in ("rows", "our_own_receipts", "excluded", "counts", "this_is_not"):
        if key not in feed:
            errors.append("missing key: " + key)
    if errors:
        return errors
    if feed["this_is_not"] != THIS_IS_NOT:
        errors.append("this_is_not was edited")
    if feed["counts"] != counts_of(feed["rows"]):
        errors.append("counts do not recompute from rows")
    for r in feed["rows"]:
        if r.get("we_are_a_party"):
            errors.append("%s: a row where we are a party is in the headline rows" % r.get("block_hash"))
        if r.get("provenance") not in ADMIT:
            errors.append("%s: provenance %r is not admissible" % (r.get("block_hash"), r.get("provenance")))
    return errors


def _citation_reachable(url):
    try:
        req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": prov.USER_AGENT})
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status < 400
    except (OSError, ValueError):
        return False


def main(argv=None, fetch=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build")
    b.add_argument("--candidates", default=os.path.join(HERE, "candidates.json"))
    b.add_argument("--operators", default=os.path.join(HERE, "operators.json"))
    b.add_argument("--out", default=os.path.join(ROOT, "feed", "external_demand.json"))
    b.add_argument("--now")
    b.add_argument("--node", action="append")
    b.add_argument("--no-citation-check", action="store_true")
    c = sub.add_parser("check")
    c.add_argument("--feed", default=os.path.join(ROOT, "feed", "external_demand.json"))
    a = p.parse_args(argv)
    if a.cmd == "check":
        errs = check(json.load(open(a.feed, encoding="utf-8")))
        print(json.dumps({"ok": not errs, "errors": errs}))
        return 0 if not errs else 1
    try:
        cands = json.load(open(a.candidates, encoding="utf-8"))["candidates"]
        feed = build(cands, _read_operator_accounts(a.operators), a.node or DEFAULT_NODES, a.now, fetch,
                     None if a.no_citation_check else _citation_reachable)
    except BuildFailed as e:
        print(json.dumps({"failed": e.code, "detail": e.detail}))
        return 3
    tmp = a.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(feed, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, a.out)
    print(json.dumps({"wrote": a.out, "counts": feed["counts"], "our_own_receipts": len(feed["our_own_receipts"]),
                      "excluded": len(feed["excluded"])}))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
