"""external_demand: a feed that cannot count our own receipts. Fake ledger, no network."""
import json
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "vendor"))
sys.path.insert(0, os.path.join(ROOT, "external_demand"))

import nanoaddr  # noqa: E402
import build as ed  # noqa: E402
import provenance as prov  # noqa: E402


def acct(n):
    return nanoaddr.encode(bytes([n]) * 32)


OURS, PAYEE_OTHER, STRANGER, STRANGER2, FUNDER, DISP, SELF = (acct(i) for i in (1, 2, 3, 4, 5, 6, 7))
T = 1_790_000_000
N1, N2 = "https://n1.example", "https://n2.example"
H1, H2, H3, H4 = ("%064X" % i for i in (11, 12, 13, 14))


class Ledger:
    """sends: {hash: (payer, payee, amount, ts)}; funding: {payer: [(funder, amount, ts)]}"""

    def __init__(self, sends, funding, dispensers=(), down=()):
        self.sends, self.funding, self.dispensers, self.down = sends, funding, set(dispensers), set(down)

    def __call__(self, url, p):
        if url in self.down:
            raise OSError("down")
        if p["action"] == "block_info":
            h = p["hash"]
            if h not in self.sends:
                return {"error": "Block not found"}
            payer, payee, amount, ts = self.sends[h]
            return {"block_account": payer, "amount": str(amount), "local_timestamp": str(ts),
                    "confirmed": "true", "subtype": "send",
                    "contents": {"previous": "A" * 64, "link_as_account": payee, "link": "0" * 64}}
        acc = p["account"]
        if acc in self.funding:
            return {"history": [{"type": "receive", "account": f, "amount": str(a), "local_timestamp": str(t),
                                 "hash": "%064X" % (100 + i), "confirmed": "true"}
                                for i, (f, a, t) in enumerate(self.funding[acc])]}
        if acc in self.dispensers:
            return {"history": [{"type": "send", "account": acct(100 + i), "amount": "1000",
                                 "local_timestamp": str(T), "hash": "%064X" % (900 + i)} for i in range(12)]}
        return {"history": []}


def cand(block, **kw):
    return dict({"block_hash": block, "what": "x", "what_source": None, "payer_published": None}, **kw)


def sends():
    return {H1: (STRANGER, PAYEE_OTHER, 10 ** 27, T), H2: (STRANGER2, OURS, 5 * 10 ** 26, T),
            H3: (STRANGER, PAYEE_OTHER, 10 ** 26, T), H4: (OURS, PAYEE_OTHER, 10 ** 26, T)}


def funding():
    return {STRANGER: [(FUNDER, 100, T - 50)], STRANGER2: [(FUNDER, 100, T - 50)]}


def run(cands, ledger=None, ops=(OURS,), **kw):
    return ed.build(cands, list(ops), nodes=[N1, N2], now="2026-11-02T00:00:00Z",
                    fetch=ledger or Ledger(sends(), funding()), **kw)


class Admission(unittest.TestCase):

    def test_our_own_payee_rows_are_not_headline_demand(self):
        feed = run([cand(H1), cand(H2)])
        self.assertEqual([r["block_hash"] for r in feed["rows"]], [H1])
        self.assertEqual([r["block_hash"] for r in feed["our_own_receipts"]], [H2])
        self.assertEqual(feed["counts"]["rows"], 1)
        self.assertTrue(feed["our_own_receipts"][0]["we_are_a_party"])

    def test_self_funded_row_is_excluded_and_listed(self):
        led = Ledger(sends(), {STRANGER: [(SELF, 100, T - 50)]})
        feed = run([cand(H1, self=[SELF])], led)
        self.assertEqual(feed["rows"], [])
        self.assertEqual([(e["block_hash"], e["why"]) for e in feed["excluded"]], [(H1, "self_funded")])

    def test_unknown_provenance_is_excluded_never_pending(self):
        led = Ledger(sends(), {})              # no receive in the window: unknown
        feed = run([cand(H1)], led)
        self.assertEqual(feed["rows"], [])
        self.assertEqual(feed["excluded"][0]["why"], "unknown")

    def test_payer_that_is_us_is_excluded(self):
        led = Ledger(sends(), {OURS: [(FUNDER, 1, T - 5)]})
        feed = run([cand(H4)], led)
        self.assertEqual(feed["rows"], [])
        self.assertEqual(feed["excluded"][0]["why"], "payer_is_operator")

    def test_dispenser_funded_row_is_admitted_with_its_disclosure(self):
        led = Ledger(sends(), {STRANGER: [(DISP, 10, T - 50), (FUNDER, 990, T - 40)]}, dispensers=[DISP])
        feed = run([cand(H1)], led)
        row = feed["rows"][0]
        self.assertEqual(row["provenance"], "dispenser_funded")
        self.assertTrue(any(DISP in d and "10000 ppm" in d for d in row["provenance_disclosures"]))

    def test_receive_block_resolves_to_the_send(self):
        recv = "%064X" % 77

        class L(Ledger):
            def __call__(self, url, p):
                if p["action"] == "block_info" and p["hash"] == recv:
                    return {"subtype": "receive", "confirmed": "true", "local_timestamp": str(T + 9),
                            "contents": {"link": H1}}
                return super().__call__(url, p)
        feed = run([cand(recv)], L(sends(), funding()))
        self.assertEqual(feed["rows"][0]["payer"], STRANGER)


class Failures(unittest.TestCase):

    def test_operator_accounts_unset_fails_build(self):
        with self.assertRaises(ed.BuildFailed) as e:
            ed.build([cand(H1)], [], nodes=[N1], fetch=Ledger(sends(), funding()))
        self.assertEqual(e.exception.code, "operator_accounts_undeclared")

    def test_operator_file_empty_or_missing_fails(self):
        for path in ("/nonexistent/x.json",):
            with self.assertRaises(ed.BuildFailed):
                ed._read_operator_accounts(path)

    def test_partial_node_read_fails_build_and_writes_nothing(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "ed.json")
            open(out, "w").write("PREVIOUS")
            cpath = os.path.join(tmp, "c.json")
            json.dump({"candidates": [cand(H1)]}, open(cpath, "w"))
            opath = os.path.join(tmp, "o.json")
            json.dump({"operator_accounts": [OURS]}, open(opath, "w"))
            code = ed.main(["build", "--candidates", cpath, "--operators", opath, "--out", out,
                            "--node", N1, "--node", N2, "--no-citation-check"],
                           fetch=Ledger(sends(), funding(), down=[N2]))
            self.assertEqual(code, 3)
            self.assertEqual(open(out).read(), "PREVIOUS")

    def test_nodes_that_disagree_fail_build(self):
        led = Ledger(sends(), funding())

        def f(url, p):
            r = led(url, p)
            if url == N2 and p["action"] == "block_info":
                r = dict(r, amount="1")
            return r
        with self.assertRaises(ed.BuildFailed):
            run([cand(H1)], f)


class Shape(unittest.TestCase):

    def test_empty_index_still_publishes(self):
        feed = run([])
        self.assertEqual(feed["rows"], [])
        self.assertEqual(feed["counts"]["rows"], 0)
        self.assertEqual(ed.check(feed), [])

    def test_counts_match_rows_and_a_hand_edit_fails(self):
        feed = run([cand(H1)])
        self.assertEqual(ed.check(feed), [])
        feed["counts"]["rows"] = 9
        self.assertIn("counts do not recompute from rows", ed.check(feed))

    def test_excluded_key_is_present_even_when_empty(self):
        feed = run([cand(H1)])
        self.assertEqual(feed["excluded"], [])
        self.assertIn("excluded", feed)

    def test_this_is_not_is_verbatim_and_edit_is_caught(self):
        feed = run([cand(H1)])
        self.assertEqual(feed["this_is_not"], ed.THIS_IS_NOT)
        feed["this_is_not"] = "a market"
        self.assertIn("this_is_not was edited", ed.check(feed))

    def test_an_own_receipt_hand_moved_into_rows_is_caught(self):
        feed = run([cand(H2)])
        feed["rows"] = feed["our_own_receipts"]
        feed["counts"] = ed.counts_of(feed["rows"])
        self.assertTrue(any("we are a party" in e for e in ed.check(feed)))

    def test_citation_that_404s_becomes_null_and_is_stamped(self):
        feed = run([cand(H1, payer_published="https://example.invalid/x")], citation_ok=lambda u: False)
        row = feed["rows"][0]
        self.assertIsNone(row["payer_published"])
        self.assertEqual(row["citation_unreachable_at"], "2026-11-02T00:00:00Z")
        self.assertEqual(feed["counts"]["payer_published"], 0)

    def test_amounts_are_exact(self):
        feed = run([cand(H1)])
        self.assertEqual(feed["rows"][0]["amount_xno"], "0.001")
        self.assertEqual(feed["counts"]["xno_total"], "0.001")

    def test_headline_never_includes_our_receipts_in_xno_total(self):
        feed = run([cand(H1), cand(H2)])
        self.assertEqual(feed["counts"]["xno_total"], "0.001")


class Committed(unittest.TestCase):

    def test_the_committed_feed_is_internally_consistent_and_counts_us_separately(self):
        with open(os.path.join(ROOT, "feed", "external_demand.json"), encoding="utf-8") as fh:
            feed = json.load(fh)
        self.assertEqual(ed.check(feed), [])
        ours = [json.load(open(os.path.join(ROOT, "external_demand", "operators.json")))["operator_accounts"]][0]
        import canonical
        for r in feed["rows"]:
            self.assertFalse(any(canonical.same_account(r["payee"], o) or canonical.same_account(r["payer"], o)
                                 for o in ours), r["block_hash"])

    def test_no_socket_is_opened_by_the_pure_functions(self):
        import socket
        real = socket.socket
        socket.socket = lambda *a, **k: (_ for _ in ()).throw(AssertionError("socket"))
        try:
            run([cand(H1)])
        finally:
            socket.socket = real


if __name__ == "__main__":
    unittest.main()
