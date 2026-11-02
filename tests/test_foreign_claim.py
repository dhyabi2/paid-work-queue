"""Settling an XNO leg against a claim on someone else's board. The 13 laws of
specs/unstuck/agent-tool-foreign-claim-settlement.md, fixtures built here (not taken from the module's --self-test).

No network in any path: test 12 walks the import graph. No 64-hex run stands as a single literal.
"""
import ast
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "vendor"))

import foreign_claim as fc  # noqa: E402
import nanoaddr  # noqa: E402
import validate  # noqa: E402
from custody_probe import NETWORK_MODULES  # noqa: E402

NOW = "2026-10-25T06:00:00Z"
BOARD = "https://github.com/Scottcjn/rustchain-bounties"
CLAIM = BOARD + "/issues/41#issuecomment-123456789"
WORK = BOARD + "/pull/58"
PAYEE = nanoaddr.encode(bytes(range(32)), "nano_")
SAID = "https://github.com/Scottcjn/rustchain-bounties/issues/41#issuecomment-123456999"
# eddie_researcher's real near miss (The Colony, 2026-10-xx): the key was right, the checksum characters were not.
EDDIE_BAD = "nano_3qucf316qrxtq684zpsqm58993imii7dh976gghp37j8rcuq9aafm94b37z3"
BLOCK = ("AB" * 32)


def root_with(receipts=None, owners=("dhyabi2",)):
    d = tempfile.mkdtemp()
    with open(os.path.join(d, "receipts.json"), "w") as fh:
        json.dump({"receipts": receipts or []}, fh)
    with open(os.path.join(d, "operator_accounts.json"), "w") as fh:
        json.dump({"operator_accounts": [], "operator_github_owners": list(owners)}, fh)
    return d


def run(root, *argv):
    r = subprocess.run([sys.executable, os.path.join(ROOT, "foreign_claim.py"), "--root", root] + list(argv),
                       capture_output=True, text=True)
    return r.returncode, json.loads(r.stdout) if r.stdout.strip() else None


def record(root, claim=CLAIM, worker="AutomatedJanitor2015", settlement="RTC"):
    return run(root, "record", "--board-url", BOARD, "--claim-url", claim, "--worker-handle", worker,
               "--work-url", WORK, "--their-settlement", settlement, "--now", NOW)


def bytes_of(root, name="foreign_claims.json"):
    p = os.path.join(root, name)
    with open(p, "rb") as fh:
        return fh.read()


class Laws(unittest.TestCase):
    def test_1_happy_path_end_to_end_with_a_receipt_that_resolves(self):
        d = root_with()
        self.assertEqual(record(d)[1]["id"], "fc-2026-10-25-001")
        self.assertEqual(run(d, "address", "fc-2026-10-25-001", "--payout-address", PAYEE, "--said-in", SAID,
                             "--said-at", "2026-10-26T09:14:00Z", "--now", NOW)[1]["state"], "addressed")
        self.assertEqual(run(d, "authorise", "fc-2026-10-25-001", "--amount-raw", "50000000000000000000000000000",
                             "--by", "owner", "--now", NOW)[1]["state"], "authorised")
        code, row = run(d, "settle", "fc-2026-10-25-001", "--block", BLOCK, "--now", NOW)
        self.assertEqual((code, row["state"]), (0, "settled"))
        receipts = json.loads(bytes_of(d, "receipts.json"))["receipts"]
        r = [x for x in receipts if x["id"] == row["receipt_id"]][0]
        self.assertEqual((r["claim_url"], r["work_url"], r["foreign_claim_id"]), (CLAIM, WORK, "fc-2026-10-25-001"))
        self.assertEqual(r["amount_xno"], "0.05")
        self.assertEqual(validate.check_receipts({"receipts": receipts}), [])
        self.assertEqual(validate.cross_check({"jobs": []}, {"receipts": receipts}), [])   # not a parallel ledger, and valid

    def test_2_their_state_machine_is_never_changed(self):
        d = root_with()
        row = record(d)[1]
        self.assertIs(row["changes_their_state_machine"], False)
        run(d, "feed", "--now", NOW)
        feed = json.loads(bytes_of(d, os.path.join("feed", "foreign_claims.json")))
        self.assertEqual(feed["state_machines_we_asked_to_change"], 0)
        self.assertTrue(all(c["changes_their_state_machine"] is False for c in feed["foreign_claims"]))

    def test_3_authorise_without_an_amount_refuses_and_leaves_the_bytes(self):
        d = root_with()
        record(d)
        run(d, "address", "fc-2026-10-25-001", "--payout-address", PAYEE, "--said-in", SAID,
            "--said-at", NOW, "--now", NOW)
        before = bytes_of(d)
        code, out = run(d, "authorise", "fc-2026-10-25-001", "--by", "owner", "--now", NOW)
        self.assertEqual((code, out["error"]), (2, "amount_not_authorised"))
        self.assertEqual(bytes_of(d), before)

    def test_4_authorise_before_address_refuses(self):
        d = root_with()
        record(d)
        code, out = run(d, "authorise", "fc-2026-10-25-001", "--amount-raw", "1", "--by", "o", "--now", NOW)
        self.assertEqual(out["error"], "address_required_before_amount")

    def test_5_eddies_bad_checksum_refuses(self):
        d = root_with()
        record(d)
        before = bytes_of(d)
        code, out = run(d, "address", "fc-2026-10-25-001", "--payout-address", EDDIE_BAD, "--said-in", SAID,
                        "--said-at", NOW, "--now", NOW)
        self.assertEqual((code, out["error"]), (2, "bad_address_checksum"))
        self.assertEqual(bytes_of(d), before)

    def test_6_an_address_with_no_said_in_refuses(self):
        d = root_with()
        record(d)
        code, out = run(d, "address", "fc-2026-10-25-001", "--payout-address", PAYEE, "--said-at", NOW, "--now", NOW)
        self.assertEqual(out["error"], "address_not_in_their_words")

    def test_7_a_claim_inside_our_own_account_refuses_using_the_declared_set(self):
        d = root_with(owners=("dhyabi2",))
        code, out = run(d, "record", "--board-url", "https://github.com/dhyabi2/some-repo", "--claim-url",
                        "https://github.com/dhyabi2/some-repo/issues/1", "--worker-handle", "w",
                        "--work-url", "https://github.com/dhyabi2/some-repo/pull/2", "--their-settlement", "x",
                        "--now", NOW)
        self.assertEqual(out["error"], "claim_url_is_ours")
        d2 = root_with(owners=())                                   # with nothing declared the same URL is accepted
        self.assertEqual(run(d2, "record", "--board-url", "https://github.com/dhyabi2/some-repo", "--claim-url",
                             "https://github.com/dhyabi2/some-repo/issues/1", "--worker-handle", "w",
                             "--work-url", "https://github.com/dhyabi2/some-repo/pull/2", "--their-settlement", "x",
                             "--now", NOW)[0], 0)
        self.assertIn("dhyabi2", json.load(open(os.path.join(ROOT, "operator_accounts.json")))["operator_github_owners"])

    def test_8_the_same_claim_url_twice_refuses_even_for_another_worker(self):
        d = root_with()
        record(d)
        code, out = record(d, worker="somebody-else")
        self.assertEqual(out["error"], "duplicate_claim_url")

    def test_9_amount_is_an_integer_string_and_renders_exactly(self):
        d = root_with()
        record(d)
        run(d, "address", "fc-2026-10-25-001", "--payout-address", PAYEE, "--said-in", SAID, "--said-at", NOW, "--now", NOW)
        self.assertEqual(run(d, "authorise", "fc-2026-10-25-001", "--amount-raw", "0.05", "--by", "o", "--now", NOW)[1]["error"],
                         "amount_not_integer_string")
        self.assertEqual(run(d, "authorise", "fc-2026-10-25-001", "--amount-raw", "50000000000000000000000000000",
                             "--by", "o", "--now", NOW)[0], 0)
        run(d, "settle", "fc-2026-10-25-001", "--block", BLOCK, "--now", NOW)
        feed_code, _ = run(d, "feed", "--now", NOW)
        feed = json.loads(bytes_of(d, os.path.join("feed", "foreign_claims.json")))
        self.assertEqual(feed["foreign_settled_total_xno"], "0.05")
        self.assertEqual(feed["foreign_settled_total_raw"], "50000000000000000000000000000")

    def test_10_byte_rule_two_feeds_one_now_identical(self):
        d = root_with()
        record(d)
        run(d, "feed", "--now", NOW)
        a = bytes_of(d, os.path.join("feed", "foreign_claims.json"))
        run(d, "feed", "--now", NOW)
        self.assertEqual(a, bytes_of(d, os.path.join("feed", "foreign_claims.json")))
        self.assertEqual(a, (json.dumps(json.loads(a), indent=2, sort_keys=True) + "\n").encode())

    def test_11_empty_is_published_and_zero(self):
        d = root_with()
        run(d, "feed", "--now", NOW)
        feed = json.loads(bytes_of(d, os.path.join("feed", "foreign_claims.json")))
        self.assertEqual((feed["foreign_settled_count"], feed["foreign_settled_total_xno"], feed["foreign_claims"]),
                         (0, "0", []))
        self.assertEqual(feed["state_machines_we_asked_to_change"], 0)

    def test_12_nothing_on_the_import_graph_can_open_a_socket(self):
        seen, todo = set(), ["foreign_claim"]
        while todo:
            name = todo.pop()
            if name in seen:
                continue
            seen.add(name)
            for base in (ROOT, os.path.join(ROOT, "vendor")):
                path = os.path.join(base, name + ".py")
                if os.path.exists(path):
                    for node in ast.walk(ast.parse(open(path).read())):
                        mods = [a.name for a in node.names] if isinstance(node, ast.Import) else \
                            [node.module] if isinstance(node, ast.ImportFrom) and node.module else []
                        for m in mods:
                            top = m.split(".")[0]
                            self.assertNotIn(top, NETWORK_MODULES, "%s imports %s" % (name, top))
                            todo.append(top)

    def test_13_their_settlement_is_recorded_verbatim_and_unclassified(self):
        d = root_with()
        for n, text in enumerate(("RTC", "internal reward pool", "tokens \U0001F680 é"), 1):
            code, row = record(d, claim=CLAIM + str(n), settlement=text)
            self.assertEqual(row["their_settlement"], text)

    def test_14_receipt_helpers_match_settle_py(self):
        import settle
        self.assertEqual(fc.EXPLORER, settle.EXPLORER)
        for rs in ([], [{"id": "receipt-001"}], [{"id": "receipt-002"}], [{"id": "receipt-001"}, {"id": "receipt-003"}]):
            self.assertEqual(fc.next_receipt_id(rs), settle.next_receipt_id(rs))

    def test_15_append_only_covers_foreign_claims(self):
        d = root_with()
        record(d)
        old = json.loads(bytes_of(d))
        edited = json.loads(json.dumps(old))
        edited["foreign_claims"][0]["claim_url"] = "https://example.com/other"
        self.assertTrue(validate.check_foreign_append_only(old, edited))
        self.assertTrue(validate.check_foreign_append_only(old, {"foreign_claims": []}))
        moved = json.loads(json.dumps(old))
        moved["foreign_claims"][0]["state"] = "addressed"
        self.assertEqual(validate.check_foreign_append_only(old, moved), [])
        back = json.loads(json.dumps(moved))
        self.assertTrue(validate.check_foreign_append_only(moved, old))

    def test_16_wrong_state_names_both_states(self):
        d = root_with()
        record(d)
        code, out = run(d, "settle", "fc-2026-10-25-001", "--block", BLOCK, "--now", NOW)
        self.assertEqual(out["error"], "wrong_state")
        self.assertIn("authorised", out["detail"])
        self.assertIn("recorded", out["detail"])

    def test_17_no_clock_refuses(self):
        d = root_with()
        code, out = run(d, "record", "--board-url", BOARD, "--claim-url", CLAIM, "--worker-handle", "w",
                        "--work-url", WORK, "--their-settlement", "x")
        self.assertEqual(out["error"], "no_clock")

    def test_18_self_test(self):
        r = subprocess.run([sys.executable, os.path.join(ROOT, "foreign_claim.py"), "--self-test"], capture_output=True)
        self.assertEqual(r.returncode, 0, r.stdout)


if __name__ == "__main__":
    unittest.main()
