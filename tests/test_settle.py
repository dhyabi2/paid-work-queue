"""The suite for settle.py. Numbered after the spec lines it pins.

Every test drives nanonode.FakeNode; none opens an outbound socket, and test 11
fails the build if any module reachable from settle.py other than nanonode.py
can. Test 12 is the custody claim as a build step rather than a sentence: if a
signing or sending primitive ever becomes reachable from settle.py, this suite
goes red.

No 64-character hex literal is committed anywhere in here - validate.py's secret
gate refuses one tree-wide, and it is right to - so every block hash is built at
runtime from a short seed string.
"""

import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "vendor"))

import nanonode  # noqa: E402
import settle  # noqa: E402

# Two real, checksum-valid addresses: the Nano genesis account and the burn
# address. A wrong-payee test needs a second address that is itself valid, so
# that a wrong payee cannot be mistaken for a bad address.
SELLER = "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3"
STRANGER = "nano_1111111111111111111111111111111111111111111111111111hifc8npp"

# The same account as SELLER in the spelling that predates the 2018 rename: the
# 60 characters after the prefix are identical, so this is not a second account.
SELLER_XRB = "xrb_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3"

PRICE_RAW = "250000000000000000000000000000"      # 0.25 XNO
PADDED_PRICE_RAW = "0250000000000000000000000000000"   # the same 0.25 XNO, padded
PRICE_XNO = "0.25"
FUTURE = "2099-10-03T07:00:00Z"
FROZEN = "2026-09-27T06:20:00Z"


def block_hash(seed="A1B2"):
    """A 64-uppercase-hex hash built here, never committed as a literal."""
    return (seed * 32)[:64].upper()


def job(job_id="job-1", state="claimed", price_raw=PRICE_RAW, price_xno=PRICE_XNO,
        payout_address=SELLER, claimed_by="a-seller",
        claim_url="https://example.invalid/pr/7", **over):
    body = {
        "id": job_id,
        "title": "title for %s" % job_id,
        "description": "description for %s" % job_id,
        "acceptance": ["one line"],
        "price_xno": price_xno,
        "price_raw": price_raw,
        "posted": "2026-09-26T07:00:00Z",
        "expires": FUTURE,
        "state": state,
        "claimed_by": claimed_by,
        "claim_url": claim_url,
        "receipt_id": None,
    }
    if payout_address is not None:
        body["payout_address"] = payout_address
    if state == "open":
        body["claimed_by"] = None
        body["claim_url"] = None
    body.update(over)
    return body


def send_block(destination=SELLER, amount=PRICE_RAW, confirmed="true", subtype="send"):
    return {
        "block_account": STRANGER,
        "amount": amount,
        "balance": "0",
        "confirmed": confirmed,
        "subtype": subtype,
        "contents": {
            "type": "state",
            "account": STRANGER,
            "link_as_account": destination,
        },
    }


class SettleFixture(unittest.TestCase):
    def setUp(self):
        self.fresh_dir()
        self._real_now = settle.now_utc
        settle.now_utc = lambda: __import__("datetime").datetime(
            2026, 9, 27, 6, 20, 0, tzinfo=__import__("datetime").timezone.utc)
        self.addCleanup(lambda: setattr(settle, "now_utc", self._real_now))

    def fresh_dir(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = self._tmp.name
        self.addCleanup(self._tmp.cleanup)

    # -- fixture plumbing ---------------------------------------------------
    def tree(self, jobs, receipts=(), commit=True, valid=True):
        """Write jobs/receipts/stats and make the directory a real clone.

        settle.py's append-only check reads receipts.json at origin/main, and
        refuses when it cannot - so the fixture has to look like the thing a
        seller actually has, which is a clone with that ref.
        """
        # Every top-level module, not a hand-kept list of five: the list went
        # stale the first time a module was added, and the failure it produced
        # was a ModuleNotFoundError inside a subprocess, which reads as a broken
        # fixture rather than as the missing file it is.
        for name in sorted(os.listdir(ROOT)):
            if name.endswith(".py"):
                shutil.copy(os.path.join(ROOT, name), os.path.join(self.dir, name))
        shutil.copytree(os.path.join(ROOT, "vendor"), os.path.join(self.dir, "vendor"))
        self.write_json("jobs.json", {"updated": "2026-09-26T07:00:00Z",
                                      "currency": "XNO", "jobs": list(jobs)})
        self.write_json("receipts.json", {"receipts": list(receipts)})
        self.regenerate_stats(valid)
        if commit:
            env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
                       GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
            for argv in (["init", "-q"], ["add", "-A"], ["commit", "-qm", "fixture"]):
                subprocess.run(["git"] + argv, cwd=self.dir, check=True, env=env,
                               stdout=subprocess.DEVNULL)
            head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.dir,
                                  check=True, stdout=subprocess.PIPE).stdout.decode().strip()
            subprocess.run(["git", "update-ref", "refs/remotes/origin/main", head],
                           cwd=self.dir, check=True)

    def write_json(self, name, document, sort_keys=False):
        payload = json.dumps(document, indent=2, sort_keys=sort_keys) + "\n"
        with open(os.path.join(self.dir, name), "w", encoding="utf-8") as handle:
            handle.write(payload)

    def regenerate_stats(self, valid=True):
        sys.path.insert(0, self.dir)
        import validate as live
        with open(os.devnull, "w", encoding="utf-8") as quiet:
            code = live.run(self.dir, write_stats=True, out=quiet)
        if valid:
            self.assertEqual(code, 0, "the fixture itself must pass validate.py")
        elif code != 0:
            # A fixture that validate.py refuses on purpose still needs a
            # stats.json, so that "nothing was written" can be compared.
            with open(os.path.join(self.dir, "jobs.json")) as handle:
                jobs = json.load(handle)
            with open(os.path.join(self.dir, "receipts.json")) as handle:
                receipts = json.load(handle)
            self.write_json("stats.json", live.compute_stats(jobs, receipts),
                            sort_keys=True)

    def run_settle(self, *argv, node=None):
        out, err = io.StringIO(), io.StringIO()
        code = settle.main(list(argv), out=out, err=err, root=self.dir, node=node)
        return code, out.getvalue(), err.getvalue()

    def bytes_of(self, name):
        with open(os.path.join(self.dir, name), "rb") as handle:
            return handle.read()

    def all_bytes(self):
        return {name: self.bytes_of(name)
                for name in ("jobs.json", "receipts.json", "stats.json")}

    def good_node(self, **over):
        return nanonode.FakeNode({block_hash(): send_block(**over)})

    def settle_ok(self, job_id="job-1", hash_seed="A1B2", node=None, extra=(),
                  amount=None):
        node = node or nanonode.FakeNode(
            {block_hash(hash_seed): send_block(amount=amount or PRICE_RAW)})
        return self.run_settle(job_id, "--block-hash", block_hash(hash_seed),
                               "--delivery-url", "https://example.invalid/work",
                               "--node", "https://node.invalid/proxy", *extra, node=node)


class SettleTests(SettleFixture):
    """The thirteen numbered tests the spec names, plus the checks around them."""

    # -- 1 ------------------------------------------------------------------
    def test_01_happy_path_appends_one_receipt_and_moves_every_counter(self):
        self.tree([job()])
        code, out, err = self.settle_ok()
        self.assertEqual(code, 0, err)
        receipts = json.loads(self.bytes_of("receipts.json"))["receipts"]
        self.assertEqual(len(receipts), 1)
        receipt = receipts[0]
        self.assertEqual(receipt["job_id"], "job-1")
        self.assertEqual(receipt["seller"], "a-seller")
        self.assertEqual(receipt["paid_to"], SELLER)
        self.assertEqual(receipt["amount_raw"], PRICE_RAW)
        self.assertEqual(receipt["amount_xno"], "0.250000")
        self.assertEqual(receipt["block_hash"], block_hash())
        self.assertIs(receipt["confirmed"], True)
        self.assertEqual(receipt["node_queried"], "https://node.invalid/proxy")
        self.assertEqual(receipt["delivery_url"], "https://example.invalid/work")
        self.assertEqual(receipt["claim_url"], "https://example.invalid/pr/7")
        self.assertEqual(receipt["settled_at"], FROZEN)

        jobs = json.loads(self.bytes_of("jobs.json"))["jobs"]
        self.assertEqual(jobs[0]["state"], "settled")
        stats = json.loads(self.bytes_of("stats.json"))
        self.assertEqual(stats["jobs_settled"], 1)
        self.assertEqual(stats["sellers_paid"], 1)
        self.assertEqual(stats["paid_xno_total"], "0.25")
        self.assertEqual(stats["first_settlement"], FROZEN)
        self.assertEqual(stats["last_settlement"], FROZEN)

    def test_01b_a_claimed_job_with_no_claim_url_is_refused_before_the_node_is_asked(self):
        # The spec says the receipt omits claim_url when the job carries none.
        # validate.py refuses such a job outright, so that tree could never be
        # merged; settle.py says so instead of writing it. The omission branch
        # stays in build_receipt for the day that rule loosens.
        self.tree([job(claim_url=None)], valid=False)
        before = self.all_bytes()
        node = self.good_node()
        code, _, err = self.settle_ok(node=node)
        self.assertEqual(code, 4)
        self.assertIn("has no claim_url", err)
        self.assertEqual(self.all_bytes(), before)
        self.assertEqual(node.calls, [], "nothing is asked of the node first")

    # -- 2 ------------------------------------------------------------------
    def test_02_sellers_paid_counts_distinct_addresses_not_receipts(self):
        self.tree([job("job-1"), job("job-2")])
        self.assertEqual(self.settle_ok("job-1", "A1B2")[0], 0)
        code, _, err = self.settle_ok("job-2", "C3D4")
        self.assertEqual(code, 0, err)
        stats = json.loads(self.bytes_of("stats.json"))
        self.assertEqual(stats["jobs_settled"], 2)
        self.assertEqual(stats["sellers_paid"], 1, "same address twice is one seller")
        self.assertEqual(stats["paid_xno_total"], "0.5")

    # -- 3 ------------------------------------------------------------------
    def test_03_an_unconfirmed_block_is_refused_and_writes_nothing(self):
        self.tree([job()])
        before = self.all_bytes()
        code, _, err = self.settle_ok(node=self.good_node(confirmed="false"))
        self.assertEqual(code, 7)
        self.assertIn("is not confirmed yet", err)
        self.assertEqual(self.all_bytes(), before)

    # -- 4 ------------------------------------------------------------------
    def test_04_one_raw_short_is_refused_and_both_numbers_are_named(self):
        self.tree([job()])
        before = self.all_bytes()
        short = str(int(PRICE_RAW) - 1)
        code, _, err = self.settle_ok(node=self.good_node(amount=short))
        self.assertEqual(code, 9)
        self.assertIn(short, err)
        self.assertIn(PRICE_RAW, err)
        self.assertEqual(self.all_bytes(), before)

    # -- 5 ------------------------------------------------------------------
    def test_05_a_valid_address_that_is_the_wrong_payee_is_a_payee_error(self):
        self.tree([job()])
        before = self.all_bytes()
        code, _, err = self.settle_ok(node=self.good_node(destination=STRANGER))
        self.assertEqual(code, 9, "a wrong payee is exit 9, not an address error")
        self.assertIn(STRANGER, err)
        self.assertIn(SELLER, err)
        self.assertNotIn("checksum", err)
        self.assertEqual(self.all_bytes(), before)

    # -- 6 ------------------------------------------------------------------
    def test_06_the_same_settlement_twice_is_refused_and_leaves_one_receipt(self):
        self.tree([job()])
        self.assertEqual(self.settle_ok()[0], 0)
        after_first = self.all_bytes()
        code, _, err = self.settle_ok()
        self.assertEqual(code, 4)
        self.assertIn("is already settled by block", err)
        self.assertEqual(len(json.loads(self.bytes_of("receipts.json"))["receipts"]), 1)
        self.assertEqual(self.all_bytes(), after_first)

    # -- 7 ------------------------------------------------------------------
    def test_07_dry_run_writes_nothing_and_prints_the_receipt_that_would_land(self):
        self.tree([job()])
        before = self.all_bytes()
        code, out, err = self.settle_ok(extra=("--dry-run",))
        self.assertEqual(code, 0, err)
        self.assertEqual(self.all_bytes(), before, "a dry run writes nothing")
        printed = json.loads(out[out.index("{"):out.rindex("}", 0, out.index("the stats")) + 1])

        code, _, err = self.settle_ok()
        self.assertEqual(code, 0, err)
        appended = json.loads(self.bytes_of("receipts.json"))["receipts"][0]
        self.assertEqual(json.dumps(printed, indent=2), json.dumps(appended, indent=2))

    # -- 8 ------------------------------------------------------------------
    def test_08_money_is_integers_all_the_way_through(self):
        tenth = "1" + "0" * 29          # 0.1 XNO
        fifth = "2" + "0" * 29          # 0.2 XNO
        self.tree([job("job-1", price_raw=tenth, price_xno="0.1"),
                   job("job-2", price_raw=fifth, price_xno="0.2")])
        self.assertEqual(self.settle_ok("job-1", "A1B2", amount=tenth)[0], 0)
        self.assertEqual(self.settle_ok("job-2", "C3D4", amount=fifth)[0], 0)
        receipts = json.loads(self.bytes_of("receipts.json"))["receipts"]
        for receipt in receipts:
            self.assertNotIn("e", receipt["amount_raw"].lower())
            self.assertNotIn(".", receipt["amount_raw"])
            self.assertTrue(receipt["amount_raw"].isdigit())
        self.assertEqual([r["amount_xno"] for r in receipts], ["0.100000", "0.200000"])
        # 0.1 + 0.2 is 0.3 exactly, not 0.30000000000000004.
        stats = json.loads(self.bytes_of("stats.json"))
        self.assertEqual(stats["paid_xno_total"], "0.3")
        self.assertEqual(int(receipts[0]["amount_raw"]) + int(receipts[1]["amount_raw"]),
                         3 * 10 ** 29)

    def test_08b_a_price_a_float_could_not_hold_survives_intact(self):
        odd = "250000000000000000000000000001"     # 0.25 XNO plus one raw
        # That single extra raw is a sub-micro tail, which validate.py now
        # refuses by default: a 6-decimal int64 amount column cannot hold it
        # (see usdc_shape.py). Priced deliberately, on the record, so this test
        # keeps asserting what it was written to assert - that settle.py carries
        # an amount no float could hold through to the receipt unchanged.
        self.tree([job(price_raw=odd, price_xno="0.250000000000000000000000000001",
                       sub_micro_ok=True,
                       excludes_ledgers=["USDC-atomic 6-decimal int64"])])
        code, _, err = self.settle_ok(node=nanonode.FakeNode(
            {block_hash(): send_block(amount=odd)}))
        self.assertEqual(code, 0, err)
        receipt = json.loads(self.bytes_of("receipts.json"))["receipts"][0]
        self.assertEqual(receipt["amount_raw"], odd)
        self.assertEqual(receipt["amount_xno"], "0." + "0" * 0 + "25" + "0" * 27 + "1")

    # -- 9 ------------------------------------------------------------------
    def test_09_deleting_an_existing_receipt_is_refused_as_not_appended(self):
        self.tree([job("job-1"), job("job-2")])
        self.assertEqual(self.settle_ok("job-1", "A1B2")[0], 0)
        # Commit that settlement, so origin/main carries the receipt, then
        # delete it from the working tree by hand.
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@t",
                   GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@t")
        subprocess.run(["git", "add", "-A"], cwd=self.dir, check=True, env=env)
        subprocess.run(["git", "commit", "-qm", "settle job-1"], cwd=self.dir,
                       check=True, env=env, stdout=subprocess.DEVNULL)
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.dir, check=True,
                              stdout=subprocess.PIPE).stdout.decode().strip()
        subprocess.run(["git", "update-ref", "refs/remotes/origin/main", head],
                       cwd=self.dir, check=True)
        self.write_json("receipts.json", {"receipts": []})
        before = self.all_bytes()
        code, _, err = self.settle_ok("job-2", "C3D4")
        self.assertEqual(code, 8)
        self.assertIn("receipts.json has been edited, not appended to - refusing", err)
        self.assertEqual(self.all_bytes(), before)

    def test_09b_without_a_base_ref_the_check_refuses_rather_than_skipping(self):
        self.tree([job()], commit=False)
        before = self.all_bytes()
        code, _, err = self.settle_ok()
        self.assertEqual(code, 8)
        self.assertIn("append-only", err)
        self.assertEqual(self.all_bytes(), before)

    # -- 10 -----------------------------------------------------------------
    def test_10_every_row_of_the_error_table_writes_nothing(self):
        good = block_hash()
        rows = [
            ("no such job", 3, "no such job: job-nope",
             ("job-nope", "--block-hash", good, "--delivery-url", "https://e.invalid/w",
              "--node", "https://node.invalid"), None),
            ("not claimed", 4, "only a claimed job can settle",
             ("job-open", "--block-hash", good, "--delivery-url", "https://e.invalid/w",
              "--node", "https://node.invalid"), None),
            ("no payout_address", 4, "has no payout_address",
             ("job-bare", "--block-hash", good, "--delivery-url", "https://e.invalid/w",
              "--node", "https://node.invalid"), None),
            ("short hash", 2, "--block-hash must be 64 hex characters",
             ("job-1", "--block-hash", "ABC", "--delivery-url", "https://e.invalid/w",
              "--node", "https://node.invalid"), None),
            ("no hash", 2, "--block-hash must be 64 hex characters",
             ("job-1", "--delivery-url", "https://e.invalid/w",
              "--node", "https://node.invalid"), None),
            ("http delivery url", 2, "--delivery-url must be an https URL",
             ("job-1", "--block-hash", good, "--delivery-url", "http://e.invalid/w",
              "--node", "https://node.invalid"), None),
            ("no delivery url", 2, "--delivery-url must be an https URL",
             ("job-1", "--block-hash", good, "--node", "https://node.invalid"), None),
            ("no node", 6, "--node or NANO_NODE_URL is required",
             ("job-1", "--block-hash", good, "--delivery-url", "https://e.invalid/w",
              "--node", ""), None),
            ("key in the node position", 2, "looks like a key or seed",
             ("job-1", "--block-hash", good, "--delivery-url", "https://e.invalid/w",
              "--node", block_hash("C3D4")), None),
            ("node unreachable", 7, "did not answer",
             ("job-1", "--block-hash", good, "--delivery-url", "https://e.invalid/w",
              "--node", "https://node.invalid"), nanonode.FakeNode(raises="timed out")),
            ("block unknown", 7, "does not know block",
             ("job-1", "--block-hash", good, "--delivery-url", "https://e.invalid/w",
              "--node", "https://node.invalid"), nanonode.FakeNode({})),
            ("unconfirmed", 7, "is not confirmed yet",
             ("job-1", "--block-hash", good, "--delivery-url", "https://e.invalid/w",
              "--node", "https://node.invalid"),
             nanonode.FakeNode({good: send_block(confirmed="false")})),
            ("not a send", 7, "is a receive, not a send",
             ("job-1", "--block-hash", good, "--delivery-url", "https://e.invalid/w",
              "--node", "https://node.invalid"),
             nanonode.FakeNode({good: send_block(subtype="receive")})),
            ("wrong payee", 9, "refusing",
             ("job-1", "--block-hash", good, "--delivery-url", "https://e.invalid/w",
              "--node", "https://node.invalid"),
             nanonode.FakeNode({good: send_block(destination=STRANGER)})),
            ("wrong amount", 9, "is priced at",
             ("job-1", "--block-hash", good, "--delivery-url", "https://e.invalid/w",
              "--node", "https://node.invalid"),
             nanonode.FakeNode({good: send_block(amount="1")})),
        ]
        for label, code, needle, argv, node in rows:
            with self.subTest(label):
                self.tree([job("job-1"),
                           job("job-open", state="open", payout_address=None),
                           job("job-bare", payout_address=None)])
                before = self.all_bytes()
                got, _, err = self.run_settle(*argv, node=node or self.good_node())
                self.assertEqual(got, code, "%s: %s" % (label, err))
                self.assertIn(needle, err, label)
                self.assertEqual(self.all_bytes(), before, label)
                self.assertEqual(
                    [n for n in os.listdir(self.dir) if n.endswith(".tmp")], [], label)
                self._tmp.cleanup()
                self.fresh_dir()

    # -- 11 -----------------------------------------------------------------
    def test_11_nanonode_is_the_only_module_that_can_open_a_socket(self):
        import ast

        network = {"socket", "http", "urllib", "ssl", "requests", "asyncio",
                   "ftplib", "smtplib", "xmlrpc", "telnetlib"}
        local = {}
        for base in (ROOT, os.path.join(ROOT, "vendor")):
            for name in os.listdir(base):
                if name.endswith(".py"):
                    local.setdefault(name[:-3], os.path.join(base, name))

        seen, queue, offenders = set(), ["settle"], {}
        while queue:
            module = queue.pop()
            if module in seen or module not in local:
                continue
            seen.add(module)
            with open(local[module], "r", encoding="utf-8") as handle:
                tree = ast.parse(handle.read())
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    top = name.split(".")[0]
                    if top in network:
                        offenders.setdefault(module, set()).add(top)
                    queue.append(top)
        self.assertIn("nanonode", seen)
        self.assertEqual(sorted(offenders), ["nanonode"],
                         "only nanonode.py may reach the network, found: %r" % offenders)

    # -- 12 -----------------------------------------------------------------
    def test_12_nothing_reachable_from_settle_can_sign_or_send(self):
        import ast

        signing = {"ed25519", "nacl", "keystore", "cryptography", "secrets",
                   "hmac", "ecdsa"}
        local = {}
        for base in (ROOT, os.path.join(ROOT, "vendor")):
            for name in os.listdir(base):
                if name.endswith(".py"):
                    local.setdefault(name[:-3], os.path.join(base, name))
        seen, queue, offenders = set(), ["settle"], {}
        while queue:
            module = queue.pop()
            if module in seen or module not in local:
                continue
            seen.add(module)
            with open(local[module], "r", encoding="utf-8") as handle:
                source = handle.read()
            for node in ast.walk(ast.parse(source)):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    top = name.split(".")[0]
                    if top in signing:
                        offenders.setdefault(module, set()).add(top)
                    queue.append(top)
            # Identifiers in *code*, not words in prose: settle.py's docstring
            # says it holds no seed, and that sentence is the point, not a leak.
            banned = {"sign", "sign_block", "send", "send_block", "private_key",
                      "secret_key", "signing_key", "seed", "wallet_create",
                      "derive_key", "unlock"}
            for node in ast.walk(ast.parse(source)):
                named = None
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    named = node.name
                elif isinstance(node, ast.Name):
                    named = node.id
                elif isinstance(node, ast.Attribute):
                    named = node.attr
                elif isinstance(node, ast.arg):
                    named = node.arg
                if named in banned:
                    self.fail("%s names %r in code and is reachable from settle.py"
                              % (module, named))
        self.assertEqual(offenders, {}, "a signing primitive is reachable: %r" % offenders)

        # The RPCs that move money, by name. The prose word "wallet" in a
        # docstring is fine; an RPC name in a request body is not.
        with open(os.path.join(ROOT, "settle.py"), "r", encoding="utf-8") as handle:
            source = handle.read()
        for rpc in ('"action": "send"', '"action":"send"', '"wallet"', '"wallet":',
                    "wallet_create", "wallet_add", "send_block", "block_create",
                    "receive_block", "password_enter"):
            self.assertNotIn(rpc, source, "settle.py names the RPC %r" % rpc)
        with open(os.path.join(ROOT, "nanonode.py"), "r", encoding="utf-8") as handle:
            node_source = handle.read()
        self.assertEqual(node_source.count('"action"'), 1,
                         "nanonode.py issues exactly one kind of RPC")
        self.assertIn('"action": "block_info"', node_source)

    # -- 13 -----------------------------------------------------------------
    def test_13_a_lowercase_hash_matches_and_is_stored_uppercase(self):
        self.tree([job()])
        lower = block_hash().lower()
        code, _, err = self.run_settle(
            "job-1", "--block-hash", lower,
            "--delivery-url", "https://example.invalid/work",
            "--node", "https://node.invalid/proxy", node=self.good_node())
        self.assertEqual(code, 0, err)
        receipt = json.loads(self.bytes_of("receipts.json"))["receipts"][0]
        self.assertEqual(receipt["block_hash"], block_hash())
        self.assertEqual(receipt["block_hash"], receipt["block_hash"].upper())

    # -- the settled tree must pass the repository's own checks -------------
    def test_14_a_settled_tree_passes_validate_and_the_append_only_check(self):
        self.tree([job()])
        self.assertEqual(self.settle_ok()[0], 0)
        result = subprocess.run(
            [sys.executable, "validate.py", "--no-write-stats"],
            cwd=self.dir, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        result = subprocess.run(
            [sys.executable, "validate.py", "--base", "origin/main", "--no-write-stats"],
            cwd=self.dir, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("skipped", result.stdout)

    def test_15_stats_is_byte_identical_to_what_validate_regenerates(self):
        self.tree([job()])
        self.assertEqual(self.settle_ok()[0], 0)
        written = self.bytes_of("stats.json")
        result = subprocess.run([sys.executable, "validate.py"], cwd=self.dir,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(self.bytes_of("stats.json"), written)

    def test_16_json_mode_prints_only_the_documented_object(self):
        self.tree([job()])
        code, out, err = self.settle_ok(extra=("--json",))
        self.assertEqual(code, 0, err)
        payload = json.loads(out)
        self.assertEqual(sorted(payload), ["ok", "receipt", "stats"])
        self.assertIs(payload["ok"], True)
        self.assertEqual(payload["receipt"]["block_hash"], block_hash())

    def test_17_exactly_one_node_request_is_made(self):
        self.tree([job()])
        node = self.good_node()
        self.assertEqual(self.settle_ok(node=node)[0], 0)
        self.assertEqual(len(node.calls), 1, node.calls)


class Spellings(SettleFixture):
    """One account, two spellings; one amount, two spellings.

    Every case here fails SAFE against the old code - it refuses a payment that
    arrived - which is why 83 green tests never saw any of it: not one fixture
    used the legacy prefix or a padded amount. By the time the refusal happens
    the buyer's money has irreversibly moved, so it costs the seller the receipt
    for money they were actually paid.
    """

    def test_a_claim_in_the_legacy_spelling_still_settles(self):
        """The bug: the block paid this account, and settle.py said it did not."""
        self.tree([job(payout_address=SELLER_XRB)])
        code, _, err = self.settle_ok(node=self.good_node(destination=SELLER))
        self.assertEqual(code, 0, err)
        receipts = json.loads(self.bytes_of("receipts.json"))["receipts"]
        self.assertEqual(len(receipts), 1)
        self.assertIs(receipts[0]["confirmed"], True)

    def test_a_node_answering_the_legacy_spelling_still_settles(self):
        """The same identity question from the other side."""
        self.tree([job()])
        code, _, err = self.settle_ok(node=self.good_node(destination=SELLER_XRB))
        self.assertEqual(code, 0, err)

    def test_a_padded_price_still_settles(self):
        """Raw is an integer, and validate.py admits a padded one, so it reaches here."""
        self.tree([job(price_raw=PADDED_PRICE_RAW)])
        code, _, err = self.settle_ok(amount=PRICE_RAW)
        self.assertEqual(code, 0, err)

    def test_a_receipt_records_the_canonical_spelling(self):
        """sellers_paid counts distinct paid_to values, so the rows this tool
        writes must not disagree with each other about one account."""
        self.tree([job(payout_address=SELLER_XRB)])
        code, _, err = self.settle_ok(node=self.good_node(destination=SELLER))
        self.assertEqual(code, 0, err)
        receipt = json.loads(self.bytes_of("receipts.json"))["receipts"][0]
        self.assertEqual(receipt["paid_to"], SELLER)

    def test_a_receipt_records_the_canonical_amount(self):
        self.tree([job(price_raw=PADDED_PRICE_RAW)])
        code, _, err = self.settle_ok(amount=PRICE_RAW)
        self.assertEqual(code, 0, err)
        receipt = json.loads(self.bytes_of("receipts.json"))["receipts"][0]
        self.assertEqual(receipt["amount_raw"], PRICE_RAW)

    def test_one_seller_spelled_two_ways_counts_once(self):
        """The public figure this repository publishes about how many sellers
        were paid must not double-count one account."""
        import validate as live
        receipts = [{"id": "receipt-001", "paid_to": SELLER,
                     "amount_raw": PRICE_RAW, "amount_xno": "0.25",
                     "block_hash": block_hash("A1B2"), "job_id": "job-1",
                     "settled_at": FROZEN},
                    {"id": "receipt-002", "paid_to": SELLER_XRB,
                     "amount_raw": PRICE_RAW, "amount_xno": "0.25",
                     "block_hash": block_hash("C3D4"), "job_id": "job-2",
                     "settled_at": FROZEN}]
        stats = live.compute_stats({"jobs": []}, {"receipts": receipts})
        self.assertEqual(stats["sellers_paid"], 1,
                         "one account in two spellings is one seller")

    def test_a_stranger_is_still_refused_in_the_legacy_spelling(self):
        """Comparing accounts must not become comparing nothing."""
        self.tree([job()])
        before = self.all_bytes()
        stranger_xrb = "xrb_" + STRANGER.split("_", 1)[1]
        code, _, err = self.settle_ok(node=self.good_node(destination=stranger_xrb))
        self.assertEqual(code, 9, err)
        self.assertEqual(self.all_bytes(), before)

    def test_a_block_with_no_destination_is_still_refused(self):
        """An absent link must not match an absent expectation."""
        self.tree([job()])
        before = self.all_bytes()
        code, _, err = self.settle_ok(node=self.good_node(destination=""))
        self.assertEqual(code, 9, err)
        self.assertEqual(self.all_bytes(), before)

    def test_a_wrong_amount_is_still_refused(self):
        """Comparing amounts numerically must not accept a different amount."""
        self.tree([job()])
        before = self.all_bytes()
        code, _, err = self.settle_ok(amount="1")
        self.assertEqual(code, 9, err)
        self.assertEqual(self.all_bytes(), before)

    def test_an_amount_that_is_not_a_number_is_refused_and_does_not_raise(self):
        """A superscript two is isdigit() but not int(): it must refuse, not crash."""
        self.tree([job()])
        before = self.all_bytes()
        code, _, err = self.settle_ok(amount="\u00b2")
        self.assertEqual(code, 9, err)
        self.assertEqual(self.all_bytes(), before)


class SettleAnHttpClaim(SettleFixture):
    """--claim-id: the same tool and the same refusals for the other door.

    A claim taken at POST /unstuck/api/v1/jobs/{id}/claim lands in claims.json,
    not in a pull request, so the operator settling it holds a claim id and no
    job id. These pin that the HTTP door reaches the same settlement path -
    including the refusal that matters most, which is an address mismatch.
    """

    def write_claims(self, *claims):
        self.write_json("claims.json", {"claims": list(claims)})

    def claim_record(self, claim_id="clm_0000000a", job_id="job-1", payee=SELLER,
                     **over):
        body = {
            "claim_id": claim_id,
            "job_id": job_id,
            "handle": "an-agent",
            "payee": payee,
            "state": "delivered",
            "claimed_at": "2026-09-27T06:00:00Z",
            "expires": FUTURE,
            "delivered_at": "2026-09-27T06:10:00Z",
            "paid_at": None,
            "delivery_url": "https://example.invalid/work",
            "price_xno": PRICE_XNO,
            "price_raw": PRICE_RAW,
            "receipt": None,
            "reconciled": False,
        }
        body.update(over)
        return body

    def settle_claim(self, claim_id="clm_0000000a", node=None, extra=()):
        node = node or nanonode.FakeNode({block_hash(): send_block()})
        return self.run_settle("--claim-id", claim_id,
                               "--block-hash", block_hash(),
                               "--delivery-url", "https://example.invalid/work",
                               "--node", "https://node.invalid/proxy",
                               *extra, node=node)

    def test_13_a_claim_id_resolves_the_job_and_settles_it(self):
        self.tree([job()])
        self.write_claims(self.claim_record())
        code, out, err = self.settle_claim()
        self.assertEqual(code, 0, err)
        receipts = json.loads(self.bytes_of("receipts.json").decode())["receipts"]
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["job_id"], "job-1")
        self.assertEqual(receipts[0]["paid_to"], SELLER)

    def test_13b_an_xrb_spelled_claim_settles_a_nano_spelled_job(self):
        """The 2026-09-27 defect, pinned at the claim layer.

        The two prefixes name one account. This file used to compare them as
        strings, so an xrb_-spelled payee could never be settled - and that was
        found after the money had gone irreversibly.
        """
        self.tree([job(payout_address=SELLER)])
        self.write_claims(self.claim_record(payee=SELLER_XRB))
        code, _, err = self.settle_claim()
        self.assertEqual(code, 0, err)
        receipts = json.loads(self.bytes_of("receipts.json").decode())["receipts"]
        self.assertEqual(receipts[0]["paid_to"], SELLER)

    def test_13c_a_claim_naming_a_different_payee_is_refused_and_writes_nothing(self):
        self.tree([job(payout_address=SELLER)])
        self.write_claims(self.claim_record(payee=STRANGER))
        before = self.all_bytes()
        code, _, err = self.settle_claim()
        self.assertEqual(code, 9, err)
        self.assertIn(STRANGER, err)
        self.assertIn(SELLER, err)
        self.assertEqual(self.all_bytes(), before)

    def test_13d_a_claim_id_contradicting_the_positional_job_is_a_usage_error(self):
        self.tree([job(), job(job_id="job-2")])
        self.write_claims(self.claim_record(job_id="job-1"))
        before = self.all_bytes()
        code, _, err = self.run_settle(
            "job-2", "--claim-id", "clm_0000000a",
            "--block-hash", block_hash(), "--delivery-url",
            "https://example.invalid/work", "--node", "https://node.invalid")
        self.assertEqual(code, 2, err)
        self.assertEqual(self.all_bytes(), before)

    def test_13e_an_unknown_or_unreadable_claim_refuses_before_the_node(self):
        self.tree([job()])
        self.write_claims(self.claim_record())
        before = self.all_bytes()
        code, _, err = self.settle_claim(claim_id="clm_ffffffff")
        self.assertEqual(code, 3, err)
        self.assertEqual(self.all_bytes(), before)

        os.remove(os.path.join(self.dir, "claims.json"))
        code, _, err = self.settle_claim()
        self.assertEqual(code, 5, err)
        self.assertEqual(self.all_bytes(), before)

    def test_13f_a_claim_payee_that_fails_checksum_is_never_paid_to(self):
        """claims.json edited by hand is the only way to get here - still refuse."""
        self.tree([job()])
        self.write_claims(self.claim_record(payee=SELLER[:-1] + "a"))
        before = self.all_bytes()
        code, _, err = self.settle_claim()
        self.assertEqual(code, 4, err)
        self.assertIn("checksum", err)
        self.assertEqual(self.all_bytes(), before)

    def test_13g_neither_a_job_id_nor_a_claim_id_is_a_usage_error(self):
        self.tree([job()])
        before = self.all_bytes()
        code, _, err = self.run_settle(
            "--block-hash", block_hash(), "--delivery-url",
            "https://example.invalid/work", "--node", "https://node.invalid")
        self.assertEqual(code, 2, err)
        self.assertEqual(self.all_bytes(), before)


if __name__ == "__main__":
    unittest.main()
