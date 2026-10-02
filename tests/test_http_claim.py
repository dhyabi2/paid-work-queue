"""The suite for http_claim.py. Every test is numbered after the spec line it pins.

No test touches the network, and test 17 fails the build if importing
`http_claim` ever pulls in something that could - the socket belongs inside
`serve()` and nowhere else. Nothing here contains a 64-character hex literal
either: `validate.py`'s secret gate refuses one anywhere in the tree, and it is
right to, so the block hash test 10 needs is built at runtime.
"""

import datetime
import json
import os
import shutil
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "vendor"))

import claim as claim_cli  # noqa: E402
import http_claim  # noqa: E402
import money  # noqa: E402
import nanoaddr  # noqa: E402
import validate  # noqa: E402

GENESIS = "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3"
BURN = "nano_1111111111111111111111111111111111111111111111111111hifc8npp"

FUTURE = "2099-10-03T07:00:00Z"
PAST = "2000-01-02T07:00:00Z"
AT = datetime.datetime(2026, 9, 29, 6, 31, 4, tzinfo=datetime.timezone.utc)


def xrb_spelling(address):
    """The same account, spelled with the legacy prefix. Built, never pasted."""
    return nanoaddr.encode(nanoaddr.decode(address), "xrb_")


def mutate_checksum(address):
    """A well-formed address whose checksum does not match its key."""
    body = address[: -1]
    last = address[-1]
    replacement = nanoaddr.ALPHABET[(nanoaddr.ALPHABET.index(last) + 1) % 32]
    return body + replacement


def job(job_id, price_xno="0.05", state="open", expires=FUTURE):
    """A job object in the exact shape and key order jobs.json uses."""
    return {
        "id": job_id,
        "title": "job %s" % job_id,
        "description": "what to do for %s" % job_id,
        "acceptance": ["line one for %s" % job_id, "line two for %s" % job_id],
        "price_xno": price_xno,
        "price_raw": str(money.xno_to_raw(price_xno)),
        "posted": "2026-09-26T07:00:00Z",
        "expires": expires,
        "state": state,
        "claimed_by": None,
        "claim_url": None,
        "receipt_id": None,
    }


class Base(unittest.TestCase):
    """A temp directory holding jobs.json, and a service with a frozen clock."""

    def setUp(self):
        import tempfile

        self.dir = tempfile.mkdtemp(prefix="http-claim-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.now = AT
        self.issued = []
        self.published = []
        self.write_jobs([job("job-a"), job("job-b"), job("job-c")])
        # validate.py reads both files, so the fixture is a whole tree: a test
        # that cannot run validate.py cannot tell whether CI would accept it.
        shutil.copy(os.path.join(ROOT, "receipts.json"), self.dir)

    # ---- fixtures -------------------------------------------------------

    def write_jobs(self, jobs, updated="2026-09-26T07:00:00Z"):
        self.jobs_document = {"updated": updated, "currency": "XNO", "jobs": jobs}
        with open(os.path.join(self.dir, "jobs.json"), "w", encoding="utf-8") as handle:
            json.dump(self.jobs_document, handle, indent=2)

    def validate_tree(self):
        """validate.py's verdict on the temp tree: 0 means CI would accept it."""
        with open(os.devnull, "w", encoding="utf-8") as sink:
            return validate.run(self.dir, write_stats=False, out=sink)

    def read_file(self, name, default=None):
        path = os.path.join(self.dir, name)
        if not os.path.exists(path):
            return default
        with open(path, encoding="utf-8") as handle:
            return json.load(handle)

    def service(self, publisher=None, rate_limit=http_claim.RATE_LIMIT_CLAIMS):
        counter = {"n": 0}

        def idgen():
            counter["n"] += 1
            self.issued.append(counter["n"])
            return "clm_%08x" % counter["n"]

        def record(claims_document, jobs_document):
            self.published.append(len(claims_document["claims"]))
            return True

        return http_claim.ClaimService(
            root=self.dir,
            clock=lambda: self.now,
            idgen=idgen,
            publisher=publisher or record,
            public_base="https://example.test/unstuck/api/v1",
            rate_limit=rate_limit,
        )

    # ---- helpers --------------------------------------------------------

    def claim(self, service, job_id="job-a", payee=GENESIS, handle="whoever",
              source="198.51.100.7", **extra):
        body = {"payee": payee, "handle": handle}
        body.update(extra)
        return service.handle("POST", "/unstuck/api/v1/jobs/%s/claim" % job_id,
                              json.dumps(body).encode("utf-8"), source=source)


class ClaimInOneRequest(Base):

    def test_01_claim_in_one_request(self):
        """From a fresh client with no account, no clone and no token."""
        status, payload = self.claim(self.service())
        self.assertEqual(status, 201, payload)
        self.assertTrue(http_claim.CLAIM_ID_RE.match(payload["claim_id"]),
                        payload["claim_id"])
        self.assertEqual(payload["job_id"], "job-a")
        self.assertEqual(payload["payee"], GENESIS)
        self.assertEqual(payload["state"], "open")
        self.assertEqual(payload["public_url"],
                         "https://example.test/unstuck/api/v1/claims/%s"
                         % payload["claim_id"])

    def test_02_claim_response_carries_acceptance(self):
        """The definition of done arrives in the same round trip as the claim."""
        status, payload = self.claim(self.service())
        self.assertEqual(status, 201)
        self.assertTrue(payload["acceptance"])
        self.assertEqual(payload["acceptance"],
                         self.jobs_document["jobs"][0]["acceptance"])
        # and the price, exactly as the git record holds it - no float anywhere
        self.assertEqual(payload["price_xno"], "0.05")
        self.assertEqual(payload["price_raw"], str(money.xno_to_raw("0.05")))
        self.assertEqual(int(payload["price_raw"]), 5 * 10 ** 28)


class AddressRefusals(Base):

    def test_03_claim_rejects_bad_checksum_and_stores_nothing(self):
        """The second half is the important half."""
        service = self.service()
        status, payload = self.claim(service, payee=mutate_checksum(GENESIS))
        self.assertEqual(status, 400)
        self.assertEqual(payload["error"], "invalid_address_checksum")
        self.assertIn("checksum_expected", payload)
        self.assertIn("checksum_found", payload)
        self.assertNotEqual(payload["checksum_expected"], payload["checksum_found"])
        # nothing was stored, in any table, at any state
        self.assertIsNone(self.read_file("claims.json"))
        self.assertEqual(self.read_file("jobs.json")["jobs"][0]["state"], "open")
        self.assertIsNone(self.read_file("jobs.json")["jobs"][0]["claimed_by"])

    def test_04_claim_normalises_xrb_prefix(self):
        """`xrb_` and `nano_` name the same account, before storage and comparison."""
        service = self.service()
        legacy = xrb_spelling(GENESIS)
        self.assertTrue(legacy.startswith("xrb_"))
        status, payload = self.claim(service, payee=legacy)
        self.assertEqual(status, 201, payload)
        self.assertEqual(payload["payee"], GENESIS)

        stored = self.read_file("claims.json")["claims"][0]
        self.assertEqual(stored["payee"], GENESIS)
        self.assertTrue(stored["payee"].startswith("nano_"))
        # the job the settlement path reads carries the nano_ spelling too, so
        # settle.py compares like with like - the 2026-09-27 defect, where an
        # xrb_-spelled payee could never be settled, cannot recur here
        self.assertEqual(self.read_file("jobs.json")["jobs"][0]["payout_address"],
                         GENESIS)
        # and releasing with the other spelling is the same agent
        status, _ = service.handle(
            "DELETE", "/unstuck/api/v1/claims/%s" % payload["claim_id"],
            json.dumps({"payee": legacy}).encode("utf-8"))
        self.assertEqual(status, 200)


class Contention(Base):

    def test_05_double_claim_is_409_with_expiry(self):
        service = self.service()
        first_status, first = self.claim(service)
        self.assertEqual(first_status, 201)
        status, payload = self.claim(service, payee=BURN, handle="second")
        self.assertEqual(status, 409)
        self.assertEqual(payload["error"], "already_claimed")
        self.assertEqual(payload["expires"], first["expires"])
        self.assertEqual(payload["handle"], "whoever")
        self.assertIn("claimed_at", payload)

    def test_06_claim_after_expiry_reopens(self):
        service = self.service()
        status, first = self.claim(service)
        self.assertEqual(status, 201)
        self.now = self.now + datetime.timedelta(
            seconds=http_claim.CLAIM_TTL_SECONDS + 1)
        status, second = self.claim(service, payee=BURN, handle="later")
        self.assertEqual(status, 201, second)
        self.assertNotEqual(second["claim_id"], first["claim_id"])
        states = {entry["claim_id"]: entry["state"]
                  for entry in self.read_file("claims.json")["claims"]}
        self.assertEqual(states[first["claim_id"]], "expired")
        self.assertEqual(states[second["claim_id"]], "open")

    def test_07_release_requires_matching_payee(self):
        service = self.service()
        status, created = self.claim(service)
        self.assertEqual(status, 201)
        path = "/unstuck/api/v1/claims/%s" % created["claim_id"]

        status, payload = service.handle(
            "DELETE", path, json.dumps({"payee": BURN}).encode("utf-8"))
        self.assertEqual(status, 403)
        self.assertEqual(payload["error"], "payee_mismatch")
        self.assertEqual(self.read_file("jobs.json")["jobs"][0]["state"], "claimed")

        status, payload = service.handle(
            "DELETE", path, json.dumps({"payee": GENESIS}).encode("utf-8"))
        self.assertEqual(status, 200)
        self.assertEqual(payload["state"], "released")
        job_after = self.read_file("jobs.json")["jobs"][0]
        self.assertEqual(job_after["state"], "open")
        self.assertIsNone(job_after["claimed_by"])
        self.assertIsNone(job_after["claim_url"])


class Delivery(Base):

    def test_08_deliver_records_but_does_not_assert_payment(self):
        service = self.service()
        _, created = self.claim(service)
        status, payload = service.handle(
            "POST", "/unstuck/api/v1/claims/%s/deliver" % created["claim_id"],
            json.dumps({"url": "https://example.org/my-work"}).encode("utf-8"))
        self.assertEqual(status, 200, payload)
        self.assertEqual(payload["state"], "delivered")
        self.assertNotIn("receipt", payload)
        rendered = json.dumps(payload).lower()
        for forbidden in ("paid", "payment is due", "we owe", "accepted"):
            self.assertNotIn(forbidden, rendered,
                             "delivery must not claim payment has occurred: %r"
                             % forbidden)
        self.assertIsNone(service.read_claim(created["claim_id"])[1]["receipt"])

    def test_08b_a_delivered_claim_is_still_settleable(self):
        """Delivery must not move the job into a state settle.py refuses.

        settle.py pays a `claimed` job and refuses every other state, so if
        delivering moved the job to "delivered" the work would be undeliverable
        and unpayable in the same step - green unit tests, no money.
        """
        service = self.service()
        _, created = self.claim(service)
        service.handle("POST", "/unstuck/api/v1/claims/%s/deliver" % created["claim_id"],
                       json.dumps({"url": "https://example.org/w"}).encode("utf-8"))

        job_after = self.read_file("jobs.json")["jobs"][0]
        self.assertEqual(job_after["state"], "claimed")
        self.assertEqual(service.read_claim(created["claim_id"])[1]["state"],
                         "delivered")
        self.assertEqual(self.validate_tree(), 0)

        import settle

        self.assertEqual(
            settle.check_job_is_settleable(job_after, "job-a", {"receipts": []}),
            GENESIS,
            "settle.py must accept the job a delivered HTTP claim leaves behind")

    def test_09_public_claim_is_readable_anonymously(self):
        service = self.service()
        _, created = self.claim(service)
        status, payload = service.handle(
            "GET", "/unstuck/api/v1/claims/%s" % created["claim_id"])
        self.assertEqual(status, 200)
        for field in ("claim_id", "job_id", "handle", "payee", "state",
                      "claimed_at", "delivered_at", "paid_at", "delivery_url",
                      "receipt"):
            self.assertIn(field, payload)
        self.assertEqual(payload["claim_id"], created["claim_id"])

    def test_10_receipt_is_null_until_paid(self):
        service = self.service()
        _, created = self.claim(service)
        claim_id = created["claim_id"]
        read = lambda: service.handle("GET", "/unstuck/api/v1/claims/%s" % claim_id)[1]

        self.assertIsNone(read()["receipt"])
        service.handle("POST", "/unstuck/api/v1/claims/%s/deliver" % claim_id,
                       json.dumps({"url": "https://example.org/w"}).encode("utf-8"))
        self.assertEqual(read()["state"], "delivered")
        self.assertIsNone(read()["receipt"])

        # a block hash is 64 hex; built here rather than written, because
        # validate.py's secret gate refuses 64 hex standing alone in the tree
        block = "".join("abcdef0123456789"[index % 16] for index in range(64))
        service.mark_paid(claim_id, block, str(money.xno_to_raw("0.05")))
        paid = read()
        self.assertEqual(paid["state"], "paid")
        self.assertIsNotNone(paid["receipt"])
        self.assertEqual(len(paid["receipt"]["block"]), 64)
        self.assertEqual(paid["receipt"]["block"], block.upper())
        self.assertEqual(paid["receipt"]["amount_raw"], str(5 * 10 ** 28))
        self.assertTrue(paid["receipt"]["explorer"].endswith(block.upper()))
        self.assertTrue(paid["receipt"]["explorer"].startswith("https://"))


class ErrorTable(Base):

    def test_11_every_error_row(self):
        """One case per row of the spec's error table, plus the row it omits."""
        service = self.service()
        claim_path = "/unstuck/api/v1/jobs/job-a/claim"

        def post(body, path=claim_path, source="203.0.113.1"):
            raw = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
            return service.handle("POST", path, raw, source=source)

        cases = [
            (400, "malformed_json", b"not json at all"),
            (400, "malformed_json", b"[1, 2, 3]"),
            (400, "payee_missing", {"handle": "x"}),
            (400, "payee_missing", {"payee": 17}),
            (400, "invalid_address_prefix", {"payee": "bitcoin_" + "1" * 60}),
            (400, "invalid_address_length", {"payee": "nano_1234567890"}),
            (400, "invalid_address_charset",
             {"payee": GENESIS[:10] + "0" + GENESIS[11:]}),
            (400, "invalid_address_padding",
             {"payee": "nano_4" + GENESIS[len("nano_") + 1:]}),
            (400, "invalid_address_checksum", {"payee": mutate_checksum(GENESIS)}),
            (400, "handle_too_long", {"payee": GENESIS, "handle": "h" * 65}),
        ]
        for expected_status, expected_error, body in cases:
            with self.subTest(error=expected_error):
                status, payload = post(body)
                self.assertEqual(status, expected_status, payload)
                self.assertEqual(payload["error"], expected_error, payload)
                self.assertTrue(payload["reason"].strip(), payload)

        status, payload = post({"payee": GENESIS},
                               path="/unstuck/api/v1/jobs/job-zzz/claim")
        self.assertEqual((status, payload["error"]), (404, "no_such_job"))

        status, _ = post({"payee": GENESIS})
        self.assertEqual(status, 201)
        status, payload = post({"payee": BURN})
        self.assertEqual((status, payload["error"]), (409, "already_claimed"))

        self.write_jobs([job("job-old", expires=PAST)])
        status, payload = post({"payee": GENESIS},
                               path="/unstuck/api/v1/jobs/job-old/claim")
        self.assertEqual((status, payload["error"]), (410, "job_expired"))

    def test_12_rate_limit_returns_retry_after(self):
        """Six claims in a minute; the sixth is refused, whatever the job's state."""
        service = self.service()
        seen = []
        for _ in range(6):
            seen.append(self.claim(service, source="192.0.2.44"))
        self.assertEqual(seen[0][0], 201)
        for status, payload in seen[1:5]:
            self.assertEqual(status, 409, payload)
        status, payload = seen[5]
        self.assertEqual(status, 429, payload)
        self.assertEqual(payload["error"], "rate_limited")
        self.assertIsInstance(payload["retry_after"], int)
        self.assertGreater(payload["retry_after"], 0)
        # a different source is unaffected
        status, payload = self.claim(service, source="192.0.2.45")
        self.assertNotEqual(status, 429)


class Record(Base):

    def test_13_the_public_record_gets_the_claim(self):
        """claims.json carries it, the job says claimed, and validate.py accepts.

        The spec asks for the git mirror in `dhyabi2/paid-work-queue`; the
        publishing path that would push it is not in this repository yet, so
        what is pinned here is the half that exists: the record this service
        writes is exactly the record CI will accept when that path lands.
        """
        service = self.service()
        _, created = self.claim(service)

        claims = self.read_file("claims.json")["claims"]
        self.assertEqual([entry["claim_id"] for entry in claims],
                         [created["claim_id"]])
        stored = claims[0]
        for field in ("claim_id", "job_id", "handle", "payee", "claimed_at",
                      "expires"):
            self.assertTrue(stored[field], field)

        job_after = self.read_file("jobs.json")["jobs"][0]
        self.assertEqual(job_after["state"], "claimed")
        self.assertEqual(job_after["claimed_by"], "whoever")
        self.assertEqual(job_after["claim_url"], created["public_url"])

        self.assertEqual(self.validate_tree(), 0,
                         "validate.py must accept a tree this service wrote")

    def test_14_claim_survives_publish_failure(self):
        """A claim silently lost because a git push failed is not allowed."""

        def explode(claims_document, jobs_document):
            raise RuntimeError("git push failed")

        service = self.service(publisher=explode)
        status, created = self.claim(service)
        self.assertEqual(status, 201, created)
        self.assertFalse(created["reconciled"])

        status, payload = service.handle(
            "GET", "/unstuck/api/v1/claims/%s" % created["claim_id"])
        self.assertEqual(status, 200)
        self.assertFalse(payload["reconciled"])
        self.assertEqual(payload["state"], "open")
        self.assertEqual(self.read_file("claims.json")["claims"][0]["claim_id"],
                         created["claim_id"])

    def test_15_pull_request_path_still_works(self):
        """This is an additional door. It must not close the one already open."""
        import io

        out, err = io.StringIO(), io.StringIO()
        code = claim_cli.main(
            ["job-b", "--handle", "by-pull-request", "--address", BURN,
             "--claim-url", "https://github.com/dhyabi2/paid-work-queue/pull/1"],
            out=out, err=err, directory=self.dir)
        self.assertEqual(code, 0, err.getvalue())

        job_after = [entry for entry in self.read_file("jobs.json")["jobs"]
                     if entry["id"] == "job-b"][0]
        self.assertEqual(job_after["state"], "claimed")
        self.assertEqual(job_after["claimed_by"], "by-pull-request")
        self.assertEqual(job_after["payout_address"], BURN)
        self.assertEqual(self.validate_tree(), 0,
                         "CI must still accept a claim.py edit")

        # and the HTTP door agrees the job is taken rather than offering it again
        status, payload = self.claim(self.service(), job_id="job-b")
        self.assertEqual(status, 409, payload)

    def test_15b_a_lapsed_claim_reopens_the_job_in_both_files(self):
        """jobs.json must not say 'claimed' while claims.json says 'expired'."""
        service = self.service()
        _, first = self.claim(service)
        self.assertEqual(self.read_file("jobs.json")["jobs"][0]["state"], "claimed")

        self.now = self.now + datetime.timedelta(
            seconds=http_claim.CLAIM_TTL_SECONDS + 1)
        status, second = self.claim(service, payee=BURN, handle="later")
        self.assertEqual(status, 201, second)

        job_after = self.read_file("jobs.json")["jobs"][0]
        self.assertEqual(job_after["claimed_by"], "later")
        self.assertEqual(job_after["payout_address"], BURN)
        self.assertEqual(job_after["claim_url"], second["public_url"])
        self.assertEqual(self.validate_tree(), 0)

    def test_15c_the_http_door_never_reassigns_a_pull_request_claim(self):
        """The defect test 15 caught: both doors write the same two fields.

        claim.py records a claim only in jobs.json. If this service read that
        as free it would hand the job to a second agent and overwrite the first
        one's payout_address, so the payment would go to whoever claimed last.
        """
        import io

        out, err = io.StringIO(), io.StringIO()
        code = claim_cli.main(
            ["job-c", "--handle", "first-by-pr", "--address", BURN,
             "--claim-url", "https://github.com/dhyabi2/paid-work-queue/pull/9"],
            out=out, err=err, directory=self.dir)
        self.assertEqual(code, 0, err.getvalue())

        status, payload = self.claim(self.service(), job_id="job-c", payee=GENESIS)
        self.assertEqual(status, 409, payload)
        self.assertEqual(payload["error"], "already_claimed")
        self.assertEqual(payload["handle"], "first-by-pr")
        self.assertIn("pull/9", payload["claim_url"])

        # and the first claimant's payout address is untouched
        job_after = [entry for entry in self.read_file("jobs.json")["jobs"]
                     if entry["id"] == "job-c"][0]
        self.assertEqual(job_after["payout_address"], BURN)
        self.assertEqual(job_after["claimed_by"], "first-by-pr")
        self.assertIsNone(self.read_file("claims.json"))

    def test_16_jobs_endpoint_matches_git_jobs_json(self):
        """A mirror, not a second source of truth. claim_href is the only addition."""
        service = self.service()
        status, payload = service.handle("GET", "/unstuck/api/v1/jobs")
        self.assertEqual(status, 200)
        self.assertEqual(payload["currency"], "XNO")
        self.assertEqual(payload["source"],
                         "https://github.com/dhyabi2/paid-work-queue")
        self.assertEqual(payload["updated"], self.jobs_document["updated"])
        self.assertEqual(len(payload["jobs"]), 3)
        for mirrored, original in zip(payload["jobs"], self.jobs_document["jobs"]):
            self.assertEqual(set(mirrored) - set(original), {"claim_href"})
            for field, value in original.items():
                self.assertEqual(mirrored[field], value, field)
            self.assertEqual(mirrored["claim_href"],
                             "/unstuck/api/v1/jobs/%s/claim" % original["id"])

        status, filtered = service.handle("GET", "/unstuck/api/v1/jobs",
                                          query={"state": "open"})
        self.assertEqual(len(filtered["jobs"]), 3)
        self.claim(service)
        status, filtered = service.handle("GET", "/unstuck/api/v1/jobs",
                                          query={"state": "open"})
        self.assertEqual([entry["id"] for entry in filtered["jobs"]],
                         ["job-b", "job-c"])


class Hygiene(Base):

    def test_17_importing_opens_no_socket(self):
        """The socket lives inside serve() and nowhere else."""
        import importlib
        import types

        forbidden = {"socket", "socketserver", "http.server", "wsgiref",
                     "urllib.request", "ssl", "asyncio", "requests", "httpx"}
        seen, frontier = set(), ["http_claim"]
        while frontier:
            name = frontier.pop()
            if name in seen:
                continue
            seen.add(name)
            module = sys.modules.get(name) or importlib.import_module(name)
            if not isinstance(module, types.ModuleType):
                continue
            if not (getattr(module, "__file__", None) or "").startswith(ROOT):
                continue
            for attribute in vars(module).values():
                if isinstance(attribute, types.ModuleType):
                    frontier.append(attribute.__name__)
        self.assertEqual(seen & forbidden, set(),
                         "http_claim's import graph reaches %s" % (seen & forbidden,))

    def test_18_a_secret_in_a_field_is_refused_not_stored(self):
        """Nothing a caller sends has any business being 64 hex standing alone."""
        service = self.service()
        secret = "".join("0123456789abcdef"[index % 16] for index in range(64))
        status, payload = self.claim(service, handle=secret)
        self.assertEqual(status, 400, payload)
        self.assertEqual(payload["error"], "looks_like_a_secret")
        self.assertIsNone(self.read_file("claims.json"))

    def test_19_check_address_is_the_fix_the_refusal_points_at(self):
        service = self.service()
        _, refusal = self.claim(service, payee=mutate_checksum(GENESIS))
        self.assertIn("check-address", refusal["reason"])

        status, payload = service.handle("GET", "/unstuck/api/v1/check-address",
                                         query={"a": mutate_checksum(GENESIS)})
        self.assertEqual(status, 200)
        self.assertFalse(payload["valid"])
        self.assertEqual(payload["error"], "invalid_address_checksum")

        status, payload = service.handle("GET", "/unstuck/api/v1/check-address",
                                         query={"a": xrb_spelling(GENESIS)})
        self.assertEqual(status, 200)
        self.assertTrue(payload["valid"])
        self.assertEqual(payload["address"], GENESIS)

    def test_20_unknown_fields_are_ignored_not_rejected(self):
        status, payload = self.claim(self.service(), favourite_colour="green")
        self.assertEqual(status, 201, payload)

    def test_21_unknown_routes_and_methods(self):
        service = self.service()
        self.assertEqual(service.handle("GET", "/nope")[0], 404)
        self.assertEqual(service.handle("GET", "/unstuck/api/v1/widgets")[0], 404)
        self.assertEqual(
            service.handle("GET", "/unstuck/api/v1/jobs/job-a/claim")[0], 405)


if __name__ == "__main__":
    unittest.main()
