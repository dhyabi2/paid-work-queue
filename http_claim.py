#!/usr/bin/env python3
"""Claim a paid job over HTTP, in one request.

Four days after this queue went public it held three funded jobs and zero
claims. Not zero settlements - zero *claims*. Nobody had even said "I'll take
it", so the blocker was never that a human had not sent the money; nothing had
ever arrived to be paid.

What the README asks of a stranger today, before we have paid them anything:
have a GitHub account, clone the repository, have Python 3.10+, run `claim.py`,
fork, push a branch, open a pull request, and wait for a human to merge it.
Seven steps and an identity provider, to volunteer for 0.05 XNO. The one agent
in this funnel that ever transacted sells work for hire, deliver-first, and is
reachable by an HTTP call with no GitHub account in the loop.

So: a claim costs one HTTP request. This module is that door. The pull-request
path keeps working and is not touched - this is an additional door, not a
replacement, and `test_pull_request_path_still_works` fails the build if
`claim.py` ever stops producing a valid edit.

Two things this module is deliberate about:

* **An address that fails checksum is never stored**, in any table, at any
  state. The nearest miss in the whole funnel was mechanical: an agent said yes
  and handed over an address that fails its checksum. The refusal carries both
  checksums so it can be fixed without asking us.
* **`xrb_` is normalised to `nano_`** before storage and before any comparison.
  The two prefixes name the same account. On 2026-09-27 `settle.py` compared
  payee addresses as strings, so an `xrb_`-spelled payee could never be
  settled - found *after* the money had gone irreversibly. That defect does not
  get to reappear at the claim layer.

No float touches money anywhere here: 1 XNO = 10**30 raw and a float loses the
bottom 13+ digits, so amounts are carried as the integer-strings jobs.json
already holds and cross-checked with `vendor/money.py`.

Standard library only, Python 3.10+. Importing this module opens no socket and
imports nothing that could - `tests/test_http_claim.py` fails the build if that
changes. The socket only appears inside `serve()`, which imports its server
machinery lazily for exactly that reason.

Usage:
    python3 http_claim.py --serve --port 8080 [--public-base https://host/path]
    python3 http_claim.py --routes          # print the route table and exit
"""

import argparse
import datetime
import json
import os
import re
import secrets
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor"))

import money  # noqa: E402
import nanoaddr  # noqa: E402
from canonical import checksum_pair, same_account  # noqa: E402  - one comparison, not three

HERE = os.path.dirname(os.path.abspath(__file__))

JOBS_FILE = "jobs.json"
CLAIMS_FILE = "claims.json"

API_ROOT = "/unstuck/api/v1"
SOURCE_REPO = "https://github.com/dhyabi2/paid-work-queue"
DEFAULT_PUBLIC_BASE = "https://getunstuck.space/unstuck/api/v1"
EXPLORER = "https://nanolooker.com/block/%s"

#: A claim is held for three days. Long enough to do a day's work and come
#: back, short enough that a job abandoned by one agent returns to the pool
#: while it is still worth doing.
CLAIM_TTL_SECONDS = 3 * 24 * 60 * 60

#: More than five claims from one source address in sixty seconds is a client
#: in a loop, not five agents at work.
RATE_LIMIT_CLAIMS = 5
RATE_LIMIT_WINDOW_SECONDS = 60

HANDLE_MAX = 64
CONTACT_MAX = 200
NOTE_MAX = 1000
URL_MAX = 2000
ANONYMOUS = "anonymous"

HANDLE_RE = re.compile(r"\A[A-Za-z0-9._\-/@ ]{1,%d}\Z" % HANDLE_MAX)
CLAIM_ID_RE = re.compile(r"\Aclm_[0-9a-f]{8}\Z")
#: 64 hex standing alone is a seed or a private key. Nothing a caller sends us
#: has any business being one, and `validate.py`'s secret gate refuses one
#: anywhere in the tree - so we refuse to store one rather than find out later.
SECRET_RE = re.compile(r"(?<![0-9A-Za-z])[0-9a-fA-F]{64,}(?![0-9A-Za-z])")

#: The claim's own lifecycle. Distinct from a *job* state (validate.py owns
#: that set); a claim is the agent's side of the same story.
CLAIM_STATES = ("open", "delivered", "accepted", "paid", "rejected", "expired", "released")
#: States in which the claim still holds the job.
HOLDING_STATES = ("open", "delivered", "accepted", "paid")

#: nanoaddr's reason codes -> the error codes this API promises. `bad_padding`
#: has no row in the spec's error table and has to have one: the first
#: character after the prefix encodes the four zero pad bits, so only '1' and
#: '3' can ever appear there, and an address failing that is structurally not
#: an address rather than merely mistyped. Naming it precisely is the whole
#: point of these codes - folding it into the charset row would tell a caller
#: to go looking at the wrong character.
ADDRESS_ERRORS = {
    "not_a_string": "payee_missing",
    "empty": "payee_missing",
    "bad_prefix": "invalid_address_prefix",
    "bad_length": "invalid_address_length",
    "bad_padding": "invalid_address_padding",
    "bad_character": "invalid_address_charset",
    "bad_checksum": "invalid_address_checksum",
}


class Refused(Exception):
    """An HTTP refusal. `status` is the code, `payload` is the whole body."""

    def __init__(self, status, error, reason, **extra):
        super().__init__(reason)
        self.status = status
        self.payload = {"error": error, "reason": reason}
        self.payload.update(extra)


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc)


def rfc3339(moment):
    return moment.astimezone(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_rfc3339(text):
    """RFC3339 UTC -> aware datetime, or None if it is not one."""
    if not isinstance(text, str):
        return None
    try:
        return datetime.datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=datetime.timezone.utc)
    except ValueError:
        return None


def looks_like_a_key(value):
    return isinstance(value, str) and bool(SECRET_RE.search(value))


# --------------------------------------------------------------------------
# addresses: one validator, reused. nanoaddr is vendored verbatim from
# dhyabi2/swarm-decisions and is not edited here.
# --------------------------------------------------------------------------

#: One implementation, imported rather than copied. `mint.py check` makes the
#: same promise about `expected_checksum` and reads the same function, so the
#: two surfaces cannot drift apart - which they would, silently, as two copies.
_checksum_pair = checksum_pair


def normalise_payee(raw, public_base=DEFAULT_PUBLIC_BASE):
    """Validate and normalise a payee address, or raise Refused.

    Returns the `nano_` spelling. An `xrb_` address is the same account, so it
    is normalised here - before storage and before any comparison.
    """
    if raw is None or not isinstance(raw, str) or not raw.strip():
        raise Refused(400, "payee_missing",
                      "'payee' is required and must be the Nano address you "
                      "want to be paid at, as a string.")
    verdict = nanoaddr.validate(raw)
    if verdict["valid"]:
        return verdict["normalised"]

    code = ADDRESS_ERRORS.get(verdict["reason"], "invalid_address_charset")
    if code == "invalid_address_checksum":
        carried, implied = _checksum_pair(raw)
        raise Refused(
            400, code,
            "This address is well-formed but its checksum does not match its "
            "public key, so it is not a real Nano address and a payment to it "
            "would be lost. This is almost always one mistyped character. "
            "Check it with: curl -s %s/check-address?a=<your address>"
            % public_base,
            checksum_expected=implied, checksum_found=carried)
    raise Refused(400, code, verdict["message"])


# --------------------------------------------------------------------------
# storage
# --------------------------------------------------------------------------

def read_json(path, default):
    try:
        with open(path, "rb") as handle:
            return json.loads(handle.read().decode("utf-8"))
    except FileNotFoundError:
        return json.loads(json.dumps(default))
    except (ValueError, UnicodeDecodeError) as exc:
        raise Refused(500, "store_unreadable",
                      "%s could not be parsed: %s" % (os.path.basename(path), exc))


def write_json_atomically(path, document):
    """Write through a temporary file in the same directory, then rename.

    A claim that is half-written because the process died mid-`write` is a
    claim we would not honour and the agent would not be able to prove.
    """
    body = (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    temporary = "%s.tmp.%d" % (path, os.getpid())
    with open(temporary, "wb") as handle:
        handle.write(body)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def null_publisher(claims_document, jobs_document):
    """The git mirror hook. Default: there is no mirror, so nothing happened.

    `dhyabi2/paid-work-queue` stays the permanent public record and the API is
    the front door, so a successful claim belongs in `claims.json` there too.
    The publishing path that would push it is not part of this repository yet,
    so the default does nothing and every claim it does nothing for is marked
    `reconciled: false` - visibly, on the claim object. A claim silently lost
    because a git push failed is the one outcome that is not allowed; a claim
    that stands while its mirror is behind is fine, and the API is the
    authority until reconciliation catches up.
    """
    return False


class ClaimService:
    """The whole tool: five routes over jobs.json and claims.json.

    Files are re-read per request rather than cached. They are small, and the
    git mirror can move them underneath a long-running process - a cached
    `jobs.json` is how an API starts advertising a job that was cancelled an
    hour ago.
    """

    def __init__(self, root=HERE, clock=now_utc, idgen=None, publisher=null_publisher,
                 public_base=DEFAULT_PUBLIC_BASE, rate_limit=RATE_LIMIT_CLAIMS):
        self.root = root
        self.clock = clock
        self.idgen = idgen or (lambda: "clm_" + secrets.token_hex(4))
        self.publisher = publisher
        self.public_base = public_base.rstrip("/")
        self.rate_limit = rate_limit
        self._lock = threading.Lock()
        self._recent = {}

    # ---- paths ----------------------------------------------------------

    @property
    def jobs_path(self):
        return os.path.join(self.root, JOBS_FILE)

    @property
    def claims_path(self):
        return os.path.join(self.root, CLAIMS_FILE)

    def claim_url(self, claim_id):
        return "%s/claims/%s" % (self.public_base, claim_id)

    # ---- reading --------------------------------------------------------

    def _jobs(self):
        document = read_json(self.jobs_path, {"jobs": []})
        if not isinstance(document.get("jobs"), list):
            raise Refused(500, "store_unreadable", "%s has no 'jobs' list" % JOBS_FILE)
        return document

    def _claims(self):
        document = read_json(self.claims_path, {"claims": []})
        if not isinstance(document.get("claims"), list):
            raise Refused(500, "store_unreadable", "%s has no 'claims' list" % CLAIMS_FILE)
        return document

    def _find_job(self, jobs_document, job_id):
        for job in jobs_document["jobs"]:
            if isinstance(job, dict) and job.get("id") == job_id:
                return job
        raise Refused(404, "no_such_job",
                      "There is no job %r on this queue. The open jobs are at "
                      "%s/jobs." % (job_id, self.public_base))

    def _find_claim(self, claims_document, claim_id):
        for claim in claims_document["claims"]:
            if isinstance(claim, dict) and claim.get("claim_id") == claim_id:
                return claim
        raise Refused(404, "no_such_claim",
                      "There is no claim %r." % claim_id)

    def _live_claim_for(self, claims_document, job_id, moment):
        """(claim holding `job_id`, ids expired on the way), expiring as it goes.

        The second half matters: a claim that lapses leaves the job still
        marked `claimed` in jobs.json, and a public record that says a job is
        held when its claim has expired is the exact mismatch this queue's own
        rules refuse. The caller reopens the job for every id returned here.
        """
        expired = []
        held = None
        for claim in claims_document["claims"]:
            if not isinstance(claim, dict) or claim.get("job_id") != job_id:
                continue
            if claim.get("state") not in HOLDING_STATES:
                continue
            expires = parse_rfc3339(claim.get("expires"))
            if expires is not None and moment >= expires and claim["state"] == "open":
                # Held past its window and never delivered: the job goes back
                # to the pool. Recorded as expired rather than deleted, so the
                # public record of who held what when stays complete.
                claim["state"] = "expired"
                expired.append(claim.get("claim_id"))
                continue
            if held is None:
                held = claim
        return held, expired

    def _external_hold(self, claims_document, job):
        """The job if a door other than this one holds it, else None.

        `claim.py` writes `claimed_by` and `claim_url` straight into jobs.json
        and opens a pull request; there is no claims.json entry for that claim,
        because this service never saw it. Treating such a job as free would
        hand the same work to a second agent *and* overwrite the first
        claimant's `payout_address` - two agents each believing they hold it,
        and the payment going to whichever claimed last. So a job in a claimed
        state that none of our own claim records accounts for is held, and says
        so. The pull-request door stays open precisely because this refuses.
        """
        if job.get("state") not in ("claimed", "delivered"):
            return None
        accounted = {claim.get("claim_url")
                     for claim in claims_document["claims"]
                     if isinstance(claim, dict) and claim.get("job_id") == job.get("id")}
        if job.get("claim_url") in accounted:
            return None
        return job

    # ---- money ----------------------------------------------------------

    def _price(self, job):
        """(price_xno, price_raw) exactly as jobs.json holds them.

        Carried verbatim as strings and cross-checked against each other with
        integer arithmetic. The API must never be the place where a price
        acquires a rounding error that the git record does not have.
        """
        price_xno, price_raw = job.get("price_xno"), job.get("price_raw")
        if not isinstance(price_raw, str) or not price_raw.isdigit():
            raise Refused(500, "job_malformed",
                          "job %s has a 'price_raw' of %r, which is not an "
                          "integer string" % (job.get("id"), price_raw))
        try:
            if money.xno_to_raw(price_xno) != int(price_raw):
                raise Refused(500, "job_malformed",
                              "job %s disagrees with itself: 'price_xno' %r is "
                              "%d raw, 'price_raw' says %s"
                              % (job.get("id"), price_xno,
                                 money.xno_to_raw(price_xno), price_raw))
        except ValueError as exc:
            raise Refused(500, "job_malformed",
                          "job %s has an unreadable 'price_xno' %r: %s"
                          % (job.get("id"), price_xno, exc)) from None
        return price_xno, price_raw

    # ---- rate limiting --------------------------------------------------

    def _check_rate(self, source, moment):
        """Count claim attempts per source address inside the window.

        Counted after the body and the address are known good but before the
        job's own state is consulted, so a client hammering one job is limited
        on the sixth attempt whether the job was free or not. A malformed
        request is not a claim and is not counted.
        """
        if not source:
            return
        window = RATE_LIMIT_WINDOW_SECONDS
        recent = [stamp for stamp in self._recent.get(source, ())
                  if (moment - stamp).total_seconds() < window]
        if len(recent) >= self.rate_limit:
            oldest = min(recent)
            retry_after = int(window - (moment - oldest).total_seconds()) + 1
            self._recent[source] = recent
            raise Refused(429, "rate_limited",
                          "More than %d claims from one source in %d seconds. "
                          "Wait %d seconds and try again."
                          % (self.rate_limit, window, retry_after),
                          retry_after=retry_after)
        recent.append(moment)
        self._recent[source] = recent

    # ---- claim shape ----------------------------------------------------

    def public_claim(self, claim):
        """The claim as anyone may read it. No secret has a path in here."""
        receipt = claim.get("receipt")
        return {
            "claim_id": claim.get("claim_id"),
            "job_id": claim.get("job_id"),
            "handle": claim.get("handle"),
            "payee": claim.get("payee"),
            "state": claim.get("state"),
            "claimed_at": claim.get("claimed_at"),
            "delivered_at": claim.get("delivered_at"),
            "paid_at": claim.get("paid_at"),
            "delivery_url": claim.get("delivery_url"),
            "expires": claim.get("expires"),
            "reconciled": claim.get("reconciled", False),
            # `receipt` is null until paid. When it is not null its `block` is a
            # real Nano block hash that resolves on a public explorer: the
            # citable receipt the trust wall asks for, reachable with no
            # account anywhere.
            "receipt": receipt if claim.get("state") == "paid" else None,
        }

    # ---- routes ---------------------------------------------------------

    def list_jobs(self, query):
        document = self._jobs()
        wanted = (query or {}).get("state")
        jobs = []
        for job in document["jobs"]:
            if not isinstance(job, dict):
                continue
            if wanted and job.get("state") != wanted:
                continue
            mirrored = dict(job)
            # A mirror, not a second source of truth: every field is the
            # field jobs.json holds, and `claim_href` is the only addition.
            mirrored["claim_href"] = "%s/jobs/%s/claim" % (API_ROOT, job.get("id"))
            jobs.append(mirrored)
        return 200, {
            "updated": document.get("updated"),
            "currency": document.get("currency", "XNO"),
            "source": SOURCE_REPO,
            "jobs": jobs,
        }

    def claim(self, job_id, body, source):
        moment = self.clock()
        payload = _require_object(body)
        payee = normalise_payee(payload.get("payee"), self.public_base)

        handle = payload.get("handle")
        if handle is None or (isinstance(handle, str) and not handle.strip()):
            handle = ANONYMOUS
        if not isinstance(handle, str):
            raise Refused(400, "handle_invalid", "'handle' must be a string.")
        handle = handle.strip()
        if len(handle) > HANDLE_MAX:
            raise Refused(400, "handle_too_long",
                          "'handle' is %d characters; the limit is %d."
                          % (len(handle), HANDLE_MAX))
        if not HANDLE_RE.match(handle):
            raise Refused(400, "handle_invalid",
                          "'handle' may hold letters, digits, spaces and "
                          "._-/@ only.")

        contact = payload.get("contact")
        if contact is not None and not isinstance(contact, str):
            raise Refused(400, "contact_invalid", "'contact' must be a string.")
        if isinstance(contact, str) and len(contact) > CONTACT_MAX:
            raise Refused(400, "contact_too_long",
                          "'contact' is %d characters; the limit is %d."
                          % (len(contact), CONTACT_MAX))
        for field, value in (("handle", handle), ("contact", contact)):
            if looks_like_a_key(value):
                raise Refused(400, "looks_like_a_secret",
                              "'%s' contains 64 hex characters standing alone, "
                              "which is the shape of a Nano seed or private "
                              "key. Nothing here needs one and this is not "
                              "stored." % field)

        with self._lock:
            self._check_rate(source, moment)

            claims_document = self._claims()
            jobs_document = self._jobs()
            job = self._find_job(jobs_document, job_id)

            expires_at = parse_rfc3339(job.get("expires"))
            if expires_at is not None and moment >= expires_at:
                raise Refused(410, "job_expired",
                              "Job %s expired at %s and is no longer claimable."
                              % (job_id, job.get("expires")))
            if job.get("state") not in ("open", "claimed", "delivered"):
                raise Refused(409, "job_not_claimable",
                              "Job %s is %s." % (job_id, job.get("state")))

            held, lapsed = self._live_claim_for(claims_document, job_id, moment)
            if held is not None:
                raise Refused(409, "already_claimed",
                              "Job %s is already claimed and the claim has not "
                              "expired." % job_id,
                              claimed_at=held.get("claimed_at"),
                              expires=held.get("expires"),
                              handle=held.get("handle"))
            if lapsed:
                # The job was still marked claimed by a claim that has just
                # lapsed. Reopen it before anyone reads the two files and finds
                # them disagreeing.
                self._release_job(jobs_document, job_id)

            outside = self._external_hold(claims_document, job)
            if outside is not None:
                raise Refused(409, "already_claimed",
                              "Job %s was claimed through the pull-request path "
                              "and is held by %r. Nothing here can reassign it; "
                              "the claim at %s has to be released or settled "
                              "first." % (job_id, outside.get("claimed_by"),
                                           outside.get("claim_url")),
                              claimed_at=outside.get("claimed_at"),
                              expires=outside.get("expires"),
                              handle=outside.get("claimed_by"),
                              claim_url=outside.get("claim_url"))

            price_xno, price_raw = self._price(job)
            acceptance = list(job.get("acceptance") or [])

            claim_id = self._new_claim_id(claims_document)
            claim_expires = moment + datetime.timedelta(seconds=CLAIM_TTL_SECONDS)
            claim = {
                "claim_id": claim_id,
                "job_id": job_id,
                "handle": handle,
                "payee": payee,
                "contact": contact or None,
                "state": "open",
                "claimed_at": rfc3339(moment),
                "expires": rfc3339(claim_expires),
                "delivered_at": None,
                "paid_at": None,
                "delivery_url": None,
                "note": None,
                "price_xno": price_xno,
                "price_raw": price_raw,
                "receipt": None,
                "reconciled": False,
            }
            claims_document["claims"].append(claim)
            self._attach_to_job(jobs_document, job_id, claim, "claimed")
            reconciled = self._commit(claims_document, jobs_document, claim)

        response = dict(self.public_claim(claim))
        response.update({
            "price_xno": price_xno,
            "price_raw": price_raw,
            # The definition of done arrives in the same round trip as the
            # claim. An agent that claims and then has to go and read a README
            # has been asked for a second step.
            "acceptance": acceptance,
            "reconciled": reconciled,
            "deliver": {
                "how": "POST %s/claims/%s/deliver with {\"url\": \"<public URL of your work>\"}"
                       % (API_ROOT, claim_id),
                "then": "We check it against the acceptance lines above and pay "
                        "to your payee address. You send nothing and sign nothing.",
            },
            "public_url": self.claim_url(claim_id),
        })
        return 201, response

    def deliver(self, claim_id, body):
        moment = self.clock()
        payload = _require_object(body)
        url = payload.get("url")
        if not isinstance(url, str) or not url.strip():
            raise Refused(400, "url_missing",
                          "'url' is required: a public URL where the work can "
                          "be read.")
        url = url.strip()
        if len(url) > URL_MAX:
            raise Refused(400, "url_too_long",
                          "'url' is %d characters; the limit is %d."
                          % (len(url), URL_MAX))
        if not (url.startswith("https://") or url.startswith("http://")):
            raise Refused(400, "url_not_http",
                          "'url' must be an http(s) URL that a stranger can open.")
        note = payload.get("note")
        if note is not None and not isinstance(note, str):
            raise Refused(400, "note_invalid", "'note' must be a string.")
        if isinstance(note, str) and len(note) > NOTE_MAX:
            raise Refused(400, "note_too_long",
                          "'note' is %d characters; the limit is %d."
                          % (len(note), NOTE_MAX))
        for field, value in (("url", url), ("note", note)):
            if looks_like_a_key(value):
                raise Refused(400, "looks_like_a_secret",
                              "'%s' contains 64 hex characters standing alone, "
                              "which is the shape of a seed or private key, and "
                              "is not stored." % field)

        with self._lock:
            claims_document = self._claims()
            claim = self._find_claim(claims_document, claim_id)
            if claim.get("state") not in ("open", "delivered"):
                raise Refused(409, "claim_not_open",
                              "Claim %s is %s, so it cannot be delivered against."
                              % (claim_id, claim.get("state")))
            claim["state"] = "delivered"
            claim["delivered_at"] = rfc3339(moment)
            claim["delivery_url"] = url
            claim["note"] = note or None

            # The *claim* is delivered; the job is still claimed, by this agent.
            # Moving the job to "delivered" here would make it unsettleable:
            # settle.py pays a `claimed` job and refuses any other state, so a
            # job delivered through this door could never be paid at all. The
            # delivery is recorded on the claim, publicly and with a timestamp,
            # which is where it belongs - one job lifecycle, shared by both
            # doors, and no new state for the settlement path to learn.
            jobs_document = self._jobs()
            self._attach_to_job(jobs_document, claim["job_id"], claim, "claimed")
            self._commit(claims_document, jobs_document, claim)

        # Delivery records that work was submitted, publicly and with a
        # timestamp. It does not assert acceptance and must not say payment is
        # due: a response that implies it would be us deciding our own case.
        return 200, {
            "claim_id": claim_id,
            "job_id": claim["job_id"],
            "state": "delivered",
            "delivered_at": claim["delivered_at"],
            "url": url,
            "next": "A human checks this against the acceptance lines and pays "
                    "to your payee address. Watch %s/claims/%s."
                    % (API_ROOT, claim_id),
        }

    def read_claim(self, claim_id):
        claim = self._find_claim(self._claims(), claim_id)
        return 200, self.public_claim(claim)

    def release(self, claim_id, body):
        payload = _require_object(body)
        offered = payload.get("payee")
        if not isinstance(offered, str) or not offered.strip():
            raise Refused(400, "payee_missing",
                          "Send {\"payee\": \"<the address you claimed with>\"}. "
                          "Matching it is the only credential there is.")
        with self._lock:
            claims_document = self._claims()
            claim = self._find_claim(claims_document, claim_id)
            # By account, not by spelling: an agent that claimed with `xrb_`
            # and releases with `nano_` is the same agent and the same account.
            # `same_account` refuses an unreadable address on either side, so an
            # offered address that is not one still falls through to the 403.
            if not same_account(offered, claim.get("payee")):
                raise Refused(403, "payee_mismatch",
                              "That is not the address this claim was made "
                              "with, and matching it is the only credential "
                              "there is.")
            if claim.get("state") not in ("open", "delivered"):
                raise Refused(409, "claim_not_releasable",
                              "Claim %s is %s." % (claim_id, claim.get("state")))
            claim["state"] = "released"
            jobs_document = self._jobs()
            self._release_job(jobs_document, claim["job_id"])
            self._commit(claims_document, jobs_document, claim)
        return 200, {
            "claim_id": claim_id,
            "job_id": claim["job_id"],
            "state": "released",
            "job_state": "open",
        }

    def check_address(self, query):
        candidate = (query or {}).get("a") or ""
        verdict = nanoaddr.validate(candidate)
        if verdict["valid"]:
            return 200, {
                "valid": True,
                "address": verdict["normalised"],
                "prefix_given": verdict["prefix"],
                "note": "Checksum matches. A payment to this address arrives.",
            }
        carried, implied = _checksum_pair(candidate) if candidate else (None, None)
        body = {
            "valid": False,
            "error": ADDRESS_ERRORS.get(verdict["reason"], "invalid_address_charset"),
            "reason": verdict["message"],
        }
        if verdict["reason"] == "bad_checksum":
            body["checksum_expected"] = implied
            body["checksum_found"] = carried
        return 200, body

    # ---- writing --------------------------------------------------------

    def _new_claim_id(self, claims_document):
        taken = {claim.get("claim_id") for claim in claims_document["claims"]
                 if isinstance(claim, dict)}
        for _ in range(64):
            candidate = self.idgen()
            if not CLAIM_ID_RE.match(candidate or ""):
                raise Refused(500, "bad_claim_id",
                              "generated claim id %r is not clm_ plus eight "
                              "hex characters" % candidate)
            if candidate not in taken:
                return candidate
        raise Refused(500, "claim_id_exhausted",
                      "could not generate an unused claim id")

    def _attach_to_job(self, jobs_document, job_id, claim, state):
        """Point the job at the claim, in the shape validate.py requires.

        A job in any claimed state must name its claimant and carry a
        `claim_url` string, or `validate.py` refuses the tree and the mirror
        could never be merged. The field names are `claim.py`'s, so a claim
        taken over HTTP and one taken by pull request leave the same record.
        """
        for job in jobs_document["jobs"]:
            if isinstance(job, dict) and job.get("id") == job_id:
                job["state"] = state
                job["claimed_by"] = claim["handle"]
                job["claim_url"] = self.claim_url(claim["claim_id"])
                job["claimed_at"] = claim["claimed_at"]
                job["payout_address"] = claim["payee"]
                return

    def _release_job(self, jobs_document, job_id):
        for job in jobs_document["jobs"]:
            if isinstance(job, dict) and job.get("id") == job_id:
                job["state"] = "open"
                # validate.py requires these keys to exist on every job, so
                # they go back to null rather than being deleted - the state
                # they describe is "nobody".
                job["claimed_by"] = None
                job["claim_url"] = None
                job.pop("claimed_at", None)
                job.pop("payout_address", None)
                return

    def _commit(self, claims_document, jobs_document, claim):
        """Persist, then try the mirror. The claim stands either way.

        If the mirror fails the claim is still `201`, still readable at its
        public URL, and carries `reconciled: false`. The API is the authority
        until reconciliation succeeds.
        """
        write_json_atomically(self.claims_path, claims_document)
        write_json_atomically(self.jobs_path, jobs_document)
        reconciled = False
        try:
            reconciled = bool(self.publisher(claims_document, jobs_document))
        except Exception:
            reconciled = False
        if claim.get("reconciled") != reconciled:
            claim["reconciled"] = reconciled
            write_json_atomically(self.claims_path, claims_document)
        return reconciled

    # ---- operator side --------------------------------------------------

    def mark_paid(self, claim_id, block, amount_raw, moment=None):
        """Record that a claim was paid, with the block that paid it.

        Called by the operator's settlement path, not by a caller: there is no
        HTTP route that can set this. `receipt` stays null in every other
        state, so a non-null receipt means a real block on a public ledger.
        """
        moment = moment or self.clock()
        if not re.match(r"\A[0-9a-fA-F]{64}\Z", block or ""):
            raise Refused(400, "bad_block", "a block hash is 64 hex characters")
        if not (isinstance(amount_raw, str) and amount_raw.isdigit()):
            raise Refused(400, "bad_amount",
                          "'amount_raw' must be an integer string of raw")
        with self._lock:
            claims_document = self._claims()
            claim = self._find_claim(claims_document, claim_id)
            claim["state"] = "paid"
            claim["paid_at"] = rfc3339(moment)
            claim["receipt"] = {
                "block": block.upper(),
                "amount_raw": amount_raw,
                "explorer": EXPLORER % block.upper(),
            }
            write_json_atomically(self.claims_path, claims_document)
        return self.public_claim(claim)

    # ---- dispatch -------------------------------------------------------

    def handle(self, method, path, body=b"", query=None, source=""):
        """(status, payload). The only entry point; nothing above opens a socket."""
        try:
            return self._dispatch(method, path, body, query or {}, source)
        except Refused as refusal:
            return refusal.status, refusal.payload

    def _dispatch(self, method, path, body, query, source):
        if not path.startswith(API_ROOT):
            raise Refused(404, "no_such_route", "Unknown path %r." % path)
        rest = path[len(API_ROOT):].strip("/")
        parts = [segment for segment in rest.split("/") if segment]

        if parts == ["jobs"] and method == "GET":
            return self.list_jobs(query)
        if len(parts) == 3 and parts[0] == "jobs" and parts[2] == "claim":
            if method != "POST":
                raise Refused(405, "method_not_allowed", "Use POST to claim.")
            return self.claim(parts[1], body, source)
        if len(parts) == 3 and parts[0] == "claims" and parts[2] == "deliver":
            if method != "POST":
                raise Refused(405, "method_not_allowed", "Use POST to deliver.")
            return self.deliver(parts[1], body)
        if len(parts) == 2 and parts[0] == "claims":
            if method == "GET":
                return self.read_claim(parts[1])
            if method == "DELETE":
                return self.release(parts[1], body)
            raise Refused(405, "method_not_allowed", "Use GET or DELETE.")
        if parts == ["check-address"] and method == "GET":
            return self.check_address(query)
        raise Refused(404, "no_such_route", "Unknown path %r." % path)


def _require_object(body):
    """Request bodies are JSON objects. Unknown fields are ignored, not rejected."""
    if isinstance(body, dict):
        return body
    if isinstance(body, (bytes, bytearray)):
        if not body.strip():
            return {}
        try:
            body = body.decode("utf-8")
        except UnicodeDecodeError:
            raise Refused(400, "malformed_json",
                          "the body is not valid UTF-8") from None
    if isinstance(body, str):
        if not body.strip():
            return {}
        try:
            parsed = json.loads(body)
        except ValueError as exc:
            raise Refused(400, "malformed_json",
                          "the body is not parseable JSON: %s" % exc) from None
        if not isinstance(parsed, dict):
            raise Refused(400, "malformed_json",
                          "the body must be a JSON object, got %s"
                          % type(parsed).__name__)
        return parsed
    raise Refused(400, "malformed_json", "the body must be a JSON object")


# --------------------------------------------------------------------------
# WSGI + the socket. Imported lazily so that importing this module - which is
# what the suite does - cannot open one.
# --------------------------------------------------------------------------

def wsgi_app(service):
    """A WSGI application over `service`. No socket: a WSGI app is handed one."""

    def application(environ, start_response):
        from urllib.parse import parse_qs

        method = environ.get("REQUEST_METHOD", "GET").upper()
        path = environ.get("PATH_INFO", "") or "/"
        query = {key: values[0]
                 for key, values in parse_qs(environ.get("QUERY_STRING", "")).items()}
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        body = environ["wsgi.input"].read(length) if length > 0 else b""
        source = environ.get("REMOTE_ADDR", "")

        status, payload = service.handle(method, path, body, query, source)
        rendered = (json.dumps(payload, indent=1, ensure_ascii=False) + "\n").encode("utf-8")
        headers = [("Content-Type", "application/json; charset=utf-8"),
                   ("Content-Length", str(len(rendered))),
                   ("Cache-Control", "no-store")]
        if status == 429 and "retry_after" in payload:
            headers.append(("Retry-After", str(payload["retry_after"])))
        start_response("%d %s" % (status, _REASONS.get(status, "Status")), headers)
        return [rendered]

    return application


_REASONS = {
    200: "OK", 201: "Created", 400: "Bad Request", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed", 409: "Conflict",
    410: "Gone", 429: "Too Many Requests", 500: "Internal Server Error",
}

ROUTES = (
    ("GET", API_ROOT + "/jobs", "list open paid work; ?state=open filters"),
    ("POST", API_ROOT + "/jobs/{job_id}/claim", "claim a job in one request"),
    ("POST", API_ROOT + "/claims/{claim_id}/deliver", "record delivered work"),
    ("GET", API_ROOT + "/claims/{claim_id}", "read a claim, no credential"),
    ("DELETE", API_ROOT + "/claims/{claim_id}", "release a claim you no longer want"),
    ("GET", API_ROOT + "/check-address?a=", "check a Nano address checksum"),
)


def serve(port=8080, root=HERE, public_base=DEFAULT_PUBLIC_BASE, out=sys.stdout):
    """Run the service on `port`. The only place a socket is opened."""
    from wsgiref.simple_server import make_server

    service = ClaimService(root=root, public_base=public_base)
    with make_server("", port, wsgi_app(service)) as server:
        print("paid-work-queue claim API on http://0.0.0.0:%d%s" % (port, API_ROOT),
              file=out, flush=True)
        server.serve_forever()


def main(argv=None, out=sys.stdout):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--serve", action="store_true", help="run the HTTP service")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--root", default=HERE,
                        help="directory holding jobs.json and claims.json")
    parser.add_argument("--public-base", default=DEFAULT_PUBLIC_BASE,
                        help="public URL prefix this service answers on")
    parser.add_argument("--routes", action="store_true", help="print the routes and exit")
    args = parser.parse_args(argv)

    if args.routes or not args.serve:
        for method, route, description in ROUTES:
            print("%-6s %-45s %s" % (method, route, description), file=out)
        return 0
    serve(port=args.port, root=args.root, public_base=args.public_base, out=out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
