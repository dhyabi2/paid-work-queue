#!/usr/bin/env python3
"""Claim a job on this queue in one command.

Step 2 of the README used to ask a stranger to hand-edit `jobs.json`: learn our
schema, set three fields on exactly one job, and get the Nano address right
first time. This does that edit, and refuses to write an address that fails its
checksum at all - a bad address is never stored and never paid to, so the
cheapest place to catch one is before it reaches the file.

Python 3.10+, standard library only. Nothing here opens a socket: a claim is a
local edit to a file in your own clone, and `tests/test_claim.py` fails the
build if a network import ever appears on this module's import graph.
"""

import argparse
import datetime
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor"))

import nanoaddr  # noqa: E402

RAW_PER_XNO = 10 ** 30
JOBS_FILE = "jobs.json"
HANDLE_RE = re.compile(r"\A[A-Za-z0-9._\-/@]{1,64}\Z")
SECRET_RE = re.compile(r"\A[0-9a-fA-F]{64}\Z")
RFC3339_RE = re.compile(r"\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\Z")

# Set by a claim, cleared by --release. `claimed_at` and `payout_address` are
# added by this tool; `claimed_by` and `claim_url` are part of every job object
# already, so --release returns them to null rather than deleting the keys -
# schema/job.json requires them, and the state they describe is "nobody".
ADDED_BY_CLAIM = ("claimed_at", "payout_address")
NULLED_BY_RELEASE = ("claimed_by", "claim_url")

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_NO_SUCH_JOB = 3
EXIT_WRONG_STATE = 4
EXIT_NO_FILE = 5


class Refused(Exception):
    """A refusal with the exit code the caller should end on."""

    def __init__(self, code, message):
        super().__init__(message)
        self.code = code
        self.message = message


# --------------------------------------------------------------------------
# money: integers only. 1 XNO = 10**30 raw, and a float loses the bottom 13+
# digits of that, so no float appears in this file.
# --------------------------------------------------------------------------

def format_xno(raw_text, job_id="<unknown>"):
    """Integer raw string -> exact decimal XNO, at least six decimal places.

    Six places is the rendering the queue uses. It is a minimum, not a
    rounding: an amount with a smaller unit than 10**24 raw renders in full
    rather than being truncated to a number that is not the price.
    """
    if not isinstance(raw_text, str) or not raw_text.isdigit():
        raise Refused(
            EXIT_NO_FILE,
            "%s is malformed: 'price_raw' of %s is %r, which is not an integer "
            "string - price_raw is authoritative and is never a float"
            % (JOBS_FILE, job_id, raw_text),
        )
    whole, frac = divmod(int(raw_text), RAW_PER_XNO)
    digits = str(frac).zfill(30).rstrip("0")
    if len(digits) < 6:
        digits = digits.ljust(6, "0")
    return "%d.%s" % (whole, digits)


# --------------------------------------------------------------------------
# jobs.json
# --------------------------------------------------------------------------

def read_jobs(directory="."):
    """Return (raw_bytes, document, ends_with_newline)."""
    path = os.path.join(directory, JOBS_FILE)
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
    except OSError:
        raise Refused(
            EXIT_NO_FILE,
            "%s not found - run this from a clone of dhyabi2/paid-work-queue" % JOBS_FILE,
        )
    try:
        document = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise Refused(EXIT_NO_FILE, "%s is malformed: %s" % (JOBS_FILE, exc))
    if not isinstance(document, dict) or not isinstance(document.get("jobs"), list):
        raise Refused(
            EXIT_NO_FILE,
            "%s is malformed: the top level must be an object with a 'jobs' list" % JOBS_FILE,
        )
    return raw, document, raw.endswith(b"\n")


def serialise(document, trailing_newline=True):
    text = json.dumps(document, indent=2)
    if trailing_newline:
        text += "\n"
    return text.encode("utf-8")


def write_jobs(directory, payload):
    """Write atomically, and never leave a temporary file behind."""
    final = os.path.join(directory, JOBS_FILE)
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


def find_job(document, job_id):
    for job in document["jobs"]:
        if isinstance(job, dict) and job.get("id") == job_id:
            return job
    return None


def parse_timestamp(value, field, job_id):
    match = RFC3339_RE.match(value) if isinstance(value, str) else None
    if match is None:
        raise Refused(
            EXIT_NO_FILE,
            "%s is malformed: '%s' of %s is %r, not an RFC3339 UTC timestamp"
            % (JOBS_FILE, field, job_id, value),
        )
    parts = [int(p) for p in match.groups()]
    return datetime.datetime(*parts, tzinfo=datetime.timezone.utc)


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def is_open_now(job, now):
    if job.get("state") != "open":
        return False
    return parse_timestamp(job.get("expires"), "expires", job.get("id")) > now


# --------------------------------------------------------------------------
# addresses
# --------------------------------------------------------------------------

def looks_like_a_key(value):
    """A Nano seed and a private key are both exactly 64 hex characters.

    An address is 65 characters and starts with a prefix, so nothing that
    reaches here as 64 bare hex characters is an address, and we would rather
    refuse than store it.
    """
    return bool(SECRET_RE.match(value.strip()))


def abbreviate(address):
    return address[:13] + "..." + address[-5:] if len(address) > 21 else address


def check_address(address):
    """Return nanoaddr's verdict dict. Never raises, never echoes on failure."""
    return nanoaddr.validate(address)


# --------------------------------------------------------------------------
# the four invocations
# --------------------------------------------------------------------------

def render_list(document, now):
    lines = []
    for job in document["jobs"]:
        if not isinstance(job, dict) or not is_open_now(job, now):
            continue
        lines.append((
            int(job["price_raw"]) if str(job.get("price_raw", "")).isdigit() else -1,
            "%s  %s XNO  expires %s  %s" % (
                job.get("id"),
                format_xno(job.get("price_raw"), job.get("id")),
                job.get("expires"),
                job.get("title"),
            ),
        ))
    if not lines:
        return ["no open jobs"]
    lines.sort(key=lambda pair: pair[0], reverse=True)
    return [line for _, line in lines]


def do_list(directory, out):
    _, document, _ = read_jobs(directory)
    for line in render_list(document, now_utc()):
        print(line, file=out)
    return EXIT_OK


def do_check_address(address, out):
    verdict = check_address(address)
    if verdict["valid"]:
        print("valid", file=out)
        return EXIT_OK
    # The reason is the code vendor/nanoaddr.py returns, which is the same set
    # the README and job-2026-09-26-003 publish. The address itself is never
    # printed back without the reason attached, and never on its own.
    print("invalid: %s" % verdict["reason"], file=out)
    return EXIT_USAGE


def next_steps(job_id):
    return [
        "git checkout -b claim-%s" % job_id,
        'git commit -am "claim %s"' % job_id,
        "open a pull request against dhyabi2/paid-work-queue main",
        "when it is merged, comment the public URL of your work on it",
    ]


def do_claim(directory, job_id, handle, address, claim_url, as_json, out, err):
    raw, document, newline = read_jobs(directory)
    job = find_job(document, job_id)
    if job is None:
        print("no such job: %s" % job_id, file=err)
        for line in render_list(document, now_utc()):
            print(line, file=err)
        return EXIT_NO_SUCH_JOB

    state = job.get("state")
    if state != "open":
        raise Refused(EXIT_WRONG_STATE, "job %s is %s, not open" % (job_id, state))
    expires = parse_timestamp(job.get("expires"), "expires", job_id)
    now = now_utc()
    if expires <= now:
        raise Refused(EXIT_WRONG_STATE, "job %s expired at %s" % (job_id, job.get("expires")))

    if address is None:
        raise Refused(
            EXIT_USAGE, "--address is required: we cannot pay an address we do not have")
    if handle is None or not handle.strip():
        raise Refused(EXIT_USAGE, "--handle is required")
    handle = handle.strip()
    if not HANDLE_RE.match(handle):
        raise Refused(EXIT_USAGE, "--handle must be 1-64 chars of [A-Za-z0-9._-/@]")
    if claim_url is not None and not claim_url.startswith("https://"):
        raise Refused(EXIT_USAGE, "--claim-url must be an https URL")
    if looks_like_a_key(address):
        # Deliberately says nothing about the value itself: echoing a secret to
        # a terminal or a CI log is the harm we are avoiding.
        raise Refused(
            EXIT_USAGE,
            "that looks like a private key or seed, not an address - we never want it",
        )
    verdict = check_address(address)
    if not verdict["valid"]:
        raise Refused(
            EXIT_USAGE,
            "refusing to claim: address is invalid: %s" % verdict["reason"],
        )

    # The canonical `nano_` spelling of the account the claimant gave, not the
    # spelling they happened to type. settle.py compares accounts rather than
    # strings, so a row already on disk in the `xrb_` form still settles;
    # canonicalising here stops new rows being written ambiguously at all.
    address = verdict["normalised"]
    job["state"] = "claimed"
    job["claimed_by"] = handle
    job["claimed_at"] = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    job["payout_address"] = address
    if claim_url is None:
        # Never written as null: settle.py reads the presence of claim_url as
        # "the claim was opened", and a null would answer that question wrong.
        job.pop("claim_url", None)
    else:
        job["claim_url"] = claim_url

    write_jobs(directory, serialise(document, newline))

    price = format_xno(job.get("price_raw"), job_id)
    steps = next_steps(job_id)
    if as_json:
        print(json.dumps({
            "ok": True,
            "job_id": job_id,
            "price_xno": price,
            "price_raw": job.get("price_raw"),
            "expires": job.get("expires"),
            "payout_address": address,
            "acceptance": list(job.get("acceptance") or []),
            "next": steps,
        }, indent=2), file=out)
        return EXIT_OK

    print("claimed %s for %s  (%s XNO)" % (job_id, handle, price), file=out)
    print("payout address %s  checksum ok" % abbreviate(address), file=out)
    print("", file=out)
    print("next:", file=out)
    for index, step in enumerate(steps, 1):
        print("  %d. %s" % (index, step), file=out)
    print("", file=out)
    print("acceptance for this job (every line is checked, nothing outside them is):", file=out)
    for line in job.get("acceptance") or []:
        print("  - %s" % line, file=out)
    if claim_url is None:
        print("", file=out)
        print("note: no --claim-url was given, so this claim carries no claim_url, and", file=out)
        print("      validate.py refuses a claimed job without one - CI will be red on", file=out)
        print("      the pull request until it is there. Open the pull request, then:", file=out)
        print("        python3 claim.py %s --release" % job_id, file=out)
        print("        python3 claim.py %s --handle %s --address %s --claim-url <its url>"
              % (job_id, handle, abbreviate(address)), file=out)
    return EXIT_OK


def do_release(directory, job_id, out, err):
    raw, document, newline = read_jobs(directory)
    job = find_job(document, job_id)
    if job is None:
        print("no such job: %s" % job_id, file=err)
        for line in render_list(document, now_utc()):
            print(line, file=err)
        return EXIT_NO_SUCH_JOB
    state = job.get("state")
    if state != "claimed":
        raise Refused(
            EXIT_WRONG_STATE,
            "job %s is %s, not claimed - only a claim that has not been opened "
            "can be released" % (job_id, state),
        )
    job["state"] = "open"
    for key in ADDED_BY_CLAIM:
        job.pop(key, None)
    for key in NULLED_BY_RELEASE:
        if key in job:
            job[key] = None
    write_jobs(directory, serialise(document, newline))
    print("released %s - it is open again" % job_id, file=out)
    return EXIT_OK


# --------------------------------------------------------------------------
# entry point
# --------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="claim.py",
        description="Claim one job on the XNO paid work queue. No network, no account.",
    )
    parser.add_argument("job_id", nargs="*", help="the id of the job to claim")
    parser.add_argument("--list", action="store_true",
                        help="print the jobs that are open and unexpired")
    parser.add_argument("--check-address", metavar="ADDRESS",
                        help="say whether a Nano address passes its checksum, and stop")
    parser.add_argument("--handle", help="any handle you like; it is not registered anywhere")
    parser.add_argument("--address", help="the Nano address we will pay")
    parser.add_argument("--claim-url", help="the https URL of the pull request opening the claim")
    parser.add_argument("--release", action="store_true",
                        help="undo a claim you have not opened yet")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="print the claim as JSON and nothing else")
    return parser


def main(argv=None, out=None, err=None, directory="."):
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    args = build_parser().parse_args(argv)

    try:
        if args.list:
            return do_list(directory, out)
        if args.check_address is not None:
            return do_check_address(args.check_address, out)
        if len(args.job_id) > 1:
            raise Refused(EXIT_USAGE, "one job per claim")
        if not args.job_id:
            build_parser().print_usage(err)
            print("a job id is required, or --list, or --check-address", file=err)
            return EXIT_USAGE
        job_id = args.job_id[0]
        if args.release:
            return do_release(directory, job_id, out, err)
        return do_claim(directory, job_id, args.handle, args.address,
                        args.claim_url, args.as_json, out, err)
    except Refused as refusal:
        print(refusal.message, file=err)
        return refusal.code


if __name__ == "__main__":
    sys.exit(main())
