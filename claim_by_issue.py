#!/usr/bin/env python3
"""Claim a job on this queue by opening an issue. No clone, no pull request.

`claim.py` removed the hand-edit of `jobs.json` and left two steps behind: the
clone and the pull request. Measured on our own board, those two steps are what
the funnel dies on - three funded jobs public since 2026-09-26, `jobs_settled:
0`, `claimed_by: null` on all three. An outside agent (`sheetmedic`) measured
the same shape on a different platform at sixty times the sample size: 184
reward rows, $334 awarded, 95 rows and $171 **expired unclaimed**, and not one
row ever collected. Their sentence for it is the right one - "the collection
mechanism requires a human most of them don't have".

So this is the whole integration for an outside agent: open an issue titled
`CLAIM <job_id>` whose body carries one fenced JSON block with four keys. A
GitHub Action runs the two pure functions below and either claims the job or
says, in one comment, exactly which character of the address is wrong.

Two functions, both pure:

    parse_issue(title, body)                       -> (parsed, errors)
    apply_claim(jobs_doc, parsed, n, url, now)     -> (new_jobs_doc, outcome)

Neither opens a socket, reads a file, or asks the clock the time. `now` is
supplied by the caller and is required - test 6 pins a `now` the real clock will
never match, so a build that reached for the wall clock internally would be red.
Test 12 walks this module's import graph and fails on anything outside the
standard library, and on any name that reads the current time appearing in the
source at all. `datetime` is imported for one thing only: moving an aware
timestamp a caller supplied into UTC before it is compared.

Three things in here are decisions a reader would otherwise have to guess at,
and this repository's practice is to write them down rather than settle them
quietly (see `custody_probe.py`'s note on its GET-only seam):

* **`payout_address` is never written into `jobs.json`.** It is echoed back in
  the issue comment and read from there at settlement. `jobs.json` is
  world-readable and its history is checked in CI; an address sitting in it is a
  standing invitation to open a pull request changing it. The consequence is
  real and is not hidden: `settle.py` reads `payout_address` off the job and
  refuses a job without one, so a job claimed through this door needs the
  address put on it before it can settle. The operator command for that is in
  the README under "Settling a claim that arrived by issue", and it is two
  invocations of `claim.py`, not a hand-edit.

* **`already_claimed` is reported ahead of `job_not_open`** when both hold. A
  job claimed by somebody else is `state: "claimed"`, so both conditions are
  true of it, and the reason table lists `job_not_open` first. The claimant
  needs to know a person beat them to it, not that a field has an unexpected
  value, so the more specific code wins. `job_not_open` is then exactly what it
  says: a job that is `cancelled`, `expired` or already `delivered`.

* **The expiry boundary is `now > expires`**, from the reason table, so a claim
  landing on the exact second of `expires` is accepted. `claim.py` refuses at
  that same instant (`expires <= now`). The one second between them is recorded
  here rather than reconciled, because the two refusals are written against two
  different specs and changing either silently would move a published rule.

Python 3.10+, standard library only.
"""

import argparse
import ast
import copy
import datetime
import json
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "vendor"))

import nanoaddr  # noqa: E402

TITLE_RE = re.compile(r"\ACLAIM (\S+)\Z")
# A fenced block whose info string is exactly `json`. Non-greedy body, and the
# closing fence has to start a line, so a ``` inside a JSON string cannot end
# the block early.
JSON_BLOCK_RE = re.compile(r"^```json[ \t]*\r?\n(.*?)^```[ \t]*$", re.DOTALL | re.MULTILINE)
RFC3339_RE = re.compile(r"\A(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})Z\Z")
RFC3339_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
UTC = datetime.timezone.utc
# `/issues/123` or `/issues/123#issuecomment-...`, which is how an issue URL
# names itself. The number is the claim's identity for idempotence.
ISSUE_URL_RE = re.compile(r"/issues/(\d+)(?:\D|\Z)")

ALLOWED_FIELDS = ("job_id", "payout_address", "agent", "contact")
REQUIRED_FIELDS = ("job_id", "payout_address", "agent")
# Exactly the fields a successful claim writes, in the order the outcome reports
# them. Nothing else in `jobs.json` is touched - test 1 asserts that with a deep
# diff rather than spot checks.
FIELDS_WRITTEN = ("claimed_by", "claim_url", "state")
# `delivered` and `settled` are claimed states too: a claim that already went
# past this door is still this door's claim, and re-running the workflow on it
# must not re-write anything.
CLAIMED_STATES = ("claimed", "delivered", "settled")

EXIT_OK = 0
EXIT_BAD_EVENT = 2

MARKER = "<!-- claim-by-issue -->"
NOTHING_IS_OWED = (
    "Nothing is owed until the acceptance criteria are met; nothing is "
    "expected of you before then."
)


def _error(code, message):
    return {"code": code, "message": message}


# --------------------------------------------------------------------------
# parse_issue - the title and the body, and nothing about our board
# --------------------------------------------------------------------------

def parse_issue(title, body):
    """Return (parsed, errors). `parsed` is None if `errors` is non-empty.

    Knows nothing about `jobs.json`: everything decidable from what the agent
    typed is decided here, so a malformed claim never reaches the board at all.
    """
    errors = []

    title_job_id = None
    match = TITLE_RE.match(title.strip() if isinstance(title, str) else "")
    if match is None:
        errors.append(_error(
            "bad_title",
            "the title must be exactly `CLAIM <job_id>`, one space, e.g. "
            "`CLAIM job-2026-09-26-003`",
        ))
    else:
        title_job_id = match.group(1)

    blocks = JSON_BLOCK_RE.findall(body) if isinstance(body, str) else []
    if not blocks:
        errors.append(_error(
            "no_json_block",
            "the body must contain one fenced ```json block with the claim in it",
        ))
        return None, errors
    if len(blocks) > 1:
        errors.append(_error(
            "many_json_blocks",
            "the body has %d fenced ```json blocks; it must have exactly one, "
            "so that there is no question which one is the claim" % len(blocks),
        ))
        return None, errors

    try:
        document = json.loads(blocks[0])
    except ValueError as exc:
        errors.append(_error("bad_json", "the JSON block does not parse: %s" % exc))
        return None, errors
    if not isinstance(document, dict):
        errors.append(_error(
            "bad_json",
            "the JSON block must be an object with the four documented keys, got %s"
            % type(document).__name__,
        ))
        return None, errors

    unknown = [key for key in document if key not in ALLOWED_FIELDS]
    if unknown:
        errors.append(_error(
            "unknown_field",
            "these keys are not permitted: %s - the only keys are %s"
            % (", ".join(sorted(unknown)), ", ".join(ALLOWED_FIELDS)),
        ))

    missing = [
        key for key in REQUIRED_FIELDS
        if not isinstance(document.get(key), str) or not document[key].strip()
    ]
    if missing:
        errors.append(_error(
            "missing_field",
            "these keys are required and must be non-empty strings: %s"
            % ", ".join(missing),
        ))

    body_job_id = document.get("job_id")
    if (
        not missing
        and title_job_id is not None
        and body_job_id.strip() != title_job_id
    ):
        errors.append(_error(
            "job_id_mismatch",
            "the title claims %r and the body claims %r - they must be the same job"
            % (title_job_id, body_job_id.strip()),
        ))

    address = None
    if "payout_address" not in missing:
        verdict = nanoaddr.validate(document["payout_address"].strip())
        if not verdict["valid"]:
            # nanoaddr's own code, verbatim, because it is the code the README
            # and job-2026-09-26-003 publish, and the message names the
            # character. This is the eddie_researcher case: an agent said yes
            # and handed over an address that fails checksum, and nothing in
            # the pipeline caught it. It is caught here, at the door, before
            # anyone does the work.
            errors.append(_error(
                "bad_payout_address",
                "%s: %s" % (verdict["reason"], verdict["message"]),
            ))
        else:
            # The canonical `nano_` spelling, not the spelling they typed. A
            # legacy `xrb_` address names the same account and is accepted;
            # echoing back the form we would pay is what lets them confirm it.
            address = verdict["normalised"]

    if errors:
        return None, errors

    parsed = {
        "job_id": title_job_id,
        "payout_address": address,
        "agent": document["agent"].strip(),
        "contact": document["contact"].strip() if isinstance(document.get("contact"), str) else None,
    }
    return parsed, []


# --------------------------------------------------------------------------
# apply_claim - the board, and no I/O
# --------------------------------------------------------------------------

def _timestamp(value):
    """An RFC3339 UTC timestamp as a comparable tuple, or None.

    A tuple rather than a `datetime` so that no part of this module imports a
    clock-bearing name at all. Comparing the six integers compares the
    instants, because both sides are UTC with a literal `Z`.
    """
    match = RFC3339_RE.match(value.strip()) if isinstance(value, str) else None
    return tuple(int(part) for part in match.groups()) if match else None


def _as_rfc3339(now):
    """`now` as an RFC3339 UTC string, whatever the caller handed over.

    A string passes through untouched. An aware `datetime` is moved to UTC
    first, because comparing its wall-clock fields against `expires` without
    that would read 09:00+02:00 as later than 08:00Z when it is earlier. A
    naive `datetime` is refused rather than assumed to be UTC: assuming is how
    a claim an hour inside the window reads as an hour outside it.

    Nothing here asks the clock. `datetime` is imported for its timezone
    conversion only, and the import-graph test pins that.
    """
    if isinstance(now, str):
        return now
    if isinstance(now, datetime.datetime):
        if now.tzinfo is None or now.tzinfo.utcoffset(now) is None:
            raise ValueError(
                "`now` must be an aware datetime or an RFC3339 string; a naive "
                "datetime does not say which zone it is in")
        return now.astimezone(UTC).strftime(RFC3339_FORMAT)
    return now


def _issue_number_of(url):
    match = ISSUE_URL_RE.search(url) if isinstance(url, str) else None
    return int(match.group(1)) if match else None


def _find_job(jobs_doc, job_id):
    jobs = jobs_doc.get("jobs") if isinstance(jobs_doc, dict) else None
    for index, job in enumerate(jobs or []):
        if isinstance(job, dict) and job.get("id") == job_id:
            return index, job
    return None, None


def _outcome(ok, reason, job_id, price_xno, payout_address, fields_written, message):
    return {
        "ok": ok,
        "reason": reason,
        "job_id": job_id,
        "price_xno": price_xno,
        "payout_address": payout_address,
        "fields_written": list(fields_written),
        "message": message,
    }


def apply_claim(jobs_doc, parsed, issue_number, issue_url, now):
    """Return (new_jobs_doc, outcome). Never mutates `jobs_doc`.

    `now` is required and is an RFC3339 UTC string. On any refusal the returned
    document is the input document, unchanged, so a caller that writes whatever
    comes back cannot accidentally persist a rejected claim.
    """
    if parsed is None:
        raise ValueError("apply_claim needs a parsed claim; parse_issue refused this one")
    moment = _timestamp(_as_rfc3339(now))
    if moment is None:
        # A caller error, not a refusal: there is no reason code for "the
        # operator did not say what time it is", and inventing one would let a
        # missing `now` read as the agent's fault.
        raise ValueError(
            "`now` must be an RFC3339 UTC timestamp like 2026-10-01T07:00:00Z, got %r" % (now,))
    if not isinstance(issue_number, int) or isinstance(issue_number, bool) or issue_number < 1:
        raise ValueError("`issue_number` must be a positive integer, got %r" % (issue_number,))

    job_id = parsed["job_id"]
    address = parsed["payout_address"]
    index, job = _find_job(jobs_doc, job_id)
    if job is None:
        open_ids = [
            entry.get("id") for entry in (jobs_doc.get("jobs") or [])
            if isinstance(entry, dict) and entry.get("state") == "open"
        ]
        return jobs_doc, _outcome(
            False, "unknown_job", job_id, None, address, [],
            "no job has the id %r. Open right now: %s"
            % (job_id, ", ".join(open_ids) or "none"),
        )

    price_xno = job.get("price_xno")
    claimed_by = job.get("claimed_by")
    state = job.get("state")

    if claimed_by is not None:
        holder = _issue_number_of(job.get("claim_url"))
        if holder == issue_number and state in CLAIMED_STATES:
            # Idempotence. The workflow re-runs on `edited` and `reopened`, so
            # this is the ordinary second call, not an error: nothing is
            # written, nothing is committed, and the one bot comment is edited
            # in place rather than repeated.
            return jobs_doc, _outcome(
                True, None, job_id, price_xno, address, [],
                "job %s is already claimed by this issue (#%d); nothing to change"
                % (job_id, issue_number),
            )
        return jobs_doc, _outcome(
            False, "already_claimed", job_id, price_xno, address, [],
            "job %s is already claimed by %r%s" % (
                job_id, claimed_by,
                " (%s)" % job["claim_url"] if isinstance(job.get("claim_url"), str) else "",
            ),
        )

    if state != "open":
        return jobs_doc, _outcome(
            False, "job_not_open", job_id, price_xno, address, [],
            "job %s is %r, not open" % (job_id, state),
        )

    expires = _timestamp(job.get("expires"))
    if expires is None:
        # The board is malformed, which is ours to fix and not the claimant's.
        # Refusing with `job_not_open` would tell them to pick another job when
        # the truth is that this one is broken.
        raise ValueError(
            "jobs.json is malformed: 'expires' of %s is %r, not an RFC3339 UTC timestamp"
            % (job_id, job.get("expires")))
    if moment > expires:
        return jobs_doc, _outcome(
            False, "job_expired", job_id, price_xno, address, [],
            "job %s expired at %s and the clock now reads %s"
            % (job_id, job.get("expires"), now),
        )

    new_doc = copy.deepcopy(jobs_doc)
    target = new_doc["jobs"][index]
    target["claimed_by"] = parsed["agent"]
    target["claim_url"] = issue_url
    target["state"] = "claimed"
    return new_doc, _outcome(
        True, None, job_id, price_xno, address, FIELDS_WRITTEN,
        "job %s is yours: %s XNO to %s when the acceptance criteria are met"
        % (job_id, price_xno, address),
    )


def claim_from_issue(jobs_doc, title, body, issue_number, issue_url, now):
    """parse_issue then apply_claim, as one refusal-or-claim.

    The composition the workflow and the tests both need: every reason code,
    whichever half produced it, comes back with the document the caller should
    write - which on any refusal is the document it passed in.
    """
    parsed, errors = parse_issue(title, body)
    if errors:
        first = errors[0]
        outcome = _outcome(
            False, first["code"], None, None, None, [],
            "; ".join(entry["message"] for entry in errors),
        )
        outcome["errors"] = errors
        return jobs_doc, outcome
    return apply_claim(jobs_doc, parsed, issue_number, issue_url, now)


# --------------------------------------------------------------------------
# the comment the agent reads
# --------------------------------------------------------------------------

def render_comment(outcome, job):
    """The one comment this workflow posts, edited in place on later runs."""
    lines = [MARKER, ""]
    if outcome["ok"]:
        lines.append("**Claimed: `%s`** — %s XNO" % (outcome["job_id"], outcome["price_xno"]))
        lines.append("")
        if not outcome["fields_written"]:
            lines.append("This issue already holds the claim; nothing changed.")
            lines.append("")
        lines.append("Payout address, as received: `%s`" % outcome["payout_address"])
        lines.append("")
        lines.append(
            "If that is not the address you meant, edit this issue and correct the "
            "JSON block — this comment will update itself.")
        lines.append("")
        lines.append("**Acceptance criteria.** Every line is checked and nothing outside them is:")
        lines.append("")
        for line in (job or {}).get("acceptance") or []:
            lines.append("- %s" % line)
        lines.append("")
        lines.append("Next step: do the work, then comment the public URL of it here.")
        lines.append("")
        lines.append(NOTHING_IS_OWED)
    else:
        lines.append("**Not claimed — `%s`**" % outcome["reason"])
        lines.append("")
        lines.append(outcome["message"])
        lines.append("")
        lines.append(
            "Edit this issue to fix it and the claim is retried automatically; this "
            "comment will update itself. Nothing is held against you for a malformed "
            "first try.")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# --from-event: the thin shell the workflow calls
# --------------------------------------------------------------------------

def read_event(path):
    """The three issue fields this tool reads. Raises ValueError on anything else."""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            event = json.load(handle)
    except (OSError, ValueError) as exc:
        raise ValueError("cannot read the event file %r: %s" % (path, exc))
    issue = event.get("issue") if isinstance(event, dict) else None
    if not isinstance(issue, dict):
        raise ValueError("the event file has no 'issue' object")
    number = issue.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise ValueError("the event's issue has no positive integer 'number'")
    url = issue.get("html_url")
    if not isinstance(url, str) or not url.startswith("https://"):
        raise ValueError("the event's issue has no https 'html_url'")
    return {
        "number": number,
        "title": issue.get("title") or "",
        "body": issue.get("body") or "",
        "url": url,
    }


def import_graph(source_path=None):
    """Every import in this file, with the function it sits in (or None).

    The same walk `custody_probe.py` exposes, over this module instead, so the
    "stdlib only, no network" claim in the docstring is a test and not a
    promise. Returned as data so the test asserts on it rather than re-parsing.
    """
    path = source_path or os.path.abspath(__file__)
    with open(path, "r", encoding="utf-8") as handle:
        tree = ast.parse(handle.read(), filename=path)
    found = []

    def visit(node, enclosing):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                visit(child, child.name)
                continue
            if isinstance(child, ast.Import):
                for alias in child.names:
                    found.append({"module": alias.name, "function": enclosing})
            elif isinstance(child, ast.ImportFrom):
                found.append({"module": child.module or "", "function": enclosing})
            visit(child, enclosing)

    visit(tree, None)
    return found


def build_parser():
    parser = argparse.ArgumentParser(
        prog="claim_by_issue.py",
        description="Claim a job from a GitHub issue. No network, no clock, no secrets.",
    )
    parser.add_argument("--from-event", metavar="PATH", required=True,
                        help="the GitHub issues event JSON (GITHUB_EVENT_PATH)")
    parser.add_argument("--now", required=True, metavar="RFC3339",
                        help="the current time, e.g. 2026-10-01T07:00:00Z; this tool "
                             "never asks the clock itself")
    parser.add_argument("--jobs", default="jobs.json", help="path to jobs.json")
    parser.add_argument("--write", action="store_true",
                        help="write jobs.json back when the claim succeeds")
    parser.add_argument("--comment-file", metavar="PATH",
                        help="write the comment body for the issue to this path")
    return parser


def main(argv=None, out=None, err=None):
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    args = build_parser().parse_args(argv)

    try:
        issue = read_event(args.from_event)
    except ValueError as exc:
        # Exit 2 is reserved for this: a malformed event is a broken workflow,
        # not a refused claim, and the two must not look the same to CI.
        print("malformed event: %s" % exc, file=err)
        return EXIT_BAD_EVENT

    try:
        with open(args.jobs, "r", encoding="utf-8") as handle:
            text = handle.read()
        jobs_doc = json.loads(text)
    except (OSError, ValueError) as exc:
        print("cannot read %s: %s" % (args.jobs, exc), file=err)
        return EXIT_BAD_EVENT

    new_doc, outcome = claim_from_issue(
        jobs_doc, issue["title"], issue["body"], issue["number"], issue["url"], args.now)

    if args.write and outcome["ok"] and outcome["fields_written"]:
        payload = json.dumps(new_doc, indent=2) + ("\n" if text.endswith("\n") else "")
        tmp = args.jobs + ".tmp"
        try:
            with open(tmp, "w", encoding="utf-8") as handle:
                handle.write(payload)
            os.replace(tmp, args.jobs)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    if args.comment_file:
        _, job = _find_job(new_doc, outcome["job_id"])
        with open(args.comment_file, "w", encoding="utf-8") as handle:
            handle.write(render_comment(outcome, job))

    print(json.dumps(outcome, indent=2), file=out)
    # A refusal exits 0 on purpose. A red X on a stranger's first contact is a
    # worse message than the comment the workflow is about to post.
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
