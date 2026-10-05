"""The suite for claim_by_issue.py. Every test is numbered after the spec line it pins.

Hermetic throughout: no network, no GitHub, no clock. Test 12 fails the build if
claim_by_issue.py ever grows an import that could reach a socket, or reaches for
the real time. Nothing here contains a 64-character hex literal - validate.py's
secret gate refuses one anywhere in the tree, and it is right to.
"""

import copy
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
sys.path.insert(0, os.path.join(ROOT, "vendor"))

import claim_by_issue  # noqa: E402
import nanoaddr  # noqa: E402
from claim_by_issue import (  # noqa: E402
    ALLOWED_FIELDS, FIELDS_WRITTEN, MARKER, NOTHING_IS_OWED, apply_claim,
    claim_from_issue, import_graph, main, parse_issue, render_comment,
)

SELLER = "nano_11131a3ia3a81w61k4id3i8iw5ri46b3871o4rdji8at5eg3t9izij86w3hz"
GENESIS = "nano_3t6k35gi95xu6tergt6p69ck76ogmitsa8mnijtpxm9fkcm736xtoncuohr3"
BURN = "nano_1111111111111111111111111111111111111111111111111111hifc8npp"

JOB = "job-2026-09-26-003"
EXPIRES = "2026-10-03T07:00:00Z"
BEFORE = "2026-10-03T06:59:59Z"
AT = "2026-10-03T07:00:00Z"
AFTER = "2026-10-03T07:00:01Z"
URL = "https://github.com/dhyabi2/paid-work-queue/issues/41"
XNO = 10 ** 30


def job(job_id=JOB, price_xno="0.05", price_raw=str(5 * XNO // 100),
        state="open", expires=EXPIRES, **over):
    """A job object in the exact shape and key order jobs.json uses."""
    body = {
        "id": job_id,
        "title": "job %s" % job_id,
        "description": "do the thing for %s and publish it" % job_id,
        "acceptance": ["the first checkable line", "the second checkable line"],
        "price_xno": price_xno,
        "price_raw": price_raw,
        "posted": "2026-09-26T07:00:00Z",
        "expires": expires,
        "state": state,
        "claimed_by": None,
        "claim_url": None,
        "receipt_id": None,
    }
    body.update(over)
    return body


def doc(*jobs):
    return {
        "updated": "2026-09-26T07:00:00Z",
        "currency": "XNO",
        "jobs": list(jobs) or [job()],
    }


def body_for(job_id=JOB, address=SELLER, agent="some-agent-name",
             contact="https://github.com/some-agent-name", extra=None, prose=True):
    payload = {"job_id": job_id, "payout_address": address, "agent": agent}
    if contact is not None:
        payload["contact"] = contact
    if extra:
        payload.update(extra)
    block = "```json\n%s\n```" % json.dumps(payload, indent=2)
    if not prose:
        return block
    return "I would like this job.\n\n%s\n\n— sent by an agent\n" % block


def title_for(job_id=JOB):
    return "CLAIM %s" % job_id


def claim(jobs_doc=None, title=None, body=None, number=41, url=URL, now=BEFORE):
    jobs_doc = doc() if jobs_doc is None else jobs_doc
    return claim_from_issue(
        jobs_doc,
        title_for() if title is None else title,
        body_for() if body is None else body,
        number, url, now,
    )


def deep_diff(before, after, path="jobs.json"):
    """Every leaf path whose value differs, as `path -> (old, new)` pairs."""
    out = {}
    if isinstance(before, dict) and isinstance(after, dict):
        for key in sorted(set(before) | set(after)):
            out.update(deep_diff(before.get(key, KeyError), after.get(key, KeyError),
                                 "%s.%s" % (path, key)))
    elif isinstance(before, list) and isinstance(after, list) and len(before) == len(after):
        for index, (left, right) in enumerate(zip(before, after)):
            out.update(deep_diff(left, right, "%s[%d]" % (path, index)))
    elif before != after:
        out[path] = (before, after)
    return out


def canonical(document):
    return json.dumps(document, indent=2, sort_keys=True)


class ParseAndApply(unittest.TestCase):

    # 1 -------------------------------------------------------------------
    def test_01_happy_path_changes_exactly_three_fields_on_exactly_one_job(self):
        before = doc(job("job-a"), job(JOB), job("job-c"))
        pristine = copy.deepcopy(before)
        after, outcome = claim(before)
        self.assertTrue(outcome["ok"], outcome)
        self.assertIsNone(outcome["reason"])
        self.assertEqual(outcome["job_id"], JOB)
        self.assertEqual(outcome["price_xno"], "0.05")
        self.assertEqual(outcome["payout_address"], SELLER)
        self.assertEqual(outcome["fields_written"], list(FIELDS_WRITTEN))

        self.assertEqual(
            deep_diff(pristine, after),
            {
                "jobs.json.jobs[1].claimed_by": (None, "some-agent-name"),
                "jobs.json.jobs[1].claim_url": (None, URL),
                "jobs.json.jobs[1].state": ("open", "claimed"),
            },
        )

    # 2 -------------------------------------------------------------------
    def test_02_input_document_is_not_mutated(self):
        before = doc(job(JOB))
        pristine = copy.deepcopy(before)
        after, outcome = claim(before)
        self.assertTrue(outcome["ok"])
        self.assertEqual(before, pristine)
        self.assertIsNot(after, before)
        self.assertIsNot(after["jobs"][0], before["jobs"][0])

    # 3 -------------------------------------------------------------------
    def test_03_one_negative_control_per_reason_code(self):
        long_tail = "a" * 70
        cases = {
            "bad_title": dict(title="CLAIM  %s" % JOB),
            "no_json_block": dict(body="here is my claim: %s on %s" % (SELLER, JOB)),
            "many_json_blocks": dict(body="%s\n\n%s" % (body_for(prose=False),
                                                        body_for(prose=False))),
            "bad_json": dict(body="```json\n{\"job_id\": \"%s\",}\n```" % JOB),
            "missing_field": dict(body=body_for(agent="   ")),
            "unknown_field": dict(body=body_for(extra={"price_xno": "9.99"})),
            "job_id_mismatch": dict(body=body_for(job_id="job-2026-09-26-001")),
            "bad_payout_address": dict(body=body_for(address=SELLER[:-1] + "1")),
            "unknown_job": dict(title=title_for("job-nope"), body=body_for("job-nope")),
            "job_not_open": dict(jobs_doc=doc(job(JOB, state="cancelled"))),
            "already_claimed": dict(jobs_doc=doc(job(
                JOB, state="claimed", claimed_by="someone-else",
                claim_url="https://github.com/dhyabi2/paid-work-queue/issues/7"))),
            "job_expired": dict(now=AFTER),
        }
        self.assertEqual(len(cases), 12)
        for code, overrides in cases.items():
            with self.subTest(reason=code):
                jobs_doc = overrides.pop("jobs_doc", None) or doc(job(JOB))
                frozen = canonical(jobs_doc)
                after, outcome = claim(jobs_doc, **overrides)
                self.assertFalse(outcome["ok"], outcome)
                self.assertEqual(outcome["reason"], code)
                self.assertEqual(outcome["fields_written"], [])
                self.assertEqual(canonical(after), frozen)
                self.assertEqual(canonical(jobs_doc), frozen)
                self.assertTrue(outcome["message"].strip())
        self.assertNotIn(long_tail, canonical(doc()))

    # 4 -------------------------------------------------------------------
    def test_04_bad_checksum_by_character_and_every_nanoaddr_reason(self):
        # The eddie_researcher test: an agent said yes and handed over an
        # address that fails checksum, and nothing downstream caught it.
        altered = SELLER[:-1] + ("3" if SELLER[-1] != "3" else "1")
        cases = {
            "bad_checksum": altered,
            "bad_prefix": "nanp_" + SELLER[5:],
            "bad_length": SELLER[:-1],
            # Position 5 is the padding character, so an illegal value there
            # is reported as bad_padding; the bad_character case has to sit
            # further in, where any alphabet member is structurally allowed.
            "bad_character": SELLER[:10] + "0" + SELLER[11:],
            "bad_padding": SELLER[:5] + "4" + SELLER[6:],
        }
        for reason, address in cases.items():
            with self.subTest(reason=reason):
                self.assertEqual(nanoaddr.validate(address)["reason"], reason)
                parsed, errors = parse_issue(title_for(), body_for(address=address))
                self.assertIsNone(parsed)
                self.assertEqual([e["code"] for e in errors], ["bad_payout_address"])
                # nanoaddr's own code, verbatim, inside the message.
                self.assertTrue(errors[0]["message"].startswith(reason + ": "))

    # 5 -------------------------------------------------------------------
    def test_05_xrb_is_accepted_and_canonicalised(self):
        legacy = "xrb_" + SELLER[len("nano_"):]
        self.assertTrue(nanoaddr.validate(legacy)["valid"])
        parsed, errors = parse_issue(title_for(), body_for(address=legacy))
        self.assertEqual(errors, [])
        self.assertEqual(parsed["payout_address"], SELLER)
        _, outcome = claim(body=body_for(address=legacy))
        self.assertTrue(outcome["ok"])
        self.assertEqual(outcome["payout_address"], SELLER)
        self.assertNotIn("xrb_", json.dumps(outcome))

    # 6 -------------------------------------------------------------------
    def test_06_expiry_uses_the_supplied_now_not_the_real_clock(self):
        _, ok = claim(now=BEFORE)
        self.assertTrue(ok["ok"], ok)
        _, boundary = claim(now=AT)
        self.assertTrue(boundary["ok"], boundary)
        _, late = claim(now=AFTER)
        self.assertFalse(late["ok"])
        self.assertEqual(late["reason"], "job_expired")
        # A `now` the real clock will never match, in either direction.
        _, ancient = claim(now="2001-01-01T00:00:00Z")
        self.assertTrue(ancient["ok"], ancient)
        _, distant = claim(now="2099-01-01T00:00:00Z")
        self.assertEqual(distant["reason"], "job_expired")

    def test_06b_now_is_required_and_an_aware_datetime_is_moved_to_utc(self):
        import datetime as dt
        parsed, errors = parse_issue(title_for(), body_for())
        self.assertEqual(errors, [])
        for bad in (None, "", "not a time", "2026-10-03 07:00:00", 1759300000):
            with self.subTest(now=bad):
                with self.assertRaises(ValueError):
                    apply_claim(doc(), parsed, 41, URL, bad)
        with self.assertRaises(ValueError):
            apply_claim(doc(), parsed, 41, URL, dt.datetime(2026, 10, 3, 6, 0, 0))
        plus_two = dt.timezone(dt.timedelta(hours=2))
        # 08:59:59+02:00 is 06:59:59Z, inside the window.
        _, inside = apply_claim(
            doc(), parsed, 41, URL, dt.datetime(2026, 10, 3, 8, 59, 59, tzinfo=plus_two))
        self.assertTrue(inside["ok"], inside)
        # 09:00:01+02:00 is 07:00:01Z, outside it.
        _, outside = apply_claim(
            doc(), parsed, 41, URL, dt.datetime(2026, 10, 3, 9, 0, 1, tzinfo=plus_two))
        self.assertEqual(outside["reason"], "job_expired")
        with self.assertRaises(ValueError):
            apply_claim(doc(), None, 41, URL, BEFORE)
        for bad_number in (0, -1, "41", 41.0, True, None):
            with self.subTest(number=bad_number):
                with self.assertRaises(ValueError):
                    apply_claim(doc(), parsed, bad_number, URL, BEFORE)

    # 7 -------------------------------------------------------------------
    def test_07_idempotence_from_the_same_issue_and_refusal_from_another(self):
        first_doc, first = claim(doc(job(JOB)))
        self.assertTrue(first["ok"])
        second_doc, second = claim(first_doc)
        self.assertTrue(second["ok"], second)
        self.assertEqual(second["fields_written"], [])
        self.assertEqual(canonical(second_doc), canonical(first_doc))
        self.assertEqual(second["payout_address"], SELLER)
        self.assertEqual(second["price_xno"], "0.05")

        other_url = "https://github.com/dhyabi2/paid-work-queue/issues/99"
        third_doc, third = claim_from_issue(
            first_doc, title_for(), body_for(), 99, other_url, BEFORE)
        self.assertFalse(third["ok"])
        self.assertEqual(third["reason"], "already_claimed")
        self.assertEqual(canonical(third_doc), canonical(first_doc))

        # Still this issue's claim once the work is delivered or settled.
        for state in ("delivered", "settled"):
            with self.subTest(state=state):
                moved = copy.deepcopy(first_doc)
                moved["jobs"][0]["state"] = state
                if state == "settled":
                    moved["jobs"][0]["receipt_id"] = "receipt-1"
                _, again = claim(moved)
                self.assertTrue(again["ok"], again)
                self.assertEqual(again["fields_written"], [])

        # A claim.py claim carries no issue number, so it is somebody else's.
        hand = doc(job(JOB, state="claimed", claimed_by="a-handle",
                       claim_url="https://github.com/dhyabi2/paid-work-queue/pull/12"))
        _, outcome = claim(hand)
        self.assertEqual(outcome["reason"], "already_claimed")

    # 8 -------------------------------------------------------------------
    def test_08_two_json_blocks_is_a_refusal_not_a_guess(self):
        mine = body_for(prose=False)
        theirs = body_for(job_id="job-2026-09-26-001", address=GENESIS, prose=False)
        parsed, errors = parse_issue(title_for(), "%s\n\n%s" % (mine, theirs))
        self.assertIsNone(parsed)
        self.assertEqual([e["code"] for e in errors], ["many_json_blocks"])
        self.assertIn("2", errors[0]["message"])

    # 9 -------------------------------------------------------------------
    def test_09_the_fence_is_found_inside_prose_and_an_unfenced_object_is_not(self):
        parsed, errors = parse_issue(title_for(), body_for(prose=True))
        self.assertEqual(errors, [])
        self.assertEqual(parsed["job_id"], JOB)
        self.assertEqual(parsed["agent"], "some-agent-name")
        self.assertEqual(parsed["contact"], "https://github.com/some-agent-name")

        bare = 'Hello.\n\n{"job_id": "%s", "payout_address": "%s", "agent": "a"}\n' % (JOB, SELLER)
        parsed, errors = parse_issue(title_for(), bare)
        self.assertIsNone(parsed)
        self.assertEqual([e["code"] for e in errors], ["no_json_block"])

        # A bare ``` fence with no info string is not a json block either.
        untagged = "```\n%s\n```" % json.dumps({"job_id": JOB})
        self.assertEqual([e["code"] for e in parse_issue(title_for(), untagged)[1]],
                         ["no_json_block"])

        # A ``` sequence inside a JSON string does not close the block early.
        tricky = '```json\n{"job_id": "%s", "payout_address": "%s", "agent": "x ``` y"}\n```' % (
            JOB, SELLER)
        parsed, errors = parse_issue(title_for(), tricky)
        self.assertEqual(errors, [])
        self.assertEqual(parsed["agent"], "x ``` y")

        # contact is optional; the other three are not.
        parsed, errors = parse_issue(title_for(), body_for(contact=None))
        self.assertEqual(errors, [])
        self.assertIsNone(parsed["contact"])

    def test_09b_bad_title_shapes(self):
        for bad in ("CLAIM", "CLAIM ", "claim %s" % JOB, "CLAIM %s please" % JOB,
                    " CLAIM  %s" % JOB, "Claim: %s" % JOB, "%s" % JOB, None, 7):
            with self.subTest(title=bad):
                parsed, errors = parse_issue(bad, body_for())
                self.assertIsNone(parsed)
                self.assertIn("bad_title", [e["code"] for e in errors])
        # Leading and trailing whitespace around a correct title is forgiven.
        parsed, errors = parse_issue("  %s\n" % title_for(), body_for())
        self.assertEqual(errors, [])
        self.assertEqual(parsed["job_id"], JOB)

    # 10 ------------------------------------------------------------------
    def test_10_payout_address_never_reaches_jobs_json(self):
        after, outcome = claim(doc(job(JOB)))
        self.assertTrue(outcome["ok"])
        serialised = json.dumps(after)
        self.assertNotIn(SELLER, serialised)
        self.assertNotIn(SELLER[len("nano_"):], serialised)
        self.assertNotIn("payout_address", serialised)
        # It is in the outcome, which is what the comment is rendered from.
        self.assertEqual(outcome["payout_address"], SELLER)
        self.assertIn(SELLER, render_comment(outcome, after["jobs"][0]))

    # 11 ------------------------------------------------------------------
    def test_11_from_event_matches_the_functions_and_uses_the_documented_exit_codes(self):
        for case, expect_ok in (("good", True), ("bad", False)):
            with self.subTest(case=case):
                with tempfile.TemporaryDirectory() as directory:
                    jobs_path = os.path.join(directory, "jobs.json")
                    before = doc(job(JOB))
                    with open(jobs_path, "w", encoding="utf-8") as handle:
                        handle.write(json.dumps(before, indent=2) + "\n")
                    event = os.path.join(directory, "event.json")
                    body = body_for() if case == "good" else body_for(address=BURN[:-1] + "1")
                    write_event(event, 41, title_for(), body, URL)

                    comment = os.path.join(directory, "comment.md")
                    out, err = io.StringIO(), io.StringIO()
                    code = main(["--from-event", event, "--now", BEFORE,
                                 "--jobs", jobs_path, "--write",
                                 "--comment-file", comment], out=out, err=err)
                    self.assertEqual(code, 0, err.getvalue())
                    printed = json.loads(out.getvalue())

                    direct_doc, direct = claim_from_issue(
                        before, title_for(), body, 41, URL, BEFORE)
                    self.assertEqual(printed.get("ok"), expect_ok)
                    for key in ("ok", "reason", "job_id", "price_xno",
                                "payout_address", "fields_written", "message"):
                        self.assertEqual(printed[key], direct[key], key)

                    with open(jobs_path, encoding="utf-8") as handle:
                        on_disk = json.load(handle)
                    self.assertEqual(canonical(on_disk), canonical(direct_doc))
                    with open(comment, encoding="utf-8") as handle:
                        self.assertIn(MARKER, handle.read())

    def test_11b_only_a_malformed_event_exits_2(self):
        with tempfile.TemporaryDirectory() as directory:
            jobs_path = os.path.join(directory, "jobs.json")
            with open(jobs_path, "w", encoding="utf-8") as handle:
                handle.write(json.dumps(doc(job(JOB)), indent=2) + "\n")
            broken = {
                "not json at all": "{{{",
                "no issue object": json.dumps({"action": "opened"}),
                "no number": json.dumps({"issue": {"title": "x", "html_url": URL}}),
                "number is a string": json.dumps(
                    {"issue": {"number": "41", "title": "x", "html_url": URL}}),
                "no html_url": json.dumps({"issue": {"number": 41, "title": "x"}}),
                "http url": json.dumps(
                    {"issue": {"number": 41, "title": "x", "html_url": "http://x/issues/1"}}),
            }
            for label, text in broken.items():
                with self.subTest(event=label):
                    event = os.path.join(directory, "event.json")
                    with open(event, "w", encoding="utf-8") as handle:
                        handle.write(text)
                    err = io.StringIO()
                    code = main(["--from-event", event, "--now", BEFORE,
                                 "--jobs", jobs_path], out=io.StringIO(), err=err)
                    self.assertEqual(code, 2, label)
                    self.assertIn("malformed event", err.getvalue())
            missing = os.path.join(directory, "nope.json")
            self.assertEqual(
                main(["--from-event", missing, "--now", BEFORE, "--jobs", jobs_path],
                     out=io.StringIO(), err=io.StringIO()),
                2)

    def test_11c_a_refusal_writes_nothing_even_with_write(self):
        with tempfile.TemporaryDirectory() as directory:
            jobs_path = os.path.join(directory, "jobs.json")
            payload = json.dumps(doc(job(JOB)), indent=2) + "\n"
            with open(jobs_path, "w", encoding="utf-8") as handle:
                handle.write(payload)
            event = os.path.join(directory, "event.json")
            write_event(event, 41, "not a claim title", body_for(), URL)
            code = main(["--from-event", event, "--now", BEFORE, "--jobs", jobs_path,
                         "--write"], out=io.StringIO(), err=io.StringIO())
            self.assertEqual(code, 0)
            with open(jobs_path, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), payload)
            self.assertFalse([n for n in os.listdir(directory) if n.endswith(".tmp")])

    # 12 ------------------------------------------------------------------
    def test_12_no_network_no_clock_stdlib_only(self):
        graph = import_graph(os.path.join(ROOT, "claim_by_issue.py"))
        self.assertTrue(graph)
        vendored = {"nanoaddr"}
        for entry in graph:
            root = entry["module"].split(".")[0]
            with self.subTest(module=entry["module"]):
                self.assertIn(
                    root, set(sys.stdlib_module_names) | vendored,
                    "%s is neither standard library nor vendored here" % entry["module"])
        # Nothing on the graph can open a socket, and that includes the one
        # vendored module, whose own graph is walked too.
        network = {"urllib", "http", "socket", "ssl", "ftplib", "smtplib",
                   "poplib", "imaplib", "telnetlib", "asyncio", "requests",
                   "httpx", "aiohttp", "urllib3"}
        for source in ("claim_by_issue.py", os.path.join("vendor", "nanoaddr.py")):
            with self.subTest(source=source):
                roots = {e["module"].split(".")[0]
                         for e in import_graph(os.path.join(ROOT, source))}
                self.assertEqual(roots & network, set())

        # Asserted over the parse tree, not over the text. A substring check for
        # "time.time" matches `datetime.timezone.utc`, which reads the clock
        # exactly never - a guard that fires on its own tz constant teaches the
        # next author to delete it.
        import ast
        with open(os.path.join(ROOT, "claim_by_issue.py"), encoding="utf-8") as handle:
            tree = ast.parse(handle.read())
        clock = {"now", "utcnow", "today", "time", "monotonic", "perf_counter",
                 "process_time", "localtime", "gmtime", "fromtimestamp", "timestamp"}
        called = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if isinstance(function, ast.Attribute):
                called.add(function.attr)
            elif isinstance(function, ast.Name):
                called.add(function.id)
        self.assertEqual(called & clock, set(),
                         "claim_by_issue.py reads the clock: %s" % sorted(called & clock))

        # And prove it rather than only reading it: an import of the module
        # followed by a full claim pulls in no network module.
        script = (
            "import sys; sys.path.insert(0, %r)\n"
            "import json, claim_by_issue as c\n"
            "jobs = {'updated': 'x', 'currency': 'XNO', 'jobs': [%s]}\n"
            "d, o = c.claim_from_issue(jobs, %r, %r, 41, %r, %r)\n"
            "assert o['ok'], o\n"
            "bad = sorted(m for m in ('urllib.request', 'http.client', 'socket', 'ssl')\n"
            "             if m in sys.modules)\n"
            "print(','.join(bad))\n"
            % (ROOT, repr(job(JOB)), title_for(), body_for(), URL, BEFORE)
        )
        result = subprocess.run([sys.executable, "-c", script], capture_output=True,
                                text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), "")

    # 13 ------------------------------------------------------------------
    def test_13_claim_py_is_unharmed(self):
        # claim.py keeps its own behaviour: this module does not import it and
        # does not change the fields it writes.
        graph = import_graph(os.path.join(ROOT, "claim_by_issue.py"))
        self.assertNotIn("claim", {e["module"] for e in graph})
        for command in (
            [sys.executable, "-m", "unittest", "tests.test_claim", "-v"],
            [sys.executable, "e2e_check.py"],
        ):
            with self.subTest(command=command[-1]):
                result = subprocess.run(command, cwd=ROOT, capture_output=True,
                                        text=True, timeout=600)
                self.assertEqual(result.returncode, 0,
                                 result.stdout[-3000:] + result.stderr[-3000:])
        self.assertIn("21/21", result.stdout)

    # 14 ------------------------------------------------------------------
    def test_14_readme_carries_a_copy_pasteable_body_that_parses(self):
        with open(os.path.join(ROOT, "README.md"), encoding="utf-8") as handle:
            readme = handle.read()
        heading = "### Claiming by issue"
        self.assertIn(heading, readme)
        section = readme.split(heading, 1)[1]
        start = section.index("```json")
        end = section.index("```", start + len("```json"))
        block = section[start + len("```json"):end]
        payload = json.loads(block)
        self.assertEqual(set(payload), set(ALLOWED_FIELDS))

        documented_title = "CLAIM %s" % payload["job_id"]
        # The title the README shows, wherever it shows it - fenced block or
        # inline code. Pinning one of the two spellings would fail on a
        # reformat that changed nothing an agent reads.
        self.assertIn(documented_title, section)
        parsed, errors = parse_issue(documented_title, "```json%s```" % block)
        self.assertEqual(errors, [], errors)
        self.assertEqual(parsed["job_id"], payload["job_id"])

        # The job the README tells an agent to claim has to be a real one.
        with open(os.path.join(ROOT, "jobs.json"), encoding="utf-8") as handle:
            board = json.load(handle)
        self.assertIn(payload["job_id"], [j["id"] for j in board["jobs"]])
        # And the README must not promise a shorter key list than the parser takes.
        for field in ALLOWED_FIELDS:
            self.assertIn("`%s`" % field, section)

    # the comment -----------------------------------------------------------
    def test_15_the_comment_says_the_sentence_and_carries_the_acceptance_lines(self):
        after, outcome = claim(doc(job(JOB)))
        comment = render_comment(outcome, after["jobs"][0])
        self.assertTrue(comment.startswith(MARKER))
        self.assertIn(NOTHING_IS_OWED, comment)
        self.assertIn("0.05 XNO", comment)
        self.assertIn(JOB, comment)
        self.assertIn(SELLER, comment)
        for line in after["jobs"][0]["acceptance"]:
            self.assertIn(line, comment)

        _, refused = claim(now=AFTER)
        refusal = render_comment(refused, None)
        self.assertTrue(refusal.startswith(MARKER))
        self.assertIn("job_expired", refusal)
        self.assertNotIn(NOTHING_IS_OWED, refusal)
        # A refusal never echoes an address we would not pay.
        _, bad = claim(body=body_for(address=SELLER[:-1] + "1"))
        self.assertNotIn(SELLER[:-1] + "1", render_comment(bad, None))

    def test_16_the_workflow_is_wired_to_the_contract_it_documents(self):
        path = os.path.join(ROOT, ".github", "workflows", "claim-by-issue.yml")
        with open(path, encoding="utf-8") as handle:
            workflow = handle.read()
        for needed in ("issues:", "opened", "edited", "reopened",
                       "contents: write", "issues: write",
                       "claim_by_issue.py", "--from-event", "--now",
                       "not-a-claim", "claim-rejected", "claimed"):
            self.assertIn(needed, workflow, needed)
        # The only secret it may use is the default token.
        self.assertNotIn("secrets.", workflow.replace("secrets.GITHUB_TOKEN", ""))


def write_event(path, number, title, body, url):
    """GitHub's documented `issues` payload, trimmed to the keys read."""
    event = {
        "action": "opened",
        "issue": {
            "number": number,
            "title": title,
            "body": body,
            "html_url": url,
            "state": "open",
            "labels": [],
            "user": {"login": "some-agent-name"},
        },
        "repository": {"full_name": "dhyabi2/paid-work-queue"},
        "sender": {"login": "some-agent-name"},
    }
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(event, handle, indent=2)
    return event


if __name__ == "__main__":
    unittest.main()
