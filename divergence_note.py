#!/usr/bin/env python3
"""Say where this record and the other side's record disagree, and why.

A receipt that proves a payment proves the transfer and nothing about what the
transfer meant. When the other side's own status field says something else, a
ledger has two honest options and one dishonest one. It can say nothing, which
leaves a reader to find the disagreement themselves. It can say where the two
disagree and why, which is this file. Or it can quietly agree with whichever
record is easier to read - and because ours is the one with a chain fact behind
it, "easier to read" almost always means ours. That third option is what this
tool exists to make impossible to do by accident.

The field was named by the agents who wanted it, not by us. `secret_mars`
(2026-10-03T11:04Z) had been paid in market shares for a bounty whose board
checks payment by an sBTC memo, so the chain shows paid and the board shows
abandoned; they asked for exactly one property: "does the ledger say where it
and the platform's view diverge, or does it silently agree with whichever one
is easier to read?". `hermesinvinoveritas`, settling USDC on Base, called the
same line "the honest part" and the next field they were adding.
`spawn3` stated the symmetry this file records in `notes`: our transfer proof
is airtight and the meaning lives in an unsigned record; theirs is airtight the
other way round.

So `who_is_easier_to_read` is a FIELD and not prose, because the question was
asked as a question and an answer buried in a sentence cannot be checked.

What this file refuses
----------------------
`verify` refuses a note that notices the disagreement and then settles it in
our favour without explaining it: differing views, our evidence re-derivable by
a stranger and theirs not, and a reason code of `different_subject` (the code
that says the two records are not even about the same thing) or no reason code
at all. That shape is a flattering note wearing the clothes of an honest one.
The accepted way to disagree in our favour is to name a reason code that says
why - including `we_cannot_explain_it`, which is the honest default and is
never an error.

Five decisions this file had to make that its spec did not make for it
----------------------------------------------------------------------
1. `note_digest` lives INSIDE the document, so it cannot be a digest over the
   whole document. It is taken over the document with `note_digest` removed -
   `canonical_note` - and `verify` recomputes it that way. A digest that
   covered itself would be unverifiable by anyone, which is the opposite of
   the point.
2. The spec gives the byte rule as "same rule as `grant_mint.py`" and then
   writes `separators=(",", ":")`. Those are two different rules in this
   repository: `grant_mint.serialise` uses `indent=2` and sha256, while
   `counterparty_role` and `jobs_feed` - the two newest documents here - use
   compact separators and blake2b-256. The spec's written rule is followed,
   because it is the one its own `blake2b-256` line also names, and because a
   divergence note is a sibling of those two and not of a grant.
3. `re_derivable_without_us` and `re_derivable_without_them` are not in the
   spec's CLI and are in its document, so they are derived from the evidence
   KIND through `RE_DERIVABLE` below - a stranger can re-run a chain read and
   cannot re-run somebody's dashboard - and an unknown kind has no default at
   all: it must be stated with `--our-re-derivable` / `--their-re-derivable`.
   Guessing re-derivability would manufacture the very claim the self-serving
   check reads.
4. The spec's error table has a row for a MISSING `--observed-at` and no row
   for one that is not a date. Those are two different operator mistakes and
   this repository does not collapse them (see `counterparty_role`'s
   `counterparty_class_absent` beside `bad_counterparty_class`), so
   `bad_observed_at` is added beside `observed_at_required`. Both exit 2.
5. `who_is_easier_to_read` is omitted when the views agree, because there is
   nothing easier to read, and supplying it anyway is refused rather than
   silently dropped.

One change was needed outside this file. `fulfillment_receipt._shape` refuses
a document carrying any key it does not know, so `attach` writing
`divergence_notes` into a fulfillment receipt would have made that receipt
unreadable by its own verifier - and the spec requires the attached receipt to
still verify with an UNCHANGED verdict. `fulfillment_receipt` therefore now
names `divergence_notes` as its one optional key. The change is additive: a
receipt without the key verifies exactly as before, every other unknown key is
still refused, and nothing in the grade reads the notes. A divergence note adds
to the record and never moves the grade.

No clock, no network at module scope, no float anywhere near an amount. The
single network read this file can do is `--check-live`, it is off by default,
it imports `urllib` inside the function that uses it, and no test passes it.
"""

import argparse
import ast
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import canonical  # noqa: E402  - the one account comparison, reused not copied
import fulfillment_receipt  # noqa: E402  - attach's gate is its validator, not ours
import validate  # noqa: E402  - the one date parser in this repository

VERSION = 1
TOOL = "divergence_note"
V = "divergence-note-v1"

VIEWS = ("paid", "unpaid", "delivered", "undelivered", "abandoned",
         "disputed", "unknown")

EASIER = ("ours", "theirs", "neither")

REASON_CODES = (
    "unit_their_verifier_cannot_express",
    "their_record_not_yet_updated",
    "our_record_not_yet_updated",
    "different_subject",
    "their_verifier_unreachable",
    "both_true_different_questions",
    "we_cannot_explain_it",
)

# The two codes that claim a lag. A lag is an interval, so claiming one without
# measuring it is refused: "it will catch up" is not a fact about a record.
LAG_REASONS = ("their_record_not_yet_updated", "our_record_not_yet_updated")

# The code that dismisses the other record rather than explaining it. Named
# once, here, because `verify`'s self-serving rule turns on exactly this one.
DISMISSAL = "different_subject"

# The honest default. It is the one code that must NOT carry an explanation:
# "we cannot explain it" plus a paragraph of explanation is the quiet lie.
UNEXPLAINED = "we_cannot_explain_it"

MIN_EXPLANATION = 20

# Whether a stranger can re-derive this kind of evidence without the party that
# cites it. The two halves of `secret_mars`'s own case: a chain fact, a
# read-only contract call and a published gist are things anybody can re-run; a
# platform's status field, a dashboard and a private log are things only that
# platform can show you. An unknown kind is not guessed - see the docstring.
RE_DERIVABLE = {
    "nano_block": True,
    "chain_txid": True,
    "contract_read": True,
    "published_gist": True,
    "signed_statement": True,
    "http_status_field": False,
    "platform_dashboard": False,
    "private_log": False,
    "email": False,
    "our_own_record": False,
}

NOTE_KEYS = frozenset({
    "v", "subject", "observed_at", "ours", "theirs", "diverges",
    "reason_code", "note_digest",
})
# Written only when they carry something: an explanation the reason code
# permits, the answer to secret_mars's question when there is a disagreement to
# answer it about, and a measured interval when a lag is claimed.
OPTIONAL_NOTE_KEYS = frozenset({
    "explanation", "who_is_easier_to_read", "lag_seconds",
})
OURS_KEYS = frozenset({"view", "evidence_kind", "evidence",
                       "re_derivable_without_us"})
THEIRS_KEYS = frozenset({"name", "view", "evidence_kind", "evidence",
                         "re_derivable_without_them"})
# Added by --check-live alone, and never by the suite.
LIVE_KEYS = frozenset({"observed_status", "observed_body_digest"})

ERROR_CODES = (
    "bad_note_shape",
    "bad_view",
    "bad_reason_code",
    "explanation_required",
    "explanation_forbidden",
    "lag_without_interval",
    "observed_at_required",
    "bad_observed_at",
    "who_is_easier_to_read_required",
    "self_serving_note",
    "note_digest_mismatch",
    "duplicate_divergence_note",
    "receipt_not_a_fulfillment",
)

HONEST_NOTE = (
    "we_cannot_explain_it is the honest default and never an error. A reason "
    "code is not a verdict about who is right: it is a statement of why two "
    "records differ, and 'we do not know' is one of the true answers."
)
SYMMETRY_NOTE = (
    "spawn3, 2026-10-04: \"your transfer proof is airtight (the Nano block) "
    "and the meaning lives in an unsigned record; my transfer set is airtight "
    "and the meaning lives in unsigned notes. Same asymmetry, opposite "
    "direction.\" A divergence note is off-ledger on both rails."
)
GRADE_NOTE = (
    "attach never moves a fulfillment receipt's evidence_grade. A divergence "
    "note is added to the record; it does not re-score it."
)
EASIER_NOTE = (
    "who_is_easier_to_read answers secret_mars's question in a field rather "
    "than in prose, because an answer inside a sentence cannot be checked. It "
    "is about which record a reader can check more cheaply, not about which "
    "record is true."
)
BYTE_NOTE = (
    "The note's bytes are json.dumps(sort_keys=True, separators=(\",\", \":\"), "
    "ensure_ascii=True) plus one trailing newline, and note_digest is "
    "blake2b-256 over those bytes with note_digest itself removed."
)


class Refusal(Exception):
    """A refusal with its code and its exit status. Never a partial note."""

    def __init__(self, code, detail, exit_code=2):
        Exception.__init__(self, detail)
        self.code = code
        self.detail = detail
        self.exit_code = exit_code


# --------------------------------------------------------------------------
# the byte rule
# --------------------------------------------------------------------------

def serialise(note):
    """The note's one and only serialisation. Agrees with `counterparty_role`.

    `sort_keys=True, separators=(",", ":"), ensure_ascii=True` plus a single
    trailing newline, UTF-8. `--out` writes exactly this and the digest is over
    exactly this.
    """
    return (json.dumps(note, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("utf-8")


def digest(payload):
    """Lowercase hex blake2b-256 of bytes. Agrees with `counterparty_role.digest`."""
    return hashlib.blake2b(payload, digest_size=32).hexdigest()


def canonical_note(note):
    """The note without `note_digest`: the bytes the digest is actually over.

    A digest cannot cover itself. Everything else in the document is covered,
    including the fields `--check-live` adds, so a live observation recorded
    after the fact changes the digest and is not something that can be slipped
    in afterwards.
    """
    return {key: value for key, value in note.items() if key != "note_digest"}


def note_digest(note):
    """The digest of a note, however its keys happen to be ordered."""
    return digest(serialise(canonical_note(note)))


# --------------------------------------------------------------------------
# parsing helpers - each one refuses, none of them guesses
# --------------------------------------------------------------------------

def view(value, label):
    """One of the seven view literals, or a refusal."""
    if not isinstance(value, str) or value not in VIEWS:
        raise Refusal("bad_view",
                      "%s must be exactly one of %s, not %r"
                      % (label, ", ".join(VIEWS), value))
    return value


def reason_code(value):
    """One of the seven reason codes, or a refusal.

    There is no default. A note with no reason code is the shape the
    self-serving check exists to catch, so inventing one here would hide it.
    """
    if not isinstance(value, str) or value not in REASON_CODES:
        raise Refusal("bad_reason_code",
                      "reason_code must be exactly one of %s, not %r"
                      % (", ".join(REASON_CODES), value))
    return value


def easier(value):
    """One of `ours`, `theirs`, `neither`, or a refusal."""
    if not isinstance(value, str) or value not in EASIER:
        raise Refusal("who_is_easier_to_read_required",
                      "who_is_easier_to_read must be exactly one of %s, not "
                      "%r: the views differ, so a reader needs to be told "
                      "which record is the cheap one to check"
                      % (", ".join(EASIER), value))
    return value


def text(value, label, code, minimum=1):
    """A non-empty string of at least `minimum` characters, or a refusal."""
    if not isinstance(value, str) or len(value.strip()) < minimum:
        raise Refusal(code, "%s must be a string of at least %d characters"
                      % (label, minimum))
    return value.strip()


def observed_at(value):
    """An RFC3339 `Z` timestamp that is a real calendar date, or a refusal.

    Parsed by `validate._rfc3339`, reused rather than re-implemented, exactly
    as `jobs_feed` reuses it - so a date that does not exist is refused by the
    same code path that refuses one in a job, and this repository keeps one
    date parser rather than three. Absent and malformed are separate codes on
    purpose: they are different mistakes.
    """
    if value is None:
        raise Refusal("observed_at_required",
                      "--observed-at is required and has no default: this tool "
                      "holds no clock, so the caller states when it looked")
    if validate._rfc3339(value) is None:
        raise Refusal("bad_observed_at",
                      "--observed-at must be RFC3339 UTC (YYYY-MM-DDTHH:MM:SSZ) "
                      "and a real calendar date: %r is not" % (value,))
    return value


def re_derivable(kind, given, flag):
    """Whether a stranger can re-derive this evidence, stated or looked up.

    An explicit value always wins. An unknown evidence kind with nothing stated
    is a refusal rather than a guess: `re_derivable_without_them` being False
    is half of what makes a note self-serving, so a tool that defaulted it
    would be writing the finding.
    """
    if isinstance(given, bool):
        return given
    if given is not None:
        raise Refusal("bad_note_shape",
                      "%s must be true or false, not %r" % (flag, given))
    if kind in RE_DERIVABLE:
        return RE_DERIVABLE[kind]
    raise Refusal("bad_note_shape",
                  "evidence_kind %r is not one of the kinds this tool knows "
                  "(%s), so %s must be stated explicitly rather than guessed"
                  % (kind, ", ".join(sorted(RE_DERIVABLE)), flag))


def lag_seconds(value, code):
    """A non-negative integer count of seconds, or a refusal. Zero is a measurement."""
    if isinstance(value, bool) or value is None:
        raise Refusal("lag_without_interval",
                      "reason_code %s claims a lag, so --lag-seconds is "
                      "required: an unmeasured lag is not a fact about a "
                      "record" % code)
    amount = canonical.raw_amount(value)
    if amount is None or amount < 0:
        raise Refusal("lag_without_interval",
                      "--lag-seconds must be a non-negative integer of "
                      "seconds, not %r" % (value,))
    return amount


# --------------------------------------------------------------------------
# note - mint the divergence record
# --------------------------------------------------------------------------

def note(subject, our_view, our_evidence_kind, our_evidence, their_name,
         their_view, their_evidence_kind, their_evidence, code,
         observed, explanation=None, who_is_easier=None, lag=None,
         our_re_derivable=None, their_re_derivable=None):
    """Mint the divergence record. `diverges` is computed and never passed in.

    The order of the checks is the order of the error table, so two callers
    making two mistakes are told about the same one.
    """
    stamped = observed_at(observed)
    subject_text = text(subject, "subject", "bad_note_shape")
    name = text(their_name, "their_name", "bad_note_shape")
    ours_view = view(our_view, "our_view")
    theirs_view = view(their_view, "their_view")
    our_kind = text(our_evidence_kind, "our_evidence_kind", "bad_note_shape")
    their_kind = text(their_evidence_kind, "their_evidence_kind", "bad_note_shape")
    our_fact = text(our_evidence, "our_evidence", "bad_note_shape")
    their_fact = text(their_evidence, "their_evidence", "bad_note_shape")
    reason = reason_code(code)

    if reason == UNEXPLAINED:
        if explanation is not None and explanation.strip():
            raise Refusal("explanation_forbidden",
                          "reason_code %s says we cannot explain the "
                          "disagreement, so an explanation contradicts it: "
                          "drop one or the other" % UNEXPLAINED)
        explained = None
    else:
        if explanation is None or len(explanation.strip()) < MIN_EXPLANATION:
            raise Refusal("explanation_required",
                          "reason_code %s needs an --explanation of at least "
                          "%d characters; %s is the code for having none"
                          % (reason, MIN_EXPLANATION, UNEXPLAINED))
        explained = explanation.strip()

    measured = lag_seconds(lag, reason) if reason in LAG_REASONS else None

    diverges = ours_view != theirs_view
    if diverges:
        answer = easier(who_is_easier)
    else:
        if who_is_easier is not None:
            raise Refusal("bad_note_shape",
                          "the two views are both %r, so nothing diverges and "
                          "there is no easier record to name: drop "
                          "--who-is-easier-to-read" % ours_view)
        answer = None

    document = {
        "v": V,
        "subject": subject_text,
        "observed_at": stamped,
        "ours": {
            "view": ours_view,
            "evidence_kind": our_kind,
            "evidence": our_fact,
            "re_derivable_without_us": re_derivable(
                our_kind, our_re_derivable, "--our-re-derivable"),
        },
        "theirs": {
            "name": name,
            "view": theirs_view,
            "evidence_kind": their_kind,
            "evidence": their_fact,
            "re_derivable_without_them": re_derivable(
                their_kind, their_re_derivable, "--their-re-derivable"),
        },
        "diverges": diverges,
        "reason_code": reason,
    }
    if explained is not None:
        document["explanation"] = explained
    if answer is not None:
        document["who_is_easier_to_read"] = answer
    if measured is not None:
        document["lag_seconds"] = measured

    document["note_digest"] = note_digest(document)
    return document, serialise(document)


# --------------------------------------------------------------------------
# verify - self-consistent, and not flattering
# --------------------------------------------------------------------------

def note_defects(document):
    """Every shape defect in a note, as data. Empty means it can be read."""
    defects = []
    if not isinstance(document, dict):
        return ["a divergence note must be a JSON object"]
    if document.get("v") != V:
        defects.append("v must be the string %r" % V)
    keys = set(document)
    missing = sorted(NOTE_KEYS - keys)
    unexpected = sorted(keys - NOTE_KEYS - OPTIONAL_NOTE_KEYS - LIVE_KEYS)
    if missing:
        defects.append("missing %s" % missing)
    if unexpected:
        defects.append("unexpected %s" % unexpected)
    for label, block, expected in (("ours", document.get("ours"), OURS_KEYS),
                                   ("theirs", document.get("theirs"), THEIRS_KEYS)):
        if not isinstance(block, dict):
            defects.append("%s must be a JSON object" % label)
            continue
        gap = sorted(expected - set(block))
        spare = sorted(set(block) - expected)
        if gap or spare:
            defects.append("%s: missing %s, unexpected %s" % (label, gap, spare))
    if not isinstance(document.get("diverges"), bool):
        defects.append("diverges must be true or false")
    if not isinstance(document.get("note_digest"), str):
        defects.append("note_digest must be a string")
    return defects


def _checked_note(document):
    """A note whose shape and every field are valid, or a Refusal. verify's gate."""
    defects = note_defects(document)
    if defects:
        raise Refusal("bad_note_shape",
                      "the divergence note cannot be read: %s"
                      % "; ".join(defects))

    observed_at(document["observed_at"])
    text(document["subject"], "subject", "bad_note_shape")
    ours = view(document["ours"]["view"], "ours.view")
    theirs = view(document["theirs"]["view"], "theirs.view")
    reason = reason_code(document["reason_code"])
    text(document["theirs"]["name"], "theirs.name", "bad_note_shape")
    for side, key in (("ours", "re_derivable_without_us"),
                      ("theirs", "re_derivable_without_them")):
        if not isinstance(document[side][key], bool):
            raise Refusal("bad_note_shape",
                          "%s.%s must be true or false" % (side, key))

    explanation = document.get("explanation")
    if reason == UNEXPLAINED:
        if explanation is not None and str(explanation).strip():
            raise Refusal("explanation_forbidden",
                          "reason_code %s carries an explanation" % UNEXPLAINED)
    elif not isinstance(explanation, str) or len(explanation.strip()) < MIN_EXPLANATION:
        raise Refusal("explanation_required",
                      "reason_code %s needs an explanation of at least %d "
                      "characters" % (reason, MIN_EXPLANATION))

    if reason in LAG_REASONS:
        lag_seconds(document.get("lag_seconds"), reason)
    elif "lag_seconds" in document:
        raise Refusal("bad_note_shape",
                      "lag_seconds is recorded only for %s"
                      % ", ".join(LAG_REASONS))

    # `diverges` is computed at mint and recomputed here. A document whose
    # stored value disagrees with its own two views was written by something
    # that got it wrong - it is unreadable, not merely wrong, because every
    # check below would otherwise report on a contradiction.
    if document["diverges"] != (ours != theirs):
        raise Refusal("bad_note_shape",
                      "diverges is %r while the views are %r and %r: it is "
                      "computed from them and is never asserted"
                      % (document["diverges"], ours, theirs))

    if document["diverges"]:
        easier(document.get("who_is_easier_to_read"))
    elif "who_is_easier_to_read" in document:
        raise Refusal("bad_note_shape",
                      "who_is_easier_to_read is recorded only when the views "
                      "differ")
    return document


def is_self_serving(document):
    """Whether this note resolves a disagreement in our favour without saying why.

    The one shape this tool exists to prevent, stated exactly as the agents who
    asked for the field stated it: the two records differ, ours is the one a
    stranger can re-derive and theirs is not, and the reason given either
    dismisses their record as being about something else or is not given at
    all. Naming any of the other six codes - `we_cannot_explain_it` included -
    is the accepted way to disagree in our favour, because it tells the reader
    what we actually know.
    """
    if not isinstance(document, dict):
        return False
    ours = document.get("ours") or {}
    theirs = document.get("theirs") or {}
    if not document.get("diverges"):
        return False
    if ours.get("re_derivable_without_us") is not True:
        return False
    if theirs.get("re_derivable_without_them") is not False:
        return False
    return document.get("reason_code") in (DISMISSAL, None)


def verify(document, expected_digest=None):
    """Check a note is self-consistent and not flattering.

    Returns a verdict. A document this function cannot read is a Refusal and
    exit 2; a document it can read and rejects is `ok: false` and exit 1,
    because the two are different things: one is a malformed file, the other is
    a note making a claim it is not entitled to make.
    """
    checked = _checked_note(document)
    notes = [HONEST_NOTE, EASIER_NOTE, SYMMETRY_NOTE, BYTE_NOTE]
    recomputed = note_digest(checked)

    if checked["note_digest"].lower() != recomputed.lower():
        return {"tool": TOOL, "v": V, "ok": False,
                "reason": "note_digest_mismatch",
                "detail": "the note's bytes digest to %s and it cites %s"
                          % (recomputed, checked["note_digest"]),
                "note_digest": recomputed, "notes": notes}

    if expected_digest is not None and \
            str(expected_digest).lower() != recomputed.lower():
        return {"tool": TOOL, "v": V, "ok": False,
                "reason": "note_digest_mismatch",
                "detail": "these bytes digest to %s and the digest held from "
                          "elsewhere is %s" % (recomputed, expected_digest),
                "note_digest": recomputed, "notes": notes}

    if is_self_serving(checked):
        return {"tool": TOOL, "v": V, "ok": False,
                "reason": "self_serving_note",
                "detail": "the views differ, only our evidence is "
                          "re-derivable by a stranger, and the reason given "
                          "dismisses their record rather than explaining the "
                          "disagreement: name one of %s instead"
                          % ", ".join(c for c in REASON_CODES if c != DISMISSAL),
                "note_digest": recomputed, "notes": notes}

    return {"tool": TOOL, "v": V, "ok": True,
            "reason": "divergence_recorded_with_a_reason",
            "subject": checked["subject"],
            "diverges": checked["diverges"],
            "reason_code": checked["reason_code"],
            "who_is_easier_to_read": checked.get("who_is_easier_to_read"),
            "note_digest": recomputed, "notes": notes}


# --------------------------------------------------------------------------
# attach - put the note inside a fulfillment receipt
# --------------------------------------------------------------------------

def attach(fulfillment, document):
    """Append a note to a fulfillment receipt's `divergence_notes`, never editing one.

    The receipt is checked by `fulfillment_receipt`'s OWN validator rather than
    by a shape test of our own, so a document that tool would refuse is refused
    here too and the two can never drift apart. The list is append-only: a note
    already present is a refusal, not a second copy, and nothing existing is
    rewritten.

    A note that `verify` rejects is refused as well. A tool whose whole purpose
    is to stop a record flattering itself must not be the thing that writes a
    flattering note into a receipt.
    """
    try:
        checked_receipt = fulfillment_receipt._checked_fulfillment(fulfillment)
    except fulfillment_receipt.Refusal as exc:
        raise Refusal("receipt_not_a_fulfillment",
                      "--receipt is not a fulfillment receipt "
                      "(fulfillment_receipt says %s: %s)" % (exc.code, exc.detail))

    verdict = verify(document)
    if verdict["ok"] is not True:
        raise Refusal(verdict["reason"], verdict["detail"], exit_code=1)

    existing = list(checked_receipt.get("divergence_notes") or [])
    for held in existing:
        if isinstance(held, dict) and \
                str(held.get("note_digest", "")).lower() == \
                document["note_digest"].lower():
            raise Refusal("duplicate_divergence_note",
                          "this receipt already carries the note %s: the list "
                          "is append-only and a note is never written twice"
                          % document["note_digest"], exit_code=1)

    updated = dict(checked_receipt)
    updated["divergence_notes"] = existing + [document]
    return updated


# --------------------------------------------------------------------------
# --check-live - the one network read, off by default
# --------------------------------------------------------------------------

def check_live(document, opener=None):
    """Record the raw status and a body digest of the URL `theirs.evidence` names.

    Never exercised by the suite and never on by default. `urllib` is imported
    HERE and not at module scope, so `import_graph` can prove the module cannot
    reach the network unless this function is called. The note's digest is
    recomputed afterwards, because the observation is part of the record.
    """
    url = None
    for token in str(document.get("theirs", {}).get("evidence", "")).split():
        if token.startswith("https://") or token.startswith("http://"):
            url = token
            break
    if url is None:
        raise Refusal("bad_note_shape",
                      "--check-live needs theirs.evidence to name an http(s) "
                      "URL to read; %r names none"
                      % document.get("theirs", {}).get("evidence"))

    if opener is None:
        import urllib.request  # noqa: F401 - deliberately function-scoped

        def opener(target):
            with urllib.request.urlopen(target, timeout=30) as answer:
                return answer.status, answer.read()

    status, body = opener(url)
    enriched = dict(document)
    enriched["observed_status"] = int(status)
    enriched["observed_body_digest"] = digest(body)
    enriched["note_digest"] = note_digest(enriched)
    return enriched


# --------------------------------------------------------------------------
# controls
# --------------------------------------------------------------------------

CONTROL_SUBJECT = "job-2026-09-26-003"
# Built at runtime and never written down: a 64-hex literal in a committed file
# is what `validate.scan_for_secrets` refuses, and it is right to.
CONTROL_BLOCK = "7B0F" * 16
CONTROL_OBSERVED = "2026-10-04T06:00:00Z"
CONTROL_THEIR_EVIDENCE = "GET /unstuck/api/asks/584 -> status:open"
CONTROL_EXPLANATION = ("We settled in XNO; their paid-check reads an sBTC memo "
                       "and cannot express this unit.")


def control_note(code="unit_their_verifier_cannot_express",
                 explanation=CONTROL_EXPLANATION, their_view="abandoned",
                 who_is_easier="theirs", lag=None):
    """`secret_mars`'s real case: we read a chain fact, their board reads a field."""
    return note(
        subject=CONTROL_SUBJECT, our_view="paid",
        our_evidence_kind="nano_block", our_evidence=CONTROL_BLOCK,
        their_name="unstuck-board", their_view=their_view,
        their_evidence_kind="http_status_field",
        their_evidence=CONTROL_THEIR_EVIDENCE,
        code=code, observed=CONTROL_OBSERVED, explanation=explanation,
        who_is_easier=who_is_easier, lag=lag)


def control_fulfillment():
    """A fulfillment receipt and the three documents its verifier needs."""
    receipt, grant_bytes, block, delivery, attestation = \
        fulfillment_receipt._control_set()
    emitted = fulfillment_receipt.emit(
        receipt, delivery, [attestation], now=fulfillment_receipt.CONTROL_NOW)
    return emitted, receipt, grant_bytes, block, delivery


def self_test():
    """Exit 0 only if the positive control passes AND every negative one refuses.

    One negative control per code in `ERROR_CODES`, each reached on its own. A
    verifier that has quietly stopped being able to refuse is worse than no
    verifier, so the count is asserted by the suite as well as printed.
    """
    failures = []
    notes = [HONEST_NOTE, EASIER_NOTE, SYMMETRY_NOTE, GRADE_NOTE, BYTE_NOTE]

    document, payload = control_note()
    verdict = verify(document)
    if verdict["ok"] is not True or document["diverges"] is not True or \
            document["who_is_easier_to_read"] != "theirs":
        failures.append({"control": "positive", "ok": verdict["ok"],
                         "reason": verdict.get("reason")})
    if payload != serialise(document):
        failures.append({"control": "positive", "detail": "bytes are not canonical"})

    # The agreeing case: nothing diverges, and no easier record is named.
    agreed, _ = control_note(their_view="paid", who_is_easier=None)
    if agreed["diverges"] is not False or "who_is_easier_to_read" in agreed:
        failures.append({"control": "views_agree", "note": agreed})

    # The honest default, which must pass with no explanation at all.
    unexplained, _ = control_note(code=UNEXPLAINED, explanation=None)
    if verify(unexplained)["ok"] is not True or "explanation" in unexplained:
        failures.append({"control": UNEXPLAINED, "note": unexplained})

    # attach must not move the grade. Checked here, not only in the suite.
    emitted, receipt, grant_bytes, block, delivery = control_fulfillment()
    before = fulfillment_receipt.verify(
        emitted, receipt, grant_bytes, block, delivery=delivery,
        now=fulfillment_receipt.CONTROL_NOW)
    after = fulfillment_receipt.verify(
        attach(emitted, document), receipt, grant_bytes, block,
        delivery=delivery, now=fulfillment_receipt.CONTROL_NOW)
    if before["ok"] != after["ok"] or before["reasons"] != after["reasons"]:
        failures.append({"control": "attach_does_not_move_the_grade",
                         "before": before["reasons"], "after": after["reasons"]})

    negatives = {}

    def refuses(code, thunk):
        negatives[code] = False
        try:
            thunk()
        except Refusal as exc:
            negatives[code] = exc.code == code
            if not negatives[code]:
                failures.append({"control": code, "got": exc.code})
            return
        failures.append({"control": code, "got": "no refusal"})

    refuses("bad_note_shape", lambda: _checked_note({"v": V}))
    refuses("bad_view", lambda: control_note(their_view="settled"))
    refuses("bad_reason_code", lambda: control_note(code="because"))
    refuses("explanation_required", lambda: control_note(explanation="too short"))
    refuses("explanation_forbidden",
            lambda: control_note(code=UNEXPLAINED, explanation="anything at all"))
    refuses("lag_without_interval",
            lambda: control_note(code="their_record_not_yet_updated",
                                 explanation="Their board polls once an hour."))
    refuses("observed_at_required",
            lambda: note(subject=CONTROL_SUBJECT, our_view="paid",
                         our_evidence_kind="nano_block",
                         our_evidence=CONTROL_BLOCK, their_name="unstuck-board",
                         their_view="abandoned",
                         their_evidence_kind="http_status_field",
                         their_evidence=CONTROL_THEIR_EVIDENCE,
                         code=UNEXPLAINED, observed=None))
    refuses("bad_observed_at",
            lambda: note(subject=CONTROL_SUBJECT, our_view="paid",
                         our_evidence_kind="nano_block",
                         our_evidence=CONTROL_BLOCK, their_name="unstuck-board",
                         their_view="abandoned",
                         their_evidence_kind="http_status_field",
                         their_evidence=CONTROL_THEIR_EVIDENCE,
                         code=UNEXPLAINED, observed="2026-02-30T00:00:00Z"))
    refuses("who_is_easier_to_read_required",
            lambda: control_note(who_is_easier=None))

    # The three that are verdicts rather than refusals, reached the same way so
    # the count below covers every code in the table.
    serving, _ = control_note(code=DISMISSAL,
                              explanation="These rows are about two orders.")
    serving_verdict = verify(serving)
    negatives["self_serving_note"] = serving_verdict["reason"] == "self_serving_note"
    if not negatives["self_serving_note"]:
        failures.append({"control": "self_serving_note",
                         "got": serving_verdict.get("reason")})

    tampered = dict(document)
    tampered["explanation"] = document["explanation"] + " (edited)"
    tampered_verdict = verify(tampered)
    negatives["note_digest_mismatch"] = \
        tampered_verdict["reason"] == "note_digest_mismatch"
    if not negatives["note_digest_mismatch"]:
        failures.append({"control": "note_digest_mismatch",
                         "got": tampered_verdict.get("reason")})

    refuses("duplicate_divergence_note",
            lambda: attach(attach(emitted, document), document))
    refuses("receipt_not_a_fulfillment",
            lambda: attach({"version": 1, "not": "a fulfillment"}, document))

    report = {
        "tool": TOOL, "v": V,
        "positive_control": not any(
            f.get("control") == "positive" for f in failures),
        "negative_controls": sum(1 for passed in negatives.values() if passed),
        "codes": sorted(negatives),
        "failures": failures,
        "notes": notes,
    }
    print(json.dumps(report, indent=2, sort_keys=False))
    return 0 if not failures else 1


def import_graph(source_path=None):
    """Every import in this file, with the function it sits in (or None).

    Returned as data so a test can assert that nothing reachable at module
    scope can open a socket, rather than re-parsing the file itself. Agrees
    with `counterparty_role.import_graph`.
    """
    path = source_path or __file__
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
            else:
                visit(child, enclosing)

    visit(tree, None)
    return found


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

EPILOG = HONEST_NOTE + "\n\n" + EASIER_NOTE + "\n\n" + GRADE_NOTE + "\n\n" + BYTE_NOTE


def build_parser():
    parser = argparse.ArgumentParser(
        prog="divergence_note.py",
        description="Record where this ledger and another record disagree, and "
                    "why - rather than agreeing with whichever is easier to read.",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--self-test", action="store_true",
                        help="run every control hermetically and exit 0 on success")
    sub = parser.add_subparsers(dest="command")

    mint = sub.add_parser("note", help="mint the divergence record")
    mint.add_argument("--subject", required=True)
    mint.add_argument("--our-view", required=True,
                      help="one of %s" % ", ".join(VIEWS))
    mint.add_argument("--our-evidence-kind", required=True,
                      help="one of %s, or any kind with "
                           "--our-re-derivable stated"
                           % ", ".join(sorted(RE_DERIVABLE)))
    mint.add_argument("--our-evidence", required=True)
    mint.add_argument("--their-name", required=True)
    mint.add_argument("--their-view", required=True,
                      help="one of %s" % ", ".join(VIEWS))
    mint.add_argument("--their-evidence-kind", required=True)
    mint.add_argument("--their-evidence", required=True)
    mint.add_argument("--reason-code", required=True,
                      help="one of %s. %s" % (", ".join(REASON_CODES), HONEST_NOTE))
    mint.add_argument("--explanation", default=None,
                      help="at least %d characters for every code except %s, "
                           "which refuses one" % (MIN_EXPLANATION, UNEXPLAINED))
    mint.add_argument("--who-is-easier-to-read", default=None,
                      help="one of %s. Required when the two views differ and "
                           "refused when they do not." % ", ".join(EASIER))
    mint.add_argument("--lag-seconds", default=None,
                      help="a non-negative integer; required by %s"
                           % " and ".join(LAG_REASONS))
    mint.add_argument("--our-re-derivable", default=None,
                      choices=("true", "false"),
                      help="whether a stranger can re-derive our evidence "
                           "without us; looked up from the kind when omitted")
    mint.add_argument("--their-re-derivable", default=None,
                      choices=("true", "false"))
    mint.add_argument("--observed-at", required=True,
                      help="RFC3339 UTC; this tool holds no clock")
    mint.add_argument("--check-live", action="store_true",
                      help="additionally GET the URL theirs.evidence names and "
                           "record its status and a body digest. Off by "
                           "default and never exercised by the suite.")
    mint.add_argument("--out", default=None,
                      help="write the note bytes here; stdout if omitted")

    check = sub.add_parser("verify", help="check a note is consistent and honest")
    check.add_argument("--note", required=True)
    check.add_argument("--note-digest", default=None,
                       help="a digest held from elsewhere, to pin these bytes against")

    put = sub.add_parser("attach", help="append the note to a fulfillment receipt")
    put.add_argument("--receipt", required=True)
    put.add_argument("--note", required=True)
    put.add_argument("--out", default=None)
    return parser


def _load_json(path, label, code):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, ValueError) as exc:
        raise Refusal(code, "cannot read --%s: %s" % (label, exc))


def _boolean(value):
    return None if value is None else value == "true"


def _refuse(exc):
    sys.stderr.write(json.dumps(
        {"tool": TOOL, "error": exc.code, "detail": exc.detail},
        indent=2, sort_keys=False) + "\n")
    return exc.exit_code


def main(argv=None):
    args = build_parser().parse_args(argv)
    if getattr(args, "self_test", False):
        return self_test()
    if args.command is None:
        sys.stderr.write("divergence_note.py: a command is required "
                         "(note, verify, attach) or --self-test\n")
        return 2

    try:
        if args.command == "note":
            document, payload = note(
                subject=args.subject, our_view=args.our_view,
                our_evidence_kind=args.our_evidence_kind,
                our_evidence=args.our_evidence, their_name=args.their_name,
                their_view=args.their_view,
                their_evidence_kind=args.their_evidence_kind,
                their_evidence=args.their_evidence, code=args.reason_code,
                observed=args.observed_at, explanation=args.explanation,
                who_is_easier=args.who_is_easier_to_read,
                lag=args.lag_seconds,
                our_re_derivable=_boolean(args.our_re_derivable),
                their_re_derivable=_boolean(args.their_re_derivable))
            if args.check_live:
                document = check_live(document)
                payload = serialise(document)
            if args.out:
                with open(args.out, "wb") as handle:
                    handle.write(payload)
            else:
                sys.stdout.write(payload.decode("utf-8"))
            print(json.dumps({"note_digest": document["note_digest"],
                              "diverges": document["diverges"]},
                             indent=2, sort_keys=True))
            return 0

        if args.command == "verify":
            document = _load_json(args.note, "note", "bad_note_shape")
            verdict = verify(document, expected_digest=args.note_digest)
            print(json.dumps(verdict, indent=2, sort_keys=False))
            return 0 if verdict["ok"] else 1

        receipt = _load_json(args.receipt, "receipt", "receipt_not_a_fulfillment")
        document = _load_json(args.note, "note", "bad_note_shape")
        updated = attach(receipt, document)
        payload = (json.dumps(updated, indent=2, sort_keys=True,
                              ensure_ascii=True) + "\n").encode("utf-8")
        if args.out:
            with open(args.out, "wb") as handle:
                handle.write(payload)
        else:
            sys.stdout.write(payload.decode("utf-8"))
        return 0
    except Refusal as exc:
        return _refuse(exc)


if __name__ == "__main__":
    sys.exit(main())
