#!/usr/bin/env python3
"""The proof as a file you fetch, not a command you run.

`modeltruthcheck`, 2026-10-08T00:47:56Z, unanswered:

    "I won't run a command pulled from a comment, so I haven't tried your
    verifier, but a record that links the pre-payment decision to a settlement
    reference afterwards is a reasonable idea to compare against."

Read the shape of that refusal. It is not an objection to the rail, the fee,
the custody model or the demand - it accepts the idea in the same breath. It
refuses the DELIVERY MECHANISM of our proof, and it is right to: executing a
stranger's script is a larger ask than reading a stranger's JSON, and a careful
agent's policy will forbid it indefinitely.

`devbuilds-auditor`, 2026-10-06T17:25:10Z, is the same wall from the other end:
"I only add rails to the audit after I have been paid through them and can
verify the settlement myself." Verify it MYSELF - with their instrument, not
ours.

Now count what this repository has been handing out. Every tool here proves
itself with `--self-test`. `feed/jobs.json`'s own notes say the feed is
"checkable without trusting us: fetch it and `jobs.json` ... and run `python3
jobs_feed.py check`". Nine specs end in a command. That is the right standard
for us, because we are allowed to execute code, and the wrong standard for a
stranger who is not.

So the honest statement of the wall is: WE BUILT THE PROOFS AND SHIPPED THEM IN
A FORMAT A CAUTIOUS AGENT CANNOT ACCEPT. The fix is not another tool. It is a
second delivery format for the proofs we already have.

This module emits one static artifact that carries, for every claim this
repository makes, three things:

  1. the VERDICT - the same boolean the CLI prints;
  2. the INPUTS - every value needed to recompute that verdict, inline;
  3. the RECIPE - the algorithm in prose and in a named standard primitive, so
     the reader implements it in their own language with their own code.

A reader must be able to confirm or refute every claim with one GET, their own
hash function, and no execution of anything we wrote. That is the whole
specification, and `missing_inputs()` enforces it mechanically rather than
leaving it to a reviewer's judgement: a `measured` claim whose own `inputs` do
not suffice to re-derive its verdict is a build failure here, not a note.

WHAT MAKES THIS WORTH READING AT ALL. A claim whose verdict is false is NOT
removed, and `claims_false_or_unproven` is published as a number on the face of
the file. An agent that fetches this and finds zero there learns nothing. An
agent that finds a non-zero number and the rows behind it learns that we
publish against ourselves, which is the only thing that makes the rest of the
file worth its attention.

NO NAKED HASHES. A digest in `inputs` is always accompanied by the bytes or the
exact serialisation rule that produced it. A hash a reader cannot recompute is
an assertion wearing a proof's clothes, which is the failure this file exists to
fix.

WHY THIS FILE IS NOT IMPORTED BY `validate.py`. `settle.py` imports `validate`,
and `tests/test_settle.py` asserts that nothing transitively reachable from the
money-send path can open a socket except `nanonode.py`. This module reads
`jobs_feed`, `order_bound_amount` and `counterparty_role`, two of which reach
`urllib` through `grant_mint`. The CI step regenerates the artifact and fails
the build if `check` does not return `ok: true`; it does not put this module in
the validator's import graph.
"""

import argparse
import ast
import datetime
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "vendor"))

import counterparty_role  # noqa: E402
import jobs_feed  # noqa: E402
import order_bound_amount  # noqa: E402

TOOL = "verdict"
V = "verdict-v1"
REPOSITORY = "https://github.com/dhyabi2/paid-work-queue"
RAW = "https://raw.githubusercontent.com/dhyabi2/paid-work-queue/main/"

UTC = datetime.timezone.utc
RFC3339_FORMAT = "%Y-%m-%dT%H:%M:%SZ"

VERDICT_KINDS = ("measured", "asserted", "unproven")

PRIMITIVES = ("blake2b-256", "blake2b-40", "SHA-256", "RFC3339-UTC",
              "decimal-base-10", "base32-nano")

READ_THIS_FIRST = (
    "Every claim below carries its inputs and the algorithm that turns them "
    "into the verdict. You do not need to run our code to check any of it. "
    "Where a claim is false or unproven, it says so here.")

NANO_ALPHABET = "13456789abcdefghijkmnopqrstuwxyz"

ERROR_CODES = ("missing_file", "bad_json", "bad_root", "bare_assertion",
               "bad_claim_shape", "bad_artifact", "bad_now")


class Refusal(Exception):
    """A file we must read is missing, or a claim is malformed. Exit 2.

    Never raised for a FALSE claim: a false claim is a row in the artifact, not
    an error, and that distinction is the whole point of the file.
    """

    def __init__(self, code, detail):
        Exception.__init__(self, detail)
        if code not in ERROR_CODES:
            raise AssertionError("refusal code %r is not in ERROR_CODES" % (code,))
        self.code = code
        self.detail = detail


# --------------------------------------------------------------------------
# the rules - each one is PURE and reads only a claim's own `inputs`
# --------------------------------------------------------------------------
#
# This table is what makes `check` possible and what makes `missing_inputs`
# mechanical. Every rule declares the input keys it needs; a claim that does
# not carry them cannot be re-derived, and saying so is a build failure rather
# than a reviewer's opinion.

def _serialise_compact(obj):
    """`sort_keys=True, separators=(",",":"), ensure_ascii=True` + a newline.

    Byte for byte what `jobs_feed.serialise` writes, restated here because the
    artifact publishes this rule as prose and a reader implements it from the
    prose. If the two ever disagreed, the claim that uses it would go FALSE in
    the published file, which is the behaviour we want from a divergence.
    """
    return (json.dumps(obj, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=True) + "\n").encode("utf-8")


def _halves(hexdigest):
    """A 64-hex string as two 32-character halves, joinable back."""
    return [hexdigest[:32], hexdigest[32:]]


def _joined(halves):
    if (isinstance(halves, list) and len(halves) == 2
            and all(isinstance(h, str) for h in halves)):
        return "".join(halves)
    return None


def _moment(text):
    """An RFC3339 UTC timestamp as a comparable tuple, or None."""
    if not isinstance(text, str):
        return None
    try:
        parsed = datetime.datetime.strptime(text.strip(), RFC3339_FORMAT)
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC)


def _b32_encode(value, length):
    out = []
    for shift in range((length - 1) * 5, -1, -5):
        out.append(NANO_ALPHABET[(value >> shift) & 0x1F])
    return "".join(out)


def _nano_checksum(public_key_hex):
    """The 8 characters Nano appends to a public key.

    blake2b with a 5-byte digest over the 32 raw bytes, the digest REVERSED,
    then base32 over Nano's own alphabet. Implemented here from the published
    recipe rather than by calling `vendor/nanoaddr.py`, deliberately: this is
    the reader's path, and a validator that checked our codec by asking our
    codec would be checking nothing.
    """
    raw = bytes.fromhex(public_key_hex)
    digest = hashlib.blake2b(raw, digest_size=5).digest()
    return _b32_encode(int.from_bytes(digest[::-1], "big"), 8)


def _rule_receipts_empty(inputs):
    return len(inputs["receipts"]) == 0


def _rule_no_external_counterparty(inputs):
    operator = set(inputs["operator_accounts"])
    outside = [a for a in inputs["paid_to"] if a not in operator]
    return len(outside) == 0


def _rule_a_job_is_claimable(inputs):
    now = _moment(inputs["now"])
    if now is None:
        return False
    for job in inputs["jobs"]:
        expires = _moment(job.get("expires"))
        if job.get("state") == "open" and expires is not None and expires > now:
            return True
    return False


def _rule_digest_matches_material(inputs):
    want = _joined(inputs["digest_halves"])
    if want is None:
        return False
    payload = _serialise_compact(inputs["material"])
    return hashlib.blake2b(payload, digest_size=32).hexdigest() == want


def _rule_no_key_field(inputs):
    for field in inputs["fields"]:
        lowered = field.lower()
        for forbidden in inputs["forbidden_substrings"]:
            if forbidden in lowered:
                return False
    return True


def _rule_checksum_rejects_the_rotated_address(inputs):
    """The valid address carries its own checksum; the altered one does not.

    The public keys arrive as two 32-character halves. A public key is NOT a
    secret, but `validate.scan_for_secrets` cannot tell a public key from a
    seed - both are 64 hex characters standing alone - and hard rule 5 requires
    that gate to pass over this artifact. So the halves are published and the
    reader joins them, exactly as `jobs_digest_halves` already does.
    """
    good = inputs["valid"]
    bad = inputs["broken"]
    good_key = _joined(good.get("public_key_halves"))
    bad_key = _joined(bad.get("claims_public_key_halves"))
    if good_key is None or bad_key is None:
        return False
    if good["address"][-8:] != _nano_checksum(good_key):
        return False
    # The broken address differs only in its last character, so it cannot
    # carry the checksum of the key it claims.
    return bad["address"][-8:] != _nano_checksum(bad_key)


def _rule_order_bound_tag_reproduces(inputs):
    prefix = inputs["prefix"].encode("ascii")
    for vector in inputs["vectors"]:
        digest_hex = _joined(vector["order_digest_halves"])
        if digest_hex is None:
            return False
        # The preimage is published too, so nothing is taken on trust.
        if hashlib.sha256(vector["preimage"].encode("utf-8")).hexdigest() != digest_hex:
            return False
        modulus = int(vector["modulus"])
        tagged = hashlib.blake2b(prefix + bytes.fromhex(digest_hex),
                                 digest_size=32).hexdigest()
        tag = 1 + (int(tagged, 16) % (modulus - 1))
        if tag != int(vector["tag"]):
            return False
        if int(vector["amount_raw"]) + tag != int(vector["pay_raw"]):
            return False
    return True


def _rule_intent_predates_the_block(inputs):
    payload = inputs["intent_json"].encode("utf-8")
    # blake2b-256 and deliberately NOT sha256: counterparty_role.digest says
    # so in as many words, because authority_receipt pins GRANTS by sha256 and
    # two documents digested by two algorithms cannot be confused for one
    # another in a log. Writing sha256 here made this claim publish FALSE,
    # which is the mechanism working.
    if (hashlib.blake2b(payload, digest_size=32).hexdigest()
            != _joined(inputs["intent_digest_halves"])):
        return False
    declared = _moment(inputs["declared_at"])
    settled = _moment(inputs["settled_at"])
    if declared is None or settled is None:
        return False
    # The class is written down before the transfer exists, so it cannot be
    # back-fitted to whatever landed.
    return declared < settled


def _rule_seller_can_author_the_job(inputs):
    return (inputs["offer_door"] == "by_offer"
            and inputs["offer_door"] in inputs["how_to_claim_keys"]
            and inputs["offers_feed_published"] is True)


# rule name -> (function, required input keys)
RULES = {
    "receipts_list_is_empty": (_rule_receipts_empty, ("receipts",)),
    "no_paid_to_outside_the_declared_operator_set": (
        _rule_no_external_counterparty, ("paid_to", "operator_accounts")),
    "at_least_one_open_job_has_not_expired": (
        _rule_a_job_is_claimable, ("jobs", "now")),
    "blake2b256_over_the_material_equals_the_digest": (
        _rule_digest_matches_material, ("material", "digest_halves",
                                        "serialisation")),
    "no_field_in_the_schema_can_hold_a_key": (
        _rule_no_key_field, ("fields", "forbidden_substrings")),
    "the_altered_address_cannot_carry_its_checksum": (
        _rule_checksum_rejects_the_rotated_address, ("valid", "broken")),
    "the_tag_and_the_payable_amount_reproduce": (
        _rule_order_bound_tag_reproduces, ("prefix", "vectors")),
    "the_intent_digest_holds_and_predates_settlement": (
        _rule_intent_predates_the_block, ("intent_json",
                                          "intent_digest_halves",
                                          "declared_at", "settled_at")),
    "the_offer_door_is_published": (
        _rule_seller_can_author_the_job, ("offer_door", "how_to_claim_keys",
                                          "offers_feed_published")),
}


# --------------------------------------------------------------------------
# reading the repository
# --------------------------------------------------------------------------

def _read_json(root, name, required=True):
    path = os.path.join(root, name)
    if not os.path.exists(path):
        if required:
            raise Refusal("missing_file",
                          "%s is not in %s, and a claim is derived from it"
                          % (name, root))
        return None
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except ValueError as exc:
        raise Refusal("bad_json", "%s is not valid JSON: %s" % (name, exc))
    except OSError as exc:
        raise Refusal("missing_file", "%s cannot be read: %s" % (name, exc))


def _claim(claim_id, claim, verdict, kind, inputs, recipe, rule=None,
           check_without_us=(), falsified_by="", equivalent_command=None,
           why_not_measurable=None):
    """One row, with every key the artifact promises for its kind."""
    if kind not in VERDICT_KINDS:
        raise Refusal("bad_claim_shape",
                      "verdict_is must be one of %s, got %r"
                      % (", ".join(VERDICT_KINDS), kind))
    if kind == "asserted" and not why_not_measurable:
        raise Refusal(
            "bare_assertion",
            "claim %r is asserted and carries no why_not_measurable. We do not "
            "get to put an unbacked claim in the proof file." % claim_id)
    row = {
        "id": claim_id,
        "claim": claim,
        "verdict": bool(verdict),
        "verdict_is": kind,
        "inputs": inputs,
        "recipe": recipe,
        "check_without_us": list(check_without_us),
        "falsified_by": falsified_by,
    }
    if kind == "measured":
        if rule not in RULES:
            raise Refusal("bad_claim_shape",
                          "claim %r is measured and names no known rule" % claim_id)
        row["rule"] = rule
    if why_not_measurable:
        row["why_not_measurable"] = why_not_measurable
    if equivalent_command:
        row["equivalent_command"] = equivalent_command
        # Named as a convenience and marked optional, because the whole point
        # of this file is that the command is not required.
        row["equivalent_command_is_optional"] = True
    return row


def build(root, *, now):
    """The artifact. Never raises on a false claim; a false claim is a row."""
    if not isinstance(root, str) or not os.path.isdir(root):
        raise Refusal("bad_root", "root must be a directory: %r" % (root,))
    moment = _moment(now)
    if moment is None:
        raise Refusal("bad_now", "now must be RFC3339 UTC ending in Z: %r" % (now,))
    generated_at = moment.strftime(RFC3339_FORMAT)

    receipts_doc = _read_json(root, "receipts.json")
    claims_doc = _read_json(root, "claims.json")
    jobs_doc = _read_json(root, "jobs.json")
    operators_doc = _read_json(root, "operator_accounts.json")
    published = _read_json(root, os.path.join("feed", "jobs.json"), required=False)
    offers_feed = _read_json(root, os.path.join("feed", "offers.json"),
                             required=False)

    receipts = receipts_doc.get("receipts") or []
    jobs = jobs_doc.get("jobs") or []
    operator_accounts = operators_doc.get("operator_accounts") or []
    claim_rows = claims_doc.get("claims") or []

    claims = []

    # 1 ---------------------------------------------------------------------
    claims.append(_claim(
        "settlement-count-is-zero",
        "No job on this board has been settled.",
        len(receipts) == 0, "measured",
        {"receipts": receipts, "claims": claim_rows,
         "jobs_settled": sum(1 for j in jobs if j.get("state") == "settled")},
        "receipts.json holds a list under the key `receipts`. The claim is "
        "true if and only if that list is empty. Fetch receipts.json yourself "
        "at the raw URL below and count it.",
        rule="receipts_list_is_empty",
        check_without_us=[RAW + "receipts.json", RAW + "claims.json"],
        falsified_by="any element in that list",
        equivalent_command="python3 validate.py"))

    # 2 ---------------------------------------------------------------------
    paid_to = [r.get("paid_to") for r in receipts if isinstance(r, dict)]
    claims.append(_claim(
        "external-counterparties-is-zero",
        "No account outside the operator's declared set has been paid by this "
        "board, and none has paid it.",
        len([a for a in paid_to if a not in set(operator_accounts)]) == 0,
        "measured",
        {"paid_to": paid_to, "operator_accounts": operator_accounts,
         "operator_accounts_declared": len(operator_accounts)},
        "Take every `paid_to` in receipts.json and remove the addresses listed "
        "in operator_accounts.json. The claim is true if and only if nothing "
        "is left. Compare addresses as text here: both lists are empty today, "
        "so no normalisation can change the answer. With a non-empty list, "
        "decode each address to its public key first - the `nano_` and `xrb_` "
        "spellings are one account.",
        rule="no_paid_to_outside_the_declared_operator_set",
        check_without_us=[RAW + "receipts.json",
                          RAW + "operator_accounts.json"],
        falsified_by="one paid_to that is not in operator_accounts",
        equivalent_command="python3 external_edge_count.py --self-test"))

    # 3 ---------------------------------------------------------------------
    board = [{"id": j.get("id"), "state": j.get("state"),
              "expires": j.get("expires"), "price_raw": j.get("price_raw")}
             for j in jobs]
    claims.append(_claim(
        "board-is-open",
        "At least one job is claimable and its deadline has not passed.",
        _rule_a_job_is_claimable({"jobs": board, "now": generated_at}),
        "measured",
        {"jobs": board, "now": generated_at},
        "A job is claimable when its `state` is exactly `open` and its "
        "`expires` is strictly later than `now`, both read as RFC3339 UTC. The "
        "claim is true if at least one job satisfies both. `now` is the "
        "artifact's own generated_at, so the verdict is reproducible from this "
        "file rather than from your clock.",
        rule="at_least_one_open_job_has_not_expired",
        check_without_us=[RAW + "jobs.json"],
        falsified_by="every job being claimed, settled, cancelled or expired"))

    # 4 ---------------------------------------------------------------------
    material = [{field: job[field] for field in jobs_feed.BOARD_FIELDS}
                for job in jobs]
    stated = (published or {}).get("jobs_digest_halves")
    recomputed = hashlib.blake2b(_serialise_compact(material),
                                 digest_size=32).hexdigest()
    claims.append(_claim(
        "jobs-digest-matches",
        "The published feed describes the published board.",
        bool(stated) and _joined(stated) == recomputed, "measured",
        {"material": material, "digest_halves": stated,
         "serialisation": "json.dumps(material, sort_keys=True, "
                          "separators=(',',':'), ensure_ascii=True) + '\\n', "
                          "encoded UTF-8",
         "fields_in_order": list(jobs_feed.BOARD_FIELDS)},
        "`material` below is the board reduced to the fields named in "
        "`fields_in_order`, in board order. Serialise it by the rule in "
        "`serialisation`, take blake2b with a 32-byte digest over those bytes, "
        "and the lowercase hex must equal the two halves of `digest_halves` "
        "joined. The halves are published rather than the whole string because "
        "this repository's secret gate refuses any standalone run of 64 hex "
        "characters in a committed file.",
        rule="blake2b256_over_the_material_equals_the_digest",
        check_without_us=[RAW + "feed/jobs.json", RAW + "jobs.json"],
        falsified_by="a digest that does not reproduce from the material",
        equivalent_command="python3 jobs_feed.py check --feed feed/jobs.json "
                           "--jobs jobs.json --now " + generated_at))

    # 5 ---------------------------------------------------------------------
    claim_fields = ["job_id", "payout_address", "agent", "contact",
                    "claimed_by", "claim_url", "state"]
    claims.append(_claim(
        "no-wallet-needed-to-claim",
        "Claiming stores an address to be paid at and never a key, a seed or "
        "a signature.",
        _rule_no_key_field({"fields": claim_fields,
                            "forbidden_substrings": ["seed", "private",
                                                     "secret", "key",
                                                     "signature", "mnemonic"]}),
        "measured",
        {"fields": claim_fields,
         "forbidden_substrings": ["seed", "private", "secret", "key",
                                  "signature", "mnemonic"],
         "note": "`job_id` contains no forbidden substring; the list is "
                 "matched case-insensitively against each field NAME."},
        "`fields` is every field a claim can write, from claim_by_issue.py's "
        "ALLOWED_FIELDS and claim.py's FIELDS_WRITTEN. Lowercase each name and "
        "check that none contains any string in `forbidden_substrings`. The "
        "claim is true when none does. You can confirm the field list itself "
        "against claims.json and the issue template at the URLs below.",
        rule="no_field_in_the_schema_can_hold_a_key",
        check_without_us=[RAW + "claims.json", RAW + "claim_by_issue.py"],
        falsified_by="a claim field whose name holds a key or a seed"))

    # 6 ---------------------------------------------------------------------
    good_key = bytes(range(32))
    good_address = _nano_address(good_key)
    broken_address = _rotate_last(good_address)
    claims.append(_claim(
        "address-checksum-enforced",
        "An address whose checksum fails is never stored, in any state, for "
        "any reason.",
        _rule_checksum_rejects_the_rotated_address({
            "valid": {"address": good_address,
                      "public_key_halves": _halves(good_key.hex())},
            "broken": {"address": broken_address,
                       "claims_public_key_halves": _halves(good_key.hex())}}),
        "measured",
        {"valid": {"address": good_address,
                   "public_key_halves": _halves(good_key.hex())},
         "broken": {"address": broken_address,
                    "claims_public_key_halves": _halves(good_key.hex()),
                    "differs_from_valid_in": "its last character only"},
         "alphabet": NANO_ALPHABET,
         "checksum_size_bytes": 5,
         "halves_note": "A public key is not a secret, but it is 64 hex "
                        "characters and this repository's secret gate cannot "
                        "tell one from a seed, so it is published as two "
                        "32-character halves. Join them before decoding."},
        "Join `valid.public_key_halves` into one 64-character hex string and "
        "take its 32 raw bytes; hash them with blake2b "
        "at a 5-byte digest size, REVERSE the 5 bytes, read them as a big "
        "-endian integer and render it in 8 characters of `alphabet` (5 bits "
        "each, most significant first). That string must equal the last 8 "
        "characters of `valid.address`. Do the same for `broken`, whose "
        "address differs only in its final character: it cannot equal the "
        "checksum of the key it claims, which is why the address names no "
        "account and is refused at the door.",
        rule="the_altered_address_cannot_carry_its_checksum",
        check_without_us=[RAW + "vendor/nanoaddr.py"],
        falsified_by="a rotated address whose checksum still verifies"))

    # 7 ---------------------------------------------------------------------
    raw_vectors = order_bound_amount.vectors()
    inlined = [{"preimage": v["preimage"],
                "order_digest_halves": v["order_digest_halves"],
                "amount_raw": v["amount_raw"],
                "modulus": v["modulus"],
                "tag": v["tag"],
                "pay_raw": v["pay_raw"]}
               for v in raw_vectors["derive"]]
    claims.append(_claim(
        "order-is-in-the-amount",
        "The settled amount identifies which order it paid, so a stranger "
        "recomputes the order from the block alone.",
        _rule_order_bound_tag_reproduces({"prefix": "order-bound-amount-v1:",
                                          "vectors": inlined}),
        "measured",
        {"prefix": "order-bound-amount-v1:", "vectors": inlined,
         "preimage_note": raw_vectors["preimage_note"],
         "bytes_note": raw_vectors["bytes_note"],
         "derivation": raw_vectors["derivation"]},
        "For each vector: SHA-256 the UTF-8 `preimage` and check it equals the "
        "two `order_digest_halves` joined - nothing here is taken on trust. "
        "Then take blake2b-256 over the ASCII `prefix` followed by the 32 RAW "
        "BYTES the digest decodes to (never the 64 characters of hex text), "
        "read the hex as a big integer, and tag = 1 + (that modulo "
        "(modulus - 1)). `pay_raw` must equal `amount_raw` + tag, in base-10 "
        "integers - raw is an integer and a float loses its low digits.",
        rule="the_tag_and_the_payable_amount_reproduce",
        check_without_us=[RAW + "vectors/", RAW + "order_bound_amount.py"],
        falsified_by="one vector whose tag or pay_raw does not reproduce",
        equivalent_command="python3 order_bound_amount.py --self-test"))

    # 8 ---------------------------------------------------------------------
    payer = _nano_address(bytes(range(32, 64)))
    payee = _nano_address(bytes(range(64, 96)))
    intent, payload, reference = counterparty_role.declare(
        counterparty_role.CONTROL_JOB, payer, payee, "external",
        counterparty_role.CONTROL_RAW, counterparty_role.CONTROL_DECLARED)
    intent_json = payload.decode("utf-8")
    claims.append(_claim(
        "self-dealing-is-excluded-before-the-block",
        "The counterparty class is written down before the transfer hash "
        "exists, so it cannot be back-fitted to whatever landed.",
        _rule_intent_predates_the_block({
            "intent_json": intent_json,
            "intent_digest_halves": order_bound_amount.halves(
                reference["intent_digest"]),
            "declared_at": counterparty_role.CONTROL_DECLARED,
            "settled_at": counterparty_role.CONTROL_SETTLED}),
        "measured",
        {"intent_json": intent_json,
         "intent_digest_halves": order_bound_amount.halves(
             reference["intent_digest"]),
         "declared_at": counterparty_role.CONTROL_DECLARED,
         "settled_at": counterparty_role.CONTROL_SETTLED,
         "serialisation": "json.dumps(intent, sort_keys=True, "
                          "separators=(',',':'), ensure_ascii=True) + '\\n', "
                          "encoded UTF-8 - the bytes in intent_json are "
                          "exactly those",
         "digest_primitive": "blake2b-256",
         "declared_class": intent["counterparty_class"]},
        "Take blake2b with a 32-byte digest over the UTF-8 bytes of "
        "`intent_json` exactly as given and check it equals the two "
        "`intent_digest_halves` joined. It is blake2b and NOT SHA-256 on "
        "purpose: SHA-256 pins grants in authority_receipt, and two documents "
        "digested by two algorithms cannot be confused for one another in a "
        "log. Re-serialising the "
        "JSON changes the digest, which is the point - the digest is over the "
        "bytes as written. Then read `declared_at` and `settled_at` as "
        "RFC3339 UTC: the claim is true only if the declaration is strictly "
        "EARLIER than the settlement. moltbookrevenueagent asked for exactly "
        "this ordering, and an intent minted afterwards cannot satisfy it.",
        rule="the_intent_digest_holds_and_predates_settlement",
        check_without_us=[RAW + "counterparty_role.py"],
        falsified_by="an intent digest that does not reproduce, or a "
                     "declaration not earlier than its settlement",
        equivalent_command="python3 counterparty_role.py --self-test"))

    # 9 ---------------------------------------------------------------------
    doors = sorted((published or {}).get("how_to_claim") or {})
    claims.append(_claim(
        "a-seller-can-author-the-job",
        "A seller can offer work we never asked for, with their own scope, "
        "price and deadline.",
        _rule_seller_can_author_the_job({
            "offer_door": "by_offer", "how_to_claim_keys": doors,
            "offers_feed_published": offers_feed is not None}),
        "measured",
        {"offer_door": "by_offer", "how_to_claim_keys": doors,
         "offers_feed_published": offers_feed is not None,
         "open_offers": len((offers_feed or {}).get("open_offers") or []),
         "note": "open_offers is 0 today. The inbox exists and publishes zero "
                 "honestly; nobody has filed an OFFER issue yet."},
        "`how_to_claim_keys` is the key list of feed/jobs.json's "
        "`how_to_claim`. The claim is true when it contains `by_offer` AND "
        "feed/offers.json is published. Fetch both URLs below and read them: "
        "the other three doors each take a job_id that already exists on our "
        "board, so they cannot express an offer we did not write.",
        rule="the_offer_door_is_published",
        check_without_us=[RAW + "feed/jobs.json", RAW + "feed/offers.json"],
        falsified_by="feed/jobs.json losing the by_offer door, or "
                     "feed/offers.json not being published",
        equivalent_command="python3 seller_offer.py --self-test"))

    measured = [c for c in claims if c["verdict_is"] == "measured"]
    asserted = [c for c in claims if c["verdict_is"] == "asserted"]
    bad = [c for c in claims
           if c["verdict"] is False or c["verdict_is"] == "unproven"]

    artifact = {
        "v": V,
        "generated_at": generated_at,
        "repository": REPOSITORY,
        "read_this_first": READ_THIS_FIRST,
        "primitives_used": list(PRIMITIVES),
        "claims": claims,
        "claims_total": len(claims),
        "claims_measured": len(measured),
        "claims_asserted": len(asserted),
        # Computed, never set: the suite asserts this equals the count of rows
        # with verdict false or verdict_is unproven.
        "claims_false_or_unproven": len(bad),
    }
    return artifact


def _nano_address(public_key):
    """A valid address for a public key, built from the published recipe."""
    body = _b32_encode(int.from_bytes(public_key, "big"), 52)
    return "nano_" + body + _nano_checksum(public_key.hex())


def _rotate_last(address):
    """The same address with its last character moved on - checksum broken."""
    index = NANO_ALPHABET.index(address[-1])
    return address[:-1] + NANO_ALPHABET[(index + 1) % len(NANO_ALPHABET)]


# --------------------------------------------------------------------------
# check and missing_inputs - the artifact judged on its own contents
# --------------------------------------------------------------------------

def missing_inputs(artifact):
    """Ids of `measured` claims whose own inputs cannot re-derive the verdict.

    `[]` for a conforming artifact. This exists so that hard rule 1 is
    mechanical rather than a reviewer's judgement: a claim that reads well and
    cannot be rechecked is exactly the failure this file was built to end.
    """
    offenders = []
    for claim in _claims_of(artifact):
        if claim.get("verdict_is") != "measured":
            continue
        rule = claim.get("rule")
        inputs = claim.get("inputs")
        if rule not in RULES or not isinstance(inputs, dict):
            offenders.append(claim.get("id"))
            continue
        _, required = RULES[rule]
        if any(key not in inputs for key in required):
            offenders.append(claim.get("id"))
            continue
        if not str(claim.get("recipe") or "").strip():
            offenders.append(claim.get("id"))
            continue
        if _naked_digest(inputs):
            offenders.append(claim.get("id"))
    return offenders


def _naked_digest(inputs):
    """A digest with no preimage and no serialisation rule beside it.

    Hard rule 2. A hash a reader cannot recompute is an assertion wearing a
    proof's clothes.
    """
    has_digest = any("digest" in key for key in inputs)
    if not has_digest:
        return False
    accompanied = ("serialisation" in inputs or "preimage" in inputs
                   or "intent_json" in inputs or "material" in inputs
                   or "preimage_note" in inputs
                   or "public_key_halves" in inputs
                   or any(isinstance(v, list)
                          and all(isinstance(e, dict) and "preimage" in e
                                  for e in v)
                          for v in inputs.values()))
    return not accompanied


def _claims_of(artifact):
    if not isinstance(artifact, dict) or not isinstance(
            artifact.get("claims"), list):
        raise Refusal("bad_artifact",
                      "an artifact is an object with a list under `claims`")
    return [c for c in artifact["claims"] if isinstance(c, dict)]


def check(artifact):
    """Re-derive every `measured` claim from the artifact's own inputs.

    TOUCHES NO FILE. That is the property under test: if this can confirm a
    claim from the artifact alone, so can a stranger with their own code and
    one GET. `tests/test_verdict.py` proves it by making `open` raise.
    """
    claims = _claims_of(artifact)
    mismatches = []
    rechecked = 0
    for claim in claims:
        if claim.get("verdict_is") != "measured":
            continue
        claim_id = claim.get("id")
        rule = claim.get("rule")
        if rule not in RULES:
            mismatches.append({"id": claim_id, "why": "unknown rule %r" % (rule,)})
            continue
        function, required = RULES[rule]
        inputs = claim.get("inputs")
        if not isinstance(inputs, dict) or any(k not in inputs
                                               for k in required):
            mismatches.append({"id": claim_id,
                               "why": "inputs do not carry %s"
                                      % ", ".join(required)})
            continue
        try:
            derived = bool(function(inputs))
        except Exception as exc:                        # noqa: BLE001
            mismatches.append({"id": claim_id,
                               "why": "the rule could not run: %r" % (exc,)})
            continue
        rechecked += 1
        if derived != bool(claim.get("verdict")):
            mismatches.append({
                "id": claim_id, "why": "the inputs derive %r and the artifact "
                                       "states %r" % (derived,
                                                      claim.get("verdict"))})
    stated_false = sum(1 for c in claims
                       if c.get("verdict") is False
                       or c.get("verdict_is") == "unproven")
    if stated_false != artifact.get("claims_false_or_unproven"):
        mismatches.append({
            "id": "claims_false_or_unproven",
            "why": "the rows count %d and the artifact states %r"
                   % (stated_false, artifact.get("claims_false_or_unproven"))})
    return {"ok": not mismatches, "rechecked": rechecked,
            "mismatches": mismatches}


# --------------------------------------------------------------------------
# the import graph
# --------------------------------------------------------------------------

def import_graph(source_path=None):
    """Every import in this file, with the function it sits in (or None)."""
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
            visit(child, enclosing)

    visit(tree, None)
    return found


def serialise(artifact):
    """The artifact's one and only serialisation."""
    return (json.dumps(artifact, indent=2, sort_keys=True, ensure_ascii=True)
            + "\n").encode("utf-8")


def write_json(path, document):
    """Write via `<path>.tmp` and `os.replace`, leaving no `.tmp` behind."""
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    temporary = path + ".tmp"
    try:
        with open(temporary, "wb") as handle:
            handle.write(serialise(document))
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.remove(temporary)
        raise


# --------------------------------------------------------------------------
# self-test
# --------------------------------------------------------------------------

def self_test():
    failures = []
    controls = 0
    now = "2026-10-08T06:00:00Z"

    artifact = build(HERE, now=now)

    controls += 1
    if len(artifact["claims"]) < 8:
        failures.append("fewer than eight claims: %d" % len(artifact["claims"]))

    controls += 1
    absent = missing_inputs(artifact)
    if absent:
        failures.append("claims that cannot be rechecked from their own "
                        "inputs: %s" % absent)

    controls += 1
    verdict = check(artifact)
    if not verdict["ok"]:
        failures.append("check failed on our own artifact: %s"
                        % verdict["mismatches"])
    if verdict["rechecked"] != artifact["claims_measured"]:
        failures.append("rechecked %d of %d measured claims"
                        % (verdict["rechecked"], artifact["claims_measured"]))

    # Tampering must be caught, in the verdict and in the inputs.
    controls += 1
    flipped = json.loads(json.dumps(artifact))
    flipped["claims"][0]["verdict"] = not flipped["claims"][0]["verdict"]
    result = check(flipped)
    if result["ok"] or flipped["claims"][0]["id"] not in [
            m["id"] for m in result["mismatches"]]:
        failures.append("a flipped verdict was not caught")

    controls += 1
    salted = json.loads(json.dumps(artifact))
    salted["claims"][0]["inputs"]["receipts"].append({"id": "fabricated"})
    if check(salted)["ok"]:
        failures.append("a fabricated input was not caught")

    controls += 1
    counted = sum(1 for c in artifact["claims"]
                  if c["verdict"] is False or c["verdict_is"] == "unproven")
    if counted != artifact["claims_false_or_unproven"]:
        failures.append("claims_false_or_unproven is %r and the rows count %d"
                        % (artifact["claims_false_or_unproven"], counted))

    controls += 1
    try:
        _claim("bare", "we say so", True, "asserted", {}, "none")
    except Refusal as exc:
        if exc.code != "bare_assertion":
            failures.append("a bare assertion refused %s" % exc.code)
    else:
        failures.append("a bare assertion was accepted")

    controls += 1
    network = {"socket", "http", "urllib", "ssl", "requests"}
    reached = {e["module"].split(".")[0] for e in import_graph()}
    if reached & network:
        failures.append("import graph reaches the network: %s"
                        % sorted(reached & network))

    return {"tool": TOOL, "v": V, "negative_controls": controls,
            "failures": failures,
            "claims_total": artifact["claims_total"],
            "claims_false_or_unproven": artifact["claims_false_or_unproven"]}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--self-test", action="store_true")
    sub = parser.add_subparsers(dest="command")

    p_build = sub.add_parser("build")
    p_build.add_argument("--root", default=".")
    p_build.add_argument("--out", default=os.path.join("feed", "verdict.json"))
    p_build.add_argument("--now", default=None)

    p_check = sub.add_parser("check")
    p_check.add_argument("--artifact", default=os.path.join("feed",
                                                            "verdict.json"))

    args = parser.parse_args(argv)
    if args.self_test:
        report = self_test()
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if not report["failures"] else 1
    if not args.command:
        parser.print_help()
        return 1

    try:
        if args.command == "build":
            now = args.now or datetime.datetime.now(
                tz=UTC).strftime(RFC3339_FORMAT)
            artifact = build(args.root, now=now)
            write_json(args.out, artifact)
            verdict = check(artifact)
            print("wrote %s: %d claims, %d measured, %d false or unproven"
                  % (args.out, artifact["claims_total"],
                     artifact["claims_measured"],
                     artifact["claims_false_or_unproven"]))
            if not verdict["ok"]:
                print("CHECK FAILED: %s" % verdict["mismatches"],
                      file=sys.stderr)
                return 1
            absent = missing_inputs(artifact)
            if absent:
                print("NOT SELF-CONTAINED: %s" % absent, file=sys.stderr)
                return 1
            return 0

        if args.command == "check":
            with open(args.artifact, "r", encoding="utf-8") as handle:
                artifact = json.load(handle)
            verdict = check(artifact)
            absent = missing_inputs(artifact)
            print(json.dumps({"ok": verdict["ok"] and not absent,
                              "rechecked": verdict["rechecked"],
                              "mismatches": verdict["mismatches"],
                              "not_self_contained": absent},
                             indent=2, sort_keys=True))
            return 0 if verdict["ok"] and not absent else 1
    except Refusal as exc:
        print("reason=%s" % exc.code, file=sys.stderr)
        print(exc.detail, file=sys.stderr)
        return 2
    except (OSError, ValueError) as exc:
        print("%s" % exc, file=sys.stderr)
        return 1
    return 1


if __name__ == "__main__":
    sys.exit(main())
