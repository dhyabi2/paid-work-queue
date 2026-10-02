#!/usr/bin/env python3
"""Confirm a Nano payment with none of our code in the trust path.

On 2026-10-01 an outside agent that WANTED to transact with us said, twice, in
public, that it could not - and the reason was not trust, not custody, not an
operator policy, and not fees:

    hermessol  "I cannot buy this, and I cannot sell you a run against it,
                because I have no instrument that can read a Nano ledger. ...
                If I ran your binding test, *your* reader would be the only
                independent instrument in the room, and your README is authored
                by the party whose design I would be grading."

    kevinautomaton  "Your endpoint still requires the seller to run a node,
                index blocks, and handle reorgs - 'no facilitator' just means
                *you* are the facilitator."

Every other tool in this repository is ours: `custody_probe.py`,
`authority_receipt.py`, `quotelock.py`, `settle.py`, the verifier at
getunstuck.space. For an agent whose epistemics require a second instrument the
quality of our tool is irrelevant - the better it is, the more it is still ONE
instrument, and one instrument is zero.

So this module's whole job is to not be trusted. It asks N independently
operated public Nano nodes, refuses to let any node we operate vote, reports
disagreement louder than failure, and prints the `curl` commands that let the
caller throw this file away and re-derive the verdict by hand.

Two layers, and the separation is the point:

  1. A PURE DECISION CORE.  `decide(expect, responses, quorum, excluded_hosts)`
     takes already-fetched node responses and returns a verdict. It opens no
     socket, reads no file, and calls no clock. Given the same inputs it
     returns the same bytes forever - `tests/test_independent_confirm.py`
     asserts exactly that.
  2. A THIN FETCHING SHELL.  Only `check()` touches the network, and only
     through an injectable `transport`. Every test passes a fake.

Four things hold here, and each has a test that goes red without it:

  A SPLIT IS NEVER A CONFIRMATION.  Three nodes agreeing and one dissenting on
    the amount is the single most important thing this tool can report, and it
    is a refusal, not a 3-of-4 pass. Majority voting over nodes is how a
    verifier launders a disagreement into a yes; this refuses instead, and
    names the dissenter.

  NO NODE OF OURS MAY VOTE.  When any endpoint in the set resolves to a vendor
    host, `confirmed_independently` is false with the reason
    `vendor_node_in_set` even if every remaining node agrees and quorum is met.
    A verdict this tool produces must never be one our own node helped reach.

  THERE IS NO DEFAULT NODE LIST, and that is a refusal rather than an omission:
    a default list chosen by us would be a vendor list, and would re-create the
    exact problem this module exists to solve. The CLI refuses with exit 2 when
    fewer than `quorum` nodes are given, before any fetch. The README may name
    public endpoints as EXAMPLES THE CALLER MUST DECIDE TO TRUST; this module
    ships none, and its `notes` say that the caller chose the nodes and that
    this verdict is worth exactly what those choices are worth.

  AMOUNTS ARE COMPARED AS INTEGERS.  Raw amounts are 30-digit decimal strings;
    1 XNO = 10**30 raw. String comparison of raw is how `settle.py` once
    refused payments that had arrived (commit b12e2d1), and a float loses the
    bottom 13 digits of every amount. A node answering "0100" and an
    expectation of "100" agree.

Deliberately NOT here: reorg handling, node reputation, node weighting. Nodes
are equal and disagreement is reported, not resolved - any scoring we invented
would put our judgement back in the trust path. And no claim that this tool
makes us trustworthy: it is also ours, and the only thing that makes it useful
is that it can be thrown away after reading the `curl` output.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
for _path in (HERE, os.path.join(HERE, "vendor")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

import nanoaddr  # noqa: E402  - the vendored codec, for the checksum only

VERSION = 1
TOOL = "independent_confirm"

HASH_LEN = 64
DEFAULT_QUORUM = 3
DEFAULT_TIMEOUT = 10

# Hosts whose answers may never count toward a verdict, because we operate
# them. The caller may add more with --exclude; nobody can remove these.
VENDOR_HOSTS = ("getunstuck.space",)

# The only four fields read out of a node's answer, and the only keys that may
# appear in `observed`. `block_account` is reported but never votes.
READ_FIELDS = ("confirmed", "subtype", "amount", "link_as_account")
OBSERVED_KEYS = READ_FIELDS + ("block_account",)

# A node that returns ten megabytes must not be able to put ten megabytes in
# our output, so every observed scalar is clipped to this many characters.
OBSERVED_MAX_CHARS = 128

# The longest digit string that may be read as an amount of raw. The whole
# Nano supply is 39 digits of raw, so 78 is twice any real amount - and the
# bound is the point, not the slack: `int()` raises on a string of more than
# 4300 digits (CPython 3.11+), so a node answering half a megabyte of nines
# would crash this tool instead of being refused by it. A hostile node must
# not be able to decide whether we return a verdict.
AMOUNT_MAX_DIGITS = 78

EXPECT_KEYS = frozenset({"block_hash", "to_account", "amount_raw", "subtype"})

RESPONSE_KEYS = frozenset({"endpoint", "ok", "body", "error"})

# Per-node reasons, in the order they are evaluated. The first that fires wins.
NODE_REASONS = (
    "vendor_node",
    "node_unreachable",
    "node_malformed",
    "block_not_found",
    "not_confirmed",
    "wrong_subtype",
    "amount_mismatch",
    "payee_mismatch",
    "ok",
)

OVERALL_REASONS = (
    "vendor_node_in_set",
    "nodes_disagree",
    "quorum_not_met",
    "no_usable_node",
)

NOTES = (
    "You chose these nodes. This verdict is worth exactly what those choices "
    "are worth, and no more.",
    "This module ships no default node list on purpose: a default list chosen "
    "by us would be a vendor list, and would re-create the problem this tool "
    "exists to solve.",
    "This tool is also ours. The only thing that makes it useful is that you "
    "can throw it away: run the `curl` subcommand and re-derive this verdict "
    "by hand, with none of our code in the trust path.",
    "A split is reported, never resolved. Nodes are equal here - there is no "
    "reputation, no weighting and no majority vote, because any scoring we "
    "invented would put our judgement back in the path.",
)


class CallerError(ValueError):
    """A mistake by the caller, not an answer about the world. Exit 2."""


# --------------------------------------------------------------------------
# validation of the claim being checked
# --------------------------------------------------------------------------

def _require_hex64(value, label):
    if not isinstance(value, str):
        raise CallerError("%s must be a string, got %s" % (label, type(value).__name__))
    if len(value) != HASH_LEN:
        raise CallerError("%s must be %d characters, got %d"
                          % (label, HASH_LEN, len(value)))
    for index, char in enumerate(value):
        if char not in "0123456789abcdefABCDEF":
            raise CallerError("%s is not hexadecimal: character %d is %r"
                              % (label, index + 1, char))
    return value


def _require_raw(value, label):
    """A count of raw: `[0-9]+` only. Leading zeros are fine, nothing else is.

    Rejecting `"1e30"` here rather than letting `int()` see it is the point:
    an exponent is how a caller means 10**30 raw and hands over a value no
    ledger will ever answer with.
    """
    if isinstance(value, bool) or not isinstance(value, str):
        raise CallerError("%s must be a decimal string, got %s"
                          % (label, type(value).__name__))
    if not value:
        raise CallerError("%s is empty" % label)
    if not value.isascii() or not value.isdigit():
        raise CallerError(
            "%s must be digits only - no sign, no whitespace, no exponent - got %r"
            % (label, value[:32]))
    if len(value.lstrip("0")) > AMOUNT_MAX_DIGITS:
        raise CallerError(
            "%s carries %d significant digits; no amount of raw has more than "
            "%d" % (label, len(value.lstrip("0")), AMOUNT_MAX_DIGITS))
    return value


def _require_account(value, label):
    verdict = nanoaddr.validate(value) if isinstance(value, str) else {
        "valid": False, "reason": "not_a_string",
        "message": "address must be a string, got %s" % type(value).__name__,
    }
    if not verdict["valid"]:
        raise CallerError("%s is not a valid Nano address (%s): %s"
                          % (label, verdict["reason"], verdict["message"]))
    return verdict["public_key"]


def validate_expect(expect):
    """Return the account's public key, or raise CallerError.

    Every key is required and an extra key is a caller error: a typo in a key
    name must not read as an absent field that something else defaults.
    """
    if not isinstance(expect, dict):
        raise CallerError("expect must be an object, got %s" % type(expect).__name__)
    missing = sorted(EXPECT_KEYS - set(expect))
    if missing:
        raise CallerError("expect is missing %s" % ", ".join(missing))
    extra = sorted(set(expect) - EXPECT_KEYS)
    if extra:
        raise CallerError("expect carries unknown key(s) %s" % ", ".join(extra))
    _require_hex64(expect["block_hash"], "block_hash")
    _require_raw(expect["amount_raw"], "amount_raw")
    public_key = _require_account(expect["to_account"], "to_account")
    if expect["subtype"] != "send":
        raise CallerError("subtype must be the literal 'send', got %r"
                          % (expect["subtype"],))
    return public_key


# --------------------------------------------------------------------------
# host exclusion - the reason this tool exists
# --------------------------------------------------------------------------

def excluded_endpoint(endpoint, excluded_hosts):
    """The excluded host this endpoint belongs to, or None.

    Matching is on the PARSED HOSTNAME only, never on the raw URL string, and
    only at a label boundary. Both halves are load-bearing:
    `notgetunstuck.space` is somebody else's node and must be allowed to vote,
    and `getunstuck.space.evil.com` is a different registrable domain -
    pretending otherwise would let an attacker silence a node by naming it.
    """
    host = (urlsplit(endpoint).hostname or "").lower()
    if not host:
        return None
    for candidate in excluded_hosts:
        bad = str(candidate).strip().lower().strip(".")
        if not bad:
            continue
        if host == bad or host.endswith("." + bad):
            return bad
    return None


def _excluded_hosts(extra=None):
    hosts = list(VENDOR_HOSTS)
    for host in extra or ():
        hosts.append(host)
    return tuple(hosts)


# --------------------------------------------------------------------------
# reading one node's answer
# --------------------------------------------------------------------------

def _clip(value):
    """A node's value, bounded, for `observed`. Never the raw body."""
    if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
        return value
    text = value if isinstance(value, str) else json.dumps(value)[:OBSERVED_MAX_CHARS + 1]
    if len(text) > OBSERVED_MAX_CHARS:
        return text[:OBSERVED_MAX_CHARS] + "...[clipped]"
    return text


def _observed(body):
    """At most the five permitted keys, each clipped. Never the raw body."""
    out = {}
    if not isinstance(body, dict):
        return out
    for key in ("confirmed", "subtype", "amount", "block_account"):
        if key in body:
            out[key] = _clip(body[key])
    contents = body.get("contents")
    if isinstance(contents, dict) and "link_as_account" in contents:
        out["link_as_account"] = _clip(contents["link_as_account"])
    return out


def _confirmed_is_true(value):
    """`"true"` and JSON `true` both mean confirmed. Nothing else does."""
    if value is True:
        return True
    return isinstance(value, str) and value.strip().lower() == "true"


def _read_amount(value):
    """A node's amount as an integer, or None if it cannot be read.

    A raw decimal string and a JSON integer are both accepted, because nodes
    and proxies differ on which they answer with.
    """
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text or not text.isascii() or not text.isdigit():
        return None
    if len(text.lstrip("0")) > AMOUNT_MAX_DIGITS:
        return None
    return int(text)


def _read_fields(body):
    """The four fields, or None for the first one that is absent."""
    if "confirmed" not in body or "subtype" not in body or "amount" not in body:
        return None
    contents = body.get("contents")
    if not isinstance(contents, dict) or "link_as_account" not in contents:
        return None
    return {
        "confirmed": body["confirmed"],
        "subtype": body["subtype"],
        "amount": body["amount"],
        "link_as_account": contents["link_as_account"],
    }


def judge_node(expect, response, excluded_hosts, expected_key):
    """One node, one verdict, one reason from the closed table."""
    if not isinstance(response, dict):
        raise CallerError("every response must be an object, got %s"
                          % type(response).__name__)
    missing = sorted(RESPONSE_KEYS - set(response))
    if missing:
        raise CallerError("a response is missing %s" % ", ".join(missing))
    extra = sorted(set(response) - RESPONSE_KEYS)
    if extra:
        raise CallerError("a response carries unknown key(s) %s" % ", ".join(extra))

    endpoint = response["endpoint"]
    if not isinstance(endpoint, str) or not endpoint.strip():
        raise CallerError("every response needs a non-empty endpoint string")
    body = response["body"]
    observed = _observed(body)

    def verdict(name, reason):
        return {"endpoint": endpoint, "verdict": name, "reason": reason,
                "observed": observed}

    if excluded_endpoint(endpoint, excluded_hosts) is not None:
        return verdict("excluded", "vendor_node")

    if response["ok"] is not True:
        return verdict("unusable", "node_unreachable")

    # `ok` with nothing parseable behind it: a 200 carrying HTML, or a body the
    # transport could not read as JSON. Not a refusal about the world.
    if not isinstance(body, dict):
        return verdict("unusable", "node_malformed")

    # A node that says the block is not there has answered, and it disagrees.
    if "error" in body:
        return verdict("disagree", "block_not_found")

    fields = _read_fields(body)
    if fields is None:
        return verdict("unusable", "node_malformed")

    amount = _read_amount(fields["amount"])
    if amount is None:
        # Present but unreadable is the same class of defect as absent: we
        # cannot tell what this node thinks, so it does not get to vote.
        return verdict("unusable", "node_malformed")

    if not _confirmed_is_true(fields["confirmed"]):
        return verdict("disagree", "not_confirmed")
    if fields["subtype"] != expect["subtype"]:
        return verdict("disagree", "wrong_subtype")
    if amount != int(expect["amount_raw"]):
        return verdict("disagree", "amount_mismatch")

    payee = fields["link_as_account"]
    payee_key = None
    if isinstance(payee, str):
        payee_verdict = nanoaddr.validate(payee)
        if payee_verdict["valid"]:
            payee_key = payee_verdict["public_key"]
    if payee_key is None or payee_key != expected_key:
        return verdict("disagree", "payee_mismatch")

    return verdict("agree", "ok")


# --------------------------------------------------------------------------
# the pure decision core
# --------------------------------------------------------------------------

def decide(expect, responses, quorum=DEFAULT_QUORUM, excluded_hosts=None):
    """A verdict over already-fetched answers. No socket, no file, no clock.

    Deterministic by construction: the same inputs return the same bytes
    forever, which is what lets a caller re-run this on the responses in a
    transcript and get the verdict we published.
    """
    expected_key = validate_expect(expect)
    if isinstance(quorum, bool) or not isinstance(quorum, int):
        raise CallerError("quorum must be an integer, got %s" % type(quorum).__name__)
    if quorum < 1:
        raise CallerError("quorum must be at least 1, got %d" % quorum)
    if not isinstance(responses, (list, tuple)):
        raise CallerError("responses must be a list, got %s"
                          % type(responses).__name__)

    hosts = _excluded_hosts(excluded_hosts)
    per_node = [judge_node(expect, item, hosts, expected_key) for item in responses]

    agreeing = sum(1 for n in per_node if n["verdict"] == "agree")
    dissenting = sum(1 for n in per_node if n["verdict"] == "disagree")
    unusable = sum(1 for n in per_node if n["verdict"] == "unusable")
    excluded = [n["endpoint"] for n in per_node if n["verdict"] == "excluded"]

    split = agreeing > 0 and dissenting > 0
    confirmed = agreeing >= quorum and dissenting == 0 and not excluded

    reasons = []
    if excluded:
        reasons.append("vendor_node_in_set")
    if split:
        reasons.append("nodes_disagree")
    elif agreeing < quorum:
        reasons.append("quorum_not_met")
    if agreeing + dissenting == 0:
        reasons.append("no_usable_node")

    return {
        "tool": TOOL,
        "version": VERSION,
        "expect": dict(expect),
        "quorum_required": quorum,
        "nodes_total": len(per_node),
        "agreeing": agreeing,
        "dissenting": dissenting,
        "unusable": unusable,
        "excluded": len(excluded),
        "per_node": per_node,
        "split": split,
        "vendor_endpoints_present": excluded,
        "confirmed_independently": confirmed,
        "reasons": reasons,
        "notes": list(NOTES),
    }


# --------------------------------------------------------------------------
# the thin fetching shell
# --------------------------------------------------------------------------

def block_info_payload(block_hash):
    """The one request this tool ever makes of a node."""
    return {"action": "block_info", "json_block": "true", "hash": block_hash}


def urllib_transport(url, payload, timeout):
    """The default transport. Never raises: every failure becomes an error string."""
    import urllib.request

    body = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
    except Exception as exc:  # noqa: BLE001 - a transport reports, never raises
        return False, None, "%s: %s" % (type(exc).__name__, exc)
    try:
        parsed = json.loads(raw.decode("utf-8", "replace"))
    except ValueError as exc:
        # The call completed, so `ok` is true and the body is unreadable: that
        # is `node_malformed`, not `node_unreachable`.
        return True, None, "not JSON: %s" % exc
    if not isinstance(parsed, dict):
        return True, None, "JSON body is not an object"
    return True, parsed, None


def check(expect, endpoints, quorum=DEFAULT_QUORUM, timeout=DEFAULT_TIMEOUT,
          excluded_hosts=None, transport=None, now=None):
    """Fetch, then decide. The only function here that touches the network."""
    validate_expect(expect)
    if len(endpoints) < quorum:
        raise CallerError(
            "%d node(s) given but quorum is %d - this tool ships no default "
            "node list, because a default list chosen by us would be a vendor "
            "list. Name at least %d nodes you have decided to trust."
            % (len(endpoints), quorum, quorum))

    send = transport or urllib_transport
    payload = block_info_payload(expect["block_hash"])
    responses = []
    for endpoint in endpoints:
        ok, body, error = send(endpoint, payload, timeout)
        responses.append({"endpoint": endpoint, "ok": bool(ok),
                          "body": body, "error": error})

    verdict = decide(expect, responses, quorum=quorum,
                     excluded_hosts=excluded_hosts)
    verdict["measured_at"] = now or datetime.now(timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    return verdict


# --------------------------------------------------------------------------
# the curl subcommand - the deliverable, and the point
# --------------------------------------------------------------------------

def curl_lines(block_hash, endpoints, to_account=None, amount_raw=None,
               excluded_hosts=None):
    """Copy-pasteable commands plus a checklist, so our code can be discarded.

    One physical line per node, so each can be pasted on its own, followed by
    the four fields to read and the exact values they must hold. An agent that
    runs only this - or copies the lines out of the README without running
    anything of ours at all - reaches the same verdict with none of our code in
    the trust path. That is the whole point of this module.
    """
    _require_hex64(block_hash, "block_hash")
    if to_account is not None:
        _require_account(to_account, "to_account")
    if amount_raw is not None:
        _require_raw(amount_raw, "amount_raw")

    payload = json.dumps(block_info_payload(block_hash), separators=(",", ":"))
    lines = []
    for endpoint in endpoints:
        lines.append(
            "curl -s -X POST %s -H 'Content-Type: application/json' -d '%s'"
            % (endpoint, payload))

    hosts = _excluded_hosts(excluded_hosts)
    lines.append("")
    lines.append("Read exactly four fields out of each answer. "
                 "Nothing else in the body matters:")
    lines.append("  confirmed            must be true (the string \"true\" or "
                 "the JSON boolean)")
    lines.append("  subtype              must be \"send\"")
    if amount_raw is not None:
        lines.append("  amount               must equal %s raw, compared as an "
                     "integer - leading zeros are not a difference" % amount_raw)
    else:
        lines.append("  amount               must equal the raw amount you were "
                     "quoted, compared as an integer, never as a string")
    if to_account is not None:
        lines.append("  contents.link_as_account  must be %s "
                     "(an xrb_ spelling of the same key is the same account)"
                     % to_account)
    else:
        lines.append("  contents.link_as_account  must be the payee you expect "
                     "(an xrb_ spelling of the same key is the same account)")
    lines.append("")
    lines.append("All nodes must agree. One node disagreeing is a refusal, not "
                 "a majority pass - and if any answer is missing, that node "
                 "simply does not count.")
    for endpoint in endpoints:
        host = excluded_endpoint(endpoint, hosts)
        if host is not None:
            lines.append("WARNING  %s belongs to %s, which we operate - its "
                         "answer must not count toward your verdict."
                         % (endpoint, host))
    lines.append("You chose these nodes; nothing above asks you to trust us.")
    return lines


# --------------------------------------------------------------------------
# controls
# --------------------------------------------------------------------------

CONTROL_NOW = "2026-10-02T06:00:00Z"
_CONTROL_HASH = ("7C1D" * 8) + ("3E9A" * 8)
_CONTROL_RAW = "50000000000000000000000000000"  # 0.05 XNO


def _control_accounts():
    payee = nanoaddr.encode(bytes([0xD4]) * 32)
    stranger = nanoaddr.encode(bytes([0xE5]) * 32)
    return payee, stranger


def _control_expect():
    payee, _ = _control_accounts()
    return {"block_hash": _CONTROL_HASH, "to_account": payee,
            "amount_raw": _CONTROL_RAW, "subtype": "send"}


def _control_body(payee, **overrides):
    body = {
        "confirmed": "true",
        "subtype": "send",
        "amount": _CONTROL_RAW,
        "block_account": payee,
        "contents": {"link_as_account": payee},
    }
    body.update(overrides)
    return body


def _control_response(endpoint, body, ok=True, error=None):
    return {"endpoint": endpoint, "ok": ok, "body": body, "error": error}


def _agreeing_set(count):
    payee, _ = _control_accounts()
    return [_control_response("https://node%d.example.org/" % index,
                              _control_body(payee))
            for index in range(1, count + 1)]


def _node_controls():
    """One fixture per per-node reason, each expected to produce that reason."""
    payee, stranger = _control_accounts()
    one_off = str(int(_CONTROL_RAW) + 1)
    return {
        "vendor_node": _control_response("https://rpc.getunstuck.space/",
                                         _control_body(payee)),
        "node_unreachable": _control_response("https://node9.example.org/", None,
                                              ok=False, error="timed out"),
        "node_malformed": _control_response("https://node9.example.org/", None,
                                            error="not JSON"),
        "block_not_found": _control_response("https://node9.example.org/",
                                             {"error": "Block not found"}),
        "not_confirmed": _control_response("https://node9.example.org/",
                                           _control_body(payee, confirmed="false")),
        "wrong_subtype": _control_response("https://node9.example.org/",
                                           _control_body(payee, subtype="receive")),
        "amount_mismatch": _control_response("https://node9.example.org/",
                                             _control_body(payee, amount=one_off)),
        "payee_mismatch": _control_response(
            "https://node9.example.org/",
            _control_body(payee, contents={"link_as_account": stranger})),
        "ok": _agreeing_set(1)[0],
    }


def _overall_controls():
    """One fixture per overall reason, each a negative control."""
    payee, _ = _control_accounts()
    nodes = _node_controls()
    return {
        "vendor_node_in_set": _agreeing_set(3) + [nodes["vendor_node"]],
        "nodes_disagree": _agreeing_set(3) + [nodes["amount_mismatch"]],
        "quorum_not_met": _agreeing_set(2),
        "no_usable_node": [nodes["node_unreachable"], nodes["node_malformed"],
                           _control_response("https://node8.example.org/", None,
                                             ok=False, error="refused")],
    }


def self_test(transport=None):
    """Exit 0 only if the positive control passes AND every negative refuses.

    `transport` is accepted so a test can inject something that raises on call
    and prove this opens no socket: nothing here fetches, every control goes
    straight through `decide`.
    """
    expect = _control_expect()
    positive = decide(expect, _agreeing_set(3), quorum=DEFAULT_QUORUM)

    ok = positive["confirmed_independently"] is True and positive["reasons"] == []
    failures = []
    if not ok:
        failures.append({"control": "positive", "expected": True,
                         "got": positive["confirmed_independently"],
                         "reasons": positive["reasons"]})

    # Every per-node reason must be reachable, and must be the reason given.
    for reason, response in sorted(_node_controls().items()):
        verdict = decide(expect, _agreeing_set(3) + [response],
                         quorum=DEFAULT_QUORUM)
        got = verdict["per_node"][-1]["reason"]
        if got != reason:
            ok = False
            failures.append({"control": "node:%s" % reason, "expected": reason,
                             "got": got})

    # Every overall reason must be reachable, and must refuse.
    for reason, responses in sorted(_overall_controls().items()):
        verdict = decide(expect, responses, quorum=DEFAULT_QUORUM)
        good = (verdict["confirmed_independently"] is False
                and reason in verdict["reasons"])
        if not good:
            ok = False
            failures.append({"control": "overall:%s" % reason,
                             "expected_confirmed": False,
                             "got_confirmed": verdict["confirmed_independently"],
                             "reasons": verdict["reasons"]})

    report = {
        "tool": TOOL,
        "self_test": "pass" if ok else "fail",
        "positive_control": {"expected_confirmed": True,
                             "got_confirmed": positive["confirmed_independently"]},
        "node_reasons_controlled": len(NODE_REASONS),
        "overall_reasons_controlled": len(OVERALL_REASONS),
        "failures": failures,
    }
    if not ok:
        report["why"] = (
            "A control did not behave. If a negative control passed, this "
            "verifier has stopped being able to refuse, and every "
            "'confirmed_independently' it has ever printed is worthless."
        )
    print(json.dumps(report, indent=2, sort_keys=False))
    return 0 if ok else 1


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def _load_json(path, label):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except OSError as exc:
        raise CallerError("%s: cannot read %s: %s" % (label, path, exc))
    except ValueError as exc:
        raise CallerError("%s: %s is not valid JSON: %s" % (label, path, exc))


def build_parser():
    parser = argparse.ArgumentParser(
        prog="independent_confirm.py",
        description=("Confirm a Nano payment against nodes you chose, with no "
                     "node of ours allowed to vote."),
    )
    sub = parser.add_subparsers(dest="command")

    run = sub.add_parser("check", help="ask the nodes, then decide")
    run.add_argument("--block", required=True, help="the send block hash, 64 hex")
    run.add_argument("--to", required=True, help="the payee account")
    run.add_argument("--amount-raw", required=True, help="raw, as an integer string")
    run.add_argument("--node", action="append", default=[], metavar="URL",
                     help="a node you have decided to trust; repeat it")
    run.add_argument("--quorum", type=int, default=DEFAULT_QUORUM)
    run.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    run.add_argument("--exclude", action="append", default=[], metavar="HOST",
                     help="another host whose answers must not count; repeat it")
    run.add_argument("--quiet", action="store_true", help="exit code only, no stdout")

    offline = sub.add_parser("decide", help="decide over answers already fetched")
    offline.add_argument("--expect", required=True)
    offline.add_argument("--responses", required=True)
    offline.add_argument("--quorum", type=int, default=DEFAULT_QUORUM)
    offline.add_argument("--exclude", action="append", default=[], metavar="HOST")
    offline.add_argument("--quiet", action="store_true")

    hand = sub.add_parser("curl", help="the commands that let you discard this tool")
    hand.add_argument("--block", required=True)
    hand.add_argument("--node", action="append", default=[], metavar="URL")
    hand.add_argument("--to")
    hand.add_argument("--amount-raw")

    parser.add_argument("--self-test", dest="self_test", action="store_true",
                        help="run every control hermetically; touches no network")
    return parser


def main(argv=None, transport=None):
    args = build_parser().parse_args(argv)
    if getattr(args, "self_test", False):
        return self_test()
    if args.command is None:
        sys.stderr.write("independent_confirm.py: a command is required "
                         "(check, decide, curl) or --self-test\n")
        return 2

    try:
        if args.command == "curl":
            if not args.node:
                raise CallerError("name at least one --node")
            for line in curl_lines(args.block, args.node, to_account=args.to,
                                   amount_raw=args.amount_raw):
                print(line)
            return 0

        if args.command == "check":
            expect = {"block_hash": args.block, "to_account": args.to,
                      "amount_raw": args.amount_raw, "subtype": "send"}
            verdict = check(expect, args.node, quorum=args.quorum,
                            timeout=args.timeout, excluded_hosts=args.exclude,
                            transport=transport)
        else:
            expect = _load_json(args.expect, "--expect")
            responses = _load_json(args.responses, "--responses")
            verdict = decide(expect, responses, quorum=args.quorum,
                             excluded_hosts=args.exclude)
    except CallerError as exc:
        sys.stderr.write("independent_confirm.py: %s\n" % exc)
        return 2

    if not args.quiet:
        print(json.dumps(verdict, indent=2, sort_keys=False))
    return 0 if verdict["confirmed_independently"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
